#!/usr/bin/env python3
"""CI EXECUTION-LATENCY watchdog — cron delivery, queue wait, execution overrun.

🤖 SPARQ agent. Companion to sparq-org/sparq#4810 (bead sq-1lc4i); same three choke modes,
this repository's conventions and this repository's separately-measured thresholds.

WHY. Maintainer-requested 2026-07-28: "alerting for when runners are not picked up for
crons or delayed for other dispatches on both repos. This is an indicator that you are
choking on runner availability." This repo has an unusually mature "detect the thing that
did NOT happen" ring — dispatch-stall-alert, metrics-alert --stale-check, cron-keepalive,
triage-stock-alert, pat-validity — but every member of it watches a NAMED lane for
LIVENESS. None measures CI EXECUTION LATENCY, and a full-tree grep for
latenc|duration|elapsed|run_started_at|percentile over every script on master finds no
workflow-run-duration or queue-wait consumer. This is new ground here.

THREE MODES, because they have different signatures and only one is runner availability:

  M1 CRON-FIRING DEFICIT   a scheduled lane firing far below what it can actually get.
                           This mode produces NO ARTIFACT — a cron that never fires leaves
                           no run, no conclusion, nothing to inspect — so it can only be
                           caught by computing an expectation and comparing.
  M2 QUEUE WAIT            a run sitting in `queued` past a measured threshold. Runner
                           availability proper. MEASURED KNOWN POSITIVE on THIS repo:
                           seven `pr-gate.yml` runs were held in `queued` for 12.8-99.5
                           minutes inside a single 00:58Z-02:24Z window on 2026-07-28.
  M3 EXECUTION OVERRUN     a run `in_progress` far past its own lane's measured duration.
                           It consumes capacity while looking perfectly healthy.

=============================================================================
THE MEASUREMENT TRAP — read before editing
=============================================================================
The obvious instrument for "are runners being picked up" is job-level
`started_at - created_at`. It does not work, and it fails in the SAFE-LOOKING direction.
MEASURED on sparq run 30333511110 (a run that had been in_progress 6.7h with 8 live jobs),
N=65 jobs: pickup lag p50 3s, MAX 10s, jobs over 60s ZERO — while `status=queued` read
zero for the entire 6.7 hours. A matrix leg throttled behind `max-parallel` or an account
concurrency ceiling is NOT CREATED as a job object while it waits, so it contributes no
queue depth and no pickup lag.

  (a) A job that never finishes never appears in a completed run. Any statistic over
      COMPLETED work is structurally incapable of detecting a hang — the failing population
      is exactly the one it excludes. M3's DETECTION VARIABLE is therefore the live age of
      a `status=in_progress` run, never a statistic over finished work.
  (b) Completed-run history is still the right population for the THRESHOLD. Completed runs
      answer HOW LONG IS NORMAL; only live runs answer IS SOMETHING STUCK NOW. Never let
      (b) drift into (a).
  (c) FAIL-OPEN HOLE, closed deliberately: a lane whose runs never complete has no
      baseline. Skipping such a lane would go silent exactly when it is 100% hung, so a
      missing baseline falls back to EXEC_FLOOR_SECONDS instead of skipping.

REQUEST BUDGET. This repo's dispatch tick budget is a live constraint (a measured 403 at
~7969 requests/h). One watchdog pass costs 1 workflow listing + one schedule-run query per
scheduled lane (9) + 2 live-state queries + at most one baseline query per DISTINCT
(workflow, event) with a live in-progress run — order 15-20 requests, hourly-equivalent,
against a 613/tick dispatch budget. It also never walks the repo-wide `actions/runs`
listing, which is capped at 1000 results and is exhausted by under six hours of this
repo's volume.

NOT A PAGER FOR THE COMMIT UNDER TEST. Hosted as its own job in groom.yml with NO `needs:`
and NO `if:` — a watcher hosted inside the watched job cannot observe the watched job's
absence — and the alert step carries `continue-on-error: true`, matching the sibling
watchdogs, so a watchdog fault can never red the grooming sweep. The SIGNAL is a rolling
`ops-alert` issue per mode, closed on explicit recovery.

NO ARMING AUTHORITY, STRUCTURALLY. `actions: read` + `contents: read` + `issues: write`.
It has no code path that writes a hold/role/status label; in particular it NEVER applies
`needs:user` or anything else that would remove a PR from the review loop.

Usage:
  ci-latency-alert.py                                   # live
  ci-latency-alert.py --dry-run                         # report; no issue writes
  ci-latency-alert.py --state-file s.json --now ...     # hermetic
  ci-latency-alert.py --self-test                       # hermetic fixtures
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError as _exc:  # pragma: no cover - fail loud rather than skip M1
    yaml = None
    _YAML_IMPORT_ERROR = _exc

ALERT_LABEL = "ops-alert"
MARKER_PREFIX = "ci-latency-alert:v1"
MAINTAINER_HANDLE = os.environ.get("MAINTAINER_HANDLE", "jeswr")

# KEEP IN SYNC with the sparse-checkout in groom.yml's `ci-latency` job. The self-test
# asserts both directions, so a checkout that drops an input reds instead of making the
# YAML-seam assertions silently unreachable on the live path.
REQUIRED_FILES = (
    "scripts/ci-latency-alert.py",
    ".github/workflows/groom.yml",
)
GROOM_WORKFLOW = ".github/workflows/groom.yml"
WORKFLOWS_DIR = ".github/workflows"


class AlarmError(RuntimeError):
    """The detector itself is broken. Never mask a choke."""


class CronError(ValueError):
    """An unparseable cron. Fail-safe QUIET, but COUNTED in the census."""


# --- M1 -----------------------------------------------------------------------------
# WINDOW 24h. A 6h window was tried and rejected: a daily lane's expectation swings
# between 0 and 1 on jitter alone.
CRON_WINDOW_HOURS = 24.0
# THE CAP, measured on THIS repo and deliberately NOT inherited from the sparq deployment.
# MEASURED over the 24h to 2026-07-28T12:41Z, event-filtered, per lane:
#   conflict-resolver nominal 71 -> 27 | curate 48 -> 27 | dashboard 95 -> 29
#   dispatch 143 -> 31 | groom-leases 95 -> 30 | groom 95 -> 31 | metrics 95 -> 30
#   retriage 47 -> 26
# Every sub-hourly lane converges to 26-31 runs/day REGARDLESS of its cron, because
# GitHub's `schedule` trigger is best-effort and dropped under load. Comparing against
# nominal would put all eight lanes permanently in breach, and a permanently-red alarm is
# a muted alarm. So the expectation is capped at what GitHub demonstrably delivers here.
# 1.25/h = 30 per 24h; the most any lane actually achieved was 31.
# NOTE the sparq deployment measures 0.5/h on the same statistic. The ceiling is a
# property of the REPOSITORY's load, not a constant — do not copy one to the other.
CRON_MAX_CREDIBLE_FIRINGS_PER_HOUR = 1.25
# Ignore firings younger than this, or the window edge races the scheduler and every tick
# landing near a lane's cron minute manufactures a phantom deficit.
CRON_GRACE_MINUTES = 15
CRON_MIN_EXPECTED = 1
# VALIDATED: across the 8 covered scheduled lanes the MINIMUM capped delivery ratio is
# 0.87 (retriage, 26 of a capped 30), so 0.60 sits 0.27 below the worst healthy lane and
# fires on ZERO of them — while still catching a lane that stops entirely (0.00) or halves
# its achieved rate (0.50).
CRON_DELIVERY_FLOOR = 0.60

# --- M2 -----------------------------------------------------------------------------
#
# THE RE-RUN TRAP — read before touching anything in this mode.
# `created_at` on the RUN-level object is the creation time of ATTEMPT 1 and does NOT
# reset when a run is re-run, while `run_attempt` and `run_started_at` DO track the live
# attempt. MEASURED 2026-07-28 on THIS repo, run 30318886362:
#     run-level    run_attempt=2  created_at=00:58:13Z  run_started_at=02:37:40Z
#     /attempts/1                 created_at=00:58:13Z  run_started_at=00:58:13Z   0s
#     /attempts/2                 created_at=02:37:41Z  run_started_at=02:37:40Z   0s
# Neither attempt ever queued. The 99-minute "wait" is the IDLE GAP between attempt 1
# failing at 01:00Z and a re-run being pressed at 02:37Z. Executed on that exact payload,
# `now - run["created_at"]` reports waited_seconds=5967 for an attempt picked up in under
# a second — so the naive form fires on EVERY re-run older than the threshold, which is
# the normal case, and a permanently-red alarm is a muted alarm. `attempt_created_at()`
# below is the fix. Do not reintroduce a bare `run.get("created_at")` here.
#
# THRESHOLD — and an HONEST statement of what does and does not support it.
# WITHDRAWN: an earlier revision claimed "15 min fires on 6 of 3,920 runs (0.153%) — and
# those six are NOT false positives, they are the real 00:58Z-02:24Z `pr-gate` queue
# event". Both halves were wrong. The six were produced by the contaminated estimator,
# and the "queue event" was seven `run_attempt: 2` re-runs pressed in a single batch at
# 02:35-02:37Z. That evidence is retracted.
#
# RE-DERIVED 2026-07-28 over a per-workflow scan (the repo-wide `actions/runs` listing
# hard-caps at 1000), splitting on `run_attempt` and resolving every re-run's TRUE wait
# against its own `/attempts/{n}` record:
#
#                                   jeswr/agent-account-registry   sparq-org/sparq
#   completed runs scanned                                 9,062            35,128
#   contaminated estimator, over 15 min                        6                 7
#     ... of which are RE-RUNS                           6 (ALL)           7 (ALL)
#   DECONTAMINATED (run_attempt == 1)                      9,053            35,070
#     over 15 min                                              0                 0
#     with ANY non-zero wait at all                            0                 0
#     maximum observed wait                                 0.0s              0.0s
#   re-runs resolved per-attempt                               9                58
#     over 15 min                                              0                 0
#     true maximum wait                                    -1.0s             -1.0s
#
# Every single row the old estimator flagged, on BOTH repos, was a re-run artefact. Across
# 44,190 completed runs there is not ONE attempt whose own queue wait was even non-zero.
#
# SO M2 HAS NO VALIDATED KNOWN POSITIVE. There is no run in the observed corpus that this
# mode would have fired on. Two consequences that must not be lost:
#
#   (i)  The threshold CANNOT be derived from the observed distribution. After
#        decontamination it is not zero-INFLATED, it is exactly ALL ZERO across 9,053
#        runs — there is no percentile, multiple or maximum to anchor to. The corpus
#        constrains this constant from BELOW only (any value above 0 has a measured
#        false-positive rate of 0); it says nothing about where in that half-line to sit.
#        15 min is a JUDGMENT about how long a human should wait before being told, not a
#        measurement, and is labelled as such.
#   (ii) The corpus proxy is itself weak. `run_started_at - created_at` is a RUN-level
#        statistic, and the measurement trap in the header is precisely that a run whose
#        jobs are throttled behind `max-parallel` reads `status=queued` ZERO for hours. A
#        zero here is consistent with "no queueing happened" AND with "the API does not
#        express the queueing that happened". It cannot distinguish them.
#
# M2 therefore ships as an UNVALIDATED detector for the maintainer's stated concern, with
# a measured false-positive rate of 0 over N=9,053 and no demonstrated true positive. It
# is cheap (it reads live state already fetched for M3) and it is the only watcher on
# `status=queued` at all. It is not evidence that queue waits are being caught.
QUEUE_MAX_WAIT_SECONDS = 15 * 60
# Key the fetch layer writes onto a queued run whose live attempt is NOT attempt 1: the
# `created_at` of that attempt's own `/attempts/{n}` record. Absent on attempt-1 runs by
# design — for those the run-level field IS the attempt's field.
ATTEMPT_CREATED_KEY = "_attempt_created_at"

# --- M3 -----------------------------------------------------------------------------
# Threshold = max(MULTIPLE x p90(completed durations for this workflow+event), FLOOR).
# VALIDATED by a leave-one-out sweep over the event-filtered completed-run corpus for this
# repo, N=2,063 runs / 30 cells: ZERO fires at K = 1.25 .. 3.0, i.e. no healthy historical
# run alarms at any candidate multiple. INSTRUMENT VALIDATED AGAINST A KNOWN ANSWER before
# that zero was trusted — injecting one synthetic run at 2.5x a cell's p90 DOES fire at
# K=2.0, so the zero is a real zero and not a broken sweep. 2.0 is carried from the sparq
# deployment, where it is the LARGEST multiple that still detects the real 2026-07-27
# 17.33h outlier (K=2.5 misses it).
EXEC_OVERRUN_MULTIPLE = 2.0
# 6h is GitHub's hosted-runner per-job ceiling, so a RUN alive past it has outlived any
# single job's maximum possible life. It also makes M3 immune to this repo's BIMODAL
# dispatch durations (a within-floor no-op tick concludes success in ~30s while a real tick
# runs minutes): both modes are far below the floor, so the floor governs and the p90's
# position between the modes never matters.
EXEC_FLOOR_SECONDS = 6 * 60 * 60
BASELINE_SAMPLE = 100
BASELINE_MIN_N = 5
RUNS_PAGE_CAP = 10

INVISIBLE_TRIGGERS = frozenset({"schedule", "workflow_dispatch"})


# ---------------------------------------------------------------------------------
# cron expansion
# ---------------------------------------------------------------------------------
def _expand_field(spec: str, lo: int, hi: int) -> set[int]:
    """Expand one cron field to the set of values it matches."""
    if not spec:
        raise CronError("empty field")
    out: set[int] = set()
    for part in spec.split(","):
        if not part:
            raise CronError(f"empty list element in {spec!r}")
        step = 1
        if "/" in part:
            part, raw = part.split("/", 1)
            if not raw.isdigit():
                raise CronError(f"bad step in {spec!r}")
            step = int(raw)
            if step <= 0:
                raise CronError(f"non-positive step in {spec!r}")
        if part in ("*", "?"):
            a, b = lo, hi
        elif "-" in part:
            lhs, rhs = part.split("-", 1)
            if not (lhs.isdigit() and rhs.isdigit()):
                raise CronError(f"bad range in {spec!r}")
            a, b = int(lhs), int(rhs)
            if a > b:
                raise CronError(f"inverted range in {spec!r}")
        else:
            if not part.isdigit():
                raise CronError(f"not a number: {part!r}")
            a = b = int(part)
        out |= set(range(a, b + 1, step))
    out = {v for v in out if lo <= v <= hi}
    if not out:
        raise CronError(f"field matches nothing: {spec!r}")
    return out


def expected_firings(expr: str, start: dt.datetime, end: dt.datetime) -> int:
    """How many times `expr` fires in (start, end]. Minute-resolution walk.

    POSIX day semantics: when BOTH day-of-month and day-of-week are restricted the match
    is their UNION, not their intersection.
    """
    if not isinstance(expr, str):
        raise CronError(f"not a string: {expr!r}")
    fields = expr.split()
    if len(fields) != 5:
        raise CronError(f"expected 5 fields, got {len(fields)}: {expr!r}")
    minute, hour, dom, month, dow = fields
    mins = _expand_field(minute, 0, 59)
    hours = _expand_field(hour, 0, 23)
    doms = _expand_field(dom, 1, 31)
    months = _expand_field(month, 1, 12)
    dows = {d % 7 for d in _expand_field(dow, 0, 7)}
    dom_wild = dom.strip() in ("*", "?")
    dow_wild = dow.strip() in ("*", "?")
    if (end - start) > dt.timedelta(days=400):
        raise CronError("window too wide to expand")

    t = start.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    n = 0
    while t <= end:
        if t.minute in mins and t.hour in hours and t.month in months:
            weekday = (t.weekday() + 1) % 7  # cron: Sunday == 0
            if dom_wild and dow_wild:
                day_ok = True
            elif dom_wild:
                day_ok = weekday in dows
            elif dow_wild:
                day_ok = t.day in doms
            else:
                day_ok = (t.day in doms) or (weekday in dows)
            if day_ok:
                n += 1
        t += dt.timedelta(minutes=1)
    return n


# ---------------------------------------------------------------------------------
# workflow scope
# ---------------------------------------------------------------------------------
def workflow_triggers(text: str) -> dict:
    """-> the parsed `on:` mapping. `on` is YAML 1.1 `true`, hence the two-key lookup."""
    if yaml is None:  # pragma: no cover
        raise AlarmError(f"PyYAML unavailable: {_YAML_IMPORT_ERROR}")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AlarmError(f"unparseable workflow YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise AlarmError("workflow YAML is not a mapping")
    on = doc.get(True, doc.get("on"))
    return on if isinstance(on, dict) else {}


def m1_scope(on: dict) -> tuple[bool, list[str], bool]:
    """-> (in_m1_scope, cron expressions, is_cron_only).

    SCOPE DIFFERS FROM THE sparq DEPLOYMENT, deliberately. In sparq-org/sparq this is
    the set COMPLEMENT of #4368's `cron_lane_liveness.py`, because that detector already
    owns the cron-only lanes there. This repository has NO cron_lane_liveness counterpart
    — its watchdog ring (`dispatch-stall-alert`, `metrics-alert --stale-check`,
    `cron-keepalive`) watches named lanes for LIVENESS, not cron DELIVERY, and covers 6 of
    the 9 scheduled lanes by name. So here M1 watches EVERY scheduled lane, and
    `cron_only` is reported for information only.
    """
    if "schedule" not in on:
        return False, [], False
    sched = on.get("schedule") or []
    crons = [s.get("cron") for s in sched
             if isinstance(s, dict) and isinstance(s.get("cron"), str)]
    cron_only = set(on) <= INVISIBLE_TRIGGERS
    return bool(crons), crons, cron_only


# ---------------------------------------------------------------------------------
# detectors — pure functions over already-fetched state
# ---------------------------------------------------------------------------------
def find_cron_deficits(lanes: list[dict], now: dt.datetime,
                       window_hours: float = CRON_WINDOW_HOURS) -> tuple[list[dict], dict]:
    """M1. `lanes` = [{workflow, crons, cron_only, in_scope, state, schedule_run_times}].

    The census counts EVERY state exit, not just the alarming one: a per-state population
    is the only shape in which a MISSING edge is visible at all.
    """
    start = now - dt.timedelta(hours=window_hours)
    # The window ENDS a grace period before `now`, so a firing whose run may not have been
    # created yet is not counted as missing. Without this the tick that lands on a lane's
    # own cron minute manufactures a deficit for that lane, every day.
    end = now - dt.timedelta(minutes=CRON_GRACE_MINUTES)
    # What GitHub will actually deliver in a window of this length. Nominal cron rate is
    # not an expectation for sub-hourly lanes — see the constant's note.
    ceiling = int(CRON_MAX_CREDIBLE_FIRINGS_PER_HOUR * window_hours)
    findings: list[dict] = []
    census: dict[str, int] = {}

    def bump(state: str) -> None:
        census[state] = census.get(state, 0) + 1

    for lane in lanes:
        if not lane.get("in_scope"):
            bump("not-scheduled")
            continue
        if lane.get("state") != "active":
            bump("disabled")
            continue
        # NEW-LANE WINDOW. A lane that did not EXIST for the whole window looks identical
        # to a lane that stopped firing: out of run times alone the detector cannot tell
        # "did not fire" from "did not exist yet", so a lane added two hours ago reads far
        # below the floor and alarms for the next ~14 hours. The workflow's own
        # `created_at` (carried on the `actions/workflows` listing) is the signal that
        # resolves it.
        # PRORATING THE EXPECTATION WAS TRIED AND REJECTED: scaling the cap by the lane's
        # observed lifetime gives a young lane an expectation of ~2, and at a floor of
        # 0.60 a single undelivered firing (1 of 2) still alarms. A prorated expectation
        # is not a smaller measurement, it is noise — the cap it derives from is itself a
        # RATE measured over a full 24h, and GitHub's delivery is bursty at short scales.
        # So a lane younger than the window is COUNTED and skipped, never guessed at; it
        # becomes watchable one window after it appears. The gap is deliberate, bounded,
        # and visible in the census rather than silent.
        created = lane.get("created_at")
        if created:
            born = created if isinstance(created, dt.datetime) else _ts(created)
            if born > start:
                bump("lane-too-new-for-an-expectation")
                continue
        try:
            nominal = sum(expected_firings(c, start, end) for c in lane["crons"])
        except CronError:
            bump("cron-unparseable")
            continue
        expected = min(nominal, ceiling)
        if expected < CRON_MIN_EXPECTED:
            bump("expectation-below-floor")
            continue
        actual = sum(1 for t in lane["schedule_run_times"] if start < t <= end)
        # No clamp on `actual`: an over-delivering lane gives a ratio above 1.0, which is
        # >= the floor and therefore healthy either way. A `min(actual, expected)` here
        # was removed after its own mutant SURVIVED — it changed no observable output, so
        # it was dead code, and an untestable guard is worse than no guard.
        ratio = actual / expected
        if ratio < CRON_DELIVERY_FLOOR:
            bump("firing-deficit")
            findings.append({
                "mode": "M1-cron-firing-deficit",
                "workflow": lane["workflow"],
                "expected": expected,
                "nominal": nominal,
                "actual": actual,
                "ratio": round(ratio, 3),
                "window_hours": window_hours,
                "crons": lane["crons"],
            })
        else:
            bump("delivering")
    return findings, census


def attempt_created_at(run: dict) -> str | None:
    """The creation time of the run's CURRENTLY-EXECUTING attempt, or None if it cannot
    be determined.

    This is NOT `run["created_at"]`. See the RE-RUN TRAP note on QUEUE_MAX_WAIT_SECONDS:
    the run-level `created_at` is frozen at attempt 1 and does not reset on re-run, so
    reading it for a re-run charges the idle gap before the re-run press as queue wait.

    Attempt 1 -> the run-level field IS the attempt's field (MEASURED equal on all 9,053
    attempt-1 runs in this repo's corpus). Attempt N>1 -> the value the fetch layer
    resolved from `/actions/runs/{id}/attempts/{n}`; None when that resolution was
    unavailable, which the caller must treat as INDETERMINATE and count, never as the
    run-level value.
    """
    if int(run.get("run_attempt") or 1) > 1:
        return run.get(ATTEMPT_CREATED_KEY) or None
    return run.get("created_at") or None


def find_queue_overruns(live_runs: list[dict], now: dt.datetime,
                        max_wait: float = QUEUE_MAX_WAIT_SECONDS
                        ) -> tuple[list[dict], dict]:
    """M2. Runner availability proper: a run still in `queued` past `max_wait`."""
    findings: list[dict] = []
    census: dict[str, int] = {}

    def bump(state: str) -> None:
        census[state] = census.get(state, 0) + 1

    for run in live_runs:
        if run.get("status") != "queued":
            continue
        created = attempt_created_at(run)
        if not created:
            # A re-run whose own attempt record could not be resolved is INDETERMINATE.
            # Fail-safe QUIET but COUNTED: the run-level `created_at` is available and
            # known-wrong here, and firing a known-false alarm is worse than a visible
            # gap. Two distinct census states so the two causes stay separable.
            bump("queued-rerun-attempt-unresolved"
                 if int(run.get("run_attempt") or 1) > 1 else "queued-no-timestamp")
            continue
        waited = (now - _ts(created)).total_seconds()
        if waited > max_wait:
            bump("queued-over-threshold")
            findings.append({
                "mode": "M2-queue-wait",
                "workflow": run.get("name") or run.get("path") or "?",
                "run_id": run.get("id"),
                "event": run.get("event"),
                "waited_seconds": int(waited),
                "threshold_seconds": int(max_wait),
                "run_attempt": int(run.get("run_attempt") or 1),
                "head_branch": run.get("head_branch"),
            })
        else:
            bump("queued-within-threshold")
    return findings, census


def find_execution_overruns(live_runs: list[dict], baselines: dict, now: dt.datetime,
                            multiple: float = EXEC_OVERRUN_MULTIPLE,
                            floor: float = EXEC_FLOOR_SECONDS
                            ) -> tuple[list[dict], dict]:
    """M3. A run `in_progress` past its own lane's measured duration.

    DETECTION VARIABLE is the live age of an in-flight run — deliberately NOT any
    statistic over completed runs, which structurally excludes the hangs this exists to
    catch (header note (a)).

    `baselines` maps (workflow_key, event) -> {"p90": seconds, "n": int}. A missing or
    under-sampled baseline falls back to `floor` and is REPORTED as such; it must never
    cause a `continue`, or a lane whose runs never complete would be unwatchable by its
    own detector (header note (c)).
    """
    findings: list[dict] = []
    census: dict[str, int] = {}

    def bump(state: str) -> None:
        census[state] = census.get(state, 0) + 1

    for run in live_runs:
        if run.get("status") != "in_progress":
            continue
        started = run.get("run_started_at") or run.get("created_at")
        if not started:
            bump("in-progress-no-timestamp")
            continue
        age = (now - _ts(started)).total_seconds()
        key = (run.get("path") or run.get("name") or "?", run.get("event"))
        base = baselines.get(key) or {}
        n = int(base.get("n") or 0)
        p90 = base.get("p90")
        if p90 is None or n < BASELINE_MIN_N:
            threshold = floor
            basis = f"floor (no usable baseline; n={n})"
        else:
            threshold = max(multiple * float(p90), floor)
            basis = f"max({multiple}x p90={int(p90)}s over n={n}, floor)"
        if age > threshold:
            bump("execution-overrun")
            findings.append({
                "mode": "M3-execution-overrun",
                "workflow": run.get("name") or run.get("path") or "?",
                "run_id": run.get("id"),
                "event": run.get("event"),
                "age_seconds": int(age),
                "threshold_seconds": int(threshold),
                "basis": basis,
                "head_branch": run.get("head_branch"),
            })
        else:
            bump("in-progress-within-threshold")
    return findings, census


def _ts(value: str) -> dt.datetime:
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise AlarmError(f"unparseable timestamp {value!r}: {exc}") from exc


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]


# ---------------------------------------------------------------------------------
# gh plumbing — mirrors scripts/dispatch-stall-alert.py
# ---------------------------------------------------------------------------------
def _gh(args, capture=False, token=None, check=False, label="ci-latency"):
    # Sanitized fail-loud wrapper: op + returncode only — never stderr (GH_DEBUG=api can
    # echo request bodies) and never argument content beyond the gh subcommand words.
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env,
                            check=False)
    if check and result.returncode != 0:
        print(f"::warning::{label}: gh {args[0]} "
              f"{args[1] if len(args) > 1 else ''} failed (rc={result.returncode})")
    return result


def _gh_json(args, label="ci-latency"):
    result = _gh(args, capture=True, check=True, label=label)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout or "null")
    except ValueError:
        print(f"::warning::{label}: gh {args[0]} succeeded but returned unparseable JSON")
        return None


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) for the alert issue — locked decision 22c / issue #39, identical
    semantics and signature to scripts/dispatch-stall-alert.py's private copy: the private
    ALERT_REPO is the destination ONLY when ALERT_TOKEN can write there; a half-configured
    deployment (repo set, token missing) falls back to the registry repo under the ambient
    token instead of silently losing the alert."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def _api(repo, path):
    payload = _gh_json(["api", "-H", "Accept: application/vnd.github+json",
                        f"/repos/{repo}/{path}"])
    if payload is None:
        raise AlarmError(f"gh api /repos/{repo}/{path} failed or returned no JSON")
    return payload


def resolve_attempt_created(repo, runs):
    """Enrich every QUEUED run whose live attempt is not attempt 1 with that attempt's own
    `created_at`, under ATTEMPT_CREATED_KEY.

    WITHOUT THIS CALL M2 IS A FALSE-POSITIVE GENERATOR — see the RE-RUN TRAP note. It is
    a separate pass rather than logic inside `find_queue_overruns` so the detectors stay
    pure functions over already-fetched state and remain hermetically testable.

    REQUEST COST is zero in the common case, which matters against this repo's live
    request budget: the pass touches only `queued` runs at attempt > 1. MEASURED over a
    9,062-run per-workflow scan on 2026-07-28, re-runs were 9 of 9,062 (0.1%), and the
    `queued` population is normally empty. A failed lookup leaves the key absent, which
    the detector counts as `queued-rerun-attempt-unresolved` rather than falling back to
    the known-wrong value.
    """
    for run in runs:
        if run.get("status") != "queued":
            continue
        attempt = int(run.get("run_attempt") or 1)
        if attempt <= 1 or not run.get("id"):
            continue
        try:
            payload = _api(repo, f"actions/runs/{run['id']}/attempts/{attempt}")
        except AlarmError:
            # Quiet + counted downstream. One unresolvable attempt record must not abort
            # the whole tick and take M1 and M3 down with it.
            continue
        if isinstance(payload, dict) and payload.get("created_at"):
            run[ATTEMPT_CREATED_KEY] = payload["created_at"]
    return runs


def fetch_live_runs(repo):
    """Every run currently `queued` or `in_progress` — the LIVE read M2 and M3 key on.
    Terminates on a SHORT page, never on `len >= total_count`: a total_count read before a
    new run started is an undercount and stopping on it truncates while the list grows."""
    live = []
    for status in ("queued", "in_progress"):
        page = 1
        while page <= RUNS_PAGE_CAP:
            payload = _api(repo, f"actions/runs?status={status}&per_page=100&page={page}")
            batch = payload.get("workflow_runs")
            if batch is None:
                raise AlarmError("workflow-run listing carries no workflow_runs")
            live.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        else:
            raise AlarmError(f"live `{status}` listing exceeded {RUNS_PAGE_CAP} pages")
    return resolve_attempt_created(repo, live)


def fetch_baseline(repo, workflow_path, event):
    """p90 of COMPLETED-run duration for one (workflow, event). Completed runs are the
    right population for "how long is normal" and the WRONG one for "is it stuck"."""
    wf = workflow_path.split("/")[-1]
    payload = _api(repo, f"actions/workflows/{wf}/runs"
                         f"?status=completed&event={event}&per_page={BASELINE_SAMPLE}")
    runs = payload.get("workflow_runs")
    if runs is None:
        raise AlarmError(f"{wf}: baseline response carries no workflow_runs")
    durations = []
    for run in runs:
        started, updated = run.get("run_started_at"), run.get("updated_at")
        if not (started and updated):
            continue
        delta = (_ts(updated) - _ts(started)).total_seconds()
        if delta >= 0:
            durations.append(delta)
    if not durations:
        return {"p90": None, "n": 0}
    return {"p90": percentile(durations, 0.90), "n": len(durations)}


def fetch_lanes(repo, root, window_hours, now):
    wf_dir = Path(root) / WORKFLOWS_DIR
    if not wf_dir.is_dir():
        raise AlarmError(f"no workflows directory at {wf_dir}")
    listing = _api(repo, "actions/workflows?per_page=100")
    if listing.get("workflows") is None:
        raise AlarmError("workflow listing carries no workflows")
    state_by_path = {w["path"]: w.get("state") for w in listing["workflows"]}
    # The lane's own birth date, which is the ONLY thing that separates "did not fire"
    # from "did not exist yet" — see the NEW-LANE WINDOW note in find_cron_deficits.
    created_by_path = {w["path"]: w.get("created_at") for w in listing["workflows"]}
    start = now - dt.timedelta(hours=window_hours)
    lanes = []
    for path in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        rel = f"{WORKFLOWS_DIR}/{path.name}"
        on = workflow_triggers(path.read_text(encoding="utf-8"))
        in_scope, crons, cron_only = m1_scope(on)
        lane = {"workflow": rel, "crons": crons, "cron_only": cron_only,
                "in_scope": in_scope, "state": state_by_path.get(rel, "active"),
                "created_at": created_by_path.get(rel),
                "schedule_run_times": []}
        if in_scope and lane["state"] == "active":
            payload = _api(repo, f"actions/workflows/{path.name}/runs"
                                 f"?event=schedule&per_page=100")
            runs = payload.get("workflow_runs")
            if runs is None:
                raise AlarmError(f"{path.name}: schedule-run response carries no runs")
            times = [_ts(r["created_at"]) for r in runs if r.get("created_at")]
            # COVERAGE GUARD: the sample is the newest 100 runs. If the OLDEST sampled run
            # is NEWER than the window start the count is TRUNCATED and would manufacture a
            # phantom deficit. Treat as indeterminate, never as 0.
            if times and min(times) > start and len(times) >= 100:
                lane["in_scope"] = False
                lane["truncated"] = True
            lane["schedule_run_times"] = times
        lanes.append(lane)
    return lanes


# ---------------------------------------------------------------------------------
# alert transport — one rolling ops-alert per mode, closed on explicit recovery
# ---------------------------------------------------------------------------------
def marker(mode):
    return f"<!-- {MARKER_PREFIX} key={mode} -->"


def title_for(mode):
    return f"ci-latency: {mode} breached its measured threshold"


def render_body(mode, repo, findings, census, now, run_url):
    lines = [
        marker(mode),
        "> 🤖 SPARQ agent — automated ops-alert (CI execution latency)",
        "",
        f"`{mode}` breached its measured threshold in `{repo}` at "
        f"`{now:%Y-%m-%dT%H:%M:%SZ}`.",
        "",
    ]
    for f in findings:
        if mode.startswith("M1"):
            lines.append(
                f"- `{f['workflow']}` fired **{f['actual']}** of an achievable "
                f"**{f['expected']}** in {f['window_hours']:g}h (nominal "
                f"{f['nominal']}, ratio {f['ratio']}, floor {CRON_DELIVERY_FLOOR}); "
                f"cron `{' | '.join(f['crons'])}`")
        elif mode.startswith("M2"):
            lines.append(
                f"- `{f['workflow']}` run {f['run_id']} ({f['event']}) queued "
                f"**{f['waited_seconds'] // 60} min**, threshold "
                f"{f['threshold_seconds'] // 60} min")
        else:
            lines.append(
                f"- `{f['workflow']}` run {f['run_id']} ({f['event']}) in progress "
                f"**{f['age_seconds'] // 60} min**, threshold "
                f"{f['threshold_seconds'] // 60} min — basis: {f['basis']}")
    lines += ["", "**Census of every state exit** (emitted every run, including the "
              "all-clear — a silent alarm is indistinguishable from a healthy system):",
              "", "```"]
    lines += [f"{k}: {v}" for k, v in sorted(census.items())]
    lines += ["```", "", f"Watchdog run: {run_url}", f"cc @{MAINTAINER_HANDLE}"]
    return "\n".join(lines)


def _find_open_alert(repo, token, mode):
    """-> (issue_number|None, hard_error, soft_skip). --limit 100: the `ops-alert` label is
    SHARED with every other ops alert, and a 30-issue default window could push this one
    out of the dedupe scan (duplicate on failure, uncloseable on recovery)."""
    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"],
                 capture=True, token=token, check=True)
    if listed.returncode != 0:
        return None, True, False
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:
        print("::warning::ci-latency: gh issue list returned unparseable JSON — skipping "
              "this tick (no dedupe/recovery data; next tick retries)")
        return None, False, True
    num = next((i["number"] for i in found if marker(mode) in (i.get("body") or "")), None)
    if num is None:
        num = next((i["number"] for i in found if i.get("title") == title_for(mode)), None)
    return num, False, False


def _apply(action, repo, token, num, mode, body, note):
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token)  # idempotent
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token, check=True)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", title_for(mode),
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True)
        return 1 if wrote.returncode != 0 else 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body", note],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo],
                     capture=True, token=token, check=True)
        return 1 if (commented.returncode != 0 or closed.returncode != 0) else 0
    return 0


def decide(findings, open_issue):
    """Pure: -> 'upsert' | 'close' | 'noop'. Closing happens ONLY on an explicit
    recovery (findings empty AND an alert is open); an indeterminate read is a noop, so a
    transient API failure can never silently close a live alert."""
    if findings:
        return "upsert"
    return "close" if open_issue else "noop"


# ---------------------------------------------------------------------------------
# hermetic self-test — enrolled in scripts/selftest-suite.txt, run by pr-gate's `gate`
# job, and run as the FIRST step of every watchdog tick.
# ---------------------------------------------------------------------------------
def capped_expectation(window_hours=CRON_WINDOW_HOURS):
    """Exposed so assertions use the DERIVED value: a test that hard-codes 30 would go
    green-but-wrong if the measured ceiling changed."""
    return int(CRON_MAX_CREDIBLE_FIRINGS_PER_HOUR * window_hours)


def _lane(workflow="a.yml", crons=("*/10 * * * *",), cron_only=False, in_scope=True,
          state="active", fires=0, now=None, spacing_min=20, created_hours_ago=None):
    """`created_hours_ago` gives the lane a birth date, for the NEW-LANE WINDOW. `None`
    means an established lane (no `created_at`), which must behave exactly as before."""
    now = now or dt.datetime(2026, 7, 28, 12, 0, tzinfo=dt.timezone.utc)
    first = now - dt.timedelta(minutes=CRON_GRACE_MINUTES + 1)
    lane = {"workflow": workflow, "crons": list(crons), "cron_only": cron_only,
            "in_scope": in_scope, "state": state,
            "schedule_run_times": [first - dt.timedelta(minutes=spacing_min * i)
                                   for i in range(fires)]}
    if created_hours_ago is not None:
        lane["created_at"] = (now - dt.timedelta(hours=created_hours_ago)
                              ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return lane


def _run_obj(status="in_progress", event="schedule", path=".github/workflows/a.yml",
             age_min=10, now=None, name="A", attempt=1, created_age_min=None,
             attempt_created_age_min=None):
    """The REAL shape of an `actions/runs` element, not a minimal hand-built dict.

    A narrow fixture is a vacuity generator. `started = run.get("updated_at") or
    run_started_at` SURVIVED the first mutation battery for exactly one reason: no fixture
    carried `updated_at`, while EVERY live run does — and on a live run `updated_at` is
    bumped continuously, so that mutant collapses M3's age to ~0 and the mode never fires
    again. The keys and their relationships below are taken from a real payload
    (this repo's run 30318886362).

    `created_age_min` exists to reproduce the RE-RUN shape, where the run-level
    `created_at` is FROZEN at attempt 1 while `run_started_at` tracks the live attempt.
    """
    now = now or dt.datetime(2026, 7, 28, 12, 0, tzinfo=dt.timezone.utc)

    def stamp(minutes):
        return (now - dt.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    obj = {
        "id": 1, "name": name, "path": path, "event": event, "status": status,
        "conclusion": None, "run_attempt": attempt, "workflow_id": 99, "run_number": 7,
        "display_title": name, "head_branch": "master", "head_sha": "0" * 40,
        "created_at": stamp(created_age_min if created_age_min is not None else age_min),
        "run_started_at": stamp(age_min),
        # A LIVE run's `updated_at` tracks the PRESENT moment, which is what makes it a
        # catastrophic substitute for `run_started_at` in M3.
        "updated_at": stamp(0) if status != "completed" else stamp(age_min),
        "html_url": "https://example.invalid/run/1",
    }
    if attempt_created_age_min is not None:
        obj[ATTEMPT_CREATED_KEY] = stamp(attempt_created_age_min)
    return obj


def _self_test():  # noqa: C901 - a flat table of named assertions reads best flat
    failures = []

    def chk(name, condition):
        if not condition:
            failures.append(name)

    NOW = dt.datetime(2026, 7, 28, 12, 0, tzinfo=dt.timezone.utc)
    H6 = NOW - dt.timedelta(hours=6)
    D1 = NOW - dt.timedelta(hours=24)
    CAP = capped_expectation()

    # --- THE CONSTANTS, pinned against LITERALS that do not derive from them ----------
    # Every threshold here was previously exercised only through fixtures COMPUTED FROM
    # the constant, so the fixture rescaled with the mutant and the mutant survived.
    # MEASURED instances on this file: `CRON_DELIVERY_FLOOR 0.60 -> 0.05` survived the
    # entire self-test because `at_floor = ceil(CAP * FLOOR)` moved with it and CAP=30
    # leaves `fires=1` at ratio 0.033, still below 0.05; and `CRON_WINDOW_HOURS
    # 24.0 -> 6.0` survived — 6.0 being the value the header says was TRIED AND REJECTED.
    # A constant is only pinned by a value written down independently of it.
    chk("CRON_WINDOW_HOURS is 24h — the value the rejected 6h trial was replaced by",
        CRON_WINDOW_HOURS == 24.0)
    chk("CRON_DELIVERY_FLOOR is inside its validated band (worst healthy lane 0.87)",
        0.50 <= CRON_DELIVERY_FLOOR <= 0.70)
    chk("CRON_MAX_CREDIBLE_FIRINGS_PER_HOUR matches THIS repo's measured ceiling "
        "(1.25/h = 30/day; the sparq deployment's 0.5 is a different repo's load)",
        CRON_MAX_CREDIBLE_FIRINGS_PER_HOUR == 1.25)
    chk("CRON_GRACE_MINUTES is 15", CRON_GRACE_MINUTES == 15)
    chk("QUEUE_MAX_WAIT_SECONDS is 15 minutes", QUEUE_MAX_WAIT_SECONDS == 15 * 60)
    chk("EXEC_OVERRUN_MULTIPLE is inside the band that still catches the 2.08x outlier",
        1.25 <= EXEC_OVERRUN_MULTIPLE <= 2.0)
    chk("EXEC_FLOOR_SECONDS is GitHub's 6h hosted-runner job ceiling",
        EXEC_FLOOR_SECONDS == 6 * 60 * 60)
    chk("BASELINE_MIN_N is 5", BASELINE_MIN_N == 5)

    # --- cron expansion, canary-validated against hand-computed answers ---
    chk("cron */10 over 6h == 36", expected_firings("*/10 * * * *", H6, NOW) == 36)
    chk("cron */10 over 24h == 144", expected_firings("*/10 * * * *", D1, NOW) == 144)
    chk("cron 17 3 * * * over 24h == 1", expected_firings("17 3 * * *", D1, NOW) == 1)
    chk("cron 3,13,23,33,43,53 over 6h == 36",
        expected_firings("3,13,23,33,43,53 * * * *", H6, NOW) == 36)
    chk("cron 7-59/15 over 24h == 96",
        expected_firings("7-59/15 * * * *", D1, NOW) == 96)
    chk("cron 17,47 over 24h == 48", expected_firings("17,47 * * * *", D1, NOW) == 48)
    chk("cron weekly Monday absent from a Tuesday 24h window",
        expected_firings("41 6 * * 1", D1, NOW) == 0)
    chk("cron weekly Monday present in a 48h window",
        expected_firings("41 6 * * 1", NOW - dt.timedelta(hours=48), NOW) == 1)
    chk("cron dom+dow both restricted is a UNION",
        expected_firings("0 0 1 * 3", dt.datetime(2026, 7, 1, tzinfo=dt.timezone.utc),
                         dt.datetime(2026, 7, 31, tzinfo=dt.timezone.utc)) > 1)
    for bad in ("", "* * * *", "* * * * * *", "60 * * * *", "*/0 * * * *", "5-1 * * * *"):
        try:
            expected_firings(bad, H6, NOW)
            chk(f"cron {bad!r} must raise CronError", False)
        except CronError:
            pass
        except Exception:
            chk(f"cron {bad!r} raised the wrong error", False)

    # --- M1 scope: EVERY scheduled lane here (no cron_lane_liveness counterpart) ---
    sched_only = {"schedule": [{"cron": "*/15 * * * *"}], "workflow_dispatch": None}
    mixed = dict(sched_only, workflow_run=None)
    chk("M1 watches a cron-ONLY lane on this repo", m1_scope(sched_only)[0] is True)
    chk("M1 still reports cron_only for information", m1_scope(sched_only)[2] is True)
    chk("M1 watches a schedule+other-trigger lane", m1_scope(mixed)[0] is True)
    chk("M1 excludes an unscheduled workflow", m1_scope({"pull_request": None})[0] is False)

    # --- M1 detection ---
    f, c = find_cron_deficits([_lane(fires=CAP, now=NOW)], NOW)
    chk("M1 quiet when the lane delivers its capped expectation",
        not f and c.get("delivering") == 1)
    f, c = find_cron_deficits([_lane(fires=1, now=NOW)], NOW)
    chk("M1 raises on a firing deficit", len(f) == 1 and c.get("firing-deficit") == 1)
    chk("M1 finding carries the CAPPED expectation and the nominal rate",
        f and f[0]["expected"] == CAP and f[0]["nominal"] > CAP)
    f, _ = find_cron_deficits([_lane(fires=0, now=NOW)], NOW)
    chk("M1 raises when a cron fired ZERO times (the no-artifact mode)", len(f) == 1)
    # THE ANTI-CRY-WOLF GUARD: nominal 96/day, GitHub delivers ~30 here.
    f, _ = find_cron_deficits([_lane(crons=("*/15 * * * *",), fires=CAP, now=NOW)], NOW)
    chk("M1 does not alarm on a lane delivering GitHub's real ceiling", not f)
    chk("cap fixture is not vacuous",
        expected_firings("*/15 * * * *", D1, NOW) > CAP)
    edge = _lane(fires=0, now=NOW)
    edge["schedule_run_times"] = [NOW - dt.timedelta(minutes=1)] * CAP
    f, _ = find_cron_deficits([edge], NOW)
    chk("M1 ignores firings inside the grace window (not yet due)", len(f) == 1)
    f, c = find_cron_deficits([_lane(state="disabled_manually", fires=0, now=NOW)], NOW)
    chk("M1 quiet on a disabled lane", not f and c.get("disabled") == 1)
    f, c = find_cron_deficits([_lane(crons=("garbage",), fires=0, now=NOW)], NOW)
    chk("M1 quiet + COUNTED on an unparseable cron",
        not f and c.get("cron-unparseable") == 1)
    f, c = find_cron_deficits([_lane(crons=("41 6 * * 1",), fires=0, now=NOW)], NOW)
    chk("M1 quiet when the expectation is below the floor",
        not f and c.get("expectation-below-floor") == 1)
    import math
    at_floor = math.ceil(CAP * CRON_DELIVERY_FLOOR)
    chk("M1 does not raise AT the delivery floor",
        not find_cron_deficits([_lane(fires=at_floor, now=NOW)], NOW)[0])
    chk("M1 does raise just BELOW the delivery floor",
        len(find_cron_deficits([_lane(fires=at_floor - 1, now=NOW)], NOW)[0]) == 1)

    # --- M1 threshold pins against LITERALS ------------------------------------------
    # The two boundary checks above derive `at_floor` FROM CRON_DELIVERY_FLOOR, so they
    # rescale with it and cannot fail when it moves. `0 */4 * * *` has a 24h nominal of 5,
    # BELOW the cap, so `expected` is 5 regardless of the cap constant. Nothing in these
    # three fixtures is computed from CRON_DELIVERY_FLOOR or from the cap.
    FOUR_HOURLY = ("0 */4 * * *",)
    f, _ = find_cron_deficits([_lane(crons=FOUR_HOURLY, fires=2, now=NOW)], NOW)
    chk("M1 raises at 2 of a literal 5 (ratio 0.40) — pins the floor from BELOW",
        len(f) == 1 and f[0]["expected"] == 5 and f[0]["ratio"] == 0.4)
    f, _ = find_cron_deficits([_lane(crons=FOUR_HOURLY, fires=3, now=NOW)], NOW)
    chk("M1 is quiet at 3 of a literal 5 (ratio 0.60) — pins the floor from ABOVE",
        not f)
    f, _ = find_cron_deficits([_lane(crons=FOUR_HOURLY, fires=2, now=NOW)], NOW)
    chk("M1's DEFAULT window makes a 4-hourly lane's expectation exactly 5 "
        "(it is 1 at the rejected 6h window)", len(f) == 1 and f[0]["expected"] == 5)

    # --- M1 new-lane window: 'did not fire' vs 'did not exist yet' --------------------
    young = _lane(fires=1, now=NOW, created_hours_ago=2)
    f, c = find_cron_deficits([young], NOW)
    chk("M1 does not alarm on a lane that did not EXIST for most of the window", not f)
    chk("M1 counts a too-young lane as its own census state",
        c.get("lane-too-new-for-an-expectation") == 1)
    # ANTI-VACUITY: the identical fixture WITHOUT a birth date must still alarm, or the
    # new-lane exit is just an unconditional mute.
    chk("M1 still alarms on the same delivery from an ESTABLISHED lane",
        len(find_cron_deficits([_lane(fires=1, now=NOW)], NOW)[0]) == 1)
    chk("M1 judges a lane older than the window on delivery alone",
        len(find_cron_deficits([_lane(fires=1, now=NOW, created_hours_ago=48)],
                               NOW)[0]) == 1)
    chk("M1 birth-date check does not change an established lane's verdict",
        not find_cron_deficits([_lane(fires=CAP, now=NOW, created_hours_ago=48)],
                               NOW)[0])
    # THE BOUNDARY, pinned from both sides against the 24h window: a lane born just
    # INSIDE the window is skipped, one born just OUTSIDE it is judged. Without both
    # directions, `if born > start` and `if born > start - 100 years` are the same test.
    f, c = find_cron_deficits([_lane(fires=1, now=NOW, created_hours_ago=23)], NOW)
    chk("M1 skips a lane born 23h ago (inside the 24h window)",
        not f and c.get("lane-too-new-for-an-expectation") == 1)
    f, c = find_cron_deficits([_lane(fires=1, now=NOW, created_hours_ago=25)], NOW)
    chk("M1 judges a lane born 25h ago (outside the 24h window)",
        len(f) == 1 and c.get("firing-deficit") == 1)

    # --- M2 ---
    f, c = find_queue_overruns(
        [_run_obj(status="queued", age_min=int(QUEUE_MAX_WAIT_SECONDS / 60) + 5, now=NOW)],
        NOW)
    chk("M2 raises past the queue threshold",
        len(f) == 1 and c.get("queued-over-threshold") == 1)
    f, c = find_queue_overruns([_run_obj(status="queued", age_min=1, now=NOW)], NOW)
    chk("M2 quiet within the queue threshold",
        not f and c.get("queued-within-threshold") == 1)
    # ABSOLUTE, not derived from the constant: a fixture computed FROM
    # QUEUE_MAX_WAIT_SECONDS scales with it and can never fail when it changes.
    # MEASURED known positive: pr-gate runs held 12.8-99.5 min on 2026-07-28.
    chk("an hour in `queued` raises under the SHIPPED threshold",
        len(find_queue_overruns([_run_obj(status="queued", age_min=60, now=NOW)],
                                NOW)[0]) == 1)
    chk("two minutes in `queued` stays quiet under the SHIPPED threshold",
        not find_queue_overruns([_run_obj(status="queued", age_min=2, now=NOW)], NOW)[0])
    chk("the queue threshold stays inside its validated band",
        5 * 60 <= QUEUE_MAX_WAIT_SECONDS <= 30 * 60)
    chk("M2 ignores in_progress runs (that is M3's job)",
        not find_queue_overruns([_run_obj(status="in_progress", age_min=9999, now=NOW)],
                                NOW)[0])

    # --- M2 RE-RUN TRAP: the reason the shipped detector is not `now - created_at` -----
    # The exact shape of this repo's run 30318886362: attempt 2, whose own creation was 1
    # minute ago, on a run-level object still reporting attempt 1's creation 99 minutes
    # ago. The naive form reports a 99-minute queue wait for a sub-second pickup — and
    # the seven runs of that shape were this mode's ENTIRE published known positive.
    rerun = _run_obj(status="queued", age_min=1, attempt=2, created_age_min=99,
                     attempt_created_age_min=1, now=NOW)
    naive_wait = (NOW - _ts(rerun["created_at"])).total_seconds()
    chk("the re-run fixture reproduces the FROZEN run-level created_at",
        naive_wait > 90 * 60
        and (NOW - _ts(rerun[ATTEMPT_CREATED_KEY])).total_seconds() < 5 * 60)
    chk("the naive `now - created_at` WOULD have fired on it (fixture is not vacuous)",
        naive_wait > QUEUE_MAX_WAIT_SECONDS)
    f, c = find_queue_overruns([rerun], NOW)
    chk("M2 does NOT charge a re-run's idle gap as queue wait", not f)
    chk("M2 counts the re-run as within threshold, not as a skip",
        c.get("queued-within-threshold") == 1)
    unresolved = _run_obj(status="queued", age_min=1, attempt=2, created_age_min=99,
                          now=NOW)
    f, c = find_queue_overruns([unresolved], NOW)
    chk("an unresolved re-run is quiet", not f)
    chk("an unresolved re-run is COUNTED in its own census state",
        c.get("queued-rerun-attempt-unresolved") == 1)
    chk("a genuine ATTEMPT-1 queue wait still raises after the re-run fix",
        len(find_queue_overruns(
            [_run_obj(status="queued", age_min=60, attempt=1, now=NOW)], NOW)[0]) == 1)
    chk("a genuine queue wait ON a re-run attempt still raises",
        len(find_queue_overruns(
            [_run_obj(status="queued", age_min=60, attempt=3, created_age_min=999,
                      attempt_created_age_min=60, now=NOW)], NOW)[0]) == 1)

    # THE CALL SITE. A pure detector that reads ATTEMPT_CREATED_KEY is worthless if
    # nothing ever writes it, and that omission is invisible to every assertion above.
    _real_api = globals()["_api"]
    try:
        seen = []

        def _fake_api(repo, path):
            seen.append(path)
            return {"created_at": "2026-07-28T11:59:00Z",
                    "run_started_at": "2026-07-28T11:59:00Z", "run_attempt": 2}

        globals()["_api"] = _fake_api
        enriched = resolve_attempt_created("o/r", [
            _run_obj(status="queued", age_min=1, attempt=2, created_age_min=99, now=NOW),
            _run_obj(status="queued", age_min=99, attempt=1, now=NOW),
            _run_obj(status="in_progress", age_min=99, attempt=2, now=NOW),
        ])
        chk("the fetch layer resolves a QUEUED re-run against /attempts/{n}",
            enriched[0].get(ATTEMPT_CREATED_KEY) == "2026-07-28T11:59:00Z")
        chk("the fetch layer asks for the LIVE attempt number",
            len(seen) == 1 and seen[0].endswith("/attempts/2"))
        chk("the fetch layer spends no request on an attempt-1 run",
            ATTEMPT_CREATED_KEY not in enriched[1])
        chk("the fetch layer spends no request on an in_progress run (M3's population)",
            ATTEMPT_CREATED_KEY not in enriched[2])
        chk("enrichment turns the re-run false positive into silence",
            [x["run_attempt"] for x in find_queue_overruns(enriched, NOW)[0]] == [1])

        def _raising_api(repo, path):
            raise AlarmError("attempt lookup unavailable")

        globals()["_api"] = _raising_api
        degraded = resolve_attempt_created("o/r", [
            _run_obj(status="queued", age_min=1, attempt=2, created_age_min=99, now=NOW)])
        chk("a failed attempt lookup does not abort the tick",
            ATTEMPT_CREATED_KEY not in degraded[0])
        chk("a failed attempt lookup lands in the unresolved census state",
            find_queue_overruns(degraded, NOW)[1]
            .get("queued-rerun-attempt-unresolved") == 1)

        # AND THE CALL SITE OF THE CALL SITE. Every assertion above invokes
        # `resolve_attempt_created` DIRECTLY, so deleting the ONE line in
        # `fetch_live_runs` that invokes it in production SURVIVED all of them
        # (MEASURED — this exact mutant survived the battery before this block existed).
        # A helper that is only ever called by its own tests is not wired to anything.
        def _live_api(repo, path):
            if "status=queued" in path:
                return {"workflow_runs": [
                    _run_obj(status="queued", age_min=1, attempt=2,
                             created_age_min=99, now=NOW)]}
            if "status=in_progress" in path:
                return {"workflow_runs": []}
            if "/attempts/2" in path:
                return {"created_at": "2026-07-28T11:59:00Z"}
            raise AssertionError(f"unexpected request {path}")

        globals()["_api"] = _live_api
        wired = fetch_live_runs("o/r")
        chk("fetch_live_runs ENRICHES what it returns (the production call site)",
            len(wired) == 1
            and wired[0].get(ATTEMPT_CREATED_KEY) == "2026-07-28T11:59:00Z")
        chk("the enrichment reaches M2 through the real fetch path",
            not find_queue_overruns(wired, NOW)[0])
    finally:
        globals()["_api"] = _real_api

    # `fetch_lanes` must carry the birth date the NEW-LANE WINDOW reads, or that guard
    # can never fire in production. Deleting it SURVIVED the battery before this check.
    _real_api = globals()["_api"]
    try:
        def _lanes_api(repo, path):
            if path.startswith("actions/workflows?"):
                return {"workflows": [{"path": GROOM_WORKFLOW, "state": "active",
                                       "created_at": "2026-07-01T00:00:00Z"}]}
            return {"workflow_runs": []}

        globals()["_api"] = _lanes_api
        root = Path(__file__).resolve().parents[1]
        fetched = {lane["workflow"]: lane
                   for lane in fetch_lanes("o/r", root, CRON_WINDOW_HOURS, NOW)}
        chk("fetch_lanes carries each lane's created_at off the workflow listing",
            fetched.get(GROOM_WORKFLOW, {}).get("created_at") == "2026-07-01T00:00:00Z")
    finally:
        globals()["_api"] = _real_api

    # --- M3 ---
    base = {(".github/workflows/a.yml", "schedule"): {"p90": 3600.0, "n": 50}}
    f, c = find_execution_overruns([_run_obj(age_min=30, now=NOW)], base, NOW)
    chk("M3 quiet inside the band", not f and c.get("in-progress-within-threshold") == 1)
    f, c = find_execution_overruns([_run_obj(age_min=8 * 60, now=NOW)], base, NOW)
    chk("M3 raises past the band", len(f) == 1 and c.get("execution-overrun") == 1)
    chk("M3 ignores queued runs (that is M2's job)",
        not find_execution_overruns([_run_obj(status="queued", age_min=9999, now=NOW)],
                                    base, NOW)[0])
    # THE FAIL-OPEN HOLE: a lane whose runs never complete has no baseline. Skipping it
    # would go silent exactly when it is 100% hung.
    f, _ = find_execution_overruns([_run_obj(age_min=7 * 60, now=NOW)], {}, NOW)
    chk("M3 still raises with NO baseline at all (fail-open hole closed)", len(f) == 1)
    chk("M3 names the floor as the basis when there is no baseline",
        f and "floor" in f[0]["basis"])
    # The under-sampling guard only BITES when the thin baseline would WIDEN the threshold.
    thin = {(".github/workflows/a.yml", "schedule"): {"p90": 20 * 3600.0, "n": 1}}
    f, _ = find_execution_overruns([_run_obj(age_min=7 * 60, now=NOW)], thin, NOW)
    chk("M3 does not trust a 1-sample baseline even when it is LARGE",
        len(f) == 1 and f[0]["threshold_seconds"] == int(EXEC_FLOOR_SECONDS))
    thick = {(".github/workflows/a.yml", "schedule"):
             {"p90": 20 * 3600.0, "n": BASELINE_MIN_N}}
    chk("M3 respects a properly-sampled baseline wider than the floor",
        not find_execution_overruns([_run_obj(age_min=7 * 60, now=NOW)], thick, NOW)[0])
    big = {(".github/workflows/a.yml", "schedule"): {"p90": 8 * 3600.0, "n": 40}}
    chk("M3 does not cry wolf on a legitimately long lane",
        not find_execution_overruns([_run_obj(age_min=7 * 60, now=NOW)], big, NOW)[0])
    chk("M3 raises on the measured 17.3h-vs-8.3h shape",
        len(find_execution_overruns([_run_obj(age_min=17 * 60, now=NOW)], big, NOW)[0]) == 1)
    # DETECTION VARIABLE IS LIVE STATE: a baseline alone can never produce a finding.
    chk("no live run => nothing to say",
        find_execution_overruns([], big, NOW) == ([], {}))
    # --- M3 threshold pins against LITERALS ------------------------------------------
    # 9h against an 8h p90 is 1.13x — inside the band at K=2.0, outside it at K<=1.13.
    # The 17.3h check pins the multiple from ABOVE (K=2.5 misses it); this pins it from
    # BELOW, which nothing did before.
    chk("M3 is quiet at 9h against an 8h p90 — pins the multiple from BELOW",
        not find_execution_overruns([_run_obj(age_min=9 * 60, now=NOW)], big, NOW)[0])
    chk("M3 is quiet at 5h with no baseline — pins the 6h floor from BELOW",
        not find_execution_overruns([_run_obj(age_min=5 * 60, now=NOW)], {}, NOW)[0])
    chk("M3 raises at 7h with no baseline — pins the 6h floor from ABOVE",
        len(find_execution_overruns([_run_obj(age_min=7 * 60, now=NOW)], {}, NOW)[0]) == 1)
    # THE `updated_at` SUBSTITUTION. A live run's `updated_at` tracks the present moment,
    # so `started = run.get("updated_at") or run_started_at` collapses every age to ~0 and
    # M3 never fires again. It survived the first battery only because the fixture was a
    # hand-built dict with no `updated_at`; the fixture now carries the real shape.
    _live = _run_obj(age_min=17 * 60, now=NOW)
    chk("the M3 fixture carries a live run's real `updated_at`",
        (NOW - _ts(_live["updated_at"])).total_seconds() < 60
        and (NOW - _ts(_live["run_started_at"])).total_seconds() > 16 * 3600)

    # --- census on the all-clear ---
    res = classify([_lane(fires=CAP, now=NOW)],
                   [_run_obj(status="queued", age_min=1, now=NOW),
                    _run_obj(age_min=1, now=NOW)], base, NOW, CRON_WINDOW_HOURS)
    chk("a clean pass still emits a non-empty census for every mode",
        all(res[m][1] for m in MODES) and not any(res[m][0] for m in MODES))

    # --- transport decisions ---
    chk("findings => upsert", decide([{"x": 1}], None) == "upsert")
    chk("findings => upsert even when an alert is open", decide([{"x": 1}], 7) == "upsert")
    chk("recovery with an open alert => close", decide([], 7) == "close")
    chk("clean with no alert => noop", decide([], None) == "noop")
    body = render_body(MODES[1], "o/r", [{"workflow": "a", "run_id": 1, "event": "push",
                                          "waited_seconds": 99, "threshold_seconds": 60}],
                       {"queued-over-threshold": 1}, NOW, "u")
    chk("body starts with the dedupe marker", body.startswith(marker(MODES[1])))
    chk("body self-identifies as a SPARQ agent", "🤖 SPARQ agent" in body)
    chk("body carries the census", "Census of every state exit" in body)
    chk("each mode has a DISTINCT marker", len({marker(m) for m in MODES}) == len(MODES))

    # --- alert routing (locked decision 22c) ---
    chk("route: private repo + token wins",
        _alert_route("p/r", "tok", "reg/reg") == ("p/r", "tok"))
    chk("route: half-configured falls back to the registry, never loses the alert",
        _alert_route("p/r", None, "reg/reg") == ("reg/reg", None))
    chk("route: unconfigured uses the registry",
        _alert_route(None, None, "reg/reg") == ("reg/reg", None))

    # --- exit codes + the empty-scan-set fail-loud ---
    import tempfile

    def _rc(lanes, live=()):
        state = {"repo": "o/r",
                 "lanes": [dict(x, schedule_run_times=[
                     t.strftime("%Y-%m-%dT%H:%M:%SZ") for t in x["schedule_run_times"]])
                     for x in lanes],
                 "live_runs": list(live), "baselines": {}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(state, fh)
            path = fh.name
        return main(["--state-file", path, "--now", "2026-07-28T12:00:00Z", "--dry-run"])

    chk("a bad repo slug is fail-loud exit 2",
        main(["--repo", "not-a-slug", "--dry-run"]) == 2)
    # THE ANNOTATION ITSELF, not just the exit code. An `::error::` prefix that is only
    # claimed in a docstring and asserted nowhere survives deletion: the job still reds on
    # the exit code, but the reason stops appearing in the Actions UI and the failure
    # becomes a bare non-zero exit someone has to go digging for. Capture and assert it.
    import contextlib
    import io
    _buf = io.StringIO()
    with contextlib.redirect_stdout(_buf):
        main(["--repo", "not-a-slug", "--dry-run"])
    chk("the infrastructure-failure path emits an ::error:: annotation",
        "::error::" in _buf.getvalue())
    chk("the ::error:: annotation names the cause, not just that something failed",
        "no usable repo slug" in _buf.getvalue())
    # 100% question: if NO workflow carried a `schedule:`, M1's population would be empty
    # and a `return 0` would report health over zero lanes. Both empty shapes are loud.
    chk("an empty workflow set is fail-loud exit 2", _rc([]) == 2)
    chk("a scan set with nothing in scope is fail-loud exit 2",
        _rc([_lane(in_scope=False, now=NOW)]) == 2)
    chk("a populated, healthy scan set is exit 0", _rc([_lane(fires=CAP, now=NOW)]) == 0)

    # --- THE CONSUMER of the hard/soft read (NOT just decide() in isolation) ----------
    # `decide()` is exercised above as a pure function, but the guard that actually
    # protects the transport lives in its CALLER: on a failed or unparseable
    # `gh issue list` the dedupe/recovery data is missing, so acting anyway would mint a
    # DUPLICATE ops-alert on every sub-hourly groom tick. Making `if hard or soft:
    # continue` inert SURVIVED the entire suite, because nothing exercised run()'s WRITE
    # path at all — a tested pure function whose consumer is untested is a tested nothing.
    _real_find, _real_apply = globals()["_find_open_alert"], globals()["_apply"]
    try:
        applied = []

        def _spy_apply(action, repo, token, num, mode, body, note):
            applied.append(action)
            return 0

        globals()["_apply"] = _spy_apply
        # A lane that fired ZERO times, so M1 has a finding and the write path is live.
        deficit = {"repo": "o/r", "baselines": {}, "live_runs": [],
                   "lanes": [dict(_lane(fires=0, now=NOW), schedule_run_times=[])]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(deficit, fh)
            deficit_path = fh.name
        argv = ["--state-file", deficit_path, "--now", "2026-07-28T12:00:00Z"]

        for label, ret, want_rc in (("a hard gh failure", (None, True, False), 1),
                                    ("an unparseable listing", (None, False, True), 0)):
            applied.clear()
            globals()["_find_open_alert"] = (
                lambda repo, token, mode, _r=ret: _r)
            rc = main(argv)
            chk(f"{label} writes NOTHING (no duplicate ops-alert)", applied == [])
            chk(f"{label} returns rc={want_rc}", rc == want_rc)
        # ANTI-VACUITY: on a CLEAN read the very same input DOES write, so the two checks
        # above are pinning the guard and not merely a broken fixture.
        applied.clear()
        globals()["_find_open_alert"] = lambda repo, token, mode: (None, False, False)
        main(argv)
        chk("a clean issue read DOES upsert the M1 alert (guard test is not vacuous)",
            applied == ["upsert", "noop", "noop"])
    finally:
        globals()["_find_open_alert"], globals()["_apply"] = _real_find, _real_apply

    # --- YAML SEAM. Neither `bash -n` nor actionlint can see which inputs a watchdog
    # keys on, so the hosting job is asserted structurally, by EXACT match. ---
    root = Path(__file__).resolve().parents[1]
    missing = [p for p in REQUIRED_FILES if not (root / p).exists()]
    if missing:
        # Sparse checkout dropped an input: the seam assertions would be silently
        # unreachable on the live path, which is worse than failing here.
        chk(f"seam: REQUIRED_FILES present (missing: {missing})", False)
    else:
        wf = yaml.safe_load((root / GROOM_WORKFLOW).read_text())
        jobs = wf.get("jobs", {})
        chk("seam: groom.yml hosts a `ci-latency` job", "ci-latency" in jobs)
        job = jobs.get("ci-latency", {})
        # A watcher hosted inside the watched job cannot observe the watched job's absence.
        chk("seam: the watchdog job has NO `needs:`", "needs" not in job)
        chk("seam: the watchdog job has NO job-level `if:`", "if" not in job)
        perms = job.get("permissions", {})
        chk("seam: actions:read + contents:read + issues:write",
            perms.get("actions") == "read" and perms.get("contents") == "read"
            and perms.get("issues") == "write")
        for forbidden in ("pull-requests", "checks", "id-token", "packages"):
            chk(f"seam: no `{forbidden}` permission (no arming authority)",
                forbidden not in perms)
        runs = [str(s.get("run", "")).strip() for s in job.get("steps", [])]
        # EXACT match, not containment: `--self-test-DISABLED` contains `--self-test`.
        chk("seam: the job runs the self-test EXACTLY",
            "python3 registry/scripts/ci-latency-alert.py --self-test" in runs)
        chk("seam: the job runs the detector EXACTLY",
            "python3 registry/scripts/ci-latency-alert.py" in runs)
        idx_self = next((i for i, r in enumerate(runs)
                         if r.endswith("--self-test")), None)
        idx_live = next((i for i, r in enumerate(runs)
                         if r == "python3 registry/scripts/ci-latency-alert.py"), None)
        chk("seam: the self-test runs BEFORE the detector",
            idx_self is not None and idx_live is not None and idx_self < idx_live)
        # THE SELF-TEST STEP MUST BE ABLE TO FAIL THE JOB. It is the only thing standing
        # between a broken detector and a live tick, and both the workflow comment and the
        # PR body claim the detector "proves itself first" — so `continue-on-error` there
        # would let a broken detector ship silently while the prose said otherwise. The
        # words and the wiring have to agree, and only an assertion keeps them agreeing.
        selftest_steps = [s for s in job.get("steps", [])
                          if str(s.get("run", "")).strip().endswith("--self-test")]
        chk("seam: exactly one self-test step", len(selftest_steps) == 1)
        for s in selftest_steps:
            chk("seam: the self-test step carries NO `continue-on-error`",
                "continue-on-error" not in s)
            chk("seam: the self-test step carries NO `if:`", "if" not in s)
        chk("seam: the JOB carries no `continue-on-error`", "continue-on-error" not in job)
        # ANTI-VACUITY for the three checks above. The ALERT step legitimately DOES carry
        # `continue-on-error: true` (a watchdog fault must never red the grooming sweep),
        # so a blanket "no continue-on-error anywhere" would be pinning the wrong thing
        # and would pass vacuously if the steps were reordered or renamed. The asymmetry
        # between the two steps is the actual invariant.
        alert_steps = [s for s in job.get("steps", [])
                       if str(s.get("run", "")).strip()
                       == "python3 registry/scripts/ci-latency-alert.py"]
        chk("seam: the ALERT step DOES carry continue-on-error (asymmetry is deliberate)",
            len(alert_steps) == 1 and alert_steps[0].get("continue-on-error") is True)
        for step in job.get("steps", []):
            uses = step.get("uses")
            if uses:
                chk(f"seam: {uses} is SHA-pinned",
                    bool(__import__("re").search(r"@[0-9a-f]{40}$", uses)))
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                with_ = step.get("with", {})
                chk("seam: checkout does not persist credentials",
                    with_.get("persist-credentials") is False)
                # EXACT LINE match, never containment: `.github/workflows` is a
                # SUBSTRING of `.github/workflows/groom.yml`, so a containment check
                # passes even when the directory entry — which is what M1 actually reads
                # every lane's cron from — has been dropped. That mutant SURVIVED a
                # containment check.
                sparse_lines = [ln.strip() for ln in
                                str(with_.get("sparse-checkout", "")).splitlines()
                                if ln.strip()]
                for required in (*REQUIRED_FILES, WORKFLOWS_DIR):
                    chk(f"seam: sparse-checkout names {required} on its own line",
                        required in sparse_lines)
        # This script is enrolled in the suite the `gate` job actually runs, so it cannot
        # silently leave CI.
        suite = (root / "scripts" / "selftest-suite.txt").read_text().split()
        chk("seam: enrolled in scripts/selftest-suite.txt",
            "ci-latency-alert.py" in suite)

    if failures:
        for name in failures:
            print(f"FAIL: {name}")
        print(f"::error::ci-latency-alert self-test: {len(failures)} failure(s)")
        return 1
    print("ci-latency-alert self-test: all checks passed")
    return 0


# ---------------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------------
MODES = ("M1-cron-firing-deficit", "M2-queue-wait", "M3-execution-overrun")


def classify(lanes, live, baselines, now, window_hours):
    """Pure: -> {mode: (findings, census)} for all three modes."""
    return {
        MODES[0]: find_cron_deficits(lanes, now, window_hours),
        MODES[1]: find_queue_overruns(live, now),
        MODES[2]: find_execution_overruns(live, baselines, now),
    }


def run(args):
    now = _ts(args.now) if args.now else dt.datetime.now(dt.timezone.utc)
    registry_repo = args.repo or os.environ.get("REGISTRY_REPO") or ""
    run_url = os.environ.get("RUN_URL", "(local)")

    if args.state_file:
        state = json.loads(Path(args.state_file).read_text(encoding="utf-8"))
        repo = state.get("repo") or registry_repo or "hermetic/fixture"
        lanes = state.get("lanes", [])
        for lane in lanes:
            lane["schedule_run_times"] = [_ts(t)
                                          for t in lane.get("schedule_run_times", [])]
        live = state.get("live_runs", [])
        baselines = {tuple(k.split("|", 1)): v
                     for k, v in (state.get("baselines") or {}).items()}
    else:
        repo = registry_repo
        if "/" not in repo:
            raise AlarmError(f"no usable repo slug: {repo!r}")
        root = Path(__file__).resolve().parents[1]
        lanes = fetch_lanes(repo, root, args.window_hours, now)
        live = fetch_live_runs(repo)
        baselines = {}
        for r in live:
            if r.get("status") != "in_progress" or not r.get("path"):
                continue
            key = (r["path"], r.get("event"))
            if key not in baselines:
                baselines[key] = fetch_baseline(repo, r["path"], r.get("event") or "push")

    # EMPTY SCAN SET IS FAIL-LOUD. A detector watching nothing is not a healthy repo; it is
    # a broken detector, and the two must never look alike. 100% question: if no workflow
    # carried a `schedule:`, M1's population would be empty and reporting "clean" would be
    # reporting health over zero lanes.
    if not lanes:
        raise AlarmError("empty scan set: no workflows discovered")
    if not any(lane.get("in_scope") for lane in lanes):
        raise AlarmError("empty M1 scan set: no workflow carries a usable `schedule:` — "
                         "either the repo changed shape or the scope predicate broke. "
                         "Refusing to report health over an empty population.")

    results = classify(lanes, live, baselines, now, args.window_hours)

    # CENSUS EVERY RUN, including the all-clear.
    print(f"ci-latency census for {repo} at {now:%Y-%m-%dT%H:%M:%SZ} "
          f"({len(lanes)} workflows, {len(live)} live runs):")
    for mode in MODES:
        findings, census = results[mode]
        print(f"  {mode}:")
        for state_name, count in sorted(census.items()):
            print(f"    {state_name}: {count}")
        for f in findings:
            print(f"    BREACH {f['workflow']}")

    alert_repo, alert_token = _alert_route(os.environ.get("ALERT_REPO"),
                                           os.environ.get("ALERT_TOKEN"), repo)
    rc = 0
    for mode in MODES:
        findings, census = results[mode]
        if args.dry_run:
            if findings:
                print(render_body(mode, repo, findings, census, now, run_url))
            continue
        num, hard, soft = _find_open_alert(alert_repo, alert_token, mode)
        if hard or soft:
            rc = 1 if hard else rc
            continue
        action = decide(findings, num)
        body = render_body(mode, repo, findings, census, now, run_url)
        note = (f"> 🤖 SPARQ agent — `{mode}` is back inside its measured threshold as of "
                f"`{now:%Y-%m-%dT%H:%M:%SZ}`. Closing this rolling alert.")
        rc |= _apply(action, alert_repo, alert_token, num, mode, body, note)
    return rc


def main(argv=None):
    parser = argparse.ArgumentParser(description="CI execution-latency watchdog")
    parser.add_argument("--repo", default="")
    parser.add_argument("--now", default="")
    parser.add_argument("--state-file", default="")
    parser.add_argument("--window-hours", type=float, default=CRON_WINDOW_HOURS)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        return run(args)
    except AlarmError as exc:
        print(f"::error::ci-latency watchdog infrastructure failure: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
