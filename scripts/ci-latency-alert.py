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

THREE DETECTED MODES plus ONE DOCUMENTED GAP. The mode that is runner availability proper —
queue wait, the maintainer's literal ask — is NOT detected, because the variable it would
read never moves on this corpus. That is recorded rather than filled with a check that
cannot see the thing:

  M1 CRON-FIRING DEFICIT   a scheduled lane firing far below what it can actually get.
                           This mode produces NO ARTIFACT — a cron that never fires leaves
                           no run, no conclusion, nothing to inspect — so it can only be
                           caught by computing an expectation and comparing.
  QUEUE WAIT               NOT DETECTED — a deliberate, documented gap. The "MEASURED
                           KNOWN POSITIVE" previously claimed here (seven `pr-gate.yml`
                           runs held 12.8-99.5 min on 2026-07-28) was SEVEN `run_attempt:
                           2` RE-RUNS; neither attempt ever queued. Zero non-zero queue
                           waits across 44,190 completed runs. See the long note below the
                           constants before adding a detector.
  M3 EXECUTION OVERRUN     a run `in_progress` far past its own lane's measured duration.
                           It consumes capacity while looking perfectly healthy.
  M4 INGESTION REJECTION   GitHub CREATES the run and executes NO JOB — `action_required`,
                           `jobs.total_count == 0`, ~1 second. The workflow is off, and
                           every liveness watcher in the ring above still reads it as
                           alive, because a run WAS created. See the M4 note below.

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
import re
import subprocess
import sys
import tempfile
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
    # M3's floor is DERIVED from this file's `worker_timeout_minutes` (see EXEC_FLOOR_SECONDS).
    # Without it in the checkout the derivation assertion would be unreachable on the live
    # path while staying green in pr-gate — the exact silent divergence #1140 was about.
    "policy/repos.toml",
)
GROOM_WORKFLOW = ".github/workflows/groom.yml"
POLICY_FILE = "policy/repos.toml"
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

# =============================================================================
# QUEUE WAIT / RUNNER STARVATION — DELIBERATELY NOT DETECTED. Read this before
# adding a detector for it; the obvious one does not work and was removed.
# =============================================================================
# There is NO detector on this route. That is a documented gap, not an oversight.
#
# An earlier revision shipped "M2", a queue-wait mode keyed on `now - run["created_at"]`
# for runs in `status=queued`. Removed for three measured reasons.
#
# 1. THE ESTIMATOR WAS WRONG. The run-level `created_at` is ATTEMPT 1's creation time and
#    does NOT reset on re-run, while `run_attempt` and `run_started_at` DO track the live
#    attempt. MEASURED on THIS repo's run 30318886362:
#        run-level    run_attempt=2  created_at=00:58:13Z  run_started_at=02:37:40Z
#        /attempts/1                 created_at=00:58:13Z  run_started_at=00:58:13Z   0s
#        /attempts/2                 created_at=02:37:41Z  run_started_at=02:37:40Z   0s
#    Neither attempt ever queued; the 99 minutes is idle time before a re-run was pressed.
#    Executed on that payload the detector reported waited_seconds=5967 for a sub-second
#    pickup — it fired on every re-run older than the threshold. The seven runs of that
#    shape were this mode's ENTIRE published known positive.
#
# 2. AFTER FIXING THAT, THE VARIABLE NEVER MOVES. Per-workflow scan, splitting on
#    `run_attempt` and resolving every re-run against its own /attempts/{n}:
#
#                                      agent-account-registry   sparq-org/sparq
#      completed runs scanned                           9,062            35,128
#      contaminated estimator, over 15 min                  6                 7
#        ... of which are RE-RUNS                     6 (ALL)           7 (ALL)
#      DECONTAMINATED (run_attempt == 1)                9,053            35,070
#        over 15 min                                        0                 0
#        with ANY non-zero wait at all                      0                 0
#        maximum observed wait                           0.0s              0.0s
#
#    Across 44,190 completed runs not ONE attempt recorded even a non-zero queue wait. The
#    distribution is not zero-INFLATED, it is exactly all-zero, so no percentile, multiple
#    or maximum exists to anchor a threshold to.
#
# 3. THE EVENT THAT MOTIVATED THE MODE WAS NOT A CAPACITY EVENT. sparq run 30333511110 was
#    cited as a 6.7h run whose starvation was invisible to `status=queued`. Re-measured:
#      job PICKUP lag, N=84 jobs:                        max 10s,  over 60s: ZERO
#      job CREATION lag:                                 max 402 min
#      the 402 min is INTRA-MATRIX (`mutation ratchet`, 51 legs, spread 401.9 min)
#      control: `test` (5 legs, no max-parallel) spread  0.0 min
#    and that job declares `max-parallel: 8`. 51 legs at 8 concurrent is 6.4 waves — the
#    402 minutes IS the configured cap working correctly, not withheld runners.
#
# WHY NOT RE-POINT IT AT JOB-CREATION LAG. That variable does move, but on this corpus it
# moves because of a configured `max-parallel`, so an alarm keyed on it would fire on every
# nightly mutation run forever. A permanently-red alarm is a muted alarm — the same reason
# the M1 expectation is capped at what GitHub actually delivers. Separating a configured
# cap from a genuine account-level ceiling needs a model of each lane's concurrency and
# per-leg duration, with no observed positive to validate it against.
#
# 4. AND THE STRONGEST REASON, FOUND LAST: THE FIELDS CANNOT EXPRESS THE QUANTITY.
#    This is not "no positive was observed" — the data source does not carry enqueue time
#    at all, so no threshold on it could ever have worked.
#      attempt-1 runs, `run_started_at - created_at`: EXACTLY 0.0 on all 44,123 of them
#        (35,070 sparq + 9,053 registry). Not approximately zero -- identically zero.
#      re-run attempts, `run_started_at - attempt.created_at`, N=67 (58 sparq + 9 registry):
#        NEGATIVE on every single one -- sparq {-1: 41, -2: 15, -4: 1, -5: 1},
#        registry {-1: 7, -2: 2}. A queue wait cannot be negative.
#    A negative value means the attempt record's `created_at` is stamped at or AFTER the
#    run starts, not when it is enqueued; and an exactly-zero run-level difference across
#    44,123 runs is what you see when the two fields are set together rather than
#    measuring an interval between two events. So BOTH the run-level pair and the
#    per-attempt pair are unable to express "how long did this wait to be picked up".
#    The all-zero corpus in point 2 is therefore not evidence that no queueing happened;
#    it is evidence that these fields do not report queueing.
#
# WHAT WOULD CHANGE THIS -- and it is NOT a better threshold. Do not re-derive a detector
# from `created_at`/`run_started_at` on either the run or the attempt: point 4 shows they
# cannot carry the signal at any threshold. It would take a DIFFERENT data source that
# actually timestamps enqueue -- a webhook capturing `workflow_job` `queued` -> `in_progress`
# transitions, or self-reported timing from inside the job -- plus at least one observed
# positive from it before a threshold means anything.

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
# THE FLOOR IS DERIVED FROM POLICY, NOT FROM GitHub's per-JOB ceiling. It used to be 6h —
# GitHub's hosted-runner limit for a single job — and that made M3 INERT on this repo
# (#1140). MEASURED: the LONGEST RUN THIS REPOSITORY HAS EVER PRODUCED is 91.5 min
# (worker.yml, n=500, p90 31.6 min; the next-longest lane, review-fix.yml, maxes at
# 37.6 min), and `policy/repos.toml` kills the longest lane's agent job at
# `worker_timeout_minutes = 90`. A threshold 3.9x above the observed maximum, on lanes
# policy terminates far below it, is not conservative — it is unreachable BY CONSTRUCTION,
# and an alarm that cannot fire is indistinguishable from no alarm at all.
#
# So the floor tracks the thing that actually bounds a run here: 1.5x the LONGEST
# `worker_timeout_minutes` any target configures in policy/repos.toml (90 -> 135 min). That
# is above every run this repo has produced, so it cannot cry wolf, and below what a genuine
# hang reaches, so it can fire. The 0.5 of headroom is the overhang measured directly: 91.5
# min of RUN against a 90-min agent-job timeout is the resolve/gate/publish jobs either side
# of the timed-out one.
#
# The floor still governs this repo's BIMODAL dispatch durations exactly as the 6h value did
# (a within-floor no-op tick concludes in ~30s while a real tick runs minutes): 2x either
# mode is far below 135 min, so the p90's position between the modes never matters.
#
# THE LINK TO POLICY IS ENFORCED, NOT ASSERTED IN PROSE: the self-test parses
# policy/repos.toml and reds if this constant stops equalling the derivation, so raising the
# policy timeout forces this constant up in the SAME PR. Silent divergence from the data is
# the precise defect 6h had — a constant nobody ever compared to a measurement.
EXEC_FLOOR_TIMEOUT_MULTIPLE = 1.5
# MEASURED 2026-07-29 over this repo's completed-run history, all lanes. Held as a constant
# so the "does the floor clear reality" assertion pins against a MEASUREMENT instead of
# against the floor it is checking.
LONGEST_OBSERVED_RUN_SECONDS = 91.5 * 60
EXEC_FLOOR_SECONDS = 135 * 60
BASELINE_SAMPLE = 100
BASELINE_MIN_N = 5
RUNS_PAGE_CAP = 10

INVISIBLE_TRIGGERS = frozenset({"schedule", "workflow_dispatch"})


# --- M4 -----------------------------------------------------------------------------
# WORKFLOW REJECTED AT INGESTION (issue #1353). GitHub accepts the trigger, CREATES a
# workflow run, and executes NO JOB: conclusion `action_required`, `jobs.total_count == 0`,
# about one second. The workflow is dead and the run list reads "waiting for approval".
#
# WHY NOTHING IN THE RING SEES IT. Every existing watcher here — `cron-keepalive`,
# `metrics-alert --stale-check`, `dispatch-stall-alert` (B), and M1 above — answers "did a
# run happen recently?". A rejected workflow KEEPS PRODUCING RUNS on its own cron, each with
# a fresh `created_at`, so every one of those reads it as alive. That is the #922 lesson —
# a run no longer implies the work — recurring in a form none of them was built for. It cost
# this estate an 18-hour dispatcher outage (#1313 -> #1320, the whole fleet idle) and a
# ~90-minute outage of dashboard.yml (c67c7cdf6 -> #1352), which is the HOST of
# `cron-keepalive` and therefore of the revival mesh for every other scheduled lane. Both
# landed on master through review, and both were found by a human, not by a check.
#
# THE MECHANISM IS UNKNOWN and tracked in #1353 — deliberately, this detector does not need
# one. It keys on the OBSERVABLE OUTCOME, so it fires for any cause that produces it.
#
# WHY `event=schedule` IS THE POPULATION, and what that excludes. A scheduled fire is never
# legitimately held for approval: `action_required` on a fork PR waiting for a maintainer is
# the conclusion's normal meaning, and no fork PR can produce a `schedule` run. This also
# costs ZERO extra requests — `fetch_lanes` already pulls exactly this listing for M1 and
# discarded everything but `created_at`. DOCUMENTED GAP, in this file's tradition: a lane
# rejected while carrying only `workflow_dispatch` is NOT sampled. It is censused as
# `not-sampled` rather than silently counted healthy.
#
# THE FALSE POSITIVE THAT REMAINS, and why the job count closes it: a scheduled run held by
# an ENVIRONMENT protection rule can also conclude `action_required` — and this repo does
# gate privileged jobs on the `dispatch-secrets` environment. That run HAS jobs. Zero jobs is
# what separates "GitHub refused to ingest the file" from "a human has not approved a
# deployment", so the count is confirmed before alarming. It is fetched ONLY for a lane that
# already looks rejected, so the healthy repo pays nothing.
MODE_INGESTION = "M4-workflow-ingestion-rejected"
# The conclusion GitHub records on a run it created but never executed. Held as a constant
# for the call sites; every fixture below writes the LITERAL, so mutating this reds.
INGESTION_REJECTED_CONCLUSION = "action_required"
# Every state a lane can exit M4 through, seeded at zero so the census emits a row for each
# on EVERY tick — including the all-clear. A census that only prints what it saw cannot
# answer "would this alarm fire if this branch took 100% of the population?".
M4_CENSUS_STATES = (
    "not-sampled",
    "no-concluded-run",
    "ingesting",
    "approval-gated-with-jobs",
    "rejected-zero-jobs",
    "rejected-jobs-unreadable",
)


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


def cron_minutes(expr: str) -> set[int]:
    """The minutes past the hour `expr` can fire at. THE definition of that expansion (#1046).

    Hour/day/month restrictions are deliberately IGNORED, and that is the fail-closed
    direction for the one question this answers — *is this minute already taken?*
    `41 6 * * 1` (pat-validity, weekly) therefore still holds :41. Over-reporting a taken
    minute costs a schedule author one alternative; under-reporting it hands them a collision.
    """
    if not isinstance(expr, str):
        raise CronError(f"not a string: {expr!r}")
    fields = expr.split()
    if len(fields) != 5:
        raise CronError(f"expected 5 fields, got {len(fields)}: {expr!r}")
    return _expand_field(fields[0], 0, 59)


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


def schedule_minute_map(root) -> dict[str, set[int]]:
    """THE registry cron-minute map — which minute is taken by which workflow — DERIVED (#1046).

    Before this existed the map was hand-copied into five places, and one copy was already
    stale: `regate-sweep` asserted :00/:15/:30/:45 was dashboard's after dashboard had moved,
    which would have walked the next schedule author straight into a collision. That is the
    #958 shape (one literal, N definitions, consumers blind to a repoint) applied to a
    schedule. A consumer that needs the map READS THE TREE through this function; prose that
    names other lanes' minutes is a copy waiting to go stale.

    -> {".github/workflows/<name>.yml": {minutes}} for every workflow carrying a schedule.
    FAIL CLOSED in both directions a caller could be misled by: a missing workflows directory
    raises, and an unparseable cron raises rather than dropping the lane from the map. A lane
    silently absent from this map reads to a collision check as a free minute.
    """
    wf_dir = Path(root) / WORKFLOWS_DIR
    if not wf_dir.is_dir():
        raise AlarmError(f"no workflows directory at {wf_dir}")
    out: dict[str, set[int]] = {}
    for path in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        _, crons, _ = m1_scope(workflow_triggers(path.read_text(encoding="utf-8")))
        if not crons:
            continue
        minutes: set[int] = set()
        for expr in crons:
            minutes |= cron_minutes(expr)
        out[f"{WORKFLOWS_DIR}/{path.name}"] = minutes
    return out


# A FLOOR ON THE EVIDENCE, not a copy of the map: this repo carries 13 scheduled lanes today,
# and the failure this guards is a map derived from a thin checkout or a broken parse, which
# yields 0-1 lanes and makes every collision assertion built on it vacuously green. A floor
# survives retiring a lane; it does not survive the derivation reading nothing.
MIN_SCHEDULED_LANES = 10


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


def find_ingestion_rejections(lanes: list[dict],
                              job_counts: dict) -> tuple[list[dict], dict]:
    """M4. `lanes` carry {runs_sampled, newest_concluded}; `job_counts` maps the run id of
    an apparently-rejected run (as a STRING — JSON object keys are strings, and a dict keyed
    by int here would silently miss every entry that came back through --state-file) to its
    `jobs.total_count`, or to None when that read failed.

    The lane's NEWEST CONCLUDED scheduled run is the whole signal. Rejection is not a flaky
    event: once GitHub refuses a file every subsequent run of it is refused the same way, so
    the newest concluded run states the CURRENT condition and the alert self-clears one cycle
    after a fix lands. An `in_progress` newest run is skipped rather than treated as evidence
    either way — a run with no conclusion has not said anything yet.
    """
    findings: list[dict] = []
    census: dict[str, int] = {state: 0 for state in M4_CENSUS_STATES}

    def bump(state: str) -> None:
        census[state] += 1

    for lane in lanes:
        if not lane.get("runs_sampled"):
            bump("not-sampled")
            continue
        newest = lane.get("newest_concluded")
        if not newest:
            bump("no-concluded-run")
            continue
        if newest.get("conclusion") != INGESTION_REJECTED_CONCLUSION:
            bump("ingesting")
            continue
        jobs = job_counts.get(str(newest.get("id")))
        if isinstance(jobs, int) and jobs > 0:
            # An environment protection rule, not a rejection. Counted, never alarmed on.
            bump("approval-gated-with-jobs")
            continue
        # UNREADABLE COUNTS AS REJECTED. The two directions are not symmetric: a false alarm
        # costs one maintainer glance at a run list, a miss costs the 18 hours #1313 cost.
        # So an unreadable job count alarms and SAYS it was unreadable, rather than resolving
        # an indeterminate read into "healthy".
        bump("rejected-zero-jobs" if isinstance(jobs, int) else "rejected-jobs-unreadable")
        findings.append({
            "mode": MODE_INGESTION,
            "workflow": lane["workflow"],
            "run_id": newest.get("id"),
            "created_at": newest.get("created_at"),
            "conclusion": newest.get("conclusion"),
            "jobs": jobs if isinstance(jobs, int) else None,
        })
    return findings, census


def max_worker_timeout_minutes(text: str) -> int:
    """The LARGEST `worker_timeout_minutes` any target configures in policy/repos.toml.

    The maximum, not this repo's own entry: every target's workers run as runs of THIS
    repository's `worker.yml`, so the longest-lived run this repo can legitimately produce is
    bounded by the most generous timeout in the file (90, sparq), not by the registry's own
    30.

    A line-anchored regex rather than a TOML parse: this script models nothing else in that
    file and the value is a flat integer. The anchor is LOAD-BEARING — repos.toml DOCUMENTS
    the key in a comment (`#   worker_timeout_minutes = positive integer`), so an unanchored
    match would read the documentation as if it were policy.

    A file carrying no assignment at all RAISES. Refusing to derive is the fail-closed
    answer; defaulting to a number nobody measured is how the unreachable 6h floor shipped.
    """
    found = re.findall(r"^[ \t]*worker_timeout_minutes[ \t]*=[ \t]*([0-9]+)", text,
                       flags=re.MULTILINE)
    if not found:
        raise AlarmError("policy carries no worker_timeout_minutes: refusing to guess an "
                         "execution-overrun floor")
    return max(int(value) for value in found)


def exec_floor_for(timeout_minutes: float) -> int:
    """M3's floor for a repo whose longest-lived job is killed at `timeout_minutes`."""
    return int(EXEC_FLOOR_TIMEOUT_MULTIPLE * timeout_minutes * 60)


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


def fetch_live_runs(repo):
    """Every run currently `in_progress` — the LIVE read M3 keys on. Terminates on a SHORT
    page, never on `len >= total_count`: a total_count read before a new run started is an
    undercount and stopping on it truncates while the list grows.

    `status=queued` is deliberately NOT fetched — see the QUEUE WAIT note above. Nothing
    consumes it, and fetching a population no detector reads is the shape of coverage this
    file exists to avoid. It also halves this pass's live-state request cost.
    """
    live = []
    page = 1
    while page <= RUNS_PAGE_CAP:
        payload = _api(repo, f"actions/runs?status=in_progress&per_page=100&page={page}")
        batch = payload.get("workflow_runs")
        if batch is None:
            raise AlarmError("workflow-run listing carries no workflow_runs")
        live.extend(batch)
        if len(batch) < 100:
            return live
        page += 1
    raise AlarmError(f"live `in_progress` listing exceeded {RUNS_PAGE_CAP} pages")


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


def newest_concluded_run(runs):
    """M4. -> {id, conclusion, created_at} for the newest run in `runs` that has CONCLUDED,
    or None. Pure, so the ordering rule is testable without the network.

    The listing arrives newest-first, but that is GitHub's promise rather than this file's,
    and reading position 0 would key on a promise: `max` over the parsed timestamp costs
    nothing and cannot be wrong. Runs missing a `created_at` are unorderable and dropped.
    """
    concluded = [r for r in runs
                 if r.get("status") == "completed" and r.get("conclusion")
                 and r.get("created_at")]
    if not concluded:
        return None
    newest = max(concluded, key=lambda r: _ts(r["created_at"]))
    # The id is stringified HERE, once, so both the job-count map and the hermetic
    # --state-file route key it the same way (JSON object keys are always strings).
    return {"id": str(newest.get("id")), "conclusion": newest.get("conclusion"),
            "created_at": newest.get("created_at")}


def fetch_job_count(repo, run_id):
    """M4. -> the run's `jobs.total_count`, or None when the read failed or was malformed.

    None is NOT zero and must never collapse into it: zero is the rejection fingerprint and
    None is "we could not tell", and the detector reports them as different census states.
    A failure here is swallowed rather than raised because the count is only ever needed for
    a lane that ALREADY looks rejected — letting it abort the pass would take M1 and M3 down
    with it at exactly the moment the repo is in trouble.
    """
    try:
        payload = _api(repo, f"actions/runs/{run_id}/jobs?per_page=1")
    except AlarmError as exc:
        print(f"::warning::ci-latency: M4 could not read jobs for run {run_id}: {exc}")
        return None
    total = payload.get("total_count")
    # `isinstance(True, int)` is True in Python, and `True > 0`, so a boolean would sail
    # through the detector as "this run executed a job" — a malformed payload silencing the
    # alarm. Refuse it here, where the value is still identifiable as not-a-count.
    if isinstance(total, bool) or not isinstance(total, int):
        return None
    return total


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
                "schedule_run_times": [],
                # M4: whether this lane's scheduled runs were actually listed, kept separate
                # from `in_scope` because `in_scope` is ALSO cleared by M1's truncation
                # guard below — and a truncated sample still states the newest run perfectly
                # well, which is all M4 reads.
                "runs_sampled": False, "newest_concluded": None}
        if in_scope and lane["state"] == "active":
            payload = _api(repo, f"actions/workflows/{path.name}/runs"
                                 f"?event=schedule&per_page=100")
            runs = payload.get("workflow_runs")
            if runs is None:
                raise AlarmError(f"{path.name}: schedule-run response carries no runs")
            lane["runs_sampled"] = True
            lane["newest_concluded"] = newest_concluded_run(runs)
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
    # M4 has no threshold to breach — it reports a workflow that is OFF — and the title is
    # what the maintainer triages from, so it says that instead. M1's and M3's titles are
    # deliberately byte-unchanged: `_find_open_alert` falls back to a title match when a
    # marker is absent, so re-wording them would orphan any alert already open.
    if mode == MODE_INGESTION:
        return ("ci-latency: a workflow is REJECTED at ingestion — GitHub is creating runs "
                "that execute NO JOB")
    return f"ci-latency: {mode} breached its measured threshold"


def render_body(mode, repo, findings, census, now, run_url):
    # M4 reports a workflow that is OFF, not a threshold that moved, so it needs its own
    # lead sentence. A NAMED local rather than a `lines[3] = ...` patch: an index into the
    # literal below silently rewrites the wrong element the day anyone adds a header line.
    lead = (f"`{mode}` breached its measured threshold in `{repo}` at "
            f"`{now:%Y-%m-%dT%H:%M:%SZ}`.")
    if mode == MODE_INGESTION:
        lead = (f"A workflow in `{repo}` is being REJECTED at ingestion as of "
                f"`{now:%Y-%m-%dT%H:%M:%SZ}` — GitHub creates the run and executes no job, "
                f"so every liveness watcher in the ring still reads the lane as alive. "
                f"Mechanism tracked in #1353; the remedy that has worked twice is to REVERT "
                f"the last change to the named workflow file.")
    lines = [
        marker(mode),
        "> 🤖 SPARQ agent — automated ops-alert (CI execution latency)",
        "",
        lead,
        "",
    ]
    for f in findings:
        if mode == MODE_INGESTION:
            jobs = "UNREADABLE" if f["jobs"] is None else f["jobs"]
            lines.append(
                f"- `{f['workflow']}` — newest concluded `schedule` run {f['run_id']} "
                f"(created {f['created_at']}) concluded **{f['conclusion']}** with "
                f"**jobs.total_count = {jobs}**")
        elif mode.startswith("M1"):
            lines.append(
                f"- `{f['workflow']}` fired **{f['actual']}** of an achievable "
                f"**{f['expected']}** in {f['window_hours']:g}h (nominal "
                f"{f['nominal']}, ratio {f['ratio']}, floor {CRON_DELIVERY_FLOOR}); "
                f"cron `{' | '.join(f['crons'])}`")
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
          state="active", fires=0, now=None, spacing_min=20, created_hours_ago=None,
          runs_sampled=True, newest_conclusion="success", run_id="1"):
    """`created_hours_ago` gives the lane a birth date, for the NEW-LANE WINDOW. `None`
    means an established lane (no `created_at`), which must behave exactly as before.

    The M4 fields default to a HEALTHY lane — sampled, newest scheduled run concluded — so
    every pre-existing fixture below keeps meaning what it meant. `newest_conclusion=None`
    is the lane whose newest scheduled run has not concluded yet.
    """
    now = now or dt.datetime(2026, 7, 28, 12, 0, tzinfo=dt.timezone.utc)
    first = now - dt.timedelta(minutes=CRON_GRACE_MINUTES + 1)
    lane = {"workflow": workflow, "crons": list(crons), "cron_only": cron_only,
            "in_scope": in_scope, "state": state,
            "runs_sampled": runs_sampled,
            "newest_concluded": ({"id": run_id, "conclusion": newest_conclusion,
                                  "created_at": "2026-07-28T11:50:00Z"}
                                 if newest_conclusion else None),
            "schedule_run_times": [first - dt.timedelta(minutes=spacing_min * i)
                                   for i in range(fires)]}
    if created_hours_ago is not None:
        lane["created_at"] = (now - dt.timedelta(hours=created_hours_ago)
                              ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return lane


def _run_obj(status="in_progress", event="schedule", path=".github/workflows/a.yml",
             age_min=10, now=None, name="A", attempt=1, created_age_min=None):
    """The REAL shape of an `actions/runs` element, not a minimal hand-built dict.

    A narrow fixture is a vacuity generator. `started = run.get("updated_at") or
    run_started_at` SURVIVED the first mutation battery for exactly one reason: no fixture
    carried `updated_at`, while EVERY live run does — and on a live run `updated_at` is
    bumped continuously, so that mutant collapses M3's age to ~0 and the mode never fires
    again. The keys and their relationships below are taken from a real payload
    (this repo's run 30318886362).

    `created_age_min` reproduces the RE-RUN shape, where the run-level `created_at` is
    FROZEN at attempt 1 while `run_started_at` tracks the live attempt — M3 must key on
    the latter. See the QUEUE WAIT note near the top of this file.
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
    # Same trap, on the schedule-map floor (#1046). A floor of 0 or 1 has no teeth: the case it
    # exists to catch is a sparse checkout yielding exactly the ONE lane its consumer already
    # knows about, and every collision assertion built on that map is then vacuously green.
    # Bounded above by the 13 lanes this repo actually carries, so it cannot be raised into a
    # permanent red either.
    chk("MIN_SCHEDULED_LANES is a floor with teeth (strictly above the one-lane thin checkout) "
        "and stays reachable by this repo's real lane count", 2 <= MIN_SCHEDULED_LANES <= 13)
    chk("EXEC_OVERRUN_MULTIPLE is inside the band that still catches the 2.08x outlier",
        1.25 <= EXEC_OVERRUN_MULTIPLE <= 2.0)
    # THE FLOOR HAS TO CLEAR REALITY FROM BOTH SIDES: above the longest run this repo has
    # ever produced (or it cries wolf) and below what a run can actually reach (or it is
    # INERT, which is what 6h was — #1140). Both bounds are written as literals that do not
    # derive from EXEC_FLOOR_SECONDS, so moving the constant reds them.
    chk("EXEC_FLOOR_SECONDS clears the longest run this repo has ever produced (91.5 min)",
        EXEC_FLOOR_SECONDS > LONGEST_OBSERVED_RUN_SECONDS)
    chk("EXEC_FLOOR_SECONDS is REACHABLE — strictly below the retired 6h job ceiling that "
        "no run of this repo could ever cross", EXEC_FLOOR_SECONDS < 6 * 60 * 60)
    chk("EXEC_FLOOR_SECONDS is 8100s (135 min)", EXEC_FLOOR_SECONDS == 8100)
    chk("LONGEST_OBSERVED_RUN_SECONDS is the measured 91.5-min maximum",
        LONGEST_OBSERVED_RUN_SECONDS == 5490)
    chk("EXEC_FLOOR_TIMEOUT_MULTIPLE leaves headroom over the timeout itself, and not so "
        "much that the floor stops being reachable",
        1.25 <= EXEC_FLOOR_TIMEOUT_MULTIPLE <= 2.0)
    chk("floor derivation: 1.5x a 90-minute policy timeout is 135 minutes",
        exec_floor_for(90) == 135 * 60)
    chk("floor derivation TRACKS the timeout rather than pinning one value",
        exec_floor_for(180) == 270 * 60 and exec_floor_for(30) == 45 * 60)
    chk("BASELINE_MIN_N is 5", BASELINE_MIN_N == 5)

    # --- the policy parse the floor derives from ---------------------------------------
    # Hermetic fixtures, so these pin the PARSER; the seam block below pins the parser
    # against the real policy/repos.toml and the shipped constant against its output.
    _pol = ('[repos."o/a"]\nworker_timeout_minutes = 30\n'
            '[repos."o/b"]\n  worker_timeout_minutes = 90   # inline comment\n')
    chk("policy parse takes the MAX timeout across targets (this repo runs every target's "
        "workers)", max_worker_timeout_minutes(_pol) == 90)
    # ANCHOR ANTI-VACUITY: repos.toml documents the key in a comment. Without `^[ \t]*` the
    # parser reads the DOCUMENTATION, which here would return 600 instead of 45.
    chk("policy parse ignores a COMMENTED occurrence of the key",
        max_worker_timeout_minutes(
            "#   worker_timeout_minutes = 600\nworker_timeout_minutes = 45\n") == 45)
    try:
        max_worker_timeout_minutes('[repos."o/a"]\nmax_concurrent = 4\n')
        chk("a policy with no timeout must FAIL CLOSED, never default", False)
    except AlarmError:
        pass
    except Exception:
        # Deleting the guard leaves `max([])` raising a bare ValueError, which would abort
        # this suite mid-run and record as a kill while every row below it never executed.
        # Naming the wrong-exception case keeps that mutant a FAIL ROW instead of a crash.
        chk("a policy with no timeout raises AlarmError, not a bare crash", False)
    chk("policy/repos.toml is a REQUIRED_FILE, so the derivation seam is reachable on the "
        "watchdog's SPARSE live checkout and not only in pr-gate's full one",
        POLICY_FILE in REQUIRED_FILES)

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

    # --- cron_minutes: the expansion the DERIVED schedule map is built on (#1046) ---
    # Every expected value here is hand-computed. Writing it as `_expand_field(...)` would
    # read the expectation out of the code under test, which is the assertion shape that
    # cannot fail (AGENTS.md pre-flight 2b).
    chk("cron_minutes */15 -> :00/:15/:30/:45", cron_minutes("*/15 * * * *") == {0, 15, 30, 45})
    chk("cron_minutes 7-59/15 -> :07/:22/:37/:52 — a stepped RANGE does not restart at :00, "
        "and reading it as */15 is exactly how a hand-copied map lies about a taken minute",
        cron_minutes("7-59/15 * * * *") == {7, 22, 37, 52})
    chk("cron_minutes 3,13,23,33,43,53 -> the six explicit minutes",
        cron_minutes("3,13,23,33,43,53 * * * *") == {3, 13, 23, 33, 43, 53})
    chk("cron_minutes ignores the hour/day fields — a weekly 06:41 lane still HOLDS :41, "
        "because the question this answers is `is this minute taken`",
        cron_minutes("41 6 * * 1") == {41})
    for bad in ("", "* * * *", "* * * * * *", "60 * * * *", "*/0 * * * *", 41, None):
        try:
            cron_minutes(bad)
            chk(f"cron_minutes {bad!r} must raise CronError", False)
        except CronError:
            pass
        except Exception:
            chk(f"cron_minutes {bad!r} raised the wrong error", False)

    # --- schedule_minute_map on a HERMETIC tree. The live-tree rows in the seam section can
    # only exercise the POSITIVE direction (this repo has no malformed cron and no missing
    # workflows directory), and the whole fail-closed claim lives in the negative one: a lane
    # that vanishes from the map reads to a collision check as a FREE minute. ---
    with tempfile.TemporaryDirectory() as _tmp:
        _wf = Path(_tmp) / WORKFLOWS_DIR
        _wf.mkdir(parents=True)
        (_wf / "a.yml").write_text("on:\n  schedule:\n    - cron: '4,24,44 * * * *'\njobs: {}\n")
        (_wf / "b.yml").write_text("on:\n  schedule:\n    - cron: '*/15 * * * *'\n"
                                   "    - cron: '7 1 * * *'\njobs: {}\n")
        (_wf / "c.yml").write_text("on:\n  push:\njobs: {}\n")
        chk("schedule map: one entry per SCHEDULED lane, minutes UNIONED across that lane's "
            "crons, unscheduled lanes absent",
            schedule_minute_map(_tmp) == {f"{WORKFLOWS_DIR}/a.yml": {4, 24, 44},
                                          f"{WORKFLOWS_DIR}/b.yml": {0, 7, 15, 30, 45}})
        (_wf / "d.yml").write_text("on:\n  schedule:\n    - cron: 'every 5 min'\njobs: {}\n")
        try:
            schedule_minute_map(_tmp)
            chk("schedule map: an UNPARSEABLE cron RAISES — dropping that lane would hand a "
                "collision check a minute it cannot see is taken", False)
        except CronError:
            pass
        except Exception:
            chk("schedule map: an unparseable cron raised the wrong error", False)
    try:
        # The directory is gone with the context manager: an absent tree must not read as
        # "no lanes are scheduled".
        schedule_minute_map(_tmp)
        chk("schedule map: a MISSING workflows directory raises rather than returning {}", False)
    except AlarmError:
        pass
    except Exception:
        chk("schedule map: a missing workflows directory raised the wrong error", False)

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

    # --- M3 ---
    base = {(".github/workflows/a.yml", "schedule"): {"p90": 3600.0, "n": 50}}
    f, c = find_execution_overruns([_run_obj(age_min=30, now=NOW)], base, NOW)
    chk("M3 quiet inside the band", not f and c.get("in-progress-within-threshold") == 1)
    f, c = find_execution_overruns([_run_obj(age_min=8 * 60, now=NOW)], base, NOW)
    chk("M3 raises past the band", len(f) == 1 and c.get("execution-overrun") == 1)
    chk("M3 ignores queued runs (its population is in_progress only)",
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
    chk("M3 is quiet at 134 min with no baseline — pins the 135-min floor from BELOW",
        not find_execution_overruns([_run_obj(age_min=134, now=NOW)], {}, NOW)[0])
    chk("M3 raises at 136 min with no baseline — pins the 135-min floor from ABOVE",
        len(find_execution_overruns([_run_obj(age_min=136, now=NOW)], {}, NOW)[0]) == 1)
    # --- #1140: THE FLOOR MUST BE REACHABLE, ON THE REAL LANE ------------------------
    # The test the issue is built on: take the LONGEST RUN THE REPO HAS ACTUALLY PRODUCED
    # (91.5 min on worker.yml, p90 31.6 min over n=500) and check the threshold sits above
    # it AND that a run which genuinely hangs crosses it. Under the retired 6h floor the
    # second half was impossible — policy kills that lane's agent job at 90 min, so no run
    # could ever reach 360 min and M3 could not fire on any lane, ever.
    # `workflow_dispatch` because that is worker.yml's ONLY trigger — the baseline is keyed
    # on (workflow, event), so a fixture naming an event the lane cannot emit would be
    # testing a cell that never exists in production.
    worker_lane = {(".github/workflows/worker.yml", "workflow_dispatch"):
                   {"p90": 31.6 * 60, "n": 500}}

    def _worker_run(age_min):
        return _run_obj(path=".github/workflows/worker.yml", event="workflow_dispatch",
                        age_min=age_min, now=NOW)

    chk("M3 is quiet at the longest run worker.yml has ever produced (91.5 min against its "
        "own measured p90) — the no-false-positive half",
        not find_execution_overruns([_worker_run(92)], worker_lane, NOW)[0])
    chk("M3 RAISES on a 3h worker.yml run — reachable now, structurally impossible at 6h",
        len(find_execution_overruns([_worker_run(180)], worker_lane, NOW)[0]) == 1)
    chk("the worker.yml fixture is not vacuous: 2x its measured p90 (63 min) is BELOW the "
        "floor, so the floor is what governs that lane",
        EXEC_OVERRUN_MULTIPLE * 31.6 * 60 < EXEC_FLOOR_SECONDS)
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
                   [_run_obj(age_min=1, now=NOW)], base, NOW, CRON_WINDOW_HOURS)
    chk("a clean pass still emits a non-empty census for every mode",
        all(res[m][1] for m in MODES) and not any(res[m][0] for m in MODES))

    # --- transport decisions ---
    chk("findings => upsert", decide([{"x": 1}], None) == "upsert")
    chk("findings => upsert even when an alert is open", decide([{"x": 1}], 7) == "upsert")
    chk("recovery with an open alert => close", decide([], 7) == "close")
    chk("clean with no alert => noop", decide([], None) == "noop")
    body = render_body(MODES[1], "o/r", [{"workflow": "a", "run_id": 1, "event": "push",
                                          "age_seconds": 99, "threshold_seconds": 60,
                                          "basis": "floor"}],
                       {"execution-overrun": 1}, NOW, "u")
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

    # --- M4: workflow REJECTED at ingestion (#1353) ----------------------------------
    # Every fixture below writes the LITERAL "action_required" and the LITERAL job counts,
    # never MODE_INGESTION/INGESTION_REJECTED_CONCLUSION, so the constants are pinned by
    # values that do not derive from them: mutating either constant reds these rows instead
    # of rescaling with them.
    chk("M4 keys on the literal conclusion GitHub records for an unexecuted run",
        INGESTION_REJECTED_CONCLUSION == "action_required")
    chk("M4's mode name is stable — it is the ops-alert marker key, so renaming it orphans "
        "any open alert", MODE_INGESTION == "M4-workflow-ingestion-rejected")
    chk("M4 is REGISTERED, and M1/M3's names are unchanged beside it (exact tuple, so a "
        "dropped mode cannot pass as a reordering)",
        MODES == ("M1-cron-firing-deficit", "M3-execution-overrun",
                  "M4-workflow-ingestion-rejected"))
    chk("M4's census names every exit, in order, so the all-clear prints a row per state",
        M4_CENSUS_STATES == ("not-sampled", "no-concluded-run", "ingesting",
                             "approval-gated-with-jobs", "rejected-zero-jobs",
                             "rejected-jobs-unreadable"))

    def _sched_run(rid, conclusion, created, status="completed"):
        return {"id": rid, "status": status, "conclusion": conclusion,
                "created_at": created, "event": "schedule"}

    # newest_concluded_run: ORDERING, not position. A `runs[0]` implementation passes on a
    # newest-first list and silently keys on a stale run the moment GitHub's order changes,
    # so the list here is deliberately OLDEST-first.
    _ordered = [_sched_run(11, "success", "2026-07-28T09:00:00Z"),
                _sched_run(22, "action_required", "2026-07-28T11:00:00Z")]
    chk("M4 picks the NEWEST concluded run by timestamp, not by list position",
        (newest_concluded_run(_ordered) or {}).get("id") == "22")
    # A DISTINCT question from the row above, not a restatement of it: that one would pass
    # on an int id too. GitHub sends the id as an INTEGER and the job-count map is keyed by
    # STRINGS (it round-trips through JSON), so a passthrough here reads correctly at every
    # glance and resolves nothing — the detector would report every rejection as
    # `rejected-jobs-unreadable`, alarming with fabricated evidence instead of a real count.
    chk("M4 stringifies the run id at the source, from GitHub's integer",
        _ordered[1]["id"] == 22
        and isinstance((newest_concluded_run(_ordered) or {}).get("id"), str))
    chk("M4 ignores a run that has not concluded — no conclusion has said nothing yet",
        (newest_concluded_run([
            _sched_run(33, None, "2026-07-28T11:59:00Z", status="in_progress"),
            _sched_run(11, "success", "2026-07-28T09:00:00Z")]) or {}).get("id") == "11")
    chk("M4 reports NO newest-concluded run when every run is still live",
        newest_concluded_run([_sched_run(33, None, "2026-07-28T11:59:00Z",
                                         status="in_progress")]) is None)
    chk("M4 reports NO newest-concluded run over an empty listing",
        newest_concluded_run([]) is None)

    _M4_CLEAN = {s: 0 for s in M4_CENSUS_STATES}

    def _m4(lane_kwargs, job_counts):
        return find_ingestion_rejections([_lane(now=NOW, **lane_kwargs)], job_counts)

    # THE ACCEPT PATH: the exact shape both outages produced.
    _f, _c = _m4({"workflow": "rejected.yml", "newest_conclusion": "action_required",
                  "run_id": "77"}, {"77": 0})
    chk("M4 ALARMS on the measured fingerprint — newest scheduled run `action_required` "
        "with zero jobs", len(_f) == 1 and _f[0]["workflow"] == "rejected.yml")
    chk("M4's finding carries the run id and job count a maintainer needs to confirm it",
        _f and _f[0]["run_id"] == "77" and _f[0]["jobs"] == 0)
    chk("M4's census counts the rejection and nothing else",
        _c == {**_M4_CLEAN, "rejected-zero-jobs": 1})
    # THE REJECT PATH, and the reason this detector is not just a conclusion grep: a
    # scheduled run held by an environment protection rule concludes `action_required` too.
    # It HAS jobs. Deleting the job-count confirmation makes this row red.
    _f, _c = _m4({"workflow": "gated.yml", "newest_conclusion": "action_required",
                  "run_id": "78"}, {"78": 4})
    chk("M4 does NOT alarm on an environment-approval hold — that run executed jobs",
        _f == [] and _c == {**_M4_CLEAN, "approval-gated-with-jobs": 1})
    # UNREADABLE IS NOT HEALTHY. Distinct census state, and it still alarms: a miss here
    # costs the 18 hours #1313 cost, a false alarm costs one glance at a run list.
    _f, _c = _m4({"workflow": "unknown.yml", "newest_conclusion": "action_required",
                  "run_id": "79"}, {"79": None})
    chk("M4 alarms when the job count is UNREADABLE, and says so in its own census row",
        len(_f) == 1 and _f[0]["jobs"] is None
        and _c == {**_M4_CLEAN, "rejected-jobs-unreadable": 1})
    _f, _c = _m4({"workflow": "unknown.yml", "newest_conclusion": "action_required",
                  "run_id": "80"}, {})
    chk("M4 treats a MISSING job-count entry as unreadable, never as zero and never as OK",
        len(_f) == 1 and _c == {**_M4_CLEAN, "rejected-jobs-unreadable": 1})
    # THE HEALTHY POPULATION, stated so "no findings" cannot be reached by a detector that
    # stopped looking: the census must place the lane in `ingesting`.
    _f, _c = _m4({"workflow": "live.yml"}, {})
    chk("M4 is quiet on a lane whose newest scheduled run concluded normally, and PLACES it",
        _f == [] and _c == {**_M4_CLEAN, "ingesting": 1})
    _f, _c = _m4({"workflow": "unsampled.yml", "runs_sampled": False}, {})
    chk("M4 counts an unsampled lane as unsampled — never as healthy",
        _f == [] and _c == {**_M4_CLEAN, "not-sampled": 1})
    _f, _c = _m4({"workflow": "fresh.yml", "newest_conclusion": None}, {})
    chk("M4 counts a lane with no concluded run as such — never as healthy",
        _f == [] and _c == {**_M4_CLEAN, "no-concluded-run": 1})
    # The `--state-file` route round-trips through JSON, where every object key becomes a
    # STRING. An int-keyed lookup reads nothing there and the detector goes permanently
    # quiet on the live-equivalent path while every in-process assertion above stays green.
    _rt = json.loads(json.dumps({"job_counts": {"77": 0}}))
    _f, _ = find_ingestion_rejections(
        [_lane(now=NOW, workflow="rejected.yml", newest_conclusion="action_required",
               run_id="77")], _rt["job_counts"])
    chk("M4 still resolves the job count after a JSON round-trip (string keys)",
        len(_f) == 1 and _f[0]["jobs"] == 0)

    # THE READ ITSELF. `fetch_job_count` is the one place `0` and "could not tell" can be
    # confused, and confusing them is not a missed alarm — it is a FABRICATED one: the alert
    # body would state `jobs.total_count = 0` as measured evidence of a rejection nobody
    # read. A mutant returning 0 on a failed read survived every other assertion here.
    _real_jobs_api = globals()["_api"]
    try:
        globals()["_api"] = lambda repo, path: {"total_count": 3}
        chk("fetch_job_count returns the count GitHub reported",
            fetch_job_count("o/r", 77) == 3)
        globals()["_api"] = lambda repo, path: {"total_count": 0}
        chk("fetch_job_count reports a real zero as a real zero",
            fetch_job_count("o/r", 77) == 0)

        def _raising_api(repo, path):
            raise AlarmError("boom")

        globals()["_api"] = _raising_api
        chk("a FAILED job read is None, never 0 — a read that did not happen must not be "
            "published as measured evidence of zero jobs",
            fetch_job_count("o/r", 77) is None)
        globals()["_api"] = lambda repo, path: {}
        chk("a payload carrying no total_count is None, never 0",
            fetch_job_count("o/r", 77) is None)
        globals()["_api"] = lambda repo, path: {"total_count": "0"}
        chk("a non-integer total_count is None, never coerced",
            fetch_job_count("o/r", 77) is None)
        globals()["_api"] = lambda repo, path: {"total_count": True}
        chk("a boolean total_count is refused — `True` IS an int in Python and `True > 0`, "
            "so it would silently reclassify a rejection as approval-gated",
            fetch_job_count("o/r", 77) is None)
    finally:
        globals()["_api"] = _real_jobs_api

    # RENDERING. M4 must not fall through to M3's line format, which would print a
    # threshold and an age this mode does not have.
    _m4_body = render_body(MODE_INGESTION, "o/r",
                           [{"mode": MODE_INGESTION, "workflow": ".github/workflows/d.yml",
                             "run_id": "77", "created_at": "2026-07-28T11:50:00Z",
                             "conclusion": "action_required", "jobs": 0}],
                           {**_M4_CLEAN, "rejected-zero-jobs": 1}, NOW, "u")
    chk("M4's body names the workflow, the run and the zero job count",
        ".github/workflows/d.yml" in _m4_body and "jobs.total_count = 0" in _m4_body
        and "77" in _m4_body)
    chk("M4's body does NOT render through M3's execution-overrun format",
        "in progress" not in _m4_body and "threshold" not in _m4_body)
    chk("M4's body points at the tracking issue and the remedy that has worked twice",
        "#1353" in _m4_body and "REVERT" in _m4_body)
    _unreadable_body = render_body(MODE_INGESTION, "o/r",
                                   [{"mode": MODE_INGESTION, "workflow": "d.yml",
                                     "run_id": "78", "created_at": "x",
                                     "conclusion": "action_required", "jobs": None}],
                                   dict(_M4_CLEAN), NOW, "u")
    chk("M4's body says UNREADABLE rather than printing a job count it never read",
        "jobs.total_count = UNREADABLE" in _unreadable_body)
    chk("M4 gets its own triage title — it reports a workflow that is OFF, not a threshold",
        title_for(MODE_INGESTION)
        == ("ci-latency: a workflow is REJECTED at ingestion — GitHub is creating runs "
            "that execute NO JOB"))
    # ANTI-VACUITY on the branch above: M1's and M3's titles must be byte-unchanged, or the
    # title fallback in `_find_open_alert` orphans alerts that are already open.
    chk("M1's alert title is unchanged by M4's title branch",
        title_for(MODES[0]) == "ci-latency: M1-cron-firing-deficit breached its measured "
                               "threshold")
    chk("M3's alert title is unchanged by M4's title branch",
        title_for(MODES[1]) == "ci-latency: M3-execution-overrun breached its measured "
                               "threshold")

    # --- exit codes + the empty-scan-set fail-loud ---
    # `tempfile` is imported at module scope (the schedule-map rows above use it too). A local
    # `import tempfile` here would rebind the name for the WHOLE function, so the earlier use
    # would raise UnboundLocalError before this line ever ran.
    def _rc(lanes, live=(), job_counts=None):
        state = {"repo": "o/r",
                 "lanes": [dict(x, schedule_run_times=[
                     t.strftime("%Y-%m-%dT%H:%M:%SZ") for t in x["schedule_run_times"]])
                     for x in lanes],
                 "live_runs": list(live), "baselines": {},
                 "job_counts": dict(job_counts or {})}
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
    # Same 100% question for M4, and it needs its own row: `in_scope` is satisfied by a
    # DISABLED lane, whose runs are never listed, so the M1 guard above does not cover it.
    chk("a scan set in which no lane's runs were sampled is fail-loud exit 2",
        _rc([_lane(fires=CAP, now=NOW, runs_sampled=False)]) == 2)
    chk("...and the SAME lane sampled is exit 0 (the guard above is not vacuous)",
        _rc([_lane(fires=CAP, now=NOW, runs_sampled=True)]) == 0)
    # END TO END through main(): the finding has to survive the JSON state file, classify(),
    # the census print and render_body. Every assertion above is in-process.
    _e2e = io.StringIO()
    with contextlib.redirect_stdout(_e2e):
        _rc([_lane(fires=CAP, now=NOW),
             _lane(workflow=".github/workflows/dead.yml", fires=CAP, now=NOW,
                   newest_conclusion="action_required", run_id="77")],
            job_counts={"77": 0})
    chk("end to end: a rejected lane reaches the rendered alert body by name",
        ".github/workflows/dead.yml" in _e2e.getvalue()
        and "jobs.total_count = 0" in _e2e.getvalue())
    chk("end to end: the healthy sibling lane is NOT named as rejected "
        "(the run is not alarming over the whole population)",
        _e2e.getvalue().count("jobs.total_count") == 1)
    chk("end to end: M4's census prints on the all-clear too, every state, including zeros",
        all(f"{state}: 0" in _e2e.getvalue() or f"{state}: 1" in _e2e.getvalue()
            for state in M4_CENSUS_STATES))

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
        # M4 REACHES THE SAME TRANSPORT. Its detector is proved pure above; a detector whose
        # findings never reach `_apply` alarms into a void, and this per-mode loop is the
        # only thing that carries them there. Exact list, so M4's POSITION is pinned too —
        # `_find_open_alert` is called per mode, and a reordered loop would file M4's body
        # under another mode's marker.
        applied.clear()
        rejected = {"repo": "o/r", "baselines": {}, "live_runs": [],
                    "job_counts": {"77": 0},
                    "lanes": [dict(_lane(fires=CAP, now=NOW,
                                         workflow=".github/workflows/dead.yml",
                                         newest_conclusion="action_required",
                                         run_id="77"),
                                   schedule_run_times=[])]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(rejected, fh)
            rejected_path = fh.name
        main(["--state-file", rejected_path, "--now", "2026-07-28T12:00:00Z"])
        chk("a rejected lane upserts the M4 ops-alert, in M4's own slot",
            applied == ["upsert", "noop", "upsert"])
    finally:
        globals()["_find_open_alert"], globals()["_apply"] = _real_find, _real_apply

    # `fetch_lanes` must carry the birth date the NEW-LANE WINDOW reads, or that guard is
    # permanently unreachable in production while its unit tests stay green. (This check
    # was collateral damage when the M2 region was cut; the battery caught its absence.)
    # M4's detector is proved pure above; everything it reads is assembled on the LIVE path,
    # which no pure assertion reaches. A detector wired to a field nothing populates is
    # permanently quiet with a green suite, so the live route is driven here against a
    # stubbed `_api` — including the job-count confirmation, which is the only thing between
    # M4 and alarming on every environment-approval hold.
    _real_lanes_api = globals()["_api"]
    _GROOM_FILE = GROOM_WORKFLOW.split("/")[-1]

    def _lanes_api_for(conclusion, asked):
        def _stub(repo, path):
            asked.append(path)
            if path.startswith("actions/workflows?"):
                return {"workflows": [{"path": GROOM_WORKFLOW, "state": "active",
                                       "created_at": "2026-07-01T00:00:00Z"}]}
            if path.startswith(f"actions/workflows/{_GROOM_FILE}/runs"):
                return {"workflow_runs": [
                    {"id": 77, "status": "completed", "conclusion": conclusion,
                     "created_at": "2026-07-28T11:50:00Z", "event": "schedule"}]}
            if "/jobs?" in path:
                return {"total_count": 0}
            return {"workflow_runs": []}
        return _stub

    try:
        _asked_rejected = []
        globals()["_api"] = _lanes_api_for("action_required", _asked_rejected)
        _fetched = {lane["workflow"]: lane for lane
                    in fetch_lanes("o/r", Path(__file__).resolve().parents[1],
                                   CRON_WINDOW_HOURS, NOW)}
        chk("fetch_lanes carries each lane's created_at off the workflow listing",
            _fetched.get(GROOM_WORKFLOW, {}).get("created_at") == "2026-07-01T00:00:00Z")
        chk("fetch_lanes marks a lane whose scheduled runs it listed as SAMPLED — M4's "
            "entire population, and its fail-loud, key on this flag",
            _fetched.get(GROOM_WORKFLOW, {}).get("runs_sampled") is True)
        chk("fetch_lanes carries the newest CONCLUDED scheduled run into the lane, with "
            "the id already stringified",
            _fetched.get(GROOM_WORKFLOW, {}).get("newest_concluded")
            == {"id": "77", "conclusion": "action_required",
                "created_at": "2026-07-28T11:50:00Z"})
        _asked_rejected.clear()
        _live_out = io.StringIO()
        with contextlib.redirect_stdout(_live_out):
            _live_rc = main(["--repo", "o/r", "--dry-run"])
        chk("the LIVE path confirms the job count for a lane that looks rejected",
            any("/jobs?" in p for p in _asked_rejected))
        chk("the LIVE path reaches M4's alert body, naming the rejected lane and its zero "
            "job count", _live_rc == 0
            and GROOM_WORKFLOW in _live_out.getvalue()
            and "jobs.total_count = 0" in _live_out.getvalue())
        # THE COST CLAIM, asserted instead of merely written down: M4 is documented as
        # costing ZERO extra requests on a healthy repo. A job-count read per lane per tick
        # would be a real budget change on a repo that has measured a 403 at ~7969
        # requests/h, and nothing except this row would notice it had happened.
        _asked_healthy = []
        globals()["_api"] = _lanes_api_for("success", _asked_healthy)
        with contextlib.redirect_stdout(io.StringIO()):
            main(["--repo", "o/r", "--dry-run"])
        chk("a HEALTHY repo pays NOTHING for M4 — no job-count request is made at all",
            _asked_healthy and not [p for p in _asked_healthy if "/jobs?" in p])
    finally:
        globals()["_api"] = _real_lanes_api

    # --- QUEUE WAIT IS AN HONESTLY DOCUMENTED GAP, and must stay one ------------------
    # An alarm reading a variable that never moves answers "would we know if we were
    # starved?" with a confident yes. Two failure directions are pinned: silently RE-ADDING
    # a detector (implying coverage that is not evidenced), and silently DELETING the
    # evidence that justifies its absence.
    _g = globals()
    for _gone in ("find_queue_overruns", "QUEUE_MAX_WAIT_SECONDS", "attempt_created_at",
                  "resolve_attempt_created", "ATTEMPT_CREATED_KEY"):
        chk(f"no queue-wait detector: `{_gone}` is absent (needs an observed positive "
            f"first — see the QUEUE WAIT note)", _gone not in _g)
    chk("the reported modes do not imply queue coverage",
        not any("M2" in m or "queue" in m.lower() for m in MODES))
    _clean = classify([_lane(fires=CAP, now=NOW)], [_run_obj(age_min=1, now=NOW)],
                      base, NOW, CRON_WINDOW_HOURS)
    _body = render_body(MODES[0], "o/r", [], _clean[MODES[0]][1], NOW, "u")
    chk("the alert body never mentions a queue mode", "queue" not in _body.lower())
    # The live read must not fetch a population nothing consumes.
    _real_api2 = globals()["_api"]
    try:
        _asked = []

        def _spy_api(repo, path):
            _asked.append(path)
            return {"workflow_runs": []}

        globals()["_api"] = _spy_api
        fetch_live_runs("o/r")
        chk("the live read does not fetch `status=queued` (nothing consumes it)",
            _asked and not [u for u in _asked if "status=queued" in u])
        chk("the live read DOES fetch `status=in_progress` (M3's population)",
            [u for u in _asked if "status=in_progress" in u])
    finally:
        globals()["_api"] = _real_api2
    # Pins the CONSEQUENCE deliberately: deleting the justification reds loudly rather
    # than leaving a bare unexplained absence. Each anchor is a measured fact, not prose.
    _src = Path(__file__).resolve().read_text(encoding="utf-8")
    for _anchor, _why in (
            ("44,190", "corpus size behind 'the variable never moves'"),
            ("max-parallel: 8", "why run 30333511110 was NOT a capacity event"),
            ("30333511110", "the run the capacity inference was drawn from"),
            ("30318886362", "the re-run behind the fabricated known positive")):
        chk(f"gap evidence retained: {_anchor} ({_why})", _anchor in _src)

    # --- YAML SEAM. Neither `bash -n` nor actionlint can see which inputs a watchdog
    # keys on, so the hosting job is asserted structurally, by EXACT match. ---
    root = Path(__file__).resolve().parents[1]
    missing = [p for p in REQUIRED_FILES if not (root / p).exists()]
    if missing:
        # Sparse checkout dropped an input: the seam assertions would be silently
        # unreachable on the live path, which is worse than failing here.
        chk(f"seam: REQUIRED_FILES present (missing: {missing})", False)
    else:
        # THE POLICY SEAM. EXEC_FLOOR_SECONDS claims to be 1.5x the longest configured
        # `worker_timeout_minutes`; this is the only thing that keeps that claim true. Raise
        # the timeout in policy/repos.toml without raising the floor and this reds — which is
        # exactly what did NOT happen while the floor sat at a hand-picked 6h (#1140).
        _policy_timeout = max_worker_timeout_minutes(
            (root / POLICY_FILE).read_text(encoding="utf-8"))
        chk(f"seam: the M3 floor equals 1.5x policy's longest worker_timeout_minutes "
            f"(policy says {_policy_timeout} min => "
            f"{exec_floor_for(_policy_timeout) // 60} min)",
            EXEC_FLOOR_SECONDS == exec_floor_for(_policy_timeout))
        # ANTI-VACUITY for the parser against the REAL file: a regex that matched nothing
        # would raise above, but one that matched the wrong line could return anything, so
        # pin the value the live policy actually carries.
        chk("seam: policy/repos.toml's longest worker timeout is still the measured 90 min "
            "(if policy moved it, re-measure the longest run and re-derive the floor)",
            _policy_timeout == 90)
        # --- THE DERIVED SCHEDULE MAP (#1046), against the LIVE tree ------------------
        # A map is only worth reading if it saw every scheduled lane: a lane missing from it
        # reads to a collision check as a FREE minute. So the YAML derivation is cross-checked
        # against an INDEPENDENT raw-text oracle — two unrelated readings of the tree must
        # agree on the lane SET. (Pinning the MINUTES here instead would re-create the very
        # hand-copy this function exists to delete; pinning them from the map would be the
        # tautology AGENTS.md pre-flight 2b names.)
        _map = schedule_minute_map(root)
        _wf_dir = root / WORKFLOWS_DIR
        _textual = {f"{WORKFLOWS_DIR}/{p.name}"
                    for p in sorted(_wf_dir.glob("*.yml")) + sorted(_wf_dir.glob("*.yaml"))
                    if re.search(r"^\s*-\s+cron:", p.read_text(encoding="utf-8"), re.M)}
        chk(f"seam: the schedule map covers every lane a raw `- cron:` scan finds "
            f"(yaml-derived {sorted(_map)} vs text-derived {sorted(_textual)})",
            set(_map) == _textual)
        chk(f"seam: the schedule map clears the evidence floor of {MIN_SCHEDULED_LANES} lanes "
            f"(saw {len(_map)}) — a thin checkout or a broken parse yields one lane or none, "
            "and a collision check built on an empty map is vacuously green",
            len(_map) >= MIN_SCHEDULED_LANES)
        chk("seam: every lane in the schedule map holds at least one minute",
            all(minutes for minutes in _map.values()))
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
MODES = ("M1-cron-firing-deficit", "M3-execution-overrun", MODE_INGESTION)


def classify(lanes, live, baselines, now, window_hours, job_counts=None):
    """Pure: -> {mode: (findings, census)} for every detected mode."""
    return {
        MODES[0]: find_cron_deficits(lanes, now, window_hours),
        MODES[1]: find_execution_overruns(live, baselines, now),
        MODES[2]: find_ingestion_rejections(lanes, job_counts or {}),
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
        job_counts = {str(k): v for k, v in (state.get("job_counts") or {}).items()}
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
        # M4's ONLY extra request, and only for a lane that already looks rejected: on a
        # healthy repo this loop makes zero calls.
        job_counts = {}
        for lane in lanes:
            newest = lane.get("newest_concluded") or {}
            if (newest.get("conclusion") == INGESTION_REJECTED_CONCLUSION
                    and newest.get("id")):
                job_counts[str(newest["id"])] = fetch_job_count(repo, newest["id"])

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
    # Same 100% question for M4, and it needs its OWN guard: `in_scope` above is satisfied by
    # a lane that carries a cron but is DISABLED, and a disabled lane's runs are never listed.
    # A pass in which no lane's runs were sampled would print an all-zero M4 census that is
    # indistinguishable from a clean one.
    if not any(lane.get("runs_sampled") for lane in lanes):
        raise AlarmError("empty M4 scan set: no lane's scheduled runs were sampled — "
                         "every scheduled lane is disabled, or the sampling broke. "
                         "Refusing to report ingestion health over an empty population.")

    results = classify(lanes, live, baselines, now, args.window_hours, job_counts)

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
