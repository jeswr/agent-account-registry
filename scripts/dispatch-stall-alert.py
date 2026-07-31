#!/usr/bin/env python3
# [OPUS-5] WATCH THE DISPATCHER — alarm on the CONDITION (a stalled pipeline), not on the run
# (issue #819).
#
# THE DEFECT THIS EXISTS FOR. dispatch.yml already carries a per-run failure alert: the `plan-alert`
# job (issue #38, extended by #778) upserts a rolling ops-alert whenever PLAN or CLAIM ends
# failure/cancelled. It did not fire once during the 2026-07-27 stall. MEASURED, run 30295860510:
#
#     PLAN   failure     <- authenticated GitHub read failed (HTTP 403)
#     GUARD  failure     <- secrets-guard: cannot resolve the repository default branch
#     CLAIM  skipped
#     ALERT  skipped     <- `if: always() && needs.secrets-guard.result == 'success'`
#
# and that shape repeated on every failing tick from 18:26:17Z onward. The alert is gated on the
# secrets guard — correctly, because it mounts ALERT_TOKEN and must not run while the secret-exfil
# settings are unverified — and the guard resolves the default branch over the SAME exhausted
# request budget that killed PLAN. So the one class of outage that takes the whole pipeline down
# is precisely the class that also disables its alarm. That gate cannot be loosened without
# reopening issue #101, which means the alarm has to live OUTSIDE the workflow it watches.
#
# Same argument, same shape, and the same host as scripts/metrics-alert.py's `--stale-check`: a
# watcher inside the thing it watches is not a watcher. The ring in the checked-in workflows is now
#
#     dispatch never PLANS / keeps failing -> groom.yml     `dispatch-stall`   (this script)
#     metrics job FAILS                    -> metrics.yml   `metrics-alert`
#     metrics never RUNS                   -> groom.yml     `metrics-stale`
#     groom never RUNS                     -> dashboard.yml `cron-keepalive`
#     dashboard never RUNS                 -> metrics.yml   `dashboard-publish` staleness fallback
#
# THREE SIGNALS, because none of them can express what the others see:
#
#   (A) FAILURE STREAK — the last FAILURE_STREAK_THRESHOLD *executed* ticks all concluded
#       `failure`. This is the brief's "N consecutive dispatch failures is a full pipeline stall".
#       Note the word EXECUTED. Counting consecutive `failure` conclusions over ALL dispatch runs
#       is unimplementable now that the #819 tick floor exists: a within-floor no-op tick concludes
#       `success` exactly like a real one, so a run sequence of F,S,F,S,F — a total outage
#       interleaved with cheap no-ops — never shows two consecutive failures. Executed ticks are
#       identified by the `dispatch-tick` marker artifact the floor job uploads, which no-op ticks
#       do not have.
#
#   (B) PLAN STALENESS — no `dispatch-plan-*` artifact newer than STALE_THRESHOLD_SECONDS. A
#       workflow cannot detect its own NON-EXECUTION, and (A) needs concluded runs to key on;
#       a dispatcher that stopped being scheduled, or one whose runs all cancel, produces neither.
#
#   (C) RING EFFICIENCY — dispatch RUNS per EXECUTED tick (issue #1326). Neither (A) nor (B) can
#       see this one, and that is the whole point: on the measured window every dispatch run
#       concluded `success` and a PLAN was completing, so both halves above read healthy while
#       54 dispatch runs produced ~4 executed ticks. The aggregate IS the defect, so it has to be
#       asserted directly — no per-run signal can carry it. See _render_ring_body for what the
#       number means and what to do about it.
#
# WHY (C) IS FREE. It is derived from the two payloads this watchdog already reads: the artifact
# listing (which run ids uploaded a `dispatch-tick` marker — i.e. which runs EXECUTED) and the
# dispatch runs listing (how many runs there were). It adds no API request, which matters here
# more than usual: the condition it watches for is contention on the very budget an extra request
# would spend. `_test_gh_flows` pins the request count at two.
#
# PAGING POLICY / AUTHORITY / CEILING: identical to scripts/metrics-alert.py. This script may
# create/edit/comment/close ONE `ops-alert` issue per marker and nothing else — no arming path, no
# merge path, no PR path, and no code path that can write a `needs:`/`status:`/`role:` label
# (enforced by _test_no_hold_labels below, not by convention). Every alert auto-closes on an
# explicit recovery. Its job carries `actions: read` + `contents: read` + `issues: write`.
#
# DEBT (issue #591): `_alert_route` is another private copy of locked decision 22c. The shared home
# scripts/alert_route.py now EXISTS on master with the IDENTICAL signature — #591 migrated the four
# emitters it named and stopped there, because this file's self-test cannot run where PyYAML is
# absent and an unverifiable migration of a live alerting path is not worth the swap. Discharging
# this is `_alert_route = <module>.alert_route` plus adding scripts/alert_route.py to the
# dispatch-stall job's sparse-checkout list in groom.yml (which alert_route.py's own census then
# enforces once this file is added to its CONSUMERS tuple).
import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ALERT_LABEL = "ops-alert"

# --- (A) the EXECUTED-TICK FAILURE-STREAK alert ------------------------------------------------
STREAK_ALERT_TITLE = ("⚠️ The dispatch pipeline is STALLED — consecutive executed ticks are "
                      "failing and nothing is being dispatched")
STREAK_ALERT_MARKER = "<!-- dispatch-stall-alert:v1 key=dispatch-failure-streak -->"
# Three. At the #819 tick floor's ceiling of six executed ticks/hour this is ~30 minutes of a dead
# pipeline — comfortably inside the 45-minute staleness threshold below, so the faster signal
# really is the faster one (asserted by _test_thresholds_agree_with_the_floor). Two would page on
# an unlucky pair of transients; four would put this behind (B) and make it dead weight.
FAILURE_STREAK_THRESHOLD = 3

# --- (B) the PLAN-STALENESS alert ---------------------------------------------------------------
STALE_ALERT_TITLE = ("⚠️ The dispatch pipeline has not completed a PLAN — the issue drain and the "
                     "review loop have stopped")
STALE_ALERT_MARKER = "<!-- dispatch-stall-alert:v1 key=dispatch-plan-stale -->"
# 45 minutes. NOT a tuning knob and deliberately NOT env-overridable (a threshold readable from the
# workflow is a second place to get it wrong, and this alert is permitted to page a human). Sizing:
# >= 3 dispatch cron periods (the cron is `3,13,23,33,43,53`, i.e. 10 min), and the host workflow
# fires every 15 min so at least three deliveries land inside the window.
# _test_threshold_vs_cadence asserts both, against the LIVE workflow files, so neither side can
# drift silently.
STALE_THRESHOLD_SECONDS = 45 * 60

# --- (C) the RING-EFFICIENCY metric (issue #1326) ----------------------------------------------
RING_ALERT_TITLE = ("⚠️ The dispatcher is mostly administering itself — dispatch RUNS per EXECUTED "
                    "tick is far above what the tick floor can ever admit")
RING_ALERT_MARKER = "<!-- dispatch-stall-alert:v1 key=dispatch-ring-efficiency -->"
# THE THRESHOLD, DERIVED — not chosen. The #819 floor admits at most
# `3600 / MIN_TICK_INTERVAL_SECONDS` = 6 executed ticks/hour, and dispatch's cron fires exactly 6
# times/hour (`3,13,23,33,43,53`). Those two numbers being EQUAL is the whole derivation: a
# dispatcher rung only by its own schedule sits at a ratio of ~1.0, because every scheduled ring
# lands on the floor boundary. `_test_ring_threshold_is_derived_from_the_floor` asserts that
# equality against the LIVE floor constant and the LIVE cron, so a change to either side reds this
# file instead of silently invalidating the number below.
#
# Every point above 1.0 is therefore doorbell rings the floor cannot admit — runs that were
# structurally incapable of dispatching anything before they started. 3 means TWO OF EVERY THREE
# dispatch runs were in that class.
#
# WHY 3 AND NOT THE MEASURED PATHOLOGY. The two reported windows read 8.2 (#1208: 41 runs, 5
# dispatched) and 13.5 (#1326: 54 runs, ~4 executed). A threshold set at those only fires once the
# fleet is already as bad as the worst case anyone has written up, which is a threshold that can
# never catch the drift toward it. 3 keeps 3x headroom over the structural ideal and still sits
# well under both measurements — asserted, in both directions, below.
RING_RUNS_PER_EXECUTED_TICK_THRESHOLD = 3
# Minimum concluded runs in the window before the ratio is allowed to mean anything. At the cron's
# 6/hour this is two hours of evidence; below it a single slow tick swings the ratio by a whole
# point and the alarm would be reporting noise. Under the sample the verdict is `unknown`, which
# `decide` reads as "do nothing" — it never pages AND never closes a live alert.
RING_MIN_RUNS = 12

# The artifacts the halves key on. Both are written by dispatch.yml and by nothing else.
TICK_MARKER_ARTIFACT = "dispatch-tick"          # an EXECUTED tick (uploaded before the snapshot)
PLAN_ARTIFACT_PREFIX = "dispatch-plan-"         # a COMPLETED plan (uploaded at the end of PLAN)
ARTIFACT_PAGE_SIZE = 100
RUN_PAGE_SIZE = 50

DISPATCH_WORKFLOW = ".github/workflows/dispatch.yml"
GROOM_WORKFLOW = ".github/workflows/groom.yml"
HOST_JOB = "dispatch-stall"

# Every file the self-test asserts against. The host job sparse-checks-out exactly this set and
# _test_selftest_inputs_are_checked_out asserts that it does — a trimmed checkout would make the
# YAML-seam assertions silently unreachable on the live path.
REQUIRED_FILES = (
    "scripts/dispatch-stall-alert.py",
    "scripts/dispatch-tick-floor.py",
    DISPATCH_WORKFLOW,
    GROOM_WORKFLOW,
)


class DispatchStallError(Exception):
    """A contract this script refuses to guess about."""


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) for the alert issue — locked decision 22c / issue #39, identical semantics and
    signature to scripts/metrics-alert.py's private copy: the private ALERT_REPO is the destination
    ONLY when ALERT_TOKEN can write there; a half-configured deployment (repo set, token missing)
    falls back to the registry repo under the ambient token instead of silently losing the alert."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def parse_rfc3339(raw):
    if not isinstance(raw, str) or not raw:
        return None
    try:
        stamp = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(stamp.timestamp())


# ---------------------------------------------------------------------------------------------
# pure derivations over the two API payloads
# ---------------------------------------------------------------------------------------------
def executed_tick_runs(artifacts_payload):
    """Run ids that uploaded a `dispatch-tick` marker, i.e. ticks that actually EXECUTED.

    This is the distinction the whole (A) half rests on. A within-floor no-op tick concludes
    `success` and would otherwise reset a consecutive-failure count on every ring of the doorbell,
    which is how the floor and a naive streak counter would have silently cancelled each other."""
    ids = set()
    for entry in _artifacts(artifacts_payload):
        if entry.get("name") != TICK_MARKER_ARTIFACT:
            continue
        run = entry.get("workflow_run")
        run_id = run.get("id") if isinstance(run, dict) else None
        if isinstance(run_id, int) and not isinstance(run_id, bool):
            ids.add(run_id)
    return ids


def newest_plan_epoch(artifacts_payload):
    """Creation time of the newest non-expired `dispatch-plan-*` artifact -> epoch|None.

    PREFIX matching here is correct and deliberate: the plan artifact's name embeds the run id and
    attempt (`dispatch-plan-<run>-<attempt>`), so it cannot be matched by equality. It is also why
    `dispatch-tick` is matched by EQUALITY everywhere else — `dispatch-plan-...` must never be read
    as a tick marker."""
    best = None
    for entry in _artifacts(artifacts_payload):
        name = entry.get("name")
        if not isinstance(name, str) or not name.startswith(PLAN_ARTIFACT_PREFIX):
            continue
        if entry.get("expired") is True:
            continue
        epoch = parse_rfc3339(entry.get("created_at"))
        if epoch is not None and (best is None or epoch > best):
            best = epoch
    return best


def _artifacts(payload):
    if not isinstance(payload, dict):
        return []
    entries = payload.get("artifacts")
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict)]


def failure_streak(runs_payload, executed_ids):
    """How many of the most recent EXECUTED ticks, newest first, concluded `failure` in a row.

    Runs still in flight (conclusion null) are SKIPPED, not counted and not treated as a reset: a
    tick that has not finished is not evidence either way, and letting it reset the streak would
    make the alarm unreachable on a busy schedule. Any concluded non-failure ends the streak."""
    runs = runs_payload.get("workflow_runs") if isinstance(runs_payload, dict) else None
    if not isinstance(runs, list):
        return 0
    executed = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        if run.get("id") not in executed_ids:
            continue
        number = run.get("run_number")
        if not isinstance(number, int) or isinstance(number, bool):
            continue
        executed.append((number, run.get("conclusion")))
    streak = 0
    for _number, conclusion in sorted(executed, reverse=True):
        if conclusion is None:
            continue
        if conclusion != "failure":
            break
        streak += 1
    return streak


def streak_verdict(streak, threshold=FAILURE_STREAK_THRESHOLD):
    """'stalled' | 'ok'. 'ok' is only ever returned for a streak that was actually COUNTED, which
    is what makes closing on it a real recovery signal."""
    return "stalled" if streak >= threshold else "ok"


def stale_verdict(epoch, now, threshold=STALE_THRESHOLD_SECONDS):
    """-> ('stale'|'fresh', reason, age_seconds|None). FAIL-CLOSED in the alerting direction: no
    readable plan artifact at all is STALE, never 'assume fresh'. A future-dated artifact (runner
    clock skew) reads fresh — under-delivery is the failure this watches for, and paging on a few
    seconds of skew is exactly the noise the paging policy forbids."""
    if epoch is None:
        return "stale", "no completed dispatch PLAN is visible at all", None
    age = int(now) - int(epoch)
    if age > threshold:
        return "stale", "the dispatcher has not completed a PLAN", age
    return "fresh", "ok", age


def artifact_horizon(payload, carried=None):
    """Oldest `created_at` on an artifact page -> epoch|None, folded into `carried` across pages.
    (`carried`, not `floor`: nothing here is related to the #819 tick floor.)

    This is the LOWER BOUND of the window in which "did run N execute?" is answerable. The listing
    is repo-wide and newest-first, so every `dispatch-tick` marker newer than this stamp is on the
    pages that were actually read; anything older may simply have been crowded off by an unrelated
    workflow's artifacts, and reading THAT as "the tick did not execute" would manufacture waste
    out of a paging artefact. Same fact `page_covers_threshold` turns into a coverage proof, used
    here as a horizon instead of a predicate.

    Names are deliberately NOT filtered: the bound is about what the PAGE reached back to, which
    every entry on it witnesses equally."""
    stamps = [parse_rfc3339(entry.get("created_at")) for entry in _artifacts(payload)]
    stamps = [s for s in stamps if s is not None]
    if carried is not None:
        stamps.append(carried)
    return min(stamps) if stamps else None


def ring_sample(runs_payload, executed_ids, horizon):
    """-> (concluded dispatch runs, of which EXECUTED) inside the adjudicable window.

    Runs OLDER than `horizon` are excluded because their marker artifact may be off the pages that
    were read (see artifact_horizon). Runs still IN FLIGHT are excluded for the same reason
    failure_streak excludes them: a tick that has not concluded has not necessarily uploaded its
    marker yet, so counting it would report latency as waste. Both exclusions can only ever shrink
    the numerator and the denominator together, never inflate the ratio."""
    if horizon is None:
        return 0, 0
    runs = runs_payload.get("workflow_runs") if isinstance(runs_payload, dict) else None
    if not isinstance(runs, list):
        return 0, 0
    counted = executed = 0
    for run in runs:
        if not isinstance(run, dict) or run.get("conclusion") is None:
            continue
        created = parse_rfc3339(run.get("created_at"))
        if created is None or created < horizon:
            continue
        counted += 1
        if run.get("id") in executed_ids:
            executed += 1
    return counted, executed


def ring_verdict(counted, executed, threshold=RING_RUNS_PER_EXECUTED_TICK_THRESHOLD,
                 min_runs=RING_MIN_RUNS):
    """-> ('wasteful'|'ok'|'unknown', ratio|None). The standing metric, and the assertion on it.

    `unknown` — never a page and never a close — for the two states that have no ratio in them:
    too small a sample, and ZERO executed ticks. The zero case is deliberately not folded into
    'infinitely wasteful': a window in which nothing executed at all is what half (B) exists to
    page for, and reporting it twice under two markers is two alerts for one condition."""
    if counted < min_runs or executed <= 0:
        return "unknown", None
    ratio = counted / executed
    return ("wasteful" if ratio >= threshold else "ok"), ratio


def decide(verdict, has_open_alert, bad="stalled"):
    """'upsert' | 'close' | 'noop'. Shared by every half."""
    if verdict == bad:
        return "upsert"
    if verdict != bad and has_open_alert and verdict in ("ok", "fresh"):
        return "close"
    return "noop"


# ---------------------------------------------------------------------------------------------
# issue bodies — fixed templates over a closed set of machine-derived scalars. No account handle,
# no token, and no byte of any remote payload can reach either of these.
# ---------------------------------------------------------------------------------------------
def _render_streak_body(streak, run_url, workflow_url, maintainer):
    return (
        f"{STREAK_ALERT_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (watch the dispatcher)\n\n"
        f"@{maintainer} the last **{streak}** dispatch ticks that actually executed all ended "
        "`failure`. Nothing is being dispatched: no issue is being claimed, no worker is being "
        "launched, and no review/fix transition is being re-derived.\n\n"
        f"- Dispatch runs: {workflow_url}\n"
        f"- Detected by: {run_url}\n\n"
        "Two causes account for every instance of this shape so far, and the run log distinguishes "
        "them in one line:\n"
        "1. **Request budget exhausted** — `HTTP 403` on an authenticated read, and "
        "`secrets-guard: cannot resolve the repository default branch` in the same run. The "
        "dispatcher is issuing more requests per hour than the budget allows; the tick floor in "
        "`scripts/dispatch-tick-floor.py` bounds that rate, so check whether it is still wired.\n"
        "2. **Guard settings regressed** — the `dispatch-secrets` environment or the repo-scope "
        "secret inventory changed. That is a maintainer settings fix, and it is fail-closed by "
        "design.\n\n"
        "This alert exists because dispatch's own `plan-alert` job cannot report either one: it is "
        "gated on `secrets-guard`, and both causes take the guard down first. It auto-closes as "
        "soon as an executed tick succeeds.\n"
    )


def _render_stale_body(reason, age_seconds, run_url, workflow_url, maintainer):
    age = "unknown" if age_seconds is None else f"{age_seconds // 60} min"
    return (
        f"{STALE_ALERT_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (watch the dispatcher)\n\n"
        f"@{maintainer} the dispatch pipeline is **stalled**: {reason}.\n\n"
        f"- Age of the newest completed PLAN: **{age}** "
        f"(threshold {STALE_THRESHOLD_SECONDS // 60} min)\n"
        f"- Dispatch runs: {workflow_url}\n"
        f"- Detected by: {run_url}\n\n"
        "A cron that stops firing, or whose runs all cancel, produces no failed job for a "
        "per-run alert to key on — a workflow cannot detect its own non-execution. This check "
        "therefore runs from a different workflow on an independent schedule.\n\n"
        "While it holds, the issue drain and the cross-provider review loop are both stopped: "
        "every review -> fix -> re-review -> arm transition is a durable marker the sweep "
        "re-derives each tick, so no tick means no transition. Auto-closes as soon as a PLAN "
        "completes.\n"
    )


def _render_ring_body(ratio, counted, executed, run_url, workflow_url, maintainer):
    wasted = counted - executed
    return (
        f"{RING_ALERT_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (watch the dispatcher)\n\n"
        f"@{maintainer} over the last **{counted}** concluded dispatch runs only **{executed}** "
        f"were EXECUTED ticks — **{ratio:.1f} runs per executed tick** (threshold "
        f"{RING_RUNS_PER_EXECUTED_TICK_THRESHOLD}). The other **{wasted}** started a job, issued "
        "the floor's anchor read and dispatched nothing.\n\n"
        f"- Dispatch runs: {workflow_url}\n"
        f"- Detected by: {run_url}\n\n"
        "**This is a throughput condition, not a failure.** Every one of those runs concluded "
        "`success`, and a PLAN is still completing, so neither the failure-streak half nor the "
        "PLAN-staleness half of this watchdog can see it — which is why the ratio is asserted "
        "directly.\n\n"
        "What it means, structurally: the `#819` tick floor admits at most one executed tick per "
        "`MIN_TICK_INTERVAL_SECONDS`, and dispatch's own cron already rings at exactly that rate. "
        "A ratio near 1 is therefore the healthy shape; everything above it is doorbell rings that "
        "could not possibly have executed when they were made.\n\n"
        "The two things that move this number:\n"
        "1. **Bound the ring rate by the floor it will be judged against.** The doorbell jobs at "
        "the end of `worker.yml` and `review-fix.yml` ring unconditionally; a ring made inside "
        "the floor is a run that is guaranteed to no-op.\n"
        "2. **Stop unfiltered triggers from starting dispatch-adjacent jobs at all** — the same "
        "shape as the job-level-filter defects tracked against the other lanes.\n\n"
        "Auto-closes as soon as the ratio comes back under the threshold.\n"
    )


# ---------------------------------------------------------------------------------------------
# gh plumbing — mirrors scripts/metrics-alert.py exactly
# ---------------------------------------------------------------------------------------------
def _gh(args, capture=False, token=None, check=False, label="dispatch-stall"):
    # Sanitized fail-loud wrapper: op + returncode only — never stderr (GH_DEBUG=api can echo
    # request bodies) and never argument content beyond the gh subcommand words.
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env, check=False)
    if check and result.returncode != 0:
        print(f"::warning::{label}: gh {args[0]} "
              f"{args[1] if len(args) > 1 else ''} failed (rc={result.returncode})")
    return result


def _gh_json(args, label="dispatch-stall"):
    result = _gh(args, capture=True, check=True, label=label)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout or "null")
    except ValueError:
        print(f"::warning::{label}: gh {args[0]} succeeded but returned unparseable JSON")
        return None


def page_covers_threshold(payload, now, threshold=STALE_THRESHOLD_SECONDS):
    """Does this artifact page reach back FURTHER than the staleness threshold?

    The listing is repo-wide — dispatch's artifacts share it with `dashboard-usage-*`,
    `publish-bundle-*` and `github-pages` (measured 2026-07-27: 34 of 100 on page one, which
    reached back 6h45m). "No plan artifact on page one" therefore means "no plan artifact
    recently" ONLY if page one reaches back past the threshold; under an artifact storm from some
    unrelated workflow it would instead mean "the plan artifact got crowded off", and firing on
    that is a false page. This is the predicate that turns the difference into a fact instead of
    an assumption, and it is why read_signals pages until it is true.

    Uses the MINIMUM created_at on the page, not the last element: the endpoint returns
    newest-first today, but a watchdog should not have a correctness dependency on an undocumented
    ordering."""
    stamps = [parse_rfc3339(entry.get("created_at")) for entry in _artifacts(payload)]
    stamps = [s for s in stamps if s is not None]
    if not stamps:
        return False
    return (int(now) - min(stamps)) > threshold


ARTIFACT_MAX_PAGES = 3


def read_signals(repo, now=None, runner=None):
    """The API reads this watchdog costs. -> (executed_ids, plan_epoch, horizon, runs).

    Normally TWO requests, and half (C) deliberately added none: `horizon` is folded out of the
    SAME artifact pages `executed_ids` comes from, and the ratio out of the SAME runs listing half
    (A) already keys on. A watchdog for budget contention that spends more budget to watch is one
    more consumer of the thing it is complaining about.

    The artifact listing pages only while it has neither found a plan artifact nor proven it
    reached back past the staleness threshold — at today's density page one covers ~7 hours, so the
    loop exits after one request; the bound exists so an artifact storm costs a couple more
    requests instead of producing a false page.

    `runner` is resolved at CALL time, not bound as a default: a default argument captures the
    function object at definition, which makes the live path unpatchable and every stubbed-flow
    assertion below quietly exercise the real `gh`."""
    runner = runner or _gh_json
    now = _now() if now is None else now
    executed, plan_epoch, horizon = set(), None, None
    for page in range(1, ARTIFACT_MAX_PAGES + 1):
        payload = runner(["api", "-H", "Accept: application/vnd.github+json",
                          f"/repos/{repo}/actions/artifacts"
                          f"?per_page={ARTIFACT_PAGE_SIZE}&page={page}"])
        entries = _artifacts(payload)
        executed |= executed_tick_runs(payload)
        horizon = artifact_horizon(payload, horizon)
        found = newest_plan_epoch(payload)
        if found is not None and (plan_epoch is None or found > plan_epoch):
            plan_epoch = found
        if plan_epoch is not None or page_covers_threshold(payload, now) or not entries:
            break
    runs = runner(["api", "-H", "Accept: application/vnd.github+json",
                   f"/repos/{repo}/actions/workflows/dispatch.yml/runs"
                   f"?per_page={RUN_PAGE_SIZE}"])
    return executed, plan_epoch, horizon, runs


def _find_open_alert(repo, token, marker, title, label):
    """-> (issue_number|None, hard_error:bool, soft_skip:bool). --limit 100: the `ops-alert` label
    is SHARED with every other ops alert, and a 30-issue default window could push this one out of
    the dedupe scan (duplicate on failure, uncloseable on recovery)."""
    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"],
                 capture=True, token=token, check=True, label=label)
    if listed.returncode != 0:
        return None, True, False
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:
        print(f"::warning::{label}: gh issue list succeeded but returned unparseable JSON — "
              "skipping this tick (no dedupe/recovery data; next tick retries)")
        return None, False, True
    num = next((i["number"] for i in found if marker in (i.get("body") or "")), None)
    if num is None:
        num = next((i["number"] for i in found if i.get("title") == title), None)
    return num, False, False


def _apply(action, repo, token, num, title, body, recovered_note, label):
    """Execute an upsert/close/noop. -> process exit code."""
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token, label=label)  # idempotent
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token, check=True, label=label)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", title,
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True, label=label)
        return 1 if wrote.returncode != 0 else 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body", recovered_note],
                        capture=True, token=token, check=True, label=label)
        closed = _gh(["issue", "close", str(num), "-R", repo],
                     capture=True, token=token, check=True, label=label)
        return 1 if (commented.returncode != 0 or closed.returncode != 0) else 0
    return 0


def _now():
    """Wall clock, isolated so the self-test can pin it."""
    return int(datetime.now(tz=timezone.utc).timestamp())


def main():
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    workflow_url = f"{server}/{registry_repo}/actions/workflows/dispatch.yml"

    now = _now()
    executed_ids, plan_epoch, horizon, runs = read_signals(registry_repo, now=now)
    streak = failure_streak(runs, executed_ids)
    streak_state = streak_verdict(streak)
    stale_state, stale_reason, age = stale_verdict(plan_epoch, _now())
    ring_runs, ring_executed = ring_sample(runs, executed_ids, horizon)
    ring_state, ring_ratio = ring_verdict(ring_runs, ring_executed)

    code = 0
    for label, marker, title, verdict, bad, body, note in (
            ("dispatch-streak", STREAK_ALERT_MARKER, STREAK_ALERT_TITLE, streak_state, "stalled",
             _render_streak_body(streak, run_url, workflow_url, maintainer),
             "✅ Recovered — an executed dispatch tick succeeded again. Auto-closing."),
            ("dispatch-stale", STALE_ALERT_MARKER, STALE_ALERT_TITLE, stale_state, "stale",
             _render_stale_body(stale_reason, age, run_url, workflow_url, maintainer),
             "✅ Recovered — the dispatcher has completed a PLAN again. Auto-closing."),
            ("dispatch-ring", RING_ALERT_MARKER, RING_ALERT_TITLE, ring_state, "wasteful",
             _render_ring_body(ring_ratio or 0.0, ring_runs, ring_executed, run_url, workflow_url,
                               maintainer),
             "✅ Recovered — dispatch runs per executed tick is back under the threshold. "
             "Auto-closing."),
    ):
        num, hard, soft = _find_open_alert(repo, token, marker, title, label)
        if hard:
            code = 1
            continue
        if soft:
            continue
        action = decide(verdict, num is not None, bad=bad)
        code = _apply(action, repo, token, num, title, body, note, label) or code
        if action == "upsert":
            print(f"::warning::{label}: dispatch is {verdict} — maintainer alerted")
        elif action == "close":
            print(f"{label}: dispatch recovered — closed the alert")
        else:
            print(f"{label}: verdict={verdict} — nothing to do")
    age_note = "unknown" if age is None else f"{age // 60} min"
    # The RATIO IS PUBLISHED EVERY RUN, not only when it pages (issue #1326 asks for a standing
    # metric, and a number that only appears once it is already bad cannot show the drift toward
    # bad). `unknown` is printed as such rather than as a 0 that would read like a healthy value.
    ratio_note = "unknown" if ring_ratio is None else f"{ring_ratio:.1f}"
    print(f"dispatch-stall: executed-tick failure streak={streak} "
          f"(threshold {FAILURE_STREAK_THRESHOLD}), newest completed PLAN {age_note} old "
          f"(threshold {STALE_THRESHOLD_SECONDS // 60} min), ring efficiency {ring_executed}/"
          f"{ring_runs} runs executed = {ratio_note} runs per executed tick "
          f"(threshold {RING_RUNS_PER_EXECUTED_TICK_THRESHOLD})")
    return code


# =============================================================================================
# self-test
# =============================================================================================
def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _require(path):
    """Read a file the self-test asserts against. FAIL CLOSED: a missing input aborts the
    self-test loudly rather than making its assertions quietly unreachable."""
    full = os.path.join(_repo_root(), path)
    if not os.path.isfile(full):
        raise DispatchStallError(
            f"self-test input {path} is missing from the working copy at {_repo_root()} — the "
            "YAML-seam assertions cannot run, and a self-test that silently stops asserting is "
            "worse than no self-test. Add it to the job's sparse-checkout list.")
    with open(full, encoding="utf-8") as handle:
        return handle.read()


def _load_workflow(path):
    import yaml  # hard requirement: regex-over-YAML is how permissive misparses get in
    return yaml.safe_load(_require(path))


def _load_floor():
    """The tick floor module, for the CROSS-FILE threshold assertion. The two constants are only
    coherent together: the streak threshold is measured in ticks, and how long N ticks take is set
    entirely by the floor."""
    path = Path(_repo_root()) / "scripts" / "dispatch-tick-floor.py"
    _require("scripts/dispatch-tick-floor.py")
    spec = importlib.util.spec_from_file_location("registry_dispatch_tick_floor", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _job(workflow, name):
    jobs = (workflow or {}).get("jobs") or {}
    if name not in jobs:
        raise DispatchStallError(
            f"workflow has no job named `{name}` — refusing to assert against a job that does not "
            "exist (a deleted watchdog must go RED here, not silently pass)")
    return jobs[name]


def _steps(job):
    return job.get("steps") or []


def _invocations(job, script):
    """Executable `python3 .../<script>` command lines across a job's steps, COMMENTS STRIPPED. A
    filename grep over a shell body is satisfied by a comment or a backslash-continuation tail."""
    pattern = re.compile(rf"^\s*python3\s+(?:\S*/)?{re.escape(script)}([^\n]*)$", re.M)
    tails = []
    for step in _steps(job):
        body = step.get("run") or ""
        live = "\n".join(line for line in body.replace("\\\n", " ").splitlines()
                         if not line.strip().startswith("#"))
        tails += [m.group(1).split() for m in pattern.finditer(live)]
    return tails


def _sparse_paths(job, path="registry"):
    found = [(step.get("with") or {}) for step in _steps(job)
             if str(step.get("uses", "")).startswith("actions/checkout@")
             and (step.get("with") or {}).get("path") == path]
    if len(found) != 1:
        raise DispatchStallError(
            f"expected exactly one actions/checkout with `path: {path}`, found {len(found)}")
    spec = found[0].get("sparse-checkout") or ""
    return {line.strip() for line in str(spec).splitlines() if line.strip()}


def _cron_period_minutes(workflow):
    """Minutes between fires for `m-59/N * * * *`, `*/N * * * *`, or an explicit minute list."""
    triggers = workflow.get("on", workflow.get(True)) or {}
    crons = [entry["cron"] for entry in (triggers.get("schedule") or []) if "cron" in entry]
    if len(crons) != 1:
        raise DispatchStallError(f"expected exactly one cron schedule, found {len(crons)}")
    minute = crons[0].split()[0]
    if "/" in minute:
        return int(minute.split("/")[1])
    minutes = sorted(int(part) for part in minute.split(","))
    if len(minutes) < 2:
        return 60
    gaps = {b - a for a, b in zip(minutes, minutes[1:])} | {60 - minutes[-1] + minutes[0]}
    return max(gaps)


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    # --- routing (mirrors the audited metrics/plan/groom/usage-alert matrix) ------------------
    chk("route: repo+token -> private + token",
        _alert_route("org/private", "tok", "org/registry"), ("org/private", "tok"))
    chk("route: repo but NO token -> registry fallback",
        _alert_route("org/private", "", "org/registry"), ("org/registry", None))
    chk("route: no repo -> registry", _alert_route("", "tok", "org/registry"),
        ("org/registry", None))

    _test_executed_tick_identification(chk)
    _test_failure_streak(chk)
    _test_plan_staleness(chk)
    _test_ring_efficiency(chk)
    _test_decide(chk)
    _test_thresholds_agree_with_the_floor(chk)
    _test_ring_threshold_is_derived_from_the_floor(chk)
    _test_threshold_vs_cadence(chk)
    _test_page_coverage(chk)
    _test_gh_flows(chk)
    _test_no_hold_labels(chk)
    _test_workflow_seam(chk)

    print("dispatch-stall-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _artifact(name, run_id=None, created_at="2026-07-27T18:00:00Z", expired=False):
    entry = {"name": name, "created_at": created_at, "expired": expired}
    if run_id is not None:
        entry["workflow_run"] = {"id": run_id}
    return entry


def _test_executed_tick_identification(chk):
    payload = {"artifacts": [
        _artifact(TICK_MARKER_ARTIFACT, 101),
        _artifact(TICK_MARKER_ARTIFACT, 103),
        _artifact("dispatch-plan-103-1"),          # no workflow_run -> not an executed tick
        _artifact("some-other-artifact", 999),
        {"name": TICK_MARKER_ARTIFACT},            # no workflow_run at all
        "not-a-dict",
    ]}
    chk("executed: only `dispatch-tick` markers with a run id count",
        executed_tick_runs(payload), {101, 103})
    chk("executed: a malformed payload yields no executed ticks (and therefore no streak)",
        executed_tick_runs({"artifacts": "nope"}), set())


def _test_failure_streak(chk):
    executed = {101, 102, 103, 104}

    def runs(*rows):
        return {"workflow_runs": [{"id": rid, "run_number": num, "conclusion": conc}
                                  for rid, num, conc in rows]}

    chk("streak: three consecutive EXECUTED failures",
        failure_streak(runs((104, 4, "failure"), (103, 3, "failure"), (102, 2, "failure"),
                            (101, 1, "success")), executed), 3)
    chk("streak: a success at the head resets it",
        failure_streak(runs((104, 4, "success"), (103, 3, "failure"), (102, 2, "failure")),
                       executed), 0)
    # THE COMPOSITION THE #819 FLOOR CREATES. Runs 201/202 are within-floor NO-OP ticks: they
    # conclude `success` and have no `dispatch-tick` marker. Counting conclusions over ALL runs
    # would read this as "never two failures in a row" and never alarm, while the pipeline is
    # totally dead. Counting only EXECUTED ticks reads it correctly as a streak of three.
    interleaved = runs((104, 6, "failure"), (202, 5, "success"), (103, 4, "failure"),
                       (201, 3, "success"), (102, 2, "failure"), (101, 1, "success"))
    chk("streak: NO-OP ticks interleaved with real failures do not reset the streak (this is the "
        "defect the floor would otherwise have introduced into this alarm)",
        failure_streak(interleaved, executed), 3)
    chk("streak: ... and counting conclusions over ALL runs instead would have read 1",
        failure_streak(interleaved, {101, 102, 103, 104, 201, 202}), 1)
    chk("streak: an in-flight tick is skipped, not counted and not a reset",
        failure_streak(runs((104, 4, None), (103, 3, "failure"), (102, 2, "failure"),
                            (101, 1, "failure")), executed), 3)
    chk("streak: a CANCELLED executed tick ends the streak (it is not evidence of failure)",
        failure_streak(runs((104, 4, "cancelled"), (103, 3, "failure")), executed), 0)
    chk("streak: a malformed runs payload yields 0 (no alarm from an unreadable signal — the "
        "staleness half covers that case)", failure_streak({"nope": 1}, executed), 0)
    chk("streak: the threshold boundary (2 does not fire, 3 does)",
        (streak_verdict(2), streak_verdict(3)), ("ok", "stalled"))


def _test_plan_staleness(chk):
    now = 1_800_000_000

    def page(minutes_old, name=f"{PLAN_ARTIFACT_PREFIX}1-1", expired=False):
        stamp = datetime.fromtimestamp(now - minutes_old * 60, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        return {"artifacts": [_artifact(name, created_at=stamp, expired=expired)]}

    chk("stale: a 5-min-old PLAN artifact is FRESH",
        stale_verdict(newest_plan_epoch(page(5)), now)[0], "fresh")
    chk("stale: a 90-min-old PLAN artifact is STALE",
        stale_verdict(newest_plan_epoch(page(90)), now)[0], "stale")
    chk("stale: EXACTLY at the threshold is fresh; one second past it is stale (the comparison is "
        "`>`, and an off-by-one here is a page or a blind spot)",
        (stale_verdict(newest_plan_epoch(page(45)), now)[0],
         stale_verdict(newest_plan_epoch(page(45)), now + 1)[0]), ("fresh", "stale"))
    chk("stale: an EXPIRED artifact does not count as a completed PLAN",
        stale_verdict(newest_plan_epoch(page(5, expired=True)), now)[0], "stale")
    chk("stale: a `dispatch-tick` marker is NOT a completed PLAN (an executed tick that then died "
        "in the snapshot must still read as stalled)",
        stale_verdict(newest_plan_epoch(page(5, name=TICK_MARKER_ARTIFACT)), now)[0], "stale")
    chk("stale: newest wins across several plan artifacts",
        newest_plan_epoch({"artifacts": [
            _artifact(f"{PLAN_ARTIFACT_PREFIX}1-1", created_at="2026-07-27T18:00:00Z"),
            _artifact(f"{PLAN_ARTIFACT_PREFIX}2-1", created_at="2026-07-27T18:30:00Z")]}),
        parse_rfc3339("2026-07-27T18:30:00Z"))
    # FAIL-CLOSED matrix: every unreadable outcome lands on 'stale'.
    for label, payload in (("no artifacts at all", {"artifacts": []}),
                           ("payload is not an object", ["nope"]),
                           ("created_at is unparseable",
                            {"artifacts": [_artifact(f"{PLAN_ARTIFACT_PREFIX}1-1",
                                                     created_at="yesterday")]})):
        chk(f"stale: {label} -> STALE (a signal that cannot be read is not a healthy signal)",
            stale_verdict(newest_plan_epoch(payload), now)[0], "stale")


def _test_ring_efficiency(chk):
    """(C). Every assertion here has to be able to go RED on a plausible wrong answer — the whole
    reason this half exists is that the aggregate is invisible to per-run signals, so a vacuous
    test of it would restore exactly the blind spot it closes."""
    now = 1_800_000_000

    def stamp(ago):
        return datetime.fromtimestamp(now - ago, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # --- the horizon, which is what makes the sample honest ---------------------------------
    page = {"artifacts": [_artifact(TICK_MARKER_ARTIFACT, 1, created_at=stamp(600)),
                          _artifact("publish-bundle-1-1", created_at=stamp(7 * 3600))]}
    chk("ring: the horizon is the OLDEST stamp on the page, whatever the artifact is named "
        "(the bound is about how far back the page reached, not about dispatch's own artifacts)",
        artifact_horizon(page), now - 7 * 3600)
    chk("ring: the horizon folds across pages, keeping the oldest",
        artifact_horizon({"artifacts": [_artifact("x", created_at=stamp(60))]}, now - 7 * 3600),
        now - 7 * 3600)
    chk("ring: a page with nothing datable yields NO horizon (and therefore no ratio)",
        artifact_horizon({"artifacts": [_artifact("x", created_at="yesterday")]}), None)

    def runs(rows):
        """rows: (id, conclusion, seconds_ago)."""
        return {"workflow_runs": [{"id": rid, "run_number": rid, "conclusion": conc,
                                   "created_at": stamp(ago)} for rid, conc, ago in rows]}

    horizon = now - 3 * 3600
    # THE MEASURED SHAPE (#1326): 13 runs inside the window, 1 of which executed.
    measured = runs([(1, "success", 600)] + [(n, "success", 600) for n in range(2, 14)])
    chk("ring: the #1326 shape — 13 concluded runs, 1 executed",
        ring_sample(measured, {1}, horizon), (13, 1))
    chk("ring: ... reads WASTEFUL", ring_verdict(*ring_sample(measured, {1}, horizon))[0],
        "wasteful")
    # A cron-only dispatcher: every run executed. This is the row that reds a mutant which always
    # returns 'wasteful', and the row that proves the recovery/close path is reachable.
    healthy = runs([(n, "success", 600) for n in range(1, 14)])
    chk("ring: a dispatcher whose every run executed is OK at ratio 1.0",
        ring_verdict(*ring_sample(healthy, set(range(1, 14)), horizon)), ("ok", 1.0))
    # THE BOUNDARY, both sides. Off-by-one here is either a page or a blind spot.
    chk("ring: exactly AT the threshold fires; one executed tick more does not "
        f"({RING_RUNS_PER_EXECUTED_TICK_THRESHOLD} vs just under it)",
        (ring_verdict(12, 4)[0], ring_verdict(12, 5)[0]), ("wasteful", "ok"))
    # EXCLUSIONS. Both can only shrink numerator and denominator together.
    older = runs([(1, "success", 600)] + [(n, "success", 4 * 3600) for n in range(2, 14)])
    chk("ring: runs OLDER than the horizon are excluded — their marker artifact may simply be off "
        "the pages that were read, and counting them would invent waste out of paging",
        ring_sample(older, {1}, horizon), (1, 1))
    inflight = runs([(1, "success", 600)] + [(n, None, 600) for n in range(2, 14)])
    chk("ring: IN-FLIGHT runs are excluded — a tick that has not concluded has not necessarily "
        "uploaded its marker yet, so counting it would report latency as waste",
        ring_sample(inflight, {1}, horizon), (1, 1))
    chk("ring: no horizon at all -> no sample", ring_sample(measured, {1}, None), (0, 0))
    chk("ring: a malformed runs payload -> no sample", ring_sample({"nope": 1}, {1}, horizon),
        (0, 0))

    # --- the two states that have no ratio in them, and must neither page nor close ----------
    # 3 runs, 1 executed — a ratio of exactly 3.0, i.e. OVER the threshold. Chosen so that
    # dropping the minimum-sample guard makes this row page instead of staying quiet; a fixture
    # that was under the threshold anyway would leave the guard untested.
    small = runs([(n, "success", 600) for n in range(1, 4)])
    chk("ring: under the minimum sample the verdict is UNKNOWN even though the ratio itself is "
        "over the threshold — three runs is not evidence of a standing condition",
        ring_verdict(*ring_sample(small, {1}, horizon)), ("unknown", None))
    chk("ring: ZERO executed ticks over a full sample is UNKNOWN here — that is precisely the "
        "condition half (B) pages for, and two markers for one condition is two alerts",
        ring_verdict(*ring_sample(measured, set(), horizon)), ("unknown", None))
    chk("ring: ... and an UNKNOWN verdict can neither page nor close a live ring alert",
        (decide("unknown", False, bad="wasteful"), decide("unknown", True, bad="wasteful")),
        ("noop", "noop"))
    chk("ring: a wasteful verdict pages, and a recovered one closes",
        (decide("wasteful", False, bad="wasteful"), decide("ok", True, bad="wasteful")),
        ("upsert", "close"))
    # main() renders every body eagerly and passes `ring_ratio or 0.0`. That fallback must be
    # UNREACHABLE on the only path that posts one, or the alert could print a ratio of 0.0 while
    # claiming the dispatcher is wasteful. It is unreachable exactly because a ratio accompanies
    # every verdict that is not `unknown`, and `unknown` never upserts — asserted, not assumed.
    chk("ring: every verdict that can reach the issue body carries its ratio (main()'s `or 0.0` "
        "fallback is unreachable on the posting path)",
        sorted({(state, ratio is None) for state, ratio in
                (ring_verdict(13, 1), ring_verdict(12, 4), ring_verdict(12, 5),
                 ring_verdict(13, 0), ring_verdict(3, 1))}),
        [("ok", False), ("unknown", True), ("wasteful", False)])


def _test_decide(chk):
    chk("decide: stalled -> upsert", decide("stalled", False), "upsert")
    chk("decide: stalled w/ open -> upsert", decide("stalled", True), "upsert")
    chk("decide: ok + open -> close", decide("ok", True), "close")
    chk("decide: ok + none -> noop", decide("ok", False), "noop")
    chk("decide: stale half — stale -> upsert", decide("stale", False, bad="stale"), "upsert")
    chk("decide: stale half — fresh + open -> close", decide("fresh", True, bad="stale"), "close")
    # Closure requires an EXPLICIT recovery verdict, never merely "not the bad one". Without this
    # the guard has no red test, and a future third verdict — `unknown`, `degraded`, whatever a
    # later signal returns when it cannot read — would silently close a live alert.
    chk("decide: an UNKNOWN verdict never closes an open alert (absence of evidence is not a "
        "recovery)", decide("unknown", True), "noop")
    chk("decide: ... on the staleness half either", decide("unknown", True, bad="stale"), "noop")


def _test_thresholds_agree_with_the_floor(chk):
    """CROSS-FILE. The streak threshold is denominated in TICKS; how long N ticks take is set
    entirely by the #819 floor. If someone doubles the floor without touching this file, (A) stops
    being the faster signal and silently becomes dead weight behind (B)."""
    floor = _load_floor()
    streak_seconds = FAILURE_STREAK_THRESHOLD * floor.MIN_TICK_INTERVAL_SECONDS
    chk("thresholds: the failure streak is reachable strictly sooner than the staleness threshold",
        (streak_seconds, streak_seconds < STALE_THRESHOLD_SECONDS), (1800, True))


def _test_ring_threshold_is_derived_from_the_floor(chk):
    """CROSS-FILE, and this one carries the whole derivation of (C)'s threshold. The claim "a
    healthy ratio is ~1.0" is true only while the cron rings at exactly the rate the #819 floor can
    admit. Both numbers live in other files, so assert them there: raise the floor to 20 minutes
    without touching this file and the ratio silently acquires a floor of 2, making the threshold
    mean something nobody chose."""
    floor = _load_floor()
    ceiling_per_hour = 3600 // floor.MIN_TICK_INTERVAL_SECONDS
    cron_per_hour = 60 // _cron_period_minutes(_load_workflow(DISPATCH_WORKFLOW))
    chk("ring/floor: the schedule alone rings at EXACTLY the rate the floor can admit, which is "
        "what makes 1.0 the healthy ratio the threshold is a multiple of",
        (ceiling_per_hour, cron_per_hour, ceiling_per_hour == cron_per_hour), (6, 6, True))
    chk("ring/floor: the threshold keeps real headroom over that structural ideal, and still fires "
        "well below both measured pathologies (8.2 in #1208, 13.5 in #1326) — a threshold set AT "
        "the measured pathology can never catch the drift toward it",
        (RING_RUNS_PER_EXECUTED_TICK_THRESHOLD > 1,
         RING_RUNS_PER_EXECUTED_TICK_THRESHOLD < 8), (True, True))
    chk("ring/floor: the minimum sample spans at least two hours of the schedule, so one slow "
        "tick cannot swing the published ratio", RING_MIN_RUNS >= 2 * cron_per_hour, True)


def _test_threshold_vs_cadence(chk):
    """Both sides of the delivery contract, against the LIVE workflow files."""
    dispatch_period = _cron_period_minutes(_load_workflow(DISPATCH_WORKFLOW))
    groom_period = _cron_period_minutes(_load_workflow(GROOM_WORKFLOW))
    chk("cadence: the staleness threshold is at least 3 dispatch cron periods",
        (dispatch_period, STALE_THRESHOLD_SECONDS // 60 >= 3 * dispatch_period), (10, True))
    chk("cadence: the HOST workflow fires at least three times inside the threshold (a watchdog "
        "that runs less often than its own threshold cannot deliver on it)",
        (groom_period, 3 * groom_period <= STALE_THRESHOLD_SECONDS // 60), (15, True))


def _test_page_coverage(chk):
    """The listing is repo-wide and shared with three other workflows' artifacts. Without this
    predicate, "no plan artifact on page one" is an ASSUMPTION about density, and an artifact storm
    from an unrelated workflow turns it into a page at 3am."""
    now = 1_800_000_000
    stamp = lambda ago: datetime.fromtimestamp(now - ago, tz=timezone.utc).strftime(  # noqa: E731
        "%Y-%m-%dT%H:%M:%SZ")
    deep = {"artifacts": [_artifact("publish-bundle-1-1", created_at=stamp(6 * 3600))]}
    shallow = {"artifacts": [_artifact("publish-bundle-1-1", created_at=stamp(5 * 60))]}
    chk("coverage: a page reaching back 6 h proves the threshold window",
        page_covers_threshold(deep, now), True)
    chk("coverage: a page reaching back only 5 min proves NOTHING (the plan artifact could be one "
        "entry off it) — and must not be read as staleness",
        page_covers_threshold(shallow, now), False)
    chk("coverage: an empty page proves nothing", page_covers_threshold({"artifacts": []}, now),
        False)

    # And the paging behaviour that predicate drives, against a stubbed listing.
    pages = {1: shallow, 2: shallow,
             3: {"artifacts": [_artifact(f"{PLAN_ARTIFACT_PREFIX}9-1", created_at=stamp(600))]}}
    seen = []

    def crowded(args, label=""):
        if "/artifacts" in args[-1]:
            page = int(args[-1].rsplit("page=", 1)[1])
            seen.append(page)
            return pages.get(page, {"artifacts": []})
        return {"workflow_runs": []}

    _executed, plan_epoch, _horizon, _runs = read_signals("o/r", now=now, runner=crowded)
    chk("coverage: an artifact STORM makes the watchdog page on rather than fire a false alarm",
        (seen, plan_epoch == now - 600), ([1, 2, 3], True))

    uncovered = []

    def storm(args, label=""):
        if "/artifacts" in args[-1]:
            uncovered.append(args[-1])
            return shallow
        return {"workflow_runs": []}

    read_signals("o/r", now=now, runner=storm)
    chk("coverage: ... but the paging is BOUNDED, so a pathological storm costs a few requests, "
        "never an unbounded walk", len(uncovered), ARTIFACT_MAX_PAGES)


def _test_gh_flows(chk):
    """The live path over a stubbed `gh`: the signal reads, and the alert flow for every half."""
    calls = []
    # 101 executed; 102-113 are floor-held rings that concluded `success` and dispatched nothing —
    # the #1326 shape, and the shape in which (A) and (B) are the only signals that read healthy.
    _run_rows = ([{"id": 101, "run_number": 1, "conclusion": "failure",
                   "created_at": "2026-07-27T19:00:00Z"}]
                 + [{"id": rid, "run_number": rid, "conclusion": "success",
                     "created_at": "2026-07-27T19:00:00Z"} for rid in range(102, 114)])

    def fake(args, label="dispatch-stall"):
        calls.append(args[-1])
        if "/artifacts" in args[-1]:
            return {"artifacts": [_artifact(TICK_MARKER_ARTIFACT, 101),
                                  _artifact(f"{PLAN_ARTIFACT_PREFIX}101-1")]}
        return {"workflow_runs": _run_rows}

    executed_ids, plan_epoch, horizon, runs = read_signals("o/r", now=1_800_000_000, runner=fake)
    chk("live: the watchdog costs exactly TWO API requests in the normal case — and half (C) "
        "added NONE, which is the point of a watchdog for budget contention", len(calls), 2)
    chk("live: ... the artifacts listing and the dispatch runs listing",
        [("/artifacts" in calls[0]), ("workflows/dispatch.yml/runs" in calls[1])], [True, True])
    chk("live: it derives all three signals from them",
        (executed_ids, plan_epoch is not None, failure_streak(runs, executed_ids),
         ring_sample(runs, executed_ids, horizon)),
        ({101}, True, 1, (13, 1)))
    chk("live: a REFUSED listing degrades to no signal rather than raising",
        read_signals("o/r", now=1_800_000_000, runner=lambda *a, **k: None),
        (set(), None, None, None))

    # The alert flow, end to end, with `gh` stubbed at the subprocess boundary.
    class _Result:
        def __init__(self, code=0, out=""):
            self.returncode, self.stdout = code, out

    issued = []

    def fake_gh(args, capture=False, token=None, check=False, label=""):
        issued.append(args[:2])
        if args[:2] == ["issue", "list"]:
            return _Result(0, "[]")
        return _Result(0, "")

    saved_gh, saved_json, saved_now = globals()["_gh"], globals()["_gh_json"], globals()["_now"]
    env_backup = {k: os.environ.get(k) for k in ("REGISTRY_REPO", "ALERT_REPO", "ALERT_TOKEN")}
    try:
        globals()["_gh"] = fake_gh
        globals()["_gh_json"] = fake
        globals()["_now"] = lambda: parse_rfc3339("2026-07-27T18:00:00Z") + 3 * 3600
        os.environ["REGISTRY_REPO"] = "o/r"
        os.environ.pop("ALERT_REPO", None)
        os.environ.pop("ALERT_TOKEN", None)
        code = main()
    finally:
        globals()["_gh"], globals()["_gh_json"], globals()["_now"] = (
            saved_gh, saved_json, saved_now)
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    chk("live: a 3-hour-old PLAN over 13 runs that produced ONE executed tick, with no open "
        "alert, files exactly TWO issues (staleness + ring efficiency — the failure streak is 1 "
        "and stays quiet) and exits 0",
        (code, issued.count(["issue", "create"])), (0, 2))


def _test_no_hold_labels(chk):
    """STRUCTURAL AUTHORITY DENIAL, mirroring scripts/metrics-alert.py. This script may touch ONE
    ops-alert issue per marker; it must have no code path that writes a hold/role/status label, no
    merge path and no PR path. Asserted over the AST, not by convention."""
    tree = ast.parse(_require("scripts/dispatch-stall-alert.py"))
    # Scan the LIVE half only. The self-test necessarily names the very literals it forbids (that
    # is what makes it an assertion), and a scan that included them could never pass — so it would
    # be deleted, and with it the check. Stripping the test functions keeps the assertion about
    # the code that actually runs against the API.
    tree.body = [node for node in tree.body
                 if not (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                         and (node.name == "_self_test" or node.name.startswith("_test_")))]
    literals = {node.value for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    forbidden = sorted(lit for lit in literals
                       if re.match(r"^(needs:|status:|role:|review:|priority:|area:)", lit)
                       or lit in {"merge", "pr", "--auto", "--admin", "--squash"})
    chk("authority: no hold/role/status label literal and no merge/PR verb anywhere in the source",
        forbidden, [])
    # Every argv this script can construct, taken from the HEAD of every list literal in the live
    # half. That is the precise question — "which `gh` verbs can this reach?" — where a bare
    # literal scan is not: `step.get("run")` is a dict key, not a subcommand, and a check that
    # cannot tell them apart gets loosened until it means nothing.
    argv_heads = {node.elts[0].value for node in ast.walk(tree)
                  if isinstance(node, ast.List) and node.elts
                  and isinstance(node.elts[0], ast.Constant)
                  and isinstance(node.elts[0].value, str)}
    chk("authority: the only argv heads this script can build are `gh` and the issue/label/api "
        "subcommands — no pr, no run, no workflow, no repo",
        sorted(argv_heads), ["api", "gh", "issue", "label"])


def _test_workflow_seam(chk):
    """THE YAML SEAM. NO `needs:` and NO `if:` on this job, on purpose: a watchdog suppressed by
    the failure of the sweep it happens to share a workflow file with is not a watchdog — and that
    is the precise defect this unit exists to fix in dispatch.yml's own ALERT job."""
    groom = _load_workflow(GROOM_WORKFLOW)
    job = _job(groom, HOST_JOB)

    chk("seam: the watchdog declares NO `needs:` (it must survive a failed groom sweep)",
        job.get("needs"), None)
    chk("seam: the watchdog declares NO `if:` (an `if:` is how a watchdog gets silently gated off "
        "— exactly what happened to dispatch's own ALERT job)", job.get("if"), None)
    chk("seam: permissions are exactly {actions:read, contents:read, issues:write}",
        job.get("permissions"),
        {"actions": "read", "contents": "read", "issues": "write"})
    chk("seam: the watchdog job is not `continue-on-error`", job.get("continue-on-error"), None)

    tails = _invocations(job, "dispatch-stall-alert.py")
    chk("seam: the job calls this script twice — once `--self-test`, once live",
        (len(tails), tails[0] if tails else None, tails[-1] if tails else None),
        (2, ["--self-test"], []))

    # It is hosted in a DIFFERENT workflow from the one it watches. If someone ever moves it into
    # dispatch.yml, the whole argument for its existence evaporates silently.
    chk("seam: the watchdog is NOT hosted in the workflow it watches",
        HOST_JOB in ((_load_workflow(DISPATCH_WORKFLOW) or {}).get("jobs") or {}), False)

    for path in REQUIRED_FILES:
        _require(path)
    chk("seam: the job sparse-checks-out every file its self-test asserts against",
        sorted(_sparse_paths(job)), sorted(REQUIRED_FILES))


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
