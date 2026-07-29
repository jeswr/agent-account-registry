#!/usr/bin/env python3
# [OPUS-5] MINIMUM INTERVAL BETWEEN EXECUTED DISPATCH TICKS (issue #819).
#
# WHAT BROKE. PR #787 cut the PLAN snapshot step from 10m02s to ~1m30s and the whole tick from
# 15-28 min to ~7 min. That is a real 6.4x and it is NOT being reverted. What it removed by
# accident was a RATE LIMITER: `concurrency: group registry-dispatcher` serialises ticks, so tick
# DURATION was the only thing bounding how often the doorbell could start one. Executed ticks per
# hour (success+failure, coalesced-cancellations excluded) on 2026-07-27, from the runs API:
#
#     04Z 2 | 05Z 6 | 06Z 6 | 07Z 4 | 08Z 5 | 09Z 6 | 10Z 7 | 11Z 5 | 12Z 6 | 13Z 6
#     14Z 4 | 15Z 4 | 16Z 6 | 17Z 4 | 18Z 13   <- #787 merged 17:38:42Z
#
# At 18:26:17Z every authenticated read started returning HTTP 403 and has ever since: the request
# budget for the token this pipeline reads with was exhausted. PLAN dies on the first listing and
# `secrets-guard` dies resolving the default branch, so CLAIM and ALERT are both skipped and the
# pipeline does zero work while it holds.
#
# THE BUDGET ARITHMETIC, and why the constant below is what it is.
#
#   requests per executed tick  = 613
#       measured 2026-07-27 by the instrumented run recorded in scripts/plan-snapshot.py's module
#       docstring (issue #721): 613 requests, 28,334 rows, median request 0.843 s, split
#       23 listings / 116 PR-detail / 474 check-runs.
#   observed SAFE band          = 4-7 executed ticks/h, i.e. ~2,450-4,291 requests/h,
#       sustained for the thirteen hours 04Z-17Z above with zero rate-limit failures.
#   observed BREAKING rate      = 13 executed ticks/h, i.e. ~7,969 requests/h -> 403 at 18:26:17Z.
#
# 613 IS NOT A CONSTANT OF NATURE — it scales with the number of WORKER PRs on the target, because
# the PR-detail and check-runs legs walk one PR at a time (together ~96% of the requests). Pinning
# the floor to a single measured total would make it silently wrong the moment the backlog grew,
# and a backlog spike would become an outage trigger in its own right. So the arithmetic is
# expressed against `requests_per_tick(worker_prs)` below, and the floor is sized at that
# function's CEILING rather than at today's backlog.
#
# The ceiling exists and is enforced in code, which is what makes this tractable:
# plan-snapshot.WORKER_PR_STATUS_LIMIT caps per-PR status at 100 worker PRs and degrades the whole
# repo to NO prstatus above it (`worker-pr-census-overflow`), so per-tick cost cannot grow past
# ~613 no matter how far the backlog runs. The instrumented run was taken at, or very near, that
# cap — sparq carried ~121 open PRs at the time — so the measurement IS the worst case, and a
# backlog reduction only ever moves the real cost DOWN from it. That is the honest direction for
# an error in a rate limiter to point.
#
# So the true ceiling lies somewhere in (4.3k, 8.0k] requests/hour. GitHub does not publish the
# effective ceiling for this token in this configuration, and `GET /rate_limit` reports a DIFFERENT
# bucket that reads healthy while every request 403s (issue #796) — so the floor is derived from
# the OBSERVED band, never from a recalled documented constant.
#
#   floor F minutes  =>  at most 60/F executed ticks/h  =>  at most (60/F) * 613 requests/h
#   F = 10  ->  6 ticks/h  ->  ~3,678 requests/h
#
# which is (a) inside the 4-7 tick/h band that ran clean all day, (b) 46% of the rate that broke
# it, and (c) exactly the rate the cron alone already schedules (`3,13,23,33,43,53`). That last
# equality is the invariant worth stating: THE FLOOR MAKES THE DOORBELL STRUCTURALLY UNABLE TO
# EXCEED THE SCHEDULE. _test_budget_arithmetic below asserts the multiplication, so the constant
# cannot drift away from the reasoning that produced it.
#
# #787's win survives: a tick still completes in ~1.5 min of step time instead of ~10, and the
# doorbell still starts a tick the moment the floor expires instead of waiting for the next cron
# edge. What it no longer buys is a THIRTEENTH tick in an hour.
#
# HOW A WITHIN-FLOOR TICK EXITS. `proceed=false` on this job's output, exit 0. `plan` is gated on
# it, `claim` needs `plan`, so both skip and the run ends green in ~30 s having issued ONE API
# request (the anchor read below). It deliberately does NOT sleep until the floor expires: a
# sleeping job occupies a runner AND holds the `registry-dispatcher` concurrency group for the
# whole wait, which is the waiter-starvation shape ci-summary.yml documents. A no-op tick releases
# the group in seconds, so the doorbell ring behind it is served immediately (and, if it is also
# inside the floor, no-ops just as cheaply).
#
# THE ANCHOR. `last executed tick` is read from the `dispatch-tick` artifacts this same job uploads
# at the moment it decides to proceed — BEFORE the snapshot runs, so a tick that later FAILS still
# counts as executed and still holds the floor. Deriving it from run conclusions instead cannot
# work: a no-op tick concludes `success` exactly like a real one.
#
# FAIL-OPEN, deliberately, and this is the one polarity in this file that is not fail-closed. If
# the anchor cannot be read — artifacts expired, listing refused, malformed page — this proceeds
# and says so loudly. A rate limiter that can permanently stop the pipeline is a worse failure than
# the burst it prevents (a human-only unpark turns a transient outage into a permanent stall), and
# the blast radius of the fail-open is exactly ONE tick: that tick writes a fresh anchor.
#
# =============================================================================================
# WHY A WALL-CLOCK FLOOR IS NOT ENOUGH — the 2026-07-29 06:19-06:32Z recurrence.
#
# The floor above WORKS, and the re-measurement says so rather than the reading: over
# 03:10Z-06:52Z on 2026-07-29 it admitted 18 EXECUTED ticks out of 68 non-coalesced runs (4.86
# executed ticks/h, inside its own 6/h ceiling) and HELD the other 50 — including, live, a tick
# 8m36s after the previous one. The doorbell rang 138 times in that window; the floor is exactly
# what kept 138 rings from becoming 138 sweeps. None of that stopped the budget going to zero
# again at 06:19Z.
#
# The defect is the DENOMINATOR. Every number in the arithmetic above is dispatch's own, and it
# is compared against a band (`OBSERVED_SAFE_REQUESTS_PER_HOUR`) that was also measured from
# dispatch's own tick counts — as though this workflow were the only thing spending. It is not.
# The `github.token` budget is ONE bucket shared by every workflow run in the repository, and in
# the exhausted hour 05:33:47Z-06:33:47Z (the window whose reset the pipeline recovered on) that
# repository ran 360 workflow runs: 131 triage-issue, 99 set-up-account, 52 dispatch, ~40
# review-fix, ~12 worker, 10 pr-gate, and the scheduled sweeps. Four full dispatch ticks in that
# hour spent 4 x 613 = 2,452 requests — 49% of the entire repository's 5,000 — and the other
# ~2,548 were spent by the other 356 runs. The floor's own ceiling, 6 x 613 = 3,678/h, is 74% of
# a budget it does not own.
#
# So the floor cannot be fixed by lowering the constant: the right number depends on what the
# REST of the estate is spending this hour, which no constant can know. What it can know is the
# ONE authoritative number — `x-ratelimit-remaining`, off a real response — and the anchor read
# below is already a real response. The budget gate therefore costs ZERO extra requests: it reads
# the remaining budget off the headers of the request the floor was making anyway, and holds the
# tick when what is left cannot pay for one.
#
# This also closes the fail-open residual the paragraph above used to end on. During a total
# budget outage the anchor read 403s — but that 403 CARRIES `x-ratelimit-remaining: 0`, which is
# positive evidence, so the tick now defers on it instead of proceeding into PLAN's 613-request
# sweep. Measured shape of the outage this removes: of the 10 red ticks at 06:19-06:32Z, 8 had
# PLAN correctly SKIPPED by the wall-clock floor and went red anyway, and 2 were admitted into an
# empty bucket and died in the snapshot.
#
# THE HOLD HAS A MACHINE EXIT, and it is the same one the wall-clock hold has: a deferred tick
# writes NO anchor (the upload step is gated on the same `proceed` output), so nothing is
# ratcheted forward and the very first doorbell ring after the budget resets executes
# immediately. No human unparks this. The cost of a deferred tick is the ONE request the anchor
# read already spent.
#
# POSITIVE EVIDENCE ONLY, in both directions. An ABSENT `x-ratelimit-remaining` proceeds — an
# absent header proves nothing, and failing closed on it would take the pipeline down on any
# proxy that strips it (the same polarity `plan-snapshot._check_reserve` chose). And the number
# is never read from `GET /rate_limit`: that endpoint reports a DIFFERENT bucket and read healthy
# through the whole 2026-07-27 outage (#796), which is why it is not called here and a response
# header is.
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------------------------
# THE FLOOR. Derived in the header block above; NOT a tuning knob and deliberately NOT
# env-overridable (a threshold readable from the workflow is a second place to get it wrong).
MIN_TICK_INTERVAL_SECONDS = 10 * 60

# The instrumented per-tick request count the arithmetic above is built on (issue #721), and the
# linear model it calibrates. Splits from the same instrumented run: 23 listings (repo-level, does
# not scale with PRs) and 590 per-PR requests (116 detail + 474 check-runs) across the worker PRs
# that run snapshotted.
SNAPSHOT_LISTING_REQUESTS = 23
# plan-snapshot.WORKER_PR_STATUS_LIMIT. Duplicated as a plain int rather than imported because
# this module is loaded in jobs that do not check out plan-snapshot.py; the self-test asserts the
# two agree whenever that file IS present, so they cannot drift silently.
WORKER_PR_STATUS_LIMIT = 100
SNAPSHOT_REQUESTS_PER_WORKER_PR = 5.9   # 590 / 100 worker PRs, the cap the run was taken at


def requests_per_tick(worker_prs=WORKER_PR_STATUS_LIMIT):
    """Authenticated requests one EXECUTED tick issues, as a function of the target's worker-PR
    count. Above WORKER_PR_STATUS_LIMIT the snapshot stops doing per-PR status entirely
    (`worker-pr-census-overflow`), so the cost does not keep climbing — it CLAMPS, and the clamp
    is what makes a floor derived from one measurement stay valid as the backlog moves."""
    counted = min(max(int(worker_prs), 0), WORKER_PR_STATUS_LIMIT)
    return SNAPSHOT_LISTING_REQUESTS + SNAPSHOT_REQUESTS_PER_WORKER_PR * counted


# THE PRE-FLIGHT BUDGET RESERVE. Held back so a tick that IS admitted leaves enough behind for the
# jobs that are not PLAN — secrets-guard's 3 reads, CLAIM's lease/launch writes, and plan-alert's
# one `gh issue list`. Deliberately the SAME number as plan-snapshot.RATE_LIMIT_RESERVE, and the
# self-test cross-asserts the two whenever that file is present: a snapshot that stops at 100
# remaining and a floor that admits a tick at 50 remaining would be two halves of one control
# disagreeing about what the reserve is for.
RATE_LIMIT_RESERVE = 100

# The SHARED bucket, as reported by `x-ratelimit-limit` on this repository's own responses. It is
# recorded here only so the arithmetic below can state the thing the original derivation missed:
# this number is not dispatch's allowance, it is the whole repository's, and dispatch is one of
# ~360 runs an hour drawing on it. Never used as a runtime threshold — the live remaining count
# off a real response is the only number the gate acts on.
SHARED_HOURLY_BUDGET = 5000

# [#1207] THIS IS NOW THE COLD-CACHE CEILING, and it stays the admission threshold on purpose.
# plan-snapshot.py makes the per-PR check-runs reads CONDITIONAL against a cross-tick ETag store,
# and measured against the live targets 213-222 of 222 of them answer 304 — which does not
# decrement the bucket — so a warm tick now spends roughly 23 listings + 116 detail + ~19
# billable check-runs reads, not 613.
#
# The floor is NOT lowered to that number. A cold store is a real state (first tick after a cache
# eviction, a mass force-push, a restore that finds nothing) and in that state the tick really
# does cost 613. Admitting a tick at the warm price would let exactly the cold tick through with
# too little budget to finish — reopening the #819 exhaustion this file exists to prevent. An
# error in a rate limiter must point at spending less, not more, so the gate keeps costing the
# tick at its ceiling.
#
# The WIN is therefore not visible in this constant; it is visible in the number this gate reads.
# Ticks that spend ~190-200 instead of 613 leave `x-ratelimit-remaining` high, so far more ticks
# clear the same threshold. (That figure is the UNDER-LOAD one: the 304 rate is ~87-90% when the
# targets are busy, against 96-100% measured in a quieter window. The conservative number is the
# one quoted, here and in the PR.) plan-snapshot.py prints the per-tick split ("SNAPSHOT conditional reads:
# N of M ... billable") so the realised saving is auditable on every tick rather than assumed.
MEASURED_REQUESTS_PER_TICK = 613
# The highest hourly request rate observed to run clean, and the rate that broke. Both are
# measured, both are asserted against the floor by _test_budget_arithmetic.
OBSERVED_SAFE_REQUESTS_PER_HOUR = 7 * MEASURED_REQUESTS_PER_TICK      # 10Z: 7 executed ticks
OBSERVED_BREAKING_REQUESTS_PER_HOUR = 13 * MEASURED_REQUESTS_PER_TICK  # 18Z: 13 executed ticks

# The artifact whose creation time IS the "this tick executed" record. Uploaded by the floor job
# itself, immediately after it decides to proceed and before any target read happens.
TICK_MARKER_ARTIFACT = "dispatch-tick"
# One page is plenty: at the floor's own ceiling of 6/h with 1-day retention there are at most
# ~144 of these, and the newest is always on the first page.
ARTIFACT_PAGE_SIZE = 100

DISPATCH_WORKFLOW = ".github/workflows/dispatch.yml"
FLOOR_JOB = "tick-floor"
GATED_JOB = "plan"
FLOOR_STEP_ID = "floor"

# Every file the self-test asserts against. The floor job sparse-checks-out exactly this set and
# _test_selftest_inputs_are_checked_out asserts that it does — a trimmed checkout would make the
# YAML-seam assertions silently unreachable in the live path, which is the exact fail-open class
# this unit exists to close.
REQUIRED_FILES = (
    "scripts/dispatch-tick-floor.py",
    DISPATCH_WORKFLOW,
)


class TickFloorError(Exception):
    """A contract this script refuses to guess about."""


# ---------------------------------------------------------------------------------------------
# pure decision
# ---------------------------------------------------------------------------------------------
def decide(last_executed_epoch, now, interval=MIN_TICK_INTERVAL_SECONDS):
    """-> ('run'|'hold', age_seconds|None, reason).

    `hold` is returned ONLY for an anchor that was actually parsed and is inside the floor. Every
    other outcome runs (see the FAIL-OPEN note in the header). A future-dated anchor (runner clock
    skew) runs rather than holding out an unbounded number of ticks on a bad clock."""
    if last_executed_epoch is None:
        return "run", None, "no readable executed-tick anchor"
    age = int(now) - int(last_executed_epoch)
    if age < 0:
        return "run", age, "anchor is in the future (clock skew)"
    if age < interval:
        return "hold", age, "inside the minimum interval between executed ticks"
    return "run", age, "ok"


def budget_floor(worker_prs=WORKER_PR_STATUS_LIMIT):
    """The remaining request budget a tick must SEE before it is allowed to start: everything the
    tick will spend, plus the reserve the rest of the pipeline needs after it. Sized at
    requests_per_tick()'s CEILING for the same reason the wall-clock floor is — an error in a rate
    limiter should point at spending less, not more."""
    return int(requests_per_tick(worker_prs)) + RATE_LIMIT_RESERVE


def decide_budget(remaining, threshold=None):
    """-> ('run'|'hold', threshold, reason). The PRE-FLIGHT half of the floor (#819 recurrence).

    POSITIVE EVIDENCE ONLY. `hold` is returned solely for a remaining count that was actually read
    off a response and is below what one tick costs. `remaining is None` — header absent, stripped
    by a proxy, unparseable — RUNS: an absent header proves nothing, and a rate limiter that fails
    closed on a missing header can stall the pipeline with no human-free way back. That is the same
    polarity plan-snapshot._check_reserve chose, and the same one decide() uses for a missing
    anchor."""
    threshold = budget_floor() if threshold is None else int(threshold)
    if remaining is None:
        return "run", threshold, "no readable remaining-budget header"
    if int(remaining) < threshold:
        return "hold", threshold, "remaining request budget cannot pay for one tick"
    return "run", threshold, "ok"


def newest_marker_epoch(payload, marker=TICK_MARKER_ARTIFACT):
    """Newest `created_at` among non-expired artifacts named exactly `marker`. -> epoch|None.

    Name matching is EQUALITY, never a prefix: `dispatch-plan-<run>-<attempt>` also starts with
    `dispatch-` and reading it as a tick marker would anchor the floor on the wrong event. Every
    malformed shape returns None, which decide() reads as `run` — the fail-open polarity."""
    if not isinstance(payload, dict):
        return None
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        return None
    best = None
    for entry in artifacts:
        if not isinstance(entry, dict) or entry.get("name") != marker:
            continue
        if entry.get("expired") is True:
            continue
        epoch = parse_rfc3339(entry.get("created_at"))
        if epoch is not None and (best is None or epoch > best):
            best = epoch
    return best


def parse_rfc3339(raw):
    """GitHub's `2026-07-27T18:26:17Z` -> epoch int, or None for anything else."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        stamp = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(stamp.timestamp())


# ---------------------------------------------------------------------------------------------
# live path
# ---------------------------------------------------------------------------------------------
def split_response(raw):
    """`gh api -i` stdout -> (headers dict, lower-cased keys; body str).

    REFUSES TO GUESS: a payload that does not begin with a status line is treated as headerless
    (`{}` — no budget evidence, which decide_budget reads as RUN) rather than being scanned for
    colons. A JSON body is full of them, and inventing an `x-ratelimit-remaining` out of one would
    make the gate fire on noise."""
    if not isinstance(raw, str) or not raw:
        return {}, ""
    text = raw.replace("\r\n", "\n")
    if not text.startswith("HTTP/"):
        return {}, raw
    head, _, body = text.partition("\n\n")
    headers = {}
    for line in head.splitlines()[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return headers, body


def _int_header(headers, name):
    try:
        return int(str((headers or {})[name]).strip())
    except (KeyError, TypeError, ValueError):
        return None


def remaining_budget(headers):
    """`x-ratelimit-remaining` off a real response, or None. The ONLY source this file will accept
    for the number: `GET /rate_limit` reports a different bucket and read healthy through the whole
    2026-07-27 outage (#796), so it is never called here."""
    return _int_header(headers, "x-ratelimit-remaining")


def budget_detail(headers):
    """`remaining/limit, resets at ...` for the recorded deferral line. Deliberately the same shape
    as plan-snapshot._budget_detail, so one grep finds both halves of the control."""
    remaining = remaining_budget(headers)
    limit = _int_header(headers, "x-ratelimit-limit")
    reset = _int_header(headers, "x-ratelimit-reset")
    when = (datetime.fromtimestamp(reset, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if reset is not None else "unknown")
    return (f"x-ratelimit-remaining={remaining if remaining is not None else 'absent'}"
            f"/{limit if limit is not None else 'absent'}, resets at {when}")


def _gh_response(args, label="tick-floor"):
    """Run `gh <args>` and read it as an `-i` response. -> (parsed|None, headers dict).

    The headers come back EVEN WHEN THE REQUEST FAILED, and that is the point: a budget-exhausted
    403 carries `x-ratelimit-remaining: 0`, which is precisely the evidence the pre-flight gate
    needs and which no successful request can supply once the bucket is empty.

    Sanitized: only the subcommand words and the return code are ever printed — `GH_DEBUG=api`
    echoes request bodies into stderr, so stderr is never surfaced, and the rate-limit numbers are
    the only part of the response this file ever prints."""
    result = subprocess.run(["gh"] + args, capture_output=True, text=True, check=False)
    headers, body = split_response(result.stdout)
    if result.returncode != 0:
        print(f"::warning::{label}: gh {args[0]} failed (rc={result.returncode})")
        return None, headers
    try:
        return json.loads(body or "null"), headers
    except ValueError:
        print(f"::warning::{label}: gh {args[0]} succeeded but returned unparseable JSON")
        return None, headers


def read_anchor(repo, runner=None):
    """-> (newest executed-tick marker epoch|None, response headers dict). ONE API request — the
    same one the pre-flight budget gate reads its evidence off, so that gate costs nothing.

    `runner` is resolved at CALL time, not bound as a default: a default argument captures the
    function object at definition, which makes the live path unpatchable and every stubbed-flow
    assertion below quietly exercise the real `gh`."""
    runner = runner or _gh_response
    payload, headers = runner(["api", "-i", "-H", "Accept: application/vnd.github+json",
                               f"/repos/{repo}/actions/artifacts"
                               f"?name={TICK_MARKER_ARTIFACT}&per_page={ARTIFACT_PAGE_SIZE}"])
    return newest_marker_epoch(payload), (headers or {})


def _now():
    """Wall clock, isolated so the self-test can pin it."""
    return int(datetime.now(tz=timezone.utc).timestamp())


def _emit(proceed):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"proceed={'true' if proceed else 'false'}\n")


def _record(line):
    """Append a deferral to the run's job summary as well as the log, so deferred ticks are
    COUNTABLE after the fact rather than only greppable. Uses the always-present
    GITHUB_STEP_SUMMARY file, so recording needs no new workflow wiring to go wrong."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


def main():
    repo = os.environ["REGISTRY_REPO"]
    anchor, headers = read_anchor(repo)
    action, age, reason = decide(anchor, _now())
    minutes = "unknown" if age is None else f"{age // 60}m{age % 60:02d}s"
    if action == "hold":
        print(f"tick-floor: HOLD — last executed tick was {minutes} ago, floor is "
              f"{MIN_TICK_INTERVAL_SECONDS // 60} min ({reason}). This tick is a clean no-op: "
              "PLAN and CLAIM will be skipped and no snapshot request will be issued.")
        _emit(False)
        return 0

    # PRE-FLIGHT BUDGET GATE. The wall-clock floor says this tick MAY run; this asks whether it
    # can AFFORD to. Evidence is the `x-ratelimit-remaining` header on the anchor read above — no
    # extra request, and the only authoritative source (#796). A tick that cannot pay defers here
    # having spent ONE request, instead of starting a 613-request sweep that dies on its first
    # read and takes GUARD, CLAIM and the ops-alert down with it.
    budget_action, threshold, budget_reason = decide_budget(remaining_budget(headers))
    if budget_action == "hold":
        detail = budget_detail(headers)
        print(f"::warning::tick-floor: DEFER (budget) — {budget_reason}: one tick costs up to "
              f"{int(requests_per_tick())} requests and this job holds back {RATE_LIMIT_RESERVE} "
              f"for GUARD/CLAIM/ALERT, so it needs {threshold} ({detail}). This tick is a clean "
              "no-op: PLAN and CLAIM are skipped, NO anchor is written, and the first doorbell "
              "ring after the reset executes immediately — no human unparks this.")
        _record(f"- `tick-floor` DEFER budget: needed {threshold}, {detail}")
        _emit(False)
        return 0

    if anchor is None:
        print(f"::warning::tick-floor: {reason} — proceeding (fail-open). The floor is a rate "
              "limiter, not a safety control; refusing here would stall the pipeline until a "
              "human intervened. This tick writes a fresh anchor.")
    else:
        print(f"tick-floor: RUN — last executed tick was {minutes} ago (floor "
              f"{MIN_TICK_INTERVAL_SECONDS // 60} min).")
    print(f"tick-floor: budget ok — {budget_detail(headers)} (needs {threshold})")
    _emit(True)
    return 0


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
        raise TickFloorError(
            f"self-test input {path} is missing from the working copy at {_repo_root()} — the "
            "YAML-seam assertions cannot run, and a self-test that silently stops asserting is "
            "worse than no self-test. Add it to the job's sparse-checkout list.")
    with open(full, encoding="utf-8") as handle:
        return handle.read()


def _load_workflow(path):
    import yaml  # hard requirement: regex-over-YAML is how five permissive misparses got in
    return yaml.safe_load(_require(path))


def _job(workflow, name):
    jobs = (workflow or {}).get("jobs") or {}
    if name not in jobs:
        raise TickFloorError(
            f"workflow has no job named `{name}` — refusing to assert against a job that does not "
            "exist (a deleted floor must go RED here, not silently pass)")
    return jobs[name]


def _declared_needs(job):
    declared = job.get("needs")
    if declared is None:
        return []
    return [declared] if isinstance(declared, str) else list(declared)


# The ONE grammar of job-level `if:` this gate uses. Anchored and single-comparison on purpose: a
# gate rewritten into a form this harness cannot reason about must RAISE, not be waved through —
# an unevaluatable gate is an UNCHECKED polarity on a surface no runtime check can reach. Copied
# deliberately from scripts/metrics-alert.py's reviewed `_eval_job_if`.
_JOB_IF_COMPARISON = re.compile(
    r"^needs\.([A-Za-z0-9_-]+)\.(result|outputs\.[A-Za-z0-9_.-]+)\s*(==|!=)\s*'([^']*)'$")


def _eval_job_if(expr, needs):
    """EVALUATE a job-level `if:` against a hypothetical `needs` context. -> bool.

    `expr is None` models GitHub's default for a job with `needs:` and no `if:` — an implicit
    success() over the needed jobs. That is what makes DELETING the gate visible here rather than
    only in production, on the one tick that matters."""
    def _success():
        return all((ctx or {}).get("result") == "success" for ctx in needs.values())

    if expr is None:
        return _success()
    if isinstance(expr, bool):  # `if: false` parses as a YAML boolean, not the string "false"
        return expr
    text = str(expr).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    if text == "always()":
        return True
    if text in ("true", "false"):
        return text == "true"
    if text == "success()":
        return _success()
    match = _JOB_IF_COMPARISON.match(text)
    if not match:
        raise TickFloorError(
            f"unmodelled job `if:` expression {expr!r} — this harness only evaluates the restricted "
            "grammar the dispatch gates use. Extend _eval_job_if deliberately, or keep the gate in "
            "the modelled grammar; an expression it cannot evaluate is an unchecked polarity.")
    job, field, operator, want = match.groups()
    context = needs.get(job)
    if context is None:
        raise TickFloorError(
            f"job `if:` reads needs.{job}, which is not among the modelled needs {sorted(needs)} — "
            "a gate that names a job it does not depend on always reads the empty string")
    got = (context.get("result", "") if field == "result"
           else (context.get("outputs") or {}).get(field.split(".", 1)[1], ""))
    return (got == want) if operator == "==" else (got != want)


def _plan_runs(workflow, proceed):
    """Does `plan` execute when the floor job succeeds with `proceed`? Models BOTH seams at once —
    the `needs:` edge AND the `if:`. A gate expressed only as an `if:` is defeated by cutting
    `needs:` (the output then reads as the empty string, which happens to hold, but the job also
    stops WAITING for the floor, so it can run before the anchor is written); a gate expressed only
    as a `needs:` edge is defeated by deleting the `if:`."""
    plan = _job(workflow, GATED_JOB)
    if FLOOR_JOB not in _declared_needs(plan):
        return True  # no dependency at all: `plan` starts regardless of the floor
    needs = {name: {"result": "success", "outputs": {}} for name in _declared_needs(plan)}
    needs[FLOOR_JOB] = {"result": "success", "outputs": {"proceed": proceed}}
    return _eval_job_if(plan.get("if"), needs)


def _invocations(step, script):
    """Executable `python3 .../<script>` command lines in a step's `run:` body, COMMENTS STRIPPED.
    A filename grep over a shell body is satisfied by a comment or a backslash-continuation tail —
    two separate ways a wiring assertion has gone vacuous in this estate."""
    body = step.get("run") or ""
    live = "\n".join(line for line in body.replace("\\\n", " ").splitlines()
                     if not line.strip().startswith("#"))
    pattern = re.compile(rf"^\s*python3\s+(?:\S*/)?{re.escape(script)}([^\n]*)$", re.M)
    return [m.group(1).split() for m in pattern.finditer(live)]


def _steps(job):
    return job.get("steps") or []


def _step_by_id(job, step_id):
    found = [s for s in _steps(job) if s.get("id") == step_id]
    if len(found) != 1:
        raise TickFloorError(
            f"expected exactly one step with `id: {step_id}`, found {len(found)} — refusing to "
            "assert against a step that cannot be located")
    return found[0]


def _sparse_paths(job, path="registry"):
    found = [(step.get("with") or {}) for step in _steps(job)
             if str(step.get("uses", "")).startswith("actions/checkout@")
             and (step.get("with") or {}).get("path") == path]
    if len(found) != 1:
        raise TickFloorError(
            f"expected exactly one actions/checkout with `path: {path}`, found {len(found)}")
    spec = found[0].get("sparse-checkout") or ""
    return {line.strip() for line in str(spec).splitlines() if line.strip()}


def _cron_minutes(workflow):
    """The set of minutes-past-the-hour an explicit-minute cron fires at."""
    triggers = workflow.get("on", workflow.get(True)) or {}
    crons = [entry["cron"] for entry in (triggers.get("schedule") or []) if "cron" in entry]
    if len(crons) != 1:
        raise TickFloorError(f"expected exactly one cron schedule, found {len(crons)}")
    minute = crons[0].split()[0]
    if "/" in minute:
        step = int(minute.split("/")[1])
        return set(range(0, 60, step))
    return {int(part) for part in minute.split(",")}


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    _test_budget_arithmetic(chk)
    _test_floor_predicate(chk)
    _test_preflight_budget_predicate(chk)
    _test_anchor_parsing(chk)
    _test_response_splitting(chk)
    _test_a_too_soon_tick_issues_no_snapshot_requests(chk)
    _test_an_unaffordable_tick_issues_no_snapshot_requests(chk)
    _test_live_path(chk)
    _test_workflow_seam(chk)

    print("dispatch-tick-floor self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _test_budget_arithmetic(chk):
    """The constant must keep agreeing with the reasoning that produced it. Every number here is
    measured (see the header); this asserts the MULTIPLICATION, so nobody can quietly halve the
    floor and leave the justification standing."""
    ticks_per_hour = 3600 / MIN_TICK_INTERVAL_SECONDS
    ceiling = ticks_per_hour * MEASURED_REQUESTS_PER_TICK
    chk("budget: the floor admits at most 6 executed ticks/hour", ticks_per_hour, 6.0)
    chk("budget: 6 ticks/h x 613 requests = 3678 requests/h", ceiling, 3678.0)
    # The cost model, and the clamp that makes a floor derived from ONE measurement stay valid as
    # the backlog moves. Without the clamp assertion, a growing backlog silently invalidates the
    # arithmetic above and a backlog spike becomes an outage trigger.
    chk("budget: the cost model reproduces the instrumented measurement at the worker-PR cap",
        round(requests_per_tick(WORKER_PR_STATUS_LIMIT)), MEASURED_REQUESTS_PER_TICK)
    chk("budget: per-tick cost is MONOTONE in the worker-PR count (a bigger backlog is a bigger "
        "tick — the floor is sized at the ceiling, not at today's backlog)",
        requests_per_tick(20) < requests_per_tick(60) < requests_per_tick(100), True)
    chk("budget: ... and CLAMPS at the WORKER_PR_STATUS_LIMIT census overflow, so no backlog can "
        "push a tick past the measured worst case",
        (requests_per_tick(500), requests_per_tick(5000)),
        (requests_per_tick(WORKER_PR_STATUS_LIMIT),) * 2)
    chk("budget: the floor holds at that CEILING, not merely at today's cost",
        ticks_per_hour * requests_per_tick(WORKER_PR_STATUS_LIMIT)
        <= OBSERVED_SAFE_REQUESTS_PER_HOUR, True)
    # Cross-file: the clamp is only real if it is the number plan-snapshot actually enforces.
    snapshot = os.path.join(_repo_root(), "scripts", "plan-snapshot.py")
    if os.path.isfile(snapshot):
        with open(snapshot, encoding="utf-8") as handle:
            declared = re.search(r"^WORKER_PR_STATUS_LIMIT\s*=\s*(\d+)", handle.read(), re.M)
        chk("budget: the clamp matches plan-snapshot.py's live WORKER_PR_STATUS_LIMIT",
            int(declared.group(1)) if declared else None, WORKER_PR_STATUS_LIMIT)
    chk("budget: the ceiling is at or under the highest rate observed to run CLEAN "
        f"({OBSERVED_SAFE_REQUESTS_PER_HOUR}/h)", ceiling <= OBSERVED_SAFE_REQUESTS_PER_HOUR, True)
    chk("budget: the ceiling is at most half the rate that BROKE it "
        f"({OBSERVED_BREAKING_REQUESTS_PER_HOUR}/h)",
        ceiling <= OBSERVED_BREAKING_REQUESTS_PER_HOUR / 2, True)
    # The invariant the header states in words: the doorbell cannot outpace the schedule.
    workflow = _load_workflow(DISPATCH_WORKFLOW)
    scheduled_per_hour = len(_cron_minutes(workflow))
    chk("budget: the floor admits no more ticks/hour than the cron alone already schedules",
        (ticks_per_hour, scheduled_per_hour <= ticks_per_hour), (6.0, True))


def _test_floor_predicate(chk):
    now = 1_800_000_000
    floor = MIN_TICK_INTERVAL_SECONDS
    chk("floor: a tick 3 min after the last executed tick HOLDS",
        decide(now - 3 * 60, now)[0], "hold")
    chk("floor: a tick 11 min after the last executed tick RUNS",
        decide(now - 11 * 60, now)[0], "run")
    chk("floor: EXACTLY at the floor runs; one second inside it holds (the comparison is `<`, and "
        "an off-by-one here is either a stalled pipeline or an unbounded one)",
        (decide(now - floor, now)[0], decide(now - floor + 1, now)[0]), ("run", "hold"))
    chk("floor: no anchor at all RUNS (fail-open — a rate limiter must never be able to stall the "
        "pipeline permanently)", decide(None, now)[0], "run")
    chk("floor: a FUTURE-dated anchor runs rather than holding out ticks on a skewed clock",
        decide(now + 600, now)[0], "run")
    chk("floor: the held tick reports its real age", decide(now - 120, now)[1], 120)


def _test_preflight_budget_predicate(chk):
    """THE PRE-FLIGHT GATE (#819 recurrence). The wall-clock floor bounds dispatch's OWN rate; this
    bounds it against what the rest of the estate has already spent out of the shared bucket."""
    floor_value = budget_floor()
    chk("preflight: the threshold is one tick's own cost PLUS the reserve the rest of the "
        "pipeline needs after it", floor_value,
        int(requests_per_tick(WORKER_PR_STATUS_LIMIT)) + RATE_LIMIT_RESERVE)
    chk("preflight: an EXHAUSTED budget (remaining 0 — the 06:19Z outage) HOLDS",
        decide_budget(0)[0], "hold")
    chk("preflight: a budget that cannot cover one tick HOLDS", decide_budget(floor_value - 1)[0],
        "hold")
    chk("preflight: EXACTLY the threshold runs; one request under it holds (an off-by-one here is "
        "either a stalled pipeline or a tick that dies mid-sweep)",
        (decide_budget(floor_value)[0], decide_budget(floor_value - 1)[0]), ("run", "hold"))
    chk("preflight: a healthy budget RUNS", decide_budget(4832)[0], "run")
    chk("preflight: an ABSENT remaining header RUNS (positive evidence only — an absent header "
        "proves nothing, and failing closed on it strands the pipeline behind a human)",
        decide_budget(None)[0], "run")
    # The reserve is only real if it is the same number the snapshot stops at. Two halves of one
    # control disagreeing about the reserve is how a tick gets admitted at 50 remaining.
    snapshot = os.path.join(_repo_root(), "scripts", "plan-snapshot.py")
    if os.path.isfile(snapshot):
        with open(snapshot, encoding="utf-8") as handle:
            declared = re.search(r"^RATE_LIMIT_RESERVE\s*=\s*(\d+)", handle.read(), re.M)
        chk("preflight: the reserve matches plan-snapshot.py's live RATE_LIMIT_RESERVE",
            int(declared.group(1)) if declared else None, RATE_LIMIT_RESERVE)
    # THE SHARED-BUCKET ARITHMETIC that makes a pre-flight gate necessary AT ALL, and the reason
    # the wall-clock floor alone could not stop the 2026-07-29 recurrence. Measured over
    # 05:33:47Z-06:33:47Z (the window whose reset the pipeline recovered on): 360 workflow runs in
    # this ONE repository, of which dispatch was 52. Every one of them spends from this bucket.
    chk("preflight: the wall-clock floor's own hourly ceiling is a MAJORITY of the whole SHARED "
        "bucket, so no constant can be safe — the other ~356 runs/h in this repository can empty "
        "it inside a legal 6-tick hour, which is why the gate reads the LIVE remaining budget",
        ((3600 // MIN_TICK_INTERVAL_SECONDS) * MEASURED_REQUESTS_PER_TICK
         > SHARED_HOURLY_BUDGET // 2), True)
    chk("preflight: ... and the gate's threshold is a small fraction of that bucket, so the gate "
        "throttles dispatch rather than reserving the bucket for it",
        budget_floor() < SHARED_HOURLY_BUDGET // 4, True)


def _test_response_splitting(chk):
    """`gh api -i` parsing. The gate is only as good as the header read that feeds it, and a
    permissive misparse here would invent budget evidence out of a JSON body."""
    raw = ("HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n"
           "X-RateLimit-Limit: 5000\r\nX-RateLimit-Remaining: 4832\r\n"
           "X-RateLimit-Reset: 1785308701\r\n\r\n{\"artifacts\": []}")
    headers, body = split_response(raw)
    chk("split: the remaining budget is read off the response headers, case-insensitively",
        remaining_budget(headers), 4832)
    chk("split: the body still parses as JSON after the headers are stripped",
        json.loads(body), {"artifacts": []})
    chk("split: the detail line names the budget and its reset", budget_detail(headers),
        "x-ratelimit-remaining=4832/5000, resets at 2026-07-29T07:05:01Z")
    # A 403 response is where the number MATTERS most: no successful request can supply it once
    # the bucket is empty, so the failure path must still yield the headers.
    refused = ("HTTP/2.0 403 Forbidden\r\nX-RateLimit-Limit: 5000\r\n"
               "X-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: 1785310427\r\n\r\n"
               "{\"message\": \"API rate limit exceeded for installation\"}")
    chk("split: a REFUSED (403) response still yields remaining=0 — the evidence the gate needs "
        "is only ever on the failure",
        (remaining_budget(split_response(refused)[0]),
         decide_budget(remaining_budget(split_response(refused)[0]))[0]), (0, "hold"))
    # REFUSING TO GUESS, and why it is load-bearing rather than decorative. Without the status-line
    # requirement, ANY captured text with two colon-bearing lines is read as a header block — so a
    # `gh` deprecation notice, a proxy error page, or a mangled capture could hand the gate a
    # `remaining: 0` it never received from GitHub and hold the pipeline out on noise. A rate
    # limiter that can be stalled by arbitrary text is worse than one that fails open.
    forged = ("Warning: gh is deprecated in this environment\n"
              "x-ratelimit-remaining: 0\n\n{\"artifacts\": []}")
    chk("split: text that is NOT an HTTP response yields NO budget evidence, even when it contains "
        "header-shaped lines (delete the status-line requirement and noise can stall the floor)",
        (remaining_budget(split_response(forged)[0]),
         decide_budget(remaining_budget(split_response(forged)[0]))[0]), (None, "run"))
    for label, payload in (("headerless JSON body", "{\"x-ratelimit-remaining\": 0}"),
                           ("empty string", ""), ("not a string", None)):
        chk(f"split: {label} yields NO budget evidence (refuses to guess) -> RUN",
            (remaining_budget(split_response(payload)[0]),
             decide_budget(remaining_budget(split_response(payload)[0]))[0]), (None, "run"))


def _test_an_unaffordable_tick_issues_no_snapshot_requests(chk):
    """THE REGRESSION THIS GATE EXISTS FOR (the 2026-07-29 06:19-06:32Z recurrence): a tick that
    arrives past the wall-clock floor but into an EMPTY shared bucket must not start the sweep.

    Composed end to end against a counting fake, exactly as dispatch.yml wires it, because the
    defect class is a gate that returns the right answer into a pipeline that ignores it — and
    because the anchor-write side is what makes the hold self-exiting rather than a stall."""
    clock = {"now": 1_800_000_000}
    store, budget, snapshot_calls = [], {"remaining": 5000}, {"n": 0}

    def tick():
        anchor = newest_marker_epoch({"artifacts": store})
        if decide(anchor, clock["now"])[0] != "run":
            return "noop-floor"
        budget["remaining"] -= 1                     # the anchor read itself
        if decide_budget(budget["remaining"])[0] != "run":
            return "noop-budget"                     # NO anchor written: nothing ratchets forward
        store.append({"name": TICK_MARKER_ARTIFACT,
                      "created_at": datetime.fromtimestamp(clock["now"], tz=timezone.utc)
                      .strftime("%Y-%m-%dT%H:%M:%SZ")})
        snapshot_calls["n"] += MEASURED_REQUESTS_PER_TICK
        budget["remaining"] -= MEASURED_REQUESTS_PER_TICK
        return "executed"

    chk("unaffordable: a tick with a full budget executes", tick(), "executed")
    # Drain the bucket the way the other ~356 runs/h in the repository actually drain it.
    budget["remaining"] = 12
    clock["now"] += 20 * 60
    baseline = snapshot_calls["n"]
    chk("unaffordable: past the wall-clock floor but with an EMPTY bucket, the tick DEFERS",
        tick(), "noop-budget")
    chk("unaffordable: ... and it issued ZERO snapshot requests (it spent 1, not 613)",
        snapshot_calls["n"] - baseline, 0)
    anchor_before = len(store)
    for _ in range(9):
        clock["now"] += 60
        tick()
    chk("unaffordable: nine more rings into the empty bucket still issue ZERO snapshot requests",
        snapshot_calls["n"] - baseline, 0)
    chk("unaffordable: ... and NONE of them wrote an anchor, so the deferral cannot ratchet the "
        "wall-clock floor forward while the budget is out", len(store), anchor_before)
    # THE MACHINE EXIT. The budget resets on its own hourly schedule; nothing human is involved,
    # and the very next ring must run. A hold with no proven exit is a stall (this estate has
    # shipped several).
    budget["remaining"] = 5000
    clock["now"] += 60
    chk("unaffordable: the FIRST ring after the budget resets executes immediately — the hold "
        "self-exits with no human unpark", tick(), "executed")


def _test_anchor_parsing(chk):
    page = {"artifacts": [
        {"name": "dispatch-plan-30295860510-1", "created_at": "2026-07-27T18:54:14Z"},
        {"name": "dispatch-tick", "created_at": "2026-07-27T18:20:00Z"},
        {"name": "dispatch-tick", "created_at": "2026-07-27T18:40:00Z"},
        {"name": "dispatch-tick", "created_at": "2026-07-27T18:50:00Z", "expired": True},
    ]}
    chk("anchor: takes the NEWEST non-expired `dispatch-tick`",
        newest_marker_epoch(page), parse_rfc3339("2026-07-27T18:40:00Z"))
    chk("anchor: `dispatch-plan-*` is NOT a tick marker (name matching is equality, not prefix — "
        "anchoring on the plan artifact would silently move the floor to a different event)",
        newest_marker_epoch({"artifacts": [
            {"name": "dispatch-plan-1-1", "created_at": "2026-07-27T18:54:14Z"}]}), None)
    for label, payload in (
            ("payload is not an object", ["nope"]),
            ("payload has no artifacts list", {"total_count": 0}),
            ("artifacts is not a list", {"artifacts": "nope"}),
            ("every entry is malformed", {"artifacts": [None, 7, {"name": "dispatch-tick"}]}),
            ("created_at is not RFC3339",
             {"artifacts": [{"name": "dispatch-tick", "created_at": "yesterday"}]}),
    ):
        chk(f"anchor: {label} -> None (and therefore RUN, fail-open)",
            newest_marker_epoch(payload), None)


def _test_a_too_soon_tick_issues_no_snapshot_requests(chk):
    """THE REGRESSION THIS UNIT EXISTS FOR (#819): a tick arriving faster than the floor must not
    issue the snapshot's API calls.

    The composition is exercised end to end against a counting fake — the floor's decision, the
    anchor it writes when it proceeds, and the snapshot that runs only when it proceeds. Asserting
    `decide()` alone would not pin this: the defect class is a gate that returns the right answer
    into a pipeline that ignores it."""
    clock = {"now": 1_800_000_000}
    store = []          # the `dispatch-tick` artifacts, as the artifacts endpoint would return them
    snapshot_calls = {"n": 0}

    def tick():
        """One dispatch run, wired exactly as dispatch.yml wires it: floor first, PLAN only when it
        says proceed, and the marker written by the floor BEFORE the snapshot (so a tick that dies
        in the snapshot still holds the floor)."""
        action, _age, _reason = decide(newest_marker_epoch({"artifacts": store}), clock["now"])
        if action != "run":
            return "noop"
        store.append({"name": TICK_MARKER_ARTIFACT,
                      "created_at": datetime.fromtimestamp(clock["now"], tz=timezone.utc)
                      .strftime("%Y-%m-%dT%H:%M:%SZ")})
        snapshot_calls["n"] += MEASURED_REQUESTS_PER_TICK   # PLAN's 613 authenticated reads
        return "executed"

    first = tick()
    chk("regression: the first tick executes (no anchor yet)", first, "executed")
    baseline = snapshot_calls["n"]

    clock["now"] += 3 * 60
    chk("regression: a tick 3 min later is a NO-OP", tick(), "noop")
    chk("regression: ... and it issued ZERO snapshot requests",
        snapshot_calls["n"] - baseline, 0)

    # The doorbell shape that actually caused #819: a burst of rings inside the floor.
    for _ in range(9):
        clock["now"] += 30
        tick()
    chk("regression: nine more doorbell rings inside the floor issue ZERO snapshot requests "
        "between them", snapshot_calls["n"] - baseline, 0)

    clock["now"] += 10 * 60
    chk("regression: the first tick PAST the floor executes again", tick(), "executed")

    # And the rate the whole composition actually admits, over a full simulated hour of a doorbell
    # ringing every 30 s — the number the budget arithmetic is about.
    clock, store, snapshot_calls = {"now": 1_800_000_000}, [], {"n": 0}
    executed = 0
    for _ in range(120):
        if tick() == "executed":
            executed += 1
        clock["now"] += 30
    chk("regression: a doorbell ringing every 30 s for an hour executes at most 6 ticks",
        executed <= 6, True)
    chk("regression: ... i.e. at most 3678 snapshot requests in that hour",
        snapshot_calls["n"] <= 3678, True)


def _test_live_path(chk):
    """read_anchor()/main() over a stubbed `gh`: the anchor read is ONE request, and every failure
    mode of it lands on the fail-open side rather than raising."""
    calls = []
    healthy = {"x-ratelimit-remaining": "4832", "x-ratelimit-limit": "5000"}

    def fake(args, label="tick-floor"):
        calls.append(args)
        return ({"artifacts": [{"name": TICK_MARKER_ARTIFACT,
                                "created_at": "2026-07-27T18:40:00Z"}]}, healthy)

    got, headers = read_anchor("jeswr/agent-account-registry", runner=fake)
    chk("live: the anchor read is exactly ONE API request", len(calls), 1)
    chk("live: ... filtered to the marker name server-side",
        f"name={TICK_MARKER_ARTIFACT}" in calls[0][-1], True)
    chk("live: ... and scoped to the registry repo",
        "/repos/jeswr/agent-account-registry/actions/artifacts" in calls[0][-1], True)
    # The budget gate is FREE only because the request it reads is one the floor already made.
    # Drop `-i` and the headers vanish, the gate goes permanently fail-open, and this row reds.
    chk("live: ... requested with `-i`, so the SAME request carries the budget headers and the "
        "pre-flight gate costs zero extra requests", "-i" in calls[0], True)
    chk("live: it returns the marker's epoch", got, parse_rfc3339("2026-07-27T18:40:00Z"))
    chk("live: ... and the remaining budget off that same response",
        remaining_budget(headers), 4832)
    chk("live: a REFUSED listing (the 403 outage itself) reads as no anchor -> RUN",
        read_anchor("o/r", runner=lambda *a, **k: (None, {}))[0], None)
    chk("live: ... but a refusal that CARRIES remaining=0 hands the gate its evidence, so the "
        "tick defers instead of proceeding into a 613-request sweep (the #819 fail-open residual)",
        decide_budget(remaining_budget(
            read_anchor("o/r", runner=lambda *a, **k: (None, {"x-ratelimit-remaining": "0"}))[1]
        ))[0], "hold")

    # The workflow output contract, written the way GitHub reads it.
    import tempfile
    for label, anchor, budget, want in (
            ("hold", 60, healthy, "proceed=false\n"),
            ("run", 4000, healthy, "proceed=true\n"),
            # Past the wall-clock floor, but the shared bucket is empty: the gate, not the clock,
            # is what refuses. Delete the call site in main() and this row reds.
            ("budget-deferred", 4000, {"x-ratelimit-remaining": "12", "x-ratelimit-limit": "5000"},
             "proceed=false\n")):
        with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as handle:
            out_path = handle.name
        env_backup = {k: os.environ.get(k) for k in ("GITHUB_OUTPUT", "REGISTRY_REPO")}
        try:
            os.environ["GITHUB_OUTPUT"] = out_path
            os.environ["REGISTRY_REPO"] = "o/r"
            stamp = datetime.fromtimestamp(_now() - anchor, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            saved = globals()["_gh_response"]
            globals()["_gh_response"] = lambda *a, _b=budget, _s=stamp, **k: (
                {"artifacts": [{"name": TICK_MARKER_ARTIFACT, "created_at": _s}]}, _b)
            try:
                code = main()
            finally:
                globals()["_gh_response"] = saved
            with open(out_path, encoding="utf-8") as handle:
                written = handle.read()
        finally:
            for key, value in env_backup.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            os.unlink(out_path)
        chk(f"live: a {label} tick exits 0 and writes {want.strip()!r}", (code, written),
            (0, want))


def _test_workflow_seam(chk):
    """THE YAML SEAM. Measured on this estate: every Python mutant died while every UNCAUGHT one
    lived in a workflow `if:`, a step, or a call site. The floor lives at that seam, so mutate it
    here — job deleted, `if:` flipped, `needs:` cut, `continue-on-error` added, call site removed."""
    workflow = _load_workflow(DISPATCH_WORKFLOW)
    floor = _job(workflow, FLOOR_JOB)
    plan = _job(workflow, GATED_JOB)

    # --- the gate itself, evaluated in BOTH directions -------------------------------------
    chk("seam: PLAN runs when the floor says proceed", _plan_runs(workflow, "true"), True)
    chk("seam: PLAN does NOT run when the floor says hold (delete the `if:` or cut the `needs:` "
        "edge and this goes red)", _plan_runs(workflow, "false"), False)
    chk("seam: PLAN declares the floor as a `needs:` dependency",
        FLOOR_JOB in _declared_needs(plan), True)
    # A gate that admits on an ABSENT/empty output is a fail-open gate. GitHub renders an
    # unset job output as the empty string, so this is the shape a deleted `_emit` produces.
    chk("seam: PLAN does NOT run when the floor emits NOTHING (an unset output is the empty "
        "string, and admitting on it is fail-open)", _plan_runs(workflow, ""), False)

    # --- the floor job's own shape ----------------------------------------------------------
    chk("seam: the floor job exposes `proceed` as a job output",
        (floor.get("outputs") or {}).get("proceed"),
        "${{ steps.%s.outputs.proceed }}" % FLOOR_STEP_ID)
    chk("seam: the floor job holds exactly {actions:read, contents:read} — actions:read is what "
        "lets it LIST the marker artifacts, and nothing else is needed",
        floor.get("permissions"), {"actions": "read", "contents": "read"})
    # `continue-on-error` discards exactly the exit status that would report a broken floor, and a
    # step can never red its own neutering — so something ELSE has to assert its absence.
    chk("seam: no truthy `continue-on-error` at the floor job or step level",
        [floor.get("continue-on-error")] + [s.get("continue-on-error") for s in _steps(floor)],
        [None] * (1 + len(_steps(floor))))

    # --- the call site ----------------------------------------------------------------------
    decision = _step_by_id(floor, FLOOR_STEP_ID)
    tails = _invocations(decision, "dispatch-tick-floor.py")
    chk("seam: the decision step calls this script twice — once `--self-test`, once live",
        (len(tails), tails[0] if tails else None, tails[-1] if tails else None),
        (2, ["--self-test"], []))
    chk("seam: the decision step is not `continue-on-error`",
        decision.get("continue-on-error"), None)

    # --- the anchor WRITE: the floor is only sound if a proceeding tick records itself --------
    uploads = [s for s in _steps(floor)
               if str(s.get("uses", "")).startswith("actions/upload-artifact@")
               and (s.get("with") or {}).get("name") == TICK_MARKER_ARTIFACT]
    chk("seam: exactly one step uploads the executed-tick marker", len(uploads), 1)
    if uploads:
        upload = uploads[0]
        chk("seam: the marker upload is gated on the SAME proceed output the plan gate reads (a "
            "marker written on a no-op tick would ratchet the floor forward forever)",
            str(upload.get("if")).strip(),
            "${{ steps.%s.outputs.proceed == 'true' }}" % FLOOR_STEP_ID)
        chk("seam: the marker upload fails loud when it has nothing to upload",
            (upload.get("with") or {}).get("if-no-files-found"), "error")
        chk("seam: the marker upload is not `continue-on-error` (a silently dropped anchor "
            "un-floors every subsequent tick)", upload.get("continue-on-error"), None)
        marker_index = _steps(floor).index(upload)
        snapshot_index = next(
            (i for i, s in enumerate(_steps(_job(workflow, GATED_JOB)))), None)
        chk("seam: the marker is written inside the FLOOR job, before PLAN can start at all "
            "(so a tick that dies in the snapshot still holds the floor)",
            (marker_index > _steps(floor).index(decision), snapshot_index is not None),
            (True, True))

    # --- the self-test's own inputs ---------------------------------------------------------
    _test_selftest_inputs_are_checked_out(chk, floor)


def _test_selftest_inputs_are_checked_out(chk, floor):
    """Every file the assertions above read must be in the live job's sparse-checkout, or the whole
    YAML-seam section is unreachable on the live path while still passing in pr-gate."""
    for path in REQUIRED_FILES:
        _require(path)
    declared = _sparse_paths(floor)
    chk("seam: the floor job sparse-checks-out every file its self-test asserts against",
        sorted(declared), sorted(REQUIRED_FILES))


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
