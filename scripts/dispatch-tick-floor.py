#!/usr/bin/env python3
# [SPARQ agent] MINIMUM INTERVAL BETWEEN EXECUTED DISPATCH TICKS (issue #819).
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
#   historical measured tick    = 613 requests at the old 100-PR census cap
#       measured 2026-07-27 by the instrumented run recorded in scripts/plan-snapshot.py's module
#       docstring (issue #721): 23 listings / 116 PR-detail / 474 check-runs.
#   post-#2099 core model       = 23 + (3.1 * 150) + (0.2 * 150) = 518 requests
#       measured 2026-08-31: 433 red-only core pages across both live targets, including
#       428 across 139 Sparq workers and 5 across 29 registry workers; 3.1 and 0.2 round both
#       target-specific slopes upward and price BOTH targets at their independent 150-row caps.
#   post-#2099 GraphQL ceiling = 300 workers * 2.5 points = 750 points/tick
#       measured 2026-08-31: 168 workers, 182 requests / 364 points, zero skips. GraphQL has
#       its own 5,000-point bucket and plan-snapshot enforces a 100-point response-body reserve.
#   observed SAFE band          = 4-7 executed ticks/h, i.e. ~2,450-4,291 requests/h,
#       sustained for the thirteen hours 04Z-17Z above with zero rate-limit failures.
#   observed BREAKING rate      = 13 executed ticks/h, i.e. ~7,969 requests/h -> 403 at 18:26:17Z.
#
# 613 WAS NEVER A CONSTANT OF NATURE — cost scales with the number of WORKER PRs on the target,
# the PR-detail and check-runs legs walk one PR at a time (together ~96% of the requests). Pinning
# the floor to a single measured total would make it silently wrong the moment the backlog grew,
# and a backlog spike would become an outage trigger in its own right. So the arithmetic is
# expressed against `requests_per_tick(worker_prs)` below, and the floor is sized at that
# function's CEILING rather than at today's backlog.
#
# The ceiling exists and is enforced in code, which is what makes this tractable:
# plan-snapshot.WORKER_PR_STATUS_LIMIT caps per-PR status at 150 worker PRs and degrades the whole
# repo to NO prstatus above it (`worker-pr-census-overflow`). The post-#2099 model prices each of
# the two enabled targets independently at that cap using its measured red-only REST slope; a
# backlog reduction only moves the modeled cost down from that two-target ceiling.
#
# So the true ceiling lies somewhere in (4.3k, 8.0k] requests/hour. GitHub does not publish the
# effective ceiling for this token in this configuration, and `GET /rate_limit` reports a DIFFERENT
# bucket that reads healthy while every request 403s (issue #796) — so the floor is derived from
# the OBSERVED band, never from a recalled documented constant.
#
#   floor F minutes  =>  at most 60/F executed ticks/h
#   F = 10  ->  6 ticks/h  ->  3,108 core requests/h and 4,500 GraphQL points/h
#
# which is (a) inside the 4-7 tick/h band that ran clean all day, (b) 46% of the rate that broke
# it, and (c) exactly the rate the cron alone schedules (`3,13,23,33,43,53`). That last
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
#
# =============================================================================================
# THE GATE WAS READING THE WRONG METER — registry #1228.
#
# Everything above is sound EXCEPT one sentence: "the `github.token` budget is ONE bucket shared
# by every workflow run in the repository". That is FALSE, and the whole gate rested on it. The
# anchor read is a real response, but it is not a response from the bucket this tick spends, so
# the gate has been reporting the health of a counter its consumers barely touch.
#
# MEASURED, 2026-07-28T12:00Z-07-29T12:00Z, over the 616 dispatch runs created in that window
# (the denominator for every rate in this block unless another is named):
#
#   * 102 EXECUTED ticks (the floor admitted them AND the PLAN job actually started).
#   * 16 of those 102 (15.7%) died in PLAN, and 16 of 16 died on the request budget — 8 on a
#     hard `x-ratelimit-remaining=0/5000` 403, 8 on the pre-emptive reserve stop at 39-100.
#   * Live `tick-floor: DEFER (budget)` lines in the same window: ZERO.
#
# The gate never fired while the failure it exists to prevent fired 16 times. That is not a
# threshold that needs tuning; it is a gate wired to the wrong signal.
#
# WHY. GitHub partitions this token's `core` allowance by API ROUTE, not by repository. Both
# halves report `x-ratelimit-limit: 5000` and `x-ratelimit-resource: core`, so nothing in the
# headers announces the split — only the RESET stamps do, and they sit ~20 minutes apart all day.
#
#   bucket the FLOOR reads   `/repos/{repo}/actions/artifacts`  (the anchor read below)
#   bucket the TICK spends   `/repos/{repo}`, `/repos/{o}/{r}/issues`, `/pulls`, `/check-runs`
#                            — i.e. PLAN's entire sweep, GUARD's default-branch read, CLAIM.
#
# THE DECISIVE OBSERVATION, and it is decisive because it holds the REPOSITORY FIXED. In run
# 30447572002, both lines live (each after its own `self-test PASSED` sentinel — the fixture
# output above the sentinel says `resets at unknown` and must never be quoted, #1250):
#
#   11:26:45Z  FLOOR  /repos/jeswr/agent-account-registry/actions/artifacts
#                     -> x-ratelimit-remaining=4643/5000, resets at 11:55:30Z
#   11:27:13Z  GUARD  repos/jeswr/agent-account-registry
#                     -> "BUDGET - read refused ... REQUEST BUDGET IS SPENT"
#
# Same repository. Same `github.token`. Twenty-eight seconds apart. One route healthy at 4643,
# the other refused as spent. A per-REPOSITORY split cannot produce that, so the earlier reading
# of this data — that the registry's bucket was healthy while sparq's was empty — was wrong about
# WHY, and a fix built on it (sweep the healthy target, skip the exhausted one) would have
# delivered nothing: when this bucket empties, EVERY target's `issues` and `pulls` reads are
# refused together. That design was built and thrown away rather than shipped on the inference.
#
# Per-job token minting is excluded too: five independent runs, with five independent GITHUB_TOKEN
# mints, reported the SAME reset 10:55:23Z with `remaining` decrementing 4887 -> 4666 -> 4612 ->
# 4546 -> 4395. A bucket minted per job starts full and cannot be shared.
#
# THE FIX, and its cost. The gate now takes its evidence from a response charged to the bucket the
# tick SPENDS: one `GET /repos/{owner}/{repo}` — the same route GUARD reads, so one grep finds the
# gate and its first consumer. That is +1 request per ADMITTED tick and it is NOT free, so it is
# justified rather than assumed: a tick that is held by the wall-clock floor still costs exactly
# the one anchor read it always did (the probe is issued only after `decide` says RUN), and an
# admitted tick trades 1 request for not starting a sweep that cannot finish. At the measured 102
# executed ticks/day that is ~102 extra requests against a 5,000/hour allowance.
#
# WHY NOT KEEP IT AT ZERO. The anchor is `dispatch-tick` artifact creation time, and artifacts are
# only listable on `/actions/artifacts` — which is the OTHER bucket, by measurement. There is no
# route that answers both questions, so one request cannot serve both. Deriving the anchor from
# run conclusions instead would put it on the spend bucket, but it cannot work for the reason the
# header states above: a no-op tick concludes `success` exactly like a real one.
#
# WITH N TARGETS THE BUDGET IS STILL SCALAR, which is the other thing getting the mechanism right
# bought. Because the split is by route and not by repository, all N targets draw on ONE counter;
# there is no per-target vector to hold on, and no "hold if ANY target is unreadable" rule that
# could strand the pipeline on one bad target. The probe is deliberately aimed at the FIRST TARGET
# rather than at the registry, which costs nothing and keeps the meter correct even if the route
# partition turns out to be finer than measured — under any keying, the repo whose sweep dominates
# the spend is the repo the gate is reading.
#
# POSITIVE EVIDENCE ONLY IS UNCHANGED, and is now the property that makes the extra request safe
# to add: a probe that fails to produce a readable count RUNS the tick. The gate can only ever
# hold on a number it actually read, so a broken probe costs one request and never a stall.
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

# The CLAIM census now walks the live 150-PR board after PLAN. Production run 33444551254
# exhausted the old 15-minute job bound before that walk completed; give the bounded job three
# floor intervals while the workflow concurrency group coalesces later doorbells behind it.
CLAIM_TIMEOUT_MINUTES = 30

# The instrumented per-tick request count the arithmetic above is built on (issue #721), and the
# linear model it calibrates. Splits from the same instrumented run: 23 listings (repo-level, does
# not scale with PRs) and 590 per-PR requests (116 detail + 474 check-runs) across the worker PRs
# that run snapshotted.
SNAPSHOT_LISTING_REQUESTS = 23
# plan-snapshot.WORKER_PR_STATUS_LIMIT. Duplicated as a plain int rather than imported because
# this module is loaded in jobs that do not check out plan-snapshot.py; the self-test asserts the
# two agree whenever that file IS present, so they cannot drift silently.
WORKER_PR_STATUS_LIMIT = 150
SNAPSHOT_REQUESTS_PER_WORKER_PR = 3.1
SECONDARY_TARGET_REQUESTS_PER_WORKER_PR = 0.2
TARGET_REPOSITORY_COUNT = 2


def requests_per_tick(worker_prs=WORKER_PR_STATUS_LIMIT,
                      secondary_worker_prs=WORKER_PR_STATUS_LIMIT):
    """Authenticated requests one EXECUTED tick issues, as a function of the target's worker-PR
    count. Above WORKER_PR_STATUS_LIMIT the snapshot stops doing per-PR status entirely
    (`worker-pr-census-overflow`), so the cost does not keep climbing — it CLAMPS, and the clamp
    is what makes a floor derived from one measurement stay valid as the backlog moves."""
    counted = min(max(int(worker_prs), 0), WORKER_PR_STATUS_LIMIT)
    secondary = min(max(int(secondary_worker_prs), 0), WORKER_PR_STATUS_LIMIT)
    return (SNAPSHOT_LISTING_REQUESTS + SNAPSHOT_REQUESTS_PER_WORKER_PR * counted
            + SECONDARY_TARGET_REQUESTS_PER_WORKER_PR * secondary)


# GraphQL is a separate primary-rate-limit bucket. The live two-target census after #2099 read
# 168 workers in 182 requests / 364 points; 2.5 points per worker rounds that 2.17-point slope
# upward, and 300 workers covers both enabled targets at their independent 150-row caps. This is
# an hourly proof, not a runtime gate: make_graphql_fetch enforces the
# authoritative response-body reserve on every query.
GRAPHQL_WORKER_PR_ALLOWANCE = TARGET_REPOSITORY_COUNT * WORKER_PR_STATUS_LIMIT
GRAPHQL_POINTS_PER_WORKER_PR = 2.5
GRAPHQL_POINTS_PER_TICK = round(GRAPHQL_WORKER_PR_ALLOWANCE * GRAPHQL_POINTS_PER_WORKER_PR)
GRAPHQL_HOURLY_BUDGET = 5000
GRAPHQL_RATE_LIMIT_RESERVE = 100


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

# [#1207/#2099] THIS IS THE CORE-BUCKET COLD-CACHE CEILING, and it stays the admission
# threshold on purpose. Exact gate/detail reads have moved to GraphQL's separate bucket;
# the remaining core fan-out is the red-only unfiltered repair-context walk.
# plan-snapshot.py makes the per-PR check-runs reads CONDITIONAL against a cross-tick ETag store,
# and measured against the live targets 213-222 of 222 of them answer 304 — which does not
# decrement the bucket — so a warm two-target tick spends roughly 23 listings plus about 43
# billable red-only pages at the measured 90% hit rate, not the 518-request cold ceiling.
#
# The floor is NOT lowered to that number. A cold store is a real state (first tick after a cache
# eviction, a mass force-push, a restore that finds nothing) and in that state the tick really
# can cost 518 with both live targets at the 150-PR cap. Admitting at the warm price would let the
# cold tick through with too little budget to finish — reopening the #819 exhaustion this file
# exists to prevent. An
# error in a rate limiter must point at spending less, not more, so the gate keeps costing the
# tick at its ceiling.
#
# The WIN is therefore not visible in this constant; it is visible in the number this gate reads.
# Warm ticks leave `x-ratelimit-remaining` high, so the six-per-hour schedule remains affordable.
# (The UNDER-LOAD 304 rate is ~87-90% when the
# targets are busy, against 96-100% measured in a quieter window. The conservative number is the
# one quoted, here and in the PR.) plan-snapshot.py prints the per-tick split ("SNAPSHOT conditional reads:
# N of M ... billable") so the realised saving is auditable on every tick rather than assumed.
HISTORICAL_MEASURED_REQUESTS_PER_TICK = 613
# The live admission price is the conservative cold-cache ceiling at the current census cap.
# Keep it computed from the model so a cap change cannot leave a plausible stale literal behind.
COLD_CACHE_REQUESTS_PER_TICK = round(requests_per_tick(WORKER_PR_STATUS_LIMIT))
# The highest hourly request rate observed to run clean, and the rate that broke. Both are
# measured, both are asserted against the floor by _test_budget_arithmetic.
OBSERVED_SAFE_REQUESTS_PER_HOUR = 7 * HISTORICAL_MEASURED_REQUESTS_PER_TICK
OBSERVED_BREAKING_REQUESTS_PER_HOUR = 13 * HISTORICAL_MEASURED_REQUESTS_PER_TICK

# The artifact whose creation time IS the "this tick executed" record. Uploaded by the floor job
# itself, immediately after it decides to proceed and before any target read happens.
TICK_MARKER_ARTIFACT = "dispatch-tick"
# One page is plenty for finding the newest marker: at 6/h there can be 144 within retention,
# but the API returns newest first and the newest is therefore always on the first page.
ARTIFACT_PAGE_SIZE = 100

DISPATCH_WORKFLOW = ".github/workflows/dispatch.yml"
FLOOR_JOB = "tick-floor"
GATED_JOB = "plan"
# Every job that must OBEY `proceed`. `plan` is the original (#819). `secrets-guard` joined it in
# #1208: on a held tick it verifies settings that gate jobs which are already skipped — pure
# observation — while spending an authenticated read from the bucket the floor is protecting, and
# when that bucket is the thing that is gone it also goes red for it. Listing them here rather than
# hard-coding `plan` is what makes the seam assertion cover both without two copies of it.
GATED_JOBS = (GATED_JOB, "secrets-guard")
FLOOR_STEP_ID = "floor"

# THE ONE DEFINITION of "which minutes past the hour does this cron fire at" (#1046), CONSUMED
# rather than copied (#1279). This file used to expand the minute field itself and got a stepped
# RANGE wrong — it read the step and dropped the range's START, so `7-59/15` (groom-sweep.yml's live
# cron) expanded to :00/:15/:30/:45 instead of :07/:22/:37/:52. It was latent only because the one
# workflow it is applied to writes explicit minutes, which is exactly how a second definition
# survives: it is never asked the question that separates it from the first (#958).
CRON_MINUTES_SCRIPT = "scripts/ci-latency-alert.py"

# Every file the self-test asserts against. The floor job sparse-checks-out exactly this set and
# _test_selftest_inputs_are_checked_out asserts that it does — a trimmed checkout would make the
# YAML-seam assertions silently unreachable in the live path, which is the exact fail-open class
# this unit exists to close.
REQUIRED_FILES = (
    "scripts/dispatch-tick-floor.py",
    "scripts/yaml_dependency.py",
    CRON_MINUTES_SCRIPT,
    DISPATCH_WORKFLOW,
)


# The owner/repo grammar the workflow's own target-manifest step enforces. Duplicated here rather
# than imported because this module is loaded in a job that checks out neither the manifest step
# nor its helper; `_test_spend_probe_repo` pins the two against dispatch.yml's copy.
_SAFE_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")


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
    """-> (newest executed-tick marker epoch|None, response headers dict). ONE API request.

    ITS HEADERS ARE NO LONGER THE BUDGET EVIDENCE (registry #1228). `/actions/artifacts` is on a
    DIFFERENT rate-limit bucket from everything this tick goes on to spend — measured, same
    repository, 28 s apart, one route at 4643/5000 while the other was refused as spent. This
    request answers "when did the last tick execute", and only that; `read_spend_budget` below
    answers "can this tick afford to run".

    `runner` is resolved at CALL time, not bound as a default: a default argument captures the
    function object at definition, which makes the live path unpatchable and every stubbed-flow
    assertion below quietly exercise the real `gh`."""
    runner = runner or _gh_response
    payload, headers = runner(["api", "-i", "-H", "Accept: application/vnd.github+json",
                               f"/repos/{repo}/actions/artifacts"
                               f"?name={TICK_MARKER_ARTIFACT}&per_page={ARTIFACT_PAGE_SIZE}"])
    return newest_marker_epoch(payload), (headers or {})


def spend_probe_repo(environ=None):
    """The repository whose `/repos/{owner}/{repo}` response the budget gate reads (#1228).

    The FIRST entry of the target manifest, because that is the repo whose sweep dominates the
    tick's spend. Falling back to `REGISTRY_REPO` is not a degraded mode: by measurement the split
    is by ROUTE, so `/repos/<anything>` is the same counter either way, and the fallback keeps the
    gate ARMED rather than silently disabled when the manifest is absent or malformed. That
    matters more than picking the ideal repo — an env var that can quietly turn a rate limiter off
    is the #1234 class, and this one cannot.

    Validated against the same owner/repo grammar the workflow's manifest step enforces, so a
    malformed manifest can never be interpolated into a request path."""
    environ = os.environ if environ is None else environ
    try:
        targets = json.loads(environ.get("DISPATCH_TARGET_REPOS") or "[]")
    except ValueError:
        targets = []
    if isinstance(targets, list):
        for entry in targets:
            if isinstance(entry, str) and _SAFE_REPO.fullmatch(entry):
                return entry
    fallback = environ.get("REGISTRY_REPO") or ""
    return fallback if _SAFE_REPO.fullmatch(fallback) else None


def read_spend_budget(repo, runner=None):
    """-> response headers dict for ONE `GET /repos/{owner}/{repo}` (#1228).

    THE METER THAT MATCHES THE SPEND. This route is on the bucket PLAN's `issues`/`pulls`/
    `check-runs` sweep, GUARD's default-branch read and CLAIM all draw from — `/actions/artifacts`
    is not, which is the whole defect. It is deliberately the exact path GUARD reads
    (`repos/{repo}` in dispatch-secrets-guard.py) so one grep finds the gate and its first
    consumer, and a single small object keeps it to one unpaginated request.

    Costs ONE request, and only on a tick the wall-clock floor has already admitted. Headers come
    back even when the request FAILED, which is the point: a budget-exhausted 403 carries
    `x-ratelimit-remaining: 0`, and that is precisely the evidence this gate needs and that no
    successful request can supply once the bucket is empty."""
    if not repo:
        # No probe was possible, so there is NO evidence — which decide_budget reads as RUN. A
        # rate limiter that stalls the pipeline because it could not name a repository is worse
        # than the burst it prevents.
        return {}
    runner = runner or _gh_response
    _payload, headers = runner(["api", "-i", "-H", "Accept: application/vnd.github+json",
                                f"/repos/{repo}"], "tick-floor budget probe")
    return headers or {}


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
    # The anchor read's headers are deliberately DISCARDED (#1228): they carry a real
    # `x-ratelimit-remaining`, for a bucket this tick does not spend. Binding them to a name here
    # is how the wrong number got believed for as long as it did.
    anchor, _artifacts_bucket_headers = read_anchor(repo)
    action, age, reason = decide(anchor, _now())
    minutes = "unknown" if age is None else f"{age // 60}m{age % 60:02d}s"
    if action == "hold":
        print(f"tick-floor: HOLD — last executed tick was {minutes} ago, floor is "
              f"{MIN_TICK_INTERVAL_SECONDS // 60} min ({reason}). This tick is a clean no-op: "
              "PLAN and CLAIM will be skipped and no snapshot request will be issued.")
        _emit(False)
        return 0

    # PRE-FLIGHT BUDGET GATE. The wall-clock floor says this tick MAY run; this asks whether it
    # can AFFORD to. A tick that cannot pay defers here having spent TWO requests, instead of
    # starting a sweep that dies on its first read and takes GUARD, CLAIM and the ops-alert with
    # it.
    #
    # [#1228] THE EVIDENCE IS A SECOND REQUEST, ON PURPOSE, and this is the only place in this
    # file that spends one it did not have to. The anchor read's headers are NOT usable here: they
    # come from `/actions/artifacts`, which is a different rate-limit bucket from the one this
    # tick spends — measured on the same repository, 28 s apart, one route at 4643/5000 while the
    # other was refused as spent. Reading the anchor's counter was free and wrong; over the 102
    # executed ticks of 2026-07-28T12:00Z-07-29T12:00Z it fired ZERO times while 16 ticks died in
    # PLAN on the budget it was supposed to be watching.
    #
    # ORDER IS LOAD-BEARING: this runs AFTER the wall-clock `hold` returns above, so a tick inside
    # the floor still costs exactly ONE request, exactly as before. Only an admitted tick pays for
    # the probe.
    headers = read_spend_budget(spend_probe_repo())
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
    from yaml_dependency import require_yaml
    yaml = require_yaml("dispatch-tick-floor workflow-seam checks")
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


def _gated_job_runs(workflow, job_name, proceed):
    """Does `job_name` execute when the floor job succeeds with `proceed`? Models BOTH seams at
    once — the `needs:` edge AND the `if:`. A gate expressed only as an `if:` is defeated by cutting
    `needs:` (the output then reads as the empty string, which happens to hold, but the job also
    stops WAITING for the floor, so it can run before the anchor is written); a gate expressed only
    as a `needs:` edge is defeated by deleting the `if:`."""
    job = _job(workflow, job_name)
    if FLOOR_JOB not in _declared_needs(job):
        return True  # no dependency at all: the job starts regardless of the floor
    needs = {name: {"result": "success", "outputs": {}} for name in _declared_needs(job)}
    needs[FLOOR_JOB] = {"result": "success", "outputs": {"proceed": proceed}}
    return _eval_job_if(job.get("if"), needs)


def _plan_runs(workflow, proceed):
    """`_gated_job_runs` for `plan`, kept as a name because the floor's whole reason for existing
    is that PLAN is the expensive half."""
    return _gated_job_runs(workflow, GATED_JOB, proceed)


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


def _cron_minutes_module(root=None):
    """Load the single definition of cron-minute expansion (#1046, #1279).

    Lazily, and only from the self-test: the live floor never expands a cron, so an admitted tick
    carries no new import. Same importlib idiom as regate-sweep.py's `_cron_map_module`.

    RAISES when the owner is absent, and that polarity is the point: a fallback to a private copy
    is how the second definition comes back, and it would come back GREEN."""
    import importlib.util

    base = _repo_root() if root is None else root
    path = os.path.join(base, CRON_MINUTES_SCRIPT)
    if not os.path.isfile(path):
        raise TickFloorError(
            f"{CRON_MINUTES_SCRIPT} is missing from the working copy at {base} — it owns the "
            "cron-minute expansion this file consumes, and without it the schedule assertion "
            "cannot run. Add it to the job's sparse-checkout list.")
    spec = importlib.util.spec_from_file_location("registry_cron_minutes", path)
    if spec is None or spec.loader is None:
        raise TickFloorError(f"cannot load {CRON_MINUTES_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cron_minutes(workflow, expand=None):
    """The set of minutes-past-the-hour this workflow's single cron fires at.

    THE EXPANSION IS NOT DEFINED HERE (#1279) — `ci-latency-alert.cron_minutes` owns it, handles
    `a-b/step` and is self-tested there in both directions. What IS defined here is the
    one-cron-per-workflow contract the caller depends on: the consumer counts minutes PER HOUR, so
    reading only the first of several schedules would under-count and make the budget invariant
    pass on a schedule it never saw. Anything it cannot expand RAISES rather than reducing to the
    empty set, which would satisfy that invariant vacuously — and since #1279 that includes a
    field that is only PARTLY unreadable, which is the shape an empty-set refusal cannot catch:
    the owner refuses an out-of-range atom instead of discarding it, so a minute list cannot come
    back rounded down to a plausible schedule the workflow will never actually fire on."""
    triggers = workflow.get("on", workflow.get(True)) or {}
    crons = [entry["cron"] for entry in (triggers.get("schedule") or []) if "cron" in entry]
    if len(crons) != 1:
        raise TickFloorError(f"expected exactly one cron schedule, found {len(crons)}")
    expand = expand or _cron_minutes_module().cron_minutes
    return set(expand(crons[0]))


def _scheduled_minutes(workflow):
    """-> (minutes|None, error). `_cron_minutes`, REPORTING instead of raising.

    The budget row reads it, and that row sits in `_test_budget_arithmetic` — the second function
    the suite runs — so a raise there would abort the NINE that follow: one mutant masking the
    rest, and a mutation run that scores that crash as a kill (AGENTS.md pre-flight item 4,
    `crash-after-partial-run`). Reporting is NOT failing open: a
    missing owner, a second schedule or an unexpandable cron comes back as (None, error) and the
    caller's row reds on it, naming the error."""
    try:
        return _cron_minutes(workflow), None
    except Exception as exc:  # noqa: BLE001 - ANY derivation failure must red, never abort
        return None, exc


def _raised(thunk):
    """Did `thunk` raise? -> bool. A row that asserts a REFUSAL needs the refusal itself, not the
    absence of a wrong answer."""
    try:
        thunk()
    except Exception:  # noqa: BLE001 - the row asserts THAT it refused, not how
        return True
    return False


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    _test_cron_minute_expansion(chk)
    _test_budget_arithmetic(chk)
    _test_floor_predicate(chk)
    _test_preflight_budget_predicate(chk)
    _test_spend_probe_repo(chk)
    _test_anchor_parsing(chk)
    _test_response_splitting(chk)
    _test_a_too_soon_tick_issues_no_snapshot_requests(chk)
    _test_an_unaffordable_tick_issues_no_snapshot_requests(chk)
    _test_live_path(chk)
    _test_workflow_seam(chk)

    print("dispatch-tick-floor self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _test_cron_minute_expansion(chk):
    """WHOSE definition of "which minutes does this cron fire at" (#1279).

    This file used to expand the minute field itself, and got a stepped RANGE wrong: it read the
    step and dropped the range's START. The one workflow it is applied to writes explicit minutes,
    so the wrong branch was never taken and the budget invariant below read a correct value out of
    a broken expander — which is why the rows here feed the SHAPES the live path does not, not
    just the one it does.

    Every row feeds a cron LITERAL rather than a parsed workflow, so this whole function runs
    without PyYAML and without a checkout of the lane whose cron it names."""
    def minutes(expr):
        return sorted(_cron_minutes({"on": {"schedule": [{"cron": expr}]}}))

    # THE DEFECT. `7-59/15` is groom-sweep.yml's live cron; the private copy this replaced answered
    # [0, 15, 30, 45], which shares NOT ONE minute with the truth — so this row cannot go green on
    # a re-introduced private expander, and the expected value is computed by hand rather than read
    # from the code under test.
    chk("cron: a stepped RANGE expands from the range's START, not from :00 (`7-59/15` is "
        "groom-sweep.yml's live cron; the private copy this replaced answered [0, 15, 30, 45])",
        minutes("7-59/15 * * * *"), [7, 22, 37, 52])
    # ...and the shapes that kept the defect latent still expand exactly as they always did.
    chk("cron: an explicit minute LIST is unchanged (dispatch.yml's own cron — the one shape the "
        "live path exercises, and the reason the defect was latent)",
        minutes("3,13,23,33,43,53 * * * *"), [3, 13, 23, 33, 43, 53])
    chk("cron: a bare step from :00 is unchanged", minutes("*/10 * * * *"),
        [0, 10, 20, 30, 40, 50])
    chk("cron: a single fixed minute is a single minute", minutes("41 6 * * 1"), [41])
    chk("cron: a range with no step expands to every minute in it", minutes("5-8 * * * *"),
        [5, 6, 7, 8])
    # THE REFUSAL PROBE ITSELF, first: every row below reads `_raised(...) is True`, so a probe
    # that could only ever answer True would satisfy all of them while proving nothing. This is the
    # one row that makes it able to say NO.
    chk("cron: the refusal probe answers False for a call that does NOT raise (a probe that cannot "
        "say no makes every refusal row below vacuous)",
        (_raised(lambda: minutes("3 * * * *")), _raised(lambda: 1 / 0)), (False, True))
    # THE REJECT DIRECTION, and it is load-bearing rather than tidy: `len(minutes) <=
    # ticks_per_hour` is vacuously TRUE for the empty set, so an expander that swallowed a cron it
    # could not read would turn the budget invariant green while asserting nothing at all.
    for label, expr in (("a non-numeric minute", "abc * * * *"),
                        ("an inverted range", "50-10 * * * *"),
                        ("a zero step", "*/0 * * * *"),
                        ("an empty minute field", ", * * * *"),
                        ("a cron with the wrong field count", "3,13 * * *")):
        chk(f"cron: {label} RAISES rather than expanding to nothing (an empty set satisfies the "
            "budget invariant vacuously)", _raised(lambda e=expr: minutes(e)), True)
    # THE PARTIALLY-invalid field, which the rows above cannot reach: they are all WHOLLY
    # unreadable, and an expander that merely DISCARDS what it cannot use refuses those anyway by
    # running out of values. This one keeps six perfectly good minutes — dispatch's own schedule,
    # exactly — beside a minute the hour does not have, so a discarding expander answers
    # `{3, 13, 23, 33, 43, 53}` and hands the budget row below the live cron's shape.
    # The row would go green on a workflow whose six claimed firings do not exist. :60
    # is used by no valid expansion anywhere in this suite, so this cannot pass by collision.
    chk("cron: a minute list that is valid EXCEPT for one impossible atom RAISES — discarding "
        "the :60 would answer with dispatch's own six minutes and confirm a schedule that never "
        "fires", _raised(lambda: minutes("3,13,23,33,43,53,60 * * * *")), True)
    chk("cron: a range whose END runs past :59 RAISES rather than being truncated to :59",
        _raised(lambda: minutes("55-70 * * * *")), True)
    # The one-cron-per-workflow contract this file's own consumer depends on, in both directions.
    chk("cron: a workflow with no schedule at all RAISES",
        _raised(lambda: _cron_minutes({"on": {"push": {}}})), True)
    chk("cron: a workflow with TWO crons RAISES — the consumer counts minutes PER HOUR, and "
        "reading only the first would under-count the schedule it is checked against",
        _raised(lambda: _cron_minutes(
            {"on": {"schedule": [{"cron": "3 * * * *"}, {"cron": "8 * * * *"}]}})), True)
    # THE REPORTING WRAPPER'S OWN FAILURE PATH, which is the pair the budget row reads. Nothing
    # else executes it — the tree under test is healthy, so `_scheduled_minutes` never takes its
    # `except` — and an unexecuted branch is an unkillable mutant (AGENTS.md pre-flight item 1): a
    # wrapper that swallowed the error and reported an EMPTY schedule would satisfy that row's
    # inequality while asserting nothing.
    reported, reported_error = _scheduled_minutes({"on": {"push": {}}})
    chk("cron: a derivation failure is REPORTED as (None, error), never swallowed into an empty "
        "schedule", (reported, isinstance(reported_error, TickFloorError)), (None, True))
    healthy, healthy_error = _scheduled_minutes({"on": {"schedule": [{"cron": "7-59/15 * * * *"}]}})
    chk("cron: ... and a derivation that WORKS reports no error alongside the expanded minutes",
        (sorted(healthy or ()), healthy_error), ([7, 22, 37, 52], None))
    # THE OWNERSHIP ITSELF. A checkout without the owner must RAISE: a fallback to a private copy
    # is how the second definition comes back, and it comes back green.
    chk("cron: the expansion is OWNED by ci-latency-alert.py, and a checkout without it RAISES "
        "instead of falling back to a private copy",
        (callable(getattr(_cron_minutes_module(), "cron_minutes", None)),
         _raised(lambda: _cron_minutes_module(os.path.join(_repo_root(), "no-such-tree")))),
        (True, True))
    # ...and the owner is checked out on the LIVE path, not merely present in this working copy.
    # Without this, the rows above pass in pr-gate and the floor job dies on its own self-test.
    chk("cron: ... and that owner is in the set the floor job is asserted to check out",
        CRON_MINUTES_SCRIPT in REQUIRED_FILES, True)


def _test_budget_arithmetic(chk):
    """The constant must keep agreeing with the reasoning that produced it. Every number here is
    measured (see the header); this asserts the MULTIPLICATION, so nobody can quietly halve the
    floor and leave the justification standing."""
    ticks_per_hour = 3600 / MIN_TICK_INTERVAL_SECONDS
    ceiling = ticks_per_hour * COLD_CACHE_REQUESTS_PER_TICK
    # [#2100] The post-GraphQL controls are a measured contract, not a cron tweak.
    # Keep the target values explicit so the old 15-minute/908-request model cannot
    # satisfy the new inequalities merely by changing both sides together.
    chk("budget: the post-GraphQL cadence and core admission price are pinned",
        (MIN_TICK_INTERVAL_SECONDS, COLD_CACHE_REQUESTS_PER_TICK), (10 * 60, 518))
    graphql_cost = globals().get("GRAPHQL_POINTS_PER_TICK")
    graphql_budget = globals().get("GRAPHQL_HOURLY_BUDGET")
    graphql_reserve = globals().get("GRAPHQL_RATE_LIMIT_RESERVE")
    chk("budget: six measured GraphQL ticks plus reserve fit the separate bucket",
        (graphql_cost, graphql_budget, graphql_reserve,
         isinstance(graphql_cost, int) and isinstance(graphql_budget, int)
         and isinstance(graphql_reserve, int)
         and ticks_per_hour * graphql_cost + graphql_reserve <= graphql_budget),
        (750, 5000, 100, True))
    chk("budget: the #2078 live plan is pinned as cap/cold-cost/admission-threshold",
        (WORKER_PR_STATUS_LIMIT, COLD_CACHE_REQUESTS_PER_TICK, budget_floor()),
        (150, 518, 618))
    chk("budget: the historical evidence remains measured history, not retuned live controls",
        (HISTORICAL_MEASURED_REQUESTS_PER_TICK, OBSERVED_SAFE_REQUESTS_PER_HOUR,
         OBSERVED_BREAKING_REQUESTS_PER_HOUR),
        (613, 4291, 7969))
    chk("budget: the floor admits at most 6 executed ticks/hour", ticks_per_hour, 6.0)
    chk("budget: 6 ticks/h x 518 requests = 3108 requests/h", ceiling, 3108.0)
    # The cost model, and the clamp that makes a floor derived from measurements stay valid as
    # the backlog moves. Without the clamp assertion, a growing backlog silently invalidates the
    # arithmetic above and a backlog spike becomes an outage trigger.
    chk("budget: the post-GraphQL model rounds the 139-worker live census upward with its fixed "
        "secondary-target slope", round(requests_per_tick(139, 29)), 460)
    chk("budget: the live 150-PR cap is priced at the conservative cold-cache ceiling",
        round(requests_per_tick(WORKER_PR_STATUS_LIMIT)), COLD_CACHE_REQUESTS_PER_TICK)
    chk("budget: per-tick cost is MONOTONE in the worker-PR count (a bigger backlog is a bigger "
        "tick — the floor is sized at the ceiling, not at today's backlog)",
        requests_per_tick(20) < requests_per_tick(60) < requests_per_tick(150), True)
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
            snapshot_source = handle.read()
        declared = re.search(
            r"^WORKER_PR_STATUS_LIMIT\s*=\s*(\d+)", snapshot_source, re.M)
        chk("budget: the clamp matches plan-snapshot.py's live WORKER_PR_STATUS_LIMIT",
            int(declared.group(1)) if declared else None, WORKER_PR_STATUS_LIMIT)
        graphql_reserve = re.search(
            r"^GRAPHQL_RATE_LIMIT_RESERVE\s*=\s*(\d+)", snapshot_source, re.M)
        chk("budget: the hourly GraphQL proof holds back the same reserve the live reader "
            "enforces from every response body",
            int(graphql_reserve.group(1)) if graphql_reserve else None,
            GRAPHQL_RATE_LIMIT_RESERVE)
    chk("budget: the ceiling is at or under the highest rate observed to run CLEAN "
        f"({OBSERVED_SAFE_REQUESTS_PER_HOUR}/h)", ceiling <= OBSERVED_SAFE_REQUESTS_PER_HOUR, True)
    chk("budget: the ceiling is at most half the rate that BROKE it "
        f"({OBSERVED_BREAKING_REQUESTS_PER_HOUR}/h)",
        ceiling <= OBSERVED_BREAKING_REQUESTS_PER_HOUR / 2, True)
    # The invariant the header states in words: the doorbell cannot outpace the schedule.
    workflow = _load_workflow(DISPATCH_WORKFLOW)
    try:
        manifest = json.loads((workflow.get("env") or {}).get("DISPATCH_TARGET_REPOS", ""))
    except (TypeError, json.JSONDecodeError):
        manifest = None
    chk("budget: the modeled target count matches dispatch.yml's live manifest",
        (len(manifest) if isinstance(manifest, list) else None,
         TARGET_REPOSITORY_COUNT, GRAPHQL_WORKER_PR_ALLOWANCE),
        (2, 2, 2 * WORKER_PR_STATUS_LIMIT))
    # DERIVED by the shared expander (#1279), and REPORTED rather than raised: this function runs
    # second in the suite, so a raise here would abort the nine that follow it.
    scheduled, cron_error = _scheduled_minutes(workflow)
    # The COUNT is pinned, not just the inequality. `len(scheduled) <= ticks_per_hour` is
    # vacuously true for the empty set, so on its own it cannot tell a derivation that read the
    # schedule from one that read nothing — and the expected value comes from
    # MIN_TICK_INTERVAL_SECONDS while the observed one comes from the YAML, so the row is not
    # comparing the file against itself. This IS the header's stated invariant: the floor admits
    # EXACTLY the rate the cron alone already schedules.
    chk("budget: the floor admits no more ticks/hour than the cron alone already schedules — and "
        "the schedule was actually DERIVED (an empty or unreadable derivation reds here rather "
        "than satisfying the inequality vacuously)",
        (cron_error, len(scheduled) if scheduled is not None else None,
         scheduled is not None and len(scheduled) <= ticks_per_hour),
        (None, int(ticks_per_hour), True))


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
        ((3600 // MIN_TICK_INTERVAL_SECONDS) * COLD_CACHE_REQUESTS_PER_TICK
         > SHARED_HOURLY_BUDGET // 2), True)
    chk("preflight: ... and the gate's threshold is a small fraction of that bucket, so the gate "
        "throttles dispatch rather than reserving the bucket for it",
        budget_floor() < SHARED_HOURLY_BUDGET // 4, True)


def _test_spend_probe_repo(chk):
    """Which repository the budget probe names (registry #1228).

    The failure mode being guarded is NOT "picks the wrong repo" — by measurement the split is by
    route, so any `/repos/...` lands on the same counter. It is "picks NOTHING and silently stops
    gating". An env var that can quietly disarm a rate limiter is the #1234 class, and this is the
    row that refuses it: every malformed manifest still yields a repo, because REGISTRY_REPO is
    always present in the floor step's own env."""
    reg = {"REGISTRY_REPO": "jeswr/agent-account-registry"}
    for label, environ, want in (
            ("the FIRST target of the manifest — the repo whose sweep dominates the spend",
             {**reg, "DISPATCH_TARGET_REPOS": '["sparq-org/sparq", "jeswr/agent-account-registry"]'},
             "sparq-org/sparq"),
            ("an ABSENT manifest falls back to the registry — still the spend bucket, so the "
             "gate stays ARMED rather than silently disabled",
             reg, "jeswr/agent-account-registry"),
            ("a malformed manifest (not JSON) falls back", {**reg, "DISPATCH_TARGET_REPOS": "{["},
             "jeswr/agent-account-registry"),
            ("a manifest that is not a list falls back",
             {**reg, "DISPATCH_TARGET_REPOS": '{"a": 1}'}, "jeswr/agent-account-registry"),
            ("an EMPTY manifest falls back", {**reg, "DISPATCH_TARGET_REPOS": "[]"},
             "jeswr/agent-account-registry"),
            # The grammar is a REQUEST-PATH guard, not tidiness: this value is interpolated into
            # `/repos/{entry}`, so a hostile or fat-fingered entry must never reach the wire.
            ("a non-string entry is skipped, not interpolated",
             {**reg, "DISPATCH_TARGET_REPOS": '[7, "o/r"]'}, "o/r"),
            ("an entry that is not owner/repo is skipped",
             {**reg, "DISPATCH_TARGET_REPOS": '["../../etc/passwd", "o/r"]'}, "o/r"),
            ("... including one carrying a query that would rewrite the request",
             {**reg, "DISPATCH_TARGET_REPOS": '["o/r?x=1", "o/r"]'}, "o/r"),
            ("... and one with a traversal segment", {**reg, "DISPATCH_TARGET_REPOS": '["o/../r"]'},
             "jeswr/agent-account-registry"),
            ("with NEITHER a usable manifest nor a usable REGISTRY_REPO there is no probe at all "
             "-> no evidence -> RUN (never a stall)", {"REGISTRY_REPO": "nope"}, None),
            ("and an empty environment likewise", {}, None),
    ):
        chk(f"spend-probe repo: {label}", spend_probe_repo(environ), want)
    # THE GRAMMAR IS THE WORKFLOW'S OWN. dispatch.yml's manifest step validates the same shape;
    # two copies that drift would let the floor probe a repo the manifest step would have refused.
    workflow = _require(DISPATCH_WORKFLOW)
    chk("spend-probe repo: the owner/repo grammar is the one dispatch.yml's manifest step "
        "enforces, character for character", _SAFE_REPO.pattern in workflow, True)


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
        snapshot_calls["n"] += COLD_CACHE_REQUESTS_PER_TICK
        budget["remaining"] -= COLD_CACHE_REQUESTS_PER_TICK
        return "executed"

    chk("unaffordable: a tick with a full budget executes", tick(), "executed")
    # Drain the bucket the way the other ~356 runs/h in the repository actually drain it.
    budget["remaining"] = 12
    clock["now"] += 20 * 60
    baseline = snapshot_calls["n"]
    chk("unaffordable: past the wall-clock floor but with an EMPTY bucket, the tick DEFERS",
        tick(), "noop-budget")
    chk("unaffordable: ... and it issued ZERO snapshot requests (it spent 1, not a cold tick)",
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
        snapshot_calls["n"] += COLD_CACHE_REQUESTS_PER_TICK  # PLAN's cold-cache ceiling
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
    chk("regression: ... i.e. at most 3108 snapshot requests in that hour",
        snapshot_calls["n"] <= 3108, True)


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
    # `-i` is still required, but for the PROBE's sake, not the anchor's: it is what makes any
    # response carry `x-ratelimit-*` at all. Drop it and the gate goes permanently fail-open.
    chk("live: ... requested with `-i`, which is what makes a response carry rate-limit headers "
        "at all", "-i" in calls[0], True)
    chk("live: it returns the marker's epoch", got, parse_rfc3339("2026-07-27T18:40:00Z"))
    chk("live: a REFUSED listing (the 403 outage itself) reads as no anchor -> RUN",
        read_anchor("o/r", runner=lambda *a, **k: (None, {}))[0], None)

    # ---- the SPEND-bucket probe (registry #1228) -------------------------------------------
    probe_calls = []

    def fake_probe(args, label="tick-floor"):
        probe_calls.append(args)
        return ({"default_branch": "master"},
                {"x-ratelimit-remaining": "41", "x-ratelimit-limit": "5000"})

    probe_headers = read_spend_budget("sparq-org/sparq", runner=fake_probe)
    chk("spend-probe: the budget probe is exactly ONE API request", len(probe_calls), 1)
    # THE POINT OF THE WHOLE CHANGE. `/actions/artifacts` and `/repos/{owner}/{repo}` are
    # different rate-limit buckets on this token — measured, same repository, 28 s apart, one at
    # 4643/5000 while the other was refused as spent. Point this row back at the artifacts route
    # and the gate is measuring the meter that never moved.
    chk("spend-probe: ... on the `/repos/{owner}/{repo}` route the tick actually SPENDS, not the "
        "`/actions/artifacts` route the anchor is listed on",
        (probe_calls[0][-1], "actions/artifacts" in probe_calls[0][-1]),
        ("/repos/sparq-org/sparq", False))
    chk("spend-probe: ... and it yields that bucket's remaining count",
        remaining_budget(probe_headers), 41)
    # Drop `-i` and the response carries no headers at all, so the gate reads `remaining is None`
    # and RUNS every tick — a silently disarmed rate limiter, green suite.
    chk("spend-probe: ... requested with `-i`, or the probe returns a body and no budget at all",
        "-i" in probe_calls[0], True)
    chk("spend-probe: a refusal that CARRIES remaining=0 hands the gate its evidence, so the tick "
        "defers instead of proceeding into a sweep that cannot finish (the #819 residual)",
        decide_budget(remaining_budget(read_spend_budget(
            "o/r", runner=lambda *a, **k: (None, {"x-ratelimit-remaining": "0"}))))[0], "hold")
    chk("spend-probe: an UNNAMEABLE probe repo issues NO request and proves NOTHING, so the tick "
        "RUNS — a rate limiter that cannot name a repo must not stall the pipeline",
        (read_spend_budget(None, runner=fake_probe), len(probe_calls),
         decide_budget(remaining_budget(read_spend_budget(None)))[0]), ({}, 1, "run"))

    # The workflow output contract, written the way GitHub reads it.
    #
    # THESE ROWS DRIVE THE REAL `main()`, SO THEIR OUTPUT MUST NOT ESCAPE THIS FUNCTION. The
    # workflow runs `--self-test` and the live floor in the SAME step (dispatch.yml), so anything
    # `main()` prints here lands in the job log, and a `::warning::` line lands in the Actions
    # ANNOTATIONS API, where a fixture is indistinguishable from a live deferral. That is not
    # hypothetical: the `x-ratelimit-remaining=12/5000` below was read off the annotations feed as
    # a live budget outage on 2026-07-29 and cost two separate wrong diagnoses — one of them
    # #1240, which was filed against `resets at unknown` when the LIVE responses carry
    # `x-ratelimit-reset` perfectly well (the fixture simply omits it).
    #
    # So stdout is CAPTURED and `GITHUB_STEP_SUMMARY` is redirected alongside `GITHUB_OUTPUT`.
    # Capturing alone would only hide the evidence, so each row now ASSERTS on what it captured:
    # the fixture output stays inside the test AND is checked, rather than escaping unchecked.
    import contextlib
    import io
    import tempfile
    spent = {"x-ratelimit-remaining": "12", "x-ratelimit-limit": "5000"}
    # Each row now pins TWO meters independently — the ARTIFACTS bucket the anchor is listed on
    # and the SPEND bucket the tick draws from (registry #1228). The last two rows are the whole
    # fix, and they are deliberately CONTRADICTORY pairs: a row where both meters agree cannot
    # tell which one `main()` read, which is exactly how the wrong one went unnoticed while the
    # gate fired 0 times against 16 budget deaths in 102 executed ticks.
    rows = (
        ("hold", 60, healthy, healthy, "proceed=false\n", "tick-floor: HOLD", ""),
        ("run", 4000, healthy, healthy, "proceed=true\n", "tick-floor: budget ok", ""),
        # THE DEFECT ITSELF. The artifacts bucket reads healthy — as it did on every one of the
        # 16 measured deaths — while the bucket PLAN is about to spend is empty. Read the anchor's
        # headers here (the pre-#1228 behaviour) and this row goes green while production dies.
        ("spend-bucket-empty-artifacts-bucket-healthy", 4000, healthy, spent,
         "proceed=false\n", "::warning::tick-floor: DEFER (budget)",
         "- `tick-floor` DEFER budget:"),
        # THE INVERSE, and the row that reds if anyone ever wires the gate back to the anchor
        # read: the artifacts bucket is empty and the spend bucket is fine, so the tick must RUN.
        # Without this row a "gate on whichever meter is lower" mutant would pass the row above.
        ("artifacts-bucket-empty-spend-bucket-healthy", 4000, spent, healthy,
         "proceed=true\n", "tick-floor: budget ok", ""),
    )
    # THE OUTER SENTINEL. Every row drives the real `main()` under its OWN redirect; this one
    # catches whatever a missing inner redirect would let through. Delete an inner redirect and
    # the last assertion in this function goes red, so the containment is tested, not just
    # performed. `chk` is called after the block closes, so its own output is never swallowed.
    leaked = io.StringIO()
    results = []
    with contextlib.redirect_stdout(leaked):
        for label, anchor, artifacts_budget, spend_budget, want, want_out, want_record in rows:
            with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as handle:
                out_path = handle.name
            with tempfile.NamedTemporaryFile("w+", suffix=".md", delete=False) as handle:
                summary_path = handle.name
            env_backup = {k: os.environ.get(k)
                          for k in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "REGISTRY_REPO",
                                    "DISPATCH_TARGET_REPOS")}
            captured = io.StringIO()
            routes = []
            try:
                os.environ["GITHUB_OUTPUT"] = out_path
                # Without this the fixture deferral appends to the RUN's real job summary — the
                # very surface #1208 made deferred ticks countable on — so every tick would
                # record a deferral it never took.
                os.environ["GITHUB_STEP_SUMMARY"] = summary_path
                os.environ["REGISTRY_REPO"] = "o/r"
                os.environ["DISPATCH_TARGET_REPOS"] = '["t/one", "t/two"]'
                stamp = datetime.fromtimestamp(_now() - anchor, tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ")
                saved = globals()["_gh_response"]

                def _routed(args, label="tick-floor", _a=artifacts_budget, _s=spend_budget,
                            _stamp=stamp, _seen=routes):
                    """A `gh` stub that answers PER ROUTE. The old stub returned one header set
                    for every request, so it could not distinguish the two buckets — and a fixture
                    that cannot express the defect cannot witness the fix."""
                    path = args[-1]
                    _seen.append(path)
                    if "actions/artifacts" in path:
                        return ({"artifacts": [{"name": TICK_MARKER_ARTIFACT,
                                                "created_at": _stamp}]}, _a)
                    return ({"default_branch": "master"}, _s)

                globals()["_gh_response"] = _routed
                try:
                    with contextlib.redirect_stdout(captured):
                        code = main()
                finally:
                    globals()["_gh_response"] = saved
                with open(out_path, encoding="utf-8") as handle:
                    written = handle.read()
                with open(summary_path, encoding="utf-8") as handle:
                    recorded = handle.read()
            finally:
                for key, value in env_backup.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
                os.unlink(out_path)
                os.unlink(summary_path)
            results.append((label, want, want_out, want_record, code, written,
                            captured.getvalue(), recorded, routes))

    for label, want, want_out, want_record, code, written, said, recorded, routes in results:
        # REQUEST COUNT IS PART OF THE CONTRACT. A wall-clock hold must still cost exactly the
        # ONE anchor read it always did — the probe is only worth its request on a tick that is
        # otherwise about to sweep — and an admitted tick costs exactly two, never a third.
        chk(f"live: a {label} tick issues the expected requests, in order",
            routes,
            ["/repos/o/r/actions/artifacts"
             f"?name={TICK_MARKER_ARTIFACT}&per_page={ARTIFACT_PAGE_SIZE}"]
            + ([] if label == "hold" else ["/repos/t/one"]))
        chk(f"live: a {label} tick exits 0 and writes {want.strip()!r}", (code, written),
            (0, want))
        # The captured output is ASSERTED, not merely swallowed — a redirect that hid a silent
        # `main()` would otherwise turn this whole block green for the wrong reason.
        chk(f"live: ... and a {label} tick still SAYS so ({want_out!r}), into the capture rather "
            "than into the live job's log and annotations", want_out in said, True)
        # `_record` stays under test, but writes to the FIXTURE summary. Only the deferral records.
        chk(f"live: ... and a {label} tick records {want_record or '(nothing)'!r} to the FIXTURE "
            "step summary, never the run's own",
            recorded[:len(want_record)] if want_record else recorded, want_record)

    chk("live: driving main() through the fixture rows emits NOTHING on this process's own stdout "
        "— the workflow runs `--self-test` in the SAME step as the live floor, so a leaked "
        "`::warning::` becomes an annotation indistinguishable from a real budget deferral (#1240)",
        leaked.getvalue(), "")


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

    # --- #1208: EVERY job that must obey `proceed`, same three directions -------------------
    # A held tick that still pays for GUARD's authenticated settings reads is spending the bucket
    # the hold exists to protect. Measured: 41 rings/h, 5 dispatches, 69% of executable ticks
    # budget-deferred — each deferred ring paid GUARD anyway. Delete either half of that job's
    # gate and one of these three rows goes red.
    for job_name in GATED_JOBS:
        chk(f"seam[#1208]: `{job_name}` runs when the floor says proceed",
            _gated_job_runs(workflow, job_name, "true"), True)
        chk(f"seam[#1208]: `{job_name}` does NOT run when the floor says hold (delete the `if:` "
            "or cut the `needs:` edge and this goes red)",
            _gated_job_runs(workflow, job_name, "false"), False)
        chk(f"seam[#1208]: `{job_name}` does NOT run when the floor emits NOTHING",
            _gated_job_runs(workflow, job_name, ""), False)
    # ...and the list is not vacuous. A `GATED_JOBS` quietly trimmed back to `("plan",)` would make
    # every row above pass while GUARD went back to paying on every deferred ring.
    chk("seam[#1208]: the gated-job list still names BOTH halves of a tick's fixed cost",
        tuple(sorted(GATED_JOBS)), ("plan", "secrets-guard"))
    # THE SAFETY DIRECTION, which is the reason gating a fail-closed guard is admissible at all:
    # a SKIPPED guard must not admit any job the guard exists to gate.
    #
    # `claim` is modelled here because it carries NO `if:` — GitHub's implicit needs-must-succeed,
    # which a skipped dependency fails. `plan-alert` is NOT modelled here on purpose: its
    # `always() && needs.secrets-guard.result == 'success'` is outside this harness's deliberately
    # restricted grammar, and the owner of that polarity question is
    # dispatch-secrets-guard.if_condition_admits — which already answers it for EVERY non-success
    # result, `skipped` included, over the live file (guard_gate_verdict property 3, plus the
    # explicit skipped-guard row in that module's self-test). Re-deciding it here with a substring
    # test is exactly the vacuous shape #621 caught: an `||` satisfies a substring test and inverts
    # the gate.
    claim = _job(workflow, "claim")
    assert "secrets-guard" in _declared_needs(claim), "claim must need secrets-guard"
    chk("seam[#2103]: CLAIM keeps the measured three-floor-interval timeout while later "
        "doorbells coalesce behind the registry-dispatcher concurrency group",
        claim.get("timeout-minutes"), CLAIM_TIMEOUT_MINUTES)
    chk("seam[#1208]: `claim` carries NO job-level `if:`, so a SKIPPED guard skips it via the "
        "implicit needs-must-succeed gate — gating the guard on the floor can only ever skip "
        "MORE, never admit more", claim.get("if"), None)

    # --- the floor job's own shape ----------------------------------------------------------
    chk("seam: the floor job exposes `proceed` as a job output",
        (floor.get("outputs") or {}).get("proceed"),
        "${{ steps.%s.outputs.proceed }}" % FLOOR_STEP_ID)
    chk("seam: the floor job holds exactly {actions:read, contents:read} — actions:read is what "
        "lets it LIST the marker artifacts, and nothing else is needed",
        floor.get("permissions"), {"actions": "read", "contents": "read"})
    # A JOB-LEVEL `if:` ON THE FLOOR ITSELF. Measured survivor of this file's own mutation battery
    # (2026-07-29) and the class sparq#5080 names: every wiring pin above asserts what the GATED
    # jobs do with the floor's ANSWER, and not one of them notices the floor never being asked.
    # `if: false` here skips the floor, so `proceed` is the empty string and the rows above stay
    # green while the rate limiter is gone. The floor is unconditional by design — it is the thing
    # that decides whether a tick happens, so nothing may decide whether IT happens.
    chk("seam: the floor job carries NO job-level `if:` — a wiring pin cannot see a gate that was "
        "never evaluated (sparq#5080), and `if: false` here disables the rate limiter with every "
        "other seam row still passing", floor.get("if"), None)
    # `continue-on-error` discards exactly the exit status that would report a broken floor, and a
    # step can never red its own neutering — so something ELSE has to assert its absence.
    chk("seam: no truthy `continue-on-error` at the floor job or step level",
        [floor.get("continue-on-error")] + [s.get("continue-on-error") for s in _steps(floor)],
        [None] * (1 + len(_steps(floor))))

    # [#1228] THE MANIFEST REACHES THE FLOOR PROCESS ONLY BY WORKFLOW-LEVEL `env:` INHERITANCE.
    # The floor step does not name `DISPATCH_TARGET_REPOS`, so if it were moved down into a single
    # job's `env:` the probe would silently fall back to REGISTRY_REPO. The gate would stay ARMED
    # and correct — the split is by route, so both repos are the same counter — but the hedge that
    # keeps it correct under a FINER partition would be gone, with every row still green. This is
    # the only thing asserting that it is still inherited.
    chk("seam[#1228]: the target manifest is workflow-level `env:`, so the floor process inherits "
        "it and the budget probe can name the target whose sweep dominates the spend",
        isinstance(workflow.get("env"), dict)
        and "DISPATCH_TARGET_REPOS" in workflow["env"], True)

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
