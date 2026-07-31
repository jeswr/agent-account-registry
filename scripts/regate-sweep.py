#!/usr/bin/env python3
# [OPUS-5] RE-QUALIFY THE PRs A MASTER-SIDE GATE FIX ALREADY UNBLOCKED (issue #927).
#
# WHAT BROKE, MEASURED. #910 (#888's SIGPIPE scanner matching its own definition line in
# worker-live.sh) made `pr-gate` fail for reasons unrelated to any PR under test. At its worst the
# registry ran 3 of 3 red and merged ZERO PRs in 58 minutes. #917 repaired it on `master` at
# 2026-07-28T02:26:49Z — and repaired NOTHING already open. Immediately after that merge, 7 of 37
# open PRs still carried a red `gate` whose newest run predated the fix:
#
#     #903 02:09:30Z   #923 02:26:13Z   #895 01:46:46Z   #893 01:36:20Z
#     #886 01:06:32Z   #856 01:00:06Z   #92  07-18 (a SEPARATE cause — see the control below)
#
# Six were moved onto the fixed base by hand and all six went green. The population was blocked by
# a bug that had already been fixed, and would have stayed blocked until a human touched each one.
#
# WHY `gh run rerun` CANNOT DO THIS, and why this script moves branches instead. Re-running the
# failed workflow re-tests the SAME TREE: `refs/pull/N/merge` is not recomputed when the base moves
# (registry #920), and the heads above read `behind_by=1, status=diverged` against #917's merge
# commit while their reruns were queued. The fix was simply not present in what was being graded.
# The head itself has to move onto a base containing the fix, so this issues `update-branch`.
#
# ---------------------------------------------------------------------------------------------
# THE ATTRIBUTION TEST — the whole safety argument, and the one thing not to loosen
# ---------------------------------------------------------------------------------------------
# "Red before, green after, on a tree that changed" is NOT attribution. A base move changes many
# things at once, so that predicate is satisfied by every red PR on the board and turns this into
# "rebase everything", which burns CI and HIDES a genuine failure behind a fresh run.
#
# A PR is attributable to repair R iff ALL of:
#
#   (a) its newest `gate` check-run concluded `failure`                     [newest-run resolution]
#   (b) that run completed BEFORE R merged to master                        [the failure predates R]
#   (c) the PR head does NOT contain R's merge commit                       [the fix was provably
#                                                                            absent from the graded
#                                                                            tree — the behind_by
#                                                                            reading from #927]
#   (d) the failing self-test harness is the one R declares it repairs
#   (e) EVERY per-assertion failure in that run's log is one R declares it repairs   [EXCLUSIVITY]
#
# (e) is what makes the sweeper safe, and it is the clause a careless generalisation drops. A PR
# red on its own merits fails at some assertion A that R does not repair, so A is unexplained and
# the PR is REFUSED (`own-merits`) — it stays red, which is the correct outcome. (a)-(c) alone
# would have churned #92 and #856; (e) is why they are not touched.
#
# The residual, stated honestly: the pr-gate suite loop runs under `set -e`, so it aborts at the
# FIRST failing harness. If a PR fails a declared signature in harness H and also fails, on its own
# merits, in a harness that runs strictly after H, the later failure is not in the log and cannot
# be seen here. That PR is moved — and its fresh gate then goes red on its own failure and it stays
# blocked. The cost is one CI run; there is no path to a false green, because THIS SCRIPT NEVER
# ARMS ANYTHING. And that PR genuinely was also blocked by R, so the move was owed to it anyway.
#
# WHAT A "SIGNATURE" IS, and why it cannot be a substring search. Every enrolled self-test prints
# one line per failed assertion; the dominant form is `  FAIL <name>: <got> (want <want>)`. But the
# same suite prints `ok` lines that QUOTE failure text verbatim — the run this was built from has
# 30+ passing lines containing the word FAILED. A substring grep for a signature therefore matches
# passing assertions, which is the exact false-positive shape that has bitten this estate before
# (the `VERDICT: pass` grep). Extraction here is LINE-ANCHORED at `^\s*FAIL[: ]`, and a declared
# signature matches a failure line only as its full body or as an exact `<signature>:` prefix.
#
# THE ACCOUNTING GUARD, and why "no unexplained failures" is not vacuous. "Every failure is
# explained" is trivially true if the extractor simply saw no failures. So a log is only READ as
# evidence when its accounting closes: exactly one `<harness> self-test FAILED` roll-up, that
# harness matching the last `== self-test X ==` header the runner printed, at least one extracted
# failure line, and — for the harnesses that print a count — the extracted count equalling the
# declared one. Anything else is `unreconciled-log` and is REFUSED. A self-test that died by
# exception prints no roll-up at all and is refused on exactly this clause.
#
# THE COUNT CLAUSE IS EXACT, NOT ADVISORY, and that is a property of the harnesses rather than of
# this parser. `worker-live.sh`'s `chk` runs EVERY assertion and increments an exact counter, so the
# roll-up's number is the true failure count for that harness; and any `die` or `set -e` abort
# terminates before the roll-up prints, so a truncated run cannot present a self-consistent
# accounting. Together those mean a log which reconciles cannot be hiding a failure from that
# harness — five candidate shapes were tried against it and none closes while concealing one.
#
# WHY THE DECLARATION IS A CHECKED-IN FILE. `orchestration/gate-repairs.json` names, per repair,
# the assertion signatures that repair fixes. It lives on master and reaches this script only
# through review + merge, so a pull request cannot declare itself attributable. The sweeper reads
# it from the checked-out DEFAULT BRANCH, never from a PR tree.
#
# ---------------------------------------------------------------------------------------------
# WHAT IT DOES NOT DO: ARM
# ---------------------------------------------------------------------------------------------
# Moving the head INVALIDATES any review verdict bound to the old head. This script's job ends at
# "a fresh gate is running on a fresh head". It routes for re-review rather than preserving a
# verdict it cannot re-derive: on a successful move it removes `review:pass` and records, in a
# comment, why the reviewer's finding about the COMPOSITION is unaffected by a base move while the
# SHA the verdict named no longer exists. It never arms, never merges, and never adds an arming
# label — three writes exist in total and none of them is an arm.
#
# WHAT REMOVING `review:pass` IS AND IS NOT. It is DE-AUTHORISATION, not DISARMING. The real arming
# primitive is `enablePullRequestAutoMerge`, whose `expectedHeadOid` is a compare-and-swap evaluated
# AT ARM TIME; once auto-merge is latched the intent is held independently and the label is never
# re-read. So dropping the label withdraws consent from any FUTURE arm decision and does NOT retract
# an existing one: an already-armed PR that this sweeper moves WILL merge on its fresh green. An
# earlier revision of this header called the label "the single label that authorises arming" in a
# way that read as a disarm. It is not one.
#
# THAT CASE IS ACCEPTED DELIBERATELY, and this script does not call `--disable-auto`. Reasons:
# (1) THE LOAD-BEARING ONE — the green it merges on is FRESH, computed against a base containing the
# repair, which is the inverse of #940's stale-green hazard; (2) it is what the six hand-moves of
# #927 did and what the maintainer recorded as the procedure — substance still applies, a fresh
# green is still required; (3) disarming has its own failure mode, because nothing re-arms a PR
# whose deliberate arm this stripped, converting a transient red into a stall needing a human.
#
# ⚠️ A FOURTH REASON WAS WITHDRAWN AS FALSE. It read "a base move adds no author commits, so the
# diff the reviewer approved is byte-identical". Measured over four `git merge` cases: a DIFFERENT
# file gives a byte-identical diff; a SAME-FILE NON-OVERLAPPING change does NOT — blob ids differ
# and hunk headers shift (`@@ -6,5` -> `@@ -7,5`) with content unchanged; a SEMANTIC conflict can be
# byte-identical while the merged tree BEHAVES differently; a true conflict 422s into `move-failed`.
# So the reviewer's approval is evidence about the OLD base and only the fresh gate speaks for the
# new one. The decision stands on reason (1) alone, which is where it always actually rested. The
# claim also shipped inside LATCHED_ARM_NOTE, i.e. onto other people's PRs — which is why it is
# withdrawn outright rather than softened.
#
# What the script owes instead is VISIBILITY: a latched arm is detected, counted in the census as
# `latched-arm=N`, and named in the PR comment, so the merge that follows is never a surprise. If
# the trade is ever rejected the change is small and local — one auto-merge-off call in `_act` plus
# a census field — not a redesign.
#
# HOW THIS COMPOSES WITH #940 (landed as #950, commit c37705ff9). #940 is the DEFENSIVE half: at
# arm time, refuse a green `gate` that
# was computed against a tree that no longer exists. This is the RECOVERY half: regenerate the
# evidence for the tree that does exist. They are the two directions of one property — a gate
# result is evidence about a TREE, not about a PR. #940 refuses stale evidence; this manufactures
# fresh evidence for the population #940 would otherwise leave permanently refused. Neither
# subsumes the other: without #940 a stale green still merges; without this, a stale red still
# blocks forever. They share no code and no state, and this script's verdict invalidation is the
# review-side analogue of #940's gate-side staleness check.
#
# ---------------------------------------------------------------------------------------------
# THE CAP, IN WALL-CLOCK
# ---------------------------------------------------------------------------------------------
# A cap stated only as "N per tick" is an unbounded stall in disguise. The arithmetic, explicitly,
# and asserted by _test_drain_arithmetic:
#
#     cap 5 moves/tick x 3 ticks/hour (TICKS_PER_HOUR, asserted against the workflow's own
#         cron — the minutes themselves are NOT restated here, see #1046) = 15 PRs/hour of drain
#     the measured class size was 7 -> fully drained in 2 ticks, i.e. <= 40 min worst case
#     the outage it clears was measured at 58 min with zero merges
#
# So the cap cannot be the binding constraint at the measured class size, and if the class ever
# exceeds it the `deferred-cap` census bucket says so on every tick it holds. The cap exists at all
# because each move fires one `pr-gate` run: over-dispatching pushes saturates the runners and
# manufactures the very red gates this is trying to clear.
#
# WHY CRON AND NOT A PUSH TRIGGER. No workflow in this repository triggers on `push`, and this is
# not the change that should introduce the first one. Polling re-derives the whole class from the
# repairs file every tick, so it is idempotent, self-healing across a missed edge, and cannot be
# desynchronised by a merge that happened while the runner was busy. The cost is <= 20 min of
# latency against a 58 min outage.
#
# TOKEN, and the one wiring mistake that would make this a silent no-op. The branch move MUST be
# authenticated with the registry App token, NOT `github.token`: a push made with a workflow's own
# GITHUB_TOKEN does not trigger `pull_request` workflows, so `pr-gate` would never re-run and every
# swept PR would sit on a fresh head with a stale red check forever. _test_workflow_seam asserts
# the live step's GH_TOKEN is the App-token output.
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

REPAIRS_FILE = "orchestration/gate-repairs.json"
SWEEP_WORKFLOW = ".github/workflows/regate-sweep.yml"
SUITE_MANIFEST = "scripts/selftest-suite.txt"

# The required status check. Branch protection requires exactly this context, and it is the same
# name dispatch-claim.py reads as CI_GATE_CHECK.
GATE_CHECK = "gate"

# The registry's default branch. sparq is `main`; this repo is `master`, and mixing them up has
# cost this estate a scripted outage before — so it is pinned, asserted against the workflow's own
# trigger, and RE-DERIVED against the live repository at run time (a drift fails closed).
DEFAULT_BRANCH = "master"

# See "THE CAP, IN WALL-CLOCK" above. Both halves of the arithmetic are asserted.
MAX_MOVES_PER_TICK = 5
TICKS_PER_HOUR = 3

# A repair older than this is inert: its class has either drained or is red for another reason, and
# Actions logs do not live forever. Bounds the per-tick cost as the declaration file grows.
REPAIR_LOOKBACK_HOURS = 24

# update-branch returns 202 (queued), so the ref lags the call. Bounded confirmation poll.
HEAD_CONFIRM_ATTEMPTS = 3
HEAD_CONFIRM_INTERVAL_SECONDS = 2.0

MARKER = "<!-- regate-sweep repair={repair} head={head} -->"
MARKER_RE = re.compile(r"<!-- regate-sweep repair=(\d+) head=([0-9a-f]{7,40}) -->")

# The label that authorises arming. A head move invalidates the verdict that earned it.
REVIEW_PASS_LABEL = "review:pass"

SELF_ID = "> \N{ROBOT FACE} **SPARQ agent** \N{EM DASH} regate-sweep"

# The ONE definition of "which minute is taken by which registry cron" (#1046). It is DERIVED
# from the tree by ci-latency-alert.py's `schedule_minute_map`, which is why this script has to
# read that script and the whole workflows directory: the collision assertion below reads every
# other lane's own schedule instead of a list somebody wrote down here and stopped updating.
WORKFLOWS_DIR = ".github/workflows"
CRON_MAP_SCRIPT = "scripts/ci-latency-alert.py"

# Every file the self-test asserts against. The sweep job sparse-checks-out exactly this set plus
# REQUIRED_DIRS, and _test_workflow_seam asserts that it does: a trimmed checkout would make the
# YAML-seam assertions unreachable on the live path while still passing in pr-gate.
REQUIRED_FILES = (
    "scripts/regate-sweep.py",
    REPAIRS_FILE,
    SUITE_MANIFEST,
    SWEEP_WORKFLOW,
    CRON_MAP_SCRIPT,
)

# Directories the self-test asserts against, held separately because they are checked out and
# verified as DIRECTORIES. `.github/workflows/regate-sweep.yml` is a substring of this entry, so
# a containment check would pass with the directory dropped — and dropping it is precisely what
# makes the derived cron map read one lane instead of thirteen (ci-latency-alert.py measured that
# same mutant surviving a containment check). Exact, per-line membership only.
REQUIRED_DIRS = (WORKFLOWS_DIR,)


class RegateSweepError(Exception):
    """A contract this script refuses to guess about."""


# =============================================================================================
# pure: the repair declaration
# =============================================================================================
def load_repairs(text):
    """Parse + VALIDATE orchestration/gate-repairs.json. -> list of records, RAISES on any defect.

    Fail-closed on shape: a malformed declaration must red pr-gate, not silently sweep nothing (an
    inert sweeper is the invisible version of the outage it exists to end)."""
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise RegateSweepError(f"{REPAIRS_FILE} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise RegateSweepError(f"{REPAIRS_FILE} must be an object with \"schema\": 1")
    repairs = document.get("repairs")
    if not isinstance(repairs, list):
        raise RegateSweepError(f"{REPAIRS_FILE}: \"repairs\" must be a list")
    seen = set()
    for record in repairs:
        if not isinstance(record, dict):
            raise RegateSweepError(f"{REPAIRS_FILE}: every repair must be an object")
        number = record.get("repair_pr")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise RegateSweepError(
                f"{REPAIRS_FILE}: repair_pr must be a positive int, got {number!r}")
        if number in seen:
            raise RegateSweepError(f"{REPAIRS_FILE}: repair_pr {number} declared twice")
        seen.add(number)
        harness = record.get("harness")
        if not isinstance(harness, str) or not harness.strip() or harness != harness.strip():
            raise RegateSweepError(
                f"{REPAIRS_FILE}: repair {number} needs a non-empty, unpadded `harness`")
        signatures = record.get("signatures")
        if not isinstance(signatures, list) or not signatures:
            raise RegateSweepError(
                f"{REPAIRS_FILE}: repair {number} must declare at least one signature — a repair "
                "that explains nothing can only ever sweep by accident")
        for signature in signatures:
            if not isinstance(signature, str) or not signature.strip():
                raise RegateSweepError(
                    f"{REPAIRS_FILE}: repair {number} has an empty signature")
            if signature != signature.strip() or "\n" in signature:
                raise RegateSweepError(
                    f"{REPAIRS_FILE}: repair {number} signature {signature!r} must be a single "
                    "unpadded line — it is matched against one log line")
        if not isinstance(record.get("why"), str) or not record["why"].strip():
            raise RegateSweepError(
                f"{REPAIRS_FILE}: repair {number} must say WHY these signatures are attributable")
    return repairs


def repair_window(detail, now, lookback_hours=REPAIR_LOOKBACK_HOURS):
    """Is a declared repair LIVE this tick? -> (ok, reason).

    `detail` is the repair PR as GitHub reports it. Every clause is a fact about the repair, not
    about any PR under test: an undeclarable repair must disqualify its whole class at once rather
    than being re-litigated per candidate."""
    if not isinstance(detail, dict):
        return False, "repair-unreadable"
    if not detail.get("merged_at"):
        return False, "repair-not-merged"
    if (detail.get("base") or {}).get("ref") != DEFAULT_BRANCH:
        return False, "repair-not-on-default-branch"
    if not detail.get("merge_commit_sha"):
        return False, "repair-has-no-merge-commit"
    merged = parse_rfc3339(detail["merged_at"])
    if merged is None:
        return False, "repair-unreadable"
    if now - merged > lookback_hours * 3600:
        return False, "repair-outside-lookback"
    if merged > now:
        return False, "repair-unreadable"
    return True, "live"


def parse_rfc3339(raw):
    """GitHub's `2026-07-28T02:26:49Z` -> epoch int, or None for anything else."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        stamp = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(stamp.timestamp())


# =============================================================================================
# pure: newest-run resolution (registry #920 / sparq #3677)
# =============================================================================================
def newest_gate(check_runs):
    """The NEWEST check-run named `gate` for a head. -> the run, or None.

    A head accumulates a check-run per re-run and per superseded wave. Reading any but the newest
    is how a resolved failure keeps blocking and a superseded one keeps being believed. Unparseable
    timestamps rank below every parseable one, so garbage can only ever LOSE."""
    best = None
    best_key = None
    for run in check_runs or []:
        if not isinstance(run, dict) or run.get("name") != GATE_CHECK:
            continue
        started = parse_rfc3339(run.get("started_at"))
        key = ((1, started) if started is not None else (0, 0), run.get("id") or 0)
        if best_key is None or key > best_key:
            best, best_key = run, key
    return best


def gate_run_id(run):
    """The Actions JOB id behind a `gate` check-run, from its details_url. -> int or None."""
    match = re.search(r"/job/(\d+)\b", str((run or {}).get("details_url") or ""))
    return int(match.group(1)) if match else None


# =============================================================================================
# pure: the failure ledger
# =============================================================================================
_TIMESTAMP = re.compile(r"^﻿?\d{4}-\d\d-\d\dT[\d:.]+Z ?")

# LINE-ANCHORED. `FAIL` must open the line (the suite indents assertion lines by two spaces) and be
# followed by `:` or whitespace. A substring search cannot be used: the same logs carry dozens of
# PASSING `ok` lines that quote failure text verbatim.
_FAIL_LINE = re.compile(r"^[ \t]*FAIL:?[ \t]+(?P<body>\S.*?)[ \t]*$")

# The four roll-up spellings the enrolled suite actually uses:
#   `worker-live self-test FAILED (1 failure(s))`   `groom self-test FAILED`
#   `mint-provenance self-test: PASS`               `triage-stock-alert self-test: FAILED a, b`
# An unmodelled spelling yields no roll-up and the log is refused as unreconciled, which is the
# safe direction: this harness never guesses at an accounting it cannot read.
_ROLLUP = re.compile(
    r"^(?P<harness>[A-Za-z0-9][A-Za-z0-9._-]*) self-test:?[ \t]+"
    r"(?P<verdict>PASSED|FAILED|PASS|FAIL)"
    r"(?:[ \t]+\((?P<count>\d+) failure\(s\)\))?"
    r"(?P<tail>[ \t].*)?$")

_SUITE_HEADER = re.compile(r"^== self-test (?P<entry>\S+) ==$")


class FailureLedger:
    """What a failed `gate` log PROVES about which assertions failed.

    `reason is None` means the accounting CLOSES and the ledger may be used as evidence. Any other
    value is a refusal: the ledger is unusable and the PR is not swept. There is deliberately no
    third state — a ledger that is "probably complete" is the shape that makes an exclusivity check
    vacuous, because "no unexplained failures" is trivially true of failures nobody extracted."""

    __slots__ = ("harness", "fails", "reason")

    def __init__(self, harness, fails, reason):
        self.harness = harness
        self.fails = tuple(fails)
        self.reason = reason

    def __repr__(self):
        return f"FailureLedger(harness={self.harness!r}, fails={self.fails!r}, " \
               f"reason={self.reason!r})"

    def __eq__(self, other):
        return (isinstance(other, FailureLedger) and self.harness == other.harness
                and self.fails == other.fails and self.reason == other.reason)


def failure_ledger(log_text):
    """Parse a `gate` job log into a FailureLedger. PURE.

    Reconciliation, all four clauses fail-closed:
      1. exactly one FAILED roll-up (the suite runs under `set -e`, so at most one harness aborts);
      2. at least one extracted `FAIL` line;
      3. the roll-up's harness matches the last `== self-test X ==` header the runner printed —
         which is what ties the accounting to the harness that actually stopped the loop;
      4. when the roll-up declares a failure COUNT, it equals the number of extracted lines."""
    if not isinstance(log_text, str) or not log_text.strip():
        return FailureLedger(None, (), "log-unavailable")
    fails = []
    failed_rollups = []
    last_header = None
    for raw in log_text.splitlines():
        line = _TIMESTAMP.sub("", raw).rstrip("\r")
        header = _SUITE_HEADER.match(line)
        if header:
            last_header = header.group("entry")
            continue
        rollup = _ROLLUP.match(line)
        if rollup:
            if rollup.group("verdict") in ("FAILED", "FAIL"):
                failed_rollups.append((rollup.group("harness"), rollup.group("count")))
            continue
        hit = _FAIL_LINE.match(line)
        if hit:
            fails.append(hit.group("body"))
    if len(failed_rollups) != 1:
        return FailureLedger(None, tuple(fails), "unreconciled-log")
    harness, declared = failed_rollups[0]
    if not fails:
        return FailureLedger(harness, (), "unreconciled-log")
    if last_header is None or not last_header.startswith(harness):
        return FailureLedger(harness, tuple(fails), "unreconciled-log")
    if declared is not None and int(declared) != len(fails):
        return FailureLedger(harness, tuple(fails), "unreconciled-log")
    return FailureLedger(harness, tuple(fails), None)


def signature_matches(body, signature):
    """Does a declared signature name THIS failure line? PURE, and deliberately not a substring
    test. The whole body, or the body up to the harness's `<name>: <got> (want <want>)` separator.
    `sig + ":"` is what stops `the guard fires` from claiming `the guard fires twice: ...`."""
    return body == signature or body.startswith(signature + ":")


def explained_by(ledger, harness, signatures):
    """Is EVERY failure in a reconciled ledger one this repair declares? -> (bool, reason).

    The exclusivity clause. `own-merits` is the refusal that keeps a genuinely-red PR red."""
    if ledger.reason is not None:
        return False, ledger.reason
    if not str(ledger.harness or "").strip() or not str(harness).startswith(ledger.harness):
        return False, "wrong-harness"
    for body in ledger.fails:
        if not any(signature_matches(body, signature) for signature in signatures):
            return False, "own-merits"
    return True, "attributable"


# =============================================================================================
# pure: the attribution test
# =============================================================================================
# Ordered cheapest-first. The FIRST clause a PR fails is its census bucket, so the buckets are
# mutually exclusive by construction and every scanned PR lands in exactly one.
def attribute(pr, repo, gate, repair_merged_at, contains_repair, ledger, repair):
    """The full attribution test for ONE pr against ONE repair. -> a census bucket name.

    `"attributable"` is the only admitting value. `gate`, `contains_repair` and `ledger` are the
    results of the progressively more expensive reads; passing them in keeps this pure and keeps
    the ordering — and therefore the mutual exclusivity of the buckets — testable."""
    if ((pr.get("head") or {}).get("repo") or {}).get("full_name") != repo:
        return "fork"
    if gate is None:
        return "no-gate-run"
    if gate.get("status") != "completed":
        return "gate-running"
    if gate.get("conclusion") != "failure":
        return "gate-not-red"
    completed = parse_rfc3339(gate.get("completed_at"))
    if completed is None or completed >= repair_merged_at:
        return "failure-postdates-repair"
    if contains_repair:
        return "already-contains-fix"
    ok, reason = explained_by(ledger, repair["harness"], repair["signatures"])
    return "attributable" if ok else reason


def plan_moves(attributable, cap=MAX_MOVES_PER_TICK):
    """Bound the tick. -> (moves, deferred). Ascending PR number: deterministic, so a tick is
    reproducible and the deferred tail is the SAME tail next tick rather than a fresh lottery."""
    if cap < 0:
        raise RegateSweepError("move cap must not be negative")
    ordered = sorted(attributable)
    return ordered[:cap], ordered[cap:]


# =============================================================================================
# census
# =============================================================================================
# Every scanned PR leaves through exactly one of these. Enumerated rather than accumulated so that
# a new exit cannot be added without also being counted — a sweep that silently skips is the class
# this estate has found repeatedly, and `actions=0 errors=0` is what both a clean board and a
# silently-starved one print.
BUCKETS = (
    "moved",
    "deferred-cap",
    "move-failed",
    "already-swept",
    "fork",
    "no-gate-run",
    "gate-running",
    "gate-not-red",
    "failure-postdates-repair",
    "already-contains-fix",
    # A read this tick could not complete (the containment compare, or the marker listing). NOT the
    # same state as "the log said nothing usable", and naming them alike would let a listing outage
    # masquerade in the census as a population that was examined and found unattributable.
    "read-failed",
    "log-unavailable",
    "unreconciled-log",
    "wrong-harness",
    "own-merits",
)

# The buckets whose members PASSED the attribution test. Everything else was refused before it.
ATTRIBUTABLE_BUCKETS = ("moved", "deferred-cap", "move-failed", "already-swept")


def seal_population(accounted, population):
    """Assert that every scanned PR left the sweep through exactly one COUNTED exit. Returns None,
    or RAISES (registry #776's invariant, same reasoning).

    It raises rather than returning a reason, deliberately: a `reason = check(...)` / `if reason:
    raise` shape has a seam between deciding and acting, and a mutation run over this estate proved
    that seam is where vacuity lives. There is no seam to delete when the decision and the raise
    are the same statement."""
    if accounted == population:
        return None
    raise RegateSweepError(
        f"regate-sweep accounting is unsealed: {accounted} counted outcome(s) for a population of "
        f"{population} open pull request(s) — some PR left the sweep through an uncounted exit")


def census_line(repair, scanned, counts, confirmed=None, latched_arms=0,
                latched_unknown=0):
    """The one line this emits every tick it holds. A silent sweeper turns a visible 58-minute
    outage into an invisible one, so the class size is reported even when nothing was moved."""
    attributable = sum(counts.get(name, 0) for name in ATTRIBUTABLE_BUCKETS)
    refused = {name: counts.get(name, 0) for name in BUCKETS
               if name not in ATTRIBUTABLE_BUCKETS and counts.get(name, 0)}
    fields = [
        f"repair={repair}",
        f"scanned={scanned}",
        f"class={attributable}",
        f"moved={counts.get('moved', 0)}",
        f"deferred-cap={counts.get('deferred-cap', 0)}",
        f"move-failed={counts.get('move-failed', 0)}",
        f"already-swept={counts.get('already-swept', 0)}",
        f"refused={sum(refused.values())}",
    ]
    if confirmed is not None:
        fields.append(f"head-confirmed={confirmed}/{counts.get('moved', 0)}")
    # NOT a bucket — a moved PR is already counted under `moved`. This is a property OF the moved
    # set: how many carried an auto-merge that the head move did not retract and will therefore
    # merge on the fresh green. Silence here would make that merge look unattended.
    fields.append(f"latched-arm={latched_arms}")
    if latched_unknown:
        fields.append(f"latched-arm-unknown={latched_unknown}")
    fields.append("refusals=" + (",".join(f"{k}:{v}" for k, v in sorted(refused.items())) or "-"))
    return "CENSUS " + " ".join(fields)


def repair_census_line(repair, reason):
    """A declared repair that is not live this tick still gets a row: an entry that quietly stops
    being evaluated is how a declaration file rots into decoration."""
    return f"CENSUS repair={repair} scanned=0 class=0 skipped={reason}"


# =============================================================================================
# live path
# =============================================================================================
# ⚠️ THE RUNNER IS THE ONLY THING BETWEEN THIS SCRIPT AND LIVE PULL REQUESTS, AND THE IN-PROCESS
# DOUBLE CANNOT SEE PAST IT. `_gh(args)` with no runner shells out to the REAL `gh`; the request
# never reaches the double at all, so every "no path arms" assertion in this file is silent about
# it. MEASURED: injecting `_gh(["pr","merge",str(number),"-R",self.repo])` — the same idiom minus
# `self.runner` — at the real call site in `_act` issued 17 real `gh pr merge` invocations against
# PRs #903/#895/#893/#886/#856 while this suite reported 202/202 PASSED. The self-test's fixtures
# name those real open registry PR numbers on purpose (they are #927's board, kept so the replay is
# the incident), and the sweep job's self-test step carries a token with `pull-requests: write`.
#
# So the sentinel sits OUTSIDE the runner seam: while `--self-test` runs, the runner-less branch is
# REFUSED instead of executed. A write that forgets its runner then reds by name — through
# `_run_total`/`_main_total` — instead of shelling out at live PR numbers. Asserted in BOTH
# directions in `_test_live_gh_sentinel`: armed, the call raises and reaches no process; disarmed,
# that identical call is what invokes `gh`, so this guards a live path and not a dead branch.
LIVE_GH_UNDER_SELF_TEST = (
    "regate-sweep: a runner-less `gh` request was issued while --self-test is running")
_LIVE_GH_FORBIDDEN = False


def forbid_live_gh(active=True):
    """Arm (or disarm) the runner-less-`gh` sentinel. -> the PREVIOUS state, so it can be restored.

    Not a constant, because `_test_live_gh_sentinel` has to disarm it to prove the branch it guards
    is real; a guard whose OFF state is never exercised is indistinguishable from dead code."""
    global _LIVE_GH_FORBIDDEN
    previous = _LIVE_GH_FORBIDDEN
    _LIVE_GH_FORBIDDEN = bool(active)
    return previous


def _gh(args, runner=None):
    """Run `gh <args>` -> (rc, stdout).

    Raises only for the self-test sentinel above — a runner-less request under `--self-test` is a
    test that has lost its double, and refusing it loudly is the whole point. On the live path it
    never raises.

    Sanitized: only the subcommand words and the return code are ever printed. `GH_DEBUG=api`
    echoes request bodies into stderr, so stderr is never surfaced."""
    if runner is not None:
        return runner(args)
    if _LIVE_GH_FORBIDDEN:
        raise RegateSweepError(
            f"{LIVE_GH_UNDER_SELF_TEST}: gh {' '.join(str(a) for a in args)}")
    result = subprocess.run(["gh"] + list(args), capture_output=True, text=True, check=False)
    return result.returncode, result.stdout or ""


def _gh_json(args, runner=None, label="regate-sweep"):
    rc, out = _gh(args, runner)
    if rc != 0:
        print(f"::warning::{label}: gh {args[0]} failed (rc={rc})")
        return None
    try:
        return json.loads(out or "null")
    except ValueError:
        print(f"::warning::{label}: gh {args[0]} returned unparseable JSON")
        return None


def api_path(repo, tail):
    return f"/repos/{repo}{tail}"


def read_open_pulls(repo, runner=None):
    payload = _gh_json(["api", "--paginate",
                        api_path(repo, "/pulls?state=open&per_page=100")], runner)
    return payload if isinstance(payload, list) else None


def read_gate(repo, head_sha, runner=None):
    payload = _gh_json(
        ["api", api_path(repo, f"/commits/{head_sha}/check-runs"
                               f"?check_name={GATE_CHECK}&per_page=100")], runner)
    return newest_gate((payload or {}).get("check_runs") if isinstance(payload, dict) else None)


def head_contains(repo, base_sha, head_sha, runner=None):
    """Does `head_sha` contain `base_sha`? -> True/False/None(unreadable).

    This is the `behind_by=1, status=diverged` reading from #927, asked authoritatively. `ahead`
    and `identical` are the two states in which the graded tree DID contain the fix."""
    payload = _gh_json(["api", api_path(repo, f"/compare/{base_sha}...{head_sha}")], runner)
    if not isinstance(payload, dict) or "status" not in payload:
        return None
    return payload["status"] in ("ahead", "identical")


def read_job_log(repo, job_id, runner=None):
    """The `gate` job log. -> text on success, None when the REQUEST failed.

    The two are different census states and were briefly conflated. A failed request is
    `read-failed` (this tick could not ask); a request that succeeds and yields nothing, or a
    check-run whose job cannot be located at all, is `log-unavailable` (there is nothing to read —
    typically an expired retention window). Collapsing them lets an API outage read, in the census,
    as a population that was examined and found unattributable."""
    rc, out = _gh(["api", api_path(repo, f"/actions/jobs/{job_id}/logs")], runner)
    if rc != 0:
        print(f"::warning::regate-sweep: log request for job {job_id} failed (rc={rc})")
        return None
    return out


def marker_author_admitted(comment, bot_login):
    """Is this comment's marker one THIS sweeper wrote? PURE.

    Markers are only counted when SELF-AUTHORED (the pattern resolve-conflicts.py established): an
    unrestricted marker scan is a DENIAL OF RECOVERY — anyone able to comment could pin a PR out of
    the class permanently by pasting the marker.

    With no known bot login the polarity flips to trusting every marker, and that is deliberate: a
    marker this function cannot attribute is at worst a MISSED move (safe, retried next tick once
    the identity is known), whereas ignoring it is a REPEATED move against a head already updated.
    Fail-closed here means declining to act, not acting on unverified provenance."""
    if not bot_login:
        return True
    return str(((comment or {}).get("user") or {}).get("login") or "") == bot_login


def already_swept(repo, number, repair, bot_login="", runner=None):
    """Has THIS repair already moved THIS PR? -> True/False/None(unreadable).

    The durable idempotence key is a self-authored HTML marker on the PR, not a state file. Three
    other conditions also converge on skipping a swept PR — the head now contains the fix, its
    newest gate postdates the repair, and that gate is no longer red — but all three depend on
    GitHub having ALREADY processed a 202-queued update, and this one does not."""
    payload = _gh_json(
        ["api", "--paginate", api_path(repo, f"/issues/{number}/comments?per_page=100")], runner)
    if not isinstance(payload, list):
        return None
    for comment in payload:
        if not marker_author_admitted(comment, bot_login):
            continue
        for match in MARKER_RE.finditer(str((comment or {}).get("body") or "")):
            if int(match.group(1)) == repair:
                return True
    return False


def move_branch(repo, number, head_sha, runner=None):
    """`update-branch` the PR onto its base. -> True on acceptance.

    `expected_head_sha` makes the write CONDITIONAL: an author push that lands between the read and
    this call rejects the update instead of silently discarding their commit."""
    rc, _ = _gh(["api", "--method", "PUT", api_path(repo, f"/pulls/{number}/update-branch"),
                 "-f", f"expected_head_sha={head_sha}"], runner)
    if rc != 0:
        print(f"::warning::regate-sweep: update-branch refused for #{number} (rc={rc}) — the head "
              "raced, the branch conflicts with its base, or the token cannot push to it")
        return False
    return True


def confirm_head_moved(repo, branch, old_sha, runner=None, sleeper=time.sleep):
    """Re-read the head AUTHORITATIVELY after a move. -> True/False.

    The PR object lags: reading `pulls/N` back immediately returns the OLD sha and reads as a
    no-op (#927 nearly recorded exactly that conclusion). The git ref is the authoritative copy.
    update-branch answers 202/queued, so this poll is bounded and an unconfirmed move is reported,
    not retried — the marker already prevents a second request."""
    for attempt in range(HEAD_CONFIRM_ATTEMPTS):
        payload = _gh_json(["api", api_path(repo, f"/git/ref/heads/{branch}")], runner)
        current = ((payload or {}).get("object") or {}).get("sha")
        if isinstance(current, str) and current != old_sha:
            return True
        if attempt + 1 < HEAD_CONFIRM_ATTEMPTS:
            sleeper(HEAD_CONFIRM_INTERVAL_SECONDS)
    return False


# ⚠️ THIS TEXT IS POSTED ONTO OTHER PEOPLE'S PULL REQUESTS, so every clause has to be true. An
# earlier revision claimed "a base move adds no author commits, so the approved diff is
# byte-identical". Re-measured here: with a same-file NON-OVERLAPPING change the hunk header shifts
# (`@@ -5,4` -> `@@ -6,4`) and the blob id changes (fcaed2f1 -> c8b58bc0) though the content is
# identical; and a textually clean merge can still change how the tree behaves. Withdrawn outright
# rather than softened — a wrong justification published on someone else's PR is worse than none.
LATCHED_ARM_NOTE = (
    "\n\n**This PR already had auto-merge armed, and moving the head did NOT retract that.** "
    "`review:pass` is consulted when DECIDING to arm; `enablePullRequestAutoMerge` holds the intent "
    "independently once latched, so this PR will merge when the fresh `gate` goes green.\n\n"
    "That is deliberate, and it rests on ONE claim: **the green it merges on is fresh** — computed "
    "against a base that contains the repair, which is the inverse of the stale-green hazard in "
    "#940. It is also what the six hand-moves in #927 did.\n\n"
    "It deliberately does NOT rest on the change being unaltered by the move. A base move can shift "
    "hunk headers and blob ids even when content is identical, and a textually clean merge can "
    "still change how the tree behaves — so **a prior approval is evidence about the old base, and "
    "only the fresh gate speaks for the new one**. If that is not enough for this PR, disarm it: "
    "the sweeper deliberately does not, because nothing would re-arm a PR whose owner's arm it "
    "stripped. Counted as `latched-arm` in this tick's census.")


# ⚠️ THE SAME WITHDRAWAL APPLIES TO THE ANNOTATION, and for two rounds it did not. The clause
# "the diff is unchanged" — measured false above and struck from the note — kept shipping to the
# operator from an inline f-string in `_act`, three lines above the note that withdraws it, because
# the guard scanned `LATCHED_ARM_NOTE` and nothing else. A guard that names ONE artifact defends
# that artifact, not the CLAIM. So the annotation is a named constant too, and the guard now scans
# the REAL captured output of a latched-arm tick plus the body it posts, which covers text nobody
# remembered to enrol.
LATCHED_ARM_WARNING = (
    "::warning::regate-sweep: #{number} had auto-merge ALREADY latched — removing `{label}` "
    "de-authorises a FUTURE arm decision but does not retract this one, so it will merge on the "
    "fresh gate. Deliberate, and it rests on one claim: the green it merges on is fresh — computed "
    "against a base that contains the repair. It is NOT a claim about what the move did to the "
    "approved diff; see the note posted on the PR. Censused as latched-arm.")

# The clauses measured FALSE and withdrawn. Scanned over everything a tick publishes, not over one
# constant — see `_test_live_sweep`. Adding a phrase here is cheap; the point is that the SURFACE
# the guard scans is derived from a real run, so it does not need to be complete to be sound.
WITHDRAWN_DIFF_CLAIMS = ("byte-identical", "diff is unchanged", "no author commits",
                         "identical diff", "the approved diff is unchanged")


def sweep_comment(repair, repair_pr_merged_at, gate_completed_at, old_sha, fails,
                  latched_arm=False):
    quoted = "\n".join(f"    FAIL {body}" for body in fails)
    return (
        f"{SELF_ID}\n\n"
        f"`gate` on `{old_sha[:9]}` failed at {gate_completed_at}, before #{repair} landed on "
        f"`{DEFAULT_BRANCH}` at {repair_pr_merged_at}. Every assertion that failed is one #"
        f"{repair} repairs:\n\n"
        f"{quoted}\n\n"
        f"`gh run rerun` cannot clear this: it re-tests the same tree, because GitHub does not "
        f"recompute a stale merge ref (registry #920). So this branch has been moved onto a base "
        f"that contains the fix, and a fresh `gate` is now running against the new head.\n\n"
        f"**This is not an arm, and it invalidates any review verdict bound to `{old_sha[:9]}`.** "
        f"A reviewer's finding about this PR's own composition is not changed by a base move, but "
        f"the verdict named a head that no longer exists — so this PR needs a verdict bound to the "
        f"NEW head as well as a green gate before it can merge. `review:pass` has been removed if "
        f"it was present. (registry #927; the arm-time half of this problem is #940.)"
        + (LATCHED_ARM_NOTE if latched_arm else "")
        + f"\n\n{MARKER.format(repair=repair, head=old_sha)}")


def post_comment(repo, number, body, runner=None):
    rc, _ = _gh(["api", "--method", "POST", api_path(repo, f"/issues/{number}/comments"),
                 "-f", f"body={body}"], runner)
    if rc != 0:
        print(f"::warning::regate-sweep: could not comment on #{number} (rc={rc})")
    return rc == 0


def drop_review_pass(repo, number, labels, runner=None):
    """Remove the arming label if the PR carries it. -> True when a write was issued.

    Scoped to exactly one label. This script must never make a PR MORE armable, and a head it moved
    is a head no verdict has seen."""
    if REVIEW_PASS_LABEL not in labels:
        return False
    rc, _ = _gh(["api", "--method", "DELETE",
                 api_path(repo, f"/issues/{number}/labels/{REVIEW_PASS_LABEL}")], runner)
    if rc != 0:
        print(f"::error::regate-sweep: could not remove {REVIEW_PASS_LABEL} from #{number} "
              f"(rc={rc}) — a moved head still carrying an arming label is exactly the stale-green "
              "hazard of #940")
    return True


def latched_arm_state(pr):
    """Is auto-merge already latched on this PR? -> True / False / None(unknown). PURE.

    `pr.get("auto_merge")` alone conflates "the API says not armed" with "the field is not in this
    payload at all", and consuming that default would make the whole latched-arm visibility control
    quietly vacuous — the field would just stop being reported and nothing would say so. So absence
    is a THIRD state, and it is censused as such."""
    if not isinstance(pr, dict) or "auto_merge" not in pr:
        return None
    return bool(pr["auto_merge"])


def label_names(pr):
    return [str((label or {}).get("name") or "") for label in (pr.get("labels") or [])]


class Sweeper:
    """One tick. `apply=False` classifies and censuses without issuing a single write."""

    def __init__(self, repo, repairs, runner=None, apply=False, cap=MAX_MOVES_PER_TICK,
                 lookback_hours=REPAIR_LOOKBACK_HOURS, clock=None, sleeper=time.sleep,
                 summary_path=None, bot_login=""):
        self.repo = repo
        self.repairs = repairs
        self.runner = runner
        self.apply = apply
        self.cap = cap
        self.lookback_hours = lookback_hours
        self.clock = clock or (lambda: int(datetime.now(tz=timezone.utc).timestamp()))
        self.sleeper = sleeper
        self.summary_path = summary_path
        self.bot_login = bot_login
        self.errors = 0
        self.latched_arms = 0
        self.latched_unknown = 0
        self.rows = []
        self.budget_used = 0

    # -- reads, each overridable in tests via `runner` ------------------------------------------
    def _repair_detail(self, number):
        return _gh_json(["api", api_path(self.repo, f"/pulls/{number}")], self.runner)

    def run(self):
        default_branch = self._default_branch()
        if default_branch != DEFAULT_BRANCH:
            raise RegateSweepError(
                f"{self.repo} reports default branch {default_branch!r}, but this sweeper is "
                f"pinned to {DEFAULT_BRANCH!r}. Refusing to move branches onto a base it cannot "
                "name — re-derive DEFAULT_BRANCH and the workflow trigger together.")
        pulls = read_open_pulls(self.repo, self.runner)
        if pulls is None:
            self.errors += 1
            print("::error::regate-sweep: could not list open pull requests — nothing was swept")
            return 1
        # A tick with NOTHING declared must still say so. An empty declaration file is the exact
        # silent-inert state #927 is about: a sweeper that prints nothing is indistinguishable from
        # a sweeper that is not running, and that is how a 58-minute outage becomes invisible.
        if not self.repairs:
            self.rows.append(f"CENSUS repair=none scanned={len(pulls)} class=0 "
                             f"skipped=no-declared-repairs")
            print(self.rows[-1])
        for repair in self.repairs:
            self._sweep_one(repair, pulls)
        self._publish()
        return 1 if self.errors else 0

    def _default_branch(self):
        payload = _gh_json(["api", api_path(self.repo, "")], self.runner)
        return (payload or {}).get("default_branch")

    def _sweep_one(self, repair, pulls):
        number = repair["repair_pr"]
        detail = self._repair_detail(number)
        live, reason = repair_window(detail, self.clock(), self.lookback_hours)
        if not live:
            self.rows.append(repair_census_line(number, reason))
            print(self.rows[-1])
            return
        merged_at = detail["merged_at"]
        merged_epoch = parse_rfc3339(merged_at)
        merge_sha = detail["merge_commit_sha"]
        counts = {name: 0 for name in BUCKETS}
        attributable = {}
        for pr in pulls:
            bucket, ledger, gate = self._classify(pr, repair, merged_epoch, merge_sha)
            if bucket == "attributable":
                attributable[pr["number"]] = (pr, ledger, gate)
            else:
                counts[bucket] += 1
        moves, deferred = plan_moves(list(attributable), max(0, self.cap - self.budget_used))
        counts["deferred-cap"] += len(deferred)
        confirmed = 0
        for pr_number in moves:
            pr, ledger, gate = attributable[pr_number]
            outcome, was_confirmed = self._act(pr, repair, merged_at, ledger, gate)
            counts[outcome] += 1
            confirmed += 1 if was_confirmed else 0
        seal_population(sum(counts.values()), len(pulls))
        self.rows.append(census_line(number, len(pulls), counts,
                                     confirmed if self.apply else None,
                                     latched_arms=self.latched_arms,
                                     latched_unknown=self.latched_unknown))
        print(self.rows[-1])

    def _classify(self, pr, repair, merged_epoch, merge_sha):
        """-> (bucket, ledger, gate). Reads escalate in cost only as cheaper clauses admit, and
        the bucket is always whatever `attribute` decides on the inputs read so far — so the
        ordering that makes the buckets mutually exclusive lives in ONE place."""
        head = (pr.get("head") or {}).get("sha") or ""
        empty = FailureLedger(None, (), "log-unavailable")
        bucket = attribute(pr, self.repo, None, merged_epoch, False, empty, repair)
        if bucket == "fork":
            return bucket, empty, None
        gate = read_gate(self.repo, head, self.runner)
        bucket = attribute(pr, self.repo, gate, merged_epoch, False, empty, repair)
        if bucket in ("no-gate-run", "gate-running", "gate-not-red", "failure-postdates-repair"):
            return bucket, empty, gate
        contains = head_contains(self.repo, merge_sha, head, self.runner)
        if contains is None:
            return "read-failed", empty, gate
        if contains:
            return "already-contains-fix", empty, gate
        job_id = gate_run_id(gate)
        log = read_job_log(self.repo, job_id, self.runner) if job_id else ""
        if log is None:
            return "read-failed", empty, gate
        ledger = failure_ledger(log)
        bucket = attribute(pr, self.repo, gate, merged_epoch, contains, ledger, repair)
        if bucket != "attributable":
            return bucket, ledger, gate
        swept = already_swept(self.repo, pr["number"], repair["repair_pr"], self.bot_login,
                              self.runner)
        if swept is None:
            return "read-failed", ledger, gate
        return ("already-swept" if swept else "attributable"), ledger, gate

    def _act(self, pr, repair, merged_at, ledger, gate):
        number = pr["number"]
        head = (pr.get("head") or {}).get("sha")
        branch = (pr.get("head") or {}).get("ref")
        if not self.apply:
            print(f"regate-sweep: DRY-RUN would move #{number} ({head[:9]}) onto "
                  f"{DEFAULT_BRANCH} for repair #{repair['repair_pr']}")
            self.budget_used += 1
            return "moved", False
        self.budget_used += 1
        if not move_branch(self.repo, number, head, self.runner):
            self.errors += 1
            return "move-failed", False
        latched = latched_arm_state(pr)
        if latched is None:
            self.latched_unknown += 1
            print(f"::warning::regate-sweep: #{number} carries no `auto_merge` field, so whether "
                  "this move leaves a latched arm in place CANNOT be determined — censused as "
                  "latched-arm-unknown rather than counted as unarmed")
        if latched:
            self.latched_arms += 1
            print(LATCHED_ARM_WARNING.format(number=number, label=REVIEW_PASS_LABEL))
        post_comment(self.repo, number,
                     sweep_comment(repair["repair_pr"], merged_at,
                                   (gate or {}).get("completed_at") or "an unrecorded time",
                                   head, ledger.fails, latched_arm=latched), self.runner)
        drop_review_pass(self.repo, number, label_names(pr), self.runner)
        confirmed = confirm_head_moved(self.repo, branch, head, self.runner, self.sleeper)
        if not confirmed:
            print(f"::warning::regate-sweep: #{number} accepted the update but its ref still "
                  f"reads {head[:9]} — update-branch answers 202/queued, so this is expected to "
                  "settle; the marker prevents a second request either way")
        return "moved", confirmed

    def _publish(self):
        if not self.summary_path:
            return
        try:
            with open(self.summary_path, "a", encoding="utf-8") as handle:
                handle.write("### regate-sweep census\n\n")
                for row in self.rows:
                    handle.write(f"    {row}\n")
                handle.write("\n")
        except OSError as exc:
            print(f"::warning::regate-sweep: step summary not written ({exc})")


def _coverage_canary_never_called():
    """DELIBERATELY UNREACHABLE. A coverage instrument that reports this at anything but 0% is
    attributing lines it should not, and one that reports EVERYTHING at 0% has measured nothing —
    both failures look like a clean report. scripts/../cover.py refuses to print numbers unless it
    separates this from a function the self-test certainly runs. Three instruments on this estate
    failed toward "nothing to report"; this is the cheapest way to notice."""
    unreachable = "this line must never execute"
    return unreachable.upper()


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _require(path):
    """Read a file this script asserts against. FAIL CLOSED: a missing input aborts loudly rather
    than making the assertions that read it quietly unreachable."""
    full = os.path.join(_repo_root(), path)
    if not os.path.isfile(full):
        raise RegateSweepError(
            f"input {path} is missing from the working copy at {_repo_root()} — the assertions "
            "that read it cannot run, and a self-test that silently stops asserting is worse than "
            "no self-test. Add it to the job's sparse-checkout list.")
    with open(full, encoding="utf-8") as handle:
        return handle.read()


def _require_dir(path):
    """`_require` for a DIRECTORY input. Same fail-closed contract: a self-test that quietly
    stops asserting is worse than no self-test."""
    full = os.path.join(_repo_root(), path)
    if not os.path.isdir(full):
        raise RegateSweepError(
            f"input directory {path} is missing from the working copy at {_repo_root()} — the "
            "assertions that read it cannot run. Add it to the job's sparse-checkout list.")
    return full


def _cron_map_module(root=None):
    """Load the single derived definition of the registry cron-minute map (#1046).

    Lazily, and only from the self-test: the live sweep never needs it, so a sweep tick carries
    no new import. Same importlib idiom as mint-provenance.py / backfill-provenance.py."""
    import importlib.util

    base = _repo_root() if root is None else root
    path = os.path.join(base, CRON_MAP_SCRIPT)
    if not os.path.isfile(path):
        raise RegateSweepError(
            f"{CRON_MAP_SCRIPT} is missing from the working copy at {base} — it owns the derived "
            "cron-minute map, and without it the collision assertion cannot run.")
    spec = importlib.util.spec_from_file_location("registry_cron_map", path)
    if spec is None or spec.loader is None:
        raise RegateSweepError(f"cannot load {CRON_MAP_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _derived_schedule_map(root=None):
    """-> (module, {workflow: minutes}, error). The derived cron-minute map, REPORTING instead
    of raising.

    It is read at the TOP of the YAML seam, and a raise there would abort the ~40 assertions
    below it — one mutant masking the rest, the shape this file's mutation run already flagged
    on the cron. Reporting is NOT failing open: an unloadable module or an unreadable tree comes
    back as ({}, error) and the caller's floor assertion reds on it."""
    root = _repo_root() if root is None else root
    try:
        module = _cron_map_module(root)
        return module, module.schedule_minute_map(root), None
    except Exception as exc:  # noqa: BLE001 - ANY derivation failure must red, never abort
        return None, {}, exc


def cron_collisions(minutes, others):
    """-> {workflow: [minutes shared]} for every OTHER lane this cron lands on top of.

    Pure, so the seam test can feed it the real derived map and the fixture test can feed it a
    map it wrote. NOTE it reports {} for an EMPTY `others` — a clean bill from this function is
    only meaningful once the caller has established the map actually saw the tree, which is what
    the lane-count floor in the seam test is for."""
    mine = set(minutes)
    return {name: sorted(mine & set(taken)) for name, taken in sorted(others.items())
            if mine & set(taken)}


def main(argv=None, runner=None, clock=None):
    """The CLI entry point. `runner` and `clock` exist so the self-test can exercise THIS function.

    `clock` exists for the same reason, and for a defect the `runner` injection did not cover
    [OPUS-5]. Every OTHER Sweeper in the suite is built with `clock=lambda: NOW`; this one was
    built by `main()`, which passed no clock, so the entry-point assertions compared a fixture
    `merged_at` against the REAL wall clock. `REPAIR_DETAIL`'s stamp is 24h + a few minutes before
    the failure, so the row passed for exactly one day and then went red on EVERY branch at once —
    a whole-repository merge lock authored by a test, at a time nobody chose. `None` keeps the
    production default (Sweeper's own real clock), so this parameter cannot change what a live
    sweep does.

    It was at 0% line coverage until a coverage run said so: the CLI-flag gate proves each flag is
    DECLARED, not that it is wired, so a typo in the slug validation, in the `[bot]` login the
    marker scan depends on, or in the repairs-file read would have passed the whole suite and failed
    only in production.

    ⚠️ `clock` is the SECOND injected environment input, and the SAME KIND of seam as `runner` —
    added for the same reason `_pinned_env` exists. The self-test's repair fixture is merged at a
    FIXED instant (`REPAIR_DETAIL["merged_at"]`), and `Sweeper` defaults to the wall clock, so
    every assertion routed through here silently inherited the calendar. That made them decaying
    tests: inside `REPAIR_LOOKBACK_HOURS` of the fixture date they passed, and a day later the same
    code put every repair `repair-outside-lookback` — which turned the `--bot-slug` wiring row RED
    (reddening the required gate for every PR at a time nobody chose) and turned the three rows
    that expect NO write VACUOUSLY green, for the wrong reason: nothing was swept at all. A
    time-bomb in one direction and vacuity in the other, from one unstated input. Passing `None`
    (every production call) keeps the real wall clock, so this parameter cannot change a live
    sweep."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true",
                        help="run the in-file test suite and exit")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"),
                        help="owner/name of the repository to sweep")
    parser.add_argument("--repairs-file", default=REPAIRS_FILE,
                        help=f"path to the repair declarations (default {REPAIRS_FILE})")
    parser.add_argument("--max-moves", type=int, default=MAX_MOVES_PER_TICK,
                        help="cap on branch moves per tick")
    parser.add_argument("--lookback-hours", type=float, default=REPAIR_LOOKBACK_HOURS,
                        help="how long a declared repair stays live")
    parser.add_argument("--bot-slug", default=os.environ.get("APP_SLUG", ""),
                        help="GitHub App slug this sweeper posts as; markers by any other author "
                             "are ignored so a spoofed marker cannot pin a PR out of the class")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="issue writes (default: dry-run)")
    mode.add_argument("--dry-run", action="store_true", help="classify and census only")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.repo:
        parser.error("--repo (or GITHUB_REPOSITORY) is required")
    if args.max_moves < 0:
        parser.error("--max-moves must not be negative")
    with open(args.repairs_file, encoding="utf-8") as handle:
        repairs = load_repairs(handle.read())
    if args.bot_slug and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.bot_slug):
        parser.error("--bot-slug must be a safe GitHub App slug")
    sweeper = Sweeper(args.repo, repairs, runner=runner, apply=args.apply, cap=args.max_moves,
                      lookback_hours=args.lookback_hours, clock=clock,
                      bot_login=f"{args.bot_slug}[bot]" if args.bot_slug else "",
                      summary_path=os.environ.get("GITHUB_STEP_SUMMARY") or None)
    return sweeper.run()


# =============================================================================================
# self-test
# =============================================================================================
def _self_test():
    ok = True
    # ⚠️ ARMED FOR THE WHOLE SUITE. Every request must go through an injected runner; a runner-less
    # `_gh` here is a test that lost its double, and the fixtures name REAL open PR numbers. See
    # `LIVE_GH_UNDER_SELF_TEST`. Restored on the way out so `main()` is not left poisoned for a
    # caller that imports this module.
    previously_forbidden = forbid_live_gh(True)

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    try:
        _run_suite(chk)
    finally:
        forbid_live_gh(previously_forbidden)

    print("regate-sweep self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _run_suite(chk):
    _test_live_gh_sentinel(chk)
    _test_drain_arithmetic(chk)
    _test_failure_ledger(chk)
    _test_signature_matching(chk)
    _test_attribution(chk)
    _test_cap_and_ordering(chk)
    _test_repairs_declaration(chk)
    _test_live_sweep(chk)
    _test_entry_point(chk)
    _test_published_census(chk)
    _test_abort_guards(chk)
    _test_census(chk)
    _test_cron_collisions(chk)
    _test_workflow_seam(chk)


def _test_live_gh_sentinel(chk):
    """The runner-less `gh` escape hatch, asserted in BOTH directions.

    ⚠️ `subprocess.run` is patched for the WHOLE of this function, including the armed direction.
    Deleting the sentinel from `_gh` must red — it must NOT execute `gh pr merge 903` against a live
    PR from inside the very test that certifies it cannot happen. The armed check therefore asserts
    the recorder saw NOTHING as well as that the call raised: 'it raised' alone would also be
    satisfied by a crash on the way to the same live write."""
    import subprocess as sp

    seen = []

    class _Completed:
        returncode = 7
        stdout = "recorded"
        stderr = ""

    def recorder(cmd, **_kwargs):
        seen.append(list(cmd))
        return _Completed()

    real_run = sp.run
    was_forbidden = _LIVE_GH_FORBIDDEN
    sp.run = recorder
    try:
        # ⚠️ `was_forbidden`, NOT the live global, and read BEFORE this function arms anything.
        # Asserting the flag after a local `forbid_live_gh(True)` would be true of a suite whose
        # entry point never armed it — the control would then certify only itself.
        chk("self-test sentinel: `_self_test` ARMED it for the whole suite — the fixtures name "
            "REAL open registry PRs and the sweep job's self-test step holds a `pull-requests: "
            "write` token", was_forbidden, True)
        forbid_live_gh(True)
        escaped = _raises(lambda: _gh(["pr", "merge", "903", "-R",
                                       "jeswr/agent-account-registry"]))
        chk("self-test sentinel: a request that FORGETS its runner raises by name and reaches no "
            "process at all — measured, this exact idiom issued 17 live `gh pr merge` calls "
            "against #903/#895/#893/#886/#856 on a 202/202 green suite",
            (type(escaped).__name__, LIVE_GH_UNDER_SELF_TEST in str(escaped), seen),
            ("RegateSweepError", True, []))
        forbid_live_gh(False)
        chk("self-test sentinel: DISARMED, that identical call is what invokes the real `gh`, and "
            "its rc/stdout are passed through — so the sentinel guards a LIVE branch, not a dead "
            "one, and this is the only assertion that executes it",
            (_gh(["pr", "merge", "903"]), seen), ((7, "recorded"), [["gh", "pr", "merge", "903"]]))
        chk("self-test sentinel: an injected runner is honoured in BOTH states, so arming it "
            "cannot quietly break the suite's own request path",
            (_gh(["api", "/x"], runner=lambda a: (0, "via-runner")), seen[-1:]),
            ((0, "via-runner"), [["gh", "pr", "merge", "903"]]))
    finally:
        sp.run = real_run
        forbid_live_gh(was_forbidden)


def _test_drain_arithmetic(chk):
    """A cap stated only as N-per-tick is an unbounded stall in disguise. This asserts the
    multiplication in the header, so nobody can halve the cap and leave the justification."""
    measured_class_size = 7          # issue #927, 7 of 37 open PRs
    measured_outage_minutes = 58     # zero merges while #910 held
    per_hour = MAX_MOVES_PER_TICK * TICKS_PER_HOUR
    ticks_to_drain = -(-measured_class_size // MAX_MOVES_PER_TICK)
    chk("cap: drain capacity per hour", per_hour, 15)
    chk("cap: the measured class drains in this many ticks", ticks_to_drain, 2)
    chk("cap: worst-case drain minutes for the measured class is inside the outage it clears",
        ticks_to_drain * (60 // TICKS_PER_HOUR) <= measured_outage_minutes, True)


def _log(*lines):
    """A gate job log, in the shape the runner actually emits (ISO-8601 prefix per line)."""
    return "".join(f"2026-07-28T02:38:5{i % 10}.1234567Z {line}\n" for i, line in enumerate(lines))


SIG = "no `producer | early-exiting consumer` survives anywhere in scripts/*.sh (#879)"
OWN = "the partition key covers every declared area"


def _worker_live_log(*fail_bodies, count=True, harness="worker-live", header="worker-live.sh"):
    lines = [f"== self-test {header} =="]
    lines.append("  ok   leftover markers fail the staged check")
    # TWO passing lines that a substring search mistakes for failures, and they are NOT
    # interchangeable. Measured on the real #910 log: 62 lines contain the substring `FAIL`, 44 of
    # them PASSING `ok` rows.
    #
    #   (1) `FAILED guard` - no whitespace after `FAIL`, so `FAIL:?[ \t]+` cannot match it however
    #       the anchor is weakened. It catches a signature-level substring search and NOTHING else.
    #   (2) `FAIL CLOSED` - whitespace DOES follow `FAIL`, so removing the line anchor extracts
    #       `CLOSED - ...` from a passing row. This is the only decoy shape that can observe the
    #       anchor, and it is a verbatim shape from the live suite.
    #
    # Decoy (1) alone left the assertion named "the extractor is LINE-ANCHORED" unable to observe
    # the property in its own name: `^[ \t]*` -> `^.*?` kept the whole suite green.
    lines.append(f"  ok   a FAILED guard is refused: {SIG}")
    lines.append("  ok   age_park_episode: FAIL CLOSED - the taxonomy cannot name this cause")
    lines.extend(f"  FAIL {body}" for body in fail_bodies)
    if count:
        lines.append(f"{harness} self-test FAILED ({len(fail_bodies)} failure(s))")
    else:
        lines.append(f"{harness} self-test FAILED")
    lines.append("##[error]Process completed with exit code 1.")
    return _log(*lines)


def _test_failure_ledger(chk):
    """The evidence layer. Every clause here is a way "every failure is explained" could be TRUE
    while the harness had in fact observed nothing."""
    good = failure_ledger(_worker_live_log(f"{SIG}: 1 (want 0)"))
    # Compared as a WHOLE LEDGER, not field-by-field: it pins all three fields at once, and it is
    # what exercises __eq__/__repr__ — both were at 0% coverage, i.e. dead code, until measured.
    chk("ledger: a clean single-failure log reconciles",
        good, FailureLedger("worker-live", (f"{SIG}: 1 (want 0)",), None))
    chk("ledger: an unequal ledger does NOT compare equal (so the assertion above has teeth)",
        good == FailureLedger("worker-live", (), None), False)
    chk("ledger: a ledger never compares equal to a same-shaped tuple",
        good == ("worker-live", (f"{SIG}: 1 (want 0)",), None), False)
    chk("ledger: the extractor is LINE-ANCHORED — the fixture carries a passing `ok  … FAIL CLOSED "
        "…` row, so weakening `^[ \\t]*` to `^.*?` extracts a SECOND body out of a line that "
        "passed (and a substring grep over the signature would find 3 hits here, not 1)",
        len(good.fails), 1)

    two = failure_ledger(_worker_live_log(f"{SIG}: 1 (want 0)", f"{OWN}: 0 (want 1)"))
    chk("ledger: both failures are extracted when two assertions fail", len(two.fails), 2)

    # THE ANTI-VACUITY CLAUSES. Each of these is a log in which the exclusivity check would
    # otherwise pass by having seen nothing.
    miscount = _worker_live_log(f"{SIG}: 1 (want 0)").replace("(1 failure(s))", "(2 failure(s))")
    chk("ledger: a roll-up declaring MORE failures than were extracted is refused — the extractor "
        "missed some, and 'all explained' would be a lie",
        failure_ledger(miscount).reason, "unreconciled-log")
    chk("ledger: a log with a roll-up but NO extracted failure line is refused",
        failure_ledger(_log("== self-test worker-live.sh ==",
                           "worker-live self-test FAILED (0 failure(s))")).reason,
        "unreconciled-log")
    chk("ledger: a self-test that died by EXCEPTION prints no roll-up and is refused",
        failure_ledger(_log("== self-test groom.py ==",
                           "Traceback (most recent call last):",
                           "RegateSweepError: input missing",
                           "##[error]Process completed with exit code 1.")).reason,
        "unreconciled-log")
    # TWO roll-ups, deliberately shaped so that NEITHER the count clause nor the header clause can
    # catch it: same harness, and a count that agrees with the single extracted failure. An inner
    # self-test invoked as a subprocess prints exactly this. Without the exactly-one clause the log
    # reconciles and its (ambiguous) accounting would be believed. The earlier two-harness spelling
    # of this test was killed by the OTHER two clauses, so it credited a kill it could not produce.
    chk("ledger: TWO failing roll-ups are refused even when the first one's own accounting is "
        "self-consistent — the log names two accountings and this harness reads neither",
        failure_ledger(_log("== self-test worker-live.sh ==", "  FAIL x: 1 (want 0)",
                            "worker-live self-test FAILED (1 failure(s))",
                            "worker-live self-test FAILED (1 failure(s))")).reason,
        "unreconciled-log")
    chk("ledger: two failing roll-ups from DIFFERENT harnesses are refused too",
        failure_ledger(_log("== self-test a.py ==", "  FAIL x: 1 (want 0)",
                            "a self-test FAILED (1 failure(s))",
                            "== self-test b.py ==", "  FAIL y: 1 (want 0)",
                            "b self-test FAILED (1 failure(s))")).reason,
        "unreconciled-log")
    chk("ledger: a roll-up that does NOT match the last `== self-test X ==` header is refused "
        "(the accounting must belong to the harness that actually stopped the loop)",
        failure_ledger(_worker_live_log(f"{SIG}: 1 (want 0)", header="groom.py")).reason,
        "unreconciled-log")
    chk("ledger: an empty/unavailable log is refused", failure_ledger("").reason, "log-unavailable")
    chk("ledger: a countless roll-up spelling still reconciles (`groom self-test FAILED`)",
        failure_ledger(_worker_live_log(f"{SIG}: 1 (want 0)", count=False)).reason, None)
    chk("ledger: the `FAIL: <name>` spelling is extracted too",
        failure_ledger(_log("== self-test resolve-conflicts.py ==", "FAIL: some assertion",
                            "resolve-conflicts self-test FAILED")).fails,
        ("some assertion",))


def _test_signature_matching(chk):
    chk("signature: exact body", signature_matches(SIG, SIG), True)
    chk("signature: `<sig>: <got> (want <want>)` tail", signature_matches(f"{SIG}: 1 (want 0)", SIG),
        True)
    chk("signature: a DIFFERENT assertion that merely starts with the same words is NOT claimed",
        signature_matches("the guard fires twice: 2 (want 1)", "the guard fires"), False)
    chk("signature: a signature appearing mid-line is NOT a match (anchored at the body start)",
        signature_matches(f"some other assertion mentioning {SIG}", SIG), False)


def _pr(number, *, head="a" * 40, repo="jeswr/agent-account-registry", labels=(), ref="feature",
        auto_merge=None):
    return {"number": number, "labels": [{"name": n} for n in labels], "auto_merge": auto_merge,
            "head": {"sha": head, "ref": ref, "repo": {"full_name": repo}}}


def _gate(conclusion="failure", completed="2026-07-28T02:09:30Z", status="completed"):
    return {"name": GATE_CHECK, "status": status, "conclusion": conclusion,
            "started_at": completed, "completed_at": completed,
            "details_url": "https://github.com/o/r/actions/runs/30323019284/job/90164408722"}


REPAIR = {"repair_pr": 917, "harness": "worker-live.sh", "signatures": [SIG], "why": "x"}
REPAIR_MERGED = parse_rfc3339("2026-07-28T02:26:49Z")


def _test_attribution(chk):
    """THE SAFETY ARGUMENT. The red case is tonight's #903; the CONTROL is a PR red on its own
    merits. Without the control this whole script could pass its tests by rebasing everything."""
    clean = failure_ledger(_worker_live_log(f"{SIG}: 1 (want 0)"))
    own = failure_ledger(_worker_live_log(f"{OWN}: 0 (want 1)"))
    both = failure_ledger(_worker_live_log(f"{SIG}: 1 (want 0)", f"{OWN}: 0 (want 1)"))

    chk("RED CASE (#903): gate red at 02:09:30Z, fix merged 02:26:49Z, head lacks the fix, and the "
        "only failing assertion is one #917 repairs -> attributable",
        attribute(_pr(903), "jeswr/agent-account-registry", _gate(), REPAIR_MERGED, False,
                  clean, REPAIR),
        "attributable")

    chk("CONTROL (#92): identical timing and an identically stale head, but the failing assertion "
        "is NOT one #917 repairs -> REFUSED, stays red",
        attribute(_pr(92), "jeswr/agent-account-registry", _gate(), REPAIR_MERGED, False,
                  own, REPAIR),
        "own-merits")
    chk("CONTROL (mixed): a PR failing a repaired assertion AND one of its own is REFUSED — "
        "exclusivity, not membership",
        attribute(_pr(856), "jeswr/agent-account-registry", _gate(), REPAIR_MERGED, False,
                  both, REPAIR),
        "own-merits")
    chk("CONTROL: the right assertion failing in the WRONG harness is refused",
        attribute(_pr(1), "jeswr/agent-account-registry", _gate(), REPAIR_MERGED, False,
                  clean, {**REPAIR, "harness": "groom.py"}),
        "wrong-harness")
    chk("CONTROL: a log whose accounting does not close is refused even when a repaired signature "
        "IS present",
        attribute(_pr(1), "jeswr/agent-account-registry", _gate(), REPAIR_MERGED, False,
                  failure_ledger(_worker_live_log(f"{SIG}: 1 (want 0)").replace(
                      "(1 failure(s))", "(2 failure(s))")), REPAIR),
        "unreconciled-log")

    # The timing and containment clauses, each in both directions.
    chk("clause (b): a failure that POSTDATES the repair is refused",
        attribute(_pr(1), "jeswr/agent-account-registry",
                  _gate(completed="2026-07-28T03:00:00Z"), REPAIR_MERGED, False, clean, REPAIR),
        "failure-postdates-repair")
    chk("clause (c): a head that ALREADY contains the fix and is still red is red on its own "
        "merits and is refused",
        attribute(_pr(1), "jeswr/agent-account-registry", _gate(), REPAIR_MERGED, True,
                  clean, REPAIR),
        "already-contains-fix")
    chk("clause (a): a GREEN newest gate is refused",
        attribute(_pr(1), "jeswr/agent-account-registry", _gate(conclusion="success"),
                  REPAIR_MERGED, False, clean, REPAIR),
        "gate-not-red")
    chk("clause (a): an in-flight gate is refused, never read as red",
        attribute(_pr(1), "jeswr/agent-account-registry",
                  _gate(conclusion=None, status="in_progress"), REPAIR_MERGED, False,
                  clean, REPAIR),
        "gate-running")
    chk("clause (a): a head with no gate at all is refused",
        attribute(_pr(1), "jeswr/agent-account-registry", None, REPAIR_MERGED, False,
                  clean, REPAIR),
        "no-gate-run")
    chk("fork: a head this token cannot push to is refused before anything is read",
        attribute(_pr(1, repo="someone/fork"), "jeswr/agent-account-registry", _gate(),
                  REPAIR_MERGED, False, clean, REPAIR),
        "fork")

    # newest-run resolution: an OLD failure must never outrank a NEW success on the same head.
    runs = [_gate(conclusion="failure", completed="2026-07-28T01:00:00Z"),
            _gate(conclusion="success", completed="2026-07-28T02:40:00Z")]
    chk("newest-run: the newest gate wins, so a resolved failure stops blocking",
        (newest_gate(runs) or {}).get("conclusion"), "success")
    chk("newest-run: an unparseable timestamp ranks BELOW every parseable one",
        (newest_gate([_gate(completed="not-a-time"),
                      _gate(conclusion="success")]) or {}).get("conclusion"), "success")
    chk("newest-run: a check-run with another name is ignored",
        newest_gate([{**_gate(), "name": "other"}]), None)
    chk("job id is read out of the check-run details_url", gate_run_id(_gate()), 90164408722)


def _test_cap_and_ordering(chk):
    chk("cap: at most MAX_MOVES_PER_TICK are moved and the tail is deferred, not dropped",
        plan_moves([903, 923, 895, 893, 886, 856, 92], 5),
        ([92, 856, 886, 893, 895], [903, 923]))
    chk("cap: the order is deterministic, so the deferred tail is the SAME tail next tick",
        plan_moves([923, 92, 903], 2), ([92, 903], [923]))
    chk("cap: a cap of zero moves nothing and defers everything",
        plan_moves([1, 2], 0), ([], [1, 2]))
    chk("cap: nothing is deferred when the class fits", plan_moves([1, 2], 5), ([1, 2], []))
    chk("cap: a NEGATIVE cap raises rather than silently slicing from the end (`ordered[:-1]` would "
        "quietly move all but one)",
        isinstance(_raises(lambda: plan_moves([1, 2], -1)), RegateSweepError), True)


def _test_repairs_declaration(chk):
    """The checked-in declaration must parse, and every harness it names must be a real enrolled
    self-test entry — a typo'd harness silently sweeps nobody."""
    text = _require(REPAIRS_FILE)
    repairs = load_repairs(text)
    chk("declaration: the checked-in file parses", len(repairs) >= 1, True)
    enrolled = {line.strip() for line in _require(SUITE_MANIFEST).splitlines() if line.strip()}
    chk("declaration: every declared harness is an ENROLLED self-test entry",
        sorted({r["harness"] for r in repairs} - enrolled), [])
    chk("declaration: this script is itself enrolled in the suite",
        "regate-sweep.py" in enrolled, True)

    def refuses(label, mutate):
        document = json.loads(text)
        mutate(document)
        try:
            load_repairs(json.dumps(document))
        except RegateSweepError:
            return True
        return False

    chk("declaration: an empty signature list is REFUSED (it would explain nothing and could only "
        "ever sweep by accident)",
        refuses("empty", lambda d: d["repairs"][0].__setitem__("signatures", [])), True)
    chk("declaration: a missing `why` is refused",
        refuses("why", lambda d: d["repairs"][0].pop("why")), True)
    chk("declaration: a duplicated repair_pr is refused",
        refuses("dup", lambda d: d["repairs"].append(dict(d["repairs"][0]))), True)
    chk("declaration: a multi-line signature is refused (it is matched against ONE log line)",
        refuses("nl", lambda d: d["repairs"][0]["signatures"].__setitem__(0, "a\nb")), True)
    chk("declaration: a wrong schema version is refused",
        refuses("schema", lambda d: d.__setitem__("schema", 2)), True)
    chk("declaration: non-JSON is refused",
        isinstance(_raises(lambda: load_repairs("{")), RegateSweepError), True)
    # The remaining validator branches, which the coverage run showed were never entered. Each is a
    # shape a hand-edited declaration file really takes.
    for label, mutate in (
            ("a repair that is not an object", lambda d: d["repairs"].__setitem__(0, "917")),
            ("a non-int repair_pr", lambda d: d["repairs"][0].__setitem__("repair_pr", "917")),
            ("a boolean repair_pr (bool is an int in Python)",
             lambda d: d["repairs"][0].__setitem__("repair_pr", True)),
            ("a zero repair_pr", lambda d: d["repairs"][0].__setitem__("repair_pr", 0)),
            ("a padded harness", lambda d: d["repairs"][0].__setitem__("harness", " x.py ")),
            ("a missing harness", lambda d: d["repairs"][0].pop("harness")),
            ("a non-string signature", lambda d: d["repairs"][0]["signatures"].__setitem__(0, 7)),
            ("a whitespace-only signature",
             lambda d: d["repairs"][0]["signatures"].__setitem__(0, "   ")),
            ("a padded signature",
             lambda d: d["repairs"][0]["signatures"].__setitem__(0, " x ")),
            ("a non-list repairs key", lambda d: d.__setitem__("repairs", {})),
            ("a whitespace-only why", lambda d: d["repairs"][0].__setitem__("why", "  "))):
        chk(f"declaration: {label} is refused", refuses(label, mutate), True)

    # The repair-liveness refusals the coverage run showed were never entered.
    for label, detail, want in (
            ("a repair merged into a NON-default branch", {**REPAIR_DETAIL, "base": {"ref": "dev"}},
             "repair-not-on-default-branch"),
            ("a merged repair with no merge commit",
             {**REPAIR_DETAIL, "merge_commit_sha": None}, "repair-has-no-merge-commit"),
            ("an unparseable merged_at", {**REPAIR_DETAIL, "merged_at": "yesterday"},
             "repair-unreadable"),
            ("a merged_at in the FUTURE (a clock this sweeper must not trust)",
             {**REPAIR_DETAIL, "merged_at": "2026-07-29T00:00:00Z"}, "repair-unreadable"),
            ("a detail payload that is not an object", None, "repair-unreadable")):
        chk(f"repair-window: {label} -> {want}", repair_window(detail, NOW)[1], want)


def _exit_code(fn):
    """The SystemExit code `fn` raises, or None. Separate from `_raises` on purpose: SystemExit
    derives from BaseException, so an `except Exception` helper lets an argparse rejection escape
    and abort the whole self-test — which is exactly what it did the first time."""
    import contextlib
    import io
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            fn()
    except SystemExit as exc:
        return exc.code
    return None


def _raises(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - the test wants the instance, whatever it is
        return exc
    return None


def _totalled(fn):
    """`fn()`, or its exception rendered as a value. For asserting a REPORTING helper is TOTAL.

    A helper that raises aborts every assertion after it, so the mutant that makes it partial dies
    by traceback with no named red and masks the rest of the section — two probes truncated at
    68/202 exactly that way. Rendering the exception turns that into a named red with the failure
    as its `got`."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"[:120]


# ⚠️ FOUR DISTINCT REFUSALS, NAMED SEPARATELY. Several of them reject the same argv — `pr merge`
# trips the first, and a bare "it raises" assertion is satisfied by ANY of them — so deleting one
# alone survives, which is the mutually-masking-duplicate-guard shape. The assertions below key on
# these strings, and a check asserts all four are pairwise DISTINCT: aliasing two of them
# (`_DOUBLE_NO_PATH = _DOUBLE_NOT_API`) restores the masking without changing behaviour, and that
# mutant used to survive because the distinct-message fix had no test of its own.
_DOUBLE_NOT_API = "unexpected FakeGh request: this double serves `gh api` only"
_DOUBLE_NO_PATH = "unexpected FakeGh request: no repository path"
_DOUBLE_UNSERVED_WRITE = "unexpected FakeGh WRITE: this double serves three writes only"
_DOUBLE_UNSERVED_READ = "unexpected FakeGh read: no route for this path"


class FakeGh:
    """The `gh` layer, injected as the `runner` callable. Records every request in order, so the
    tests can assert on WHAT WAS NOT CALLED — which is the only way a "does not touch it" control
    can be expressed at all."""

    def __init__(self, repo, pulls, *, gate_by_head=None, logs=None, contains=None,
                 comments=None, default_branch=DEFAULT_BRANCH, repair_detail=None,
                 refuse_update=(), ref_moves=True, refuse_comment_reads=False,
                 refuse_pr_list=False):
        self.repo = repo
        self.pulls = pulls
        self.gate_by_head = gate_by_head or {}
        self.logs = logs or {}
        self.contains = contains or {}
        self.comments = comments or {}
        self.default_branch = default_branch
        self.repair_detail = repair_detail
        self.refuse_update = set(refuse_update)
        self.ref_moves = ref_moves
        self.refuse_comment_reads = refuse_comment_reads
        self.refuse_pr_list = refuse_pr_list
        self.calls = []

    def __call__(self, args):
        self.calls.append(tuple(args))
        # ⚠️ FAIL CLOSED. This double used to answer ANY argv whose first word was not `api` with
        # the repository payload, because `path` fell back to "" and `tail == ""` is the repo
        # endpoint. That made the `unexpected FakeGh request` raise UNREACHABLE for every CLI form —
        # and `gh pr merge 903 -R o/r`, which is exactly how scripts/worker-pr.py and
        # scripts/gh_retry.py invoke gh, was silently accepted. A test double that answers calls the
        # production code would never make cannot witness "no path arms"; it only witnesses "no path
        # arms via a REST path spelling".
        if not args or args[0] != "api":
            raise AssertionError(
                f"{_DOUBLE_NOT_API}: got {list(args)!r}")
        method = args[args.index("--method") + 1] if "--method" in args else "GET"
        prefix = f"/repos/{self.repo}"
        path = next((a for a in args if a.startswith(prefix)), None)
        if path is None:
            raise AssertionError(f"{_DOUBLE_NO_PATH}: {self.repo} not in {list(args)!r}")
        tail = path[len(prefix):]
        if method not in ("GET", "HEAD"):
            return self._write(method, tail, args)
        if tail == "":
            return 0, json.dumps({"default_branch": self.default_branch})
        if tail.startswith("/pulls?state=open"):
            return (1, "") if self.refuse_pr_list else (0, json.dumps(self.pulls))
        if re.fullmatch(r"/pulls/\d+", tail):
            return 0, json.dumps(self.repair_detail)
        if "/check-runs" in tail:
            head = tail.split("/")[2]
            return 0, json.dumps({"check_runs": self.gate_by_head.get(head, [])})
        if tail.startswith("/compare/"):
            head = tail.split("...")[-1]
            state = self.contains.get(head, False)
            if state is None:
                return 1, ""      # the compare could not be read at all
            return 0, json.dumps({"status": "ahead" if state else "diverged"})
        if "/actions/jobs/" in tail:
            body = self.logs.get(int(tail.split("/")[3]), "")
            return (1, "") if body is None else (0, body)
        if "/comments" in tail:
            if self.refuse_comment_reads:
                return 1, ""
            number = int(tail.split("/")[2])
            return 0, json.dumps([b if isinstance(b, dict) else
                                  {"body": b, "user": {"login": BOT_LOGIN}}
                                  for b in self.comments.get(number, [])])
        if tail.startswith("/git/ref/heads/"):
            branch = tail[len("/git/ref/heads/"):]
            moved = "z" * 40 if self.ref_moves else None
            for pull in self.pulls:
                if pull["head"]["ref"] == branch:
                    return 0, json.dumps({"object": {"sha": moved or pull["head"]["sha"]}})
            return 1, ""
        raise AssertionError(f"{_DOUBLE_UNSERVED_READ}: {method} {tail}")

    # ⚠️ FAIL CLOSED ON WRITES — this is the guarantee; the argv-spelling enumeration below is only
    # an optimisation on top of it. The double used to answer EVERY `--method POST|DELETE` under
    # `/repos/<repo>` with `(0,"{}")` before looking at the path, so for those two methods the
    # spelling list was the only defence and it had holes. MEASURED at the real call site in `_act`,
    # both survived 202/202 rc 0: `POST /issues/903/labels --input f.json` (adds `review:pass` — the
    # one label that authorises arming, and the label this sweeper REMOVES for exactly that reason,
    # invisible to the spelling list because the label name is in the file, not the argv) and
    # `POST /pulls/903/reviews -f event=APPROVE` (the REST twin of `gh pr review --approve`).
    #
    # These three (method, tail) pairs are every write the sweeper issues: `move_branch`,
    # `post_comment`, `drop_review_pass`. Everything else raises, so a NEW arming spelling nobody
    # enumerated is refused by construction rather than by having been thought of.
    SERVED_WRITES = (
        ("PUT", re.compile(r"/pulls/\d+/update-branch")),
        ("POST", re.compile(r"/issues/\d+/comments")),
        ("DELETE", re.compile(r"/issues/\d+/labels/" + re.escape(REVIEW_PASS_LABEL))),
    )

    def _write(self, method, tail, args):
        if not any(m == method and pattern.fullmatch(tail) for m, pattern in self.SERVED_WRITES):
            raise AssertionError(f"{_DOUBLE_UNSERVED_WRITE}: {method} {tail} in {list(args)!r}")
        if method == "PUT":
            number = int(tail.split("/")[2])
            return (1, "") if number in self.refuse_update else (0, "{}")
        return 0, "{}"

    def updated(self):
        """The PRs this double was asked to `update-branch`. TOTAL.

        ⚠️ `re.search(...).group(1)` on any PUT that is not an update-branch raises AttributeError,
        and a raise inside a REPORTING helper aborts every assertion after it: two probes truncated
        at 68/202 with a traceback and no named red, which masks everything below. Every helper in
        this double reports instead of raising — a stray PUT is refused by `_write`, and its
        refusal is the finding, not this function's stack trace."""
        numbers = []
        for call in self.calls:
            if "--method" not in call or call[call.index("--method") + 1] != "PUT":
                continue
            match = re.search(r"/pulls/(\d+)/update-branch", " ".join(str(a) for a in call))
            if match is not None:
                numbers.append(int(match.group(1)))
        return sorted(numbers)

    def posted_bodies(self):
        """Every comment body this double was asked to POST."""
        return [a[len("body="):] for c in self.calls
                if "--method" in c and c[c.index("--method") + 1] == "POST"
                for a in c if a.startswith("body=")]

    def deleted_labels(self):
        return [c[-1] for c in self.calls
                if "--method" in c and c[c.index("--method") + 1] == "DELETE"]


REPAIR_DETAIL = {"merged_at": "2026-07-28T02:26:49Z", "merge_commit_sha": "f" * 40,
                 "base": {"ref": DEFAULT_BRANCH}}
NOW = parse_rfc3339("2026-07-28T02:30:00Z")


# ---------------------------------------------------------------------------------------------
# "NEVER ARMS" — enumerated by SPELLING, not by endpoint
# ---------------------------------------------------------------------------------------------
# ⚠️ The controls here used to substring-search the JOINED argv for `/merge`, `enablePull` and the
# like. That catches the REST and GraphQL spellings and MISSES the one this estate actually uses:
# `gh pr merge 903 -R o/r` is `["pr","merge","903","-R","o/r"]`, and no token in it contains `/merge`
# (scripts/worker-pr.py:1485 and scripts/gh_retry.py:820 are both this form). An arming call was
# therefore invisible to the assertion whose name is this PR's central safety claim.
#
# So enumerate the SPELLINGS. Each entry is (label, predicate over the argv tuple).
ARMING_SPELLINGS = (
    # CLI subcommands — the form the production helpers use. Matched STRUCTURALLY on the leading
    # words, because a joined-string search can never see them.
    ("cli:pr merge", lambda a: a[:2] == ("pr", "merge")),
    ("cli:pr ready", lambda a: a[:2] == ("pr", "ready")),
    ("cli:pr edit --add-label", lambda a: a[:2] == ("pr", "edit") and "--add-label" in a),
    ("cli:issue edit --add-label", lambda a: a[:2] == ("issue", "edit") and "--add-label" in a),
    ("cli:pr review --approve", lambda a: a[:2] == ("pr", "review") and "--approve" in a),
    ("cli:run rerun", lambda a: a[:2] == ("run", "rerun")),
    ("cli:workflow run", lambda a: a[:2] == ("workflow", "run")),
    # REST paths.
    ("rest:merge", lambda a: any(re.search(r"/pulls/\d+/merge\b", x) for x in a)),
    ("rest:auto_merge", lambda a: any("/auto_merge" in x for x in a)),
    ("rest:rerun", lambda a: any(re.search(r"/(runs|jobs)/\d+/rerun", x) for x in a)),
    # ⚠️ NOT `and REVIEW_PASS_LABEL in " ".join(a)`. That conjunct made the predicate blind to
    # `--method POST …/issues/903/labels --input f.json`, where the label name is in the FILE and
    # never appears in the argv — measured surviving at the real call site. The sweeper POSTs to
    # `/labels` never, so any such write is arming-class regardless of which label it names.
    ("rest:add labels", lambda a: any(x.endswith("/labels") for x in a)),
    # The REST twin of `gh pr review --approve`; `review:pass` is not the only way to authorise.
    ("rest:approve", lambda a: any(re.search(r"/pulls/\d+/reviews\b", x) for x in a)),
    # GraphQL mutations.
    ("graphql:enablePullRequestAutoMerge",
     lambda a: any("enablePullRequestAutoMerge" in x for x in a)),
    ("graphql:mergePullRequest", lambda a: any("mergePullRequest" in x for x in a)),
    ("graphql:addLabelsToLabelable", lambda a: any("addLabelsToLabelable" in x for x in a)),
)


# ⚠️ ONE POSITIVE DETECTION PROBE PER SPELLING, and a check that this table's labels are EXACTLY
# the enumerated ones. Without it the list implies coverage it does not have: MEASURED, replacing
# each predicate with `lambda a: False` one at a time, 8 of 14 could be made constantly false and
# the suite stayed 202/202 — `cli:pr ready`, `cli:issue edit --add-label`, `cli:pr review
# --approve`, `cli:workflow run`, `rest:rerun`, `rest:add …`, `graphql:mergePullRequest` and
# `graphql:addLabelsToLabelable` were decoration. Order matters: `arming_calls` stops at the first
# match, so each probe must be matched by ITS OWN predicate and by no earlier one.
ARMING_PROBES = (
    ("cli:pr merge", ("pr", "merge", "903", "-R", "o/r")),
    ("cli:pr ready", ("pr", "ready", "903")),
    ("cli:pr edit --add-label", ("pr", "edit", "903", "--add-label", REVIEW_PASS_LABEL)),
    ("cli:issue edit --add-label", ("issue", "edit", "903", "--add-label", REVIEW_PASS_LABEL)),
    ("cli:pr review --approve", ("pr", "review", "903", "--approve")),
    ("cli:run rerun", ("run", "rerun", "123", "--failed")),
    ("cli:workflow run", ("workflow", "run", "regate-sweep.yml")),
    ("rest:merge", ("api", "--method", "PUT", "/repos/o/r/pulls/903/merge")),
    ("rest:auto_merge", ("api", "--method", "PUT", "/repos/o/r/pulls/903/auto_merge")),
    ("rest:rerun", ("api", "--method", "POST", "/repos/o/r/actions/runs/5/rerun")),
    ("rest:add labels", ("api", "--method", "POST", "/repos/o/r/issues/903/labels",
                         "--input", "f.json")),
    ("rest:approve", ("api", "--method", "POST", "/repos/o/r/pulls/903/reviews",
                      "-f", "event=APPROVE")),
    ("graphql:enablePullRequestAutoMerge",
     ("api", "graphql", "-f", "query=mutation{enablePullRequestAutoMerge(input:$i){clientMutationId}}")),
    ("graphql:mergePullRequest",
     ("api", "graphql", "-f", "query=mutation{mergePullRequest(input:$i){clientMutationId}}")),
    ("graphql:addLabelsToLabelable",
     ("api", "graphql", "-f", "query=mutation{addLabelsToLabelable(input:$i){clientMutationId}}")),
)

# The three writes the sweeper really issues. None may be flagged, or the "no arming call" checks
# would be true of a run that never wrote anything — and none may be REFUSED by the double, or the
# fail-closed allow-list and this enumeration have drifted apart.
SWEEPER_WRITES = (
    ("api", "--method", "PUT", "/repos/o/r/pulls/903/update-branch", "-f", "expected_head_sha=a"),
    ("api", "--method", "POST", "/repos/o/r/issues/903/comments", "-f", "body=x"),
    ("api", "--method", "DELETE", f"/repos/o/r/issues/903/labels/{REVIEW_PASS_LABEL}"),
)


def arming_calls(calls):
    """Every recorded call that matches an arming SPELLING. -> [(label, argv)]."""
    found = []
    for call in calls:
        argv = tuple(str(x) for x in call)
        for label, matches in ARMING_SPELLINGS:
            if matches(argv):
                found.append((label, argv))
                break
    return found


BOT_SLUG = "registry-admin"
BOT_LOGIN = f"{BOT_SLUG}[bot]"


def _fixture(*, labels=(), comments=None, refuse_update=(), cap=MAX_MOVES_PER_TICK, apply=True,
             ref_moves=True, refuse_comment_reads=False, bot_login=BOT_LOGIN, auto_merge=None):
    """Tonight's board, reduced to its two load-bearing members: #903 (attributable) and #92 (red
    on its own merits, identical in every other respect)."""
    pulls = [_pr(903, head="a" * 40, ref="fix/903", labels=labels, auto_merge=auto_merge),
             _pr(92, head="b" * 40, ref="fix/92")]
    gh = FakeGh(
        "jeswr/agent-account-registry", pulls,
        gate_by_head={"a" * 40: [_gate()], "b" * 40: [_gate()]},
        logs={90164408722: _worker_live_log(f"{SIG}: 1 (want 0)")},
        contains={}, comments=comments or {}, repair_detail=REPAIR_DETAIL,
        refuse_update=refuse_update, ref_moves=ref_moves,
        refuse_comment_reads=refuse_comment_reads)
    # #92's gate points at a different job whose log carries its OWN failure.
    gh.gate_by_head["b" * 40] = [{**_gate(),
                                 "details_url": ".../actions/runs/1/job/555"}]
    gh.logs[555] = _worker_live_log(f"{OWN}: 0 (want 1)")
    sweeper = Sweeper("jeswr/agent-account-registry", [dict(REPAIR)], runner=gh, apply=apply,
                      cap=cap, clock=lambda: NOW, sleeper=lambda _s: None, bot_login=bot_login)
    return gh, sweeper


def _row(sweeper, index=0):
    """A census row, or "" when there is none. TOTAL on purpose: `sweeper.rows[0]` on an empty list
    raises IndexError, and a raise here ABORTS every assertion after it — so one mutant would mask
    the rest of the section and the reported check count would stop meaning what it says."""
    rows = getattr(sweeper, "rows", [])
    return rows[index] if len(rows) > index else ""


def _capturing(call):
    """Run `call` with its OPERATOR-FACING OUTPUT captured -> that text. The census a `main()` tick
    prints is the only place the tick's REASON is stated, so an assertion about why a sweep moved
    nobody has to read it. Re-emitted in a `finally`, so the job log is unchanged and an escaping
    exception (`SystemExit` from argparse) does not swallow what was printed before it."""
    import contextlib
    import io
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            call()
    finally:
        print(buffer.getvalue(), end="")
    return buffer.getvalue()


def _run_total(chk, label, sweeper):
    """Run one tick, turning an ESCAPING exception into a NAMED red rather than an abort."""
    return _run_capturing(chk, label, sweeper)[0]


def _run_capturing(chk, label, sweeper):
    """Run one tick with its OPERATOR-FACING OUTPUT captured. -> (result, printed text).

    ⚠️ The `::warning::` and `::error::` annotations are published to a human exactly as surely as
    the text posted onto the PR, and a guard that scans only the note CONSTANT is blind to them —
    which is how the withdrawn "the diff is unchanged" clause kept shipping for two rounds from an
    inline f-string three lines above the note that withdraws it. Returning the real text lets the
    guard scan what the run ACTUALLY printed rather than a hand-enrolled list of artifacts.

    The captured text is re-emitted, so the job log is unchanged and an annotation is never
    swallowed by the act of checking it."""
    import contextlib
    import io
    buffer = io.StringIO()
    result = None
    try:
        with contextlib.redirect_stdout(buffer):
            result = sweeper.run()
    except BaseException as exc:                                          # noqa: BLE001
        print(buffer.getvalue(), end="")
        chk(f"tick[{label}] completed without raising",
            f"{type(exc).__name__}: {exc}"[:140], "no exception")
        return None, buffer.getvalue()
    print(buffer.getvalue(), end="")
    return result, buffer.getvalue()


def _test_live_sweep(chk):
    """THE REPLAY. Tonight's case end-to-end through the live path, PAIRED WITH THE CONTROL."""
    gh, sweeper = _fixture()
    chk("live: the tick exits 0", _run_total(chk, "main", sweeper), 0)
    chk("live: the attributable PR's BRANCH IS MOVED (not its job re-run — no rerun endpoint is "
        "ever called)", gh.updated(), [903])
    # Scoped to the API PATH, not to the whole command line: the marker comment this posts
    # explains why `gh run rerun` cannot work, so a substring search over the argv finds the word
    # `rerun` in prose and passes for the wrong reason.
    chk("live: NO rerun endpoint is ever called — re-running grades the same tree (#920)",
        [c for c in gh.calls
         if any(re.search(r"/actions/(runs|jobs)/\d+/rerun", a) for a in c)], [])
    chk("live: the CONTROL — a PR red on its own merits — is NOT touched", 92 in gh.updated(),
        False)
    chk("live: the move is CONDITIONAL on the head it classified — an author push landing between "
        "the read and the write rejects the update instead of discarding their commit",
        [a for c in gh.calls for a in c if a.startswith("expected_head_sha=")],
        ["expected_head_sha=" + "a" * 40])
    chk("live: the control's refusal is named in the census",
        "own-merits:1" in _row(sweeper), True)
    chk("live: the census names the class and the move", "class=1 moved=1" in _row(sweeper), True)

    # IDEMPOTENCE, twice over: by marker, and by the head now containing the fix.
    gh2, sweeper2 = _fixture(comments={903: [MARKER.format(repair=917, head="a" * 40)]})
    _run_total(chk, 'sweeper2', sweeper2)
    chk("idempotence: a PR already swept for THIS repair is not moved again",
        gh2.updated(), [])
    chk("idempotence: it is censused as already-swept, not silently dropped",
        "already-swept=1" in _row(sweeper2), True)
    spoof = {"body": MARKER.format(repair=917, head="a" * 40), "user": {"login": "someone-else"}}
    gh2b, sweeper2b = _fixture(comments={903: [spoof]})
    _run_total(chk, 'sweeper2b', sweeper2b)
    chk("idempotence: a marker posted by ANYONE ELSE does not suppress the sweep — an "
        "unrestricted marker scan is a denial of recovery, not an idempotence key",
        gh2b.updated(), [903])
    gh2c, sweeper2c = _fixture(comments={903: [spoof]}, bot_login="")
    _run_total(chk, 'sweeper2c', sweeper2c)
    chk("idempotence: with NO known bot login the polarity flips to trusting every marker — a "
        "missed move is safe and retried, a repeated move is not",
        gh2c.updated(), [])

    gh3, sweeper3 = _fixture(comments={903: [MARKER.format(repair=999, head="a" * 40)]})
    _run_total(chk, 'sweeper3', sweeper3)
    chk("idempotence: a marker for a DIFFERENT repair does not suppress this one",
        gh3.updated(), [903])
    gh4, sweeper4 = _fixture()
    gh4.contains["a" * 40] = True
    _run_total(chk, 'sweeper4', sweeper4)
    chk("idempotence: once the head contains the fix the PR leaves the class on its own",
        (gh4.updated(), "already-contains-fix:1" in _row(sweeper4)), ([], True))

    # A failed READ is its own state. Collapsing it into an evidence bucket would let a listing
    # outage read, in the census, as a population that WAS examined and found unattributable.
    gh4b, sweeper4b = _fixture()
    gh4b.contains["a" * 40] = None
    _run_total(chk, 'sweeper4b', sweeper4b)
    chk("read-failure: an unreadable containment compare is censused as read-failed, never as an "
        "examined-and-refused PR", (gh4b.updated(), "read-failed:1" in _row(sweeper4b)),
        ([], True))
    gh4d, sweeper4d = _fixture()
    gh4d.logs[90164408722] = None          # the log REQUEST fails, rather than returning nothing
    _run_total(chk, 'sweeper4d', sweeper4d)
    chk("read-failure: a FAILED log REQUEST is read-failed, not log-unavailable — an API outage "
        "must not be censused as an expired retention window",
        (gh4d.updated(), "read-failed:1" in _row(sweeper4d)), ([], True))
    gh4e, sweeper4e = _fixture()
    gh4e.logs[90164408722] = ""            # the request SUCCEEDS and yields nothing
    _run_total(chk, 'sweeper4e', sweeper4e)
    chk("read-failure: a log request that succeeds and yields NOTHING is log-unavailable",
        (gh4e.updated(), "log-unavailable:1" in _row(sweeper4e)), ([], True))

    gh4c, sweeper4c = _fixture(refuse_comment_reads=True)
    _run_total(chk, 'sweeper4c', sweeper4c)
    chk("read-failure: an unreadable MARKER listing refuses the move — reading it as 'not swept' "
        "would move a head this tick cannot prove it has not already moved",
        (gh4c.updated(), "read-failed:1" in _row(sweeper4c)), ([], True))

    # THE CAP, on the live path.
    many = [_pr(n, head=f"{n:040x}", ref=f"fix/{n}") for n in (903, 923, 895, 893, 886, 856)]
    gh5 = FakeGh("jeswr/agent-account-registry", many,
                 gate_by_head={p["head"]["sha"]: [_gate()] for p in many},
                 logs={90164408722: _worker_live_log(f"{SIG}: 1 (want 0)")},
                 repair_detail=REPAIR_DETAIL)
    sweeper5 = Sweeper("jeswr/agent-account-registry", [dict(REPAIR)], runner=gh5, apply=True,
                       cap=MAX_MOVES_PER_TICK, clock=lambda: NOW, sleeper=lambda _s: None)
    _run_total(chk, 'sweeper5', sweeper5)
    chk("cap: six attributable PRs -> exactly MAX_MOVES_PER_TICK moved this tick",
        len(gh5.updated()), MAX_MOVES_PER_TICK)
    chk("cap: the residue is REPORTED, never dropped", "deferred-cap=1" in _row(sweeper5), True)

    # ------------------------------------------------------------------------------------
    # THE DOUBLE ITSELF. A control that says "no arming call was issued" is worth exactly as
    # much as the double's ability to NOTICE one.
    # ------------------------------------------------------------------------------------
    probe = FakeGh("jeswr/agent-account-registry", [])
    for label, argv in (
            ("gh pr merge (worker-pr.py / gh_retry.py's own idiom)", ("pr", "merge", "903",
                                                                      "-R", "o/r")),
            ("gh pr merge --auto --squash", ("pr", "merge", "903", "--auto", "--squash")),
            ("gh pr merge --admin", ("pr", "merge", "903", "--admin")),
            ("gh pr edit --add-label review:pass", ("pr", "edit", "903", "--add-label",
                                                    REVIEW_PASS_LABEL)),
            ("gh run rerun --failed", ("run", "rerun", "123", "--failed"))):
        chk(f"double: REFUSES `{label}` as a non-`api` argv instead of answering it with the "
            "repository payload — keyed on WHICH guard fired, because the two refusals both "
            "reject this shape and would otherwise mask each other",
            _DOUBLE_NOT_API in str(_raises(lambda a=argv: probe(a))), True)
    chk("double: the SECOND refusal has its own observer — an `api` call to a repository this "
        "double does not serve is refused for THAT reason, not the first one's",
        _DOUBLE_NO_PATH in str(_raises(lambda: probe(("api", "/repos/someone/else/pulls/1")))), True)
    chk("double: still serves the `gh api` calls the sweeper really makes",
        isinstance(_raises(lambda: probe(("api", "/repos/jeswr/agent-account-registry"))), Exception),
        False)
    chk("double: an `api` path it has no route for is refused for THAT reason — the third refusal "
        "had no observer, so nothing would have noticed it being deleted",
        _DOUBLE_UNSERVED_READ in str(_raises(
            lambda: probe(("api", "/repos/jeswr/agent-account-registry/collaborators")))), True)
    chk("double: the four refusal messages are PAIRWISE DISTINCT — aliasing two of them restores "
        "the mutual masking the separate naming exists to prevent, and that mutant survived",
        len({_DOUBLE_NOT_API, _DOUBLE_NO_PATH, _DOUBLE_UNSERVED_WRITE, _DOUBLE_UNSERVED_READ}), 4)

    # ⚠️ FAIL CLOSED ON WRITES. Before this, EVERY `--method POST|DELETE` under `/repos/<repo>` was
    # answered `(0,"{}")` before the path was looked at, so the spelling enumeration was the only
    # defence on the write path — and the first two rows below were MEASURED surviving 202/202 rc 0
    # when injected at the real call site in `_act`.
    writes = FakeGh("jeswr/agent-account-registry", [])
    repo_prefix = "/repos/jeswr/agent-account-registry"
    for label, argv in (
            ("POST …/issues/903/labels --input f.json (adds `review:pass` from a FILE, so the "
             "label name is nowhere in the argv)",
             ("api", "--method", "POST", f"{repo_prefix}/issues/903/labels", "--input", "f.json")),
            ("POST …/pulls/903/reviews -f event=APPROVE (the REST twin of `pr review --approve`)",
             ("api", "--method", "POST", f"{repo_prefix}/pulls/903/reviews", "-f",
              "event=APPROVE")),
            ("PUT …/pulls/903/merge",
             ("api", "--method", "PUT", f"{repo_prefix}/pulls/903/merge")),
            ("PUT …/pulls/903/auto_merge",
             ("api", "--method", "PUT", f"{repo_prefix}/pulls/903/auto_merge")),
            ("DELETE of a label that is NOT review:pass",
             ("api", "--method", "DELETE", f"{repo_prefix}/issues/903/labels/needs-user")),
            ("PATCH of the PR itself",
             ("api", "--method", "PATCH", f"{repo_prefix}/pulls/903")),
            ("a spelling nobody enumerated",
             ("api", "--method", "POST", f"{repo_prefix}/issues/903/assignees"))):
        chk(f"double: FAILS CLOSED on the unserved write `{label[:52]}`",
            _DOUBLE_UNSERVED_WRITE in str(_raises(lambda a=argv: writes(a))), True)
    for argv in SWEEPER_WRITES:
        served = tuple(a.replace("/repos/o/r", repo_prefix) for a in argv)
        chk(f"double: still SERVES the write the sweeper really issues — "
            f"`{argv[2]} {argv[3].split('/repos/o/r')[-1]}`",
            _raises(lambda a=served: writes(a)), None)
    chk("double: and a stray PUT is REFUSED rather than crashing the reporting helper — "
        "`updated()` is TOTAL over the refused calls it still recorded, so a partial helper cannot "
        "truncate the run and mask every assertion below it",
        _totalled(writes.updated), [903])

    # AND the control must be able to SEE those spellings. Without this the "no arming call" checks
    # could pass by matching nothing at all — the vacuity that hid the CLI form in the first place.
    chk("never-arm control: EVERY enumerated spelling has a positive detection probe — an "
        "un-probed predicate can be replaced by `lambda a: False` and nothing notices, which was "
        "true of 8 of the 14",
        sorted({label for label, _ in ARMING_PROBES}),
        sorted({label for label, _ in ARMING_SPELLINGS}))
    for label, argv in ARMING_PROBES:
        chk(f"never-arm control: `{' '.join(argv)[:44]}` is DETECTED as {label}",
            [name for name, _ in arming_calls([argv])], [label])
    chk("never-arm control: an ordinary read is NOT flagged (so the control is not simply true "
        "of everything)",
        arming_calls([("api", "/repos/o/r/pulls?state=open"),
                      ("api", "/repos/o/r/commits/abc/check-runs")]), [])
    chk("never-arm control: and none of the three writes the sweeper DOES issue is flagged — a "
        "control that fires on `update-branch`, the marker comment or the `review:pass` removal "
        "would make `arming_calls(...) == []` mean 'this tick wrote nothing'",
        arming_calls(SWEEPER_WRITES), [])

    # NEVER ARM.
    gh6, sweeper6 = _fixture(labels=[REVIEW_PASS_LABEL])
    _run_total(chk, 'sweeper6', sweeper6)
    chk("never-arm: moving the head REMOVES the arming label — the verdict was bound to a head "
        "that no longer exists", gh6.deleted_labels(),
        [f"/repos/jeswr/agent-account-registry/issues/903/labels/{REVIEW_PASS_LABEL}"])
    chk("never-arm: no ARMING SPELLING is ever issued — CLI (`gh pr merge …`, the form "
        "worker-pr.py/gh_retry.py use), REST path, or GraphQL mutation",
        arming_calls(gh6.calls), [])
    gh7, sweeper7 = _fixture()
    _run_total(chk, 'sweeper7', sweeper7)
    chk("never-arm: a PR WITHOUT the arming label gets no label write at all",
        gh7.deleted_labels(), [])

    # DE-AUTHORISATION IS NOT DISARMING. Removing `review:pass` withdraws consent from a FUTURE arm
    # decision; a latched auto-merge is held by `enablePullRequestAutoMerge` and is never re-read.
    # That case is accepted (the green it merges on is fresh) but it must be VISIBLE.
    gh7b, sweeper7b = _fixture(labels=[REVIEW_PASS_LABEL],
                               auto_merge={"enabled_by": {"login": "someone"}})
    _, printed7b = _run_capturing(chk, 'sweeper7b', sweeper7b)
    chk("latched-arm: an ALREADY-armed PR is moved, counted and named — the head move does not "
        "retract auto-merge, so the census must not report this merge as unattended",
        ("latched-arm=1" in _row(sweeper7b), gh7b.updated()), (True, [903]))
    chk("latched-arm: no auto-merge-off / disable call is issued — the case is accepted, not "
        "silently disarmed",
        [c for c in gh7b.calls if any(w in " ".join(c)
                                      for w in ("auto_merge", "disable-auto", "DisableAuto"))], [])
    chk("latched-arm: an UNARMED moved PR reports zero, so the field cannot read as decoration",
        "latched-arm=0" in _row(sweeper7), True)
    # A MISSING `auto_merge` field is a third state. Reading it as "not armed" would let the control
    # stop reporting without anything saying so — the silent-default shape.
    chk("latched-arm: an ABSENT auto_merge field is unknown, not False",
        (latched_arm_state({}), latched_arm_state({"auto_merge": None}),
         latched_arm_state({"auto_merge": {"x": 1}})), (None, False, True))
    gh7c, sweeper7c = _fixture()
    for pull in gh7c.pulls:
        pull.pop("auto_merge")
    _run_total(chk, 'sweeper7c', sweeper7c)
    chk("latched-arm: a payload with no auto_merge field censuses latched-arm-unknown instead of "
        "silently reporting zero armed PRs",
        ("latched-arm-unknown=1" in _row(sweeper7c), gh7c.updated()), (True, [903]))
    chk("latched-arm: and the unknown field is ABSENT when every payload carried auto_merge, so it "
        "cannot become permanent noise", "latched-arm-unknown" in _row(sweeper7), False)
    chk("latched-arm: the published note does NOT claim the approved diff is unchanged — measured "
        "false (same-file non-overlapping merges shift hunk headers and blob ids), and this text "
        "is posted onto other people's PRs",
        [phrase for phrase in WITHDRAWN_DIFF_CLAIMS if phrase in LATCHED_ARM_NOTE], [])
    # ⚠️ AND THE SAME OVER EVERYTHING THE TICK ACTUALLY PUBLISHED. Scanning the note constant alone
    # is what let the withdrawn clause keep shipping from the `::warning::` three lines above it.
    # This input is the REAL captured stdout of the latched-arm tick plus the body it really
    # posted — so a justification added in a new annotation, or in the comment, is covered without
    # anyone remembering to enrol it.
    published7b = printed7b + "\n" + "\n".join(gh7b.posted_bodies())
    chk("latched-arm: the scanned surface really CONTAINS the tick's annotation channel — an "
        "inert capture would leave the guard below scanning only the posted body, which is the "
        "one artifact it was already scanning",
        LATCHED_ARM_WARNING.format(number=903, label=REVIEW_PASS_LABEL) in printed7b, True)
    chk("latched-arm: NO justification this tick published to a human — captured annotations AND "
        "the posted body, not one hand-named constant — claims the approved diff survived the move",
        (sorted(p for p in WITHDRAWN_DIFF_CLAIMS if p in published7b),
         "latched-arm" in published7b), ([], True))
    chk("latched-arm: and what it publishes INSTEAD is the freshness claim named with the base it "
        "rests on — gutting that clause to a vacuous one leaves the guard above satisfied",
        ("computed against a base that contains the repair" in published7b,
         "computed against a base that contains the repair" in LATCHED_ARM_NOTE,
         "computed against a base that contains the repair" in LATCHED_ARM_WARNING),
        (True, True, True))
    chk("latched-arm: the note states the one claim it DOES rest on (the green is fresh)",
        "green it merges on is fresh" in LATCHED_ARM_NOTE.lower(), True)
    chk("latched-arm: and it tells the reader what to do if that is not enough for their PR",
        "disarm it" in LATCHED_ARM_NOTE, True)
    chk("latched-arm: the PR comment names the latched arm explicitly",
        LATCHED_ARM_NOTE[:40] in sweep_comment(917, "t", "t", "a" * 40, ("x",), latched_arm=True),
        True)
    chk("latched-arm: and says nothing when there is no latched arm",
        LATCHED_ARM_NOTE[:40] in sweep_comment(917, "t", "t", "a" * 40, ("x",)), False)

    # ------------------------------------------------------------------------------------
    # THE MARKER COMMENT. It is the ENTIRE operator-facing record of what the sweeper did, and
    # it had no test at all: deleting the post, dropping the marker, deleting the
    # verdict-invalidation sentence and posting an empty body ALL survived. So assert CONTENT,
    # not merely that a call happened.
    # ------------------------------------------------------------------------------------
    ghc, sweeperc = _fixture()
    _run_total(chk, "comment", sweeperc)
    bodies = ghc.posted_bodies()
    chk("comment: exactly one comment is posted, on the PR that moved", len(bodies), 1)
    body = bodies[0] if bodies else ""
    chk("comment: it is not empty", bool(body.strip()), True)
    chk("comment: it carries the idempotence MARKER for THIS repair and the OLD head — without it "
        "the next tick has no record that this move happened",
        MARKER.format(repair=917, head="a" * 40) in body, True)
    chk("comment: the marker is machine-readable by the same regex `already_swept` scans with",
        [(int(m.group(1)), m.group(2)) for m in MARKER_RE.finditer(body)], [(917, "a" * 40)])
    chk("comment: it states the VERDICT INVALIDATION — a moved head is a head no verdict has seen",
        all(phrase in body for phrase in ("not an arm", "invalidates any review verdict")), True)
    chk("comment: it names the repair PR, so a reader can check the attribution claim",
        "#917" in body, True)
    chk("comment: it quotes the failing assertion(s) it attributed, verbatim",
        f"    FAIL {SIG}: 1 (want 0)" in body, True)
    chk("comment: it says why a rerun cannot substitute (the #920 mechanism)",
        "rerun" in body and "#920" in body, True)
    chk("comment: it identifies the agent, per the estate's self-id rule",
        body.startswith("> \N{ROBOT FACE} **SPARQ agent**"), True)
    chk("comment: the CONTROL PR that was not moved gets no comment at all",
        [b for b in bodies if "#92" in b.split("\n")[0]], [])
    # And the body must be REACHED from _act, not merely constructible: the assertion above reads
    # what the double was actually asked to POST, so deleting the post_comment call reds it.
    chk("comment: it is posted through the API, addressed to the moved PR",
        [c for c in ghc.calls if "--method" in c and c[c.index("--method") + 1] == "POST"
         and any("/issues/903/comments" in a for a in c)] != [], True)

    # DRY RUN and failure handling.
    gh8, sweeper8 = _fixture(apply=False)
    chk("dry-run: exits 0", _run_total(chk, "sweeper8", sweeper8), 0)
    chk("dry-run: issues no write of any kind",
        [c for c in gh8.calls if "--method" in c], [])
    gh9, sweeper9 = _fixture(refuse_update=(903,))
    chk("failure: a refused update-branch makes the tick exit NON-ZERO",
        _run_total(chk, "sweeper9", sweeper9), 1)
    chk("failure: and is censused as move-failed", "move-failed=1" in _row(sweeper9), True)
    gh10, sweeper10 = _fixture(ref_moves=False)
    _run_total(chk, 'sweeper10', sweeper10)
    chk("head-lag: an unconfirmed ref is reported, not retried (update-branch answers 202)",
        "head-confirmed=0/1" in _row(sweeper10), True)

    # The repair itself must be live.
    gh11, sweeper11 = _fixture()
    gh11.repair_detail = {**REPAIR_DETAIL, "merged_at": None}
    _run_total(chk, 'sweeper11', sweeper11)
    chk("repair: an UNMERGED declared repair sweeps nobody and says so",
        (gh11.updated(), _row(sweeper11)), ([], repair_census_line(917, "repair-not-merged")))
    gh12, sweeper12 = _fixture()
    gh12.repair_detail = {**REPAIR_DETAIL, "merged_at": "2026-07-26T02:26:49Z"}
    _run_total(chk, 'sweeper12', sweeper12)
    chk("repair: a repair older than the lookback is inert",
        (gh12.updated(), _row(sweeper12)),
        ([], repair_census_line(917, "repair-outside-lookback")))
    gh14, _ = _fixture()
    sweeper14 = Sweeper("jeswr/agent-account-registry", [], runner=gh14, apply=True,
                        clock=lambda: NOW, sleeper=lambda _s: None)
    _run_total(chk, 'sweeper14', sweeper14)
    chk("silence: a tick with NO declared repairs still emits a census row — a sweeper that prints "
        "nothing is indistinguishable from one that is not running",
        sweeper14.rows, ["CENSUS repair=none scanned=2 class=0 skipped=no-declared-repairs"])

    # THE FAIL-CLOSED EXIT. An unreadable PR listing must exit NON-ZERO and sweep nobody: a tick
    # that cannot see the population is not a tick that found nothing, and reporting 0 either way is
    # how a listing outage becomes an invisible one.
    gh15, sweeper15 = _fixture()
    gh15.refuse_pr_list = True
    chk("fail-closed: an unreadable PR listing exits 1, sweeps nobody, and emits NO census row "
        "that could be mistaken for an empty class",
        (_run_total(chk, "sweeper15", sweeper15), gh15.updated(), sweeper15.rows), (1, [], []))

    gh13, sweeper13 = _fixture()
    gh13.default_branch = "main"
    chk("repair: a default-branch drift FAILS CLOSED rather than moving branches onto a base it "
        "cannot name", isinstance(_raises(sweeper13.run), RegateSweepError), True)


def _main_total(chk, argv, runner=None, clock=None):
    """`main()` with an escaping exception converted into a NAMED red rather than an abort. Four
    arming mutants died here by traceback instead of by their own observer until this existed."""
    try:
        return main(argv, runner=runner, clock=clock)
    except SystemExit:
        raise
    except BaseException as exc:                                          # noqa: BLE001
        chk(f"main({argv[:2]}) completed without raising",
            f"{type(exc).__name__}: {exc}"[:120], "no exception")
        return None


def _main_census(chk, argv, runner=None, clock=None):
    """`_main_total` with the tick's CENSUS ROW returned as well: -> (result, census line or "").

    A row that asserts only "no write was issued" is equally satisfied by a tick that swept NOTHING,
    so the census — the operator-facing statement of what this tick actually classified — is the
    only evidence that separates suppression from inertness. The captured output is re-emitted, so
    the job log is unchanged by the act of reading it (same contract as `_run_capturing`)."""
    import contextlib
    import io
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result = _main_total(chk, argv, runner=runner, clock=clock)
    print(buffer.getvalue(), end="")
    rows = [line.strip() for line in buffer.getvalue().splitlines()
            if line.strip().startswith("CENSUS")]
    return result, rows[0] if rows else ""


class _pinned_env:
    """Run a block with the ambient CI variables PINNED to known values.

    ⚠️ This exists because the first version of `_test_entry_point` was ENVIRONMENT-DEPENDENT and
    that made it green locally and RED in CI. `--repo` defaults to `$GITHUB_REPOSITORY`, which is
    unset on a workstation and SET inside Actions, so "no --repo exits 2" was only ever true off-CI —
    it passed locally for the reason it could not hold in the one environment that matters. The same
    trap applies to `$APP_SLUG` (the `--bot-slug` default) and `$GITHUB_STEP_SUMMARY`, which would
    have made these tests APPEND to the real job summary as a side effect. Assertions about defaults
    must state the environment they assume rather than inherit it."""

    VARS = ("GITHUB_REPOSITORY", "APP_SLUG", "GITHUB_STEP_SUMMARY")

    def __init__(self, **values):
        self.values = values
        self.saved = {}

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in self.VARS}
        for key in self.VARS:
            want = self.values.get(key)
            if want is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = want
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return False


def _test_entry_point(chk):
    """`main()` was at 0% line coverage. The CLI-flag gate proves flags are DECLARED; nothing
    proved they were WIRED — including the `--bot-slug` -> `<slug>[bot]` construction the whole
    marker-authorship control rests on. Every assertion here runs with the ambient CI variables
    PINNED, because the defaults under test are read from them.

    The CLOCK is pinned for the same reason and is the same class of bug: the wall clock is an
    ambient input exactly like `$APP_SLUG`. `_fixture`'s sweeper takes `clock=lambda: NOW`, but
    `main()` built its own `Sweeper` with the WALL clock, so these rows read an input nobody
    stated — which made this section decay: once `REPAIR_LOOKBACK_HOURS` of real time had passed
    the fixture repair went inert, the move assertion below went red on every PR, and the rows that
    expect no write went vacuously green. See `main`'s docstring for what that cost.

    EVERY instant below is handed in explicitly — none is inherited — and both directions of the
    window are asserted, so a `clock` that stops reaching `Sweeper` cannot go unnoticed whichever
    way it is broken. `pinned` is `NOW`, inside `REPAIR_LOOKBACK_HOURS` of the fixture's merge;
    `stale` is one second past the end of that window, derived from the fixture's own merge time;
    and the inline `aged` is one lookback past `NOW` and additionally asserts the tick SAYS WHY it
    moved nobody (`skipped=repair-outside-lookback`) rather than merely writing nothing — an inert
    sweep and a suppressed one are otherwise indistinguishable by `updated()` alone."""
    import tempfile
    repairs = json.dumps({"schema": 1, "repairs": [dict(REPAIR)]})
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        handle.write(repairs)
        path = handle.name
    repo = "jeswr/agent-account-registry"

    def pinned():
        """The same instant `_fixture`'s own sweeper is pinned to — inside the repair's window."""
        return NOW

    def stale():
        """One second past the END of that window, derived from the fixture's own merge time."""
        return REPAIR_MERGED + int(REPAIR_LOOKBACK_HOURS * 3600) + 1

    try:
        with _pinned_env():        # no GITHUB_REPOSITORY, no APP_SLUG, no step summary
            # A marker written by SOMEONE ELSE. If `main` mis-wires the slug into the login the
            # marker scan compares against, this PR is wrongly skipped and the sweep does nothing.
            spoof = {"body": MARKER.format(repair=917, head="a" * 40), "user": {"login": "nobody"}}
            gh, _ = _fixture(comments={903: [spoof]})
            code = _main_total(chk, ["--repo", repo, "--repairs-file", path, "--bot-slug", BOT_SLUG,
                         "--max-moves", "5", "--apply"], runner=gh, clock=pinned)
            chk("entry point: main() runs the sweep end to end and exits 0", code, 0)
            chk("entry point: main() wires --bot-slug through as `<slug>[bot]`, so a foreign marker "
                "is ignored and the attributable PR is still moved", gh.updated(), [903])
            # THE OTHER DIRECTION of the clock this row depends on, and the only thing that proves
            # `main` hands its `clock` to the Sweeper rather than accepting and dropping it: the
            # SAME argv and the SAME board, one second past the lookback, must sweep NOBODY and say
            # so. Dropping the argument makes the row above red and this one green — neither can be
            # satisfied by a `main` that ignores the seam, in either direction of the mutation.
            gh_stale, _ = _fixture(comments={903: [spoof]})
            _main_total(chk, ["--repo", repo, "--repairs-file", path, "--bot-slug", BOT_SLUG,
                              "--max-moves", "5", "--apply"], runner=gh_stale, clock=stale)
            chk("entry point: ...and main() carries the CLOCK through too — one second past the "
                "repair's lookback window the same board is inert and censused, not moved",
                gh_stale.updated(), [])

            # THE OTHER DIRECTION OF THE SAME SEAM, and the one that makes every "nothing moved"
            # assertion in this section non-vacuous: the ONLY difference from the sweep above is
            # the instant `main` is handed, so a `main` that ignored `clock` (or read the wall
            # clock alongside it) would move #903 here and go red — no matter what day it is run.
            aged = NOW + int(REPAIR_LOOKBACK_HOURS * 3600) + 60
            gh_aged, _ = _fixture(comments={903: [spoof]})
            aged_log = _capturing(lambda: _main_total(
                chk, ["--repo", repo, "--repairs-file", path, "--bot-slug", BOT_SLUG,
                      "--max-moves", "5", "--apply"], runner=gh_aged, clock=lambda: aged))
            chk("entry point: main() HONOURS the clock it is handed — one lookback later the same "
                "board moves nobody, AND SAYS WHY, so the assertions above are pinned to an "
                "instant rather than inheriting the day the suite happens to run",
                (gh_aged.updated(), "skipped=repair-outside-lookback" in aged_log), ([], True))

            gh2, _ = _fixture(comments={903: [{"body": MARKER.format(repair=917, head="a" * 40),
                                              "user": {"login": BOT_LOGIN}}]})
            _main_total(chk, ["--repo", repo, "--repairs-file", path, "--bot-slug", BOT_SLUG, "--apply"],
                 runner=gh2, clock=pinned)
            chk("entry point: and OUR OWN marker read through main() does suppress the move",
                gh2.updated(), [])

            # [OPUS-5] THE CLOCK IS WIRED, and this is why it has to be. Every other Sweeper in
            # this suite is built with `clock=lambda: NOW`; the ones `main()` built were not, so
            # every assertion above compared REPAIR_DETAIL's fixed `merged_at` against the REAL wall
            # clock. That stamp is 24h + 3min before the lookback expires, so the block passed for
            # exactly one day and then went red on EVERY branch simultaneously — a repository-wide
            # merge lock authored by a test, firing at a time nobody chose and correlating with no
            # change. A suite that cannot be re-run tomorrow and get the same answer is not a suite.
            #
            # This row is the guard on the wiring itself: same fixture, same argv, only the injected
            # clock moved past the lookback. Drop `clock=clock` from main()'s Sweeper construction
            # and the far-future call falls back to the real clock and sweeps [903] — red.
            gh_now, _ = _fixture()
            _main_total(chk, ["--repo", repo, "--repairs-file", path, "--bot-slug", BOT_SLUG,
                              "--apply"], runner=gh_now, clock=lambda: NOW)
            gh_expired, _ = _fixture()
            _main_total(chk, ["--repo", repo, "--repairs-file", path, "--bot-slug", BOT_SLUG,
                              "--apply"], runner=gh_expired,
                        clock=lambda: NOW + int(REPAIR_LOOKBACK_HOURS * 3600) + 60)
            chk("entry point: main() HONOURS the injected clock, so these assertions do not depend "
                "on the wall clock (inside the lookback sweeps, past it does not)",
                (gh_now.updated(), gh_expired.updated()), ([903], []))

            gh3, _ = _fixture()
            _, dry_census = _main_census(chk, ["--repo", repo, "--repairs-file", path],
                                         runner=gh3, clock=pinned)
            chk("entry point: main() DEFAULTS to dry-run — --apply is opt-in, so a mis-wired "
                "workflow cannot write", [c for c in gh3.calls if "--method" in c], [])
            # ...and the row above, ALONE, is satisfied by a tick that swept nothing at all — which
            # is what a conditionally-inert clock (`clock=clock if args.apply else None`) produces
            # on exactly this call, the one row here with no `--apply`. The census is the evidence
            # that the repair was LIVE, its class non-empty and a move IDENTIFIED, so what the dry
            # run suppressed is the WRITE and not the work.
            chk("entry point: ...and that dry run still SWEPT — live repair, non-empty class, a "
                "move identified, nothing skipped",
                (dry_census.startswith("CENSUS repair=917 "), "class=1" in dry_census,
                 "moved=1" in dry_census, "skipped=" in dry_census),
                (True, True, True, False))

            for label, argv in (
                    ("a malformed --bot-slug", ["--repo", "o/r", "--repairs-file", path,
                                                "--bot-slug", "bad slug; rm -rf /"]),
                    ("a negative --max-moves", ["--repo", "o/r", "--repairs-file", path,
                                                "--max-moves", "-1"]),
                    ("neither --repo NOR $GITHUB_REPOSITORY", ["--repairs-file", path])):
                chk(f"entry point: {label} exits 2 rather than sweeping",
                    _exit_code(lambda a=argv: main(a, runner=_fixture()[0],
                                                   clock=lambda: NOW)), 2)

        # BOTH DIRECTIONS OF THE DEFAULT, each stating its environment instead of inheriting it.
        with _pinned_env(GITHUB_REPOSITORY=repo, APP_SLUG=BOT_SLUG):
            gh4, _ = _fixture(comments={903: [{"body": MARKER.format(repair=917, head="a" * 40),
                                              "user": {"login": BOT_LOGIN}}]})
            code = main(["--repairs-file", path, "--apply"], runner=gh4, clock=pinned)
            chk("entry point: with $GITHUB_REPOSITORY set, --repo may be omitted and the sweep runs",
                code, 0)
            chk("entry point: and $APP_SLUG supplies --bot-slug, so OUR marker still suppresses — "
                "the env default is wired to the same login the flag builds",
                gh4.updated(), [])
            gh5, _ = _fixture(comments={903: [{"body": MARKER.format(repair=917, head="a" * 40),
                                              "user": {"login": "nobody"}}]})
            main(["--repairs-file", path, "--apply"], runner=gh5, clock=lambda: NOW)
            chk("entry point: ...and the CONTROL for that suppression — same env-supplied slug, a "
                "marker by anyone else — still moves the PR, so the row above cannot pass merely "
                "because this board sweeps nobody",
                gh5.updated(), [903])
        with _pinned_env(APP_SLUG="bad slug; rm -rf /", GITHUB_REPOSITORY=repo):
            chk("entry point: a malformed $APP_SLUG is rejected exactly like a malformed flag",
                _exit_code(lambda: main(["--repairs-file", path], runner=_fixture()[0],
                                        clock=lambda: NOW)), 2)
    finally:
        os.unlink(path)


def _test_published_census(chk):
    """The step-summary write was at 22% coverage — the census's PUBLISHED surface, which is the
    half a human actually reads."""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as handle:
        path = handle.name
    try:
        gh, sweeper = _fixture()
        sweeper.summary_path = path
        _run_total(chk, 'sweeper', sweeper)
        written = open(path, encoding="utf-8").read()
        chk("published census: the row reaches the step summary, not only stdout",
            [line.strip() for line in written.splitlines() if line.strip().startswith("CENSUS")],
            [_row(sweeper)])
        chk("published census: it is headed, so a reader can find it", "### regate-sweep census"
            in written, True)
        gh2, sweeper2 = _fixture()
        sweeper2.summary_path = "/nonexistent-dir/summary.md"
        chk("published census: an unwritable summary path warns and does NOT fail the tick — the "
            "sweep already happened, and losing the receipt must not re-run it",
            _run_total(chk, "publish", sweeper2), 0)
    finally:
        os.unlink(path)


def _test_abort_guards(chk):
    """The four report-instead-of-raise helpers ARE the safety net that keeps one mutant from
    masking the rest of a section — and an untested safety net is the shape this PR keeps finding.
    Each is exercised on its exception arm with a RECORDING chk, so a helper that silently swallows
    (records nothing) is distinguishable from one that reports."""
    def recorder():
        seen = []
        return seen, lambda name, got, want: seen.append((name, got == want))

    class _Boom:
        def run(self):
            raise RuntimeError("tick exploded")

    seen, rec = recorder()
    chk("abort-guard: _run_total returns None when the tick raises", _run_total(rec, "x", _Boom()),
        None)
    chk("abort-guard: ...and RECORDS it as a red rather than swallowing it",
        [ok for _n, ok in seen], [False])
    chk("abort-guard: _run_total is transparent for a tick that does NOT raise",
        (_run_total(rec, "y", type("_", (), {"run": lambda self: 7})()), len(seen)), (7, 1))

    seen2, rec2 = recorder()
    chk("abort-guard: _main_total returns None when main() raises",
        _main_total(rec2, ["--repo", "o/r", "--repairs-file", "/nonexistent-repairs.json"]), None)
    chk("abort-guard: ...and records that red", [ok for _n, ok in seen2], [False])
    chk("abort-guard: _main_total lets SystemExit through — an argparse rejection is a RESULT, "
        "not a crash, and swallowing it would make the exit-2 assertions vacuous",
        _exit_code(lambda: _main_total(rec2, ["--bogus-flag"])), 2)

    chk("abort-guard: _job_or_empty returns {} for a missing job instead of raising",
        _job_or_empty({"jobs": {}}, "nope"), {})
    chk("abort-guard: ...while _job itself still RAISES, so the strict form stays available",
        isinstance(_raises(lambda: _job({"jobs": {}}, "nope")), RegateSweepError), True)
    chk("abort-guard: _sparse_paths_or_empty returns an empty set when there is no checkout",
        _sparse_paths_or_empty({"steps": []}), set())
    chk("abort-guard: ...while _sparse_paths itself still RAISES",
        isinstance(_raises(lambda: _sparse_paths({"steps": []})), RegateSweepError), True)
    # The derived cron map is read at the TOP of the seam, so a raise there would abort every
    # assertion below it. It REPORTS — and reporting is not failing open: the map comes back
    # EMPTY with the error attached, which is what the seam's lane-count floor reds on.
    _no_tree = os.path.join(_repo_root(), "no-such-checkout")
    chk("abort-guard: _require_dir accepts a directory that IS checked out",
        os.path.isdir(_require_dir(WORKFLOWS_DIR)), True)
    chk("abort-guard: ...and RAISES on one that is not, rather than letting the assertions that "
        "read it quietly stop asserting",
        isinstance(_raises(lambda: _require_dir("no-such-checkout")), RegateSweepError), True)
    _owner = _cron_map_module()
    chk("abort-guard: the cron-map owner still exposes the two names this script's seam binds to "
        "— renaming either there must red HERE, by name, not as a confusing seam failure",
        (callable(getattr(_owner, "schedule_minute_map", None)),
         isinstance(getattr(_owner, "MIN_SCHEDULED_LANES", None), int)), (True, True))
    _module, _map, _error = _derived_schedule_map(_no_tree)
    chk("abort-guard: a cron map that cannot be derived REPORTS instead of raising, and reports "
        "an EMPTY map rather than a clean one",
        (_module, _map, isinstance(_error, RegateSweepError)), (None, {}, True))
    chk("abort-guard: ...while _cron_map_module itself still RAISES, so the strict form stays "
        "available", isinstance(_raises(lambda: _cron_map_module(_no_tree)), RegateSweepError),
        True)


def _test_census(chk):
    counts = {name: 0 for name in BUCKETS}
    counts.update({"moved": 1, "own-merits": 2, "gate-not-red": 30})
    chk("census: a sealed population raises nothing", seal_population(33, 33), None)
    chk("census: an UNSEALED population raises — a PR that left through an uncounted exit is the "
        "silent-skip class", isinstance(_raises(lambda: seal_population(32, 33)),
                                        RegateSweepError), True)
    line = census_line(917, 33, counts, confirmed=1)
    for field in ("repair=917", "scanned=33", "class=1", "moved=1", "refused=32",
                  "gate-not-red:30", "own-merits:2", "head-confirmed=1/1"):
        chk(f"census: the row states {field}", field in line, True)
    chk("census: a tick that moved NOTHING still reports the class size",
        "class=0" in census_line(917, 33, {name: 0 for name in BUCKETS}), True)
    chk("census: BUCKETS partitions into attributable + refused with no overlap and no gap",
        sorted(BUCKETS),
        sorted(set(ATTRIBUTABLE_BUCKETS) | (set(BUCKETS) - set(ATTRIBUTABLE_BUCKETS))))


def _test_cron_collisions(chk):
    """The collision predicate on FIXTURES. The seam test feeds it the real derived map; this
    feeds it maps written here, so the predicate is exercised in both directions without a
    workflow tree — including the shape that was live on master when #1046 was filed."""
    others = {".github/workflows/latch-watchdog.yml": {9, 19, 29, 39, 49, 59},
              ".github/workflows/curate.yml": {17, 47}}
    chk("cron-map: the collision that the hand-copied map hid is reported, named, per minute",
        cron_collisions([9, 29, 49], others),
        {".github/workflows/latch-watchdog.yml": [9, 29, 49]})
    chk("cron-map: a triple that lands on nobody reports nothing",
        cron_collisions([4, 24, 44], others), {})
    chk("cron-map: ONE shared minute out of three is still a collision — a partial overlap must "
        "not average away", cron_collisions([4, 24, 47], others),
        {".github/workflows/curate.yml": [47]})
    chk("cron-map: every colliding lane is reported, not just the first",
        sorted(cron_collisions([9, 17, 44], others)),
        [".github/workflows/curate.yml", ".github/workflows/latch-watchdog.yml"])
    chk("cron-map: an EMPTY map returns a clean bill — which is why the seam test gates this "
        "predicate behind a lane-count floor rather than trusting the {} on its own",
        cron_collisions([9, 29, 49], {}), {})


# ---------------------------------------------------------------------------------------------
# the YAML seam
# ---------------------------------------------------------------------------------------------
def _load_workflow(path):
    import yaml  # hard requirement: regex-over-YAML is how permissive misparses get in
    return yaml.safe_load(_require(path))


def _job(workflow, name):
    jobs = (workflow or {}).get("jobs") or {}
    if name not in jobs:
        raise RegateSweepError(
            f"{SWEEP_WORKFLOW} has no job named `{name}` — a deleted sweep must go RED here")
    return jobs[name]


def _job_or_empty(workflow, name):
    """`_job` that REPORTS instead of raising. A raise here masked 31 seam assertions when the job
    was renamed (measured: Y19 ran 131 of 162 with zero named reds), so one mutant could hide the
    rest. The named `exactly one job` / `job is named` checks still red."""
    try:
        return _job(workflow, name)
    except RegateSweepError:
        return {}


def _steps(job):
    return (job or {}).get("steps") or []


def _invocations(step, script):
    """Executable `python3 .../<script>` command lines in a step's `run:`, COMMENTS STRIPPED. A
    filename grep over a shell body is satisfied by a comment or a continuation tail — two separate
    ways a wiring assertion has gone vacuous in this estate."""
    body = step.get("run") or ""
    live = "\n".join(line for line in body.replace("\\\n", " ").splitlines()
                     if not line.strip().startswith("#"))
    pattern = re.compile(rf"^\s*python3\s+(?:\S*/)?{re.escape(script)}([^\n]*)$", re.M)
    return [m.group(1).split() for m in pattern.finditer(live)]


def _sparse_paths(job, path="registry"):
    found = [(step.get("with") or {}) for step in _steps(job)
             if str(step.get("uses", "")).startswith("actions/checkout@")
             and (step.get("with") or {}).get("path") == path]
    if len(found) != 1:
        raise RegateSweepError(
            f"expected exactly one actions/checkout with `path: {path}`, found {len(found)}")
    spec = found[0].get("sparse-checkout") or ""
    return {line.strip() for line in str(spec).splitlines() if line.strip()}


def _sparse_paths_or_empty(job, path="registry"):
    """`_sparse_paths` that REPORTS instead of raising. A raise aborts every seam assertion after
    it, so one mutant would mask the rest — the shape the mutation run flagged on the cron."""
    try:
        return _sparse_paths(job, path)
    except RegateSweepError:
        return set()


SWEEP_JOB = "sweep"
SWEEP_STEP_ID = "sweep"
TOKEN_STEP_ID = "registry-token"


def _test_workflow_seam(chk):
    """THE YAML SEAM. Measured on this estate: Python mutants die, and every UNCAUGHT mutant lived
    in a workflow `if:`, a step, or a call site. Mutate each of those here, one at a time."""
    workflow = _load_workflow(SWEEP_WORKFLOW)
    chk("seam: the workflow declares the sweep job (renaming or deleting it reds HERE, and the "
        "rest of this section still runs)",
        SWEEP_JOB in ((workflow or {}).get("jobs") or {}), True)
    job = _job_or_empty(workflow, SWEEP_JOB)
    steps = _steps(job)
    triggers = workflow.get("on", workflow.get(True)) or {}

    # --- the trigger ------------------------------------------------------------------------
    crons = [entry.get("cron") for entry in (triggers.get("schedule") or [])]
    chk("seam: the sweep is on a schedule (delete the cron and it only ever runs by hand)",
        len(crons), 1)
    # Derived DEFENSIVELY. `crons[0]` on an empty list raises, and a raise here does not just look
    # untidy: it aborts the ~30 seam assertions below, so the single mutant that deletes the cron
    # would mask every other seam regression behind it. Measured — the mutation run flagged exactly
    # this as a kill-by-exception.
    minutes = sorted(int(part) for part in str(crons[0]).split()[0].split(",")) if crons else []
    chk("seam: the cron fires TICKS_PER_HOUR times an hour — the number the drain arithmetic uses",
        len(minutes), TICKS_PER_HOUR)
    # THE MAP IS DERIVED, NOT WRITTEN DOWN (#1046). This assertion used to carry a hand-copied
    # list of every other lane's minutes — one of five copies, and it was already stale: it
    # claimed :00/:15/:30/:45 for dashboard after dashboard had moved off it, so it would have
    # walked the next schedule author straight into a collision while reading green. Now every
    # other lane's OWN schedule is read, so a repoint anywhere in the tree reds HERE.
    cron_map, schedule_map, map_error = _derived_schedule_map()
    others = {name: mins for name, mins in schedule_map.items() if name != SWEEP_WORKFLOW}
    # An unreachable floor when the module itself failed to load: a derivation that cannot report
    # its own floor must not be treated as having cleared one.
    lane_floor = getattr(cron_map, "MIN_SCHEDULED_LANES", 1 << 30)
    chk("seam: this script and the cron-map owner agree on where the workflows live — the path "
        "is written in both files, and two copies can be repointed together with neither redding",
        WORKFLOWS_DIR, getattr(cron_map, "WORKFLOWS_DIR", None))
    chk(f"seam: the cron map is DERIVED from the tree and saw both this lane and the rest of the "
        f"estate ({len(schedule_map)} lanes, floor {lane_floor}) — a thin checkout, a failed "
        "import or a failed parse yields one lane or none, and a collision check over an empty "
        "map is vacuously green",
        map_error or (len(schedule_map) >= lane_floor and SWEEP_WORKFLOW in schedule_map),
        True)
    chk("seam: the derived map agrees with this workflow's own parsed cron — two independent "
        "readings of the same schedule, so a map keyed or expanded wrongly reds instead of "
        "quietly comparing this lane against somebody else's minutes",
        sorted(schedule_map.get(SWEEP_WORKFLOW, [])), minutes)
    chk("seam: these minutes collide with NO other registry cron (derived; the collision is "
        "reported by lane and by minute)", cron_collisions(minutes, others), {})
    chk("seam: manual dispatch is available", "workflow_dispatch" in triggers, True)

    # --- the call site ------------------------------------------------------------------------
    sweep_steps = [s for s in steps if s.get("id") == SWEEP_STEP_ID]
    chk("seam: exactly one step with the sweep id", len(sweep_steps), 1)
    step = sweep_steps[0] if sweep_steps else {}
    tails = _invocations(step, "regate-sweep.py")
    chk("seam: the step calls this script twice — once `--self-test`, once live",
        (len(tails), tails[0] if tails else None), (2, ["--self-test"]))
    live = tails[-1] if len(tails) == 2 else []
    chk("seam: the LIVE call passes --apply (drop it and the sweeper silently degrades to a "
        "dry-run that reports a class it never clears)", "--apply" in live, True)
    chk("seam: the live call bounds the tick with --max-moves",
        live[live.index("--max-moves") + 1] if "--max-moves" in live else None,
        str(MAX_MOVES_PER_TICK))
    chk("seam: the live call passes --bot-slug, so the marker scan is restricted to markers this "
        "sweeper itself wrote", "--bot-slug" in live, True)
    # Passing the flag is not enough. An EMPTY slug flips marker_author_admitted to trusting every
    # author, which restores the denial-of-recovery this sweeper exists not to have. The guard that
    # refuses an empty slug is therefore part of the control, and deleting it must go red HERE.
    body = step.get("run") or ""
    chk("seam: the step REFUSES to run on an empty APP_SLUG — an empty slug silently re-enables "
        "the spoofable marker scan, so the mint failing open is a hard stop",
        [line.strip() for line in body.splitlines()
         if "APP_SLUG" in line and "-n" in line and "exit 1" in line],
        ["""[[ -n "${APP_SLUG:-}" ]] || { echo '::error::the App mint delivered no slug'; exit 1; }"""])
    chk("seam: APP_SLUG is bound to the mint's own slug output, not to a literal",
        {k: str(v) for k, v in (step.get("env") or {}).items()}.get("APP_SLUG"),
        "${{ steps.%s.outputs.app-slug }}" % TOKEN_STEP_ID)
    chk("seam: every flag the workflow passes is declared by this script's parser",
        sorted(f for f in live if f.startswith("--")
               if f not in ("--apply", "--dry-run", "--repo", "--repairs-file", "--max-moves",
                            "--lookback-hours", "--bot-slug", "--self-test")),
        [])

    # --- the TOKEN. A push made with `github.token` does not trigger `pull_request` workflows,
    # so wiring this to it would move every branch and re-run NOTHING. -----------------------
    env = {k: str(v) for k, v in (step.get("env") or {}).items()}
    chk("seam: the sweep step authenticates with the minted App token", "GH_TOKEN" in env, True)
    chk("seam: the sweep step does NOT use `github.token` — a GITHUB_TOKEN push does not trigger "
        "`pull_request`, so pr-gate would never re-run and every move would be a silent no-op",
        [k for k, v in env.items() if "github.token" in v or "secrets.GITHUB_TOKEN" in v], [])
    chk("seam: GH_TOKEN reads the App-token step's output",
        f"steps.{TOKEN_STEP_ID}.outputs.token" in env.get("GH_TOKEN", ""), True)
    mints = [s for s in steps if str(s.get("uses", "")).startswith(
        "actions/create-github-app-token@")]
    chk("seam: exactly one App-token mint", len(mints), 1)
    mint = mints[0] if mints else {}
    chk("seam: the mint is scoped to this repository only",
        ((mint.get("with") or {}).get("owner"), (mint.get("with") or {}).get("repositories")),
        ("jeswr", "agent-account-registry"))
    chk("seam: the mint grants contents:write (push the moved branch) and pull-requests:write "
        "(comment + de-label), and nothing else",
        sorted(k for k in (mint.get("with") or {}) if k.startswith("permission-")),
        ["permission-contents", "permission-pull-requests"])
    chk("seam: the mint is NOT continue-on-error — a sweep that silently loses its token is the "
        "invisible outage this issue is about", mint.get("continue-on-error"), None)

    # --- neutering ----------------------------------------------------------------------------
    chk("seam: no truthy `continue-on-error` at the job or any step level",
        [job.get("continue-on-error")] + [s.get("continue-on-error") for s in steps],
        [None] * (1 + len(steps)))
    chk("seam: the sweep job carries no `if:` that could silence it",
        job.get("if"), None)
    chk("seam: the sweep step body neither swallows failures nor disables errexit",
        [t for t in ("|| true", "set +e", "continue-on-error") if t in (step.get("run") or "")],
        [])
    chk("seam: the step sets `set -euo pipefail`", "set -euo pipefail" in (step.get("run") or ""),
        True)
    chk("seam: the job is the only one in the workflow, so nothing can gate it via `needs:`",
        sorted((workflow.get("jobs") or {})), [SWEEP_JOB])
    chk("seam: the workflow's top-level permissions are empty (every grant is per-job)",
        workflow.get("permissions"), {})
    chk("seam: the job runs in the default-branch-restricted secrets environment",
        job.get("environment"), "dispatch-secrets")
    chk("seam: concurrency serialises ticks WITHOUT cancelling one mid-move",
        (workflow.get("concurrency") or {}).get("cancel-in-progress"), False)

    # --- the checkout: the declaration must come from MASTER, never from a PR tree ------------
    checkouts = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
    chk("seam: exactly one checkout", len(checkouts), 1)
    first_checkout = checkouts[0] if checkouts else {}
    chk("seam: the checkout pins no `ref`, so the repair declaration is read from the default "
        "branch — a PR must not be able to declare ITSELF attributable",
        (first_checkout.get("with") or {}).get("ref"), None)
    chk("seam: the checkout does not persist credentials",
        (first_checkout.get("with") or {}).get("persist-credentials"), False)
    chk("seam: every file AND directory the self-test asserts against is in the job's sparse "
        "checkout, by exact per-line membership",
        sorted(_sparse_paths_or_empty(job)), sorted(REQUIRED_FILES + REQUIRED_DIRS))
    for path in REQUIRED_FILES:
        _require(path)
    for path in REQUIRED_DIRS:
        _require_dir(path)


if __name__ == "__main__":
    sys.exit(main())
