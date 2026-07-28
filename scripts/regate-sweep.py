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
# THAT CASE IS ACCEPTED DELIBERATELY, and this script does not call `--disable-auto`. Reasons, in
# order of weight: (1) the green it merges on is FRESH — computed against a base that contains the
# repair — so it is the opposite of #940's stale-green hazard; (2) a base move adds no author
# commits, so the diff the reviewer approved is byte-identical and only the SHA naming it changed;
# (3) it is exactly what the six hand-moves of #927 did, and what the maintainer recorded as the
# procedure — substance still applies, a fresh green is still required; (4) disarming has its own
# failure mode, because nothing re-arms a PR whose deliberate arm this stripped, which converts a
# transient red into a stall needing a human. What the script owes instead is VISIBILITY: a latched
# arm is detected, counted in the census as `latched-arm=N`, and named in the PR comment, so the
# merge that follows is never a surprise. If that trade is ever rejected the change is small and
# local — one auto-merge-off call in `_act` plus a census field — not a redesign.
#
# HOW THIS COMPOSES WITH #940. #940 is the DEFENSIVE half: at arm time, refuse a green `gate` that
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
#     cap 5 moves/tick x 3 ticks/hour (cron :09,:29,:49) = 15 PRs/hour of drain capacity
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

# Every file the self-test asserts against. The sweep job sparse-checks-out exactly this set and
# _test_selftest_inputs_are_checked_out asserts that it does: a trimmed checkout would make the
# YAML-seam assertions unreachable on the live path while still passing in pr-gate.
REQUIRED_FILES = (
    "scripts/regate-sweep.py",
    REPAIRS_FILE,
    SUITE_MANIFEST,
    SWEEP_WORKFLOW,
)


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
def _gh(args, runner=None):
    """Run `gh <args>` -> (rc, stdout). Never raises.

    Sanitized: only the subcommand words and the return code are ever printed. `GH_DEBUG=api`
    echoes request bodies into stderr, so stderr is never surfaced."""
    if runner is not None:
        return runner(args)
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


LATCHED_ARM_NOTE = (
    "\n\n**This PR already had auto-merge armed, and moving the head did NOT retract that.** "
    "`review:pass` is consulted when DECIDING to arm; `enablePullRequestAutoMerge` holds the intent "
    "independently once latched, so this PR will merge when the fresh `gate` goes green. That is "
    "deliberate and is the opposite of the #940 hazard — the green it merges on is computed against "
    "a base containing the fix, and a base move adds no author commits, so the approved diff is "
    "byte-identical. It is also exactly what the six hand-moves in #927 did. Noted here rather than "
    "silently, and counted as `latched-arm` in this tick's census.")


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
            print(f"::warning::regate-sweep: #{number} had auto-merge ALREADY latched — removing "
                  "`review:pass` de-authorises a future arm but does not retract this one, so it "
                  "will merge on the fresh gate. Deliberate (the green is fresh, the diff is "
                  "unchanged); recorded on the PR and censused as latched-arm.")
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


def main(argv=None, runner=None):
    """The CLI entry point. `runner` exists so the self-test can exercise THIS function.

    It was at 0% line coverage until a coverage run said so: the CLI-flag gate proves each flag is
    DECLARED, not that it is wired, so a typo in the slug validation, in the `[bot]` login the
    marker scan depends on, or in the repairs-file read would have passed the whole suite and failed
    only in production."""
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
                      lookback_hours=args.lookback_hours,
                      bot_login=f"{args.bot_slug}[bot]" if args.bot_slug else "",
                      summary_path=os.environ.get("GITHUB_STEP_SUMMARY") or None)
    return sweeper.run()


# =============================================================================================
# self-test
# =============================================================================================
def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    _test_drain_arithmetic(chk)
    _test_failure_ledger(chk)
    _test_signature_matching(chk)
    _test_attribution(chk)
    _test_cap_and_ordering(chk)
    _test_repairs_declaration(chk)
    _test_live_sweep(chk)
    _test_entry_point(chk)
    _test_published_census(chk)
    _test_census(chk)
    _test_workflow_seam(chk)

    print("regate-sweep self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


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
        method = args[args.index("--method") + 1] if "--method" in args else "GET"
        prefix = f"/repos/{self.repo}"
        path = next((a for a in args if a.startswith(prefix)), "")
        tail = path[len(prefix):]
        if method == "PUT" and tail.endswith("/update-branch"):
            number = int(tail.split("/")[2])
            return (1, "") if number in self.refuse_update else (0, "{}")
        if method in ("POST", "DELETE"):
            return 0, "{}"
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
        raise AssertionError(f"unexpected FakeGh request: {method} {tail}")

    def updated(self):
        return sorted(int(re.search(r"/pulls/(\d+)/update-branch", " ".join(c)).group(1))
                      for c in self.calls
                      if "--method" in c and c[c.index("--method") + 1] == "PUT")

    def deleted_labels(self):
        return [c[-1] for c in self.calls
                if "--method" in c and c[c.index("--method") + 1] == "DELETE"]


REPAIR_DETAIL = {"merged_at": "2026-07-28T02:26:49Z", "merge_commit_sha": "f" * 40,
                 "base": {"ref": DEFAULT_BRANCH}}
NOW = parse_rfc3339("2026-07-28T02:30:00Z")


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


def _test_live_sweep(chk):
    """THE REPLAY. Tonight's case end-to-end through the live path, PAIRED WITH THE CONTROL."""
    gh, sweeper = _fixture()
    chk("live: the tick exits 0", sweeper.run(), 0)
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
        "own-merits:1" in sweeper.rows[0], True)
    chk("live: the census names the class and the move", "class=1 moved=1" in sweeper.rows[0], True)

    # IDEMPOTENCE, twice over: by marker, and by the head now containing the fix.
    gh2, sweeper2 = _fixture(comments={903: [MARKER.format(repair=917, head="a" * 40)]})
    sweeper2.run()
    chk("idempotence: a PR already swept for THIS repair is not moved again",
        gh2.updated(), [])
    chk("idempotence: it is censused as already-swept, not silently dropped",
        "already-swept=1" in sweeper2.rows[0], True)
    spoof = {"body": MARKER.format(repair=917, head="a" * 40), "user": {"login": "someone-else"}}
    gh2b, sweeper2b = _fixture(comments={903: [spoof]})
    sweeper2b.run()
    chk("idempotence: a marker posted by ANYONE ELSE does not suppress the sweep — an "
        "unrestricted marker scan is a denial of recovery, not an idempotence key",
        gh2b.updated(), [903])
    gh2c, sweeper2c = _fixture(comments={903: [spoof]}, bot_login="")
    sweeper2c.run()
    chk("idempotence: with NO known bot login the polarity flips to trusting every marker — a "
        "missed move is safe and retried, a repeated move is not",
        gh2c.updated(), [])

    gh3, sweeper3 = _fixture(comments={903: [MARKER.format(repair=999, head="a" * 40)]})
    sweeper3.run()
    chk("idempotence: a marker for a DIFFERENT repair does not suppress this one",
        gh3.updated(), [903])
    gh4, sweeper4 = _fixture()
    gh4.contains["a" * 40] = True
    sweeper4.run()
    chk("idempotence: once the head contains the fix the PR leaves the class on its own",
        (gh4.updated(), "already-contains-fix:1" in sweeper4.rows[0]), ([], True))

    # A failed READ is its own state. Collapsing it into an evidence bucket would let a listing
    # outage read, in the census, as a population that WAS examined and found unattributable.
    gh4b, sweeper4b = _fixture()
    gh4b.contains["a" * 40] = None
    sweeper4b.run()
    chk("read-failure: an unreadable containment compare is censused as read-failed, never as an "
        "examined-and-refused PR", (gh4b.updated(), "read-failed:1" in sweeper4b.rows[0]),
        ([], True))
    gh4d, sweeper4d = _fixture()
    gh4d.logs[90164408722] = None          # the log REQUEST fails, rather than returning nothing
    sweeper4d.run()
    chk("read-failure: a FAILED log REQUEST is read-failed, not log-unavailable — an API outage "
        "must not be censused as an expired retention window",
        (gh4d.updated(), "read-failed:1" in sweeper4d.rows[0]), ([], True))
    gh4e, sweeper4e = _fixture()
    gh4e.logs[90164408722] = ""            # the request SUCCEEDS and yields nothing
    sweeper4e.run()
    chk("read-failure: a log request that succeeds and yields NOTHING is log-unavailable",
        (gh4e.updated(), "log-unavailable:1" in sweeper4e.rows[0]), ([], True))

    gh4c, sweeper4c = _fixture(refuse_comment_reads=True)
    sweeper4c.run()
    chk("read-failure: an unreadable MARKER listing refuses the move — reading it as 'not swept' "
        "would move a head this tick cannot prove it has not already moved",
        (gh4c.updated(), "read-failed:1" in sweeper4c.rows[0]), ([], True))

    # THE CAP, on the live path.
    many = [_pr(n, head=f"{n:040x}", ref=f"fix/{n}") for n in (903, 923, 895, 893, 886, 856)]
    gh5 = FakeGh("jeswr/agent-account-registry", many,
                 gate_by_head={p["head"]["sha"]: [_gate()] for p in many},
                 logs={90164408722: _worker_live_log(f"{SIG}: 1 (want 0)")},
                 repair_detail=REPAIR_DETAIL)
    sweeper5 = Sweeper("jeswr/agent-account-registry", [dict(REPAIR)], runner=gh5, apply=True,
                       cap=MAX_MOVES_PER_TICK, clock=lambda: NOW, sleeper=lambda _s: None)
    sweeper5.run()
    chk("cap: six attributable PRs -> exactly MAX_MOVES_PER_TICK moved this tick",
        len(gh5.updated()), MAX_MOVES_PER_TICK)
    chk("cap: the residue is REPORTED, never dropped", "deferred-cap=1" in sweeper5.rows[0], True)

    # NEVER ARM.
    gh6, sweeper6 = _fixture(labels=[REVIEW_PASS_LABEL])
    sweeper6.run()
    chk("never-arm: moving the head REMOVES the arming label — the verdict was bound to a head "
        "that no longer exists", gh6.deleted_labels(),
        [f"/repos/jeswr/agent-account-registry/issues/903/labels/{REVIEW_PASS_LABEL}"])
    chk("never-arm: no merge/auto-merge/arming call is ever issued",
        [c for c in gh6.calls if any(w in " ".join(c) for w in ("merge\"", "/merge", "enablePull"))],
        [])
    gh7, sweeper7 = _fixture()
    sweeper7.run()
    chk("never-arm: a PR WITHOUT the arming label gets no label write at all",
        gh7.deleted_labels(), [])

    # DE-AUTHORISATION IS NOT DISARMING. Removing `review:pass` withdraws consent from a FUTURE arm
    # decision; a latched auto-merge is held by `enablePullRequestAutoMerge` and is never re-read.
    # That case is accepted (the green it merges on is fresh) but it must be VISIBLE.
    gh7b, sweeper7b = _fixture(labels=[REVIEW_PASS_LABEL],
                               auto_merge={"enabled_by": {"login": "someone"}})
    sweeper7b.run()
    chk("latched-arm: an ALREADY-armed PR is moved, counted and named — the head move does not "
        "retract auto-merge, so the census must not report this merge as unattended",
        ("latched-arm=1" in sweeper7b.rows[0], gh7b.updated()), (True, [903]))
    chk("latched-arm: no auto-merge-off / disable call is issued — the case is accepted, not "
        "silently disarmed",
        [c for c in gh7b.calls if any(w in " ".join(c)
                                      for w in ("auto_merge", "disable-auto", "DisableAuto"))], [])
    chk("latched-arm: an UNARMED moved PR reports zero, so the field cannot read as decoration",
        "latched-arm=0" in sweeper7.rows[0], True)
    # A MISSING `auto_merge` field is a third state. Reading it as "not armed" would let the control
    # stop reporting without anything saying so — the silent-default shape.
    chk("latched-arm: an ABSENT auto_merge field is unknown, not False",
        (latched_arm_state({}), latched_arm_state({"auto_merge": None}),
         latched_arm_state({"auto_merge": {"x": 1}})), (None, False, True))
    gh7c, sweeper7c = _fixture()
    for pull in gh7c.pulls:
        pull.pop("auto_merge")
    sweeper7c.run()
    chk("latched-arm: a payload with no auto_merge field censuses latched-arm-unknown instead of "
        "silently reporting zero armed PRs",
        ("latched-arm-unknown=1" in sweeper7c.rows[0], gh7c.updated()), (True, [903]))
    chk("latched-arm: and the unknown field is ABSENT when every payload carried auto_merge, so it "
        "cannot become permanent noise", "latched-arm-unknown" in sweeper7.rows[0], False)
    chk("latched-arm: the PR comment names the latched arm explicitly",
        LATCHED_ARM_NOTE[:40] in sweep_comment(917, "t", "t", "a" * 40, ("x",), latched_arm=True),
        True)
    chk("latched-arm: and says nothing when there is no latched arm",
        LATCHED_ARM_NOTE[:40] in sweep_comment(917, "t", "t", "a" * 40, ("x",)), False)

    # DRY RUN and failure handling.
    gh8, sweeper8 = _fixture(apply=False)
    chk("dry-run: exits 0", sweeper8.run(), 0)
    chk("dry-run: issues no write of any kind",
        [c for c in gh8.calls if "--method" in c], [])
    gh9, sweeper9 = _fixture(refuse_update=(903,))
    chk("failure: a refused update-branch makes the tick exit NON-ZERO", sweeper9.run(), 1)
    chk("failure: and is censused as move-failed", "move-failed=1" in sweeper9.rows[0], True)
    gh10, sweeper10 = _fixture(ref_moves=False)
    sweeper10.run()
    chk("head-lag: an unconfirmed ref is reported, not retried (update-branch answers 202)",
        "head-confirmed=0/1" in sweeper10.rows[0], True)

    # The repair itself must be live.
    gh11, sweeper11 = _fixture()
    gh11.repair_detail = {**REPAIR_DETAIL, "merged_at": None}
    sweeper11.run()
    chk("repair: an UNMERGED declared repair sweeps nobody and says so",
        (gh11.updated(), sweeper11.rows[0]), ([], repair_census_line(917, "repair-not-merged")))
    gh12, sweeper12 = _fixture()
    gh12.repair_detail = {**REPAIR_DETAIL, "merged_at": "2026-07-26T02:26:49Z"}
    sweeper12.run()
    chk("repair: a repair older than the lookback is inert",
        (gh12.updated(), sweeper12.rows[0]),
        ([], repair_census_line(917, "repair-outside-lookback")))
    gh14, _ = _fixture()
    sweeper14 = Sweeper("jeswr/agent-account-registry", [], runner=gh14, apply=True,
                        clock=lambda: NOW, sleeper=lambda _s: None)
    sweeper14.run()
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
        (sweeper15.run(), gh15.updated(), sweeper15.rows), (1, [], []))

    gh13, sweeper13 = _fixture()
    gh13.default_branch = "main"
    chk("repair: a default-branch drift FAILS CLOSED rather than moving branches onto a base it "
        "cannot name", isinstance(_raises(sweeper13.run), RegateSweepError), True)


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
    PINNED, because the defaults under test are read from them."""
    import tempfile
    repairs = json.dumps({"schema": 1, "repairs": [dict(REPAIR)]})
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        handle.write(repairs)
        path = handle.name
    repo = "jeswr/agent-account-registry"
    try:
        with _pinned_env():        # no GITHUB_REPOSITORY, no APP_SLUG, no step summary
            # A marker written by SOMEONE ELSE. If `main` mis-wires the slug into the login the
            # marker scan compares against, this PR is wrongly skipped and the sweep does nothing.
            spoof = {"body": MARKER.format(repair=917, head="a" * 40), "user": {"login": "nobody"}}
            gh, _ = _fixture(comments={903: [spoof]})
            code = main(["--repo", repo, "--repairs-file", path, "--bot-slug", BOT_SLUG,
                         "--max-moves", "5", "--apply"], runner=gh)
            chk("entry point: main() runs the sweep end to end and exits 0", code, 0)
            chk("entry point: main() wires --bot-slug through as `<slug>[bot]`, so a foreign marker "
                "is ignored and the attributable PR is still moved", gh.updated(), [903])

            gh2, _ = _fixture(comments={903: [{"body": MARKER.format(repair=917, head="a" * 40),
                                              "user": {"login": BOT_LOGIN}}]})
            main(["--repo", repo, "--repairs-file", path, "--bot-slug", BOT_SLUG, "--apply"],
                 runner=gh2)
            chk("entry point: and OUR OWN marker read through main() does suppress the move",
                gh2.updated(), [])

            gh3, _ = _fixture()
            main(["--repo", repo, "--repairs-file", path], runner=gh3)
            chk("entry point: main() DEFAULTS to dry-run — --apply is opt-in, so a mis-wired "
                "workflow cannot write", [c for c in gh3.calls if "--method" in c], [])

            for label, argv in (
                    ("a malformed --bot-slug", ["--repo", "o/r", "--repairs-file", path,
                                                "--bot-slug", "bad slug; rm -rf /"]),
                    ("a negative --max-moves", ["--repo", "o/r", "--repairs-file", path,
                                                "--max-moves", "-1"]),
                    ("neither --repo NOR $GITHUB_REPOSITORY", ["--repairs-file", path])):
                chk(f"entry point: {label} exits 2 rather than sweeping",
                    _exit_code(lambda a=argv: main(a, runner=_fixture()[0])), 2)

        # BOTH DIRECTIONS OF THE DEFAULT, each stating its environment instead of inheriting it.
        with _pinned_env(GITHUB_REPOSITORY=repo, APP_SLUG=BOT_SLUG):
            gh4, _ = _fixture(comments={903: [{"body": MARKER.format(repair=917, head="a" * 40),
                                              "user": {"login": BOT_LOGIN}}]})
            code = main(["--repairs-file", path, "--apply"], runner=gh4)
            chk("entry point: with $GITHUB_REPOSITORY set, --repo may be omitted and the sweep runs",
                code, 0)
            chk("entry point: and $APP_SLUG supplies --bot-slug, so OUR marker still suppresses — "
                "the env default is wired to the same login the flag builds",
                gh4.updated(), [])
        with _pinned_env(APP_SLUG="bad slug; rm -rf /", GITHUB_REPOSITORY=repo):
            chk("entry point: a malformed $APP_SLUG is rejected exactly like a malformed flag",
                _exit_code(lambda: main(["--repairs-file", path], runner=_fixture()[0])), 2)
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
        sweeper.run()
        written = open(path, encoding="utf-8").read()
        chk("published census: the row reaches the step summary, not only stdout",
            [line.strip() for line in written.splitlines() if line.strip().startswith("CENSUS")],
            [sweeper.rows[0]])
        chk("published census: it is headed, so a reader can find it", "### regate-sweep census"
            in written, True)
        gh2, sweeper2 = _fixture()
        sweeper2.summary_path = "/nonexistent-dir/summary.md"
        chk("published census: an unwritable summary path warns and does NOT fail the tick — the "
            "sweep already happened, and losing the receipt must not re-run it", sweeper2.run(), 0)
    finally:
        os.unlink(path)


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


def _steps(job):
    return job.get("steps") or []


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
    job = _job(workflow, SWEEP_JOB)
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
    chk("seam: the cron minutes do not collide with the other registry crons (dispatch 3/13/…, "
        "conflict-resolver 1/21/41, groom 7/22/37/52, metrics 11/26/41/56, dashboard */15)",
        sorted(set(minutes) & ({0, 15, 30, 45} | {1, 21, 41} | {7, 22, 37, 52}
                               | {11, 26, 41, 56} | set(range(3, 60, 10)))), [])
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
    chk("seam: every file the self-test asserts against is in the job's sparse checkout",
        sorted(_sparse_paths_or_empty(job)), sorted(REQUIRED_FILES))
    for path in REQUIRED_FILES:
        _require(path)


if __name__ == "__main__":
    sys.exit(main())
