#!/usr/bin/env python3
# Issue #86 / #940 (comment 5102313507): a DEAD AUTO-MERGE LATCH -- a pull request that is armed,
# mergeable, CLEAN, and whose required check is green, but which GitHub never enqueues.
#
# Measured incident, sparq-org/sparq#4617: mergeable=MERGEABLE, mergeStateStatus=CLEAN,
# gate=success, autoMergeRequest != null, review:pass bound to the live head -- and
# isInMergeQueue=false from the moment it was armed at 2026-07-27T21:20:19Z. ELEVEN HOURS.
# sparq merged nothing for 45 minutes with an EMPTY merge queue while it sat ready. A
# `--disable-auto` followed by a re-arm put it at queue position 1 within 25 seconds.
#
# WHY NOTHING NOTICED. `autoMergeRequest` and `isInMergeQueue` are MUTUALLY EXCLUSIVE: the latch
# is non-null only while waiting to enqueue and becomes null once the PR enters the queue. So:
#
#   autoMergeRequest != null                     OVER-counts  -- a dead latch scores armed forever
#   isInMergeQueue                               UNDER-counts -- misses everything still waiting
#   isInMergeQueue OR autoMergeRequest != null   correct for "in flight", but cannot tell a LIVE
#                                                latch from a DEAD one
#
# Every armed-census in this estate reported #4617 as healthy. This is the recurring shape: a
# failure that REMOVES an item from the population it would be counted in, rather than marking it
# bad. The discriminator is not the latch field at all -- it is TIME SINCE ELIGIBILITY.
#
# WHAT THIS DETECTS -- the SYMPTOM, never a theory of the cause. Issue #86 attributes the stall to
# arming inside the async `code_quality` eval window and #4617's dead latch carried
# mergeMethod=MERGE, but re-arming prints "The merge strategy for main is set by the merge queue"
# -- the queue overrides the method regardless. Both are CORRELATION. Nothing here encodes either.
#
# TWO SAFETY FACTS THAT SHAPE THE REMEDY (both measured, both load-bearing):
#
#  1. `gh pr merge --disable-auto` on a PR that IS in the queue does NOT dequeue it -- it returns
#     "is already queued to merge". The dequeue is a DIFFERENT mutation,
#     `dequeuePullRequest(input:{id: <PR node id>})`, which this script never calls and must never
#     learn to call.
#  2. A dequeue STRIPS THE VERDICT: `review:pass` -> `review:changes`, arm disabled, because
#     `removed_from_merge_queue` is routed as a change request regardless of cause. But a PR that
#     was never IN the queue cannot be removed from it, so `--disable-auto` + re-arm on a dead
#     latch is VERDICT-SAFE (confirmed on #4617: its labels were untouched throughout).
#
# Together those make the hazard STRUCTURALLY unreachable rather than merely avoided by a check:
# the only operation that can strip a verdict is one this script does not implement, and the
# worst case of losing the isInMergeQueue race is a no-op error from GitHub.
#
# GRACE PERIOD -- DERIVED FROM MEASUREMENT, NOT TASTE. See `MEASURED_*` below.
#
# This script NEVER writes a human-terminal label (`needs:user` and friends). A human-only exit
# turns a transient outage into a permanent stall, which is the failure class this mechanism
# exists to end. Its only escalation is a red run plus a census row.
import argparse
import ast
import calendar
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------------------------
# Measured anchor (2026-07-28), sparq-org/sparq, the 300 most recently merged PRs.
#
# The NAIVE anchor -- auto_merge_enabled -> added_to_merge_queue -- is worthless: it is dominated
# by CI duration (measured p50 1226 s, p90 6495 s), because the latch only enqueues once the
# required check goes green. The anchor that actually bounds a dead latch is
#
#     eligible_at = max(auto_merge_enabled_at, gate_success_at)   ->   added_to_merge_queue
#
# Two instrument bugs were found and fixed while deriving this, both failing toward "nothing to
# report", both caught only by validating the instrument against a KNOWN answer (#4617) first:
#   (a) every merged PR emits RemovedFromMergeQueueEvent AT MERGE TIME, so excluding on its mere
#       presence excluded 100% of the population;
#   (b) merge-queue group CI reports a SECOND `gate` check-run against the PR head sha, so taking
#       max(success) picked a run AFTER the enqueue and pushed eligibility past it.
# A third artefact shapes the population: GitHub emits NO second AutoMergeEnabledEvent when a
# latch is re-enabled, so any PR disarmed before its enqueue has an UNOBSERVABLE arm time and
# cannot measure this quantity at all. Those 60 rows are excluded rather than believed.
#
# Retained healthy population N=188:
#     min 1 s | p50 2 s | p90 2 s | p95 2 s | p99 14 s | MAX 17 s
#     histogram: 1 s x56, 2 s x123, 3 s x6, 14 s x1, 16 s x1, 17 s x1   (98.4% within 3 s)
# Against that, the two pathologies are not close: #4074 at 1206 s and #4617 at 40844 s.
MEASURED_SAMPLE_SIZE = 188
MEASURED_MAX_ELIGIBLE_TO_ENQUEUE_SECONDS = 17

# 900 s = 15 min = 52.9x the observed maximum. Four reasons it is 900 and not the 30x (510 s) a
# sibling watchdog used:
#  1. The measured population is MERGED PRs, so by construction it cannot contain a legitimate
#     wait that never resolved. A wide multiple covers legitimate waits the sample cannot show.
#  2. sparq's ruleset sets merge_queue.min_entries_to_merge_wait_minutes = 5 (300 s). Any grace
#     period must clear that CONFIGURED wait by a wide margin or ordinary queue batching reads as
#     a dead latch. 900 s is 3x it; 510 s would be 1.7x.
#  3. Issue #86 proposed 15-20 min by taste. The measurement corroborates the low end of that
#     estimate rather than contradicting it, so nothing is being silently retuned.
#  4. Cost asymmetry. The two real incidents stalled 20 min and 11.35 h. Tightening 900 -> 510
#     recovers 6.5 minutes of an eleven-hour stall -- negligible -- while widening false-positive
#     exposure against a distribution whose tail is only three samples deep.
DEFAULT_GRACE_SECONDS = 900

# Bounded, and CONSUMED ONCE PER HEAD: every action posts a durable marker comment first, and the
# count of markers for the CURRENT head sha is the whole budget. Two lets one rescue be completed
# by one orphan re-arm (see `classify`); it does not let a PR be re-armed in a loop.
DEFAULT_MAX_ACTIONS_PER_HEAD = 2
# Blast radius per run, independent of the per-head budget.
DEFAULT_MAX_ACTIONS_PER_RUN = 5

MARKER_PREFIX = "<!-- latch-watchdog:v1"
SELF_ID = "> 🤖 SPARQ agent — latch-watchdog"

# Labels that WITHDRAW authorisation. Issue #151 recorded the mirror-image bug: human-hold labels
# disabling the stale-arm safety invariant, i.e. a hold suppressing a DISARM. Here the polarity is
# the safe one -- a hold suppresses a RE-ARM. Refusing to act on a held PR can only leave it
# where it already is, and it still gets a census row, so it never leaves the population.
DEFAULT_DENY_LABELS = (
    "review:changes", "review:needs-user", "review:parked", "needs:user", "hold", "do-not-merge",
)
# Authorisation is RE-DERIVED at action time, never inherited from the fact that a latch exists.
# Removing `review:pass` does NOT retract a GitHub auto-merge latch (the arm is a CAS evaluated
# once), so an armed PR is not by itself evidence that the estate still authorises its merge.
DEFAULT_REQUIRE_LABEL = "review:pass"

# `gate` is the ONLY required status check on both repos (sparq-org/sparq ruleset 17688455 and
# jeswr/agent-account-registry classic protection). Matched by EQUALITY -- never a prefix and
# never a substring, or `gate-optional` would satisfy `gate`.
DEFAULT_REQUIRED_CHECK = "gate"


def _load_gh_retry():
    """The shared retry policy. Import-first by PATH -- the module name has no hyphen but its
    siblings do, so every script in this tree loads helpers this way."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gh_retry.py")
    spec = importlib.util.spec_from_file_location("registry_gh_retry_for_latch", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load shared gh retry policy")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------------------------
# Pure core.
# ---------------------------------------------------------------------------------------------
def eligible_at(pr):
    """When this PR last became eligible to enqueue -- the anchor the grace period ages.

    max() of three stamps, and each one matters:
      - `auto_merge_enabled_at`: armed after the check went green (issue #86's window).
      - `gate_success_at`: green after it was armed (the ordinary case -- 187 of the 188 measured
        healthy rows are gate-bound).
      - `last_action_at`: OUR own last rescue. GitHub emits no second AutoMergeEnabledEvent on a
        re-arm, so `enabledAt` may still report the ORIGINAL arm after we have already rescued the
        PR; without this term the very next tick would re-derive the same stale age and act again.
    Returns None when nothing is datable -- which `classify` treats as ineligible, never as old.
    """
    gate = pr.get("gate") or {}
    stamps = [t for t in (pr.get("auto_merge_enabled_at"),
                          gate.get("latest_success_at"),
                          pr.get("last_action_at")) if t is not None]
    return max(stamps) if stamps else None


def classify(pr, now, *, grace_seconds, required_check,
             deny_labels, require_label, max_actions_per_head):
    """Pure verdict for one PR. Returns (action, reason).

    action is one of:
      "skip"          -- reason says why; ALWAYS censused
      "need-gate"     -- caller must fetch the required check at the head sha and re-classify
      "need-markers"  -- caller must fetch this script's marker comments and re-classify
      "rescue"        -- dead latch: disable-auto, then re-arm
      "rearm-only"    -- we already disarmed this head and the re-arm did not take; just re-arm

    The two "need-*" results make every API read DEMAND-DRIVEN: a 92-PR repo costs one list call
    per tick, and the per-PR reads are paid only for the handful that survive the cheap guards.

    GUARD ORDER IS LOAD-BEARING and every reason token is unique. Adding an EARLIER guard can
    silently vacate a later guard's test, so each fixture in the self-test is valid in every
    respect except the one under test, and the sweep is re-run for everything downstream.
    """
    # (1) THE SAFETY GUARD, and it dominates everything. A PR inside the merge queue is working
    # exactly as intended; touching it risks the one operation that strips a verdict. First, so
    # that no later condition -- however green, however old -- can reach a queued PR.
    if pr.get("is_in_merge_queue"):
        return "skip", "in-merge-queue"
    if pr.get("is_draft"):
        return "skip", "draft"
    # (3)(4) Fail CLOSED on anything that is not an explicit healthy value. GitHub reports
    # mergeable=UNKNOWN while it recomputes the merge ref; UNKNOWN is not MERGEABLE, and a PR
    # whose state we cannot read is not a PR we may act on.
    mergeable = pr.get("mergeable")
    if mergeable != "MERGEABLE":
        return "skip", "not-mergeable:%s" % (mergeable or "MISSING")
    state = pr.get("merge_state_status")
    if state != "CLEAN":
        return "skip", "not-clean:%s" % (state or "MISSING")

    # (5) The required check, BY EQUALITY, at the live head sha. CLEAN already implies the
    # protection is satisfied, but a mergeStateStatus is a summary computed by GitHub at an
    # unknown time; this re-derives the fact from the check-runs themselves.
    gate = pr.get("gate")
    if gate is None:
        return "need-gate", "need-gate"
    if gate.get("name") != required_check:
        return "skip", "gate-name-mismatch:%s" % (gate.get("name") or "MISSING")
    if gate.get("total", 0) <= 0:
        return "skip", "gate-absent"
    if gate.get("incomplete", 0) > 0:
        return "skip", "gate-incomplete"
    if gate.get("failed", 0) > 0:
        return "skip", "gate-failed"
    if gate.get("latest_success_at") is None:
        return "skip", "gate-no-success-timestamp"

    # (6)(7) Authorisation, re-derived now.
    labels = set(pr.get("labels") or ())
    held = sorted(labels & set(deny_labels))
    if held:
        return "skip", "held:%s" % held[0]
    if require_label and require_label not in labels:
        return "skip", "authorisation-not-re-derivable"

    # (8)(9) Sustained beyond the grace period. THE PAIRED CONTROL lives here: a PR that is a
    # perfect dead latch in every other respect but is still inside its grace window is
    # legitimately waiting, and must be left alone.
    # The gate-success-timestamp guard above is what makes this datable -- it is the only stamp
    # guaranteed non-None by the time control reaches here, so eligible_at() cannot return None.
    # There is deliberately NO `since is None` branch: it measured as unreachable under line
    # coverage, and an unreachable defensive branch is a branch no test can ever pin.
    age = now - eligible_at(pr)
    if age < grace_seconds:
        return "skip", "within-grace"

    # (10) Bounded and consumed once per head. Checked BEFORE the armed/unarmed split so both
    # action kinds share one budget and neither can loop.
    markers = pr.get("markers_for_head")
    if markers is None:
        return "need-markers", "need-markers"
    if markers >= max_actions_per_head:
        return "skip", "action-budget-exhausted"

    # (10a) NO MERGE QUEUE ON THE BASE REF -> DETECT, BUT DO NOT ACT.
    # The remedy is disarm-then-relatch, and GitHub REFUSES `enablePullRequestAutoMerge`
    # outright while a PR reads clean status ("Pull request is in clean status") -- which
    # every PR reaching this line does, because (4) above requires CLEAN. On a queue-enabled
    # base the latch is still meaningful (the PR is not immediately mergeable; it must
    # traverse the queue) and GitHub accepts it. On a base with NO queue the relatch cannot
    # succeed, so acting would disarm a PR and then fail to re-arm it -- converting a dead
    # latch into an UNARMED PR, which is strictly worse than what we found.
    # This is the guard that also makes `is_in_merge_queue` non-vacuous: without it that
    # field is False by construction wherever there is no queue.
    # The population is still CENSUSED so the gap is visible rather than silently dropped;
    # a base without a queue needs a different remedy, which this tool does not have.
    if not pr.get("is_merge_queue_enabled"):
        return "skip", "no-merge-queue-on-base:cannot-relatch"

    if pr.get("auto_merge_enabled_at") is not None:
        return "rescue", "dead-latch"
    # Unarmed, but we hold a marker for THIS head: our own disarm landed and the re-arm did not.
    # Without this branch a failed re-arm would drop the PR out of the population entirely --
    # converting a visible stall into an invisible one, which is the bug this file exists to fix.
    if markers > 0:
        return "rearm-only", "orphaned-disarm"
    # Unarmed and never touched by us. Not a dead latch: nothing was ever latched. Arming an
    # unarmed PR is a different mechanism with a different owner (registry #447) and this script
    # must not silently become it.
    return "skip", "not-armed"


def new_census(repo):
    return {"repo": repo, "considered": 0, "rescued": 0, "rearmed": 0,
            "budget_exhausted": 0, "errors": 0, "skipped": {}}


def census_note(row, reason):
    row["skipped"][reason] = row["skipped"].get(reason, 0) + 1


def aggregate_census(rows):
    total = {key: sum(row[key] for row in rows)
             for key in ("considered", "rescued", "rearmed", "budget_exhausted", "errors")}
    skipped = {}
    for row in rows:
        for key, count in row["skipped"].items():
            skipped[key] = skipped.get(key, 0) + count
    total["repos"] = len(rows)
    total["skipped"] = dict(sorted(skipped.items()))
    return total


def render_census_summary(rows, total):
    """Markdown for $GITHUB_STEP_SUMMARY -- the operator-facing form of the census."""
    lines = [
        "### latch-watchdog census",
        "",
        "| repo | considered | rescued | re-armed | budget exhausted | errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in [*rows, {**total, "repo": "**all %d repo(s)**" % total["repos"]}]:
        lines.append("| %s | %s | %s | %s | %s | %s |"
                     % (row["repo"], row["considered"], row["rescued"], row["rearmed"],
                        row["budget_exhausted"], row["errors"]))
    if total["skipped"]:
        lines += ["", "Skip reasons:", ""]
        lines += ["- `%s`: %d" % (key, count) for key, count in total["skipped"].items()]
    return "\n".join(lines) + "\n"


def marker_body(head_sha, action, grace_seconds, age_seconds, run_url):
    """The durable record of one action. Posted BEFORE the mutation, so a crash between the
    comment and the disarm leaves an over-count (harmless: it only spends budget) rather than an
    under-count (which would let the budget be exceeded)."""
    return (
        "%s head=%s action=%s -->\n" % (MARKER_PREFIX, head_sha, action)
        + "%s (issue #86)\n\n" % SELF_ID
        + "This PR's auto-merge latch was **armed and eligible for %d s** (grace %d s) but the "
          "PR was not in the merge queue: `mergeable=MERGEABLE`, `mergeStateStatus=CLEAN`, "
          "required check green at `%s`, `isInMergeQueue=false`.\n\n"
          % (int(age_seconds), int(grace_seconds), head_sha)
        + "That is a **dead auto-merge latch** — the latch and the queue are mutually exclusive "
          "states, so an armed-but-unqueued PR reads as healthy to every armed-census. Action: "
          "`%s` (disable-auto then re-arm with the latch's own merge method). This PR was never "
          "in the queue, so nothing is being dequeued and the review verdict is untouched.\n\n"
          % action
        + "Run: %s\n" % (run_url or "(local)")
    )


# ---------------------------------------------------------------------------------------------
# GitHub IO. Reads go through the shared retry policy; MUTATIONS never do (gh_retry's hard scope
# rule -- a retried write is a repeated write).
# ---------------------------------------------------------------------------------------------
# The ONLY remediation verb this tool may use. See Watchdog.rearm for why `gh pr merge --auto`
# is not an option here, and `worker-pr.py` ARM_AUTO_MERGE_MUTATION for the estate-wide rule.
# `%s` is the merge method, restricted by the caller to the three GitHub accepts.
REARM_MUTATION = (
    "mutation($pr:ID!,$oid:GitObjectID!){"
    "enablePullRequestAutoMerge(input:{pullRequestId:$pr,expectedHeadOid:$oid,"
    "mergeMethod:%s}){clientMutationId}}")

OPEN_PR_QUERY = """
query($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: 50, after: $cursor,
                 orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        id number url isDraft isInMergeQueue isMergeQueueEnabled mergeable mergeStateStatus
        headRefOid
        autoMergeRequest { enabledAt mergeMethod }
        labels(first: 60) { nodes { name } }
      }
    }
  }
}
"""


def parse_iso(text):
    """GitHub timestamps are always Z-suffixed UTC. Returns epoch seconds, or None.

    `calendar.timegm`, deliberately, not `time.mktime(...) - time.timezone`: mktime interprets a
    struct_time as LOCAL time and guesses DST, so the latter is correct only on a UTC host. The
    runner is UTC and every test here would agree with it -- which is exactly why the bug would
    survive. Ages drive the grace period, so an hour of DST skew is a real false positive.
    """
    if not text:
        return None
    try:
        return float(calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")))
    except (ValueError, TypeError):
        return None


class Watchdog:
    def __init__(self, *, apply_changes, grace_seconds, required_check, deny_labels,
                 require_label, max_actions_per_head, max_actions_per_run, marker_actor,
                 run_url="", summary_path=None, clock=None, gh_read=None, gh_write=None):
        self.apply_changes = apply_changes
        self.grace_seconds = grace_seconds
        self.required_check = required_check
        self.deny_labels = tuple(deny_labels)
        self.require_label = require_label
        self.max_actions_per_head = max_actions_per_head
        self.max_actions_per_run = max_actions_per_run
        self.marker_actor = marker_actor
        self.run_url = run_url
        self.summary_path = summary_path
        # None sentinels resolved at CALL time. A `def __init__(..., clock=time.time)` default
        # binds at DEFINITION time, which silently defeats injection in a self-test; the AST
        # sweep in block (p) asserts this module never grows one.
        self._clock = clock
        self._gh_read = gh_read
        self._gh_write = gh_write
        self.actions = 0
        self.errors = []
        self.census = []

    def now(self):
        return (self._clock or time.time)()

    def gh_read(self, args, token):
        return (self._gh_read or self._default_read)(args, token)

    def gh_write(self, args, token):
        return (self._gh_write or self._default_write)(args, token)

    def _env(self, token):
        env = dict(os.environ)
        if token:
            env["GH_TOKEN"] = token
        env.pop("GH_DEBUG", None)
        return env

    def _default_read(self, args, token):
        # `run_gh` executes `["gh", *args]` -- it prepends the binary ITSELF. So every argv handed
        # to gh_read starts at the SUBCOMMAND ("api", ...), never at "gh". Passing "gh" too runs
        # `gh gh api ...` -> `unknown command "gh" for "gh"` -> rc=1 on every read, which is
        # exactly how this tool failed 16/16 runs (#1137). The write seam is the opposite: it
        # execs the argv verbatim, so `_default_write` argvs DO carry "gh". Block (r) pins both.
        result = _load_gh_retry().run_gh(list(args), env=self._env(token))
        return result.returncode, result.stdout or ""

    def _default_write(self, args, token):
        result = subprocess.run(list(args), capture_output=True, text=True, env=self._env(token))
        return result.returncode, result.stdout or ""

    # -- reads ---------------------------------------------------------------------------------
    def list_open_prs(self, repo, token):
        owner, name = repo.split("/", 1)
        records, cursor = [], None
        while True:
            args = ["api", "graphql", "-f", "query=" + OPEN_PR_QUERY,
                    "-F", "owner=" + owner, "-F", "name=" + name]
            if cursor:
                args += ["-F", "cursor=" + cursor]
            code, out = self.gh_read(args, token)
            if code != 0:
                raise RuntimeError("open-PR listing failed for %s (rc=%d)" % (repo, code))
            page = json.loads(out)["data"]["repository"]["pullRequests"]
            for node in page["nodes"]:
                auto = node.get("autoMergeRequest") or {}
                records.append({
                    "repo": repo,
                    "number": node["number"],
                    "url": node["url"],
                    "head_sha": node["headRefOid"],
                    "is_draft": bool(node["isDraft"]),
                    "node_id": node["id"],
                    "is_in_merge_queue": bool(node["isInMergeQueue"]),
                    # The BASE ref's queue, not this PR's membership of it. Load-bearing:
                    # see the no-merge-queue guard in classify().
                    "is_merge_queue_enabled": bool(node["isMergeQueueEnabled"]),
                    "mergeable": node["mergeable"],
                    "merge_state_status": node["mergeStateStatus"],
                    "auto_merge_enabled_at": parse_iso(auto.get("enabledAt")),
                    "auto_merge_method": auto.get("mergeMethod"),
                    "labels": [lab["name"] for lab in node["labels"]["nodes"]],
                    "gate": None,
                    "markers_for_head": None,
                    "last_action_at": None,
                })
            if not page["pageInfo"]["hasNextPage"]:
                return records
            cursor = page["pageInfo"]["endCursor"]

    def fetch_gate(self, pr, token):
        """The required check at the EXACT head sha. A force-push leaves a real pass latched to a
        superseded head, so this is queried per-commit and never read off the PR rollup."""
        args = ["api", "repos/%s/commits/%s/check-runs?check_name=%s&per_page=100"
                % (pr["repo"], pr["head_sha"], self.required_check)]
        code, out = self.gh_read(args, token)
        if code != 0:
            raise RuntimeError("check-run read failed for %s#%d (rc=%d)"
                               % (pr["repo"], pr["number"], code))
        runs = json.loads(out).get("check_runs", [])
        # EQUALITY, applied here and not left to the server-side filter: `check_name=` is a query
        # parameter whose semantics we do not control, and a prefix match would let a check named
        # `gate-optional` stand in for `gate`.
        named = [r for r in runs if r.get("name") == self.required_check]
        successes = sorted(parse_iso(r.get("completed_at")) or 0.0
                           for r in named if r.get("conclusion") == "success")
        return {
            "name": self.required_check,
            "total": len(named),
            "incomplete": sum(1 for r in named if r.get("status") != "completed"),
            "failed": sum(1 for r in named
                          if r.get("status") == "completed"
                          and r.get("conclusion") not in ("success", "neutral", "skipped")),
            "latest_success_at": successes[-1] if successes else None,
        }

    def fetch_markers(self, pr, token):
        """Count OUR OWN prior actions on this head. Comments on a public repo are written by
        anyone, so the author is filtered by exact login equality against the actor the workflow
        minted -- a marker is only evidence when we know who wrote it. Logins are globally unique
        and unforgeable, which is what makes the equality sound."""
        args = ["api", "repos/%s/issues/%d/comments?per_page=100"
                % (pr["repo"], pr["number"]), "--paginate"]
        code, out = self.gh_read(args, token)
        if code != 0:
            raise RuntimeError("comment read failed for %s#%d (rc=%d)"
                               % (pr["repo"], pr["number"], code))
        needle = "%s head=%s" % (MARKER_PREFIX, pr["head_sha"])
        stamps = []
        for comment in json.loads(out):
            if (comment.get("user") or {}).get("login") != self.marker_actor:
                continue
            if needle not in (comment.get("body") or ""):
                continue
            stamps.append(parse_iso(comment.get("created_at")) or 0.0)
        return len(stamps), (max(stamps) if stamps else None)

    # -- writes --------------------------------------------------------------------------------
    def post_marker(self, pr, action, age, token):
        body = marker_body(pr["head_sha"], action, self.grace_seconds, age, self.run_url)
        code, _ = self.gh_write(["gh", "pr", "comment", str(pr["number"]),
                                 "--repo", pr["repo"], "--body", body], token)
        if code != 0:
            raise RuntimeError("marker comment failed for %s#%d (rc=%d)"
                               % (pr["repo"], pr["number"], code))

    def disarm(self, pr, token):
        code, _ = self.gh_write(["gh", "pr", "merge", str(pr["number"]), "--repo", pr["repo"],
                                 "--disable-auto"], token)
        if code != 0:
            raise RuntimeError("disable-auto failed for %s#%d (rc=%d)"
                               % (pr["repo"], pr["number"], code))

    def rearm(self, pr, token):
        """Re-latch via the RAW enablePullRequestAutoMerge MUTATION -- never `gh pr merge --auto`.

        THIS VERB CHOICE IS THE SAFETY PROPERTY, not a style preference. `gh pr merge --auto`
        does NOT reliably latch: in gh v2.94.0 `merge.go:530` computes
        `autoMerge = AutoMergeEnable && !isImmediatelyMergeable(mergeStateStatus)`, and
        `isImmediatelyMergeable("CLEAN")` is TRUE (`merge.go:763-769`), so `--auto` on a CLEAN
        PR yields `autoMerge=false`. `payload.auto` is forced back to true ONLY when the base
        ref has a merge queue (`merge.go:302` via `shouldAddToMergeQueue`, `:488`), and
        `http.go:88` then branches: `payload.auto` true -> `enablePullRequestAutoMerge`,
        false -> `MergePullRequest` -- an IMMEDIATE, IRREVERSIBLE MERGE.
        classify() requires CLEAN, so on any base without a merge queue every "re-arm" this
        tool issued would have been an unreviewed merge, while the marker comment it posts
        says it re-armed. That is the defect this function exists to not have.

        This is also the estate's standing rule, not a local judgement: `gh pr merge --auto`
        is banned repo-wide (`pr-gate.yml`, `worker-pr.py`) for exactly this reason, and the
        sanctioned primitive is this mutation -- see worker-pr.py's ARM_AUTO_MERGE_MUTATION.

        The mutation can ONLY ever latch. It cannot merge, at any gh version, on any repo
        shape, with any flag -- the safety no longer depends on a precondition steering an
        internal branch of a third-party CLI whose semantics have already changed once.
        `expectedHeadOid` carries the head CAS that `--match-head-commit` used to.
        """
        method = (pr.get("auto_merge_method") or "SQUASH").upper()
        if method not in ("SQUASH", "REBASE", "MERGE"):
            method = "SQUASH"
        code, _ = self.gh_write(
            ["gh", "api", "graphql",
             "-f", "query=" + REARM_MUTATION % method,
             "-F", "pr=%s" % pr["node_id"],
             "-F", "oid=%s" % pr["head_sha"]], token)
        if code != 0:
            raise RuntimeError("re-arm failed for %s#%d (rc=%d)"
                               % (pr["repo"], pr["number"], code))

    # -- drive ---------------------------------------------------------------------------------
    def verdict(self, pr, token):
        """classify() + the demand-driven reads it asks for. Returns (action, reason)."""
        for _ in range(3):
            action, reason = classify(
                pr, self.now(), grace_seconds=self.grace_seconds,
                required_check=self.required_check, deny_labels=self.deny_labels,
                require_label=self.require_label,
                max_actions_per_head=self.max_actions_per_head)
            if action == "need-gate":
                pr["gate"] = self.fetch_gate(pr, token)
                continue
            if action == "need-markers":
                pr["markers_for_head"], pr["last_action_at"] = self.fetch_markers(pr, token)
                continue
            return action, reason
        raise RuntimeError("classification did not converge for %s#%d"
                           % (pr["repo"], pr["number"]))

    def act(self, pr, action, age, token):
        # Marker FIRST: it is the durable record that bounds the budget and that lets an
        # orphaned disarm be found again next tick.
        self.post_marker(pr, action, age, token)
        if action == "rescue":
            self.disarm(pr, token)
        self.rearm(pr, token)

    def sweep_repo(self, repo, token):
        row = new_census(repo)
        try:
            if not token:
                census_note(row, "no-token-for-owner")
                return
            for pr in self.list_open_prs(repo, token):
                row["considered"] += 1
                try:
                    action, reason = self.verdict(pr, token)
                except (RuntimeError, ValueError, KeyError) as exc:
                    row["errors"] += 1
                    self.errors.append(str(exc))
                    print("::warning::latch-watchdog %s#%d: %s" % (repo, pr["number"], exc),
                          file=sys.stderr)
                    continue
                if action == "skip":
                    if reason == "action-budget-exhausted":
                        row["budget_exhausted"] += 1
                    census_note(row, reason)
                    print("SKIP %s#%d: %s" % (repo, pr["number"], reason))
                    continue
                age = self.now() - (eligible_at(pr) or self.now())
                if self.actions >= self.max_actions_per_run:
                    census_note(row, "run-budget-exhausted")
                    print("SKIP %s#%d: run-budget-exhausted" % (repo, pr["number"]))
                    continue
                print("%s %s#%d: %s (eligible %ds ago, grace %ds, head %s)"
                      % ("APPLY" if self.apply_changes else "DRY-RUN", repo, pr["number"],
                         reason, int(age), self.grace_seconds, pr["head_sha"]))
                if not self.apply_changes:
                    census_note(row, "dry-run")
                    continue
                try:
                    self.act(pr, action, age, token)
                except (RuntimeError, ValueError) as exc:
                    row["errors"] += 1
                    self.errors.append(str(exc))
                    print("::warning::latch-watchdog %s#%d: %s" % (repo, pr["number"], exc),
                          file=sys.stderr)
                    continue
                self.actions += 1
                row["rescued" if action == "rescue" else "rearmed"] += 1
        except (RuntimeError, ValueError, KeyError) as exc:
            row["errors"] += 1
            self.errors.append(str(exc))
            print("::error::latch-watchdog %s: %s" % (repo, exc), file=sys.stderr)
        finally:
            # A census row is emitted for EVERY repo on EVERY path -- success, error, and the
            # no-token path. A detector that goes quiet when it does nothing converts a visible
            # stall into an invisible one, which is the exact bug being fixed here.
            self.census.append(row)
            print("CENSUS " + json.dumps(row, separators=(",", ":"), sort_keys=True))

    def run(self, repos, tokens, budget_threshold):
        for repo in repos:
            self.sweep_repo(repo, tokens.get(repo.split("/", 1)[0]))
        total = aggregate_census(self.census)
        print("CENSUS-TOTAL " + json.dumps(total, separators=(",", ":"), sort_keys=True))
        print("SUMMARY mode=%s repos=%d rescued=%d rearmed=%d errors=%d"
              % ("apply" if self.apply_changes else "dry-run", total["repos"],
                 total["rescued"], total["rearmed"], total["errors"]))
        if self.summary_path:
            try:
                with open(self.summary_path, "a", encoding="utf-8") as handle:
                    handle.write(render_census_summary(self.census, total))
            except OSError as exc:
                print("::warning::latch-watchdog could not write the step summary: %s" % exc,
                      file=sys.stderr)
        if total["budget_exhausted"] > budget_threshold:
            # The population alarm a per-run exit code cannot otherwise express: a PR we have
            # already rescued to its per-head limit and which STILL is not in the queue. Loud and
            # machine-readable -- never a human-terminal label.
            print("::error::latch-watchdog left %d pull request(s) with an exhausted per-head "
                  "action budget still armed, eligible, and outside the merge queue"
                  % total["budget_exhausted"], file=sys.stderr)
        return 1 if (self.errors or total["budget_exhausted"] > budget_threshold) else 0


def parse_repos(text):
    return [item for item in (chunk.strip() for chunk in (text or "").split(",")) if item]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Detect and rescue dead auto-merge latches.")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--repos", default="")
    parser.add_argument("--marker-actor", default="")
    parser.add_argument("--grace-seconds", type=int, default=DEFAULT_GRACE_SECONDS)
    parser.add_argument("--required-check", default=DEFAULT_REQUIRED_CHECK)
    parser.add_argument("--require-label", default=DEFAULT_REQUIRE_LABEL)
    parser.add_argument("--max-actions-per-head", type=int,
                        default=DEFAULT_MAX_ACTIONS_PER_HEAD)
    parser.add_argument("--max-actions-per-run", type=int, default=DEFAULT_MAX_ACTIONS_PER_RUN)
    parser.add_argument("--budget-threshold", type=int, default=0)
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    repos = parse_repos(args.repos)
    if not repos:
        print("::error::latch-watchdog needs --repos", file=sys.stderr)
        return 1
    if args.apply and not args.marker_actor:
        print("::error::latch-watchdog needs --marker-actor to apply (a marker whose author we "
              "cannot verify is not evidence)", file=sys.stderr)
        return 1
    tokens = json.loads(os.environ.get("TARGET_GH_TOKENS") or "{}")
    watchdog = Watchdog(
        apply_changes=args.apply, grace_seconds=args.grace_seconds,
        required_check=args.required_check, deny_labels=DEFAULT_DENY_LABELS,
        require_label=args.require_label,
        max_actions_per_head=args.max_actions_per_head,
        max_actions_per_run=args.max_actions_per_run, marker_actor=args.marker_actor,
        run_url=os.environ.get("RUN_URL", ""),
        summary_path=os.environ.get("GITHUB_STEP_SUMMARY") or None)
    return watchdog.run(repos, tokens, args.budget_threshold)


# ---------------------------------------------------------------------------------------------
# Self-test.
# ---------------------------------------------------------------------------------------------
def _dead_latch(**over):
    """A PR that is a dead latch in EVERY respect. Each test mutates exactly ONE field of this,
    so a fixture is never accidentally rejected by a guard other than the one under test."""
    pr = {
        "repo": "sparq-org/latch-watchdog-fixture-repo", "number": 999000617, "url": "u",
        "head_sha": "cd0ca3f1786b95ef731245c6443123238068c6a3",
        "is_draft": False, "is_in_merge_queue": False,
        # A queue-enabled base: the ONLY shape this tool may act on, because the relatch
        # mutation is refused on a clean-status PR whose base has no queue. See classify (10a).
        "is_merge_queue_enabled": True,
        "node_id": "PR_kwFAKEFIXTUREnodeid",
        "mergeable": "MERGEABLE", "merge_state_status": "CLEAN",
        "auto_merge_enabled_at": 1000.0, "auto_merge_method": "MERGE",
        "labels": ["review:pass", "area:ci"],
        "gate": {"name": "gate", "total": 1, "incomplete": 0, "failed": 0,
                 "latest_success_at": 1300.0},
        "markers_for_head": 0, "last_action_at": None,
    }
    pr.update(over)
    return pr


def _verdict(pr, now, **over):
    kwargs = {"grace_seconds": DEFAULT_GRACE_SECONDS, "required_check": DEFAULT_REQUIRED_CHECK,
              "deny_labels": DEFAULT_DENY_LABELS, "require_label": DEFAULT_REQUIRE_LABEL,
              "max_actions_per_head": DEFAULT_MAX_ACTIONS_PER_HEAD}
    kwargs.update(over)
    return classify(pr, now, **kwargs)


class _FakeGh:
    """Records every argv it is handed. Reads are answered from a scripted table; anything a
    test did not script raises, so an unmodelled call cannot pass silently."""

    def __init__(self, reads=None, write_rc=None, read_rc=None):
        self.reads = reads or {}
        self.write_rc = write_rc or {}
        self.read_rc = read_rc or {}
        self.read_log = []
        self.write_log = []

    def read(self, args, token):
        self.read_log.append(list(args))
        for key, code in self.read_rc.items():
            if any(key in part for part in args):
                return code, ""
        for key, payload in self.reads.items():
            if any(key in part for part in args):
                # A list payload is a QUEUE -- successive calls get successive pages.
                if isinstance(payload, list):
                    return 0, payload.pop(0) if payload else "[]"
                return 0, payload
        raise AssertionError("unscripted gh read: %s" % (args,))

    def write(self, args, token):
        self.write_log.append(list(args))
        for key, code in self.write_rc.items():
            if any(key in part for part in args):
                return code, ""
        return 0, ""


def _fetch_one_pr(is_queue):
    """Drive the REAL open-PR fetch against a stubbed read, so the parse is exercised end to
    end rather than hand-built. Used to pin that isMergeQueueEnabled is actually consumed."""
    payload = json.dumps({"data": {"repository": {"pullRequests": {
        "pageInfo": {"hasNextPage": False, "endCursor": None},
        "nodes": [{"id": "PR_kwFPARSE", "number": 1, "url": "u", "isDraft": False,
                   "isInMergeQueue": False, "isMergeQueueEnabled": is_queue,
                   "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN", "headRefOid": "a",
                   "autoMergeRequest": None, "labels": {"nodes": []}}]}}}})
    fake = _FakeGh(reads={"query=": payload})
    dog = Watchdog(apply_changes=False, grace_seconds=DEFAULT_GRACE_SECONDS,
                   required_check="gate", deny_labels=DEFAULT_DENY_LABELS,
                   require_label="review:pass", max_actions_per_head=2, max_actions_per_run=5,
                   marker_actor="b[bot]", clock=lambda: 0.0,
                   gh_read=fake.read, gh_write=fake.write)
    return dog.list_open_prs("o/r", "t")[0]


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    # -- (a) THE RED TEST: a real dead latch, reconstructed from the measured #4617 state. -----
    # armed 21:20:19Z, gate green 21:25:43Z, never enqueued; observed 11.35 h later.
    dead = _dead_latch()
    chk("RED: an armed, CLEAN, gate-green, unqueued PR sustained past grace is a dead latch",
        _verdict(dead, 1300.0 + 40844), ("rescue", "dead-latch"))

    # -- (b) THE PAIRED CONTROL: identical in every respect, still inside the grace window. ----
    chk("CONTROL: the SAME PR one second inside the grace window is left alone",
        _verdict(_dead_latch(), 1300.0 + DEFAULT_GRACE_SECONDS - 1), ("skip", "within-grace"))
    chk("CONTROL: the boundary is inclusive -- exactly grace old is actionable",
        _verdict(_dead_latch(), 1300.0 + DEFAULT_GRACE_SECONDS)[0], "rescue")
    chk("CONTROL: the measured healthy maximum (17 s) is nowhere near actionable",
        _verdict(_dead_latch(), 1300.0 + MEASURED_MAX_ELIGIBLE_TO_ENQUEUE_SECONDS),
        ("skip", "within-grace"))

    # -- (c) THE SAFETY GUARD. A queued PR is untouchable, and it dominates every other signal. -
    chk("a PR IN the merge queue is never touched (dequeue is what strips a verdict)",
        _verdict(_dead_latch(is_in_merge_queue=True), 1e9), ("skip", "in-merge-queue"))
    chk("in-merge-queue dominates even an infinitely old, perfectly eligible PR",
        _verdict(_dead_latch(is_in_merge_queue=True, auto_merge_enabled_at=0.0), 1e12),
        ("skip", "in-merge-queue"))

    # -- (d) Fail CLOSED on every unreadable or unhealthy state. -------------------------------
    for value, reason in (("UNKNOWN", "not-mergeable:UNKNOWN"),
                          ("CONFLICTING", "not-mergeable:CONFLICTING"),
                          (None, "not-mergeable:MISSING")):
        chk("mergeable=%s does not admit" % value,
            _verdict(_dead_latch(mergeable=value), 1e9), ("skip", reason))
    for value, reason in (("UNKNOWN", "not-clean:UNKNOWN"), ("BLOCKED", "not-clean:BLOCKED"),
                          ("BEHIND", "not-clean:BEHIND"), (None, "not-clean:MISSING")):
        chk("mergeStateStatus=%s does not admit" % value,
            _verdict(_dead_latch(merge_state_status=value), 1e9), ("skip", reason))
    chk("a draft is never acted on", _verdict(_dead_latch(is_draft=True), 1e9), ("skip", "draft"))

    # -- (e) The required check, BY EQUALITY. --------------------------------------------------
    chk("an unfetched gate demands a read rather than admitting",
        _verdict(_dead_latch(gate=None), 1e9), ("need-gate", "need-gate"))
    chk("a check named gate-optional does NOT satisfy the `gate` requirement",
        _verdict(_dead_latch(gate={"name": "gate-optional", "total": 1, "incomplete": 0,
                                   "failed": 0, "latest_success_at": 1.0}), 1e9),
        ("skip", "gate-name-mismatch:gate-optional"))
    chk("zero gate runs at head does not admit",
        _verdict(_dead_latch(gate={"name": "gate", "total": 0, "incomplete": 0, "failed": 0,
                                   "latest_success_at": 1.0}), 1e9), ("skip", "gate-absent"))
    chk("an INCOMPLETE gate does not admit",
        _verdict(_dead_latch(gate={"name": "gate", "total": 2, "incomplete": 1, "failed": 0,
                                   "latest_success_at": 1.0}), 1e9), ("skip", "gate-incomplete"))
    chk("a FAILED gate does not admit",
        _verdict(_dead_latch(gate={"name": "gate", "total": 2, "incomplete": 0, "failed": 1,
                                   "latest_success_at": 1.0}), 1e9), ("skip", "gate-failed"))
    chk("a gate with no success timestamp cannot be aged, so it does not admit",
        _verdict(_dead_latch(gate={"name": "gate", "total": 1, "incomplete": 0, "failed": 0,
                                   "latest_success_at": None}), 1e9),
        ("skip", "gate-no-success-timestamp"))

    # -- (f) Authorisation is RE-DERIVED, never inherited from the latch's existence. ----------
    for held in DEFAULT_DENY_LABELS:
        chk("a %s hold suppresses the re-arm" % held,
            _verdict(_dead_latch(labels=["review:pass", held]), 1e9), ("skip", "held:%s" % held))
    chk("no review:pass -> authorisation cannot be re-derived, so no action",
        _verdict(_dead_latch(labels=["area:ci"]), 1e9),
        ("skip", "authorisation-not-re-derivable"))
    chk("an EMPTY require-label setting disables the positive check but not the deny list",
        (_verdict(_dead_latch(labels=[]), 1e9, require_label="")[0],
         _verdict(_dead_latch(labels=["hold"]), 1e9, require_label="")),
        ("rescue", ("skip", "held:hold")))

    # -- (g) The aging anchor. -----------------------------------------------------------------
    chk("eligibility is the LATER of arm and gate-green, not the arm alone",
        eligible_at(_dead_latch(auto_merge_enabled_at=1000.0)), 1300.0)
    chk("eligibility follows a LATE arm when the gate went green first",
        eligible_at(_dead_latch(auto_merge_enabled_at=9000.0)), 9000.0)
    chk("our own last action re-anchors the clock (GitHub emits no second AutoMergeEnabledEvent "
        "on a re-arm, so enabledAt can stay stale after we rescue)",
        eligible_at(_dead_latch(last_action_at=50000.0)), 50000.0)
    chk("a PR armed AFTER the gate is not actionable until ITS OWN grace elapses",
        _verdict(_dead_latch(auto_merge_enabled_at=1e6), 1e6 + 10), ("skip", "within-grace"))
    chk("nothing datable -> ineligible, never treated as infinitely old",
        _verdict(_dead_latch(auto_merge_enabled_at=None, last_action_at=None,
                             gate={"name": "gate", "total": 1, "incomplete": 0, "failed": 0,
                                   "latest_success_at": None}), 1e9),
        ("skip", "gate-no-success-timestamp"))

    # -- (h) Budget: bounded, consumed once per head, and it gates BOTH action kinds. ----------
    chk("markers are demanded before any action is authorised",
        _verdict(_dead_latch(markers_for_head=None), 1e9), ("need-markers", "need-markers"))
    chk("a head already actioned to its limit is refused",
        _verdict(_dead_latch(markers_for_head=DEFAULT_MAX_ACTIONS_PER_HEAD), 1e9),
        ("skip", "action-budget-exhausted"))
    chk("the budget binds the ORPHAN path too, so a failing re-arm cannot loop",
        _verdict(_dead_latch(auto_merge_enabled_at=None,
                             markers_for_head=DEFAULT_MAX_ACTIONS_PER_HEAD), 1e9),
        ("skip", "action-budget-exhausted"))
    chk("one prior action still leaves room for the orphan completion",
        _verdict(_dead_latch(markers_for_head=1), 1e9), ("rescue", "dead-latch"))

    # -- (i) The orphaned disarm -- the state that would otherwise become INVISIBLE. -----------
    chk("unarmed + our marker for THIS head = our disarm landed and the re-arm did not",
        _verdict(_dead_latch(auto_merge_enabled_at=None, markers_for_head=1,
                             last_action_at=1300.0), 1e9), ("rearm-only", "orphaned-disarm"))
    chk("unarmed with NO marker is not our business (arming unarmed PRs is registry #447)",
        _verdict(_dead_latch(auto_merge_enabled_at=None, markers_for_head=0), 1e9),
        ("skip", "not-armed"))
    # -- NO MERGE QUEUE ON THE BASE: detect, census, never act. --------------------------------
    # The relatch mutation is REFUSED by GitHub while a PR reads clean status, and classify
    # requires CLEAN -- so on a base without a queue the remedy cannot succeed. Acting would
    # disarm and then fail to re-arm, leaving the PR UNARMED: strictly worse than found.
    # This is also what makes `is_in_merge_queue` non-vacuous; without it that field is False
    # by construction exactly where there is no queue.
    chk("a dead latch on a base with NO merge queue is censused, never actioned",
        _verdict(_dead_latch(is_merge_queue_enabled=False), 1e9),
        ("skip", "no-merge-queue-on-base:cannot-relatch"))
    chk("the orphan path is refused on a no-queue base too",
        _verdict(_dead_latch(is_merge_queue_enabled=False, auto_merge_enabled_at=None,
                             markers_for_head=1), 1e9),
        ("skip", "no-merge-queue-on-base:cannot-relatch"))
    # ANTI-VACUITY: the SAME fixture on a queue-enabled base must still be actioned, or the
    # guard is just the watchdog switched off.
    chk("the identical dead latch IS actioned when the base has a queue",
        _verdict(_dead_latch(is_merge_queue_enabled=True), 1e9), ("rescue", "dead-latch"))
    # The guard sits AFTER the grace and budget checks, so it cannot mask them.
    chk("a no-queue base still reports within-grace first (guard ordering)",
        _verdict(_dead_latch(is_merge_queue_enabled=False), 1000.0), ("skip", "within-grace"))

    # The parse must READ the field: replacing it with a constant `True` re-opens the whole
    # defect while every classify test above still passes, because they set the field directly.
    chk("PARSE: is_merge_queue_enabled is read from the GraphQL payload, not assumed",
        [_fetch_one_pr(is_queue=False)["is_merge_queue_enabled"],
         _fetch_one_pr(is_queue=True)["is_merge_queue_enabled"]], [False, True])

    chk("an orphan that reached the queue on its own is left alone",
        _verdict(_dead_latch(auto_merge_enabled_at=None, markers_for_head=1,
                             is_in_merge_queue=True), 1e9), ("skip", "in-merge-queue"))

    # -- (j) The census ALWAYS emits, including the zero row. ----------------------------------
    empty = new_census("o/r")
    chk("a zero row is a real row", aggregate_census([empty])["repos"], 1)
    chk("aggregation folds skip reasons across repos",
        aggregate_census([{**new_census("a"), "skipped": {"draft": 2}},
                          {**new_census("b"),
                           "skipped": {"draft": 1, "not-armed": 3}}])["skipped"],
        {"draft": 3, "not-armed": 3})
    chk("the markdown summary renders a zero census without crashing",
        "### latch-watchdog census" in render_census_summary([empty], aggregate_census([empty])),
        True)

    # -- (k) FLOW: the demand-driven reads, and the exact mutations, against a fake gh. --------
    gate_json = json.dumps({"check_runs": [
        {"name": "gate", "status": "completed", "conclusion": "success",
         "completed_at": "2026-07-27T21:25:43Z"}]})
    prs_json = json.dumps({"data": {"repository": {"pullRequests": {
        "pageInfo": {"hasNextPage": False, "endCursor": None},
        "nodes": [{"id": "PR_kwFLIVEFLOWnodeid", "number": 999000617, "url": "u",
                   "isDraft": False, "isInMergeQueue": False, "isMergeQueueEnabled": True,
                   "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
                   "headRefOid": "cd0ca3f", "autoMergeRequest": {"enabledAt":
                       "2026-07-27T21:20:19Z", "mergeMethod": "MERGE"},
                   "labels": {"nodes": [{"name": "review:pass"}]}}]}}}})
    fake = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": "[]"})
    dog = Watchdog(apply_changes=True, grace_seconds=DEFAULT_GRACE_SECONDS,
                   required_check="gate", deny_labels=DEFAULT_DENY_LABELS,
                   require_label="review:pass", max_actions_per_head=2, max_actions_per_run=5,
                   marker_actor="sparq-bot[bot]", clock=lambda: parse_iso(
                       "2026-07-28T08:46:00Z"), gh_read=fake.read, gh_write=fake.write)
    rc = dog.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    # CHANGED DELIBERATELY, and the change IS the fix. The previous form of this check pinned
    # `("pr", "merge", ["--auto"])` as the re-arm -- i.e. it asserted the hazardous verb was
    # present. `gh pr merge --auto` on a CLEAN PR resolves to an IMMEDIATE MERGE unless the base
    # has a merge queue (gh v2.94.0 merge.go:530/:763/:302, http.go:88), and classify() requires
    # CLEAN. So the old check was pinning an unreviewed-merge path in place. The re-arm is now
    # the raw enablePullRequestAutoMerge mutation, which can only ever latch.
    chk("flow: a live dead latch produces marker -> disable-auto -> relatch, in that order",
        [(w[1], w[2]) for w in fake.write_log],
        [("pr", "comment"), ("pr", "merge"), ("api", "graphql")])
    # DEFENSIVE INDEXING, deliberately. These assertions previously indexed `write_log[-1]`
    # directly; a mutant that produced NO writes raised IndexError and aborted the whole
    # self-test before any named row printed. A crash is not a kill -- it reads identically
    # whether the guarantee broke or the fixture broke -- so every access below degrades to a
    # value that FAILS BY NAME instead of exploding.
    last = fake.write_log[-1] if fake.write_log else []
    relatch_q = next((a for a in last if a.startswith("query=")), "")
    chk("flow: the relatch is the raw auto-merge MUTATION, never a merge verb",
        relatch_q.startswith(
            "query=mutation($pr:ID!,$oid:GitObjectID!){enablePullRequestAutoMerge("), True)
    chk("flow: the relatch carries the head CAS in expectedHeadOid",
        "oid=cd0ca3f" in last, True)
    chk("flow: the relatch binds the PR by node id, not by number",
        "pr=PR_kwFLIVEFLOWnodeid" in last, True)
    chk("flow: the relatch restores the latch's OWN merge method",
        "mergeMethod:MERGE" in "".join(last), True)
    # ANTI-VACUITY for the whole block: no merge verb may appear in ANY mutation issued.
    chk("flow: NO `gh pr merge --auto` is issued anywhere in the rescue",
        [w for w in fake.write_log if "--auto" in w], [])
    chk("flow: the marker carries the head sha so the budget is per-head",
        "head=cd0ca3f" in fake.write_log[0][-1], True)
    # NOT a substring search over the argv -- the marker BODY legitimately contains the word
    # "dequeued" in its own explanation, and grepping for it matched this tool's own prose.
    # The remedy now DOES make a raw API call (the relatch mutation), so this check can no
    # longer be "no raw API call at all". It is instead an ALLOW-LIST of the exact three
    # mutations, which is strictly tighter: the verdict-stripping dequeue mutation is still
    # unreachable, and so is every other graphql document except the one named relatch.
    chk("flow: every mutation issued is one of exactly three allowed forms",
        sorted({tuple(w[:3]) for w in fake.write_log}),
        [("gh", "api", "graphql"), ("gh", "pr", "comment"), ("gh", "pr", "merge")])
    chk("flow: the ONLY graphql document issued is the relatch mutation",
        sorted({q[len("query="):][:40] for w in fake.write_log for q in w
                if isinstance(q, str) and q.startswith("query=")}),
        ["mutation($pr:ID!,$oid:GitObjectID!){enab"])
    chk("flow: rc is 0 and the census counts one rescue",
        (rc, dog.census[0]["rescued"], dog.census[0]["considered"]), (0, 1, 1))

    # -- (l) FLOW: the paired control end-to-end -- nothing is written at all. -----------------
    fake2 = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": "[]"})
    dog2 = Watchdog(apply_changes=True, grace_seconds=DEFAULT_GRACE_SECONDS,
                    required_check="gate", deny_labels=DEFAULT_DENY_LABELS,
                    require_label="review:pass", max_actions_per_head=2, max_actions_per_run=5,
                    marker_actor="sparq-bot[bot]",
                    clock=lambda: parse_iso("2026-07-27T21:30:00Z"),
                    gh_read=fake2.read, gh_write=fake2.write)
    rc2 = dog2.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("flow CONTROL: a PR inside grace gets ZERO writes and a censused skip",
        (rc2, fake2.write_log, dog2.census[0]["skipped"]), (0, [], {"within-grace": 1}))

    # -- (m) FLOW: marker authorship is filtered by exact login. -------------------------------
    forged = json.dumps([
        {"user": {"login": "outsider"}, "created_at": "2026-07-28T00:00:00Z",
         "body": "%s head=cd0ca3f action=rescue -->" % MARKER_PREFIX},
        {"user": {"login": "outsider"}, "created_at": "2026-07-28T00:00:01Z",
         "body": "%s head=cd0ca3f action=rescue -->" % MARKER_PREFIX}])
    fake3 = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": forged})
    dog3 = Watchdog(apply_changes=True, grace_seconds=DEFAULT_GRACE_SECONDS,
                    required_check="gate", deny_labels=DEFAULT_DENY_LABELS,
                    require_label="review:pass", max_actions_per_head=2, max_actions_per_run=5,
                    marker_actor="sparq-bot[bot]",
                    clock=lambda: parse_iso("2026-07-28T08:46:00Z"),
                    gh_read=fake3.read, gh_write=fake3.write)
    dog3.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("flow: markers written by a NON-actor login cannot exhaust the budget (a public repo "
        "lets anyone write what a control reads)",
        dog3.census[0]["rescued"], 1)

    # -- (n) FLOW: a missing owner token censuses instead of crashing or acting, and the ZERO ---
    # ROW REACHES STDOUT. Asserting only the in-memory list let a mutant that wrapped the print
    # in `if row["considered"]:` survive -- the census would still exist and simply never be
    # seen, which is precisely how a visible stall becomes an invisible one.
    fake4 = _FakeGh(reads={})
    dog4 = Watchdog(apply_changes=True, grace_seconds=1, required_check="gate",
                    deny_labels=DEFAULT_DENY_LABELS, require_label="review:pass",
                    max_actions_per_head=2, max_actions_per_run=5, marker_actor="b[bot]",
                    clock=lambda: 0.0, gh_read=fake4.read, gh_write=fake4.write)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc4 = dog4.run(["nobody/none"], {}, 0)
    printed = buffer.getvalue().splitlines()
    emitted = [json.loads(line[len("CENSUS "):]) for line in printed
               if line.startswith("CENSUS ")]
    chk("flow: an owner with no minted token is CENSUSED, never silently dropped",
        (rc4, dog4.census[0]["skipped"], fake4.write_log), (0, {"no-token-for-owner": 1}, []))
    chk("flow: the ZERO row is PRINTED, not merely accumulated -- a census that goes quiet when "
        "it does nothing is the bug this tool exists to fix",
        [(row["repo"], row["considered"]) for row in emitted], [("nobody/none", 0)])
    chk("flow: a run that considered nothing still prints CENSUS-TOTAL",
        sum(1 for line in printed if line.startswith("CENSUS-TOTAL ")), 1)

    # -- (n2) FLOW: the ORPHAN path must NOT issue a disarm. A PR whose latch is already off has
    # nothing to disable, and `--disable-auto` is the one call whose sibling operation strips a
    # verdict -- so the disarm belongs to the rescue path ALONE. Without this the mutant that
    # makes `self.disarm(...)` unconditional survives the whole suite.
    orphan_prs = json.dumps({"data": {"repository": {"pullRequests": {
        "pageInfo": {"hasNextPage": False, "endCursor": None},
        "nodes": [{"id": "PR_kwFORPHANnodeid", "number": 999000617, "url": "u",
                   "isDraft": False, "isInMergeQueue": False, "isMergeQueueEnabled": True,
                   "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
                   "headRefOid": "cd0ca3f", "autoMergeRequest": None,
                   "labels": {"nodes": [{"name": "review:pass"}]}}]}}}})
    ours = json.dumps([{"user": {"login": "sparq-bot[bot]"},
                        "created_at": "2026-07-28T00:00:00Z",
                        "body": "%s head=cd0ca3f action=rescue -->" % MARKER_PREFIX}])
    fake5 = _FakeGh(reads={"query=": orphan_prs, "check-runs": gate_json, "comments": ours})
    dog5 = Watchdog(apply_changes=True, grace_seconds=DEFAULT_GRACE_SECONDS,
                    required_check="gate", deny_labels=DEFAULT_DENY_LABELS,
                    require_label="review:pass", max_actions_per_head=2, max_actions_per_run=5,
                    marker_actor="sparq-bot[bot]",
                    clock=lambda: parse_iso("2026-07-28T08:46:00Z"),
                    gh_read=fake5.read, gh_write=fake5.write)
    dog5.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("flow ORPHAN: an already-unarmed PR is re-armed with NO disable-auto call",
        [(w[2], sorted(set(w) & {"--disable-auto", "--auto"})) for w in fake5.write_log],
        [("comment", []), ("graphql", [])])
    chk("flow ORPHAN: the census books it as a re-arm, not a rescue",
        (dog5.census[0]["rearmed"], dog5.census[0]["rescued"]), (1, 0))

    # -- (n3..n9) The paths line coverage showed NOTHING executed: the population alarm, both ---
    # budgets, dry-run, and every error exit. The escalation is the least-tested thing in a
    # watchdog precisely because the happy path is what gets written first.
    def _dog(fake, **over):
        kwargs = {"apply_changes": True, "grace_seconds": DEFAULT_GRACE_SECONDS,
                  "required_check": "gate", "deny_labels": DEFAULT_DENY_LABELS,
                  "require_label": "review:pass", "max_actions_per_head": 2,
                  "max_actions_per_run": 5, "marker_actor": "sparq-bot[bot]",
                  "clock": lambda: parse_iso("2026-07-28T08:46:00Z"),
                  "gh_read": fake.read, "gh_write": fake.write}
        kwargs.update(over)
        return Watchdog(**kwargs)

    spent = json.dumps([{"user": {"login": "sparq-bot[bot]"},
                         "created_at": "2026-07-28T0%d:00:00Z" % i,
                         "body": "%s head=cd0ca3f action=rescue -->" % MARKER_PREFIX}
                        for i in (1, 2)])
    fake6 = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": spent})
    dog6 = _dog(fake6)
    errbuf = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errbuf):
        rc6 = dog6.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("ALARM: a PR that exhausted its per-head budget and is STILL a dead latch reds the run, "
        "is counted, and is never touched again",
        (rc6, dog6.census[0]["budget_exhausted"], dog6.census[0]["skipped"], fake6.write_log),
        (1, 1, {"action-budget-exhausted": 1}, []))
    chk("ALARM: the population alarm is emitted as a workflow ::error::",
        "::error::latch-watchdog left 1 pull request(s)" in errbuf.getvalue(), True)
    chk("ALARM: raising the threshold above the population silences it and greens the run",
        _dog(_FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": spent})
             ).run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 1), 0)

    fake7 = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": "[]"})
    dog7 = _dog(fake7, max_actions_per_run=0)
    with contextlib.redirect_stdout(io.StringIO()):
        dog7.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("BLAST RADIUS: the per-run cap stops the action and censuses it, without writing",
        (dog7.census[0]["skipped"], fake7.write_log), ({"run-budget-exhausted": 1}, []))

    fake8 = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": "[]"})
    dog8 = _dog(fake8, apply_changes=False)
    with contextlib.redirect_stdout(io.StringIO()):
        rc8 = dog8.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("DRY RUN: a detected dead latch is reported and censused but NOTHING is written",
        (rc8, dog8.census[0]["skipped"], fake8.write_log), (0, {"dry-run": 1}, []))

    fake9 = _FakeGh(reads={"query=": prs_json}, read_rc={"check-runs": 4})
    dog9 = _dog(fake9)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc9 = dog9.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("ERROR PATH: a failed required-check read counts an error, reds the run, and writes "
        "nothing -- an unreadable state is never an actionable one",
        (rc9, dog9.census[0]["errors"], dog9.census[0]["considered"], fake9.write_log),
        (1, 1, 1, []))

    fake10 = _FakeGh(reads={}, read_rc={"query=": 1})
    dog10 = _dog(fake10)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc10 = dog10.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("ERROR PATH: a failed repo listing still emits that repo's census row",
        (rc10, dog10.census[0]["errors"], dog10.census[0]["considered"]), (1, 1, 0))

    fake11 = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": "[]"},
                     write_rc={"--disable-auto": 3})
    dog11 = _dog(fake11)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc11 = dog11.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("ERROR PATH: a failed disarm reds the run and is counted -- and the marker is ALREADY "
        "posted, so the next tick finds the PR instead of losing it",
        (rc11, dog11.census[0]["errors"], dog11.census[0]["rescued"],
         [w[2] for w in fake11.write_log]), (1, 1, 0, ["comment", "merge"]))

    page1 = json.dumps({"data": {"repository": {"pullRequests": {
        "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
        "nodes": [{"id": "PR_kwFPAGEA", "number": 999000001, "url": "u", "isDraft": True,
                   "isInMergeQueue": False, "isMergeQueueEnabled": True,
                   "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN", "headRefOid": "a",
                   "autoMergeRequest": None, "labels": {"nodes": []}}]}}}})
    page2 = json.dumps({"data": {"repository": {"pullRequests": {
        "pageInfo": {"hasNextPage": False, "endCursor": None},
        "nodes": [{"id": "PR_kwFPAGEB", "number": 999000002, "url": "u", "isDraft": True,
                   "isInMergeQueue": False, "isMergeQueueEnabled": True,
                   "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN", "headRefOid": "b",
                   "autoMergeRequest": None, "labels": {"nodes": []}}]}}}})
    # Fully scripted downstream reads on purpose: this fixture is about PAGINATION, so it must
    # not crash when some UNRELATED guard is mutated away and its PRs fall through to the
    # per-PR reads. A fixture that aborts the run masks every check below it.
    fake12 = _FakeGh(reads={"query=": [page1, page2], "check-runs": gate_json, "comments": "[]"})
    dog12 = _dog(fake12)
    with contextlib.redirect_stdout(io.StringIO()):
        dog12.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("PAGINATION: a second page is followed, so a large open-PR set is not silently truncated",
        (dog12.census[0]["considered"],
         any("cursor=c1" in part for call in fake12.read_log for part in call)), (2, True))

    # The budget is per HEAD, not per PR: a marker left over from a head that has since been
    # pushed past must not spend the new head's budget, or one rescue would permanently retire
    # the PR from the population.
    # Enough of them to EXHAUST the budget if the head scoping were dropped -- one would leave
    # room under the cap and the mutant that ignores the head would survive.
    stale_head = json.dumps([{"user": {"login": "sparq-bot[bot]"},
                              "created_at": "2026-07-28T0%d:00:00Z" % i,
                              "body": "%s head=OTHERSHA action=rescue -->" % MARKER_PREFIX}
                             for i in (1, 2)])
    fake15 = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json,
                            "comments": stale_head})
    dog15 = _dog(fake15)
    with contextlib.redirect_stdout(io.StringIO()):
        dog15.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("a marker for a DIFFERENT head does not spend this head's budget",
        (dog15.census[0]["rescued"], dog15.census[0]["skipped"]), (1, {}))

    for label, rc_map, want_writes in (
            ("a failed marker post aborts before any merge mutation", {"comment": 5}, 1),
            # Keyed on the MUTATION NAME now, not `--auto`: the relatch is a raw graphql
            # document, and a fixture still keyed on the old flag would never fire -- it would
            # pass by never exercising the failure path at all.
            ("a failed re-arm reds the run after the marker is already durable",
             {"enablePullRequestAutoMerge": 6}, 3)):
        faken = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": "[]"},
                        write_rc=rc_map)
        dogn = _dog(faken)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rcn = dogn.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
        chk(label, (rcn, dogn.census[0]["errors"], dogn.census[0]["rescued"],
                    len(faken.write_log)), (1, 1, 0, want_writes))

    fake16 = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json}, read_rc={"comments": 2})
    dog16 = _dog(fake16)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc16 = dog16.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    chk("an unreadable comment list is an ERROR, never an assumed-empty budget",
        (rc16, dog16.census[0]["errors"], fake16.write_log), (1, 1, []))

    chk("parse_iso rejects malformed input instead of raising",
        (parse_iso(""), parse_iso(None), parse_iso("not-a-date"), parse_iso(17)),
        (None, None, None, None))
    # Pinned to a HARD-CODED epoch, not to another call of the same function: #4617's arm time is
    # 1785187219 in UTC. A local-time parse gives a different number anywhere but a UTC host, and
    # every self-consistent assertion in this file would pass regardless.
    chk("parse_iso reads GitHub timestamps as UTC on any host, not local time",
        parse_iso("2026-07-27T21:20:19Z"), 1785187219.0)
    chk("the markdown summary lists skip reasons when there are any",
        "- `within-grace`: 2" in render_census_summary(
            [{**new_census("a"), "skipped": {"within-grace": 2}}],
            aggregate_census([{**new_census("a"), "skipped": {"within-grace": 2}}])), True)
    scrub = _dog(_FakeGh())._env("tok")
    chk("the gh environment carries the minted token and never GH_DEBUG (which can echo request "
        "bodies containing that token)",
        (scrub.get("GH_TOKEN"), "GH_DEBUG" in scrub), ("tok", False))
    chk("--apply without a --marker-actor REFUSES: a marker whose author we cannot verify is "
        "not evidence, and without markers the budget is unbounded",
        main(["--apply", "--repos", "o/r"]), 1)
    chk("no --repos refuses rather than sweeping nothing and reporting success",
        main(["--repos", ""]), 1)
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as handle:
        summary_file = handle.name
    dog13 = _dog(_FakeGh(reads={}), summary_path=summary_file)
    with contextlib.redirect_stdout(io.StringIO()):
        dog13.run(["nobody/none"], {}, 0)
    chk("the step summary is written even for a run that did nothing",
        "### latch-watchdog census" in open(summary_file, encoding="utf-8").read(), True)
    dog14 = _dog(_FakeGh(reads={}), summary_path="/nonexistent-dir/summary.md")
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc14 = dog14.run(["nobody/none"], {}, 0)
    chk("an unwritable step summary warns but never changes the verdict (the census is already "
        "on stdout)", rc14, 0)
    os.unlink(summary_file)

    # -- (o) THE YAML SEAM. Every uncaught mutant measured in this repo lived in a workflow -----
    # `if:`/step/call-site, not the Python. Pin the call site itself.
    workflows = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             ".github", "workflows")
    if not os.path.isdir(workflows):
        print("  note  workflow directory absent (sparse checkout) -- YAML seam not asserted")
    else:
        from yaml_dependency import require_yaml
        workflow_yaml = require_yaml("latch-watchdog workflow-seam checks")
        with open(os.path.join(workflows, "latch-watchdog.yml"), encoding="utf-8") as handle:
            doc = workflow_yaml.safe_load(handle.read())
        steps = doc["jobs"]["watch"]["steps"]
        mine = [s for s in steps if "latch-watchdog.py" in str(s.get("run", ""))]
        # Shell COMMENTS are stripped first: a guard a comment can satisfy is not a guard.
        body = "\n".join(line for line in str(mine[0].get("run", "")).splitlines()
                         if not line.strip().startswith("#")) if mine else ""
        run = " ".join(body.replace("\\\n", " ").split())
        chk("YAML: the workflow call site wires the watchdog and every bounding flag",
            (len(mine),
             [f for f in ("python3 scripts/latch-watchdog.py --self-test",
                          "python3 scripts/latch-watchdog.py", "--apply", "--repos",
                          "--marker-actor", "--grace-seconds", "--max-actions-per-head",
                          "--max-actions-per-run", "--budget-threshold")
              if f not in run]),
            (1, []))
        chk("YAML: the watchdog step can neither continue-on-error nor swallow its exit code",
            (mine[0].get("continue-on-error") if mine else "no step", "|| true" in run,
             "set +e" in run, "set -euo pipefail" in run), (None, False, False, True))
        chk("YAML: the grace period passed by the workflow is the MEASURED one",
            "--grace-seconds %d" % DEFAULT_GRACE_SECONDS in run, True)
        # THE VALUES, not just the flag names. The block above asserts each flag is PRESENT,
        # which a mutant that changes its VALUE survives untouched -- and these two values are
        # the blast radius itself. Measured: `--max-actions-per-run 5 -> 500` and
        # `--marker-actor "${APP_SLUG}[bot]" -> "${APP_SLUG}"` both survived the battery, the
        # second of which makes the per-head marker budget match nothing, so `eligible_at`
        # never re-anchors and the rescue loop is unbounded per tick.
        # TOKEN equality, never substring: "--max-actions-per-run 5" is a SUBSTRING of
        # "--max-actions-per-run 500", so the containment form passed on a 100x blast radius.
        # That mutant SURVIVED the containment version of this very check.
        run_tokens = run.split()

        def _flag_value(flag):
            return run_tokens[run_tokens.index(flag) + 1] if flag in run_tokens else None

        chk("YAML: the per-run blast radius is EXACTLY the bounded value",
            _flag_value("--max-actions-per-run"), "5")
        chk("YAML: the marker actor is the BOT identity, so markers this tool wrote are the "
            "ones its own budget counts",
            "--marker-actor \"${APP_SLUG}[bot]\"" in run
            or "--marker-actor '${APP_SLUG}[bot]'" in run
            or "--marker-actor ${APP_SLUG}[bot]" in run, True)
        chk("YAML: the per-head budget value is EXACTLY pinned too",
            _flag_value("--max-actions-per-head"), "2")
        chk("YAML: the grace period value is EXACTLY the measured one",
            _flag_value("--grace-seconds"), str(DEFAULT_GRACE_SECONDS))
        chk("YAML: the marker actor value carries the [bot] suffix EXACTLY",
            (_flag_value("--marker-actor") or "").strip("\"'"), "${APP_SLUG}[bot]")
        chk("YAML: the job never grants write permissions to the ambient token",
            doc["jobs"]["watch"].get("permissions"), {"contents": "read"})
        chk("YAML: the secret-consuming job is bound to the protected environment",
            doc["jobs"]["watch"].get("environment"), "dispatch-secrets")
        chk("YAML: no GH_DEBUG anywhere in this workflow",
            "GH_DEBUG" in open(os.path.join(workflows, "latch-watchdog.yml"),
                               encoding="utf-8").read(), False)

    # -- (p) No default-bound callables. `def f(..., gh=run_gh)` captures at DEFINITION time, --
    # which silently defeats every injection seam below it. Both ast.Name and ast.Attribute
    # defaults are checked: a sweep matching only ast.Name misses `= subprocess.run`.
    tree = ast.parse(open(os.path.abspath(__file__), encoding="utf-8").read())
    bound = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for default in list(node.args.defaults) + list(node.args.kw_defaults):
            if isinstance(default, (ast.Name, ast.Attribute)):
                bound.append("%s:%d" % (node.name, default.lineno))
    chk("no function in this module binds a callable as a DEFAULT argument value", bound, [])

    # -- (q) The remedy STRUCTURALLY cannot strip a verdict or write a label. ------------------
    # Deliberately an AST scan of the argv this module hands to its write seam, not a substring
    # grep of the source: a grep for "dequeue" matched this file's own explanation of why it does
    # not dequeue, and a grep for a label flag matched the assertion that looked for it. A check
    # that its own text can satisfy is not a check.
    write_argvs = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "gh_write"):
            continue
        if not (node.args and isinstance(node.args[0], ast.List)):
            write_argvs.append(("NON-LITERAL-ARGV",))
            continue
        write_argvs.append(tuple(
            el.value for el in node.args[0].elts
            if isinstance(el, ast.Constant) and isinstance(el.value, str)))
    # The relatch is now a RAW MUTATION, so "there is no raw-API call site" is no longer the
    # right invariant -- and stating it that way would now be FALSE. The tighter replacement is
    # an exact ALLOW-LIST of the three call sites, plus a scan of every graphql document this
    # module can issue. dequeuePullRequest stays unreachable by construction, and so does every
    # other mutation except the named relatch.
    chk("every mutation this module can issue is one of exactly three allowed call sites",
        sorted({argv[:3] for argv in write_argvs}),
        [("gh", "api", "graphql"), ("gh", "pr", "comment"), ("gh", "pr", "merge")])
    graphql_docs = sorted({s for argv in write_argvs for s in argv if "mutation(" in s})
    chk("the ONLY graphql mutation in the source is enablePullRequestAutoMerge",
        [d for d in graphql_docs if "enablePullRequestAutoMerge" not in d], [])
    chk("no graphql document mentions dequeue or a merge mutation",
        [d for d in graphql_docs
         if "dequeue" in d.lower() or "mergePullRequest" in d], [])
    # THE BANNED VERB, asserted structurally at the argv level. `gh pr merge --auto` resolves to
    # an immediate merge on a CLEAN PR whose base has no queue; it is banned estate-wide.
    chk("NO call site can issue `gh pr merge --auto` (the banned direct-merge verb)",
        [argv for argv in write_argvs
         if argv[:3] == ("gh", "pr", "merge") and "--auto" in argv], [])
    chk("NO call site can pass --admin (which would bypass the queue entirely)",
        [argv for argv in write_argvs if "--admin" in argv], [])
    chk("no mutation call site carries a label flag, so no human-terminal label can be written",
        sorted({flag for argv in write_argvs for flag in argv
                if flag in ("--add-label", "--remove-label", "--edit", "--label")}), [])

    # -- (r) THE PRODUCTION READ PATH, driven end to end. ---------------------------------------
    # Every block above injects `gh_read=fake.read`, so `_default_read` -- the ONLY read path a
    # live run takes -- had ZERO line coverage and nothing anywhere asserted the argv this tool
    # actually executes. #1137: all three read builders prepended "gh" to an argv that
    # `gh_retry.run_gh` already prefixes with "gh", so production ran `gh gh api …`, every read
    # returned rc=1, and all 16 runs since launch concluded `failure` -- each one seconds after
    # printing "latch-watchdog self-test PASSED". So this block injects NOTHING at the watchdog
    # seam: it stubs the process boundary underneath the real gh_retry and reads back the argv.
    real_run = subprocess.run
    spawned = []

    def _stub_response(cmd):
        """The process boundary, stubbed BELOW gh_retry: gh's own argv reaches here verbatim."""
        joined = " ".join(str(part) for part in cmd)
        body = prs_json if "query=" in joined else (
            gate_json if "check-runs" in joined else "[]")
        return subprocess.CompletedProcess(cmd, 0, stdout=body, stderr="")

    def _record_spawn(cmd, **kwargs):
        spawned.append(list(cmd))
        return _stub_response(cmd)

    live = Watchdog(apply_changes=False, grace_seconds=DEFAULT_GRACE_SECONDS,
                    required_check="gate", deny_labels=DEFAULT_DENY_LABELS,
                    require_label="review:pass", max_actions_per_head=2, max_actions_per_run=5,
                    marker_actor="sparq-bot[bot]", clock=lambda: 0.0)
    # The reads are caught and NAMED rather than allowed to propagate: with the #1137 argv,
    # `run_gh` now raises on the doubled binary, and a traceback out of the last block would
    # abort the suite -- which records as a crash, not as a kill, and prints no row at all
    # (AGENTS.md pre-flight 4, "crash-after-partial-run"). Every row below still runs.
    live_prs, live_gate, live_markers, read_error = [{}], {}, None, None
    try:
        subprocess.run = _record_spawn
        try:
            live_prs = live.list_open_prs("sparq-org/latch-watchdog-fixture-repo", "t")
            live_gate = live.fetch_gate(live_prs[0], "t")
            live_markers = live.fetch_markers(live_prs[0], "t")
        except Exception as exc:
            read_error = "%s: %s" % (type(exc).__name__, exc)
    finally:
        subprocess.run = real_run
    chk("READ PATH: the production read path completes without raising", read_error, None)
    # THE ROW #1137 WOULD HAVE REDDED. Not "an argv was built" -- the argv the OS was handed.
    # With the shipped bug this reads [['gh','gh'], ['gh','gh'], ['gh','gh']].
    chk("READ PATH: `gh` is prepended by gh_retry, so every executed read starts `gh api` -- "
        "exactly one binary token",
        [cmd[:2] for cmd in spawned], [["gh", "api"]] * 3)
    # The same invariant read through gh_retry's OWN parser, which is what decides retry scope:
    # the doubled form parsed as verb ("gh","api") -- outside the admit-list -- so the reads also
    # silently lost their retries and logged a refusal naming `api` as admitted.
    shapes = [_load_gh_retry().gh_request_shape(cmd[1:])["verb"] for cmd in spawned]
    chk("READ PATH: every read parses as the `api` verb under gh_retry's own scope parser",
        shapes, [("api",)] * 3)
    # ANTI-VACUITY: all three readers really ran, hit three distinct endpoints, and returned
    # PARSED data. A stub that spawned nothing, or a reader that raised, cannot satisfy this.
    chk("READ PATH: all three production readers executed, against three distinct endpoints",
        (len(spawned), sorted({("graphql" if "graphql" in cmd else
                                "check-runs" if any("check-runs" in p for p in cmd) else
                                "comments") for cmd in spawned})),
        (3, ["check-runs", "comments", "graphql"]))
    chk("READ PATH: the responses parse into the records the predicate consumes",
        ((live_prs[0] or {}).get("number"), (live_prs[0] or {}).get("head_sha"),
         (live_gate or {}).get("total"), live_markers),
        (999000617, "cd0ca3f", 1, (0, None)))
    # ...AND WHAT THE FIX DELIVERS INTO. Correct argv is only worth anything because the census
    # depends on it: the shipped tool emitted `CENSUS-TOTAL {"considered":0,"errors":2}` on all 16
    # runs, i.e. it never reached `classify` at all. Same production seam, now driven through the
    # whole `run()` -- so a break anywhere in the read chain shows up as the operator-visible
    # number rather than as an argv detail.
    def _stub_spawn(cmd, **kwargs):
        return _stub_response(cmd)

    swept = Watchdog(apply_changes=False, grace_seconds=DEFAULT_GRACE_SECONDS,
                     required_check="gate", deny_labels=DEFAULT_DENY_LABELS,
                     require_label="review:pass", max_actions_per_head=2, max_actions_per_run=5,
                     marker_actor="sparq-bot[bot]",
                     clock=lambda: parse_iso("2026-07-28T08:46:00Z"))
    try:
        subprocess.run = _stub_spawn
        swept_rc = swept.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    finally:
        subprocess.run = real_run
    swept_row = swept.census[0] if swept.census else {}
    chk("READ PATH: a dry-run sweep through the PRODUCTION seam CONSIDERS the dead latch and "
        "records no errors -- the measured 16/16 failure was considered=0 errors=2",
        (swept_rc, swept_row.get("considered"), swept_row.get("errors"),
         swept_row.get("skipped"), swept.errors), (0, 1, 0, {"dry-run": 1}, []))
    # STATIC, so a read call site added tomorrow and never exercised cannot re-introduce this.
    # Paired with its own control: the WRITE builders legitimately carry "gh" (they exec the argv
    # verbatim via `_default_write`), and asserting the scan still SEES that shape is what proves
    # the scan can fail at all.
    def _leading_gh_argvs(fn_names):
        found = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.FunctionDef) and node.name in fn_names):
                continue
            for inner in ast.walk(node):
                if not (isinstance(inner, ast.List) and inner.elts):
                    continue
                head = inner.elts[0]
                if isinstance(head, ast.Constant) and head.value == "gh":
                    found.append("%s:%d" % (node.name, inner.lineno))
        return sorted(found)

    chk("READ PATH: no reader builds an argv beginning with the binary gh_retry prepends",
        _leading_gh_argvs({"list_open_prs", "fetch_gate", "fetch_markers"}), [])
    chk("READ PATH CONTROL: the same scan DOES see the write builders, which exec their argv "
        "verbatim and so must carry `gh` -- the scan can fail",
        len(_leading_gh_argvs({"post_marker", "disarm", "rearm"})), 3)

    # -- (s) THE PRODUCTION WRITE PATH, driven end to end. --------------------------------------
    # (r)'s mirror image, and the same hole. Every flow block above injects `gh_write=fake.write`,
    # so `_default_write` -- the ONLY write path a live run takes -- had ZERO line coverage: after
    # the #1137 fix `python3 -m trace --count --missing` reported its two statements as the entire
    # uncovered remainder of the read/write seam, and nothing anywhere asserted the argv the
    # marker / disarm / relatch mutations actually hand to the OS. The two seams are OPPOSITES:
    # `_default_read` goes through `run_gh`, which prepends the binary itself, while
    # `_default_write` execs the argv VERBATIM, so these argvs must carry the leading "gh". Row
    # (r)'s static control pins that shape in the SOURCE; only this block pins what is EXECUTED,
    # which is what a change routing the write seam through a prepending helper -- #1137 in mirror
    # image -- would break while shipping green. So this block injects NOTHING at the write seam:
    # it stubs the process boundary beneath it and reads back what the OS was handed.
    real_run_w = subprocess.run
    written, written_env = [], []

    def _record_write(cmd, **kwargs):
        written.append(list(cmd))
        written_env.append(dict(kwargs.get("env") or {}))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    # The reads stay faked, so the ONLY thing reaching the stubbed process boundary is a write.
    # `gh_write` is left UNSET -- that omission is the entire point of the block.
    fake17 = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": "[]"})
    livew = Watchdog(apply_changes=True, grace_seconds=DEFAULT_GRACE_SECONDS,
                     required_check="gate", deny_labels=DEFAULT_DENY_LABELS,
                     require_label="review:pass", max_actions_per_head=2, max_actions_per_run=5,
                     marker_actor="sparq-bot[bot]",
                     clock=lambda: parse_iso("2026-07-28T08:46:00Z"), gh_read=fake17.read)
    # GH_DEBUG is REALLY set for the window: the scrub assertion below would otherwise pass
    # vacuously on any host that simply never had it, which is every CI runner.
    had_debug, write_error, livew_rc = os.environ.get("GH_DEBUG"), None, None
    try:
        os.environ["GH_DEBUG"] = "api"
        subprocess.run = _record_write
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            livew_rc = livew.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    except Exception as exc:
        # Named, never propagated: a traceback out of here records as a crash rather than a kill
        # and prints no row at all (AGENTS.md pre-flight 4, "crash-after-partial-run").
        write_error = "%s: %s" % (type(exc).__name__, exc)
    finally:
        subprocess.run = real_run_w
        if had_debug is None:
            os.environ.pop("GH_DEBUG", None)
        else:
            os.environ["GH_DEBUG"] = had_debug

    def _wargv(index):
        """Defensive, like (r): a mutant that writes nothing FAILS BY NAME instead of raising."""
        return written[index] if len(written) > index else []

    # ANTI-VACUITY FIRST: the rescue really ran the whole way through the production seam. Every
    # argv row below is satisfiable by an empty log, so this is what makes them mean anything.
    chk("WRITE PATH: an apply-mode rescue driven through the PRODUCTION write seam completes, "
        "spawns exactly three processes, and is censused as one rescue",
        (write_error, livew_rc, len(written),
         (livew.census[0] if livew.census else {}).get("rescued")), (None, 0, 3, 1))
    # THE ROW A MIRROR-IMAGE #1137 WOULD RED. Not "an argv was built" -- the argv the OS was
    # handed. Routing `_default_write` through a helper that prepends the binary reads
    # [['gh','gh'], ...] here while every flow block above stays green.
    chk("WRITE PATH: the write seam execs the argv VERBATIM, so each executed write starts at the "
        "binary and carries EXACTLY ONE `gh` token",
        [(cmd[:2], cmd.count("gh")) for cmd in written],
        [(["gh", "pr"], 1), (["gh", "pr"], 1), (["gh", "api"], 1)])
    chk("WRITE PATH: the executed marker comment is exactly "
        "`gh pr comment <n> --repo <repo> --body <body>`, 8 tokens, body carrying the head sha",
        (_wargv(0)[:7], len(_wargv(0)), "head=cd0ca3f" in (_wargv(0)[7:8] or [""])[0]),
        (["gh", "pr", "comment", "999000617", "--repo",
          "sparq-org/latch-watchdog-fixture-repo", "--body"], 8, True))
    # EXACT LIST EQUALITY, not containment: an appended token is the whole hazard here, and a
    # containment check is what let `--max-actions-per-run 5 -> 500` survive elsewhere (item 6).
    chk("WRITE PATH: the executed disarm is EXACTLY `gh pr merge <n> --repo <repo> "
        "--disable-auto` and nothing else",
        _wargv(1), ["gh", "pr", "merge", "999000617", "--repo",
                    "sparq-org/latch-watchdog-fixture-repo", "--disable-auto"])
    chk("WRITE PATH: the executed relatch is `gh api graphql` carrying the node id and the head "
        "CAS, in 9 tokens",
        (_wargv(2)[:3], [t for t in _wargv(2) if t.startswith(("pr=", "oid="))], len(_wargv(2))),
        (["gh", "api", "graphql"], ["pr=PR_kwFLIVEFLOWnodeid", "oid=cd0ca3f"], 9))
    chk("WRITE PATH: the graphql document that reached the process is the relatch MUTATION",
        [t[:len("query=mutation($pr:ID!,$oid:GitObjectID!){enablePullRequestAutoMerge(")]
         for t in _wargv(2) if t.startswith("query=")],
        ["query=mutation($pr:ID!,$oid:GitObjectID!){enablePullRequestAutoMerge("])
    # The arm-adjacent surface, asserted over what was EXECUTED. Block (q) proves no call site can
    # spell these; this proves none reaches the OS, which is the property that actually matters
    # and the only form that survives a future non-literal argv builder.
    chk("WRITE PATH: no `--auto`, `--admin` or label flag reaches the process on any write",
        sorted({t for cmd in written for t in cmd
                if t in ("--auto", "--admin", "--add-label", "--remove-label", "--label",
                         "--edit")}), [])
    chk("WRITE PATH CONTROL: the same scan DOES see the one flag that IS issued, so it can fail",
        sorted({t for cmd in written for t in cmd if t == "--disable-auto"}), ["--disable-auto"])
    chk("WRITE PATH: every executed write carries the MINTED token in its own environment and "
        "never GH_DEBUG (which can echo a request body containing that token)",
        [(env.get("GH_TOKEN"), "GH_DEBUG" in env) for env in written_env], [("t", False)] * 3)

    # The seam must return the PROCESS's return code, not a constant. Without this row a
    # `_default_write` that returned `0, ""` unconditionally would swallow every failed mutation
    # -- the run would green while the PR stayed disarmed, which is strictly worse than found.
    def _fail_the_disarm(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 9 if "--disable-auto" in cmd else 0, stdout="", stderr="")

    fake18 = _FakeGh(reads={"query=": prs_json, "check-runs": gate_json, "comments": "[]"})
    dog17 = Watchdog(apply_changes=True, grace_seconds=DEFAULT_GRACE_SECONDS,
                     required_check="gate", deny_labels=DEFAULT_DENY_LABELS,
                     require_label="review:pass", max_actions_per_head=2, max_actions_per_run=5,
                     marker_actor="sparq-bot[bot]",
                     clock=lambda: parse_iso("2026-07-28T08:46:00Z"), gh_read=fake18.read)
    rc17 = None
    try:
        subprocess.run = _fail_the_disarm
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc17 = dog17.run(["sparq-org/latch-watchdog-fixture-repo"], {"sparq-org": "t"}, 0)
    except Exception:
        pass
    finally:
        subprocess.run = real_run_w
    chk("WRITE PATH: a non-zero exit from the real process propagates out of the write seam -- "
        "the run reds, the rescue is not booked, and the relatch never runs",
        (rc17, (dog17.census[0] if dog17.census else {}).get("errors"),
         (dog17.census[0] if dog17.census else {}).get("rescued")), (1, 1, 0))

    # ...and the second half of that same return statement: a process that produced no stdout
    # yields the empty STRING, never None -- every caller does `code, _ = self.gh_write(...)`
    # today, so only a direct call can pin it.
    direct = Watchdog(apply_changes=True, grace_seconds=1, required_check="gate",
                      deny_labels=DEFAULT_DENY_LABELS, require_label="review:pass",
                      max_actions_per_head=2, max_actions_per_run=5, marker_actor="b[bot]")
    direct_write = None
    try:
        subprocess.run = lambda cmd, **kwargs: subprocess.CompletedProcess(
            cmd, 4, stdout=None, stderr="")
        direct_write = direct._default_write(["gh", "pr", "comment", "1"], "tok")
    except Exception as exc:
        # Measured, not hypothetical: the mirror-#1137 mutant makes this call raise out of
        # `run_gh`'s own doubled-binary guard, which aborted the suite one row short and recorded
        # as a kill with a SMALLER total check count (AGENTS.md pre-flight 4).
        direct_write = "%s: %s" % (type(exc).__name__, exc)
    finally:
        subprocess.run = real_run_w
    chk("WRITE PATH: the seam returns the process's OWN return code and normalises a None stdout "
        "to the empty string", direct_write, (4, ""))

    print("latch-watchdog self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
