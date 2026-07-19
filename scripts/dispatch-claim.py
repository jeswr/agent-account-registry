#!/usr/bin/env python3
# [GPT-5.6] REG-4 privileged dispatcher half. Target code never executes in this process: the
# unprivileged PLAN artifact is treated as hostile data, revalidated against registry policy and
# protected target routing, then fed to the CAS allocator before a workflow_dispatch is emitted.
"""Validate an unprivileged dispatch plan, claim leases, and launch live workers fail-closed."""

import argparse
import base64
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import tomllib


# v2 adds top-level `review_items` (the cross-provider review/fix loop) and a per-item `deferred`
# flag (the deferred-retry path). v3 adds the zero-manual repair surface: review-item states
# `needs-ci-fix` (red ci-summary gate on the current head) and `needs-rebase` (conflicting base)
# with an advisory `context` field, the `stranded` escalation state ({drafted, unarmed, reviewed
# head, green gate} has no other autonomous exit — CLAIM hands it loudly to a human), plus
# top-level `disarm_items` (armed-SHA-mismatch safety invariant, registry issue #42). Both
# validators — this one and the dispatch.yml PLAN inline check — are bumped in the same commit;
# the TARGET repo's dispatch-plan.py is untouched.
# The 2026-07-17 round-budget escalation (decide_budget + the fix-model floor pin) deliberately
# adds NO plan fields: the pin and the round/model/progress accounting are re-derived at CLAIM
# time from durable bot-authored PR markers plus registry verdict records, so a hostile PLAN
# artifact cannot inject, clear, or inflate them — the (then-)v3 schema was unchanged.
# v3 -> v4 (run 29617040167): the plan carries PLAN-side per-item snapshot skips
# (`snapshot_skips`) so one oversized PR's check-run listing defers THAT PR instead of
# killing the whole sweep. CLAIM only COUNTS these into the dispatch-summary histogram —
# a hostile plan can at worst inflate accounting noise, never trigger an act.
SCHEMA = "registry-dispatch-plan/v4"
PLAN_FIELDS = {"schema", "generated_at", "repositories", "review_items", "disarm_items",
               "snapshot_skips"}
REPOSITORY_FIELDS = {"target_repo", "target_sha", "items"}
ITEM_FIELDS = {
    "number",
    "priority",
    "package",
    "role",
    "model_chain",
    "agent",
    "escalate",
    "labels",
    "author",
    "body_sha",
    "deferred",
}
REVIEW_ITEM_FIELDS = {
    "pr_number",
    "head_sha",
    "state",
    "impl_provider",
    "repo",
    "package",
    "security",
    "context",
}
DISARM_ITEM_FIELDS = {"pr_number", "head_sha", "reviewed_sha", "repo"}
SNAPSHOT_SKIP_FIELDS = {"repo", "pr_number", "reason"}
# The reasons plan-snapshot.py may record for a per-item skip of a worker PR's CI/merge
# snapshot (pr_number 0 = the repo-level worker-PR census overflow). Two tiers (PR #60
# round-1 review): a PRE-detail skip (pr-detail-*/census) has NO pr_status record, so
# every snapshot-derived admission (ci-fix/rebase/stranded/disarm) stands down for it
# that tick. A POST-detail skip (check-runs-*) records the same row for visibility but
# ALSO ships a DEGRADED record (detail fields intact, check_runs empty + marked): the
# check-run-DEPENDENT admissions (ci-fix, stranded) stand down, while the detail-derived
# ones still evaluate on sound data — the needs-rebase conflict repair, and the #42
# armed-SHA-mismatch disarm (whose ACT is itself the safety measure) still fires.
# Fail-closed per ITEM, never per sweep; never fail-OPEN on the disarm net; MONOTONE
# under a forged marker (the unmarked outcome or do-nothing, never a different act).
SNAPSHOT_SKIP_REASONS = {
    "check-runs-overflow",
    "check-runs-malformed",
    "check-runs-read-failed",
    "pr-detail-read-failed",
    "pr-detail-malformed",
    "worker-pr-census-overflow",
}
# needs-ci-fix / needs-rebase are the zero-manual repair states: same-provider fix runs (reuse
# mode=fix) that target red full-matrix CI legs / a conflicting base instead of review findings.
# stranded is the loud terminal escalation for {drafted, unarmed, reviewed-sha == head, green
# gate}: nothing else re-admits that posture (no re-review without a head advance, no ci-fix
# without a red gate), so CLAIM re-derives it live and applies the needs-user hand-off.
REVIEW_STATES = {"needs-review", "needs-fix", "needs-ci-fix", "needs-rebase", "stranded"}
FIX_KIND_OF_STATE = {"needs-fix": "verdict", "needs-ci-fix": "ci", "needs-rebase": "rebase"}
# Human-owned PR labels: review:needs-user is the loop's own terminal escalation; needs:user is
# groom's parked-PR marker ("Human attention required"). EITHER parks the whole autonomous
# surface for the PR — enumeration, repair admission, and worker-pr.py disarm all stand down.
HUMAN_HOLD_PR_LABELS = {"review:needs-user", "needs:user"}
IMPL_PROVIDERS = {"anthropic", "openai"}
SAFE_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
SAFE_ATOM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
SAFE_PACKAGE = re.compile(r"(?:[A-Za-z0-9][A-Za-z0-9_.-]*|__global__)")
SAFE_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[bot\])?")
SAFE_SHA = re.compile(r"[0-9a-f]{40}")
TRUSTED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
BUSY_OR_GATED = {
    "status:blocked",
    "status:deferred",
    "status:in-progress",
    "status:in-progress-review",
    "status:untriaged",
    "trust:untrusted",
}
# Busy/gated set for the deferred-RETRY path: status:deferred is the retry trigger, everything
# else still gates (locked decision 20).
DEFERRED_GATED = BUSY_OR_GATED - {"status:deferred"}
# Readiness re-derivation (issue #102): PLAN computes blockers/non-dispatchability with HOSTILE
# target code (dispatch-plan.py in the cloned target). CLAIM must independently re-prove the same
# readiness predicate from LIVE registry-owned code before dispatch — an epic is a tracking
# umbrella (never a work item), and `Blocked-by: #N` gates until every referenced issue is closed.
# Kept byte-identical to scripts/ready-issues.py (NON_DISPATCHABLE + the blocker regex) so CLAIM
# and the ready engine cannot silently diverge.
NON_DISPATCHABLE = "kind:epic"
BLOCKED_BY_RE = re.compile(r"[Bb]locked-by:\s*#([0-9]+)")
# Cross-provider chains (locked decisions 14/17): the review chain is the INVERSE of the
# implementer's provider and is computed HERE, never through policy-resolve.resolve() (whose
# role=review row is always [opus]); resolve() supplies account_pool/caps/gate/arm only.
REVIEW_CHAIN = {"anthropic": ["terra"], "openai": ["opus"]}
FIX_CHAIN = {"anthropic": ["fable", "sonnet"], "openai": ["terra"]}
# Static per-prefix lease caps (locked decision 9, caps re-raised per maintainer direction
# 2026-07-17: codex rate limits are far from binding and 10+ parallel agents are fine; the
# earlier 2->10 raise was lost in the review-loop deploy rebase). The `select-and-claim` CLI
# path does not usage-gate; codex accounts are usage-EXEMPT, so this shared `review:` prefix
# cap IS the codex slot bound, and `fix:` bounds concurrent same-provider fix agents.
REVIEW_MAX_CONCURRENT = 10
FIX_MAX_CONCURRENT = 8
REVIEW_TTL = 1200   # short — a crashed reviewer must free the scarce codex slot fast
FIX_TTL = 3600      # a fix runs the crate gate (cargo), which can be slow
MISSED_FIX_LIMIT = 6  # consecutive missed fix dispatches per round before needs-user (decision 13)
HEAD_REF_RE = re.compile(r"^sparq-agent/issue-([1-9][0-9]*)-")
# Mirrors worker-pr.py REVIEWED_SHA_RE (the marker is written there; keep formats in sync).
REVIEWED_SHA_RE = re.compile(r"<!-- sparq-reviewed-sha:([0-9a-f]{40}|none) -->")
SECURITY_KEYWORDS = ("zk", "mpc", "crypto", "auth", "e2ee")
# The authoritative aggregator check-run on the target (sparq's `ci-summary / gate` job): only a
# CONCLUDED failure of THIS check on the CURRENT head enumerates a ci-fix; in-progress = no churn.
CI_GATE_CHECK = "gate"
FAILED_CONCLUSIONS = {"failure", "timed_out"}
GLOBAL_PACKAGE = "__global__"   # mirrors the target ready-engine's serializing partition
CI_CONTEXT_MAX = 1000           # advisory failing-leg context cap (plan field + workflow input)
MAX_FAILING_LEGS = 20


class DispatchError(RuntimeError):
    """A concise fail-closed error suitable for Actions logs."""


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise DispatchError(f"cannot load registry helper {Path(path).name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _require_exact_fields(value, fields, where):
    if not isinstance(value, dict):
        raise DispatchError(f"{where} must be an object")
    missing = sorted(fields - value.keys())
    extra = sorted(value.keys() - fields)
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unknown {', '.join(extra)}")
        raise DispatchError(f"{where} has invalid fields ({'; '.join(detail)})")


def _safe_string(value, pattern, where):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise DispatchError(f"{where} is missing or unsafe")
    return value


def normalize_plan_order(document):
    """Sort review/disarm items into the GLOBAL (repo, pr_number) order validate_plan
    requires. THE one production sort — the PLAN assembler (dispatch.yml heredoc) calls this
    instead of sorting inline, so the self-test exercises the exact code the workflow runs
    (sol r2 on #233: an inline workflow sort could regress to a crashing key while a
    fixture-local sort kept the test green). Returns the document for chaining."""
    document["review_items"].sort(key=lambda item: (item["repo"], item["pr_number"]))
    document["disarm_items"].sort(key=lambda item: (item["repo"], item["pr_number"]))
    return document


def validate_plan(document):
    """Strictly validate the entire PLAN artifact before any network mutation."""
    _require_exact_fields(document, PLAN_FIELDS, "plan")
    if document["schema"] != SCHEMA:
        raise DispatchError("plan schema is unsupported")
    if (not isinstance(document["generated_at"], str)
            or not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                                document["generated_at"])):
        raise DispatchError("plan generated_at is malformed")
    repositories = document["repositories"]
    if not isinstance(repositories, list):
        raise DispatchError("plan repositories must be a list")
    seen_repositories = set()
    seen_issues = set()
    for repo_index, repository in enumerate(repositories, 1):
        where = f"repository #{repo_index}"
        _require_exact_fields(repository, REPOSITORY_FIELDS, where)
        target = _safe_string(repository["target_repo"], SAFE_REPO, f"{where} target_repo")
        if target in seen_repositories:
            raise DispatchError(f"plan repeats target repository {target}")
        seen_repositories.add(target)
        if not isinstance(repository["target_sha"], str) or not re.fullmatch(
                r"[0-9a-f]{40}", repository["target_sha"]):
            raise DispatchError(f"{where} target_sha is malformed")
        items = repository["items"]
        if not isinstance(items, list):
            raise DispatchError(f"{where} items must be a list")
        prior_order = None
        for item_index, item in enumerate(items, 1):
            item_where = f"{where} item #{item_index}"
            _require_exact_fields(item, ITEM_FIELDS, item_where)
            number = item["number"]
            priority = item["priority"]
            if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
                raise DispatchError(f"{item_where} number must be a positive integer")
            if not isinstance(priority, int) or isinstance(priority, bool) or priority not in range(5):
                raise DispatchError(f"{item_where} priority must be P0..P4")
            issue_key = (target, number)
            if issue_key in seen_issues:
                raise DispatchError(f"plan repeats {target}#{number}")
            seen_issues.add(issue_key)
            order = (priority, number)
            if prior_order is not None and order < prior_order:
                raise DispatchError(f"{where} items are not in deterministic priority order")
            prior_order = order
            _safe_string(item["package"], SAFE_PACKAGE, f"{item_where} package")
            for field in ("role", "agent"):
                _safe_string(item[field], SAFE_ATOM, f"{item_where} {field}")
            chain = item["model_chain"]
            if (not isinstance(chain, list) or not chain
                    or any(not isinstance(model, str) or not SAFE_ATOM.fullmatch(model)
                           for model in chain)
                    or len(set(chain)) != len(chain)):
                raise DispatchError(f"{item_where} model_chain is invalid")
            if not isinstance(item["escalate"], bool):
                raise DispatchError(f"{item_where} escalate must be boolean")
            labels = item["labels"]
            if (not isinstance(labels, list) or not labels
                    or any(not isinstance(label, str) or not label or "\n" in label or "\r" in label
                           for label in labels)
                    or labels != sorted(set(labels))):
                raise DispatchError(f"{item_where} labels must be sorted unique strings")
            _safe_string(item["author"], SAFE_LOGIN, f"{item_where} author")
            if not isinstance(item["body_sha"], str) or not re.fullmatch(
                    r"[0-9a-f]{64}", item["body_sha"]):
                raise DispatchError(f"{item_where} body_sha is malformed")
            if not isinstance(item["deferred"], bool):
                raise DispatchError(f"{item_where} deferred must be boolean")
    review_items = document["review_items"]
    if not isinstance(review_items, list):
        raise DispatchError("plan review_items must be a list")
    prior_review = None
    seen_reviews = set()
    for review_index, item in enumerate(review_items, 1):
        where = f"review item #{review_index}"
        _require_exact_fields(item, REVIEW_ITEM_FIELDS, where)
        number = item["pr_number"]
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise DispatchError(f"{where} pr_number must be a positive integer")
        if not isinstance(item["head_sha"], str) or not SAFE_SHA.fullmatch(item["head_sha"]):
            raise DispatchError(f"{where} head_sha is malformed")
        # isinstance BEFORE each set membership: an unhashable JSON value ([] / {}) would
        # TypeError the lookup — malformed plan input must fail as DispatchError, not crash.
        state = item["state"]
        if not isinstance(state, str) or state not in REVIEW_STATES:
            raise DispatchError(f"{where} state is invalid")
        impl_provider = item["impl_provider"]
        if not isinstance(impl_provider, str) or impl_provider not in IMPL_PROVIDERS:
            raise DispatchError(f"{where} impl_provider is invalid")
        repo = _safe_string(item["repo"], SAFE_REPO, f"{where} repo")
        if repo not in seen_repositories:
            raise DispatchError(f"{where} repo is not a planned repository")
        _safe_string(item["package"], SAFE_PACKAGE, f"{where} package")
        if not isinstance(item["security"], bool):
            raise DispatchError(f"{where} security must be boolean")
        context = item["context"]
        if (not isinstance(context, str) or len(context) > CI_CONTEXT_MAX
                or "\n" in context or "\r" in context):
            raise DispatchError(f"{where} context is malformed")
        review_key = (repo, number)
        if review_key in seen_reviews:
            raise DispatchError(f"plan repeats review item {repo}#{number}")
        seen_reviews.add(review_key)
        if prior_review is not None and review_key < prior_review:
            raise DispatchError("plan review items are not in deterministic order")
        prior_review = review_key
    disarm_items = document["disarm_items"]
    if not isinstance(disarm_items, list):
        raise DispatchError("plan disarm_items must be a list")
    prior_disarm = None
    seen_disarms = set()
    for disarm_index, item in enumerate(disarm_items, 1):
        where = f"disarm item #{disarm_index}"
        _require_exact_fields(item, DISARM_ITEM_FIELDS, where)
        number = item["pr_number"]
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise DispatchError(f"{where} pr_number must be a positive integer")
        if not isinstance(item["head_sha"], str) or not SAFE_SHA.fullmatch(item["head_sha"]):
            raise DispatchError(f"{where} head_sha is malformed")
        reviewed = item["reviewed_sha"]
        if not isinstance(reviewed, str) or not (reviewed == "none"
                                                 or SAFE_SHA.fullmatch(reviewed)):
            raise DispatchError(f"{where} reviewed_sha is malformed")
        if reviewed == item["head_sha"]:
            raise DispatchError(f"{where} reviewed_sha equals head_sha (nothing to disarm)")
        repo = _safe_string(item["repo"], SAFE_REPO, f"{where} repo")
        if repo not in seen_repositories:
            raise DispatchError(f"{where} repo is not a planned repository")
        disarm_key = (repo, number)
        if disarm_key in seen_disarms:
            raise DispatchError(f"plan repeats disarm item {repo}#{number}")
        seen_disarms.add(disarm_key)
        if prior_disarm is not None and disarm_key < prior_disarm:
            raise DispatchError("plan disarm items are not in deterministic order")
        prior_disarm = disarm_key
    snapshot_skips = document["snapshot_skips"]
    if not isinstance(snapshot_skips, list):
        raise DispatchError("plan snapshot_skips must be a list")
    prior_skip = None
    seen_skips = set()
    for skip_index, item in enumerate(snapshot_skips, 1):
        where = f"snapshot skip #{skip_index}"
        _require_exact_fields(item, SNAPSHOT_SKIP_FIELDS, where)
        number = item["pr_number"]
        # pr_number 0 is the repo-level worker-PR census-overflow skip (no single PR).
        if not isinstance(number, int) or isinstance(number, bool) or number < 0:
            raise DispatchError(f"{where} pr_number must be a non-negative integer")
        reason = item["reason"]
        if not isinstance(reason, str) or reason not in SNAPSHOT_SKIP_REASONS:
            raise DispatchError(f"{where} reason is invalid")
        repo = _safe_string(item["repo"], SAFE_REPO, f"{where} repo")
        if repo not in seen_repositories:
            raise DispatchError(f"{where} repo is not a planned repository")
        skip_key = (repo, number)
        if skip_key in seen_skips:
            raise DispatchError(f"plan repeats snapshot skip {repo}#{number}")
        seen_skips.add(skip_key)
        if prior_skip is not None and skip_key < prior_skip:
            raise DispatchError("plan snapshot skips are not in deterministic order")
        prior_skip = skip_key
    return document


def _security_flagged(labels):
    """Security surfaces never auto-arm (mirrors worker-pr.py security_flagged): substring
    keywords per routing match_labels semantics plus the trust:* prefix namespace."""
    return (any(keyword in label for label in labels for keyword in SECURITY_KEYWORDS)
            or any(label.startswith("trust:") for label in labels))


def _live_holder_keys(leases, now):
    return {
        str(lease.get("holder", "")).split("@", 1)[0]
        for lease in leases
        if isinstance(lease, dict) and lease.get("expires_at", 0) > now
    }


def _sanitize_leg(name):
    """Printable-ASCII, length-capped check-run leg name (context is advisory model input that
    also crosses a workflow_dispatch input — never multiline, never control characters)."""
    return re.sub(r"[^ -~]", "?", str(name))[:120].strip()


def interpret_check_runs(check_runs):
    """PURE interpreter for a commit's check-runs listing (hostile-tolerant: malformed input
    degrades to gate=unknown, never a crash and never an ACT). Re-runs of the same check name are
    superseded by the latest `started_at`. Returns {"gate", "failing_legs"} where gate is one of
    failure|pending|success|missing|unknown — ONLY a concluded `failure` ever admits a ci-fix
    (an in-progress gate is deliberately not enumerated: no churn)."""
    if not isinstance(check_runs, list):
        return {"gate": "unknown", "failing_legs": []}
    latest = {}
    for run in check_runs:
        if not isinstance(run, dict):
            continue
        name = run.get("name")
        if not isinstance(name, str) or not name:
            continue
        started = str(run.get("started_at") or "")
        prior = latest.get(name)
        if prior is None or started >= prior[0]:
            latest[name] = (started, run)
    gate_entry = latest.get(CI_GATE_CHECK)
    if gate_entry is None:
        gate = "missing"
    elif gate_entry[1].get("status") != "completed":
        gate = "pending"
    elif gate_entry[1].get("conclusion") in FAILED_CONCLUSIONS:
        gate = "failure"
    else:
        gate = "success"
    failing = sorted({
        _sanitize_leg(name) for name, (_started, run) in latest.items()
        if name != CI_GATE_CHECK and run.get("status") == "completed"
        and run.get("conclusion") in FAILED_CONCLUSIONS and _sanitize_leg(name)
    })[:MAX_FAILING_LEGS]
    return {"gate": gate, "failing_legs": failing}


def pr_ci_status(record):
    """PURE per-PR CI/merge status from the PLAN snapshot's raw detail record. Hostile-tolerant:
    anything malformed degrades to unknown (empty dict / None fields) so a poisoned snapshot can
    only cause DO-NOTHING, never a spurious repair item."""
    if not isinstance(record, dict):
        return {}
    head_sha = record.get("head_sha")
    if not isinstance(head_sha, str) or not SAFE_SHA.fullmatch(head_sha):
        return {}
    mergeable = record.get("mergeable")
    status = {
        "head_sha": head_sha,
        # REST tri-state: False = conflicting, True = clean, null = still computing (unknown).
        "conflicting": True if mergeable is False else (False if mergeable is True else None),
        "armed": isinstance(record.get("auto_merge"), dict),
        # PLAN's post-detail degradation marker (oversized/unreadable check-run listing).
        # Hostile-tolerant AND narrows-only: ANY truthy marker forces gate=missing below
        # (the check-run payload is ignored outright), so a forged marker can only stand
        # admissions DOWN — it never widens; the disarm net reads head_sha/armed only.
        "check_runs_degraded": bool(record.get("check_runs_degraded")),
    }
    status.update(interpret_check_runs(
        [] if status["check_runs_degraded"] else record.get("check_runs")))
    return status


def snapshot_skip_reasons(snapshot_skips):
    """PURE: dispatch-summary histogram entries for PLAN's per-item snapshot skips (run
    29617040167 fix — a degraded snapshot must be VISIBLE, not silent). Coarse category
    counts only; PR numbers stay in the logs, never the summary."""
    reasons = Counter()
    for skip in snapshot_skips:
        reasons[f"snapshot-skip:{skip['reason']}"] += 1
    return reasons


def decide_repair_admission(state, mergeable, gate, draft):
    """PURE repair-admission decision. The LIVE trigger is re-derived BEFORE any defuse can run:
    a plan row is hostile AND stale by construction, so a validly-armed PR whose PLAN-time
    trigger evaporated (a flaky gate leg re-ran green, the base moved past the conflict) must
    NEVER be demoted to draft on snapshot state alone — that would destroy a matching-SHA valid
    arm and strand the PR in an un-enumerable state. Returns one of:
    ("defer", reason)   — trigger absent/unknown on live data; NO mutation this tick,
    ("defuse", kind)    — live-confirmed trigger on a ready/armed PR; disarm --when always first,
    ("proceed", kind)   — live-confirmed trigger on a drafted PR; dispatch the fix run."""
    if state == "needs-rebase":
        if mergeable is not False:
            return ("defer", "base is no longer conflicting (or mergeability is still computing)")
    elif state == "needs-ci-fix":
        if mergeable is False:
            return ("defer", "base is conflicting; rebase repair runs first")
        if gate != "failure":
            return ("defer", "the gate check is not a concluded failure on the live head")
    else:
        return ("defer", "not a repair state")
    kind = FIX_KIND_OF_STATE[state]
    if not draft:
        return ("defuse", kind)
    return ("proceed", kind)


def stranded_live(draft, armed, reviewed_match, mergeable, gate):
    """PURE live re-derivation of the stranded posture: a DRAFTED, UNARMED PR whose current head
    equals its reviewed-sha marker on a cleanly-mergeable base with a concluded-GREEN gate. The
    loop has no autonomous exit from that state (re-review is bound to a head advance, ci-fix to
    a red gate, rebase to a conflict, arm to a review outcome), so it is handed loudly to a
    human. Anything else — armed, ready, unreviewed, red/pending/unknown gate, conflicting or
    still-computing base — is some other path's job and must NOT be escalated."""
    return (draft is True and not armed and reviewed_match
            and mergeable is True and gate == "success")


def enumerate_disarm_items(repo, pulls, pr_status, provenance, bot_login=""):
    """PURE armed-SHA-mismatch enumerator (registry issue #42): any ARMED worker PR whose live
    head no longer equals its recorded reviewed-sha marker is a safety violation — the GitHub
    auto-merge latch survives force-pushes, so on green CI a never-reviewed tree would merge.
    An UNARMED but READY (non-draft) worker PR with the same mismatch is ALSO emitted: that is a
    disarm interrupted between disable-auto and redraft (or an arm crash between ready and
    merge --auto), and re-emitting it until the invariant holds is what makes the disarm loop
    re-entrant across crash windows. A drafted unarmed PR has nothing latched and nothing
    interrupted — never emitted. CLAIM re-derives every precondition live (worker-pr.py disarm
    --when mismatch) before acting, and matching SHAs are NEVER emitted (an unarmed ready PR
    whose head equals its marker is the valid arm=false-policy terminal). Trust surface mirrors
    enumerate_review_items; a review:needs-user or needs:user PR is human-owned (a human
    arm/park decision stands). A check_runs_degraded snapshot record is CONSUMED here on
    purpose (PR #60 round-1): the disarm reads only head_sha + the armed bit — both detail
    fields — so check-run volume must never stand this net down (that would be fail-OPEN:
    the one admission whose ACT is the safety measure, defeatable by churning a head past
    the check-run ceiling)."""
    items = []
    for pull in pulls:
        if not isinstance(pull, dict):
            raise DispatchError("disarm enumeration met a malformed pull request")
        number = pull.get("number")
        head = pull.get("head") or {}
        ref = str(head.get("ref", ""))
        sha = str(head.get("sha", ""))
        head_repo = (head.get("repo") or {}).get("full_name")
        login = str((pull.get("user") or {}).get("login", ""))
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            continue
        if pull.get("state") != "open":
            continue
        if not HEAD_REF_RE.match(ref) or head_repo != repo:
            continue
        if not login.endswith("[bot]") or (bot_login and login != bot_login):
            continue
        record = provenance.get(number)
        record_number = record.get("pr_number") if isinstance(record, dict) else None
        # Strict int identity, bool excluded — same float/bool-equality hazard as
        # provenance_admission_error: 41.0 == 41 and True == 1 under a bare !=.
        if (not isinstance(record_number, int) or isinstance(record_number, bool)
                or record_number != number):
            continue                      # never loop-armed without provenance — leave to humans
        if not SAFE_SHA.fullmatch(sha):
            continue
        labels = {label.get("name") if isinstance(label, dict) else label
                  for label in (pull.get("labels") or [])}
        if labels & HUMAN_HOLD_PR_LABELS:
            continue
        status = pr_status.get(number) if isinstance(pr_status, dict) else None
        if not isinstance(status, dict) or status.get("head_sha") != sha:
            continue                      # stale/unknown snapshot — unknown never acts
        if status.get("armed") is not True and pull.get("draft") is True:
            continue                      # unarmed draft — nothing latched, nothing interrupted
        reviewed = REVIEWED_SHA_RE.search(pull.get("body") or "")
        reviewed_sha = reviewed.group(1) if reviewed else "none"
        if reviewed_sha == sha:
            continue                      # the arm is bound to this exact head — valid, keep it
        items.append({"pr_number": number, "head_sha": sha,
                      "reviewed_sha": reviewed_sha, "repo": repo})
    items.sort(key=lambda item: (item["repo"], item["pr_number"]))
    return items


def _pull_provably_inactive(pull, status):
    """True iff a HUMAN-PARKED worker PR provably cannot reach main on its own — the busy-
    partition carve-out guard (round-2 P1 HELD != INACTIVE, restricted to DRAFTS ONLY in
    round 3). Provably inactive means exactly one thing: a DRAFT with no latched arm
    visible anywhere. Draft is the loop's own defused state — the disarm path converts to
    draft, and GitHub cancels/refuses auto-merge on drafts — and the measured
    frontier-collapse population is exactly parked drafts (26/27 open sparq worker PRs,
    2026-07-18). A draft that still SHOWS a latched arm — an `auto_merge` dict on a
    raw-REST row (defense in depth; the PLAN snapshot projection drops the field), or a
    fresher PLAN detail record (pr_ci_status) whose armed bit reads True — is a
    crashed-disarm artifact and reads ACTIVE, fail closed.

    EVERY parked NON-draft stays busy unconditionally: non-draft queue/arm state is NOT
    provable from the REST snapshot. The dispatch.yml PLAN `pr_snapshot` projection
    carries no `auto_merge` field at all, and even a full REST row cannot prove a
    non-draft inert — merge-queue membership is GraphQL-only (worker-pr.py
    `_merge_queue_state`, issue #69: a directly-queued PR can show NO REST latch), so a
    null/absent `auto_merge` may still be a queued PR about to merge. Round 2's non-draft
    `auto_merge: null` branch was therefore unsound AND unreachable in production
    (round-3 P1s); it is gone. A missing/garbage `draft` field reads ACTIVE (busy)."""
    if isinstance(pull.get("auto_merge"), dict):
        return False                      # latched arm on a raw-REST row — it may merge
    if isinstance(status, dict) and status.get("armed") is True:
        return False                      # detail read says latched — crashed-disarm artifact
    return pull.get("draft") is True      # non-draft/unknown: never provably inactive


def busy_packages_of_pulls(repo, pulls, issue_labels, provenance, pr_status=None):
    """PURE busy-area union for the PLAN conflict partition (registry issue #27): every open
    same-repo `sparq-agent/*` PR that can still LAND in a crate — because the review loop
    still owns it, or because a latched/unknown arm means it may merge regardless — reserves
    the `area:*` packages of its provenance-linked source issue plus its own PR labels. A
    linked issue with NO area labels reserves the serializing global partition (mirrors the
    target ready-engine).

    LINKAGE PARITY (round-2 P2): the source issue comes from the SAME validated provenance
    record enumerate_review_items admits (is_enumerable_provenance) — NEVER the branch name.
    Divergent linkage let the two sides disagree in both directions: branch-parked/
    provenance-live freed a crate the enumerator still emits into (mid-air collision), and
    branch-live/provenance-parked kept reserving a crate the enumerator had already handed
    to a human (frontier collapse preserved). A PR with MISSING/invalid provenance is
    invisible to the enumerator but can still carry a latched arm, and its true crate is
    unknowable — it reserves the GLOBAL partition (fail closed; the old "stray branch
    reserves nothing" rule freed exactly the crate an armed stray could merge into). A valid
    record whose source issue is absent from the open-issue map mirrors the enumerator,
    which still emits that PR as `__global__`.

    HELD != INACTIVE (round-2 P1 on the 2026-07-18 frontier collapse, DRAFTS-ONLY since
    round 3): a human-parked PR — `review:needs-user`/`needs:user` on the PR, or `needs:*`
    on the provenance-linked source issue — frees its packages ONLY when it is a
    provably-inert DRAFT (_pull_provably_inactive: draft with no visible latch; a latched
    draft is a crashed-disarm artifact and stays busy). EVERY parked NON-draft stays BUSY
    unconditionally: groom parks stale non-draft PRs WITHOUT disarming, and non-draft
    queue/arm state is not provable from the REST snapshot (the PLAN projection carries no
    auto_merge field, and merge-queue membership is GraphQL-only per worker-pr.py's own
    doctrine — a directly-queued PR shows no REST latch), so an unprovable park could merge
    mid-air into a crate this partition just freed for a sibling. The measured collapse
    (26 of 27 open sparq worker PRs source-parked, ~1 plan item/tick against a 13-row
    frontier, dispatch runs 29664401328/29665207000) is still fixed: the collapse
    population is parked DRAFTS, and those free. The parked SOURCE issue itself stays
    `needs:*`-gated out of the target ready engine, so freeing an inert PR's crate can
    never re-dispatch the parked issue — only siblings in the same crate."""
    busy = set()
    for pull in pulls:
        if not isinstance(pull, dict) or pull.get("state") != "open":
            continue
        head = pull.get("head") or {}
        if not HEAD_REF_RE.match(str(head.get("ref", ""))):
            continue
        if (head.get("repo") or {}).get("full_name") != repo:
            continue                      # fork head — cannot land in a target crate
        number = pull.get("number")
        pr_labels = {
            label.get("name") if isinstance(label, dict) else label
            for label in (pull.get("labels") or [])
        }
        areas = {label[5:] for label in pr_labels
                 if isinstance(label, str) and label.startswith("area:")}
        parked = bool(pr_labels & HUMAN_HOLD_PR_LABELS)
        record = provenance.get(number) if isinstance(provenance, dict) else None
        if is_enumerable_provenance(record, number):
            source = (issue_labels.get(record["issue"])
                      if isinstance(issue_labels, dict) else None)
            if isinstance(source, list):
                if any(isinstance(label, str) and label.startswith("needs:")
                       for label in source):
                    parked = True         # source issue human-parked — same terminal posture
                issue_areas = {label[5:] for label in source
                               if isinstance(label, str) and label.startswith("area:")}
                areas |= issue_areas or {GLOBAL_PACKAGE}
            else:
                areas |= {GLOBAL_PACKAGE}  # closed/unlisted source: the enumerator still
                                           # emits this PR as `__global__` — mirror it
        else:
            areas |= {GLOBAL_PACKAGE}      # missing/invalid linkage — fail closed
        status = pr_status.get(number) if isinstance(pr_status, dict) else None
        if parked and _pull_provably_inactive(pull, status):
            continue                      # provably inert human-parked PR — frees its crates
        busy |= areas
    return busy


def filter_busy_area_items(items, repo, pulls, issue_labels, provenance, pr_status=None):
    """Drop plan items whose package has an in-flight worker PR (registry issue #27: the review
    loop's PRs were invisible to the busy-area partition, double-dispatching onto a busy crate).
    Global semantics mirror the target ready-engine: a global reservation blocks everything, and
    a global item cannot co-run with ANY reserved package. `provenance`/`pr_status` are the same
    maps handed to enumerate_review_items — the busy partition and the enumerator must read the
    same linkage and the same arm state (round-2 P1/P2)."""
    busy = busy_packages_of_pulls(repo, pulls, issue_labels, provenance, pr_status)
    if not busy:
        return items
    kept = []
    for item in items:
        package = item.get("package")
        if GLOBAL_PACKAGE in busy or package == GLOBAL_PACKAGE or package in busy:
            continue
        kept.append(item)
    return kept


def provenance_admission_error(record, pr_number):
    """Return why a PARSED provenance record for target PR ``pr_number`` is NOT admissible by
    the review loop, or None when it passes EVERY record-shape requirement of EVERY consumer.

    This is the ONE definition of "enumerable provenance" — the complete union of every field
    constraint the review path enforces before driving a PR:
    - dict shape + strict-int matching ``pr_number`` (float/bool excluded: 41.0 == 41 and
      True == 1 under Python equality) + registered ``impl_provider`` (PLAN admission in
      enumerate_review_items, review-fix.yml resolve),
    - ``impl_alias`` a safe atom (review-fix.yml resolve: the alias flows into workflow
      outputs and model prompts),
    - ``issue`` a positive integer, bool excluded (review-fix.yml resolve + the source-issue
      needs:* human-hold reads here and in review-fix.yml — a bool/zero/negative issue makes
      the ``repos/<repo>/issues/<issue>`` read crash the run into the lease-expiry retry loop),
    - well-formed 40-hex ``head_sha_at_open`` (CLAIM ancestry check, review-fix.yml resolve),
    - salted 16-hex ``impl_account_h`` (locked decision 22a; CLAIM reviewer!=implementer
      assertion, review-fix.yml resolve).

    EVERY consumer calls this ONE function — enumerate_review_items (PLAN), the CLAIM record
    re-read below, review-fix.yml's resolve step (imports this module from the registry
    checkout), and groom.py's draft age-park carve-out (is_enumerable_provenance): a stale
    draft worker PR is review-loop-owned (exempt from the terminal needs:user park) exactly
    when this returns None. Adding a field constraint HERE updates every consumer in the same
    commit — the partial-replica drift that groom-preserved a review-rejected draft (round-3
    finding: alias/issue unchecked) is structurally impossible to reintroduce."""
    if not isinstance(record, dict):
        return "provenance record is not a JSON object"
    number = record.get("pr_number")
    # Strict int identity, bool excluded: Python's cross-type equality (41.0 == 41,
    # True == 1) would otherwise ADMIT a JSON float or bool pr_number under a bare !=.
    if not isinstance(number, int) or isinstance(number, bool) or number != pr_number:
        return "provenance record does not match this PR"
    impl_provider = record.get("impl_provider")
    # isinstance BEFORE the set membership: an unhashable JSON value ([] / {}) would
    # TypeError the lookup, and this predicate must REJECT a malformed record, never
    # raise — a raise here aborts the whole PLAN/groom run instead of parking one orphan.
    if not isinstance(impl_provider, str) or impl_provider not in IMPL_PROVIDERS:
        return "provenance implementer provider is invalid"
    impl_alias = record.get("impl_alias")
    if not isinstance(impl_alias, str) or not SAFE_ATOM.fullmatch(impl_alias):
        return "provenance implementer alias is invalid"
    impl_account_h = record.get("impl_account_h")
    if not isinstance(impl_account_h, str) or not re.fullmatch(r"[0-9a-f]{16}", impl_account_h):
        return ("provenance implementer account hash is invalid "
                "(legacy raw-handle records must be re-recorded via backfill-provenance.py)")
    issue = record.get("issue")
    if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
        return "provenance issue number is invalid"
    opened_sha = record.get("head_sha_at_open")
    if not isinstance(opened_sha, str) or not SAFE_SHA.fullmatch(opened_sha):
        return "provenance head sha is malformed"
    return None


def is_enumerable_provenance(record, pr_number):
    """True iff the review loop will admit target PR ``pr_number``'s provenance record —
    a thin predicate over provenance_admission_error (the single source of truth; see its
    docstring for the field set and the consumer list)."""
    return provenance_admission_error(record, pr_number) is None


def enumerate_review_items(repo, pulls, provenance, leases, issue_labels, now, bot_login="",
                           pr_status=None):
    """PURE review_items enumerator (called by the dispatch.yml PLAN step against its own data;
    unit-tested by --self-test). Fail-closed trust posture (locked decisions 1/3/11/13/19):
    - only open PRs whose head branch matches the worker pattern,
    - head.repo MUST be the target repo (a fork PR with a spoofed head ref is never enumerated),
    - the author must be a [bot] (and the App bot when `bot_login` is known),
    - a REGISTRY provenance record must exist for the PR (the root of trust — the target model
      cannot write the registry), carrying a valid impl provider,
    - review:needs-user AND needs:user (groom's parked-PR marker) are TERMINAL (human-owned) for
      every state including the repair states, and a `needs:*` label on the provenance-linked
      SOURCE issue parks the PR the same way (groom's stale paths ping a maintainer when they
      park — autonomy stands down until the human clears the label) — required so a
      budget-exhausted or groom escalation actually halts the loop. Round-budget exhaustion
      is deliberately NOT excluded here: CLAIM re-derives the live round count and applies the
      terminal needs-user transition itself, so a PR whose final outcome mutation crashed (label
      never landed) converges to a loud human hand-off instead of silently stalling,
    - a PR with a LIVE review/fix lease is not re-emitted (the reconciler re-emits a
      review:changes PR with NO live fix lease, so a crashed fix converges),
    - a needs-review PR whose head equals its reviewed-sha marker is skipped (no re-review
      without a head advance; the non-empty-diff gate runs at CLAIM time).

    `pr_status` (optional, {number: pr_ci_status(...)}) admits the zero-manual repair states over
    the SAME surface — draft or not, any non-terminal review state:
    - needs-rebase: a CONFLICTING base (mutually exclusive with, and prioritized over, both the
      review/fix loop and the ci-fix — CI and reviews on a conflicted base are noise),
    - needs-ci-fix: the authoritative gate check CONCLUDED failure on the CURRENT head while the
      loop has nothing else to do for the PR (the merge-queue starver: crate-scoped local gates
      pass, full-matrix legs are red, reviews approve on substance, nothing fixes CI). A gate
      still in progress is NOT enumerated (no churn). A status whose head_sha disagrees with the
      live listing is stale and ignored (unknown never acts),
    - stranded: a DRAFTED, unarmed PR whose reviewed head has a concluded-GREEN gate on a clean
      base — no other state can re-admit it, so CLAIM escalates it to a human (needs-user)
      after its own live re-derivation. A READY (non-draft) unarmed PR in the same posture is
      deliberately NOT stranded: that is the valid arm=false-policy terminal (human merges)."""
    live_keys = _live_holder_keys(leases, now)
    items = []
    for pull in pulls:
        if not isinstance(pull, dict):
            raise DispatchError("review enumeration met a malformed pull request")
        number = pull.get("number")
        head = pull.get("head") or {}
        ref = str(head.get("ref", ""))
        sha = str(head.get("sha", ""))
        head_repo = (head.get("repo") or {}).get("full_name")
        login = str((pull.get("user") or {}).get("login", ""))
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            continue
        if pull.get("state") != "open":
            continue
        if not HEAD_REF_RE.match(ref):
            continue
        if head_repo != repo:
            continue                      # fork head — attacker-controlled, never reviewed
        if not login.endswith("[bot]") or (bot_login and login != bot_login):
            continue
        record = provenance.get(number)
        if not is_enumerable_provenance(record, number):
            continue                      # missing/invalid registry provenance record — fail
                                          # closed by the ONE shared predicate (CLAIM,
                                          # review-fix.yml resolve, and groom's draft carve-out
                                          # apply the same one, so "enumerated here" and
                                          # "admitted there" cannot drift)
        impl_provider = record["impl_provider"]
        labels = sorted({
            label.get("name") if isinstance(label, dict) else label
            for label in (pull.get("labels") or [])
            if isinstance(label, (dict, str))
        } - {None})
        if HUMAN_HOLD_PR_LABELS & set(labels):
            continue                      # terminal — human-owned, nothing autonomous re-enters
        if not SAFE_SHA.fullmatch(sha):
            continue
        issue_number = record["issue"]    # a positive int — guaranteed by the predicate above
        source_labels = issue_labels.get(issue_number, [])
        if any(isinstance(label, str) and label.startswith("needs:") for label in source_labels):
            continue                      # the SOURCE issue is human-parked (groom/escalation) —
                                          # the whole PR surface is human-owned too
        draft = pull.get("draft") is True
        status = pr_status.get(number) if isinstance(pr_status, dict) else None
        if not isinstance(status, dict) or status.get("head_sha") != sha:
            status = {}                   # stale/unknown CI snapshot — unknown never acts
        elif status.get("check_runs_degraded"):
            # PLAN's check-run read degraded for this PR: keep ONLY the detail-derived
            # fields (head_sha / conflicting / armed — all read successfully BEFORE the
            # check runs failed) and drop everything check-run-derived, so the gate-
            # dependent admissions (ci-fix, stranded) stand down while the conflict
            # repair and the disarm net still evaluate on sound data. MONOTONE by
            # construction (round-2 finding): a degraded/forged marker yields the
            # unmarked outcome or DO-NOTHING, never a DIFFERENT act — blanking the whole
            # status here would flip a conflicting PR from needs-rebase into the
            # status-independent review/fix flow (a state SWITCH, not a narrowing).
            status = {"head_sha": status.get("head_sha"),
                      "conflicting": status.get("conflicting"),
                      "armed": status.get("armed")}
        lease_free = (f"fix:{repo}#{number}" not in live_keys
                      and f"review:{repo}#{number}" not in live_keys)
        areas = sorted(label[5:] for label in source_labels if label.startswith("area:"))
        reviewed = REVIEWED_SHA_RE.search(pull.get("body") or "")
        reviewed_match = bool(reviewed and reviewed.group(1) == sha)

        def emit(state, context=""):
            items.append({
                "pr_number": number,
                "head_sha": sha,
                "state": state,
                "impl_provider": impl_provider,
                "repo": repo,
                "package": areas[0] if areas else "__global__",
                "security": _security_flagged(set(labels) | set(source_labels)),
                "context": context[:CI_CONTEXT_MAX],
            })

        # GAP-B: conflict repair FIRST and alone — CI on a conflicted base is noise.
        if status.get("conflicting") is True:
            if lease_free:
                emit("needs-rebase")
            continue
        if draft:
            if "review:changes" in labels:
                if f"fix:{repo}#{number}" in live_keys:
                    continue              # a fix run is live; the reconciler re-emits if it dies
                emit("needs-fix")
                continue
            # review:needs, a provenance-backfilled pre-migration PR with no review:* label yet,
            # or a crashed-disarm artifact still carrying review:pass while drafted (no valid
            # flow leaves a DRAFT labelled review:pass, so re-review is the converging action).
            if f"review:{repo}#{number}" in live_keys:
                continue
            if not reviewed_match:
                emit("needs-review")
                continue
            # head already reviewed — fall through to the ci-fix consideration below (this is
            # exactly the starved posture: the loop is done with this head, CI is not).
        # GAP-A: red authoritative gate on the current head, loop otherwise idle for this PR.
        if status.get("gate") == "failure" and lease_free:
            emit("needs-ci-fix", context=", ".join(status.get("failing_legs") or []))
        elif (draft and reviewed_match and lease_free
                and status.get("gate") == "success"
                and status.get("conflicting") is False
                and status.get("armed") is not True):
            # Absorbing-state escape (never-silent-stall): a DRAFTED, unarmed PR whose reviewed
            # head has a concluded-GREEN gate has no other autonomous exit (re-review requires a
            # head advance, ci-fix a red gate, rebase a conflict, arm a review outcome). It is
            # the residue of a defused arm whose repair trigger evaporated, or of a crashed
            # disarm — CLAIM re-derives it live and hands it loudly to a human.
            emit("stranded")
    items.sort(key=lambda item: (item["repo"], item["pr_number"]))
    return items


def filter_deferred_items(items, repo, leases, now):
    """Drop deferred-retry items that still have a LIVE lease (a worker is already on them)."""
    live_keys = _live_holder_keys(leases, now)
    return [
        item for item in items
        if not item.get("deferred") or f"{repo}#{item['number']}" not in live_keys
    ]


def _run_gh(args, *, check=True):
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        operation = args[0] if args else "request"
        raise DispatchError(f"GitHub {operation} failed")
    return result


def _gh_json(args):
    result = _run_gh(args)
    try:
        return json.loads(result.stdout or "null")
    except json.JSONDecodeError as exc:
        raise DispatchError("GitHub returned malformed JSON") from exc


def _labels(issue):
    labels = issue.get("labels") if isinstance(issue, dict) else None
    if not isinstance(labels, list):
        raise DispatchError("target issue labels are malformed")
    result = []
    for label in labels:
        name = label.get("name") if isinstance(label, dict) else None
        if not isinstance(name, str) or not name:
            raise DispatchError("target issue carries a malformed label")
        result.append(name)
    return sorted(set(result))


def _issue_is_trusted(issue):
    author = issue.get("user", {}).get("login") if isinstance(issue, dict) else None
    association = str(issue.get("author_association", "")).upper() if isinstance(issue, dict) else ""
    return (
        isinstance(author, str)
        and (author.endswith("[bot]") or association in TRUSTED_ASSOCIATIONS)
    )


def _linked_open_pr_issues(pages):
    if not isinstance(pages, list):
        raise DispatchError("target pull-request listing is malformed")
    linked = set()
    for page in pages:
        if not isinstance(page, list):
            raise DispatchError("target pull-request page is malformed")
        for pull in page:
            if not isinstance(pull, dict):
                raise DispatchError("target pull-request entry is malformed")
            head = pull.get("head", {}).get("ref", "")
            body = pull.get("body") or ""
            if not isinstance(head, str) or not isinstance(body, str):
                raise DispatchError("target pull-request fields are malformed")
            linked.update(int(number) for number in re.findall(
                r"(?:^|/)issue-([1-9][0-9]*)-", head
            ))
            linked.update(int(number) for number in re.findall(
                r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#([1-9][0-9]*)\b", body
            ))
    return linked


def _routing_at_plan_sha(repo, path, sha):
    meta = _gh_json(["api", f"repos/{repo}/contents/{path}?ref={sha}"])
    if not isinstance(meta, dict) or meta.get("type") != "file":
        raise DispatchError(f"protected routing file is missing for {repo}")
    try:
        encoded = "".join(meta["content"].split())
        raw = base64.b64decode(encoded, validate=True).decode("utf-8")
        return tomllib.loads(raw)
    except (KeyError, ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise DispatchError(f"protected routing file is malformed for {repo}") from exc


def _open_blockers(repo, body):
    """Issue #102 readiness leg: re-derive `Blocked-by: #N` from the LIVE body and confirm every
    referenced issue is closed, using registry-owned code — CLAIM never trusts the planner's
    open-blocker count. Returns the sorted list of blocker numbers still OPEN. Fail-closed: a
    blocker whose live state cannot be fetched, or whose state is anything other than exactly
    "open"/"closed", raises DispatchError (the item then defers, per the per-item resilience in
    dispatch()), so a row CLAIM cannot prove unblocked is never dispatched."""
    numbers = sorted({int(match) for match in BLOCKED_BY_RE.findall(body)})
    still_open = []
    for number in numbers:
        blocker = _gh_json(["api", f"repos/{repo}/issues/{number}"])
        state = blocker.get("state") if isinstance(blocker, dict) else None
        if state == "open":
            still_open.append(number)
        elif state != "closed":
            # null/"unknown"/non-string states are NOT proof of closure — fail closed rather
            # than dispatch a row whose blocker cannot be confirmed resolved.
            raise DispatchError(f"blocker {repo}#{number} state is unreadable")
    return still_open


def _current_issue_matches(repo, item):
    issue = _gh_json(["api", f"repos/{repo}/issues/{item['number']}"])
    if not isinstance(issue, dict) or "pull_request" in issue or issue.get("state") != "open":
        return False, "issue is no longer an open issue"
    labels = _labels(issue)
    if labels != item["labels"]:
        return False, "issue labels changed after planning"
    author = issue.get("user", {}).get("login")
    if author != item["author"]:
        return False, "issue author changed after planning"
    body = issue.get("body") or ""
    if not isinstance(body, str) or hashlib.sha256(body.encode()).hexdigest() != item["body_sha"]:
        return False, "issue body changed after planning"
    if not _issue_is_trusted(issue):
        return False, "issue is not maintainer/collaborator/bot authored"
    # Issue #102: re-prove the readiness predicate in registry-owned CLAIM code rather than trusting
    # the hostile planner's frontier. `kind:epic` is a non-dispatchable tracking umbrella, and any
    # still-open `Blocked-by: #N` gates the row. Both legs apply on the normal AND deferred paths —
    # a deferred-retry of a re-blocked or epic issue must fail closed exactly like a fresh one.
    if NON_DISPATCHABLE in labels:
        return False, "issue is a non-dispatchable epic"
    blocked = _open_blockers(repo, body)
    if blocked:
        return False, "issue has unresolved blockers: " + ", ".join(f"#{n}" for n in blocked)
    if item["deferred"]:
        # Deferred-retry (locked decision 20): status:deferred IS the trigger; every other
        # busy/gated label still fails closed. CLAIM flips deferred->ready on dispatch.
        if "status:deferred" not in labels:
            return False, "issue is no longer deferred"
        if "status:ready" in labels:
            return False, "issue already re-attested ready (normal path will dispatch it)"
        if any(label in DEFERRED_GATED or label.startswith("needs:") for label in labels):
            return False, "deferred issue is otherwise busy or gated"
        return True, ""
    if "status:ready" not in labels:
        return False, "issue lost status:ready"
    if any(label in BUSY_OR_GATED or label.startswith("needs:") for label in labels):
        return False, "issue became busy or gated"
    return True, ""


def _target_tokens_map():
    """[OPUS-4.8] defects #1,#5: the PER-OWNER target App-token map. dispatch.yml mints one App
    token per DISTINCT manifest owner and passes {owner: token} as JSON in TARGET_GH_TOKENS. The
    single-target legacy env TARGET_GH_TOKEN is still honoured as a fallback (mapped to the first
    manifest owner via TARGET_GH_TOKEN_OWNER), so a single-target deployment is unchanged. This is
    the fix for the wrong-owner-token bug: with two targets, targets[0]'s token would 404 every
    registry-owner disarm / needs-user / deferred-label mutation and defer-retry them forever."""
    raw = os.environ.get("TARGET_GH_TOKENS", "")
    tokens = {}
    if raw:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DispatchError("TARGET_GH_TOKENS is not valid JSON") from exc
        if not isinstance(data, dict):
            raise DispatchError("TARGET_GH_TOKENS must be a {owner: token} object")
        for owner, token in data.items():
            if isinstance(owner, str) and isinstance(token, str) and owner and token:
                tokens[owner] = token
    legacy = os.environ.get("TARGET_GH_TOKEN", "")
    legacy_owner = os.environ.get("TARGET_GH_TOKEN_OWNER", "")
    if legacy and legacy_owner and legacy_owner not in tokens:
        tokens[legacy_owner] = legacy
    return tokens


def _target_token(repo):
    """The App token scoped to the OWNER of `repo`. Empty when this owner has no minted token
    (that owner's mutation paths then DEFER loudly instead of 404-looping with a wrong-owner
    token). `repo` is an owner/name string."""
    if not isinstance(repo, str) or "/" not in repo:
        return ""
    owner = repo.split("/", 1)[0]
    return _target_tokens_map().get(owner, "")


def _run_target_helper(script_dir, repo, script, args):
    """Run a registry helper (worker-issue.py / worker-pr.py) against the TARGET repo under the
    OWNER-scoped target App token. The ambient GH_TOKEN stays the registry workflow token."""
    token = _target_token(repo)
    if not token:
        raise DispatchError(
            f"target-scoped App token is unavailable for owner {repo.split('/', 1)[0]!r}")
    result = subprocess.run(
        [sys.executable, str(script_dir / script), *args],
        capture_output=True, text=True, check=False,
        env={**os.environ, "GH_TOKEN": token},
    )
    if result.returncode != 0:
        # Surface the failure cause: the helper's stderr never contains the token (GH_TOKEN is
        # env-only and the helpers never echo it), and without this line a deterministic
        # App-token-specific failure is invisible in the CLAIM log (live incident 2026-07-17:
        # 5 defuses failed silently while the same command succeeded under a user token).
        tail = " | ".join((result.stderr or result.stdout or "").strip().splitlines()[-3:])[:300]
        raise DispatchError(
            f"target helper {script} {args[0] if args else ''} failed: {tail or 'no output'}")
    return result


def _pr_needs_user(script_dir, repo, pr_number, issue, reason):
    args = ["needs-user", "--repo", repo, "--pr", str(pr_number), "--reason", reason]
    if isinstance(issue, int) and issue > 0:
        args += ["--issue", str(issue)]
    _run_target_helper(script_dir, repo, "worker-pr.py", args)


def _run_gh_target_comment(repo, issue_or_pr, body):
    token = _target_token(repo)
    if not token:
        raise DispatchError("target-scoped App token is unavailable")
    result = subprocess.run(
        ["gh", "api", "-X", "POST", f"repos/{repo}/issues/{issue_or_pr}/comments", "--input", "-"],
        input=json.dumps({"body": body}), capture_output=True, text=True, check=False,
        env={**os.environ, "GH_TOKEN": token},
    )
    if result.returncode != 0:
        raise DispatchError("target comment failed")


def _pr_comments(repo, pr_number):
    pages = _gh_json([
        "api", "--paginate", "--slurp", f"repos/{repo}/issues/{pr_number}/comments?per_page=100",
    ])
    if not isinstance(pages, list):
        raise DispatchError("target PR comments are malformed")
    return [item for page in pages if isinstance(page, list) for item in page]


def record_file_path(ledger_root, registry_root, relative):
    """Resolve a provenance/verdict record file: the `ledger` data-plane branch checkout is the
    PRIMARY location (issue #96 — master's required `gate` check rejects every direct
    contents-API PUT, so post-outage records land ONLY on the ledger branch), and the legacy
    master registry checkout is the fallback so pre-outage records (<= sparq#2542) stay
    visible. An empty ledger_root (no ledger checkout wired) reads the legacy path only."""
    if ledger_root:
        candidate = Path(ledger_root) / relative
        if candidate.is_file():
            return candidate
    return Path(registry_root) / relative


def latest_recorded_progress(worker_pr, registry_root, repo, number, rounds, comments,
                             bot_login, ledger_root=""):
    """The LATEST verdict's progress grade for decide_budget. Primary source: the registry
    verdict record for the newest recorded round (written FIRST in the outcome ordering, so it
    survives a crash before the findings comment); fallback: the durable progress marker in the
    bot's findings comment. Missing/unreadable/ungraded degrades to None (decide_budget treats
    that as not-improving — fail closed toward a human, never toward a silent extension)."""
    if rounds < 1:
        return None
    path = record_file_path(ledger_root, registry_root,
                            worker_pr.verdict_path(repo, number, rounds))
    if path.is_file():
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            document = None
        if isinstance(document, dict):
            progress = document.get("progress")
            if progress in worker_pr.PROGRESS_VALUES:
                return progress
    return worker_pr.round_progress(comments, bot_login).get(rounds)


def _resolvable_chain(chain, routing):
    """Keep only chain aliases the harness can actually run (locked decision 14). A CLAUDE alias
    needs a concrete provider_model. A CODEX alias is resolvable even with a missing/TBD
    provider_model: the proven codex drain passes NO --model flag (codex CLI default; the
    operator config pins only reasoning effort), and worker-live.sh omits --model in that case —
    so an unpinned terra never turns into the common-case liveness stop of every
    anthropic-implemented PR escalating to needs-user. An empty result means the direction is
    genuinely unresolvable and the caller must escalate to a human immediately (never
    silent-queue)."""
    models = routing.get("models") if isinstance(routing, dict) else None
    if not isinstance(models, dict):
        return []
    usable = []
    for alias in chain:
        meta = models.get(alias)
        if not isinstance(meta, dict):
            continue
        provider_model = meta.get("provider_model")
        concrete = (isinstance(provider_model, str) and provider_model != "TBD"
                    and SAFE_ATOM.fullmatch(provider_model))
        codex_default = (meta.get("harness") == "codex"
                         and provider_model in (None, "", "TBD"))
        if concrete or codex_default:
            usable.append(alias)
    return usable


def _dispatch_review_items(review_items, repo, policy, routing, allocator, worker_pr,
                           registry_repo, registry_root, workflow_ref, bot_login, usage, margin,
                           defer_reasons, ledger_root=""):
    """Hostile re-validation + claim + launch for the review/fix loop. Every item failure SKIPS
    that item (per-item resilience, like the issue loop). `defer_reasons` is the tick's SHARED
    histogram: allocator lease errors here must fold into the same `lease-error` counter the
    issue loop uses, because _ledger_health/_ledger_rot_zeroed_dispatch (issue #28) read that
    counter — an all-review/fix tick whose claims all errored would otherwise report ledger=ok
    and dodge the zero-dispatch fail-loud."""
    launched = 0
    script_dir = Path(__file__).resolve().parent
    max_rounds = int(policy.get("max_review_rounds", 3))
    for item in review_items:
        number = item["pr_number"]
        try:
            if not bot_login:
                print(f"defer review {repo}#{number}: bot login unavailable (no App token)")
                continue
            repair_state = item["state"] in {"needs-ci-fix", "needs-rebase"}
            pull = _gh_json(["api", f"repos/{repo}/pulls/{number}"])
            if not isinstance(pull, dict) or pull.get("state") != "open":
                print(f"defer review {repo}#{number}: PR is no longer open")
                continue
            draft = pull.get("draft") is True
            if not draft and not repair_state:
                print(f"defer review {repo}#{number}: PR is no longer an open draft")
                continue
            head = pull.get("head") or {}
            head_repo = (head.get("repo") or {}).get("full_name")
            head_ref = str(head.get("ref", ""))
            head_sha = str(head.get("sha", ""))
            login = str((pull.get("user") or {}).get("login", ""))
            if head_repo != repo or not HEAD_REF_RE.match(head_ref):
                print(f"defer review {repo}#{number}: head is not a same-repo worker branch")
                continue
            if login != bot_login:
                print(f"defer review {repo}#{number}: PR author is not the App bot")
                continue
            if head_sha != item["head_sha"] or not SAFE_SHA.fullmatch(head_sha):
                print(f"defer review {repo}#{number}: head advanced since planning; re-plan")
                continue
            labels = _labels(pull)
            held = HUMAN_HOLD_PR_LABELS & set(labels)
            if held:
                print(f"defer review {repo}#{number}: human-owned "
                      f"({'/'.join(sorted(held))})")
                continue
            record_path = record_file_path(ledger_root, registry_root,
                                           worker_pr.provenance_path(repo, number))
            if not record_path.is_file():
                print(f"defer review {repo}#{number}: no registry provenance record (fail closed)")
                continue
            try:
                record = json.loads(record_path.read_text(encoding="utf-8"))
            except ValueError:
                print(f"defer review {repo}#{number}: provenance record is not readable JSON "
                      "(fail closed)")
                continue
            # ONE shared record-shape admission (provenance_admission_error — same function as
            # PLAN, review-fix.yml resolve, and groom's draft carve-out), re-run on the LIVE
            # re-read so a record edited between PLAN and CLAIM still fails closed.
            record_error = provenance_admission_error(record, number)
            if record_error:
                print(f"defer review {repo}#{number}: {record_error}")
                continue
            if record["impl_provider"] != item["impl_provider"]:
                print(f"defer review {repo}#{number}: provenance disagrees with the plan")
                continue
            opened_sha = record["head_sha_at_open"]
            issue_number = record["issue"]
            # Human-owned SOURCE issue: groom's stale paths park work with needs:user (and a
            # maintainer ping) — the repair loop must never disarm/redraft/push (nor review
            # past) a PR whose work item a human explicitly owns. Live read, fail closed.
            source_issue = _gh_json(["api", f"repos/{repo}/issues/{issue_number}"])
            if any(label.startswith("needs:") for label in _labels(source_issue)):
                print(f"defer review {repo}#{number}: source issue #{issue_number} is "
                      "human-owned (needs:*)")
                continue
            if opened_sha != head_sha:
                compare = _gh_json(["api", f"repos/{repo}/compare/{opened_sha}...{head_sha}"])
                if compare.get("status") not in {"identical", "ahead"}:
                    # Rewritten history — the worker-opened commit is no longer an ancestor.
                    _pr_needs_user(script_dir, repo, number, issue_number,
                                   "the PR head no longer descends from the worker-opened commit "
                                   "(history was rewritten); refusing autonomous review")
                    continue
            fix_kind, fix_context = "verdict", ""
            if repair_state:
                # The plan row is HOSTILE AND STALE: re-derive the repair trigger from LIVE data
                # BEFORE any mutation — including the defuse. A non-draft (ready/armed) PR is
                # only ever defused on a live-confirmed trigger; if the trigger evaporated
                # between PLAN and now (a flaky gate leg re-ran green, the base moved past the
                # conflict) the item defers with NO mutation, and a matching-SHA valid arm
                # keeps merging (the earlier head check already pinned live head == plan head).
                live_gate = None
                if item["state"] == "needs-ci-fix" and pull.get("mergeable") is not False:
                    # check_name filter is load-bearing: sparq heads carry ~200 check runs, so an
                    # unfiltered page-1 read drops the `gate` run entirely -> gate reads "missing"
                    # -> every ci-fix defers forever (observed live 2026-07-17: PLAN emitted 7
                    # repair items, CLAIM dispatched 0). The gate STATUS is the only live-safety
                    # input; the failing-leg names are advisory prompt context and come from the
                    # item's PLAN-computed `context` (paginated snapshot, validated <=1000).
                    checks = _gh_json([
                        "api",
                        f"repos/{repo}/commits/{head_sha}/check-runs"
                        f"?check_name={CI_GATE_CHECK}&per_page=100"])
                    live_ci = interpret_check_runs(
                        (checks or {}).get("check_runs") if isinstance(checks, dict) else None)
                    live_gate = live_ci["gate"]
                decision, detail = decide_repair_admission(
                    item["state"], pull.get("mergeable"), live_gate, draft)
                if decision == "defer":
                    print(f"defer review {repo}#{number}: {detail}")
                    continue
                if decision == "defuse":
                    # Live-confirmed trigger on a ready/armed PR: it must be defused BEFORE an
                    # autonomous push can ride the stale auto-merge latch (issue #42), and the
                    # review sweep only enumerates drafts. disarm --when always is idempotent +
                    # live-revalidated; the repair item re-admits next tick against the draft.
                    _run_target_helper(script_dir, repo, "worker-pr.py", [
                        "disarm", "--repo", repo, "--pr", str(number), "--when", "always"])
                    print(f"defer review {repo}#{number}: defused to draft for {item['state']}; "
                          "retried next tick")
                    continue
                fix_kind = detail
                if fix_kind == "ci":
                    fix_context = item["context"][:CI_CONTEXT_MAX]
            elif item["state"] == "stranded":
                # Loud escape from the absorbing {drafted, unarmed, reviewed head, green gate}
                # state — re-derived LIVE before the terminal hand-off; any drift (armed again,
                # head moved, gate red/pending, base conflicting) defers to the path that owns
                # the new posture instead.
                checks = _gh_json([
                    "api",
                    f"repos/{repo}/commits/{head_sha}/check-runs"
                    f"?check_name={CI_GATE_CHECK}&per_page=100"])
                live_ci = interpret_check_runs(
                    (checks or {}).get("check_runs") if isinstance(checks, dict) else None)
                reviewed = REVIEWED_SHA_RE.search(pull.get("body") or "")
                if not stranded_live(draft, isinstance(pull.get("auto_merge"), dict),
                                     bool(reviewed and reviewed.group(1) == head_sha),
                                     pull.get("mergeable"), live_ci["gate"]):
                    print(f"defer review {repo}#{number}: the stranded posture did not "
                          "re-derive on live data")
                    continue
                _pr_needs_user(script_dir, repo, number, issue_number,
                               "the PR's reviewed head has a green gate but the PR is drafted "
                               "and unarmed with nothing left for the loop to do (the residue "
                               "of an interrupted defuse/disarm); a human must re-arm it (mark "
                               "ready + enable auto-merge) or restart the review")
                print(f"escalated {repo}#{number}: stranded reviewed head handed to a human")
                continue
            comments = _pr_comments(repo, number)
            rounds = worker_pr.count_rounds(comments, bot_login)
            impl_provider = record["impl_provider"]
            run_key = (f"{os.environ.get('GITHUB_RUN_ID', 'local')}."
                       f"{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}")
            # Round budget via the PURE decide_budget (maintainer directive 2026-07-17): the
            # flat rounds>=max needs-user is replaced by exhaustion-with-escalation — first a
            # model-tier extension (pin the fix floor one tier up when a weaker model burned the
            # base budget), then an improving-progress extension, both bounded by the hard cap.
            # The terminal transition is still applied HERE (not just skipped) so a PR whose
            # final review outcome crashed before its needs-user label landed converges loudly.
            # Corrupt/forged escalation markers are ALSO loud (needs-user): silently ignoring a
            # bad pin would run the unpinned chain — the fall-back-down the pin forbids.
            try:
                round_models = worker_pr.fix_round_models(comments, bot_login)
                fix_models = sorted({model for models in round_models.values()
                                     for model in models})
                progress = latest_recorded_progress(worker_pr, registry_root, repo, number,
                                                    rounds, comments, bot_login,
                                                    ledger_root=ledger_root)
                pin_floor = worker_pr.pinned_fix_floor(comments, bot_login, impl_provider)
                # A needs-review head whose LATEST round carries a fix-model marker is a PUSHED
                # fix awaiting its re-review (an executed fix flips the label to review:needs).
                # decide_budget authorizes grading it even at exhaustion — otherwise the model
                # pin's terminal grant orphans the top-tier fix round: its own marker falsifies
                # the "top tier not yet run" predicate while the latest recorded grade predates
                # the fix (it graded the weaker tier's stagnant output). Other states pass no
                # pending fix: review:changes / repair markers for the current round record
                # no-change or gate-failed attempts, not a pushed head awaiting grading.
                pending_fix = (round_models.get(rounds, [])
                               if item["state"] == "needs-review" else [])
                budget = worker_pr.decide_budget(rounds, fix_models, progress, impl_provider,
                                                 base_rounds=max_rounds,
                                                 pending_fix_models=pending_fix,
                                                 pin_floor=pin_floor)
            except worker_pr.WorkerPrError as exc:
                _pr_needs_user(script_dir, repo, number, issue_number,
                               f"round-budget escalation-marker validation failed ({exc}); a "
                               "human must inspect this PR's round/model/pin markers")
                continue
            if budget["action"] == "needs-user":
                _pr_needs_user(script_dir, repo, number, issue_number,
                               f"the review round budget is exhausted at {rounds} round(s) "
                               f"(base {max_rounds}, hard cap {worker_pr.HARD_CAP_ROUNDS}) "
                               "with no extension left — the top fix tier has run, the latest "
                               "verdict does not grade the PR improving, and no pushed fix at "
                               "or above the pinned floor awaits re-review; a human must "
                               "decide")
                continue
            if budget["action"] == "extend-model-pin" and budget["pin"]:
                # Converge the durable pin marker (normally recorded by the review outcome; this
                # covers a crashed outcome). record_model_pin is idempotent and an existing
                # equal-or-higher floor wins, so re-running it every tick is safe.
                _run_target_helper(script_dir, repo, "worker-pr.py", [
                    "record-model-pin", "--repo", repo, "--pr", str(number),
                    "--round", str(max(rounds, 1)), "--tier", budget["pin"],
                    "--provider", impl_provider, "--run-key", run_key,
                    "--bot-login", bot_login])
                ladder = worker_pr.ESCALATION_LADDERS[impl_provider]
                if pin_floor is None or ladder.index(budget["pin"]) > ladder.index(pin_floor):
                    pin_floor = budget["pin"]
            # DEFER-NOT-FALLBACK (the WHY): once a floor is pinned, tiers BELOW it are never
            # offered to the allocator again for this PR. The extended budget exists precisely
            # because the below-floor model already burned the base budget without converging,
            # so when no at/above-floor account is free the claim returns None and the item
            # simply DEFERS to the next tick — falling back down the chain would silently spend
            # the extension re-running the model that already failed. (The missed-fix marker
            # budget still bounds how long it can defer before a loud needs-user.)
            fix_aliases = (worker_pr.pinned_fix_chain(impl_provider, pin_floor)
                           if pin_floor else FIX_CHAIN[impl_provider])
            # Privacy (locked decision 22a): provenance stores ONLY the salted account hash; a
            # raw-handle/missing hash already deferred above (provenance_admission_error).
            impl_account_h = record["impl_account_h"]
            if item["state"] == "needs-review":
                reviewed = REVIEWED_SHA_RE.search(pull.get("body") or "")
                if reviewed and reviewed.group(1) == head_sha:
                    print(f"defer review {repo}#{number}: head already reviewed")
                    continue
                base_branch = str((pull.get("base") or {}).get("repo", {}).get(
                    "default_branch", "")) or "main"
                diff = _gh_json(["api", f"repos/{repo}/compare/{base_branch}...{head_sha}"])
                if not diff.get("files"):
                    print(f"defer review {repo}#{number}: empty diff vs merge base (no-op rebase)")
                    continue
                mode, role = "review", "review"
                chain = _resolvable_chain(REVIEW_CHAIN[impl_provider], routing)
                holder_prefix, cap, ttl = "review:", REVIEW_MAX_CONCURRENT, REVIEW_TTL
                round_number = rounds + 1
            elif repair_state:
                # GAP-A/B autonomous repair (reuse mode=fix, same-provider chain). The live
                # trigger was re-derived ABOVE (before any defuse could run). Budgets are
                # SHARED with the review loop: rounds>=max_rounds already escalated above, every
                # pushed repair flips to review:needs (the re-review consumes a round), and the
                # missed/nochange/gatefail markers below bound in-round churn — a ci-fix
                # ping-pong therefore always terminates in review:needs-user.
                mode, role = "fix", "fix"
                round_number = max(rounds, 1)
                missed = worker_pr.marker_runs(comments, bot_login, "missed", round_number)
                if len(missed) >= MISSED_FIX_LIMIT:
                    _pr_needs_user(script_dir, repo, number, issue_number,
                                   f"{len(missed)} consecutive fix dispatches missed for round "
                                   f"{round_number}; a human must unstick this PR")
                    continue
                chain = _resolvable_chain(fix_aliases, routing)
                holder_prefix, cap, ttl = "fix:", FIX_MAX_CONCURRENT, FIX_TTL
            else:
                if rounds < 1:
                    print(f"defer review {repo}#{number}: review:changes with no recorded round")
                    continue
                missed = worker_pr.marker_runs(comments, bot_login, "missed", rounds)
                if len(missed) >= MISSED_FIX_LIMIT:
                    _pr_needs_user(script_dir, repo, number, issue_number,
                                   f"{len(missed)} consecutive fix dispatches missed for round "
                                   f"{rounds}; a human must unstick this PR")
                    continue
                verdict_file = record_file_path(ledger_root, registry_root,
                                                worker_pr.verdict_path(repo, number, rounds))
                if not verdict_file.is_file():
                    _run_target_helper(script_dir, repo, "worker-pr.py", [
                        "record-marker", "--repo", repo, "--pr", str(number), "--kind", "missed",
                        "--round", str(rounds), "--run-key",
                        f"{os.environ.get('GITHUB_RUN_ID', 'local')}."
                        f"{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}",
                        "--bot-login", bot_login])
                    print(f"defer review {repo}#{number}: round {rounds} verdict record missing")
                    continue
                mode, role = "fix", "fix"
                chain = _resolvable_chain(fix_aliases, routing)
                holder_prefix, cap, ttl = "fix:", FIX_MAX_CONCURRENT, FIX_TTL
                round_number = rounds
            if not chain:
                # The inverse (or same-provider) chain cannot resolve a concrete model right now
                # (e.g. terra provider_model unset). Never silent-queue: hand to a human.
                _pr_needs_user(script_dir, repo, number, issue_number,
                               f"the {mode} model chain for a {impl_provider}-implemented PR is "
                               "unresolvable in the target routing (no concrete provider model)")
                continue
        except DispatchError as exc:
            print(f"defer review {repo}#{number}: revalidation failed ({exc}); skipped")
            continue
        now = int(time.time())
        holder = f"{holder_prefix}{repo}#{number}@dispatch-" \
                 f"{os.environ.get('GITHUB_RUN_ID', 'local')}." \
                 f"{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}"
        try:
            claim = allocator.claim(
                registry_repo,
                item["package"],
                role,
                chain,
                holder,
                now,
                ttl=ttl,
                account_pool=policy["account_pool"],
                holder_prefix=holder_prefix,
                max_holder_concurrent=cap,
                usage=usage,
                margin=margin,
            )
        except (RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            defer_reasons["lease-error"] += 1
            print(f"defer review {repo}#{number}: lease allocation errored ({exc}); skipped")
            continue
        if claim is None:
            if mode == "fix":
                try:
                    _run_target_helper(script_dir, repo, "worker-pr.py", [
                        "record-marker", "--repo", repo, "--pr", str(number), "--kind", "missed",
                        "--round", str(round_number), "--run-key",
                        f"{os.environ.get('GITHUB_RUN_ID', 'local')}."
                        f"{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}",
                        "--bot-login", bot_login])
                except DispatchError:
                    pass
            print(f"defer review {repo}#{number}: no eligible {mode} lease is free this tick")
            continue
        account = claim.get("account")
        claim_id = claim.get("claim_id")
        claim_provider = claim.get("provider")
        # Cross-provider fail-closed assertions (locked decision 6, claim layer). The account
        # comparison runs on SALTED HASHES (locked decision 22a) — the provenance record never
        # holds a raw handle, so the live handle is hashed here with the same PROVENANCE_SALT;
        # a missing salt fails closed (never dispatch with the assertion unverified).
        salt = os.environ.get("PROVENANCE_SALT", "")
        violation = ""
        if not isinstance(account, str) or not re.fullmatch(r"acct[0-9a-z]{2,}", account) \
                or not isinstance(claim_id, str) or not re.fullmatch(r"[0-9a-f]{32}", claim_id) \
                or claim.get("model") not in chain:
            violation = "allocator returned an unsafe/out-of-policy claim"
        elif mode == "review" and (not claim_provider or claim_provider == impl_provider):
            violation = "reviewer provider would equal implementer provider"
        elif mode == "review" and not salt:
            violation = "PROVENANCE_SALT unavailable; cannot assert reviewer != implementer"
        elif mode == "review" and worker_pr.account_hash(account, salt) == impl_account_h:
            violation = "reviewer account would equal implementer account"
        elif mode == "fix" and claim_provider and claim_provider != impl_provider:
            violation = "fixer provider would differ from implementer provider"
        if violation:
            _release_failed_dispatch(allocator, registry_repo, str(claim_id or ""))
            print(f"defer review {repo}#{number}: {violation}; released + skipped")
            continue
        result = _run_gh([
            "workflow", "run", "review-fix.yml",
            "--repo", registry_repo,
            "--ref", workflow_ref,
            "-f", f"target_repo={repo}",
            "-f", f"pr_number={number}",
            "-f", f"mode={mode}",
            "-f", f"fix_kind={fix_kind}",
            "-f", f"fix_context={fix_context}",
            # The pinned fix-model floor rides along so the workflow's own chain resolution
            # honours it (review mode never carries a pin; the input is ladder-validated there).
            "-f", f"model_pin={(pin_floor or '') if mode == 'fix' else ''}",
            "-f", f"review_round={round_number}",
            "-f", f"account={account}",
            "-f", f"claim_id={claim_id}",
        ], check=False)
        if result.returncode != 0:
            released = _release_failed_dispatch(allocator, registry_repo, claim_id)
            if not released:
                print("::error::review-fix dispatch failed and its lease could not be released")
            print(f"defer review {repo}#{number}: {mode} dispatch failed; skipped")
            continue
        launched += 1
        # Privacy (locked decision 22b): public workflow logs never carry account handles.
        kind_note = "" if fix_kind == "verdict" else f"/{fix_kind}"
        print(f"dispatched {mode}{kind_note} {repo}#{number}: round={round_number}, "
              f"claim={claim_id[:8]}")
    return launched


def _apply_disarm_items(disarm_items, repo, script_dir, bot_login):
    """GAP-C (registry issue #42): retract stale GitHub auto-merge latches BEFORE any fix/review
    admission each sweep. The plan rows are HOSTILE — worker-pr.py `disarm --when mismatch`
    re-derives every precondition from the LIVE API (open same-repo bot worker PR, armed OR
    ready with an interrupted disarm, head != reviewed-sha marker, not human-owned via
    review:needs-user / needs:user) and is a no-op otherwise, so a spoofed row can never disarm
    a validly-armed or human-owned PR. Failures skip the item (per-item resilience); the
    enumeration re-emits next tick until the invariant holds — including across a crash between
    disable-auto and redraft, which mismatch mode re-enters via the ready-but-unarmed leg."""
    for item in disarm_items:
        number = item["pr_number"]
        try:
            if not bot_login or not _target_token(repo):
                print(f"defer disarm {repo}#{number}: target App token unavailable")
                continue
            _run_target_helper(script_dir, repo, "worker-pr.py", [
                "disarm", "--repo", repo, "--pr", str(number), "--when", "mismatch"])
            print(f"disarm {repo}#{number}: live armed-SHA invariant re-checked and applied")
        except DispatchError as exc:
            print(f"defer disarm {repo}#{number}: {exc}; retried next tick")
            continue


def _route_matches(repo, item, policy_doc, routing_doc, policy_module):
    try:
        resolved = policy_module.resolve(repo, item["labels"], policy_doc, routing_doc)
    except ValueError as exc:
        raise DispatchError(f"policy resolution failed for {repo}#{item['number']}") from exc
    expected = {
        "model_chain": item["model_chain"],
        "agent": item["agent"],
        "escalate": item["escalate"],
    }
    if any(resolved[key] != value for key, value in expected.items()):
        raise DispatchError(f"plan route no longer matches protected routing for {repo}#{item['number']}")
    roles = sorted(label[5:] for label in item["labels"] if label.startswith("role:"))
    packages = sorted(label[5:] for label in item["labels"] if label.startswith("area:"))
    priorities = sorted(
        int(match.group(1))
        for label in item["labels"]
        for match in [re.fullmatch(r"priority:P([0-4])", label)]
        if match
    )
    if roles != [item["role"]] or priorities != [item["priority"]]:
        raise DispatchError(f"plan labels disagree with route fields for {repo}#{item['number']}")
    if item["package"] != (packages[0] if packages else "__global__"):
        raise DispatchError(f"plan package disagrees with labels for {repo}#{item['number']}")
    return resolved


def _enabled_repositories(policy_doc, policy_module):
    repos = policy_doc.get("repos") if isinstance(policy_doc, dict) else None
    if not isinstance(repos, dict):
        raise DispatchError("registry policy has no repos table")
    enabled = set()
    for repo, row in repos.items():
        if not isinstance(row, dict) or not isinstance(row.get("enabled"), bool):
            raise DispatchError(f"registry policy enabled flag is malformed for {repo}")
        if row["enabled"]:
            try:
                policy_module._policy_row(repo, policy_doc)
            except ValueError as exc:
                raise DispatchError(f"enabled registry policy is invalid for {repo}") from exc
            enabled.add(repo)
    return enabled


def _release_failed_dispatch(allocator, registry_repo, claim_id):
    try:
        return allocator.release(registry_repo, claim_id, int(time.time()))
    except Exception:
        return False


def escalate_starved(escalate, usage, effective_cap):
    """Escalation contract (routing.toml `escalate = true`, security/soundness surfaces): those
    routes pin a RESTRICTED model chain (e.g. opus-only) and must ESCALATE to a human on
    chain-exhaustion instead of silently starving or degrading to a weaker model. True when the
    LIVE usage probe is present and shows ZERO accounts able to serve the chain (dynamic
    concurrency 0). With no usage map the signal is unknown, so the item simply defers (the
    require_usage fail-closed hold + usage-alert cover that case)."""
    return bool(escalate) and usage is not None and effective_cap == 0


def _load_usage():
    """Optional live-usage map for usage-aware dispatch, written by scripts/account-usage.py and passed
    via WORKER_USAGE_FILE. Absent/empty/unreadable -> None, and dispatch falls back to the static cap
    with no usage gating (backward compatible)."""
    path = os.environ.get("WORKER_USAGE_FILE")
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) and data else None


def dispatch(plan_path, policy_path, registry_repo, workflow_ref, script_dir,
             registry_root=".", bot_login="", ledger_root=""):
    policy_module = _load_module("registry_policy_resolve", script_dir / "policy-resolve.py")
    allocator = _load_module("registry_select_and_claim", script_dir / "select-and-claim.py")
    worker_pr = _load_module("registry_worker_pr", script_dir / "worker-pr.py")
    worker_issue = _load_module("registry_worker_issue", script_dir / "worker-issue.py")
    usage = _load_usage()
    catalog_cache = {"accounts": None}  # read the account catalog at most once, only if usage-aware
    try:
        with open(plan_path, encoding="utf-8") as handle:
            plan = validate_plan(json.load(handle))
        with open(policy_path, "rb") as handle:
            policy_doc = tomllib.load(handle)
    except (OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise DispatchError("cannot load dispatcher plan or policy") from exc

    planned_repositories = {entry["target_repo"] for entry in plan["repositories"]}
    enabled_repositories = _enabled_repositories(policy_doc, policy_module)
    if planned_repositories != enabled_repositories:
        raise DispatchError("PLAN target manifest does not exactly match enabled registry policy")
    if not workflow_ref or "\n" in workflow_ref or "\r" in workflow_ref:
        raise DispatchError("worker workflow ref is missing or unsafe")

    dispatched = 0
    # Zero-dispatch visibility (registry #28/#32): count the ready items the PLAN carried and, per
    # tick, WHY each was NOT launched. A tick that PLANNED work but launched NOTHING is a health
    # signal (capacity/access/lease contention, not an empty backlog); the CLAIM step records it +
    # renders this histogram to the job summary. Categories are coarse (no issue numbers/handles).
    planned = sum(len(repository["items"]) + len(
        [e for e in plan["review_items"] if e["repo"] == repository["target_repo"]])
        for repository in plan["repositories"])
    # Per-item snapshot degradation (run 29617040167): PLAN skipped these PRs' CI/merge
    # snapshot (oversized check-run listing, failed detail read, census overflow) instead of
    # failing the sweep. Their snapshot-derived admissions already stood down at PLAN time
    # (no pr_status record); here they are made VISIBLE — logged and counted into the
    # dispatch-summary histogram, so a snapshot-degraded tick never looks like a quiet one.
    defer_reasons = snapshot_skip_reasons(plan["snapshot_skips"])
    for skip in plan["snapshot_skips"]:
        print(f"snapshot skip {skip['repo']}#{skip['pr_number']}: {skip['reason']} "
              "(snapshot-derived PR admissions stood down this tick)")
    # EARLY summary write (review defect #6): persist the plan-derived planned count BEFORE any
    # claim-side work, so a mid-claim abort (API/validation/setup failure) still leaves a
    # planned>0/launched-0 summary for the workflow's always()-guarded tick recorder — instead of
    # a missing file that used to read as planned=0 and record nothing. The final write below
    # overwrites it with the real launched count + histogram.
    _write_dispatch_summary(planned, 0, defer_reasons)
    for repository in plan["repositories"]:
        repo = repository["target_repo"]
        try:
            policy = policy_module._policy_row(repo, policy_doc)
        except ValueError as exc:
            raise DispatchError(f"registry policy is invalid for {repo}") from exc
        routing = _routing_at_plan_sha(repo, policy["routing"], repository["target_sha"])
        pull_pages = _gh_json([
            "api", "--paginate", "--slurp", f"repos/{repo}/pulls?state=open&per_page=100"
        ])
        linked_open_prs = _linked_open_pr_issues(pull_pages)

        # Safety invariant FIRST (issue #42): stale arm latches are retracted before any fix or
        # review admission can push onto (or re-review past) an armed, mutated head.
        _apply_disarm_items(
            [entry for entry in plan["disarm_items"] if entry["repo"] == repo],
            repo, script_dir, bot_login)

        for item in repository["items"]:
            number = item["number"]
            if number in linked_open_prs:
                defer_reasons["existing-pr"] += 1
                print(f"defer {repo}#{number}: an open worker/closing PR already exists")
                continue
            # [OPUS-4.8] Per-item resilience: a single item's trust/route/policy resolution failure
            # must SKIP that item, not abort the whole dispatch (which would strand the other ready
            # issues and mark the run failed). Global setup errors above still abort as before.
            try:
                current, reason = _current_issue_matches(repo, item)
                if not current:
                    defer_reasons["stale-issue"] += 1
                    print(f"defer {repo}#{number}: {reason}")
                    continue
                resolved = _route_matches(repo, item, policy_doc, routing, policy_module)
                if item["deferred"]:
                    # Deferred-retry budget (locked decision 20): re-dispatch is bounded by the
                    # SAME durable attempt markers the worker records; exhausted -> needs-user +
                    # a maintainer-visible comment, never another silent attempt.
                    if not bot_login or not _target_token(repo):
                        defer_reasons["no-target-token"] += 1
                        print(f"defer {repo}#{number}: deferred retry needs the target App token")
                        continue
                    comments = _pr_comments(repo, number)
                    used = worker_issue.count_attempts(comments, bot_login)
                    if used >= resolved["max_attempts"]:
                        _run_target_helper(script_dir, repo, "worker-issue.py", [
                            "status", "--repo", repo, "--issue", str(number),
                            "--status", "needs-user"])
                        _run_gh_target_comment(repo, number,
                                               f"> 🤖 SPARQ agent — deferred-retry budget "
                                               f"exhausted ({used}/{resolved['max_attempts']} "
                                               "attempts). "
                                               f"@{os.environ.get('MAINTAINER_HANDLE', 'jeswr')} "
                                               "this issue needs a human.")
                        defer_reasons["budget-exhausted"] += 1
                        print(f"escalated {repo}#{number}: deferred-retry budget exhausted")
                        continue
            except DispatchError as exc:
                defer_reasons["route-policy-failed"] += 1
                print(f"defer {repo}#{number}: trust/route/policy resolution failed ({exc}); skipped")
                continue
            now = int(time.time())
            holder_prefix = f"{repo}#"
            holder = f"{repo}#{number}@dispatch-{os.environ.get('GITHUB_RUN_ID', 'local')}." \
                     f"{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}"
            ttl = resolved["worker_timeout_minutes"] * 60 + 900
            # Dynamic concurrency: when live usage is available, the cap is the number of accounts with
            # real headroom (starts high, backs off as utilisation climbs), bounded by the static policy
            # max_concurrent. FAIL-CLOSED: a repo with require_usage=true and NO usage map (a TOTAL probe
            # failure) HOLDS this cycle rather than dispatching ungated onto possibly rate-limited
            # accounts. Without require_usage, absent usage falls back to the static cap (backward compat).
            margin = resolved["usage_safety_margin"]
            if usage is None and resolved["require_usage"]:
                defer_reasons["usage-probe-unavailable"] += 1
                print(f"defer {repo}#{number}: require_usage set but live usage is unavailable "
                      "(probe failed) — holding fail-closed")
                continue
            if usage is not None:
                if catalog_cache["accounts"] is None:
                    catalog_cache["accounts"] = allocator.read_accounts(registry_repo)
                pool = set(resolved["account_pool"])
                pool_accounts = [a for a in catalog_cache["accounts"] if a["handle"] in pool]
                effective_cap = allocator.dynamic_concurrency(
                    pool_accounts, usage, model_chain=resolved["model_chain"],
                    absolute_cap=resolved["max_concurrent"], margin=margin)
                if escalate_starved(resolved.get("escalate"), usage, effective_cap):
                    # Security surfaces never degrade: chain-exhaustion -> needs:user, loudly.
                    try:
                        _run_target_helper(script_dir, repo, "worker-issue.py", [
                            "status", "--repo", repo, "--issue", str(number),
                            "--status", "needs-user"])
                        _run_gh_target_comment(
                            repo, number,
                            "> 🤖 SPARQ agent — this task routes to the restricted "
                            f"`{'/'.join(resolved['model_chain'])}` tier (a security/soundness "
                            "surface, `escalate = true` in routing.toml), and NO account currently "
                            "has usage headroom to run that tier. Escalating to a human instead of "
                            "silently starving or degrading to a weaker model. "
                            f"@{os.environ.get('MAINTAINER_HANDLE', 'jeswr')}: free capacity (or "
                            "decide the route), then remove `needs:user` and re-add "
                            "`status:ready`.")
                        defer_reasons["escalate-tier-starved"] += 1
                        print(f"escalated {repo}#{number}: escalate-tier has no eligible account")
                    except DispatchError as exc:
                        defer_reasons["escalate-tier-starved"] += 1
                        print(f"defer {repo}#{number}: escalate-tier starved, escalation "
                              f"failed ({exc}); retried next tick")
                    continue
            else:
                effective_cap = resolved["max_concurrent"]
            try:
                claim = allocator.claim(
                    registry_repo,
                    item["package"],
                    item["role"],
                    resolved["model_chain"],
                    holder,
                    now,
                    ttl=ttl,
                    account_pool=resolved["account_pool"],
                    holder_prefix=holder_prefix,
                    max_holder_concurrent=effective_cap,
                    usage=usage,
                    margin=margin,
                )
            except (RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
                defer_reasons["lease-error"] += 1
                print(f"defer {repo}#{number}: lease allocation errored ({exc}); skipped")
                continue
            if claim is None:
                # No eligible account/slot: the dominant capacity/access signal for zero-dispatch.
                defer_reasons["no-eligible-account"] += 1
                print(
                    f"defer {repo}#{number}: duplicate lease, repository cap, or account cap is active"
                )
                continue
            account = claim.get("account")
            model = claim.get("model")
            claim_id = claim.get("claim_id")
            secret_ref = claim.get("secret_ref")
            if (not isinstance(account, str) or not re.fullmatch(r"acct[0-9a-z]{2,}", account)
                    or model not in resolved["model_chain"]
                    or not isinstance(claim_id, str) or not re.fullmatch(r"[0-9a-f]{32}", claim_id)
                    or secret_ref != f"{account.upper()}_TOKEN"):
                _release_failed_dispatch(allocator, registry_repo, str(claim_id or ""))
                defer_reasons["unsafe-claim"] += 1
                print(f"defer {repo}#{number}: allocator returned an unsafe/out-of-policy claim; released + skipped")
                continue

            if item["deferred"]:
                # Strip status:deferred + restore status:ready ON DISPATCH so the worker's
                # reverify (which requires status:ready) passes. If the workflow launch below
                # fails, the issue is simply a ready issue again next tick — it converges.
                try:
                    _run_target_helper(script_dir, repo, "worker-issue.py", [
                        "status", "--repo", repo, "--issue", str(number), "--status", "retry"])
                except DispatchError as exc:
                    _release_failed_dispatch(allocator, registry_repo, claim_id)
                    defer_reasons["label-flip-failed"] += 1
                    print(f"defer {repo}#{number}: deferred label flip failed ({exc}); released")
                    continue

            result = _run_gh([
                "workflow", "run", "worker.yml",
                "--repo", registry_repo,
                "--ref", workflow_ref,
                "-f", f"target_repo={repo}",
                "-f", f"issue_number={number}",
                "-f", f"account={account}",
                "-f", f"claim_id={claim_id}",
                "-f", "dry_run=false",
            ], check=False)
            if result.returncode != 0:
                released = _release_failed_dispatch(allocator, registry_repo, claim_id)
                if not released:
                    print("::error::worker dispatch failed and its lease could not be released")
                defer_reasons["dispatch-launch-failed"] += 1
                print(f"defer {repo}#{number}: worker dispatch failed; skipped")
                continue
            dispatched += 1
            kind = "deferred-retry" if item["deferred"] else "worker"
            # Privacy (locked decision 22b): public workflow logs never carry account handles.
            print(f"dispatched {kind} {repo}#{number}: model={model}, claim={claim_id[:8]}")

        repo_review_items = [
            entry for entry in plan["review_items"] if entry["repo"] == repo
        ]
        if repo_review_items:
            dispatched += _dispatch_review_items(
                repo_review_items, repo, policy, routing, allocator, worker_pr,
                registry_repo, registry_root, workflow_ref, bot_login, usage,
                float(policy.get("usage_safety_margin", 0.10)),
                defer_reasons, ledger_root=ledger_root)
    print(f"dispatcher complete: {dispatched} worker/review/fix run(s) launched")

    # Final summary (registry #28/#32): overwrite the early claim-start write with the real
    # launched count + defer-reason histogram.
    _write_dispatch_summary(planned, dispatched, defer_reasons)

    # Fail LOUD on ledger rot (issue #28): a tick that launched NOTHING because the lease ledger
    # errored (CAS failures, unreadable ledger, auth) is byte-identical to a genuinely empty
    # frontier if it stays green — infra rot can then zero the fleet for hours with nothing
    # alerting. When the ledger errored AND nothing dispatched, fail the run so the tick is not
    # mistaken for a quiet backlog. The `ledger=error` field surfaces the same signal on a tick
    # that still dispatched (partial ledger flakiness), but that tick does NOT fail — dispatching
    # is demonstrably working and per-item resilience must hold.
    if _ledger_rot_zeroed_dispatch(dispatched, defer_reasons):
        raise DispatchError(
            f"lease ledger errored on {defer_reasons['lease-error']} item(s) and NOTHING "
            "dispatched this tick — failing loud so ledger rot is not read as an empty frontier")


def _ledger_rot_zeroed_dispatch(dispatched, defer_reasons):
    """Issue #28 fail-loud boundary: True IFF the lease ledger errored this tick AND nothing
    launched — the exact case that is byte-identical to an empty frontier and so must fail the run
    rather than stay green. A tick that dispatched at least one item returns False even with ledger
    errors present (dispatching works; per-item resilience holds); a zero-dispatch tick with NO
    ledger error (a genuinely empty/contended frontier) also returns False."""
    return dispatched == 0 and bool(defer_reasons.get("lease-error", 0))


def _ledger_health(defer_reasons):
    """Lease-ledger health for a tick (issue #28): 'error' if ANY item's claim raised a lease-
    ledger I/O error this tick (CAS failure, unreadable ledger, auth) — the coarse signal that
    tells a zero-dispatch tick caused by ledger rot apart from a genuinely empty frontier — else
    'ok'. Derived from the same `lease-error` defer counter dispatch() folds in; no ledger contents
    or account handles leak into it."""
    return "error" if defer_reasons.get("lease-error", 0) else "ok"


def _write_dispatch_summary(planned, dispatched, defer_reasons):
    """Zero-dispatch visibility (registry #28/#32): emit a compact, privacy-safe summary
    ({planned, dispatched, frontier_size, ledger, defer_reasons histogram}) for the CLAIM step to
    render + record. `frontier_size` is the ready-frontier size the tick observed (== planned) and
    `ledger` is ok|error — together they let the run summary distinguish an empty frontier from a
    lease-ledger failure (issue #28), which both otherwise present as a green 0-dispatch tick. NO
    issue numbers or account handles — only coarse category counts. Best-effort file write; a
    failure here must never fail dispatch. Called at claim START (planned only — review defect #6)
    and again at the end with the launched counts."""
    summary_path = os.environ.get("DISPATCH_SUMMARY_FILE")
    if not summary_path:
        return
    try:
        with open(summary_path, "w", encoding="utf-8") as handle:
            json.dump({"planned": planned, "dispatched": dispatched,
                       "frontier_size": planned, "ledger": _ledger_health(defer_reasons),
                       "defer_reasons": dict(defer_reasons)}, handle)
    except OSError as exc:
        print(f"::warning::dispatch summary write failed ({exc}); continuing")


def _self_test():
    fixture = {
        "schema": SCHEMA,
        "generated_at": "2026-07-16T12:00:00Z",
        "repositories": [{
            "target_repo": "example/repo",
            "target_sha": "a" * 40,
            "items": [{
                "number": 7,
                "priority": 1,
                "package": "crate-a",
                "role": "impl",
                "model_chain": ["fable", "terra"],
                "agent": "repo-impl",
                "escalate": False,
                "labels": ["area:crate-a", "priority:P1", "role:impl", "status:ready"],
                "author": "maintainer",
                "body_sha": "b" * 64,
                "deferred": False,
            }, {
                "number": 9,
                "priority": 2,
                "package": "crate-b",
                "role": "impl",
                "model_chain": ["fable", "terra"],
                "agent": "repo-impl",
                "escalate": False,
                "labels": ["area:crate-b", "priority:P2", "role:impl", "status:deferred"],
                "author": "maintainer",
                "body_sha": "c" * 64,
                "deferred": True,
            }],
        }],
        "review_items": [{
            "pr_number": 41,
            "head_sha": "d" * 40,
            "state": "needs-review",
            "impl_provider": "anthropic",
            "repo": "example/repo",
            "package": "crate-a",
            "security": False,
            "context": "",
        }, {
            "pr_number": 44,
            "head_sha": "e" * 40,
            "state": "needs-ci-fix",
            "impl_provider": "openai",
            "repo": "example/repo",
            "package": "crate-b",
            "security": False,
            "context": "docs-quality, opt-in wasm feature-OFF equality",
        }, {
            "pr_number": 46,
            "head_sha": "e" * 40,
            "state": "stranded",
            "impl_provider": "anthropic",
            "repo": "example/repo",
            "package": "crate-a",
            "security": False,
            "context": "",
        }],
        "disarm_items": [{
            "pr_number": 45,
            "head_sha": "f" * 40,
            "reviewed_sha": "none",
            "repo": "example/repo",
        }],
        "snapshot_skips": [{
            "repo": "example/repo",
            "pr_number": 0,
            "reason": "worker-pr-census-overflow",
        }, {
            "repo": "example/repo",
            "pr_number": 48,
            "reason": "check-runs-overflow",
        }],
    }
    assert validate_plan(fixture) is fixture
    # MIXED-REPO regression (2026-07-18 outage): the assembler must emit GLOBAL
    # (repo, pr_number) order — per-repo policy order inverts it lexicographically the
    # moment a second target has review items ("jeswr/..." < "sparq-org/..."), and the
    # assembler's sort key must be pr_number (a wrong "number" key KeyErrors every
    # non-empty plan — sol r1 on #233). Simulate the assembler on reverse-policy-order
    # input and require the sorted document to validate.
    mixed = json.loads(json.dumps(fixture))
    second = json.loads(json.dumps(mixed["repositories"][0]))
    second["target_repo"] = "aaa/first-lexically"
    mixed["repositories"].append(second)
    ri = json.loads(json.dumps(mixed["review_items"][0]))
    ri["repo"] = "aaa/first-lexically"
    # policy order appends the second repo's items AFTER example/repo's — unsorted this
    # violates the global-order invariant
    mixed["review_items"] = mixed["review_items"] + [ri]
    di = json.loads(json.dumps(mixed["disarm_items"][0]))
    di["repo"] = "aaa/first-lexically"
    mixed["disarm_items"] = mixed["disarm_items"] + [di]
    try:
        validate_plan(mixed)
        raise AssertionError("unsorted mixed-repo plan must be rejected")
    except DispatchError:
        pass
    # the PRODUCTION sort — the same helper dispatch.yml calls
    validate_plan(normalize_plan_order(mixed))
    assert mixed["review_items"][0]["repo"] == "aaa/first-lexically"
    assert mixed["disarm_items"][0]["repo"] == "aaa/first-lexically"
    # A skip-free plan is the common case and must validate too.
    empty_skips = json.loads(json.dumps(fixture))
    empty_skips["snapshot_skips"] = []
    validate_plan(empty_skips)
    # The dispatch summary records the skips (run 29617040167): the fold is what dispatch()
    # seeds defer_reasons with, and the summary file carries it for the tick recorder.
    folded = snapshot_skip_reasons(fixture["snapshot_skips"])
    assert folded == {"snapshot-skip:worker-pr-census-overflow": 1,
                      "snapshot-skip:check-runs-overflow": 1}
    with tempfile.TemporaryDirectory() as summary_dir:
        summary_file = os.path.join(summary_dir, "summary.json")
        prior_summary = os.environ.get("DISPATCH_SUMMARY_FILE")
        os.environ["DISPATCH_SUMMARY_FILE"] = summary_file
        try:
            _write_dispatch_summary(5, 0, folded)
        finally:
            if prior_summary is None:
                del os.environ["DISPATCH_SUMMARY_FILE"]
            else:
                os.environ["DISPATCH_SUMMARY_FILE"] = prior_summary
        with open(summary_file, encoding="utf-8") as handle:
            recorded = json.load(handle)
    assert recorded["defer_reasons"]["snapshot-skip:check-runs-overflow"] == 1
    # Issue #28: the summary carries the ready-frontier size and lease-ledger health so a
    # 0-dispatch tick can be told apart from a ledger failure. A snapshot-skip-only tick has a
    # HEALTHY ledger (no lease-error), so ledger == "ok".
    assert recorded["frontier_size"] == 5, recorded
    assert recorded["ledger"] == "ok", recorded
    # _ledger_health flips to "error" exactly when a lease-error is folded in, and stays "ok"
    # otherwise (an empty histogram or non-ledger defers must NOT masquerade as ledger rot).
    assert _ledger_health(Counter()) == "ok"
    assert _ledger_health(Counter({"no-eligible-account": 4})) == "ok"
    assert _ledger_health(Counter({"lease-error": 1})) == "error"
    # Fail-loud boundary (issue #28): ONLY a zero-dispatch tick whose ledger errored fails the run.
    # An empty/contended frontier (no lease-error) stays green, and a tick that dispatched at least
    # one item stays green even with ledger errors present (dispatching demonstrably works).
    assert _ledger_rot_zeroed_dispatch(0, Counter({"lease-error": 2})) is True
    assert _ledger_rot_zeroed_dispatch(0, Counter()) is False
    assert _ledger_rot_zeroed_dispatch(0, Counter({"no-eligible-account": 3})) is False
    assert _ledger_rot_zeroed_dispatch(3, Counter({"lease-error": 2})) is False
    assert _issue_is_trusted({"user": {"login": "maintainer"}, "author_association": "MEMBER"})
    assert _issue_is_trusted({"user": {"login": "worker[bot]"}, "author_association": "NONE"})
    assert not _issue_is_trusted({"user": {"login": "external"}, "author_association": "CONTRIBUTOR"})

    # ---- issue #102: CLAIM independently RE-PROVES the readiness predicate (non-dispatchable
    # epic + live blocker state) from registry-owned code, never trusting the hostile planner's
    # frontier. Every assertion flips red if either leg is removed from _current_issue_matches. ----
    prev_gh_json = _gh_json

    def ready_issue(labels, body):
        return {"state": "open", "user": {"login": "maintainer"},
                "author_association": "MEMBER",
                "labels": [{"name": name} for name in labels], "body": body}

    def match_with(main_issue, blockers, item):
        def fake(args):
            found = re.search(r"/issues/(\d+)$", args[-1])
            if not found:
                raise AssertionError(f"unexpected read {args[-1]}")
            number = int(found.group(1))
            if number == item["number"]:
                return main_issue
            if number in blockers:
                return blockers[number]
            raise DispatchError(f"blocker #{number} unreadable")
        globals()["_gh_json"] = fake
        try:
            return _current_issue_matches("example/repo", item)
        finally:
            globals()["_gh_json"] = prev_gh_json

    ready_labels = sorted(["area:crate-a", "priority:P1", "role:impl", "status:ready"])
    plain_body = "do the work"
    item102 = {"number": 700, "labels": ready_labels, "author": "maintainer",
               "body_sha": hashlib.sha256(plain_body.encode()).hexdigest(), "deferred": False}
    # baseline: a ready, non-epic, unblocked issue passes every leg
    passed, _ = match_with(ready_issue(ready_labels, plain_body), {}, item102)
    assert passed, "ready unblocked non-epic issue must claim"
    # kind:epic is independently rejected even though the plan emitted it (and its labels match)
    epic_labels = sorted(ready_labels + [NON_DISPATCHABLE])
    epic_item = dict(item102, labels=epic_labels)
    epic_ok, epic_reason = match_with(ready_issue(epic_labels, plain_body), {}, epic_item)
    assert not epic_ok and "epic" in epic_reason, epic_reason
    # an OPEN `Blocked-by: #N` gates; the SAME body with a CLOSED blocker does not
    blk_body = "prep first\nBlocked-by: #42"
    blk_item = dict(item102, body_sha=hashlib.sha256(blk_body.encode()).hexdigest())
    open_ok, open_reason = match_with(
        ready_issue(ready_labels, blk_body), {42: {"state": "open"}}, blk_item)
    assert not open_ok and "#42" in open_reason, open_reason
    closed_ok, _ = match_with(
        ready_issue(ready_labels, blk_body), {42: {"state": "closed"}}, blk_item)
    assert closed_ok, "issue whose sole blocker is closed must claim"
    # the readiness legs bind the DEFERRED-retry path too (a re-blocked deferred issue fails closed)
    deferred_blk = dict(blk_item, deferred=True,
                        labels=sorted(["area:crate-a", "priority:P1", "role:impl",
                                       "status:deferred"]))
    def_ok, _ = match_with(
        ready_issue(deferred_blk["labels"], blk_body), {42: {"state": "open"}}, deferred_blk)
    assert not def_ok, "deferred-retry of a re-blocked issue must fail closed"
    # fail-closed: an UNREADABLE blocker state raises (the item then defers), never dispatches
    try:
        match_with(ready_issue(ready_labels, blk_body), {}, blk_item)
        raise AssertionError("unreadable blocker must fail closed")
    except DispatchError:
        pass
    # fail-closed: a PRESENT but malformed blocker state is not proof of closure — every
    # non-open/closed value raises rather than dispatching (null, unexpected enum, wrong type,
    # and case drift from the exact REST lowercase values all refuse)
    for bad_state in (None, "unknown", "OPEN", "Closed", 1, ["open"]):
        try:
            match_with(ready_issue(ready_labels, blk_body), {42: {"state": bad_state}}, blk_item)
            raise AssertionError(f"malformed blocker state {bad_state!r} must fail closed")
        except DispatchError:
            pass
    # the parser is byte-identical to the ready engine's blocker regex (no silent divergence)
    assert BLOCKED_BY_RE.findall("Blocked-by: #7 and blocked-by:#8") == ["7", "8"]
    # A DRAFT worker PR must land in linked_open_prs (dedupes issue re-dispatch) while the SAME PR
    # is separately enumerated as a review_item — the two enumerations must not fight (the issue
    # stays busy in status:in-progress-review while the PR cycles). Linking is head-ref/body based
    # and draft-agnostic, so this is structural; asserted here against regression.
    linked = _linked_open_pr_issues([[
        {"head": {"ref": "sparq-agent/issue-7-1-1"}, "body": "", "draft": True},
        {"head": {"ref": "topic"}, "body": "Fixes #9"},
    ]])
    assert linked == {7, 9}
    for mutate, name in (
            (lambda d: d["repositories"][0]["items"][0].update(unknown=True), "unknown item field"),
            (lambda d: d["repositories"][0]["items"][0].pop("deferred"), "missing deferred flag"),
            (lambda d: d["review_items"][0].update(state="armed"), "bad review state"),
            (lambda d: d["review_items"][0].update(state=[]), "unhashable review state"),
            (lambda d: d["review_items"][0].update(impl_provider="other"), "bad impl provider"),
            (lambda d: d["review_items"][0].update(impl_provider={}), "unhashable impl provider"),
            (lambda d: d["review_items"][0].update(repo="not/planned"), "unplanned review repo"),
            (lambda d: d["review_items"][0].update(head_sha="zz"), "bad review head sha"),
            (lambda d: d.pop("review_items"), "missing review_items"),
            (lambda d: d.update(schema="registry-dispatch-plan/v1"), "stale schema version"),
            (lambda d: d.update(schema="registry-dispatch-plan/v2"), "previous schema version"),
            (lambda d: d["review_items"][0].pop("context"), "missing review context"),
            (lambda d: d["review_items"][0].update(context="a\nb"), "multiline review context"),
            (lambda d: d["review_items"][1].update(context="x" * 1001), "oversized review context"),
            (lambda d: d.pop("disarm_items"), "missing disarm_items"),
            (lambda d: d["disarm_items"][0].update(unknown=True), "unknown disarm field"),
            (lambda d: d["disarm_items"][0].pop("reviewed_sha"), "missing disarm reviewed_sha"),
            (lambda d: d["disarm_items"][0].update(reviewed_sha="zz"), "bad disarm reviewed_sha"),
            (lambda d: d["disarm_items"][0].update(reviewed_sha="f" * 40),
             "disarm reviewed==head (nothing to disarm)"),
            (lambda d: d["disarm_items"][0].update(repo="not/planned"), "unplanned disarm repo"),
            (lambda d: d["disarm_items"].append(dict(d["disarm_items"][0])),
             "duplicate disarm item"),
            (lambda d: d.update(schema="registry-dispatch-plan/v3"),
             "pre-snapshot-skips schema version"),
            (lambda d: d.pop("snapshot_skips"), "missing snapshot_skips"),
            (lambda d: d["snapshot_skips"][0].update(unknown=True), "unknown snapshot skip field"),
            (lambda d: d["snapshot_skips"][0].update(reason="because"), "invalid snapshot skip reason"),
            (lambda d: d["snapshot_skips"][0].update(reason=[]), "unhashable snapshot skip reason"),
            (lambda d: d["snapshot_skips"][0].update(repo="not/planned"), "unplanned snapshot skip repo"),
            (lambda d: d["snapshot_skips"][0].update(pr_number=-1), "negative snapshot skip pr_number"),
            (lambda d: d["snapshot_skips"].append(dict(d["snapshot_skips"][1])),
             "duplicate snapshot skip"),
            (lambda d: d["snapshot_skips"].reverse(), "unsorted snapshot skips"),
    ):
        malformed = json.loads(json.dumps(fixture))
        mutate(malformed)
        try:
            validate_plan(malformed)
        except DispatchError:
            pass
        else:
            raise AssertionError(f"schema accepted {name}")

    # ---- review_items enumeration (fail-closed trust fixtures, locked decision 3) ----
    now = 1000
    repo = "example/repo"
    bot = "sparq-worker[bot]"
    sha_a, sha_b = "1" * 40, "2" * 40

    def pull(number, ref, sha, *, head_repo=repo, login=bot, draft=True, labels=(),
             body="", state="open"):
        return {"number": number, "state": state, "draft": draft, "body": body,
                "head": {"ref": ref, "sha": sha, "repo": {"full_name": head_repo}},
                "user": {"login": login, "type": "Bot"},
                "labels": [{"name": name} for name in labels]}

    # Privacy (locked decision 22a): provenance carries ONLY the salted 16-hex account hash.
    provenance = {
        41: {"pr_number": 41, "head_sha_at_open": sha_a, "impl_provider": "anthropic",
             "impl_alias": "fable", "impl_account_h": "ab" * 8, "issue": 7,
             "recorded_at_run": "1.1"},
        42: {"pr_number": 42, "head_sha_at_open": sha_a, "impl_provider": "openai",
             "impl_alias": "terra", "impl_account_h": "cd" * 8, "issue": 9,
             "recorded_at_run": "2.1"},
    }
    issue_labels = {7: ["area:crate-a", "role:impl"], 9: ["area:sparq-zk", "role:impl"]}
    pulls = [
        pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["review:needs"]),
        # spoofed FORK head with a worker-shaped ref: must NOT be enumerated
        pull(90, "sparq-agent/issue-1-x-1", sha_b, head_repo="mallory/fork",
             login="mallory", draft=True),
        # same-repo bot-shaped PR WITHOUT a registry provenance record: fail closed
        pull(91, "sparq-agent/issue-3-9-1", sha_b, login="other[bot]"),
        # terminal states never re-enter
        pull(42, "sparq-agent/issue-9-2-1", sha_b, labels=["review:needs-user"]),
    ]
    items = enumerate_review_items(repo, pulls, provenance, [], issue_labels, now)
    assert [item["pr_number"] for item in items] == [41], items
    assert items[0]["state"] == "needs-review" and items[0]["impl_provider"] == "anthropic"
    assert items[0]["package"] == "crate-a" and items[0]["security"] is False

    # security flag from the SOURCE issue labels (zk) — needs a provenance-linked issue
    sec = enumerate_review_items(
        repo, [pull(42, "sparq-agent/issue-9-2-1", sha_b, labels=["review:needs"])],
        provenance, [], issue_labels, now)
    assert sec and sec[0]["security"] is True

    # reviewed-sha binding: a head equal to the marker is NOT re-enumerated (no advance)
    marked = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["review:needs"],
                  body=f"x <!-- sparq-reviewed-sha:{sha_a} -->")
    assert enumerate_review_items(repo, [marked], provenance, [], issue_labels, now) == []

    # Round-budget exhaustion is deliberately NOT excluded at enumeration: CLAIM re-derives the
    # live round count and applies the terminal needs-user transition itself, so a crashed final
    # outcome (label never landed) converges loudly instead of silently stalling. Only the LABEL
    # terminal states filter here — asserted structurally by the review:needs-user case above.
    assert enumerate_review_items(repo, pulls[:1], provenance, [], issue_labels, now) != []

    # a LIVE fix lease suppresses the needs-fix item; an expired one does not (reconciler)
    changes = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["review:changes"])
    live_fix = [{"holder": f"fix:{repo}#41@run.1", "expires_at": now + 100}]
    dead_fix = [{"holder": f"fix:{repo}#41@run.1", "expires_at": now - 1}]
    assert enumerate_review_items(repo, [changes], provenance, live_fix,
                                  issue_labels, now) == []
    reconciled = enumerate_review_items(repo, [changes], provenance, dead_fix,
                                        issue_labels, now)
    assert reconciled and reconciled[0]["state"] == "needs-fix"

    # non-draft (armed/ready) PRs leave the loop
    assert enumerate_review_items(repo, [pull(41, "sparq-agent/issue-7-1-1", sha_a,
                                              draft=False)],
                                  provenance, [], issue_labels, now) == []

    # known bot login pins authorship exactly
    assert enumerate_review_items(repo, pulls[:1], provenance, [], issue_labels, now,
                                  bot_login="another[bot]") == []

    # ---- provenance_admission_error / is_enumerable_provenance (the ONE record-shape
    # admission shared by PLAN, CLAIM, review-fix.yml resolve, and groom.py's draft age-park
    # carve-out) ----
    # Known-good: exactly the fixtures the enumerator admits above — complete records with a
    # valid impl_alias and a positive-int issue.
    assert provenance_admission_error(provenance[41], 41) is None
    assert is_enumerable_provenance(provenance[41], 41)
    assert is_enumerable_provenance(provenance[42], 42)
    # PARITY battery: for EVERY malformed record, the predicate rejects AND the enumerator
    # refuses to emit the PR — the two decisions are the same function call, and this battery
    # is the regression tripwire should anyone ever split them again. Each case is keyed to
    # exactly ONE field check in provenance_admission_error (dropping that check reds it).
    def _rejected_everywhere(bad_record):
        return (not is_enumerable_provenance(bad_record, 41)
                and enumerate_review_items(repo, pulls[:1], {41: bad_record}, [],
                                           issue_labels, now) == [])
    assert _rejected_everywhere("not-a-dict")
    assert _rejected_everywhere({})
    assert _rejected_everywhere({**provenance[41], "pr_number": 40})       # mismatched PR
    # Cross-type equality hazard: Python says 41.0 == 41 and True == 1, so a JSON float or
    # bool pr_number slips through a bare != comparison. The strict int-not-bool guard
    # rejects both; reverting it to bare != ADMITS 41.0 (this assertion reds).
    assert _rejected_everywhere({**provenance[41], "pr_number": 41.0})     # float is not an int
    assert _rejected_everywhere({**provenance[41], "pr_number": True})     # bool is not an int
    assert _rejected_everywhere({**provenance[41], "pr_number": "41"})     # string is not an int
    # ... and the True == 1 direction needs a target PR of 1 to be a live tripwire:
    assert not is_enumerable_provenance({**provenance[41], "pr_number": True}, 1)
    assert _rejected_everywhere({**provenance[41], "impl_provider": "mallory"})
    # UNHASHABLE / wrong-type fields must be REJECTED, never raise: before the
    # isinstance-before-membership guard, impl_provider=[] / {} raised TypeError out of the
    # set lookup and aborted the entire PLAN/groom run instead of parking the one orphan.
    # Reverting that guard makes these assertions RAISE (mutation tripwire), not just fail.
    assert _rejected_everywhere({**provenance[41], "impl_provider": []})
    assert _rejected_everywhere({**provenance[41], "impl_provider": {}})
    assert _rejected_everywhere({**provenance[41], "impl_provider": 5})
    assert _rejected_everywhere({**provenance[41], "issue": []})
    assert _rejected_everywhere({**provenance[41], "head_sha_at_open": {}})
    assert _rejected_everywhere({**provenance[41], "impl_account_h": []})
    assert _rejected_everywhere({**provenance[41], "head_sha_at_open": "not-a-sha"})
    assert _rejected_everywhere({**provenance[41], "impl_account_h": "raw-handle@example"})
    assert _rejected_everywhere(
        {key: value for key, value in provenance[41].items() if key != "impl_account_h"})
    # Round-3 finding: alias and issue are review-fix.yml resolve requirements the old partial
    # predicate omitted — a draft carrying these passed groom's carve-out but crashed every
    # review claim into the lease-expiry retry loop. Now rejected by the same single function.
    assert _rejected_everywhere(
        {key: value for key, value in provenance[41].items() if key != "impl_alias"})
    assert _rejected_everywhere({**provenance[41], "impl_alias": "no spaces allowed"})
    assert _rejected_everywhere({**provenance[41], "impl_alias": 5})       # non-string
    assert _rejected_everywhere(
        {key: value for key, value in provenance[41].items() if key != "issue"})
    assert _rejected_everywhere({**provenance[41], "issue": 0})
    assert _rejected_everywhere({**provenance[41], "issue": -7})
    assert _rejected_everywhere({**provenance[41], "issue": True})         # bool is not an issue
    assert _rejected_everywhere({**provenance[41], "issue": "7"})          # string is not an int
    # The error strings are consumer-facing (CLAIM defer lines, review-fix.yml SystemExit):
    # assert the reason routing so a reordered/collapsed check cannot silently misreport.
    assert provenance_admission_error({**provenance[41], "impl_alias": 5}, 41) \
        == "provenance implementer alias is invalid"
    assert provenance_admission_error({**provenance[41], "issue": True}, 41) \
        == "provenance issue number is invalid"
    assert provenance_admission_error({**provenance[41], "pr_number": 41.0}, 41) \
        == "provenance record does not match this PR"
    assert provenance_admission_error({**provenance[41], "impl_provider": []}, 41) \
        == "provenance implementer provider is invalid"

    # ---- interpret_check_runs / pr_ci_status (pure CI interpreters, GAP-A inputs) ----
    runs = [
        {"name": "gate", "status": "completed", "conclusion": "failure", "started_at": "T2"},
        {"name": "docs-quality", "status": "completed", "conclusion": "failure",
         "started_at": "T1"},
        {"name": "js", "status": "completed", "conclusion": "timed_out", "started_at": "T1"},
        {"name": "green", "status": "completed", "conclusion": "success", "started_at": "T1"},
    ]
    assert interpret_check_runs(runs) == {"gate": "failure",
                                          "failing_legs": ["docs-quality", "js"]}
    # a later re-run supersedes an earlier conclusion of the same check name
    rerun = runs + [{"name": "gate", "status": "completed", "conclusion": "success",
                     "started_at": "T3"}]
    assert interpret_check_runs(rerun)["gate"] == "success"
    assert interpret_check_runs([{"name": "gate", "status": "in_progress",
                                  "conclusion": None}])["gate"] == "pending"
    assert interpret_check_runs([])["gate"] == "missing"
    assert interpret_check_runs("junk") == {"gate": "unknown", "failing_legs": []}
    assert interpret_check_runs([
        {"name": "gate", "status": "completed", "conclusion": "failure"},
        {"name": "lég\nx", "status": "completed", "conclusion": "failure"},
    ])["failing_legs"] == ["l?g?x"]

    record = {"head_sha": sha_a, "mergeable": False, "auto_merge": {"merge_method": "squash"},
              "check_runs": runs}
    ci = pr_ci_status(record)
    assert (ci["conflicting"], ci["armed"], ci["gate"]) == (True, True, "failure")
    assert pr_ci_status({**record, "mergeable": None})["conflicting"] is None
    assert pr_ci_status({**record, "mergeable": True})["conflicting"] is False
    assert pr_ci_status({**record, "auto_merge": None})["armed"] is False
    assert pr_ci_status({**record, "head_sha": "zz"}) == {}
    assert pr_ci_status("junk") == {}
    # post-detail degradation (PR #60 round-1): ANY truthy marker forces gate=missing and
    # the check-run payload is ignored OUTRIGHT — so a forged/hostile marker on a record
    # that also smuggles check runs can only stand admissions DOWN (narrows-only); the
    # detail-derived fields (armed/conflicting) survive for the disarm net alone.
    degraded_ci = pr_ci_status({**record, "check_runs_degraded": "check-runs-overflow"})
    assert (degraded_ci["gate"], degraded_ci["failing_legs"]) == ("missing", [])
    assert degraded_ci["check_runs_degraded"] is True and degraded_ci["armed"] is True
    assert pr_ci_status(record)["check_runs_degraded"] is False
    assert pr_ci_status({**record, "check_runs_degraded": True})["gate"] == "missing"

    # ---- GAP-A/B enumeration: zero-manual repair states over the same surface ----
    def status_of(status_sha, gate="success", conflicting=False, armed=False, legs=()):
        return {"head_sha": status_sha, "conflicting": conflicting, "armed": armed,
                "gate": gate, "failing_legs": sorted(legs)}

    starved = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["review:needs"],
                   body=f"x <!-- sparq-reviewed-sha:{sha_a} -->")
    red = {41: status_of(sha_a, gate="failure", legs=["docs-quality", "workspace clippy"])}
    ci_items = enumerate_review_items(repo, [starved], provenance, [], issue_labels, now,
                                      pr_status=red)
    assert [(item["state"], item["context"]) for item in ci_items] == [
        ("needs-ci-fix", "docs-quality, workspace clippy")], ci_items
    # an in-progress/absent/unknown gate is DO-NOTHING (no churn while CI is still running)
    for idle_gate in ("pending", "missing", "unknown"):
        assert enumerate_review_items(repo, [starved], provenance, [], issue_labels, now,
                                      pr_status={41: status_of(sha_a, gate=idle_gate)}) == []
    # ... while a concluded-GREEN gate on a drafted, unarmed, reviewed head is the STRANDED
    # posture (no other autonomous exit exists) — enumerated so CLAIM can hand it to a human
    green = {41: status_of(sha_a, gate="success")}
    stranded_items = enumerate_review_items(repo, [starved], provenance, [], issue_labels, now,
                                            pr_status=green)
    assert [(item["state"], item["context"]) for item in stranded_items] == [
        ("stranded", "")], stranded_items
    # DO-NOTHING sides of stranded: an UNREVIEWED draft head re-reviews instead; a READY
    # (non-draft) unarmed green reviewed head is the valid arm=false-policy terminal; an
    # unknown (still-computing) base or a live lease never acts
    assert [item["state"] for item in enumerate_review_items(
        repo, [pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["review:needs"])],
        provenance, [], issue_labels, now, pr_status=green)] == ["needs-review"]
    ready_terminal = pull(41, "sparq-agent/issue-7-1-1", sha_a, draft=False,
                          labels=["review:pass"],
                          body=f"x <!-- sparq-reviewed-sha:{sha_a} -->")
    assert enumerate_review_items(repo, [ready_terminal], provenance, [], issue_labels, now,
                                  pr_status=green) == []
    unknown_base = {41: dict(status_of(sha_a, gate="success"), conflicting=None)}
    assert enumerate_review_items(repo, [starved], provenance, [], issue_labels, now,
                                  pr_status=unknown_base) == []
    assert enumerate_review_items(
        repo, [starved], provenance,
        [{"holder": f"review:{repo}#41@run.1", "expires_at": now + 100}],
        issue_labels, now, pr_status=green) == []
    # an UN-reviewed draft with red CI stays a review item (the loop's own work comes first)
    fresh = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["review:needs"])
    assert [item["state"] for item in enumerate_review_items(
        repo, [fresh], provenance, [], issue_labels, now, pr_status=red)] == ["needs-review"]
    # a non-draft review:pass PR blocked on red CI is exactly the merge-queue starver
    passed = pull(41, "sparq-agent/issue-7-1-1", sha_a, draft=False, labels=["review:pass"],
                  body=f"x <!-- sparq-reviewed-sha:{sha_a} -->")
    assert [item["state"] for item in enumerate_review_items(
        repo, [passed], provenance, [], issue_labels, now, pr_status=red)] == ["needs-ci-fix"]
    # review:needs-user stays terminal for the repair states too (escalation must halt the loop)
    stopped = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["review:needs-user"])
    assert enumerate_review_items(repo, [stopped], provenance, [], issue_labels, now,
                                  pr_status=red) == []
    # groom's plain needs:user PR label ("Human attention required") is human-owned terminal
    # exactly like review:needs-user — for the repair states AND the plain review flow
    parked_pr = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["needs:user", "review:needs"])
    assert enumerate_review_items(repo, [parked_pr], provenance, [], issue_labels, now,
                                  pr_status=red) == []
    assert enumerate_review_items(repo, [parked_pr], provenance, [], issue_labels, now) == []
    # ... and a needs:*-parked SOURCE issue parks its PR's whole autonomous surface the same way
    # (groom's stale-PR path parks exactly the merge states the repair states target)
    parked_issue = {7: ["area:crate-a", "needs:user", "role:impl", "status:deferred"],
                    9: issue_labels[9]}
    assert enumerate_review_items(repo, [starved], provenance, [], parked_issue, now,
                                  pr_status=red) == []
    conflicted = {41: status_of(sha_a, gate="failure", conflicting=True)}
    assert enumerate_review_items(repo, [starved], provenance, [], parked_issue, now,
                                  pr_status=conflicted) == []
    assert enumerate_review_items(repo, pulls[:1], provenance, [], parked_issue, now) == []
    # flip side: the SAME PR without the park emits (asserted red above via ci_items)
    # GAP-B beats GAP-A per tick: CI on a conflicted base is noise — rebase repair only
    both = {41: status_of(sha_a, gate="failure", conflicting=True, legs=["js"])}
    rebase_items = enumerate_review_items(repo, [starved], provenance, [], issue_labels, now,
                                          pr_status=both)
    assert [(item["state"], item["context"]) for item in rebase_items] == [
        ("needs-rebase", "")], rebase_items
    # ... and a conflicting base also pre-empts a normal re-review
    assert [item["state"] for item in enumerate_review_items(
        repo, [fresh], provenance, [], issue_labels, now, pr_status=both)] == ["needs-rebase"]
    # any live review:/fix: lease suppresses both repair states (no double-dispatch)
    for holder in (f"review:{repo}#41@run.1", f"fix:{repo}#41@run.1"):
        live = [{"holder": holder, "expires_at": now + 100}]
        assert enumerate_review_items(repo, [starved], provenance, live, issue_labels, now,
                                      pr_status=red) == []
        assert enumerate_review_items(repo, [starved], provenance, live, issue_labels, now,
                                      pr_status=both) == []
    # a stale snapshot (status head != live head) is ignored — unknown never acts
    assert enumerate_review_items(
        repo, [starved], provenance, [], issue_labels, now,
        pr_status={41: status_of(sha_b, gate="failure", conflicting=True)}) == []
    # a DEGRADED snapshot record (PR #60 rounds 1+2) is MONOTONE: the check-run-derived
    # admissions (ci-fix, stranded) stand down even when the record smuggles a would-be
    # trigger past the forced gate=missing, while the DETAIL-derived fields stay live —
    # a degraded conflicting PR still emits needs-rebase (the SAME state as unmarked;
    # blanking it would switch the act into the review/fix flow, widening not narrowing)
    degraded_trigger = {41: dict(status_of(sha_a, gate="failure", conflicting=True,
                                           legs=["js"]), check_runs_degraded=True)}
    assert [item["state"] for item in enumerate_review_items(
        repo, [starved], provenance, [], issue_labels, now,
        pr_status=degraded_trigger)] == ["needs-rebase"]
    # ... and the SAME degraded record on an unreviewed draft stays needs-rebase too
    # (identical to the unmarked `both` outcome above — no state switch to needs-review)
    assert [item["state"] for item in enumerate_review_items(
        repo, [fresh], provenance, [], issue_labels, now,
        pr_status=degraded_trigger)] == ["needs-rebase"]
    # a smuggled RED gate on a clean degraded base admits NO ci-fix (guard is load-
    # bearing beyond pr_ci_status: a hostile status map bypasses the forced-missing)
    degraded_red = {41: dict(status_of(sha_a, gate="failure", legs=["js"]),
                             check_runs_degraded=True)}
    assert enumerate_review_items(repo, [starved], provenance, [], issue_labels, now,
                                  pr_status=degraded_red) == []
    # a smuggled GREEN gate on a degraded record admits NO stranded escalation
    degraded_green = {41: dict(status_of(sha_a, gate="success"), check_runs_degraded=True)}
    assert enumerate_review_items(repo, [starved], provenance, [], issue_labels, now,
                                  pr_status=degraded_green) == []
    # ... while the snapshot-independent review flow is unaffected by the degradation
    assert [item["state"] for item in enumerate_review_items(
        repo, [fresh], provenance, [], issue_labels, now,
        pr_status={41: dict(status_of(sha_a), check_runs_degraded=True)})] == ["needs-review"]

    # ---- GAP-C enumeration (issue #42: armed-SHA-mismatch disarm) ----
    armed_status = {41: status_of(sha_b, armed=True)}
    moved = pull(41, "sparq-agent/issue-7-1-1", sha_b, draft=False, labels=["review:pass"],
                 body=f"x <!-- sparq-reviewed-sha:{sha_a} -->")
    acted = enumerate_disarm_items(repo, [moved], armed_status, provenance)
    assert acted == [{"pr_number": 41, "head_sha": sha_b, "reviewed_sha": sha_a,
                      "repo": repo}], acted
    # matching SHAs are NEVER disarmed (the invariant's DO-NOTHING side)
    bound = pull(41, "sparq-agent/issue-7-1-1", sha_b, draft=False, labels=["review:pass"],
                 body=f"x <!-- sparq-reviewed-sha:{sha_b} -->")
    assert enumerate_disarm_items(repo, [bound], armed_status, provenance) == []
    # a READY-but-unarmed mismatch is a disarm interrupted between disable-auto and redraft
    # (or an arm crash between ready and merge --auto): re-emitted so the sweep re-enters the
    # crash window and completes the redraft
    interrupted = enumerate_disarm_items(repo, [moved], {41: status_of(sha_b)}, provenance)
    assert [item["pr_number"] for item in interrupted] == [41], interrupted
    # ... but a DRAFTED unarmed mismatch has nothing latched and nothing interrupted, and a
    # ready-unarmed MATCH is the valid arm=false-policy terminal — both DO-NOTHING
    drafted_moved = pull(41, "sparq-agent/issue-7-1-1", sha_b, labels=["review:needs"],
                         body=f"x <!-- sparq-reviewed-sha:{sha_a} -->")
    assert enumerate_disarm_items(repo, [drafted_moved], {41: status_of(sha_b)},
                                  provenance) == []
    assert enumerate_disarm_items(repo, [bound], {41: status_of(sha_b)}, provenance) == []
    # unknown snapshot / stale snapshot head / missing provenance / human-owned
    # (review:needs-user OR groom's needs:user) are all DO-NOTHING
    assert enumerate_disarm_items(repo, [moved], {}, provenance) == []
    assert enumerate_disarm_items(repo, [moved], {41: status_of(sha_a, armed=True)},
                                  provenance) == []
    assert enumerate_disarm_items(
        repo, [pull(90, "sparq-agent/issue-1-1-1", sha_b, draft=False)],
        {90: status_of(sha_b, armed=True)}, provenance) == []
    for hold in ("review:needs-user", "needs:user"):
        parked = pull(41, "sparq-agent/issue-7-1-1", sha_b, draft=False,
                      labels=[hold], body="x")
        assert enumerate_disarm_items(repo, [parked], armed_status, provenance) == []
    # a never-bound marker reads as "none" (crash-window recovery: arm landed, bind crashed)
    unbound = pull(41, "sparq-agent/issue-7-1-1", sha_b, draft=False, labels=["review:pass"])
    assert enumerate_disarm_items(repo, [unbound], armed_status, provenance)[0][
        "reviewed_sha"] == "none"
    # a DEGRADED snapshot record still feeds the disarm net (PR #60 round-1): the disarm
    # consumes only detail fields (head_sha + armed), so check-run degradation must not
    # stand the one act-is-the-safety-measure admission down (that would be fail-OPEN,
    # inducible by churning an armed mismatched head past the check-run ceiling)
    degraded_armed = {41: dict(status_of(sha_b, gate="missing", armed=True),
                               check_runs_degraded=True)}
    assert [item["pr_number"] for item in enumerate_disarm_items(
        repo, [moved], degraded_armed, provenance)] == [41]
    # the disarm provenance re-read carries the same strict-int pr_number guard as
    # provenance_admission_error: a float/bool record (41.0 == 41 under bare !=) never binds
    assert enumerate_disarm_items(repo, [moved], armed_status,
                                  {41: {**provenance[41], "pr_number": 41.0}}) == []
    assert enumerate_disarm_items(repo, [moved], armed_status,
                                  {41: {**provenance[41], "pr_number": True}}) == []

    # ---- decide_repair_admission: the LIVE trigger gates the defuse (defect-1 regression) ----
    # trigger holds: drafted proceeds, ready/armed defuses
    assert decide_repair_admission("needs-rebase", False, None, True) == ("proceed", "rebase")
    assert decide_repair_admission("needs-rebase", False, None, False) == ("defuse", "rebase")
    assert decide_repair_admission("needs-ci-fix", True, "failure", True) == ("proceed", "ci")
    assert decide_repair_admission("needs-ci-fix", None, "failure", False) == ("defuse", "ci")
    # trigger evaporated between PLAN and CLAIM: a NON-DRAFT (possibly validly-armed) PR must
    # DEFER with no defuse — never demote a matching-SHA valid arm on snapshot state alone
    assert decide_repair_admission("needs-rebase", True, None, False)[0] == "defer"
    assert decide_repair_admission("needs-rebase", None, None, False)[0] == "defer"
    for live_gate in ("success", "pending", "missing", "unknown", None):
        assert decide_repair_admission("needs-ci-fix", True, live_gate, False)[0] == "defer"
        assert decide_repair_admission("needs-ci-fix", True, live_gate, True)[0] == "defer"
    # conflict repair pre-empts a ci-fix on live data too, and non-repair states never admit
    assert decide_repair_admission("needs-ci-fix", False, "failure", True)[0] == "defer"
    assert decide_repair_admission("needs-review", False, "failure", True)[0] == "defer"

    # ---- stranded_live: the terminal hand-off is re-derived live before needs-user ----
    assert stranded_live(True, False, True, True, "success") is True
    assert stranded_live(False, False, True, True, "success") is False  # ready: arm=false valid
    assert stranded_live(True, True, True, True, "success") is False    # armed again: valid arm
    assert stranded_live(True, False, False, True, "success") is False  # unreviewed: re-review
    assert stranded_live(True, False, True, False, "success") is False  # conflicting: rebase
    assert stranded_live(True, False, True, None, "success") is False   # base still computing
    for live_gate in ("failure", "pending", "missing", "unknown"):
        assert stranded_live(True, False, True, True, live_gate) is False

    # ---- _dispatch_review_items wiring (defect-1/2 regression, monkeypatched I/O): the
    # non-draft defuse is reachable ONLY through a live-confirmed trigger, and a human-parked
    # source issue blocks repair admission before any mutation ----
    fake = {}
    helper_calls = []

    def fake_gh_json(args):
        path = args[-1]
        if "/pulls/41" in path:
            return fake["pull"]
        if "/check-runs" in path:
            return {"check_runs": fake["check_runs"]}
        if "/issues/41/comments" in path:
            return [fake.get("comments", [])]
        if "/issues/7" in path:
            return {"labels": [{"name": name} for name in fake.get("issue_labels", [])]}
        if "/compare/" in path:
            return {"status": "ahead", "files": [{"filename": "src/a.rs"}]}
        raise AssertionError(f"unexpected API read: {path}")

    def fake_helper(script_dir, target_repo, script, args):
        helper_calls.append((script, args))

    def live_pull(*, draft, labels=(), body="", auto_merge=None, mergeable=True):
        return {"number": 41, "state": "open", "draft": draft, "body": body,
                "mergeable": mergeable, "auto_merge": auto_merge,
                "head": {"ref": "sparq-agent/issue-7-1-1", "sha": sha_a,
                         "repo": {"full_name": repo}},
                "base": {"repo": {"default_branch": "main"}},
                "user": {"login": bot, "type": "Bot"},
                "labels": [{"name": name} for name in labels]}

    def run_items(items, allocator=None, routing=None):
        helper_calls.clear()
        reasons = Counter()
        launched = _dispatch_review_items(
            items, repo, {"max_review_rounds": 3, "account_pool": []},
            routing or {}, allocator, wiring_worker_pr, "reg/repo",
            wiring_root, "main", bot, None, 0.10, reasons,
            ledger_root=wiring_ledger_root)
        return launched, reasons

    ci_item = {"pr_number": 41, "head_sha": sha_a, "state": "needs-ci-fix",
               "impl_provider": "anthropic", "repo": repo, "package": "crate-a",
               "security": False, "context": "js"}
    real_io = (_gh_json, _run_target_helper, _target_token)
    with tempfile.TemporaryDirectory() as tmp:
        wiring_root = str(Path(tmp) / "registry")
        # A separate `ledger` branch checkout root (issue #96): records land there post-outage;
        # the legacy registry root remains the fallback for pre-outage records.
        wiring_ledger_root = str(Path(tmp) / "ledger")
        wiring_worker_pr = _load_module(
            "registry_worker_pr_wiring", Path(__file__).resolve().parent / "worker-pr.py")
        record_file = Path(wiring_root) / wiring_worker_pr.provenance_path(repo, 41)
        record_file.parent.mkdir(parents=True)
        record_file.write_text(json.dumps(provenance[41]), encoding="utf-8")
        try:
            globals()["_gh_json"] = fake_gh_json
            globals()["_run_target_helper"] = fake_helper
            globals()["_target_token"] = lambda repo: "tok"
            gate_red = [{"name": "gate", "status": "completed", "conclusion": "failure",
                         "started_at": "T1"}]
            gate_green = [{"name": "gate", "status": "completed", "conclusion": "success",
                           "started_at": "T1"}]
            # trigger evaporated (gate re-ran green): the ready PR is NOT defused — no mutation
            fake.update(pull=live_pull(draft=False, auto_merge={"merge_method": "squash"}),
                        check_runs=gate_green, issue_labels=["area:crate-a"])
            run_items([ci_item])
            assert helper_calls == [], helper_calls
            # trigger still live: the ready PR IS defused (disarm --when always), exactly once
            fake["check_runs"] = gate_red
            run_items([ci_item])
            assert [(script, args[0], args[-1]) for script, args in helper_calls] == [
                ("worker-pr.py", "disarm", "always")], helper_calls
            # human-parked source issue: no defuse, no dispatch, even with a live trigger
            fake["issue_labels"] = ["area:crate-a", "needs:user"]
            run_items([ci_item])
            assert helper_calls == [], helper_calls
            # human-parked PR label: same stand-down
            fake.update(pull=live_pull(draft=False, labels=["needs:user"],
                                       auto_merge={"merge_method": "squash"}),
                        issue_labels=["area:crate-a"])
            run_items([ci_item])
            assert helper_calls == [], helper_calls
            # stranded ACT: {draft, unarmed, reviewed head, green gate} -> loud needs-user
            stranded_item = dict(ci_item, state="stranded", context="")
            fake.update(pull=live_pull(
                draft=True, labels=["review:needs"],
                body=f"x <!-- sparq-reviewed-sha:{sha_a} -->"), check_runs=gate_green)
            run_items([stranded_item])
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "needs-user")], helper_calls
            # stranded DO-NOTHING: the posture failed to re-derive (gate red again) -> defer
            fake["check_runs"] = gate_red
            run_items([stranded_item])
            assert helper_calls == [], helper_calls

            # ---- round-budget escalation (directive 2026-07-17): decide_budget replaces the
            # flat rounds>=max needs-user at CLAIM, the fix chain honours the pinned floor, and
            # a starved pinned chain DEFERS (defer-not-fallback: sonnet is never re-offered) ----
            class FakeAllocator:
                def __init__(self):
                    self.chains = []

                def claim(self, _repo, _package, _role, chain, *_args, **_kwargs):
                    self.chains.append(list(chain))
                    return None   # no account free: the fix must DEFER, never fall back down

                def release(self, *_args, **_kwargs):
                    return True

            def bot_comment(body):
                return {"user": {"login": bot}, "body": body}

            def round_markers(count):
                return [bot_comment(f"x {wiring_worker_pr.ROUND_MARKER} n={i} run={i}.1 -->")
                        for i in range(1, count + 1)]

            def write_verdict(round_n, progress, root=None):
                path = Path(root or wiring_root) / wiring_worker_pr.verdict_path(
                    repo, 41, round_n)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({
                    "verdict": "request_changes", "injection_detected": False,
                    "summary": "s", "issues": [], "progress": progress}), encoding="utf-8")

            fix_item = {"pr_number": 41, "head_sha": sha_a, "state": "needs-fix",
                        "impl_provider": "anthropic", "repo": repo, "package": "crate-a",
                        "security": False, "context": ""}
            routing_ok = {"models": {
                "sonnet": {"provider_model": "claude-sonnet-4-6", "harness": "claude"},
                "fable": {"provider_model": "claude-fable-5", "harness": "claude"},
                "opus": {"provider_model": "claude-opus-4-8", "harness": "claude"},
                "terra": {"provider_model": "TBD", "harness": "codex"},
            }}
            fake.update(pull=live_pull(draft=True, labels=["review:changes"]),
                        check_runs=gate_green, issue_labels=["area:crate-a"])
            fix_model = wiring_worker_pr.FIX_MODEL_MARKER
            pin_marker = wiring_worker_pr.MODEL_PIN_MARKER

            # ACT: base budget spent on sonnet -> extension, fable pin converged, and a chain
            # WITHOUT sonnet; the None claim then defers with a missed marker, NOT needs-user
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=sonnet run=1.9 -->"),
                bot_comment(f"x {fix_model} round=2 model=sonnet run=2.9 -->")]
            write_verdict(3, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-model-pin"),
                ("worker-pr.py", "record-marker")], helper_calls
            pin_args = helper_calls[0][1]
            assert pin_args[pin_args.index("--tier") + 1] == "fable", pin_args
            assert alloc.chains == [["fable", "opus"]], alloc.chains

            # DO-NOTHING flip: under budget -> no pin call, the DEFAULT fix chain is offered
            fake["comments"] = round_markers(2)
            write_verdict(2, None)
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-marker")], helper_calls
            assert alloc.chains == [["fable", "sonnet"]], alloc.chains

            # a recorded bot pin governs the chain even under budget (the floor never lowers) ...
            fake["comments"] = round_markers(2) + [
                bot_comment(f"z {pin_marker} round=1 tier=opus run=1.5 -->")]
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [["opus"]], alloc.chains
            # ... while a NON-bot forged pin marker is inert (bot-login trust filter)
            fake["comments"] = round_markers(2) + [
                {"user": {"login": "mallory"},
                 "body": f"z {pin_marker} round=1 tier=opus run=6.6 -->"}]
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [["fable", "sonnet"]], alloc.chains

            # top tier ran + latest verdict improving -> progress extension (pin floor kept)
            fake["comments"] = round_markers(4) + [
                bot_comment(f"x {fix_model} round=1 model=sonnet run=1.9 -->"),
                bot_comment(f"x {fix_model} round=3 model=opus run=3.9 -->"),
                bot_comment(f"z {pin_marker} round=3 tier=opus run=3.9 -->")]
            write_verdict(4, "improving")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-marker")], helper_calls
            assert alloc.chains == [["opus"]], alloc.chains

            # flip-goes-red: top tier + stagnant -> the loud terminal needs-user, no claim
            fake["comments"] = round_markers(4) + [
                bot_comment(f"x {fix_model} round=1 model=sonnet run=1.9 -->"),
                bot_comment(f"x {fix_model} round=3 model=opus run=3.9 -->")]
            write_verdict(4, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "needs-user")], helper_calls
            assert alloc.chains == [], alloc.chains

            # hard cap: 6 rounds stop even with a weaker tier + an improving grade
            fake["comments"] = round_markers(6) + [
                bot_comment(f"x {fix_model} round=1 model=sonnet run=1.9 -->")]
            write_verdict(6, "improving")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "needs-user")], helper_calls

            # a corrupt bot-authored pin tier is LOUD (needs-user) — silently ignoring it
            # would run the unpinned chain, the exact fall-back-down the pin forbids
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=sonnet run=1.9 -->"),
                bot_comment(f"z {pin_marker} round=1 tier=gpt-omega run=1.1 -->")]
            write_verdict(3, "improving")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "needs-user")], helper_calls
            assert alloc.chains == [], alloc.chains

            # ACT (terminal-grant orphan defect): the pinned opus fix EXECUTED and PUSHED
            # (state review:needs) must get its re-review — the opus fix-model marker
            # falsifies the top-tier escalation predicate and the recorded round-3 grade
            # (stagnant) predates the opus fix, so without the pending-fix authorization
            # this exact posture went needs-user with the top-tier round burned unreviewed.
            # The allocator is offered the cross-provider REVIEW chain (round 4), no
            # needs-user and no pin mutation.
            review_item = dict(fix_item, state="needs-review")
            fake.update(pull=live_pull(draft=True, labels=["review:needs"]))
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=fable run=1.9 -->"),
                bot_comment(f"x {fix_model} round=2 model=fable run=2.9 -->"),
                bot_comment(f"z {pin_marker} round=3 tier=opus run=3.5 -->"),
                bot_comment(f"x {fix_model} round=3 model=opus run=3.9 -->")]
            write_verdict(3, "stagnant")
            alloc = FakeAllocator()
            run_items([review_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [], helper_calls
            assert alloc.chains == [["terra"]], alloc.chains

            # flip-goes-red: the same posture whose latest fix ran BELOW the recorded opus
            # floor (a pin violation / forged marker) mints NO re-review — with the top tier
            # already graded stagnant it is the loud terminal instead
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->"),
                bot_comment(f"z {pin_marker} round=1 tier=opus run=1.5 -->"),
                bot_comment(f"x {fix_model} round=3 model=fable run=3.9 -->")]
            alloc = FakeAllocator()
            run_items([review_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "needs-user")], helper_calls
            assert alloc.chains == [], alloc.chains
            fake.update(pull=live_pull(draft=True, labels=["review:changes"]))

            # latest_recorded_progress: the registry record is primary, the findings-comment
            # marker is the fallback, and unknown/absent degrades to None (never extends)
            write_verdict(5, "regressing")
            assert latest_recorded_progress(wiring_worker_pr, wiring_root, repo, 41, 5, [],
                                            bot) == "regressing"
            marker_only = [bot_comment(
                f"y {wiring_worker_pr.PROGRESS_MARKER} round=9 progress=improving -->")]
            assert latest_recorded_progress(wiring_worker_pr, wiring_root, repo, 41, 9,
                                            marker_only, bot) == "improving"
            assert latest_recorded_progress(wiring_worker_pr, wiring_root, repo, 41, 8,
                                            marker_only, bot) is None
            assert latest_recorded_progress(wiring_worker_pr, wiring_root, repo, 41, 0,
                                            marker_only, bot) is None

            # ---- ledger-first record resolution (issue #96): post-outage records exist ONLY
            # on the `ledger` branch checkout; the legacy master-checkout copy remains visible
            # as the fallback so pre-outage records (<= sparq#2542) keep working ----
            verdict_rel = wiring_worker_pr.verdict_path(repo, 41, 7)
            assert record_file_path(wiring_ledger_root, wiring_root, verdict_rel) == \
                Path(wiring_root) / verdict_rel        # ledger miss -> legacy fallback
            write_verdict(7, "improving", root=wiring_ledger_root)
            assert record_file_path(wiring_ledger_root, wiring_root, verdict_rel) == \
                Path(wiring_ledger_root) / verdict_rel  # ledger hit wins
            assert record_file_path("", wiring_root, verdict_rel) == \
                Path(wiring_root) / verdict_rel        # no ledger checkout -> legacy only
            # a ledger-only verdict is found (the outage class: master copy never lands) ...
            assert latest_recorded_progress(wiring_worker_pr, wiring_root, repo, 41, 7, [],
                                            bot, ledger_root=wiring_ledger_root) == "improving"
            assert latest_recorded_progress(wiring_worker_pr, wiring_root, repo, 41, 7, [],
                                            bot) is None
            # ... and where both branches carry the round, the ledger copy governs
            write_verdict(5, "improving", root=wiring_ledger_root)
            assert latest_recorded_progress(wiring_worker_pr, wiring_root, repo, 41, 5, [],
                                            bot, ledger_root=wiring_ledger_root) == "improving"
            # end-to-end CLAIM wiring on a LEDGER-ONLY provenance record: the legacy record is
            # gone (post-outage reality) and the review item still admits + defers normally
            record_file.unlink()
            ledger_record = Path(wiring_ledger_root) / wiring_worker_pr.provenance_path(
                repo, 41)
            ledger_record.parent.mkdir(parents=True, exist_ok=True)
            ledger_record.write_text(json.dumps(provenance[41]), encoding="utf-8")
            fake["comments"] = round_markers(2)
            fake.update(pull=live_pull(draft=True, labels=["review:changes"]),
                        check_runs=gate_green, issue_labels=["area:crate-a"])
            write_verdict(2, None, root=wiring_ledger_root)
            alloc = FakeAllocator()
            launched, reasons = run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [["fable", "sonnet"]], alloc.chains
            # a deferring (None-claim) allocator is contention, NOT ledger rot: no lease-error,
            # ledger stays ok, and the zero-dispatch tick stays green
            assert launched == 0 and reasons["lease-error"] == 0, (launched, reasons)
            assert _ledger_health(reasons) == "ok", reasons
            assert _ledger_rot_zeroed_dispatch(launched, reasons) is False

            # ---- review/fix lease-error propagation (PR #258 review defect): an allocator
            # that RAISES inside the review/fix loop must land in the tick's SHARED
            # lease-error counter — dispatch() feeds this same histogram to _ledger_health
            # (summary `ledger` field) and _ledger_rot_zeroed_dispatch (the fail-loud raise),
            # so an all-review/fix frontier whose every claim errored now reports
            # ledger=error and fails the run instead of masquerading as an empty frontier ----
            class RaisingAllocator:
                def claim(self, *_args, **_kwargs):
                    raise RuntimeError("ledger CAS failed")

            launched, reasons = run_items([fix_item], allocator=RaisingAllocator(),
                                          routing=routing_ok)
            assert launched == 0 and reasons["lease-error"] == 1, (launched, reasons)
            assert _ledger_health(reasons) == "error", reasons
            assert _ledger_rot_zeroed_dispatch(launched, reasons) is True
        finally:
            (globals()["_gh_json"], globals()["_run_target_helper"],
             globals()["_target_token"]) = real_io

    # ---- GAP-D (issue #27): busy-area union over ALL open worker PRs ----
    # Linkage parity (round-2 P2): the busy partition reads each PR's source issue from the
    # SAME validated provenance record the enumerator admits, so these fixtures carry
    # provenance — the branch name is only the worker-pattern gate.
    def busy_record(number, issue):
        return {"pr_number": number, "head_sha_at_open": sha_a,
                "impl_provider": "anthropic", "impl_alias": "fable",
                "impl_account_h": "ab" * 8, "issue": issue, "recorded_at_run": "1.1"}

    busy_prov = {**provenance,
                 60: busy_record(60, 8), 61: busy_record(61, 999),
                 75: busy_record(75, 80), 76: busy_record(76, 81),
                 77: busy_record(77, 82), 78: busy_record(78, 81),
                 79: busy_record(79, 84), 85: busy_record(85, 82),
                 86: busy_record(86, 80)}
    plan_items = [{"number": 7, "package": "crate-a", "deferred": False},
                  {"number": 9, "package": "crate-b", "deferred": False}]
    in_review = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["review:needs"])
    kept = filter_busy_area_items(plan_items, repo, [in_review], issue_labels, busy_prov)
    assert [item["number"] for item in kept] == [9], kept  # crate-a busy via issue 7's area
    assert filter_busy_area_items(plan_items, repo, [], issue_labels, busy_prov) == plan_items
    # draft-agnostic, review-state-agnostic: a non-draft review:pass PR still reserves its area
    ready_pr = pull(41, "sparq-agent/issue-7-1-1", sha_a, draft=False, labels=["review:pass"])
    assert [item["number"] for item in filter_busy_area_items(
        plan_items, repo, [ready_pr], issue_labels, busy_prov)] == [9]
    # area:* labels on the PR itself union in as well
    labelled = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["area:crate-b"])
    assert filter_busy_area_items(plan_items, repo, [labelled], issue_labels, busy_prov) == []
    # a known source issue with NO areas reserves the serializing global partition
    assert filter_busy_area_items(plan_items, repo,
                                  [pull(60, "sparq-agent/issue-8-1-1", sha_a)],
                                  {8: ["role:impl"]}, busy_prov) == []
    # [round-2 P2] a VALID provenance record whose source issue is closed/unlisted mirrors
    # the enumerator — which still emits that PR as `__global__` — with a global reservation
    # (the old "reserves nothing" rule freed a crate the loop was still driving into)
    stray_closed = pull(61, "sparq-agent/issue-999-1-1", sha_a)
    assert busy_packages_of_pulls(repo, [stray_closed], issue_labels,
                                  busy_prov) == {GLOBAL_PACKAGE}
    stray_items = enumerate_review_items(repo, [stray_closed], busy_prov, [],
                                         issue_labels, now)
    assert [item["package"] for item in stray_items] == [GLOBAL_PACKAGE], stray_items
    # [round-2 P2] MISSING/invalid provenance: invisible to the enumerator but still able to
    # carry a latched arm, and its true crate is unknowable — global reservation (fail
    # closed), even when the PR wears area labels of its own
    assert busy_packages_of_pulls(repo, [stray_closed], issue_labels, {}) == {GLOBAL_PACKAGE}
    assert GLOBAL_PACKAGE in busy_packages_of_pulls(
        repo, [pull(61, "sparq-agent/issue-999-1-1", sha_a, labels=["area:crate-a"])],
        issue_labels, {})
    assert busy_packages_of_pulls(
        repo, [stray_closed], issue_labels,
        {61: {**busy_record(61, 999), "issue": True}}) == {GLOBAL_PACKAGE}
    # a global plan item never co-runs with ANY in-flight worker PR
    assert filter_busy_area_items([{"number": 3, "package": "__global__", "deferred": False}],
                                  repo, [in_review], issue_labels, busy_prov) == []
    # fork-headed imposters do not reserve (filtered BEFORE the fail-closed linkage read)
    assert filter_busy_area_items(plan_items, repo,
                                  [pull(62, "sparq-agent/issue-7-1-1", sha_a,
                                        head_repo="mallory/fork")],
                                  issue_labels, busy_prov) == plan_items

    # ---- P1 frontier-collapse regression (2026-07-18): HUMAN-PARKED worker PRs must NOT
    # reserve their crates. Reproduction shape (dispatch runs 29664401328/29665207000): a
    # ready frontier of N=4 rows across M=4 crates while 3 crates carry an open worker PR —
    # but only ONE of those PRs is review-loop-owned; the other two are terminal (a `needs:*`
    # park on the source issue / a HUMAN_HOLD label on the PR itself, the exact
    # enumerate_review_items exclusions). The plan must emit the 3 free-crate rows — dropping
    # ONLY the live PR's crate — not collapse to the single PR-less crate (the measured
    # ~1-item/tick deadlock: 26/27 open sparq worker PRs sat parked and every planned crate
    # read busy).
    frontier = [{"number": 70, "package": "crate-a", "deferred": False},
                {"number": 71, "package": "crate-b", "deferred": False},
                {"number": 72, "package": "crate-c", "deferred": False},
                {"number": 73, "package": "crate-d", "deferred": False}]
    collapse_labels = {80: ["area:crate-a", "needs:user", "role:impl"],  # source-parked
                       81: ["area:crate-b", "role:impl"],  # source of the PR-label-parked PR
                       82: ["area:crate-c", "role:impl"]}  # source of the LIVE in-flight PR
    collapse_pulls = [
        pull(75, "sparq-agent/issue-80-1-1", sha_a, labels=["review:needs"]),
        pull(76, "sparq-agent/issue-81-1-1", sha_a, labels=["review:needs-user"]),
        pull(77, "sparq-agent/issue-82-1-1", sha_a, labels=["review:needs"]),
    ]
    assert busy_packages_of_pulls(repo, collapse_pulls, collapse_labels,
                                  busy_prov) == {"crate-c"}
    kept = filter_busy_area_items(frontier, repo, collapse_pulls, collapse_labels, busy_prov)
    assert [item["number"] for item in kept] == [70, 71, 73], kept
    # a needs:user PR label parks just as terminally as review:needs-user
    assert filter_busy_area_items(
        frontier, repo, [pull(78, "sparq-agent/issue-81-1-1", sha_a, labels=["needs:user"])],
        collapse_labels, busy_prov) == frontier
    # the GLOBAL-freeze slice of the same bug: a PARKED PR whose known source issue has no
    # area labels must not reserve the serializing global partition (pre-fix it froze the
    # ENTIRE repo frontier); the unparked twin still does.
    assert filter_busy_area_items(
        frontier, repo, [pull(79, "sparq-agent/issue-84-1-1", sha_a)],
        {84: ["needs:user", "role:impl"]}, busy_prov) == frontier
    assert filter_busy_area_items(
        frontier, repo, [pull(79, "sparq-agent/issue-84-1-1", sha_a)],
        {84: ["role:impl"]}, busy_prov) == []
    # a parked PR's own area:* labels are discarded with it (the whole PR is terminal)
    assert filter_busy_area_items(
        frontier, repo, [pull(78, "sparq-agent/issue-81-1-1", sha_a,
                              labels=["needs:user", "area:crate-d"])],
        collapse_labels, busy_prov) == frontier

    # ---- [round-3 P1, drafts-only] HELD != INACTIVE: a human-parked PR frees its crates
    # ONLY when it is a provably-inert DRAFT. Round 2 also freed a parked NON-draft on an
    # explicit `auto_merge: null` listing read — unsound twice over (round-3 P1s):
    # (1) the PLAN snapshot projection DROPS auto_merge, so that branch was UNREACHABLE in
    # production and its fixtures were synthetic; (2) REST `auto_merge: null` cannot prove
    # a non-draft inert anyway — merge-queue membership is GraphQL-only (worker-pr.py
    # _merge_queue_state, issue #69: a directly-queued PR shows NO REST latch).
    # SNAPSHOT-SHAPE PARITY: the fixtures below are built in the workflow's EXACT
    # field-selected row shape, with the projection key set read from dispatch.yml itself
    # so fixture and projection cannot silently drift apart again. Rows carrying a
    # synthetic latch field are explicitly labeled as such and exist to prove a non-draft
    # stays busy EVEN IF a latch field were present. ----
    workflow = (Path(__file__).resolve().parent.parent
                / ".github" / "workflows" / "dispatch.yml").read_text(encoding="utf-8")
    projection = re.search(r"pr_snapshot\.append\(\{\n(.*?)\n\s*\}\)", workflow, re.DOTALL)
    assert projection, "dispatch.yml lost the pr_snapshot.append projection block"
    key_lines = [line for line in projection.group(1).splitlines()
                 if re.match(r'\s*"[a-z_]+": ', line)]
    key_indent = min(len(line) - len(line.lstrip()) for line in key_lines)
    snapshot_fields = {re.match(r'\s*"([a-z_]+)"', line).group(1) for line in key_lines
                       if len(line) - len(line.lstrip()) == key_indent}
    assert snapshot_fields == {"number", "state", "draft", "body", "labels",
                               "head", "user"}, snapshot_fields

    def snapshot_row(number, ref, *, draft, labels=()):
        # EXACTLY the dispatch.yml projection: top-level keys pinned to the workflow read
        # above; labels are plain STRINGS (not {"name": ...} dicts); head/user sub-shapes
        # mirror the projection's nested selections.
        row = {"number": number, "state": "open", "draft": draft, "body": "",
               "labels": list(labels),
               "head": {"ref": ref, "sha": sha_a, "repo": {"full_name": repo}},
               "user": {"login": bot, "type": "Bot"}}
        assert set(row) == snapshot_fields, "fixture drifted from the workflow projection"
        return row

    def parked_draft(**synthetic):
        return dict(snapshot_row(76, "sparq-agent/issue-81-1-1", draft=True,
                                 labels=["review:needs-user"]), **synthetic)

    def parked_ready(**synthetic):
        return dict(snapshot_row(76, "sparq-agent/issue-81-1-1", draft=False,
                                 labels=["review:needs-user"]), **synthetic)

    latched = {"enabled_by": {"login": bot}, "merge_method": "squash"}
    # parked DRAFT, no visible latch — the production frontier-collapse population
    # (26/27 open sparq worker PRs on 2026-07-18): provably inert, frees its crate
    assert busy_packages_of_pulls(repo, [parked_draft()], collapse_labels,
                                  busy_prov) == set()
    # parked DRAFT whose fresher PLAN detail record says the arm is still latched: a
    # crashed-disarm artifact — busy (pr_status is the production-visible latch signal;
    # the snapshot row itself carries no auto_merge field)
    assert busy_packages_of_pulls(repo, [parked_draft()], collapse_labels, busy_prov,
                                  {76: {"head_sha": sha_a, "armed": True}}) == {"crate-b"}
    # parked DRAFT with a synthetic auto_merge dict (raw-REST defense in depth, NOT a
    # snapshot field): same crashed-disarm artifact — busy
    assert busy_packages_of_pulls(repo, [parked_draft(auto_merge=latched)],
                                  collapse_labels, busy_prov) == {"crate-b"}
    # parked NON-draft in the production row shape (no auto_merge field exists): busy
    assert busy_packages_of_pulls(repo, [parked_ready()],
                                  collapse_labels, busy_prov) == {"crate-b"}
    # parked NON-draft with a synthetic latch field — armed, explicitly-null, garbage:
    # ALL busy (round 2 freed the null one; non-draft is now unconditional)
    assert busy_packages_of_pulls(repo, [parked_ready(auto_merge=latched)],
                                  collapse_labels, busy_prov) == {"crate-b"}
    assert busy_packages_of_pulls(repo, [parked_ready(auto_merge=None)],
                                  collapse_labels, busy_prov) == {"crate-b"}
    assert busy_packages_of_pulls(repo, [parked_ready(auto_merge="yes")],
                                  collapse_labels, busy_prov) == {"crate-b"}
    # directly-queued-shaped NON-draft: NO REST latch visible ANYWHERE — synthetic
    # auto_merge:null AND an agreeing unarmed detail record, exactly how a merge-queue
    # member can present over REST (membership is GraphQL-only): busy
    assert busy_packages_of_pulls(repo, [parked_ready(auto_merge=None)], collapse_labels,
                                  busy_prov,
                                  {76: {"head_sha": sha_a, "armed": False}}) == {"crate-b"}
    # unknown DRAFT state (the projection carries the key; the API returned garbage): busy
    assert busy_packages_of_pulls(repo, [parked_ready(draft=None)], collapse_labels,
                                  busy_prov) == {"crate-b"}
    # source-issue parks compose the same way: issue 80 is needs:user-parked; its
    # NON-draft worker PR still reserves crate-a...
    assert busy_packages_of_pulls(
        repo, [snapshot_row(75, "sparq-agent/issue-80-1-1", draft=False,
                            labels=["review:needs"])],
        collapse_labels, busy_prov) == {"crate-a"}
    # ...while its parked-DRAFT twin frees it
    assert busy_packages_of_pulls(
        repo, [snapshot_row(75, "sparq-agent/issue-80-1-1", draft=True,
                            labels=["review:needs"])],
        collapse_labels, busy_prov) == set()

    # ---- [round-2 P2] LINKAGE PARITY: when the branch-derived and provenance-derived
    # source issues differ, the busy result must mirror the enumerator's classification in
    # BOTH directions (provenance is the linkage; the branch name is only the pattern gate).
    # Direction 1 — branch says PARKED issue 80, provenance says LIVE issue 82: the
    # enumerator still emits this PR into crate-c, so crate-c stays busy (pre-fix the
    # branch-derived park freed it -> mid-air collision) and branch-issue 80's crate-a is
    # NOT reserved. ----
    cross_live = pull(85, "sparq-agent/issue-80-1-1", sha_a, labels=["review:needs"])
    assert busy_packages_of_pulls(repo, [cross_live], collapse_labels,
                                  busy_prov) == {"crate-c"}
    cross_items = enumerate_review_items(repo, [cross_live], busy_prov, [],
                                         collapse_labels, now)
    assert [(item["pr_number"], item["package"]) for item in cross_items] \
        == [(85, "crate-c")], cross_items
    # Direction 2 — branch says LIVE issue 82, provenance says PARKED issue 80: the
    # enumerator skips it (human-owned), and the provably-inert draft frees its crates the
    # same way (pre-fix the branch-derived linkage kept crate-c reserved -> frontier
    # collapse preserved).
    cross_parked = pull(86, "sparq-agent/issue-82-1-1", sha_a, labels=["review:needs"])
    assert busy_packages_of_pulls(repo, [cross_parked], collapse_labels,
                                  busy_prov) == set()
    assert enumerate_review_items(repo, [cross_parked], busy_prov, [],
                                  collapse_labels, now) == []
    # ... and the SAME divergent-linkage PR with the arm latched stays busy on the
    # provenance-linked crate (P1's HELD != INACTIVE composes with P2's parity)
    assert busy_packages_of_pulls(repo, [dict(cross_parked, auto_merge=latched)],
                                  collapse_labels, busy_prov) == {"crate-a"}

    # deferred-retry lease filter: a live lease suppresses the retry, expiry re-admits it
    deferred_items = [{"number": 9, "deferred": True}, {"number": 7, "deferred": False}]
    live_impl = [{"holder": f"{repo}#9@run.1", "expires_at": now + 100}]
    assert filter_deferred_items(deferred_items, repo, live_impl, now) == [
        {"number": 7, "deferred": False}]
    assert filter_deferred_items(deferred_items, repo, [], now) == deferred_items

    # Inverse-chain resolvability (locked decision 14): a CODEX alias with a missing/TBD
    # provider_model resolves to the CLI default (the proven drain passes no --model flag), so
    # the common anthropic->terra direction is live from day one; a CLAUDE alias still needs a
    # concrete id; an alias absent from routing stays unresolvable.
    routing = {"models": {"terra": {"provider_model": "TBD", "harness": "codex"},
                          "opus": {"provider_model": "claude-opus-4-8", "harness": "claude"},
                          "fable": {"provider_model": "TBD", "harness": "claude"}}}
    assert _resolvable_chain(["terra"], routing) == ["terra"]
    assert _resolvable_chain(["opus"], routing) == ["opus"]
    assert _resolvable_chain(["fable"], routing) == []
    assert _resolvable_chain(["ghost"], routing) == []
    del routing["models"]["terra"]["provider_model"]
    assert _resolvable_chain(["terra"], routing) == ["terra"]
    routing["models"]["terra"]["provider_model"] = "gpt-5.6-codex"
    assert _resolvable_chain(["terra"], routing) == ["terra"]

    # ---- CLAIM disarm application (issue #42): runs per-item-resilient and token-gated; the
    # live precondition re-derivation itself lives in worker-pr.py disarm (tested there) ----
    calls = []
    real_helper, real_token = _run_target_helper, _target_token
    try:
        globals()["_target_token"] = lambda repo: "tok"

        def fake_helper(script_dir, target_repo, script, args):
            calls.append(args)
            if args[4] == "13":
                raise DispatchError("boom")

        globals()["_run_target_helper"] = fake_helper
        _apply_disarm_items([
            {"pr_number": 13, "head_sha": "1" * 40, "reviewed_sha": "none",
             "repo": "example/repo"},
            {"pr_number": 14, "head_sha": "1" * 40, "reviewed_sha": "none",
             "repo": "example/repo"},
        ], "example/repo", Path("."), "reg[bot]")
        # a failing item SKIPS (never aborts the sweep) and every call is the strict
        # mismatch-only mode — CLAIM never requests an unconditional disarm from the plan
        assert [args[4] for args in calls] == ["13", "14"], calls
        assert all(args[0] == "disarm" and args[-1] == "mismatch" for args in calls)
        calls.clear()
        _apply_disarm_items([{"pr_number": 15, "head_sha": "1" * 40, "reviewed_sha": "none",
                              "repo": "example/repo"}], "example/repo", Path("."), "")
        assert calls == []            # no bot identity -> defer with NO mutation attempted
    finally:
        globals()["_run_target_helper"] = real_helper
        globals()["_target_token"] = real_token

    # ---- per-owner target token map (defects #1,#5): the wrong-owner-token bug fix ----
    _saved_env = {k: os.environ.get(k) for k in
                  ("TARGET_GH_TOKENS", "TARGET_GH_TOKEN", "TARGET_GH_TOKEN_OWNER")}
    try:
        for k in ("TARGET_GH_TOKENS", "TARGET_GH_TOKEN", "TARGET_GH_TOKEN_OWNER"):
            os.environ.pop(k, None)
        os.environ["TARGET_GH_TOKENS"] = json.dumps(
            {"sparq-org": "tok-sparq", "jeswr": "tok-registry"})
        # EACH owner resolves to ITS OWN token — a registry-owner mutation no longer 404s under the
        # sparq-org token (the exact defect: single-token mint covered targets[0]=sparq only).
        assert _target_token("sparq-org/sparq") == "tok-sparq"
        assert _target_token("jeswr/agent-account-registry") == "tok-registry"
        assert _target_token("unknown/repo") == ""      # unminted owner -> defer, never wrong-owner
        assert _target_token("not-a-repo") == ""
        # legacy single-token fallback stays backward compatible for a single-target deployment
        os.environ.pop("TARGET_GH_TOKENS", None)
        os.environ["TARGET_GH_TOKEN"] = "legacy-tok"
        os.environ["TARGET_GH_TOKEN_OWNER"] = "sparq-org"
        assert _target_token("sparq-org/sparq") == "legacy-tok"
        assert _target_token("jeswr/agent-account-registry") == ""   # other owner still deferred
    finally:
        for k, v in _saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # Escalation contract (routing.toml escalate=true, audit-2026-07-17): a security-surface item
    # whose restricted tier has ZERO usage-eligible accounts escalates to needs:user — but ONLY on
    # a live usage signal (no probe => defer, the require_usage hold + usage-alert own that), and
    # NEVER for non-escalate routes (they starve fail-closed and retry next tick).
    assert escalate_starved(True, {"acct01": {}}, 0) is True
    assert escalate_starved(True, {}, 0) is True            # empty-but-present map still signals
    assert escalate_starved(True, None, 0) is False         # no probe -> unknown -> defer
    assert escalate_starved(True, {"acct01": {}}, 1) is False
    assert escalate_starved(False, {"acct01": {}}, 0) is False
    assert escalate_starved(None, {"acct01": {}}, 0) is False

    print("dispatch-claim self-test PASSED")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", help="schema-checked artifact emitted by the PLAN job")
    parser.add_argument("--policy-file", default="policy/repos.toml")
    parser.add_argument("--registry-repo", default="jeswr/agent-account-registry")
    parser.add_argument("--registry-root", default=".",
                        help="registry checkout root (legacy pre-outage provenance + verdict "
                             "records)")
    parser.add_argument("--ledger-root", default="",
                        help="`ledger` data-plane branch checkout root — the PRIMARY location "
                             "of provenance + verdict records (issue #96); empty reads the "
                             "legacy registry root only")
    parser.add_argument("--bot-login", default="",
                        help="target App bot login (<slug>[bot]); required for review/deferred")
    parser.add_argument("--workflow-ref", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        _self_test()
        return 0
    if not args.plan:
        parser.error("--plan is required unless --self-test is used")
    try:
        dispatch(
            args.plan,
            args.policy_file,
            args.registry_repo,
            args.workflow_ref,
            Path(__file__).resolve().parent,
            registry_root=args.registry_root,
            bot_login=args.bot_login,
            ledger_root=args.ledger_root,
        )
    except DispatchError as exc:
        print(f"dispatch-claim: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
