#!/usr/bin/env python3
# [GPT-5.6] REG-4 privileged dispatcher half. Target code never executes in this process: the
# unprivileged PLAN artifact is treated as hostile data, revalidated against registry policy and
# protected target routing, then fed to the CAS allocator before a workflow_dispatch is emitted.
"""Validate an unprivileged dispatch plan, claim leases, and launch live workers fail-closed."""

import argparse
import base64
from collections import Counter
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import types
import sys
import tempfile
import textwrap
import time
import tomllib


# v2 adds top-level `review_items` (the cross-provider review/fix loop) and a per-item `deferred`
# flag (the deferred-retry path). v3 adds the zero-manual repair surface: review-item states
# `needs-ci-fix` (red ci-summary gate on the current head) and `needs-rebase` (conflicting base)
# with an advisory `context` field, the `stranded` recovery state ({drafted, unarmed, reviewed
# head, green gate} is the residue of an interrupted defuse/disarm — CLAIM re-reviews the head
# under the round budget, escalating to a human only after repeated failed recovery; issue #161),
# plus
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
# stranded is the recovery state for {drafted, unarmed, reviewed-sha == head, green gate} — the
# residue of an interrupted defuse/disarm that no other state re-admits (no re-review without a
# head advance, no ci-fix without a red gate). CLAIM re-derives it live and RE-REVIEWS the head
# under the bounded round budget, handing it to a human only after repeated failed recovery
# (issue #161).
REVIEW_STATES = {"needs-review", "needs-fix", "needs-ci-fix", "needs-rebase", "stranded"}
FIX_KIND_OF_STATE = {"needs-fix": "verdict", "needs-ci-fix": "ci", "needs-rebase": "rebase"}
# Independent per-lane tick accounting (issue #108): a productive worker launch must NEVER mask a
# failed safety disarm or a review/fix lane that planned work but launched nothing. Each lane keeps
# its own planned/launched/deferred/error tally so the tick-health recorder can surface a stalled
# lane (and a safety-critical disarm error) regardless of activity in the other lanes.
DISPATCH_LANES = ("worker", "review", "fix", "disarm")
# Task-side half of #500: two honest no-change outcomes on one issue are a routing signal, not
# another reason to spin the same deferred route. The marker is keyed to the two newest validated
# ledger outcomes, so the impl -> research escalation is idempotent while a LATER research-route
# no-change can trigger the distinct needs:user escalation.
DECLINE_ESCALATION_MIN = 2
DECLINE_ESCALATION_MARKER = "sparq-task-decline-escalation:v1"
# The review-loop lane owns needs-review re-reviews and the stranded recovery re-review; every
# other REVIEW_STATE (needs-fix / needs-ci-fix / needs-rebase) is a fix-loop launch.
REVIEW_LANE_STATES = {"needs-review", "stranded"}


def _review_item_lane(state):
    """The dispatch lane a review-plan item belongs to (issue #108): the review loop (needs-review
    plus the stranded recovery) vs the fix loop (needs-fix / needs-ci-fix / needs-rebase). Used so
    a stalled review lane is counted apart from the fix lane and from worker launches — a worker
    launch can otherwise mark the whole tick healthy while every review item fails forever."""
    return "review" if state in REVIEW_LANE_STATES else "fix"


def _new_lane_counts():
    """A fresh per-lane accumulator: {lane: Counter(planned/launched/deferred/error)} (issue #108).
    planned is seeded up front from the plan; the worker loop and the review/fix/disarm helpers fold
    in launched/error as each item resolves, and deferred is derived (planned-launched-error) at
    summary time so escalations and capacity holds are neither launches nor hard errors."""
    return {lane: Counter() for lane in DISPATCH_LANES}


def _fix_dispatch_line(counts):
    """One privacy-safe, per-tick fix fan-out telemetry line (issues #448/#460).

    ``eligible`` means PLAN enumerated a fix-lane item.  CLAIM may still exclude it during
    authoritative live revalidation; those items remain visible as deferred instead of making
    the line incorrectly report zero eligible after PLAN already surfaced work.
    """
    counts = counts or Counter()
    eligible = int(counts.get("eligible", 0) or 0)
    launched = int(counts.get("launched", 0) or 0)
    deferred = max(0, eligible - launched)
    reasons = sorted(
        (key[6:], int(value)) for key, value in counts.items()
        if key.startswith("defer:") and value
    )
    detail = ", ".join(f"{reason}={count}" for reason, count in reasons) or "none"
    return (f"fix-dispatch: {eligible} eligible, {launched} launched, {deferred} deferred "
            f"(reasons: {detail})")


def _claim_defer_category(reason):
    """Privacy-safe review/fix claim deferral category for the shared tick histogram.

    The allocator exposes its precise single-flight/capacity reason, while the public dispatch
    summary needs only a stable coarse category.  Keep lease ownership distinct from package
    conflict and account capacity so a planned-but-not-launched lane is never reasonless.
    """
    return {
        "pr-single-flight": "lease-held",
        "package-single-flight": "conflict",
        "no-account-slots": "no-slot",
        "lane-cap": "no-slot",
    }.get(reason or "no-account-slots", "claim-deferred")


# Human-owned PR labels: review:needs-user is the loop's own terminal escalation; needs:user is
# groom's parked-PR marker ("Human attention required"). EITHER parks the whole autonomous
# surface for the PR — enumeration, repair admission, and worker-pr.py disarm all stand down.
HUMAN_HOLD_PR_LABELS = {"review:needs-user", "needs:user"}
# The MACHINE-owned PR-side capacity park (park_policy.py; written by worker-pr needs_user
# park_class="capacity"): a SOFT hold, not a human terminal — excluded from active review/fix
# enumeration while it stands, but re-admitted by a human readmission gesture (an unlabel of
# review:parked / status:parked / needs:user on either surface, latest event wins). It is
# deliberately NOT in HUMAN_HOLD_PR_LABELS: the enumeration carve-out below re-admits it,
# whereas a human hold is terminal for everything autonomous.
MACHINE_PARK_PR_LABEL = "review:parked"
# Every label under which a PR counts as PARKED for crate occupancy (the provably-inert-DRAFT
# carve-out): the human holds plus the machine capacity park — a capacity-parked inert draft
# frees its crate exactly like the pre-split review:needs-user park did.
PARKED_PR_HOLD_LABELS = HUMAN_HOLD_PR_LABELS | {MACHINE_PARK_PR_LABEL}
# CLAIM's live busy-window revalidation also sees curator's terminal artifact posture.  Keep
# this narrower than the union above where it matters: status:blocked is an occupancy carve-out
# only after the raw listing row proves the PR inert; it does not redefine review-loop
# admission globally.
CLAIM_REVALIDATION_PARK_LABELS = PARKED_PR_HOLD_LABELS | {"status:blocked"}
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
    "status:parked",
    "status:untriaged",
    "trust:untrusted",
}
# Busy/gated set for the deferred-RETRY path: status:deferred is the retry trigger, everything
# else still gates (locked decision 20) — EXCEPT status:parked, the MACHINE-owned capacity park
# (park_policy.py): a parked+deferred issue stays IN the deferred-retry lane, which is its
# readmission hook — the same lane that re-sweeps status:deferred. The park lifts exactly when
# the allocator grants a claim (capacity exists): the `retry` label flip strips BOTH
# status:deferred and status:parked. Until then the escalation guards below hold it parked
# without re-commenting, and the ordinary ready lane still gates on status:parked (no NEW
# implementation dispatch outside this readmission path).
DEFERRED_GATED = BUSY_OR_GATED - {"status:deferred", "status:parked"}
# Readiness re-derivation (issue #102): PLAN computes blockers/non-dispatchability with HOSTILE
# target code (dispatch-plan.py in the cloned target). CLAIM must independently re-prove the same
# readiness predicate from LIVE registry-owned code before dispatch — an epic is a tracking
# umbrella (never a work item), and `Blocked-by: #N` gates until every referenced issue is closed.
# Kept byte-identical to scripts/ready-issues.py (NON_DISPATCHABLE + the blocker regex) so CLAIM
# and the ready engine cannot silently diverge.
NON_DISPATCHABLE = "kind:epic"
BLOCKED_BY_RE = re.compile(r"[Bb]locked-by:\s*#([0-9]+)")
# Cross-provider chains (locked decisions 14/17): the review chain is the INVERSE of the
# CONTENT author's provider and is computed HERE, never through policy-resolve.resolve() (whose
# role=review row is always [opus]); resolve() supplies account_pool/caps/gate/arm only.
# Model policy (maintainer directive 2026-07-18): sol — the codex-side frontier model — is THE
# reviewer of anthropic-authored content (luna is its fallback); opus stays lead reviewer of
# openai-authored content (proven verdict quality + the security-surface doctrine). terra and
# sonnet are DOCS-ONLY models and must NEVER appear in a review/fix chain (asserted in
# _self_test; review-fix.yml + worker-pr.py ESCALATION_LADDERS enforce the same).
REVIEW_CHAIN = {"anthropic": ["sol", "luna"], "openai": ["opus", "fable"]}
# FIX_CHAIN is the UNPINNED allocator PREFERENCE walk (strongest tier FIRST — choose_account
# takes the first serving account, and the frontier tier leads per the sol-first doctrine).
# It is deliberately the REVERSE of worker_pr.ESCALATION_LADDERS, which are capability-
# ASCENDING (weakest first, terminal strongest LAST; opus < luna < fable < sol) and govern
# exhaustion escalation + pinned floors (sol r2 f2 fixed the previously inverted ladders).
FIX_CHAIN = {"anthropic": ["fable", "opus"], "openai": ["sol", "luna"]}
# Probe-exempt PROVIDERS for the require_usage hold (issue #115). Mirrors account-usage.py's
# EXEMPT_PROVIDERS allowlist (the maintainer decision names openai): codex/openai accounts report
# no rate-limit-header usage and are governed by reactive backoff, so a usage=None probe outage is
# their EXPECTED steady state, not a failure. Kept as an explicit allowlist, never "any non-
# anthropic": a missing/typo provider stays on the fail-closed hold path (never silently exempted).
PROBE_EXEMPT_PROVIDERS = frozenset({"openai"})
# Issue #448: dispatch fan-out is bounded by the allocator's LIVE remaining account slots, not a
# second, coarse `review:`/`fix:` lease-row constant.  The old fleet-wide 10/8 caps mixed repos and
# providers: unrelated work could leave (for example) every sol slot idle while consuming the
# shared prefix ceiling.  Each item still obtains its own CAS lease; per-account caps and the
# repository/package/PR single-flight predicates remain the authoritative safety bounds.
# Lease TTL must OUTLIVE the owning review-fix.yml workflow's worst-case wall-clock, or the
# allocator reclaims a still-live account and two sessions race on one credential / write-back
# (issue #159). A DISPATCHER-claimed lease (adopted by review-fix.yml's `claim` job) is created
# BEFORE the workflow's resolve/claim/run jobs run, so the bound is every job timeout on the
# claim -> run -> release critical path PLUS GitHub runner queue slack between jobs — NOT the run
# job alone. The pre-#159 1200/3600 were the run-job timeout itself (25m/60m), so a lease expired
# mid-run and the account was reclaimed while the original session was still live. Keep these job
# bounds in sync with .github/workflows/review-fix.yml `timeout-minutes:` (the _self_test pins the
# derivation so a silent cut below the run bound flips red).
_WF_RESOLVE_TIMEOUT = 600    # review-fix.yml resolve job (10m)
_WF_CLAIM_TIMEOUT = 600      # review-fix.yml claim/adopt job (10m)
_WF_RELEASE_TIMEOUT = 600    # review-fix.yml release job — the job that frees the lease (10m)
_WF_RUN_TIMEOUT = {"review": 1500, "fix": 3600}  # run job, per mode (25m / 60m)
# Slack for runner queue time (the dispatch queue plus inter-job handoffs); a lease must NEVER
# expire while its workflow can still be scheduling or running the credential-using `run` job.
_WF_QUEUE_SLACK = 900        # 15m


def _lease_ttl(mode):
    """The minimum lease TTL that outlives the owning review-fix.yml workflow's worst-case
    wall-clock (issue #159): every job timeout on the claim -> run -> release critical path plus
    queue slack, measured from the DISPATCHER claim (before resolve runs — the longest path).
    Fail-closed: an unknown mode takes the longest (fix) run bound, never a shorter one, so a
    typo can only over-hold an account, never free a live one early."""
    run = _WF_RUN_TIMEOUT.get(mode, _WF_RUN_TIMEOUT["fix"])
    return (_WF_RESOLVE_TIMEOUT + _WF_CLAIM_TIMEOUT + run
            + _WF_RELEASE_TIMEOUT + _WF_QUEUE_SLACK)


REVIEW_TTL = _lease_ttl("review")   # 10+10+25+10+15 = 70m (was 20m — shorter than the 25m run job)
FIX_TTL = _lease_ttl("fix")         # 10+10+60+10+15 = 105m (was 60m — exactly the run job, no slack)
MISSED_FIX_LIMIT = 6  # consecutive missed fix dispatches per round before needs-user (decision 13)
HEAD_REF_RE = re.compile(r"^sparq-agent/issue-([1-9][0-9]*)-")
# Mirrors worker-pr.py REVIEWED_SHA_RE (the marker is written there; keep formats in sync).
REVIEWED_SHA_RE = re.compile(r"<!-- sparq-reviewed-sha:([0-9a-f]{40}|none) -->")
SECURITY_KEYWORDS = ("zk", "mpc", "crypto", "auth", "e2ee")
# The authoritative aggregator check-run on the target (sparq's `ci-summary / gate` job): only a
# CONCLUDED failure of THIS check on the CURRENT head enumerates a ci-fix; in-progress = no churn.
CI_GATE_CHECK = "gate"
FAILED_CONCLUSIONS = {"failure", "timed_out"}
# A gate check-run that COMPLETED with any of these did not pass and did not cleanly fail: the
# run was cancelled, never started, went stale, or needs a human (issue #160). None of these is
# green and none is silently deferrable — required checks in these states will NOT merge, so each
# must take the SAME ci-fix rerun/escalation path as a hard failure rather than collapse to
# success. Previously only FAILED_CONCLUSIONS mapped to gate=failure and EVERY other completed
# conclusion (cancelled/action_required/startup_failure/stale/neutral/skipped) fell through to
# success — suppressing repair while looking merge-ready. These are the GitHub check-run
# conclusions outside {success} ∪ FAILED_CONCLUSIONS; an UNRECOGNISED conclusion (None / hostile
# garbage on a "completed" run) is deliberately NOT here — it degrades to gate=unknown (no ACT).
BROKEN_CONCLUSIONS = {"cancelled", "action_required", "startup_failure", "stale",
                      "neutral", "skipped"}
GLOBAL_PACKAGE = "__global__"   # mirrors the target ready-engine's serializing partition
CI_CONTEXT_MAX = 1000           # advisory failing-leg context cap (plan field + workflow input)
MAX_FAILING_LEGS = 20


def plan_package(areas):
    """The single conflict partition a plan/lease row reserves for a collection of `area:*`
    sections (registry issue #112). EXACTLY one area -> that area; ZERO OR MULTIPLE -> the
    serializing global partition. Mirrors dispatch-plan.py:_plan_package byte-for-byte so the
    anti-tamper package/label agreement in _route_matches holds: the old
    alphabetically-first reduction dropped every secondary area, so a multi-area issue/PR
    leased or dispatched onto a crate a second area already held. Fail-closed — over-serialize
    a multi-area row rather than free a busy sibling crate."""
    uniq = {a for a in areas if isinstance(a, str) and a}
    return next(iter(uniq)) if len(uniq) == 1 else GLOBAL_PACKAGE


class DispatchError(RuntimeError):
    """A concise fail-closed error suitable for Actions logs."""


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise DispatchError(f"cannot load registry helper {Path(path).name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Shared park-label policy (park_policy.py): the round-budget human-readmission window
# (readmission_cutoff) consumed by the CLAIM review loop. Loaded at module scope, same idiom as
# groom.py, so the per-item review sweep never re-imports it.
_park_policy = _load_module(
    "registry_park_policy", Path(__file__).resolve().with_name("park_policy.py"))


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
    live = set()
    for lease in leases:
        if not isinstance(lease, dict):
            continue
        expires = lease.get("expires_at", 0)
        if isinstance(expires, bool) or not isinstance(expires, (int, float)):
            # [round-5] unparseable expiry: not PROVABLY live, so it never suppresses a
            # re-emit here — while sibling_lease_conflict reads the same row as ambiguity
            # and EXCLUDES (both directions fail safe; a bare > comparison used to raise).
            continue
        if expires > now:
            live.add(str(lease.get("holder", "")).split("@", 1)[0])
    return live


def _lease_holder_repo(key):
    """[round-6 P1] The target repository a lease holder key belongs to. Holder grammar
    (select-and-claim.py): impl keys are `<owner>/<name>#<issue>`, review/fix-lane keys are
    `review:<owner>/<name>#<pr>` / `fix:<owner>/<name>#<pr>` (the run suffix is already
    stripped by the caller). Returns "" when the key does not parse to that shape — callers
    fail toward exclusion, never toward guessing a repository."""
    for prefix in ("review:", "fix:"):
        if key.startswith(prefix):
            key = key[len(prefix):]
            break
    repository, sep, rest = key.partition("#")
    if not sep or not rest.isdigit() or not SAFE_REPO.fullmatch(repository):
        return ""
    return repository


def sibling_lease_conflict(repo, own_keys, packages, leases, now):
    """[round-5 P1] The cross-lane crate-ownership view over the lease ledger, SCOPED to the
    candidate's target `repo` [round-6 P1]. True when ANY live SAME-REPOSITORY lease whose
    holder key is NOT in `own_keys` holds one of `packages` — regardless of lane prefix:
    impl leases key `<repo>#<issue>`, review/fix leases key `review:<repo>#<pr>` /
    `fix:<repo>#<pr>`, and the allocator's partition_available checks only SAME-prefix
    leases by design, so without this view the lanes cannot see each other. That is the
    park -> sibling-launch -> UNPARK hole: parking a provably-inert draft frees its crate,
    an impl sibling claims an impl lease there (invisible to the review lane), and the
    moment a human unparks the PR both same-crate lanes progress at once.

    REPOSITORY SCOPE [round-6 P1, sol round-5 item 3]: the ledger is fleet-wide (one lease
    file across every dispatch target), while package names and `__global__` are PER-REPO
    partitions — the allocator's partition_available is explicitly repository-scoped via the
    holder prefix. A lease whose holder parses to a DIFFERENT target repository never
    conflicts here (a same-named crate — or a global lease — in one target must not freeze
    another target's frontier; unscoped, this check would itself recreate the fleet-wide
    frontier collapse it exists to prevent). A holder that does not parse to any repository
    is ambiguity and excludes, as below.

    Package semantics mirror partition_available / the busy union: `__global__` serializes in
    both directions WITHIN the repo (a global lease conflicts with everything; a
    global-packaged candidate conflicts with any live same-repo sibling lease). An empty
    `packages` set means the candidate's crate is unknown and collapses to `__global__`
    (fail closed).

    FAIL TOWARD EXCLUSION ON AMBIGUITY: a non-list ledger, a malformed row, an unparseable
    expiry, or a missing/invalid/unparseable holder or package all read as a live colliding
    sibling — the caller defers/excludes and retries next tick rather than launching into a
    crate whose ownership cannot be proven.

    DEFENSE-IN-DEPTH ONLY — RESIDUAL TOCTOU WINDOW (descoped from PR #286, tracked in
    issue #294): this view reads a CHECKOUT SNAPSHOT of the ledger, and the allocator's own
    CAS predicate still filters same-prefix leases only — a sibling lease claimed AFTER the
    snapshot (or through a self-claim path) is invisible until the next tick. The concrete
    worst case is a duplicate same-crate worker PR (humanly recoverable churn — never
    credential exposure or data corruption). Closing the window means enforcing cross-lane
    repository/package exclusion INSIDE select-and-claim's CAS transaction for every claim
    path; see issue #294 for the design constraints."""
    if not isinstance(repo, str) or not repo:
        return True                       # unscoped candidate — cannot prove any lease foreign
    mine = {package for package in packages if isinstance(package, str) and package} \
        or {GLOBAL_PACKAGE}
    if not isinstance(leases, list):
        return True                       # no provable lease view — cannot prove the crate free
    for lease in leases:
        if not isinstance(lease, dict):
            return True                   # unreadable row — cannot prove it is not a sibling
        expires = lease.get("expires_at")
        if isinstance(expires, bool) or not isinstance(expires, (int, float)):
            return True                   # unparseable expiry — cannot prove the lease dead
        if expires <= now:
            continue                      # provably expired — reclaimable, never a conflict
        holder = lease.get("holder")
        key = holder.split("@", 1)[0] if isinstance(holder, str) else ""
        if not key:
            return True                   # cannot prove the lease is one of OUR own
        if key in own_keys:
            continue                      # the candidate's own lease never supersedes it
        holder_repo = _lease_holder_repo(key)
        if not holder_repo:
            return True                   # unparseable holder — cannot prove which target owns it
        if holder_repo != repo:
            continue                      # [round-6 P1] another TARGET's lease: package and
                                          # __global__ partitions are per-repository — a foreign
                                          # lease never blocks this repo's frontier
        package = lease.get("package")
        if not isinstance(package, str) or not package:
            return True                   # unknown crate — cannot prove disjointness
        if package == GLOBAL_PACKAGE or GLOBAL_PACKAGE in mine or package in mine:
            return True
    return False


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
    else:
        # ONLY the literal `success` conclusion is green (issue #160). A hard/transient failure
        # OR a broken/incomplete run (cancelled, action_required, startup_failure, stale,
        # neutral, skipped) is a concluded non-pass that takes the ci-fix rerun/escalation path.
        # Anything unrecognised (None or hostile garbage on a "completed" run) degrades to
        # unknown so a poisoned snapshot can only DEFER, never spuriously repair or go green.
        # isinstance BEFORE each set membership: an unhashable JSON value ([] / {}) as the
        # conclusion would TypeError the `in` lookup — a hostile snapshot must degrade to
        # unknown, never crash (mirrors the plan-validation guard above).
        conclusion = gate_entry[1].get("conclusion")
        if conclusion == "success":
            gate = "success"
        elif isinstance(conclusion, str) and (conclusion in FAILED_CONCLUSIONS
                                              or conclusion in BROKEN_CONCLUSIONS):
            gate = "failure"
        else:
            gate = "unknown"
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
    draft = record.get("draft")
    status = {
        "head_sha": head_sha,
        # REST tri-state: False = conflicting, True = clean, null = still computing (unknown).
        "conflicting": True if mergeable is False else (False if mergeable is True else None),
        # [round-5 P2] STRICT tri-state arm bit: a dict is armed, an explicit null is
        # unarmed, and ANY other shape (a garbage string in a hostile/degraded snapshot) is
        # UNKNOWN (None). The old isinstance() read collapsed garbage to False = unarmed —
        # fail OPEN: the busy-partition carve-out would free a crate whose latch state was
        # unprovable. Unknown never frees (_pull_inactivity_decision requires armed exactly
        # False) and never proves the stranded posture.
        # [round-6 P2] ABSENCE != NULL: the bit is derived ONLY from a PRESENT auto_merge
        # field (plan-snapshot preserves field presence). A record that never carried the
        # field — a projected/degraded/pre-round-6 shape — proves NOTHING about the latch:
        # the old record.get() read collapsed absence to explicit-null = unarmed, so a
        # detail with a matching head and draft:true but NO auto_merge field "proved" the
        # PR inactive and freed its crate (fail OPEN). Absent reads UNKNOWN (busy).
        "armed": ((True if isinstance(record["auto_merge"], dict)
                   else False if record["auto_merge"] is None else None)
                  if "auto_merge" in record else None),
        # [round-4 P1] the detail read's OWN draft bit (the pulls/N REST response carries
        # `draft`): the busy-partition carve-out frees a parked draft ONLY when this NEWER
        # read confirms the listing's stale draft flag on the same head. Strict bool;
        # anything else degrades to None (unknown never frees — fail closed to BUSY).
        "draft": draft if isinstance(draft, bool) else None,
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
    still-computing base — is some other path's job and must NOT be escalated. [round-5 P2]
    the arm bit is tri-state (see pr_ci_status): only an EXPLICIT armed=False proves the
    stranded posture — an unknown/garbage latch shape never acts."""
    return (draft is True and armed is False and reviewed_match
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
    enumerate_review_items EXCEPT for the human hold: a review:needs-user or needs:user PR is
    human-owned for pushes/reviews, but issue #105 — this net is safety-ONLY (latch retraction),
    so a held PR with an armed-SHA mismatch is STILL emitted (worker-pr.py disarm --when mismatch
    retracts the latch while preserving the hold). A check_runs_degraded snapshot record is CONSUMED here on
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
        # Issue #105: a human hold (review:needs-user / needs:user) parks autonomous PUSHES and
        # reviews, but it must NEVER suppress this safety-only latch retraction. A stale armed
        # head escalated to review:needs-user after a failed disarm — or a human label applied
        # while auto-merge stays latched — would otherwise strand the latch and merge an
        # unreviewed tree on green CI. Held PRs are enumerated here on the same footing as any
        # other armed-SHA mismatch; worker-pr.py disarm --when mismatch retracts the latch
        # (disable-auto/dequeue + redraft) while PRESERVING the hold label (it drops the relabel
        # that would strip review:needs-user and re-admit the PR). enumerate_review_items still
        # skips held PRs, so the hold keeps stopping pushes/reviews.
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


_NO_PR_DETAIL = object()


def _pull_inactivity_decision(pull, status=_NO_PR_DETAIL):
    """The reason-bearing #516 parked-free gate used by PLAN and CLAIM occupancy.

    Returns ``(inactive, reason)``.  A post-#517 LISTING row is coherent by itself only when
    ``draft`` is the literal boolean True and the ``auto_merge`` KEY IS PRESENT with the literal
    value None.  If a per-PR DETAIL record exists, that newer split-snapshot read remains
    authoritative and must itself prove the same unlatched draft posture on the listing head.
    Any absent field required by the selected proof, malformed value, latch, non-draft bit, or
    head disagreement fails closed to BUSY, with a stable reason that the assembler can print for
    the row it drops. A coherent DETAIL may still prove a pre-#517 listing that lacks auto_merge.

    Provably inactive means exactly one thing: a DRAFT with no latched arm visible in the
    authoritative read.  The reasoned result is deliberately shared rather than reconstructed
    at the logging call site: diagnostics must describe the gate decision that actually reserved
    the crate.

    This is the busy-partition carve-out guard (round-2 P1 HELD != INACTIVE; DRAFTS ONLY
    since round 3; split-snapshot coherent since round 4). Draft is the loop's own defused state —
    the disarm path converts to draft, GitHub cancels/refuses auto-merge on drafts, and the
    measured frontier-collapse population is exactly parked drafts (26/27 open sparq worker PRs,
    2026-07-18).

    [round-4 P1] SPLIT-SNAPSHOT RACE: the PLAN snapshot lists pulls BEFORE fetching the
    per-PR details, so the detail record (`status`, from pr_ci_status) is the NEWER of
    the two reads. A draft flipped ready — and possibly armed or directly QUEUED
    (GraphQL-only, latch-invisible over REST) — between the two reads presents as a
    stale listing `draft: True` plus a newer detail with no visible latch; round 3 freed
    its crate while the PR could merge. The carve-out therefore frees ONLY when the
    NEWER read coherently CONFIRMS the defused draft state:
      - listing `draft` is True (non-draft/unknown never frees, unchanged), AND
      - the detail's armed bit is exactly False (True is a crashed-disarm artifact; a
        missing bit is unknown), AND
      - the detail record EXISTS and its head_sha equals the listing head (a head that
        moved between the reads means the listing row is stale — unprovable), AND
      - the detail's OWN `draft` bit is True (the pulls/N REST detail carries `draft`;
        a record without the field — the pre-round-4 snapshot shape — proves nothing).
    When DETAIL is absent, a complete post-#517 listing row supplies the same coherence proof in
    one atomic REST row.  A pre-#517 row with no ``auto_merge`` key still reserves its crate:
    ABSENCE != NULL."""
    listing_draft = pull.get("draft")
    if listing_draft is False:
        return False, "non-draft"
    if listing_draft is not True:
        return False, "malformed-draft"
    head = pull.get("head")
    head_sha = str(head.get("sha", "")) if isinstance(head, dict) else ""
    if not SAFE_SHA.fullmatch(head_sha):
        return False, "malformed-head"
    if ("auto_merge" in pull and pull["auto_merge"] is not None
            and not isinstance(pull["auto_merge"], dict)):
        return False, "malformed-auto-merge"

    if status is _NO_PR_DETAIL:
        if "auto_merge" not in pull:
            return False, "no-detail"    # legacy row cannot supply listing-only coherence
        listing_arm = pull["auto_merge"]
        if isinstance(listing_arm, dict):
            return False, "latched"
        return True, "listing"

    # DETAIL exists and is authoritative.  In particular, never fall back to a friendly
    # listing row when a present detail is malformed, latched, or says the PR went ready.
    if not isinstance(status, dict):
        return False, "malformed-detail"
    armed = status.get("armed")
    if armed is True:
        return False, "latched"
    if armed is not False:
        return False, "malformed-auto-merge"
    detail_head = status.get("head_sha")
    if not isinstance(detail_head, str) or not SAFE_SHA.fullmatch(detail_head):
        return False, "malformed-head"
    if detail_head != head_sha:
        return False, "head-mismatch"
    detail_draft = status.get("draft")
    if detail_draft is False:
        return False, "non-draft"
    if detail_draft is not True:
        return False, "malformed-draft"
    return True, "detail"


def busy_packages_of_pulls(repo, pulls, issue_labels, provenance, pr_status=None,
                           parked_pr_labels=None, occupancy=None):
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
    round 3, listing-or-newer-detail coherent since #519): a human-parked PR —
    `review:needs-user`/`needs:user` on the PR, or `needs:*` on the provenance-linked
    source issue — frees its packages ONLY when it is a provably-inert DRAFT
    (_pull_inactivity_decision: draft with no visible latch, CONFIRMED either by the
    post-#517 listing's present explicit-null auto_merge field or by a head-matched newer
    detail record whose own draft bit is True). EVERY parked NON-draft stays BUSY
    unconditionally: groom parks stale non-draft PRs WITHOUT disarming, and non-draft
    queue/arm state is not provable from an explicit-null REST latch alone because merge-queue
    membership is GraphQL-only per worker-pr.py's own doctrine — a directly-queued PR shows no
    REST latch — so an unprovable park could merge
    mid-air into a crate this partition just freed for a sibling. The measured collapse
    (26 of 27 open sparq worker PRs source-parked, ~1 plan item/tick against a 13-row
    frontier, dispatch runs 29664401328/29665207000) is still fixed: the collapse
    population is parked DRAFTS, and those free. The parked SOURCE issue itself stays
    `needs:*`-gated out of the target ready engine, so freeing an inert PR's crate can
    never re-dispatch the parked issue — only siblings in the same crate."""
    busy = set()
    hold_labels = (PARKED_PR_HOLD_LABELS if parked_pr_labels is None
                   else set(parked_pr_labels))
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
        parked = bool(pr_labels & hold_labels)
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
        status = (pr_status[number]
                  if isinstance(pr_status, dict) and number in pr_status else _NO_PR_DETAIL)
        inactive, reason = _pull_inactivity_decision(pull, status)
        if parked and inactive:
            if isinstance(occupancy, list):
                occupancy.append(("parked-free", number, frozenset(areas), reason))
            continue                      # provably inert human-parked PR — frees its crates
        if isinstance(occupancy, list):
            occupancy.append(("busy", number, frozenset(areas),
                              reason if parked else "not-parked"))
        busy |= areas
    return busy


def filter_busy_area_items(items, repo, pulls, issue_labels, provenance, pr_status=None,
                           leases=None, now=0):
    """Drop plan items whose package has an in-flight worker PR (registry issue #27: the review
    loop's PRs were invisible to the busy-area partition, double-dispatching onto a busy crate).
    Global semantics mirror the target ready-engine: a global reservation blocks everything, and
    a global item cannot co-run with ANY reserved package. `provenance`/`pr_status` are the same
    maps handed to enumerate_review_items — the busy partition and the enumerator must read the
    same linkage and the same arm state (round-2 P1/P2).

    [round-5 P1] ONE crate-ownership view across lanes: beyond the open-PR busy union, an item
    is ALSO excluded when the lease ledger holds ANY live lease — impl, review, or fix lane —
    on its package (its own impl lease excepted; duplicate-work suppression stays the
    allocator partition's job). This closes the impl-side half of the park -> sibling-launch
    -> unpark hole: a parked provably-inert draft frees its crate in the busy union, but a
    review/fix run on it (or any sibling) may still hold a live lease there — launching an
    impl worker into that crate would put two lanes on one crate the moment the park lifts.
    `leases=None` (no ledger view supplied) fails toward exclusion, mirroring
    sibling_lease_conflict's ambiguity rule — callers must pass the real ledger list."""
    occupancy = []
    busy = busy_packages_of_pulls(
        repo, pulls, issue_labels, provenance, pr_status, occupancy=occupancy)
    kept = []
    for item in items:
        package = item.get("package")
        if busy and (GLOBAL_PACKAGE in busy or package == GLOBAL_PACKAGE or package in busy):
            blocker = next(
                ((pr_number, reason)
                 for decision, pr_number, packages, reason in occupancy
                 if decision == "busy" and
                 (GLOBAL_PACKAGE in packages or package == GLOBAL_PACKAGE or package in packages)),
                ("unknown", "unknown"))
            print(f"assembler defer #{item.get('number')}: crate {package} busy via "
                  f"pr#{blocker[0]} [{blocker[1]}]")
            continue
        if sibling_lease_conflict(
                repo, {f"{repo}#{item.get('number')}"},
                {package} if isinstance(package, str) else set(),
                leases, now):
            print(f"exclude {repo}#{item.get('number')}: superseded-until-sibling-resolves — "
                  "a live sibling lease (any lane) holds its package")
            continue
        kept.append(item)
    return kept


def live_pull_detail_stub(pull):
    """[round-4] PURE single-read coherence stub for a raw REST pull LISTING row, feeding
    the CLAIM-side busy revalidation. Unlike the PLAN snapshot's split listing->detail
    pair, a raw `/pulls?state=open` row carries head + draft + auto_merge in ONE
    response, so the row is its own head-matched "newer detail" for
    _pull_inactivity_decision — synthesizing the status from the same row encodes exactly
    that atomicity, and keeps the one strict coherence contract in one place instead of
    a key-presence side channel. Returns None (no status -> the carve-out fails closed
    to BUSY) when the row does not carry the full latch+draft surface or a well-formed
    head sha (a projected/partial row must never read as its own confirmation)."""
    if not isinstance(pull, dict) or "auto_merge" not in pull or "draft" not in pull:
        return None
    head_sha = str((pull.get("head") or {}).get("sha", ""))
    if not SAFE_SHA.fullmatch(head_sha):
        return None
    draft = pull.get("draft")
    auto_merge = pull.get("auto_merge")
    return {"head_sha": head_sha,
            # [round-5 P2] same STRICT tri-state as pr_ci_status: a garbage auto_merge shape
            # is UNKNOWN (None), never unarmed — the carve-out then reads BUSY (fail closed)
            # instead of freeing a crate whose latch state was unprovable.
            "armed": (True if isinstance(auto_merge, dict)
                      else False if auto_merge is None else None),
            "draft": draft if isinstance(draft, bool) else None}


def revalidate_items_against_live_pulls(items, repo, pull_pages, issue_labels, provenance,
                                        leases=None, now=0):
    """[round-4 P1] PURE CLAIM-side re-check of the PLAN busy partition against the LIVE
    pull listing CLAIM already fetches: the PLAN artifact's freeing decisions are minutes
    old by the time an item launches, so a parked draft that went ready (or a brand-new
    worker PR) inside the PLAN->CLAIM window could get a sibling dispatched into a crate
    it can still merge into. Recomputes the SAME filter_busy_area_items partition over
    the live raw rows — same linkage (provenance), same hold surfaces (issue labels),
    with each row serving as its own coherent detail via live_pull_detail_stub. A raw row
    carrying needs:user, review:needs-user, or status:blocked is ignored ONLY when that
    same row proves a draft with an explicitly absent latch through
    _pull_inactivity_decision; non-draft, latched, partial, and malformed rows stay busy.
    Returns the set of item numbers still dispatchable; the caller DEFERS the rest to the
    next tick (the fail-closed direction: a busy re-read never launches). Every parked-free
    decision and every deferred item names its live blocking artifact in the claim log.
    [round-5 P1] `leases`/`now` feed the cross-lane lease partition inside
    filter_busy_area_items (the CLAIM caller reads the ledger-branch checkout);
    leases=None fails toward exclusion."""
    rows = []
    for page in pull_pages if isinstance(pull_pages, list) else []:
        if isinstance(page, list):
            rows.extend(row for row in page if isinstance(row, dict))
    live_status = {}
    for row in rows:
        number = row.get("number")
        if isinstance(number, int) and not isinstance(number, bool):
            stub = live_pull_detail_stub(row)
            if stub is not None:
                live_status[number] = stub
    occupancy = []
    busy = busy_packages_of_pulls(
        repo, rows, issue_labels, provenance, live_status,
        parked_pr_labels=CLAIM_REVALIDATION_PARK_LABELS, occupancy=occupancy)

    for decision, pr_number, packages, _reason in occupancy:
        if decision == "parked-free":
            for package in sorted(packages):
                print(f"claim-revalidation free: crate {package} freed via parked pr#{pr_number}")

    dispatchable = set()
    for item in items:
        number = item["number"]
        package = item.get("package")
        if busy and (GLOBAL_PACKAGE in busy or package == GLOBAL_PACKAGE or package in busy):
            blocker = next(
                (pr_number for decision, pr_number, packages, _reason in occupancy
                 if decision == "busy" and
                 (GLOBAL_PACKAGE in packages or package == GLOBAL_PACKAGE or package in packages)),
                "unknown")
            print(f"claim-revalidation defer #{number}: crate {package} busy via pr#{blocker}")
            continue
        if sibling_lease_conflict(
                repo, {f"{repo}#{number}"},
                {package} if isinstance(package, str) else set(), leases, now):
            print(f"claim-revalidation defer #{number}: crate {package} busy via sibling lease")
            continue
        dispatchable.add(number)
    return dispatchable


def _live_issue_labels(repo):
    """LIVE open-issue label map for the CLAIM-side busy revalidation — the same linkage
    input the PLAN partition read from its issue snapshot (round-2 P2 parity: the busy
    union and the enumerator must read the same source-issue hold/area state), re-read
    from the list API at claim time. PR rows in the issues listing are skipped; a source
    issue absent from the map (closed in the window) reserves `__global__` inside
    busy_packages_of_pulls exactly as at PLAN time. Malformed listings raise (the whole
    repo's claim aborts loudly rather than revalidating against garbage)."""
    pages = _gh_json(["api", "--paginate", "--slurp",
                      f"repos/{repo}/issues?state=open&per_page=100"])
    if not isinstance(pages, list):
        raise DispatchError("target issue listing is malformed")
    labels_map = {}
    for page in pages:
        if not isinstance(page, list):
            raise DispatchError("target issue listing page is malformed")
        for issue in page:
            if not isinstance(issue, dict) or "pull_request" in issue:
                continue
            number = issue.get("number")
            if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
                continue
            labels_map[number] = [
                label.get("name") for label in (issue.get("labels") or [])
                if isinstance(label, dict) and isinstance(label.get("name"), str)]
    return labels_map


def _claim_provenance_map(repo, registry_root, ledger_root=""):
    """Provenance records for `repo`'s worker PRs from the LOCAL checkouts, legacy-first so
    a ledger record wins any collision — the same precedence the PLAN assemble step uses
    (issue #96). Pure file reads (no API cost). An unreadable/garbage record is skipped:
    its PR then reserves fail-closed as missing-linkage inside busy_packages_of_pulls."""
    owner, name = repo.split("/", 1)
    pattern = re.compile(rf"{re.escape(owner)}--{re.escape(name)}--pr([1-9][0-9]*)\.json")
    provenance = {}
    for root in (registry_root, ledger_root):
        if not root:
            continue
        provenance_dir = Path(root) / "orchestration" / "provenance"
        if not provenance_dir.is_dir():
            continue
        for record_path in sorted(provenance_dir.iterdir()):
            match = pattern.fullmatch(record_path.name)
            if not match:
                continue
            try:
                provenance[int(match.group(1))] = json.loads(
                    record_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                continue
    return provenance


def _ledger_leases(ledger_root):
    """[round-5 P1] The CLAIM-side lease view for the cross-lane package partition, read from
    the data-plane ledger checkout (the same branch PLAN read its lease state from). Returns
    the lease list, or None when no ledger checkout is wired or the file is
    missing/unreadable/malformed — the partition then FAILS TOWARD EXCLUSION
    (sibling_lease_conflict treats a None ledger as ambiguity), deferring items rather than
    launching into a crate whose ownership cannot be proven."""
    if not ledger_root:
        return None
    try:
        document = json.loads((Path(ledger_root) / "data" / "leases.json")
                              .read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    leases = document.get("leases") if isinstance(document, dict) else None
    return leases if isinstance(leases, list) else None


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
                           pr_status=None, exclusions=None):
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
    - an explicit review:needs/review:changes label is a re-entry signal even on a ready PR; for
      an unlabeled legacy fallback only, a matching reviewed-sha still suppresses re-review. The
      non-empty-diff gate runs at CLAIM time.

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
      base — the residue of an interrupted defuse/disarm that no other state can re-admit. After
      its own live re-derivation CLAIM RE-REVIEWS the current head (issue #161) under the bounded
      round budget, escalating to a human (needs-user) only once that budget is spent by repeated
      failed recovery. A READY (non-draft) unarmed PR in the same posture is deliberately NOT
      stranded: that is the valid arm=false-policy terminal (human merges)."""
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
        # Issue #460 exclusion telemetry, GENERALIZED (park-policy defect 3): identify EVERY
        # explicit review-loop signal (review:changes AND review:needs) BEFORE any trust/shape
        # gate, then make every rejection of such a PR visible with its exact reason. The old
        # review:changes-only telemetry let a PLAN print "0 review item(s)" while 13
        # review:needs-labeled worker PRs sat excluded with ZERO logged exclusions (live
        # 2026-07-18). The optional `exclusions` Counter aggregates reason->count so the PLAN
        # caller can emit ONE fleet-wide summary line at completion.
        # The snapshot projection emits label-name strings while direct REST fixtures carry
        # objects, so accept exactly those two production shapes and ignore malformed entries.
        labels = sorted({
            name for label in (pull.get("labels") or [])
            for name in [label.get("name") if isinstance(label, dict) else label]
            if isinstance(name, str) and name
        })
        signalled = bool({"review:changes", "review:needs", MACHINE_PARK_PR_LABEL}
                         & set(labels))

        def exclude_signalled(reason):
            if signalled:
                identity = number if isinstance(number, int) and not isinstance(number, bool) \
                    and number > 0 else "unknown"
                print(f"review-enumeration: exclude {repo}#{identity}: {reason}")
                if exclusions is not None:
                    exclusions[reason] += 1

        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            exclude_signalled("invalid PR number in snapshot")
            continue
        if pull.get("state") != "open":
            exclude_signalled(f"snapshot state is {pull.get('state')!r}, not open")
            continue
        if not HEAD_REF_RE.match(ref):
            exclude_signalled("head ref is not a worker branch")
            continue
        if head_repo != repo:
            exclude_signalled("head repo is not the target repo")
            continue                      # fork head — attacker-controlled, never reviewed
        if not login.endswith("[bot]") or (bot_login and login != bot_login):
            exclude_signalled("author is not the trusted App bot")
            continue
        record = provenance.get(number)
        record_error = provenance_admission_error(record, number)
        if record_error:
            exclude_signalled(record_error)
            continue                      # missing/invalid registry provenance record — fail
                                          # closed by the ONE shared predicate (CLAIM,
                                          # review-fix.yml resolve, and groom's draft carve-out
                                          # apply the same one, so "enumerated here" and
                                          # "admitted there" cannot drift)
        impl_provider = record["impl_provider"]
        if HUMAN_HOLD_PR_LABELS & set(labels):
            exclude_signalled("PR carries a human-owned hold label")
            continue                      # terminal — human-owned, nothing autonomous re-enters
        if not SAFE_SHA.fullmatch(sha):
            exclude_signalled("head SHA is missing or malformed")
            continue
        issue_number = record["issue"]    # a positive int — guaranteed by the predicate above
        source_labels = issue_labels.get(issue_number, [])
        if any(isinstance(label, str) and label.startswith("needs:") for label in source_labels):
            exclude_signalled(f"source issue #{issue_number} carries a needs:* human hold")
            continue                      # the SOURCE issue is human-parked (groom/escalation) —
                                          # the whole PR surface is human-owned too
        # MACHINE capacity park — ONE predicate, one proof gate (round-3 finding 2): a PR is
        # capacity-parked iff EITHER machine label is live — review:parked on the PR OR
        # status:parked on its source issue — and a parked PR is excluded from this pure
        # snapshot walk outright. The old AND-predicate let a half-cleared pair (a
        # veto-suppressed PR-side write, or a triage-side dismissal of one label) re-enter
        # enumeration, and CLAIM's proof only triggered on the surviving review:parked label —
        # so a label-free-but-still-parked PR dispatched with NO proof at all. Re-admission is
        # now label-clearing + strict proof: a human clears the live machine label(s)
        # (whichever are present), which re-enumerates the PR here, and CLAIM then re-proves
        # the human gesture from the DURABLE receipts + label timelines (strict maintainer
        # probe) before any budget/dispatch decision — receipts trigger that proof even when
        # every label is already gone, so a label dismissal can never bypass it.
        if MACHINE_PARK_PR_LABEL in labels or "status:parked" in source_labels:
            exclude_signalled(
                "machine capacity park stands (review:parked on the PR or status:parked "
                "on the source issue)")
            continue
        # [round-5 P1] CROSS-LANE SUPERSESSION: an (un)parked PR that reaches this point may
        # sit in a crate a SIBLING lease already owns — the park -> sibling-launch -> UNPARK
        # hole: the park freed the crate (busy-partition carve-out), an impl sibling claimed
        # an impl lease there (`<repo>#<issue>` — a prefix the review lane's own
        # partition_available never checks), and the human's unpark would otherwise re-admit
        # this PR immediately, letting both same-crate lanes progress at once. The ledger is
        # the ONE crate-ownership view across lanes: ANY live lease (any prefix) on this PR's
        # package(s) that is not the PR's OWN (its review:/fix: lease, its source issue's
        # impl lease) keeps it EXCLUDED until the sibling resolves (release/expiry) — then it
        # re-enters here on a later tick. Ambiguity fails toward exclusion.
        pr_areas = {label[5:] for label in labels if label.startswith("area:")}
        issue_areas = {label[5:] for label in source_labels
                       if isinstance(label, str) and label.startswith("area:")}
        if sibling_lease_conflict(
                repo,
                {f"review:{repo}#{number}", f"fix:{repo}#{number}", f"{repo}#{issue_number}"},
                pr_areas | issue_areas, leases, now):
            print(f"exclude {repo}#{number}: superseded-until-sibling-resolves — a live "
                  "sibling lease (any lane) still holds this PR's package(s); it re-enters "
                  "when that lease releases or expires")
            exclude_signalled("superseded until a live sibling package lease resolves")
            continue
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
                "package": plan_package(areas),
                "security": _security_flagged(set(labels) | set(source_labels)),
                "context": context[:CI_CONTEXT_MAX],
            })

        # GAP-B: conflict repair FIRST and alone — CI on a conflicted base is noise. This is
        # REVIEW-STATE-AGNOSTIC by design (issue #351, the #256 limbo): a review:pass PR is
        # armable (decision 7 REVISED) but the arm can NEVER merge a conflicting base, so a
        # pass verdict on a conflicting base is NOT a terminal arm-and-wait — it emits
        # needs-rebase exactly like any other non-terminal state. The pass does NOT survive
        # the rebase: the pushed merge advances the head and the fix outcome flips the PR to
        # review:needs (see the repair dispatch below — "every pushed repair flips to
        # review:needs"), so a verdict bound to the now-STALE base is re-verified against the
        # merged-in code rather than auto-armed on content it never reviewed. (A no-op rebase
        # that pushes nothing is guarded elsewhere and legitimately leaves the pass intact —
        # nothing merged in, nothing to re-verify.)
        if status.get("conflicting") is True:
            if lease_free:
                emit("needs-rebase")
            else:
                exclude_signalled("a live per-PR review/fix lease holds the conflict repair")
            continue
        # Explicit review labels are authoritative re-entry signals, independent of GitHub's
        # draft bit.  An orchestrator/human adjudication can relabel a formerly human-owned READY
        # worker PR back to review:changes/review:needs without creating a fresh round marker; the
        # old `if draft:` wrapper made that valid transition invisible forever.  CLAIM safely
        # redrafts a ready item while preserving this state before any model is launched.
        if "review:changes" in labels:
            if f"fix:{repo}#{number}" in live_keys:
                exclude_signalled("a live per-PR fix lease already owns this PR")
                continue                  # per-PR single-flight; re-emit after release/expiry
            emit("needs-fix")
            continue
        if "review:needs" in labels:
            # (review:parked no longer re-enters here: the one-predicate exclusion above
            # excludes ANY live machine park label — round-3 finding 2. A readmitted PR
            # arrives label-free and CLAIM re-proves the gesture from receipts + timelines.)
            if f"review:{repo}#{number}" in live_keys:
                # Finding D: this exit was telemetry-silent — a labeled PR could sit here
                # every tick while PLAN printed "0 review item(s)" with zero logged exclusions.
                exclude_signalled("a live per-PR review lease already owns this PR")
                continue                  # per-PR single-flight; re-emit after release/expiry
            # Normal drafted flow still avoids re-reviewing an already-bound head so concluded
            # red CI can fall through to needs-ci-fix. A READY explicit re-entry is different:
            # the external transition itself requests that the PR be brought back into review.
            if not draft or not reviewed_match:
                emit("needs-review")
                continue
        if draft:
            # A provenance-backfilled pre-migration PR with no review:* label yet, or a
            # crashed-disarm artifact still carrying review:pass while drafted (no valid flow
            # leaves a DRAFT labelled review:pass).  Unlike an explicit label re-entry, this
            # fallback retains the reviewed-sha no-repeat guard.
            if f"review:{repo}#{number}" in live_keys:
                # Finding D: same silent residue as above — make the lease exclusion visible.
                exclude_signalled("a live per-PR review lease already owns this PR")
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
                and status.get("armed") is False):
            # [round-5 P2] armed is tri-state: only an EXPLICIT False admits the stranded
            # escalation — an unknown/garbage latch shape (None) never acts.
            # Absorbing-state escape (never-silent-stall): a DRAFTED, unarmed PR whose reviewed
            # head has a concluded-GREEN gate has no other autonomous exit (re-review requires a
            # head advance, ci-fix a red gate, rebase a conflict, arm a review outcome). It is
            # the residue of a defused arm whose repair trigger evaporated, or of a crashed
            # disarm — CLAIM re-derives it live and RE-REVIEWS the current head under the bounded
            # round budget (issue #161), escalating to a human only after repeated failed recovery.
            emit("stranded")
        else:
            # Finding D: the drafted already-reviewed fall-through — a labeled PR whose head is
            # bound but whose gate is not a concluded failure and whose posture is not stranded
            # exits here every tick. Name the residue instead of dropping it silently.
            exclude_signalled(
                "head already reviewed; no live repair trigger (gate not concluded-red, "
                "posture not stranded)")
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


def _issue_is_trusted(issue, trusted_bots, allow_actions_bot_issues=False):
    """Fail-closed issue-author trust (registry issue #111). Honours the declared
    `trust = "collaborators"` policy mode: an author is trusted iff its association is
    OWNER/MEMBER/COLLABORATOR, OR its login is an EXACT member of `trusted_bots` — the
    policy-controlled allowlist (policy `trusted_bots` unioned with the runtime-resolved worker App
    `bot_login` at the call site). Issue #487 adds one narrow per-repo opt-in: when
    `allow_actions_bot_issues` is true, ONLY the exact `github-actions[bot]` login is also trusted.
    Fork-PR workflows receive read-only tokens and cannot create issues, so that login can author
    an issue in one of our own repositories only through a workflow controlled by that repository.
    A bare "[bot]" suffix is NEVER trusted: suffix-matching admitted any unrelated or compromised
    GitHub App into the dispatch pipeline (the defect this closes)."""
    if not isinstance(issue, dict):
        return False
    # A truthy non-dict `user` (string/list) must DENY, not raise AttributeError — the CLAIM loop
    # catches only DispatchError, so an uncaught exception here would abort the whole dispatch.
    user = issue.get("user")
    author = user.get("login") if isinstance(user, dict) else None
    association = str(issue.get("author_association", "")).upper()
    return (
        isinstance(author, str)
        and (association in TRUSTED_ASSOCIATIONS
             or author in trusted_bots
             or (allow_actions_bot_issues and author == "github-actions[bot]"))
    )


def _linked_open_pr_issues(pages, repo):
    """Issue numbers an OPEN pull request provably deduplicates, so dispatch skips relaunching a
    worker for them. Fail-closed provenance (issue #110): a fork contributor's PR must NEVER
    suppress an issue. Two admission paths, never "every open PR":
      - a same-repository worker branch (`head.repo.full_name == repo` AND a
        `sparq-agent/issue-N-*` head) is pipeline-owned provenance — only an actor with push
        access to the target repo can create that branch ON the repo itself (a fork PR's head
        lives on the fork, so its `head.repo` is the fork), so its worker-shaped branch ref AND
        its closing keywords are admissible; and
      - a trusted-collaborator PR (author_association OWNER/MEMBER/COLLABORATOR) — its body
        closing keywords are admissible after that explicit author-association check, the same
        gate `_issue_is_trusted` applies to issue authors.
    Any OTHER open PR (a fork / CONTRIBUTOR / NONE author) contributes NOTHING: its branch text
    and `Fixes #N` body are attacker-controlled and must not park an issue indefinitely."""
    if not isinstance(pages, list):
        raise DispatchError("target pull-request listing is malformed")
    linked = set()
    for page in pages:
        if not isinstance(page, list):
            raise DispatchError("target pull-request page is malformed")
        for pull in page:
            if not isinstance(pull, dict):
                raise DispatchError("target pull-request entry is malformed")
            head = pull.get("head") or {}
            ref = head.get("ref", "")
            body = pull.get("body") or ""
            if not isinstance(ref, str) or not isinstance(body, str):
                raise DispatchError("target pull-request fields are malformed")
            head_repo = (head.get("repo") or {}).get("full_name")
            association = str(pull.get("author_association", "")).upper()
            # A same-repo `sparq-agent/issue-N-*` head is App provenance; a fork head is not.
            app_pr = head_repo == repo and HEAD_REF_RE.match(ref) is not None
            if app_pr:
                linked.update(int(number) for number in re.findall(
                    r"(?:^|/)issue-([1-9][0-9]*)-", ref
                ))
            if app_pr or association in TRUSTED_ASSOCIATIONS:
                linked.update(int(number) for number in re.findall(
                    r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#([1-9][0-9]*)\b", body
                ))
    return linked


def _protected_default_tip(repo):
    """Independently resolve the target's PROTECTED default-branch tip in registry-owned CLAIM
    code (registry issue #119). PLAN derives the plan's `target_sha` with `git rev-parse HEAD` in
    the SAME checkout that just executed the hostile target planner, so a malicious target can
    leave HEAD on an obsolete commit whose routing catalog is weaker or incompatible. CLAIM must
    never let target-controlled data select the routing revision it trusts, so it re-resolves the
    default branch (the branch-protected surface the routing file lives on) and reads its tip
    straight from the GitHub API here. Fail-closed: an unreadable repo, a missing default branch, a
    default branch that is not branch-protected, or a tip that is not a 40-hex sha raises
    DispatchError, so the caller defers rather than routing off an unverifiable revision."""
    meta = _gh_json(["api", f"repos/{repo}"])
    branch = meta.get("default_branch") if isinstance(meta, dict) else None
    if not isinstance(branch, str) or not branch:
        raise DispatchError(f"cannot resolve default branch for {repo}")
    ref = _gh_json(["api", f"repos/{repo}/branches/{branch}"])
    # The routing catalog's trust rests on the default branch being branch-PROTECTED — that is the
    # only reason CLAIM treats its tip as an authority a hostile target cannot rewrite. Prove it
    # from the API response, not from the branch's name: accept only an explicit `protected is
    # True`. Anything else (protected false, missing, or non-bool) means the surface is not the
    # protected control surface we claim, so fail closed rather than route off an unprotected tip.
    protected = ref.get("protected") if isinstance(ref, dict) else None
    if protected is not True:
        raise DispatchError(f"default branch for {repo} is not branch-protected")
    commit = ref.get("commit") if isinstance(ref, dict) else None
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not SAFE_SHA.fullmatch(sha):
        raise DispatchError(f"cannot resolve default-branch tip for {repo}")
    return sha


def _protected_routing(repo, path):
    """Fetch the target's protected routing catalog from the default-branch tip CLAIM resolves
    ITSELF (registry issue #119) — never from the plan's `target_sha`, which the hostile target
    planner controls. This is the routing revision every downstream route/policy decision trusts,
    so sourcing it from a target-selected commit let a malicious target dispatch its own issues
    against an obsolete, weaker routing catalog. Fail-closed: an unresolvable protected tip, or a
    missing/malformed routing file at that tip, raises DispatchError."""
    sha = _protected_default_tip(repo)
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


def _current_issue_matches(repo, item, trusted_bots, allow_actions_bot_issues=False):
    issue = _gh_json(["api", f"repos/{repo}/issues/{item['number']}"])
    if not isinstance(issue, dict) or "pull_request" in issue or issue.get("state") != "open":
        return False, "issue is no longer an open issue"
    labels = _labels(issue)
    if labels != item["labels"]:
        return False, "issue labels changed after planning"
    user = issue.get("user")
    author = user.get("login") if isinstance(user, dict) else None
    if author != item["author"]:
        return False, "issue author changed after planning"
    body = issue.get("body") or ""
    if not isinstance(body, str) or hashlib.sha256(body.encode()).hexdigest() != item["body_sha"]:
        return False, "issue body changed after planning"
    if not _issue_is_trusted(issue, trusted_bots, allow_actions_bot_issues):
        return False, "issue is not maintainer/collaborator/allowlisted-bot authored"
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


def _pr_needs_user(script_dir, repo, pr_number, issue, reason, park_class="question",
                   bot_login=""):
    """Stop the loop for a PR. `park_class` picks the label PAIR (park_policy.py ownership):
    "question" (default) -> the human-owned pair (review:needs-user on the PR, needs:user on
    the source issue) for genuine human questions; "capacity" -> the machine-owned soft-hold
    pair (review:parked on the PR, status:parked on the source issue) for capacity/decline/
    budget-driven stops — veto-gated, receipted per readmission window, and escalating to the
    question class after PARK_ESCALATION_GENERATIONS consumed windows (worker-pr needs_user
    owns all of that; `bot_login` feeds its receipt parser's trust filter)."""
    args = ["needs-user", "--repo", repo, "--pr", str(pr_number), "--reason", reason,
            "--park-class", park_class]
    if bot_login:
        args += ["--bot-login", bot_login]
    if isinstance(issue, int) and issue > 0:
        args += ["--issue", str(issue)]
    _run_target_helper(script_dir, repo, "worker-pr.py", args)


def _park_source_issue(script_dir, repo, number):
    """Apply the machine-owned capacity park (worker-issue `--status parked`; that helper
    enforces the sticky human-unpark veto at the write point — park_policy.py defect 2).
    Returns True when the park LANDED and False when the veto suppressed it — the caller's
    park comment must then be HONEST about the suppressed label (round-3 finding 1; the
    receipt still lands exactly once, so a standing veto never induces comment spam)."""
    result = _run_target_helper(script_dir, repo, "worker-issue.py", [
        "status", "--repo", repo, "--issue", str(number), "--status", "parked"])
    if "park suppressed" in (result.stdout or ""):
        print(f"park suppressed for {repo}#{number}: sticky human unpark (or unreadable "
              "timeline) — no park label was written this tick")
        return False
    return True


def _issue_needs_user_landed(script_dir, repo, number):
    """Apply the terminal question park (worker-issue `--status needs-user`; that helper
    enforces the sticky human-unpark veto at the write point). Returns True when the label
    pair LANDED and False when the veto suppressed it — the caller's terminal comment must
    then say so (round-3 finding 1: the escalation is terminal in the durable receipts, but
    NO label was applied — never claim a label that did not land)."""
    result = _run_target_helper(script_dir, repo, "worker-issue.py", [
        "status", "--repo", repo, "--issue", str(number), "--status", "needs-user"])
    if "park suppressed" in (result.stdout or ""):
        print(f"terminal needs:user suppressed for {repo}#{number}: sticky human unpark — "
              "the escalation is recorded in the receipts without a label")
        return False
    return True


def _run_gh_target_comment(repo, issue_or_pr, body):
    _run_gh_target_api(
        repo, "POST", f"repos/{repo}/issues/{issue_or_pr}/comments", {"body": body})


def _run_gh_target_api(repo, method, path, input_doc=None):
    """One target-owner issue mutation in the same token-isolated API style as every existing
    dispatch-side target write. The registry token is never used as a fallback for another
    owner's issue mutation."""
    token = _target_token(repo)
    if not token:
        raise DispatchError("target-scoped App token is unavailable")
    command = ["gh", "api", "-X", method, path]
    if input_doc is not None:
        command += ["--input", "-"]
    result = subprocess.run(
        command, input=json.dumps(input_doc) if input_doc is not None else None,
        capture_output=True, text=True, check=False,
        env={**os.environ, "GH_TOKEN": token},
    )
    if result.returncode != 0:
        raise DispatchError("target issue mutation failed")
    return result


def _replace_issue_role_with_research(repo, item):
    """Atomically replace the revalidated role:impl label with role:research.

    A full labels PATCH is intentional: add-then-remove can strand the issue with two role labels,
    while remove-then-add can strand it with none; both shapes are rejected by the planner. The
    caller has just required the live issue labels to exactly equal this plan copy via
    _current_issue_matches, and stops the cached claim after this mutation, so the old impl route
    can never launch from the same plan.
    """
    labels = set(item["labels"])
    if item.get("role") != "impl" or "role:impl" not in labels:
        raise DispatchError("decline reroute no longer has exactly the impl route")
    # Re-read immediately before the full-label replacement. The earlier claim revalidation
    # precedes the ledger/comment reads; without this last-step check, a human needs:* label landing
    # in that interval could be erased by our PATCH.
    live_result = _run_gh_target_api(
        repo, "GET", f"repos/{repo}/issues/{item['number']}")
    try:
        live_issue = json.loads(live_result.stdout or "null")
    except json.JSONDecodeError as exc:
        raise DispatchError("target issue re-read returned malformed JSON") from exc
    if (not isinstance(live_issue, dict) or "pull_request" in live_issue
            or live_issue.get("state") != "open"
            or _labels(live_issue) != item["labels"]):
        raise DispatchError("target issue changed before decline reroute; leaving it untouched")
    desired = sorted((labels - {"role:impl"}) | {"role:research"})
    _run_gh_target_api(
        repo, "PATCH", f"repos/{repo}/issues/{item['number']}", {"labels": desired})


def _pr_comments(repo, pr_number):
    """All conversation comments of a target PR/issue (paginated). A malformed PAGE must
    RAISE, never be silently dropped (round-3 finding 3): a discarded page could hide a
    durable receipt (round/attempt/park-generation marker) — hiding one would un-count budget
    rounds or un-consume an escalation-ladder window. Same fail-closed shape as
    _issue_timeline_events."""
    pages = _gh_json([
        "api", "--paginate", "--slurp", f"repos/{repo}/issues/{pr_number}/comments?per_page=100",
    ])
    if not isinstance(pages, list):
        raise DispatchError("target PR comments are malformed")
    for page in pages:
        if not isinstance(page, list):
            raise DispatchError("target PR comments page is malformed")
    return [item for page in pages for item in page]


def _issue_timeline_events(repo, number):
    """The FULL label timeline of an issue/PR (paginated) for the round-budget readmission
    window. The newest events — the ones the readmission cutoff hinges on — are on the LAST
    page, so a truncated/malformed read must RAISE rather than return a prefix — and a
    malformed PAGE must raise for the same reason (it could hold the newest human unlabel;
    silently dropping it would hide the exact event the window hinges on). The caller
    (park_policy) then keeps the full historical count with a loud log line (fail toward the
    OLD conservative budget, never a fresh one)."""
    pages = _gh_json([
        "api", "--paginate", "--slurp", f"repos/{repo}/issues/{number}/timeline?per_page=100",
    ])
    if not isinstance(pages, list):
        raise DispatchError("target timeline is malformed")
    for page in pages:
        if not isinstance(page, list):
            raise DispatchError("target timeline page is malformed")
    return [item for page in pages for item in page]


def _target_is_human_maintainer(repo, login):
    """The strict maintainer probe for the readmission window / unpark veto (park-policy
    hygiene finding; the worker-issue._is_human_maintainer pattern): TARGET collaborator
    permission in park_policy.HUMAN_MAINTAINER_PERMISSIONS, read under the target App token
    (the ambient registry token has no collaborator visibility there). Probe-call FAILURE
    counts as NOT a maintainer and emits the shared distinct ::warning:: diagnostic
    (park_policy.probe_maintainer, round-3 Opus finding); a genuine not-a-maintainer
    permission stays quiet."""
    def read_permission(probe_login):
        result = _run_gh_target_api(
            repo, "GET", f"repos/{repo}/collaborators/{probe_login}/permission")
        payload = json.loads(result.stdout or "null")
        if not isinstance(payload, dict):
            raise DispatchError("collaborator permission payload is malformed")
        return payload.get("permission")

    return _park_policy.probe_maintainer(repo, login, read_permission)


def _read_model_health_window(model_health, registry_repo, now, api=None):
    """Read the task-decline evidence through model-health's authoritative validated reader.

    Dispatch is a read-only consumer: it never calls append_record or writes the health ledger.
    Invalid contents, a missing data-plane branch, or an unreadable API all return None after a
    loud diagnostic; callers leave the issue deferred and MUST NOT infer an escalation.
    """
    try:
        api = api or model_health.GitHubAPI(os.environ.get("GH_TOKEN", ""))
        records, _ = model_health.read_ledger(api, registry_repo)
        return model_health.prune(records, now)
    except (model_health.HealthError, ValueError) as exc:
        print("::error::dispatch decline escalation: validated model-health ledger is "
              f"unreadable ({exc}); NO task escalation will fire")
        return None


def _issue_no_change_outcomes(model_health, records, issue):
    """Validated, in-window no_change rows for one target issue, newest last."""
    rows = [record for record in records
            if record.get("exit_class") == model_health.CLASS_NO_CHANGE
            and record.get("issue") == issue]
    return sorted(
        rows,
        key=lambda record: (
            record["ts"], record.get("run_id", ""), record.get("account", ""),
            json.dumps(record, sort_keys=True, separators=(",", ":")),
        ),
    )


def _decline_escalation_evidence(outcomes):
    """The two newest rows plus a stable, non-sensitive marker key for exactly that escalation."""
    evidence = outcomes[-DECLINE_ESCALATION_MIN:]
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return evidence, hashlib.sha256(encoded.encode()).hexdigest()[:16]


def _decline_marker_action(comments, bot_login, key):
    """Return the bot-authored action already audited for this evidence pair, if any.

    Third parties cannot forge an idempotence marker: as elsewhere in the worker control plane,
    only the orchestration bot's own durable comments are receipts.
    """
    pattern = re.compile(
        rf"<!-- {re.escape(DECLINE_ESCALATION_MARKER)} key={re.escape(key)} "
        r"action=(research|needs-user) -->"
    )
    actions = {
        match.group(1)
        for comment in comments
        if str(comment.get("user", {}).get("login", "")).casefold() == bot_login.casefold()
        for match in pattern.finditer(str(comment.get("body", "")))
    }
    if len(actions) > 1:
        raise DispatchError("task decline escalation has conflicting audit markers")
    return next(iter(actions), None)


def _decline_outcome_name(record):
    run_id = record.get("run_id") or f"ledger-ts-{record['ts']}"
    return f"run `{run_id}` → `no_change`"


def _escalate_repeated_declines(repo, item, outcomes, comments, bot_login, script_dir,
                                apply_action=None, post_comment=None):
    """Apply or reconcile one repeated-decline escalation.

    Returns ``proceed`` below threshold and after a previously completed impl->research reroute;
    every other result means the caller must stop this cached claim. The audit marker is written
    BEFORE the label mutation so a mutation failure can be reconciled next tick without a second
    loud comment. Conversely, a failed comment performs no label mutation and safely retries.
    Injectable mutation/comment callables keep the --self-test tripwires on the real control flow.
    """
    if len(outcomes) < DECLINE_ESCALATION_MIN:
        return "proceed"

    evidence, key = _decline_escalation_evidence(outcomes)
    marked_action = _decline_marker_action(comments, bot_login, key)
    labels = set(item["labels"])

    if apply_action is None:
        def apply_action(action):
            if action == "research":
                _replace_issue_role_with_research(repo, item)
            else:
                # Repeated honest declines are decline-driven, not a human question: the issue
                # takes the MACHINE-owned status:parked soft hold (park_policy.py defect 1).
                # The durable marker keeps its historical action name "needs-user" so
                # pre-existing escalation receipts still reconcile. worker-issue's set_status
                # enforces the sticky human-unpark veto at the write point.
                _run_target_helper(script_dir, repo, "worker-issue.py", [
                    "status", "--repo", repo, "--issue", str(item["number"]),
                    "--status", "parked",
                ])
    if post_comment is None:
        post_comment = lambda body: _run_gh_target_comment(repo, item["number"], body)

    if marked_action == "research":
        # The same two impl outcomes have already caused the route swap. Permit ONLY the new
        # research route; if the label write crashed after its marker, reconcile it and stop this
        # stale impl claim. This is the cached-claim bypass tripwire.
        if item.get("role") == "research" and "role:research" in labels \
                and "role:impl" not in labels:
            return "proceed"
        if item.get("role") == "impl" and "role:impl" in labels:
            apply_action("research")
            return "rerouted"
        raise DispatchError("recorded decline reroute conflicts with the issue's current role")
    if marked_action == "needs-user":
        # Reconcile a crashed label write for THIS evidence pair. Legacy needs:user parks (or a
        # human's own needs:user) also count as already-parked — never re-park over them.
        if "status:parked" not in labels and "needs:user" not in labels:
            apply_action("needs-user")
        return "parked"

    action = "research" if item.get("role") == "impl" else "needs-user"
    outcome_lines = "\n".join(
        f"- Outcome {index}: {_decline_outcome_name(record)}"
        for index, record in enumerate(evidence, 1)
    )
    if action == "research":
        action_text = ("**Action:** swapped `role:impl` → `role:research` for architect "
                       "decomposition. The cached implementation claim is cancelled; only the "
                       "new research route may dispatch.")
    else:
        role = item.get("role") or "unknown"
        action_text = (f"**Action:** parked this issue with the machine-owned `status:parked` "
                       f"soft hold. It was already on the non-implementation route "
                       f"`role:{role}`, so another automated reroute would loop. The park "
                       "clears automatically once the decline evidence ages out of the "
                       "model-health window and capacity exists; no human action is required "
                       "unless it persists.")
    marker = f"<!-- {DECLINE_ESCALATION_MARKER} key={key} action={action} -->"
    post_comment(
        "> 🤖 SPARQ agent — **repeated honest-decline escalation**\n\n"
        "This issue returned without repository changes twice in the validated model-health "
        f"window, regardless of which accounts ran it:\n\n{outcome_lines}\n\n"
        f"{action_text}\n\n{marker}"
    )
    apply_action(action)
    return "rerouted" if action == "research" else "parked"


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
            # Issue #156: records are now the host envelope {host_envelope, verdict}; unwrap to
            # the model document (a legacy bare-document record returns itself unchanged).
            progress = worker_pr.envelope_verdict(document).get("progress")
            if progress in worker_pr.PROGRESS_VALUES:
                return progress
    return worker_pr.round_progress(comments, bot_login).get(rounds)


def _resolvable_chain(chain, routing):
    """Keep only chain aliases the harness can actually run (locked decision 14). A CLAUDE alias
    needs a concrete provider_model. A CODEX alias is resolvable even with a missing/TBD
    provider_model: the proven codex drain passes NO --model flag (codex CLI default; the
    operator config pins only reasoning effort), and worker-live.sh omits --model in that case —
    so an unpinned sol/luna never turns into the common-case liveness stop of every
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


def _chain_probe_exempt(chain, routing):
    """True iff EVERY alias in `chain` maps to a POSITIVELY probe-exempt provider in the target
    routing catalog (issue #115) — so a wholesale usage-probe outage (usage=None) does NOT gate a
    claim served entirely by codex/openai accounts, whose absent usage is the expected steady
    state. Fail-closed: an empty chain, a missing routing catalog, or ANY alias whose provider is
    absent / unknown / non-exempt makes the whole chain non-exempt, and the require_usage hold then
    applies (a probe-gated anthropic review/fix never rides an unavailable probe)."""
    models = routing.get("models") if isinstance(routing, dict) else None
    if not isinstance(models, dict) or not chain:
        return False
    for alias in chain:
        meta = models.get(alias)
        provider = meta.get("provider") if isinstance(meta, dict) else None
        if str(provider or "").strip().lower() not in PROBE_EXEMPT_PROVIDERS:
            return False
    return True


def _dispatch_review_items(review_items, repo, policy, routing, allocator, worker_pr,
                           registry_repo, registry_root, workflow_ref, bot_login, usage, margin,
                           defer_reasons, lanes=None, ledger_root="", fix_dispatch=None):
    """Hostile re-validation + claim + launch for the review/fix loop. Every item failure SKIPS
    that item (per-item resilience, like the issue loop). `defer_reasons` is the tick's SHARED
    histogram: allocator lease errors here must fold into the same `lease-error` counter the
    issue loop uses, because _ledger_health/_ledger_rot_zeroed_dispatch (issue #28) read that
    counter — an all-review/fix tick whose claims all errored would otherwise report ledger=ok
    and dodge the zero-dispatch fail-loud.

    `lanes` is the tick's per-lane accumulator (issue #108). Each item's plan state selects its lane
    (review vs fix via _review_item_lane); a launch folds into that lane's `launched` and a hard
    failure (lease error, revalidation DispatchError, failed workflow launch) into its `error`. This
    keeps a review/fix lane that launched NOTHING visible to the tick-health recorder even when the
    worker lane launched — the exact masking this loop's bare launched-count return used to allow."""
    if lanes is None:
        lanes = _new_lane_counts()
    if fix_dispatch is None:
        fix_dispatch = Counter()
    launched = 0
    script_dir = Path(__file__).resolve().parent
    max_rounds = int(policy.get("max_review_rounds", 3))
    # Issue #115: the same fail-closed usage gate the worker loop applies (a require_usage repo
    # HOLDS on a wholesale usage-probe outage rather than dispatching ungated). Enforced per-claim
    # below, with an explicit carve-out for a chain served entirely by probe-exempt accounts.
    require_usage = bool(policy.get("require_usage", False))
    # Close the preceding item's telemetry at the next iteration (and once after the loop).  This
    # catches every pre-claim validation/policy `continue` without duplicating counters at the many
    # already-instrumented lease/error exits.  The exact cause remains in the per-PR log line; the
    # shared summary gets the stable coarse reason required for lane health.
    pending_telemetry = None

    def finish_pending():
        nonlocal pending_telemetry
        if pending_telemetry is None:
            return
        if (not pending_telemetry["launched"]
                and sum(defer_reasons.values()) == pending_telemetry["reason_total"]):
            defer_reasons[f"{pending_telemetry['lane']}:preclaim-defer"] += 1
        if (pending_telemetry["lane"] == "fix" and not pending_telemetry["launched"]
                and sum(value for key, value in fix_dispatch.items()
                        if key.startswith("defer:"))
                == pending_telemetry["fix_reason_total"]):
            # The exact per-PR cause was printed at the rejection site. Keep the aggregate
            # privacy-safe while ensuring an enumerated fix item can never vanish from the
            # fleet line merely because it stopped before allocator.claim().
            fix_dispatch["defer:preclaim-defer"] += 1
        pending_telemetry = None

    for item in review_items:
        finish_pending()
        number = item["pr_number"]
        lane = _review_item_lane(item["state"])
        lanes[lane]["planned"] += 1
        if lane == "fix":
            # Issue #460: count at the actual PLAN->CLAIM enumeration boundary, not just
            # immediately before allocator.claim(). The old placement turned every valid
            # live-revalidation/budget exclusion into the false `0 eligible` signal.
            fix_dispatch["eligible"] += 1
        pending_telemetry = {
            "lane": lane,
            "launched": False,
            "reason_total": sum(defer_reasons.values()),
            "fix_reason_total": sum(
                value for key, value in fix_dispatch.items() if key.startswith("defer:")),
        }
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
            source_labels_live = _labels(source_issue)
            if any(label.startswith("needs:") for label in source_labels_live):
                print(f"defer review {repo}#{number}: source issue #{issue_number} is "
                      "human-owned (needs:*)")
                continue
            if "status:parked" in source_labels_live:
                # The one-predicate rule (round-3 finding 2): EITHER live machine label parks
                # the whole PR surface. PLAN already excludes on this; a status:parked read
                # here means the park landed in the PLAN->CLAIM window — a fresh park, never
                # a readmission candidate this tick.
                print(f"defer review {repo}#{number}: machine capacity park stands "
                      f"(status:parked on source issue #{issue_number})")
                continue
            # Comments are read ONCE here (before the park-proof gate — the durable
            # park-generation receipts live in them) and reused by the round-budget
            # processing below.
            comments = _pr_comments(repo, number)
            park_receipts = worker_pr.park_generation_cutoffs(comments, bot_login)
            if MACHINE_PARK_PR_LABEL in labels or park_receipts:
                # ONE proof gate (round-3 finding 2): the trigger is the DURABLE receipt
                # state OR a live review:parked label — never the label alone. A triage-side
                # label dismissal leaves the receipts standing, so CLAIM still re-proves the
                # human gesture from the label TIMELINES (strict maintainer probe;
                # most-recent-event-wins against the park application, receipted windows
                # consumed) before anything mutates or dispatches — a spoofed/stale label
                # state can re-enumerate, but it can never mint budget or strip the park.
                if not _park_policy.capacity_park_readmitted(
                        repo, number, issue_number, _issue_timeline_events,
                        is_human=lambda login: _target_is_human_maintainer(repo, login),
                        consumed=park_receipts):
                    print(f"defer review {repo}#{number}: machine capacity park stands "
                          "(durable receipts/label; no unconsumed proven-human readmission "
                          "gesture)")
                    continue
                if MACHINE_PARK_PR_LABEL in labels:
                    # Proven gesture: converge the stale PR-side park back into the loop (the
                    # review-fix.yml admission rejects review:parked, so the strip must
                    # precede any dispatch). set_review_state drops review:parked for
                    # review:needs.
                    _run_target_helper(script_dir, repo, "worker-pr.py", [
                        "review-state", "set", "--repo", repo, "--pr", str(number),
                        "--state", "needs"])
                    print(f"re-admit review {repo}#{number}: human readmission gesture "
                          "proven; review:parked converged to review:needs")
            if opened_sha != head_sha:
                compare = _gh_json(["api", f"repos/{repo}/compare/{opened_sha}...{head_sha}"])
                if compare.get("status") not in {"identical", "ahead"}:
                    # Rewritten history — the worker-opened commit is no longer an ancestor.
                    _pr_needs_user(script_dir, repo, number, issue_number,
                                   "the PR head no longer descends from the worker-opened commit "
                                   "(history was rewritten); refusing autonomous review")
                    continue
            if not draft and item["state"] in {"needs-review", "needs-fix"}:
                # Label-driven re-entry may arrive while the PR is READY (and possibly armed).
                # Defuse before any review/fix model runs, but preserve the externally selected
                # review:needs/review:changes state; the historical disarm relabel-to-needs would
                # otherwise turn a requested fix into a review during this safety transition.
                _run_target_helper(script_dir, repo, "worker-pr.py", [
                    "disarm", "--repo", repo, "--pr", str(number), "--when", "always",
                    "--preserve-review-state"])
                draft = True
                print(f"re-enter review {repo}#{number}: safely returned the ready PR to draft "
                      f"while preserving {item['state']}")
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
                # Issue #161: the stranded posture — {drafted, unarmed, reviewed head, green
                # gate} — is the RESIDUE of an interrupted defuse/disarm (a pipeline-owned
                # crash), not a review verdict. Terminally parking it on a human made a
                # pipeline crash into permanent manual work. The pipeline instead RECOVERS with
                # its own trusted provenance: it re-reviews the current head (despite the
                # matching reviewed-sha marker) under the SAME bounded round budget as any
                # review, and reserves the terminal human hand-off for REPEATED failed recovery
                # — decide_budget below escalates to needs-user only once that budget is spent.
                # Re-derived LIVE first: any drift (armed again, head moved, gate red/pending,
                # base conflicting) means some other path owns the new posture, so defer with NO
                # mutation and let that path re-admit it.
                checks = _gh_json([
                    "api",
                    f"repos/{repo}/commits/{head_sha}/check-runs"
                    f"?check_name={CI_GATE_CHECK}&per_page=100"])
                live_ci = interpret_check_runs(
                    (checks or {}).get("check_runs") if isinstance(checks, dict) else None)
                reviewed = REVIEWED_SHA_RE.search(pull.get("body") or "")
                # [round-5 P2] tri-state live arm bit: garbage auto_merge shapes are UNKNOWN
                # (None) and stranded_live then refuses to act — never "unarmed".
                live_auto = pull.get("auto_merge")
                live_armed = (True if isinstance(live_auto, dict)
                              else False if live_auto is None else None)
                if not stranded_live(draft, live_armed,
                                     bool(reviewed and reviewed.group(1) == head_sha),
                                     pull.get("mergeable"), live_ci["gate"]):
                    print(f"defer review {repo}#{number}: the stranded posture did not "
                          "re-derive on live data")
                    continue
                print(f"recover review {repo}#{number}: stranded residue of an interrupted "
                      "defuse/disarm — re-reviewing the current head under the round budget")
                # Fall through to the shared round-budget + review dispatch below.
            # Base admission (issue #164; the #81 precedent in
            # worker-pr._merge_only_carry_forward): the worker-PR invariant is base == protected
            # default branch (review-fix.yml resolve rejects a retarget LOUDLY; a human retarget
            # is an explicit act that removes the PR from the loop). Enforce that same invariant
            # HERE — BEFORE the round-budget processing below, whose needs-user and
            # extend-model-pin actions mutate the PR (labels/comments, a durable pin marker) —
            # so a retargeted or unresolved-base PR leaves the loop with NO mutation, failing
            # closed rather than probing/dispatching the wrong comparison. Deliberately AFTER
            # the repair defuse above: defusing a live auto-merge latch is the safety action and
            # must run whatever the base says.
            base = pull.get("base") or {}
            base_ref = str(base.get("ref", ""))
            default_branch = str((base.get("repo") or {}).get("default_branch", ""))
            if (not SAFE_ATOM.fullmatch(base_ref) or not default_branch
                    or base_ref != default_branch):
                print(f"defer review {repo}#{number}: PR base {base_ref!r} is not the "
                      "protected default branch (retargeted/unresolved) — refusing to "
                      "process against the wrong base")
                continue
            # `comments` was read once above (before the park-proof gate); the round markers
            # and receipts below parse the same snapshot.
            rounds = worker_pr.count_rounds(comments, bot_login)
            # Human-readmission window (live defect sparq#2804/PR#3442, 2026-07-23): the budget
            # decision below used to charge ALL historical rounds, so five rounds burned during
            # the broken-CI era (gate-aggregator churn, phantom-leg failures, Copilot-outage
            # stub reviews) re-parked the PR 22 minutes after the maintainer explicitly removed
            # needs:user — the human said "keep trying" and the math ignored it. The budget
            # instead charges only rounds recorded AFTER the latest HUMAN `unlabeled needs:user`
            # event across the PR and its provenance-linked source issue (an explicit
            # re-admission restarts the budget so the loop actually retries). No proven human
            # unlabel — including a failed timeline read, which park_policy logs loudly — keeps
            # the full historical count (never a fresh budget on unproven data). `rounds` itself
            # stays the global count everywhere else: round numbering, the pending-fix lookup,
            # the latest-progress read and the pin round all keep marker/verdict identity.
            # Probed only at/above the base budget: below it decide_budget continues either way.
            budget_rounds = rounds
            if rounds >= max_rounds:
                cutoff = _park_policy.readmission_cutoff(
                    repo, number, issue_number, _issue_timeline_events,
                    is_human=lambda login: _target_is_human_maintainer(repo, login))
                if cutoff:
                    budget_rounds = worker_pr.count_rounds_since(comments, bot_login, cutoff)
                    if budget_rounds != rounds:
                        print(f"readmission window open for {repo}#{number}: a human "
                              f"unlabeled a park label at {cutoff}; the round budget charges "
                              f"{budget_rounds} of {rounds} recorded round(s)")
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
                budget = worker_pr.decide_budget(budget_rounds, fix_models, progress,
                                                 impl_provider, base_rounds=max_rounds,
                                                 pending_fix_models=pending_fix,
                                                 pin_floor=pin_floor)
            except worker_pr.WorkerPrError as exc:
                _pr_needs_user(script_dir, repo, number, issue_number,
                               f"round-budget escalation-marker validation failed ({exc}); a "
                               "human must inspect this PR's round/model/pin markers")
                continue
            if budget["action"] == "needs-user":
                # Budget-driven stop -> the MACHINE-owned soft-hold pair (finding A:
                # review:parked on the PR + status:parked on the source issue; park_policy.py
                # defect 1): exhaustion is not a human question, and the old unconditional
                # review:needs-user terminally absorbed the whole PR surface (2026-07-18 mass
                # park) and closed the readmission window forever. worker-pr needs_user owns
                # the veto gate, the per-window receipt dedupe, and the
                # PARK_ESCALATION_GENERATIONS question-class escalation (bot_login feeds its
                # receipt trust filter). `budget_rounds` is the charged count —
                # post-readmission when a human unlabeled a park label (sparq#2804/PR#3442),
                # the full history otherwise.
                _pr_needs_user(script_dir, repo, number, issue_number,
                               f"the review round budget is exhausted at {budget_rounds} "
                               f"round(s) "
                               f"(base {max_rounds}, hard cap {worker_pr.HARD_CAP_ROUNDS}) "
                               "with no extension left — the top fix tier has run, the latest "
                               "verdict does not grade the PR improving, and no pushed fix at "
                               "or above the pinned floor awaits re-review; a human must "
                               "decide", park_class="capacity", bot_login=bot_login)
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
            if item["state"] in {"needs-review", "stranded"}:
                reviewed = REVIEWED_SHA_RE.search(pull.get("body") or "")
                # A needs-review head that already equals its reviewed-sha marker has nothing to
                # re-review (no head advance) and defers. The stranded RECOVERY (issue #161) is
                # the sole, deliberate exception: it re-reviews the MATCHING head to escape the
                # residue of an interrupted defuse/disarm — the reviewed-sha guard is bypassed
                # for it, and the round budget above bounds how often it may retry.
                if (item["state"] == "needs-review"
                        and reviewed and reviewed.group(1) == head_sha
                        and "review:needs" not in labels):
                    print(f"defer review {repo}#{number}: head already reviewed")
                    continue
                # The empty-diff / no-op-rebase probe compares against the PR's ACTUAL base
                # ref, never the repo default branch (issue #164): a wrong-base probe reads
                # either empty (a silent forever-defer) or non-empty vs a base the arm can never
                # merge. The base admission ABOVE already validated base_ref as the protected
                # default, so an empty result here really is a no-op rebase.
                diff = _gh_json(["api", f"repos/{repo}/compare/{base_ref}...{head_sha}"])
                if not diff.get("files"):
                    print(f"defer review {repo}#{number}: empty diff vs merge base (no-op rebase)")
                    continue
                mode, role = "review", "review"
                chain = _resolvable_chain(REVIEW_CHAIN[impl_provider], routing)
                holder_namespace, ttl = "review:", REVIEW_TTL
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
                    # Missed dispatches ARE capacity starvation (the allocator found no slot
                    # every tick) -> the machine-owned park, never a fake human question.
                    _pr_needs_user(script_dir, repo, number, issue_number,
                                   f"{len(missed)} consecutive fix dispatches missed for round "
                                   f"{round_number}; a human must unstick this PR",
                                   park_class="capacity", bot_login=bot_login)
                    continue
                chain = _resolvable_chain(fix_aliases, routing)
                holder_namespace, ttl = "fix:", FIX_TTL
            else:
                # Externally relabelled review:changes is a first-class re-entry even when no
                # bot round marker survived/exists.  Round 1 is the positive workflow round that
                # corresponds to the clean synthetic round-0 budget posture; the trusted verdict
                # record is still required below before a verdict-seeded fixer may run.
                round_number = max(rounds, 1)
                missed = worker_pr.marker_runs(comments, bot_login, "missed", round_number)
                if len(missed) >= MISSED_FIX_LIMIT:
                    # Same capacity-starvation classification as the repair-state branch above.
                    _pr_needs_user(script_dir, repo, number, issue_number,
                                   f"{len(missed)} consecutive fix dispatches missed for round "
                                   f"{round_number}; a human must unstick this PR",
                                   park_class="capacity", bot_login=bot_login)
                    continue
                verdict_file = record_file_path(ledger_root, registry_root,
                                                worker_pr.verdict_path(repo, number, round_number))
                if not verdict_file.is_file():
                    _run_target_helper(script_dir, repo, "worker-pr.py", [
                        "record-marker", "--repo", repo, "--pr", str(number), "--kind", "missed",
                        "--round", str(round_number), "--run-key",
                        f"{os.environ.get('GITHUB_RUN_ID', 'local')}."
                        f"{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}",
                        "--bot-login", bot_login])
                    print(f"defer review {repo}#{number}: round {round_number} trusted verdict "
                          "record missing")
                    continue
                if rounds < 1:
                    # Bind the recovered trusted round-1 verdict back into the durable comment
                    # state before launching its fix. Without this synthesis the pushed fix would
                    # be re-reviewed as round 1 and collide with the existing immutable round-1
                    # verdict path. The budget decision above intentionally saw round 0, so this
                    # externally adjudicated re-entry starts clean; subsequent ticks see round 1.
                    _run_target_helper(script_dir, repo, "worker-pr.py", [
                        "round-record", "--repo", repo, "--pr", str(number),
                        "--round", str(round_number), "--run-key", run_key,
                        "--head-sha", head_sha, "--bot-login", bot_login])
                mode, role = "fix", "fix"
                chain = _resolvable_chain(fix_aliases, routing)
                holder_namespace, ttl = "fix:", FIX_TTL
            if not chain:
                # The inverse (or same-provider) chain cannot resolve a concrete model right now
                # (e.g. sol/luna not yet in the target routing catalog). Never silent-queue:
                # hand to a human.
                _pr_needs_user(script_dir, repo, number, issue_number,
                               f"the {mode} model chain for a {impl_provider}-implemented PR is "
                               "unresolvable in the target routing (no concrete provider model)")
                continue
        except DispatchError as exc:
            lanes[lane]["error"] += 1
            print(f"defer review {repo}#{number}: revalidation failed ({exc}); skipped")
            continue
        # Issue #115 fail-closed usage hold: the worker loop already HOLDS a require_usage repo when
        # a TOTAL usage-probe failure leaves `usage` unavailable; the review/fix loop must apply the
        # SAME hold before its claim or a probe-gated (anthropic) review/fix silently falls to the
        # allocator's ungated static selection during the outage. The ONLY exception is a chain
        # served entirely by probe-exempt (codex/openai) accounts, for which usage=None is expected.
        if usage is None and require_usage and not _chain_probe_exempt(chain, routing):
            defer_reasons["usage-probe-unavailable"] += 1
            print(f"defer review {repo}#{number}: require_usage set but live usage is unavailable "
                  f"(probe failed) — holding the {mode} claim fail-closed")
            continue
        now = int(time.time())
        # Repository-scoped prefix: package names (including __global__) are target-local.  The
        # old bare `review:` / `fix:` prefix mixed unrelated repos into one package partition and
        # one fixed lane cap, so a sparq lease could suppress registry work while its provider's
        # account slots sat idle.  The holder grammar itself is unchanged, preserving adoption and
        # per-PR duplicate keys; only the allocator's partition scope becomes the documented repo.
        holder_prefix = f"{holder_namespace}{repo}#"
        holder = f"{holder_prefix}{number}@dispatch-" \
                 f"{os.environ.get('GITHUB_RUN_ID', 'local')}." \
                 f"{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}"
        try:
            claim_result = allocator.claim(
                registry_repo,
                item["package"],
                role,
                chain,
                holder,
                now,
                ttl=ttl,
                account_pool=policy["account_pool"],
                holder_prefix=holder_prefix,
                usage=usage,
                margin=margin,
                # Issue #448: recompute the live remaining slots inside every CAS attempt.  N
                # candidates therefore produce min(N, S) leases as earlier successes consume S;
                # S=0 fails closed.  No static per-lane ceiling can strand an idle provider.
                account_slot_bound=True,
                return_reason=True,
            )
        except (RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            defer_reasons["lease-error"] += 1
            lanes[lane]["error"] += 1
            if mode == "fix":
                fix_dispatch["defer:lease-error"] += 1
            print(f"defer review {repo}#{number}: lease allocation errored ({exc}); skipped")
            continue
        # Compatibility with self-test allocators and out-of-tree allocator shims that implement
        # the historical claim-or-None API; the real allocator returns (claim, reason) here.
        if isinstance(claim_result, tuple) and len(claim_result) == 2:
            claim, claim_reason = claim_result
        else:
            claim, claim_reason = claim_result, "no-account-slots"
        if claim is None:
            defer_reasons[f"{lane}:{_claim_defer_category(claim_reason)}"] += 1
            if mode == "fix":
                try:
                    _run_target_helper(script_dir, repo, "worker-pr.py", [
                        "record-marker", "--repo", repo, "--pr", str(number), "--kind", "missed",
                        "--round", str(round_number), "--run-key",
                        f"{os.environ.get('GITHUB_RUN_ID', 'local')}."
                        f"{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}",
                        "--bot-login", bot_login])
                except DispatchError as exc:
                    # Issue #117 fail-closed missed-fix budget: swallowing this write left the
                    # durable `missed` marker unrecorded, so the missed-fix budget could stay at
                    # zero forever — the MISSED_FIX_LIMIT escalation to a human never fired and the
                    # PR was silently stranded. A missed dispatch we cannot durably count is a
                    # COUNTED lane error + rolling-alert defer reason, NOT a healthy defer: surface
                    # it and do not fall through to the normal "no lease free" line, whose green
                    # defer is exactly the signal that hid this.
                    lanes[lane]["error"] += 1
                    defer_reasons["missed-marker-write-failed"] += 1
                    fix_dispatch["defer:missed-marker-write-failed"] += 1
                    print(f"defer review {repo}#{number}: missed-fix marker write FAILED ({exc}); "
                          "missed-fix budget unconfirmed")
                    # Issue #165: the durable `missed` marker is the ONLY input to the
                    # MISSED_FIX_LIMIT terminal budget, so if it can NEVER be written the budget can
                    # never bound this PR and the counted-error/rolling-alert above is only a
                    # PER-TICK signal — a persistent comment/API failure would defer forever without
                    # the promised human escalation. An accounting failure we cannot durably count
                    # is itself a terminal, hand-to-human state, so escalate DIRECTLY instead of
                    # waiting on a budget that can no longer accrue. This is retryable, not
                    # premature: needs-user rides the SAME target API as the failed marker, so a
                    # broad transient outage fails this POST too and we simply defer to the next
                    # tick — the escalation only STICKS on a record-marker-specific failure that
                    # will not self-heal. The item is bounded the moment EITHER the marker or this
                    # escalation is durably confirmed; until then it stays a retryable defer.
                    try:
                        _pr_needs_user(script_dir, repo, number, issue_number,
                                       f"the durable missed-fix marker could not be recorded "
                                       f"({exc}); the MISSED_FIX_LIMIT budget can no longer bound "
                                       "this PR, so a human must unstick it")
                    except DispatchError as esc_exc:
                        defer_reasons["missed-escalation-failed"] += 1
                        print(f"defer review {repo}#{number}: missed-fix human escalation ALSO "
                              f"FAILED ({esc_exc}); retrying until the marker or escalation is "
                              "confirmed")
                    continue
                fix_dispatch[f"defer:{claim_reason or 'no-account-slots'}"] += 1
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
            # Issue #118: never report the lease "released" without confirming it. A CAS
            # conflict (or a garbage claim_id that was itself the violation) can leave the
            # lease ACTIVE — consuming its account/package until expiry — so a failed release
            # is a COUNTED lane error + hard `::error::`, not a green unsafe-claim defer that
            # falsely logs recovery.
            released = _release_failed_dispatch(allocator, registry_repo, str(claim_id or ""))
            if not released:
                lanes[lane]["error"] += 1
                defer_reasons["unsafe-claim-release-failed"] += 1
                if mode == "fix":
                    fix_dispatch["defer:unsafe-claim-release-failed"] += 1
                print(f"::error::review {repo}#{number}: {violation}; lease release FAILED "
                      "(claim still active until expiry)")
                continue
            if mode == "fix":
                fix_dispatch["defer:unsafe-claim"] += 1
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
            # A failed workflow launch is a HARD dispatch error, not capacity contention: fold it
            # into the lane's error tally (issue #108) so an all-launch-failed review/fix lane
            # reads planned>0/launched=0/error>0 (stalled) instead of deriving as `deferred` and
            # dodging the tick-health recorder while another lane launched.
            defer_reasons["dispatch-launch-failed"] += 1
            lanes[lane]["error"] += 1
            if mode == "fix":
                fix_dispatch["defer:dispatch-launch-failed"] += 1
            print(f"defer review {repo}#{number}: {mode} dispatch failed; skipped")
            continue
        launched += 1
        pending_telemetry["launched"] = True
        lanes[lane]["launched"] += 1
        if mode == "fix":
            fix_dispatch["launched"] += 1
        # Privacy (locked decision 22b): public workflow logs never carry account handles.
        kind_note = "" if fix_kind == "verdict" else f"/{fix_kind}"
        print(f"dispatched {mode}{kind_note} {repo}#{number}: round={round_number}, "
              f"claim={claim_id[:8]}")
    finish_pending()
    return launched


def _apply_disarm_items(disarm_items, repo, script_dir, bot_login, disarm_counts=None):
    """GAP-C (registry issue #42): retract stale GitHub auto-merge latches BEFORE any fix/review
    admission each sweep. The plan rows are HOSTILE — worker-pr.py `disarm --when mismatch`
    re-derives every precondition from the LIVE API (open same-repo bot worker PR, armed OR
    ready with an interrupted disarm, head != reviewed-sha marker) and is a no-op otherwise, so a
    spoofed row can never disarm a validly-armed PR. A human hold (review:needs-user / needs:user)
    does NOT block this safety-only retraction (issue #105): --when mismatch retracts the latch
    while preserving the hold label. Failures skip the item (per-item resilience); the
    enumeration re-emits next tick until the invariant holds — including across a crash between
    disable-auto and redraft, which mismatch mode re-enters via the ready-but-unarmed leg.

    `disarm_counts` (issue #108) is the disarm lane's tick accumulator: `launched` when the
    live-revalidated retraction applied (or was a confirmed no-op), `error` when the helper RAISED,
    `deferred` when no App token/bot identity was available to even attempt it. An `error` here is
    safety-critical — a stale auto-merge latch that could not be retracted — so the caller surfaces
    disarm_counts['error'] to the tick-health recorder INDEPENDENTLY of the fleet dispatch count; a
    worker launch must never let a failed disarm read as a healthy tick."""
    if disarm_counts is None:
        disarm_counts = Counter()
    for item in disarm_items:
        number = item["pr_number"]
        disarm_counts["planned"] += 1
        try:
            if not bot_login or not _target_token(repo):
                disarm_counts["deferred"] += 1
                print(f"defer disarm {repo}#{number}: target App token unavailable")
                continue
            _run_target_helper(script_dir, repo, "worker-pr.py", [
                "disarm", "--repo", repo, "--pr", str(number), "--when", "mismatch"])
            disarm_counts["launched"] += 1
            print(f"disarm {repo}#{number}: live armed-SHA invariant re-checked and applied")
        except DispatchError as exc:
            disarm_counts["error"] += 1
            print(f"defer disarm {repo}#{number}: {exc}; retried next tick")
            continue
    return disarm_counts


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
    if item["package"] != plan_package(packages):
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
    require_usage fail-closed hold + usage-alert cover that case).

    NOTE (issue #116): this predicate only says the route is starved RIGHT NOW — a single usage
    snapshot. Whether that momentary starvation is handed to a human is a SEPARATE, bounded
    decision (escalate_persist_decision): transient rate-limit exhaustion is pipeline-owned and
    refills on its own, so one zero-headroom snapshot must NOT become a permanent human terminal."""
    return bool(escalate) and usage is not None and effective_cap == 0


# Issue #116: how long an escalate-tier route must stay CONTINUOUSLY starved before a transient
# capacity snapshot is promoted to a loud persistent-shortage park (the machine-owned
# status:parked — capacity starvation is never the human-question terminal needs:user;
# park_policy.py defect 1). Rate-limit headroom is pipeline-owned and refills within minutes; a
# bounded grace lets auto-retry recover the common case while still guaranteeing a genuinely
# persistent starvation is alerted and parked. Measured against the first alert of the CURRENT
# streak, so it is independent of how often the dispatcher ticks.
ESCALATE_PERSIST_SECONDS = 30 * 60
# Durable, privacy-safe receipt marking an escalate-tier starvation alert. Its presence + timestamp
# ARE the persistence clock (mirroring the worker-attempt receipt idiom); it carries no PII.
STARVE_ALERT_MARKER = "<!-- sparq-escalate-starved:v1 -->"
# Issue #116 (round 1): durable receipt that LIVE capacity RECOVERED (effective_cap > 0) for an
# escalate-tier issue that still carried an open starvation streak. Recovery is a genuine end of
# continuous starvation even when it yields NO worker attempt (the allocator returned no slot, the
# launch failed, or another pre-dispatch hold intervened), so this receipt — not a subsequent
# attempt — is what closes the streak. Carries no PII, same idiom as the alert receipt.
STARVE_RESET_MARKER = "<!-- sparq-escalate-recovered:v1 -->"


def _latest_receipt(comments, bot, marker):
    """Newest `created_at` (ISO-8601 UTC, lexicographically comparable) among comments authored by
    `bot` (casefolded login) that carry `marker`; "" when none. Shared clock helper for the
    starvation-persistence + recovery-reset logic."""
    return max(
        (str(c.get("created_at", "")) for c in comments
         if str(c.get("user", {}).get("login", "")).casefold() == bot
         and marker in str(c.get("body", ""))),
        default="",
    )


def escalate_persist_decision(comments, bot_login, now, attempt_marker,
                              persist_seconds=ESCALATE_PERSIST_SECONDS):
    """Bounded-persistence gate between a TRANSIENT escalate-tier capacity snapshot and a loud
    persistent-shortage park (issue #116). A single usage snapshot showing zero eligible accounts
    is pipeline-owned rate-limit exhaustion that refills on its own; promoting it straight to a
    park strands pipeline-owned work behind a wait for the same capacity. So the FIRST starved
    tick just alerts ops with a durable STARVE_ALERT_MARKER receipt and keeps the issue
    status:deferred (auto-retry); the machine-owned status:parked soft hold (park_policy.py —
    capacity starvation is never the human-question terminal needs:user) is applied ONLY once
    that alert streak has persisted at least `persist_seconds`.

    The streak RESETS on a real dispatch: only starvation receipts posted (by `bot_login`) STRICTLY
    AFTER the most recent worker attempt receipt (`attempt_marker`) count — the exact "after the
    last failure" idiom find_maintainer_approval uses. So capacity that recovered, dispatched, then
    starved again later begins a fresh transient streak instead of inheriting a stale age (which
    would re-create the very bug this fixes: a new momentary snapshot reading as long-persistent).

    Returns (escalate: bool, streak_started_at: str). `streak_started_at` is the oldest in-streak
    receipt ("" when this is the first observation, i.e. no receipt yet). `escalate` is True only
    when that oldest receipt is at least `persist_seconds` old — a bounded persistent failure,
    never one snapshot. ISO-8601 UTC `created_at` values compare lexicographically."""
    bot = bot_login.casefold()
    # The continuous-starvation streak ENDS on any durable end-of-starvation signal, not solely a
    # worker attempt: a live-capacity RECOVERY receipt (STARVE_RESET_MARKER) closes it too (issue
    # #116 round 1). Recovery is a real streak end even when it produced no attempt (allocator
    # returned no slot, the launch failed, or a later pre-dispatch hold intervened), so alerts at or
    # before the NEWER of {last attempt, last reset} are stale and must not age a later snapshot.
    reset_at = max(_latest_receipt(comments, bot, attempt_marker),
                   _latest_receipt(comments, bot, STARVE_RESET_MARKER))
    streak = sorted(
        str(c.get("created_at", "")) for c in comments
        if str(c.get("user", {}).get("login", "")).casefold() == bot
        and STARVE_ALERT_MARKER in str(c.get("body", ""))
        and str(c.get("created_at", "")) > reset_at
    )
    if not streak:
        return False, ""
    threshold_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - persist_seconds))
    return streak[0] <= threshold_iso, streak[0]


def escalate_recovery_pending(comments, bot_login, attempt_marker):
    """True when an escalate-tier issue carries an ACTIVE starvation alert — a STARVE_ALERT_MARKER
    posted strictly after the latest reset/attempt receipt — so an observed live-capacity recovery
    should now persist a STARVE_RESET_MARKER that closes the streak (issue #116 round 1). Returns
    False once a reset (or attempt) already supersedes every alert, which keeps recovery recording to
    ONE receipt per streak — no per-tick comment spam while capacity stays healthy."""
    bot = bot_login.casefold()
    reset_at = max(_latest_receipt(comments, bot, attempt_marker),
                   _latest_receipt(comments, bot, STARVE_RESET_MARKER))
    return any(
        str(c.get("user", {}).get("login", "")).casefold() == bot
        and STARVE_ALERT_MARKER in str(c.get("body", ""))
        and str(c.get("created_at", "")) > reset_at
        for c in comments
    )


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
    model_health = _load_module("registry_model_health", script_dir / "model-health.py")
    usage = _load_usage()
    catalog_cache = {"accounts": None}  # read the account catalog at most once, only if usage-aware
    # The health ledger is immutable from dispatch and read at most once per tick. None is the
    # fail-closed unreadable state; the separate flag distinguishes it from an unread cache.
    health_window = None
    health_window_loaded = False
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
    # Independent per-lane accounting (issue #108): each lane's iterator (the worker loop,
    # _dispatch_review_items, _apply_disarm_items) folds its own planned/launched/error into this
    # shared accumulator as items resolve; deferred is derived at summary time. worker+review+fix
    # planned == the fleet `planned` above; disarm is its OWN lane (it consumes no account/lease, so
    # it was invisible to the fleet count — the exact gap that let a failed safety disarm hide
    # behind a worker launch). A worker launch can no longer mark the whole tick healthy while a
    # safety disarm or an entire review/fix lane failed.
    lanes = _new_lane_counts()
    # Issue #448 fix-lane fan-out telemetry.  This is accumulated across every target repository
    # and rendered once per tick, so the observable ceiling is fleet-wide rather than a sequence
    # of ambiguous per-repo snippets.
    fix_dispatch = Counter()
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
    _write_dispatch_summary(planned, 0, defer_reasons, lanes)
    for repository in plan["repositories"]:
        repo = repository["target_repo"]
        try:
            policy = policy_module._policy_row(repo, policy_doc)
        except ValueError as exc:
            raise DispatchError(f"registry policy is invalid for {repo}") from exc
        # [issue #111] The exact issue-author bot allowlist: the policy-declared `trusted_bots`
        # unioned with the RUNTIME-resolved worker App login. `bot_login` is our own orchestration
        # App (it opens the pipeline's follow-up/groom issues), so an empty policy list still trusts
        # it; every OTHER bot must be listed exactly. No suffix match — a stray "<x>[bot]" is denied.
        trusted_bots = set(policy.get("trusted_bots", []))
        if bot_login:
            trusted_bots.add(bot_login)
        allow_actions_bot_issues = policy["allow_actions_bot_issues"]
        # [issue #119] Read the routing catalog from the protected default-branch tip CLAIM
        # resolves ITSELF, NOT from repository["target_sha"]: that sha is `git rev-parse HEAD` of
        # the checkout that ran the hostile target planner, so trusting it let target-controlled
        # data pick an obsolete/weaker routing revision. target_sha stays an audit-only plan field.
        routing = _protected_routing(repo, policy["routing"])
        pull_pages = _gh_json([
            "api", "--paginate", "--slurp", f"repos/{repo}/pulls?state=open&per_page=100"
        ])
        linked_open_prs = _linked_open_pr_issues(pull_pages, repo)
        # [round-4 P1] PLAN->CLAIM busy-window revalidation: the PLAN partition's freeing
        # decisions are minutes stale by launch time. Re-prove every item's crate against
        # the LIVE pull listing just fetched (zero extra pulls-API cost), the live issue
        # labels, and the local provenance checkouts BEFORE anything launches; an item
        # whose crate re-reads busy (a parked draft went ready, a new worker PR opened)
        # defers to the next tick instead of racing a PR that can now merge into it.
        live_dispatchable = revalidate_items_against_live_pulls(
            repository["items"], repo, pull_pages, _live_issue_labels(repo),
            _claim_provenance_map(repo, registry_root, ledger_root),
            # [round-5 P1] the cross-lane lease partition reads the ledger-branch checkout;
            # an unreadable ledger view yields None and the partition fails toward exclusion.
            leases=_ledger_leases(ledger_root), now=int(time.time()))

        # Safety invariant FIRST (issue #42): stale arm latches are retracted before any fix or
        # review admission can push onto (or re-review past) an armed, mutated head. The disarm lane
        # folds its own launched/error/deferred into `lanes` (issue #108) — an error here alerts
        # regardless of the worker/review/fix outcome below.
        _apply_disarm_items(
            [entry for entry in plan["disarm_items"] if entry["repo"] == repo],
            repo, script_dir, bot_login, lanes["disarm"])

        for item in repository["items"]:
            number = item["number"]
            lanes["worker"]["planned"] += 1
            if number in linked_open_prs:
                defer_reasons["existing-pr"] += 1
                print(f"defer {repo}#{number}: an open worker/closing PR already exists")
                continue
            if number not in live_dispatchable:
                # [round-4 P1] the crate freed at PLAN time re-read BUSY on the live pull
                # state — a worker PR went active (or appeared) in the PLAN->CLAIM window.
                # revalidate_items_against_live_pulls already emitted the single per-item
                # artifact line naming the blocking PR/lease; do not bury it under a second,
                # generic defer line here.
                defer_reasons["live-busy-crate"] += 1
                continue
            # [OPUS-4.8] Per-item resilience: a single item's trust/route/policy resolution failure
            # must SKIP that item, not abort the whole dispatch (which would strand the other ready
            # issues and mark the run failed). Global setup errors above still abort as before.
            try:
                current, reason = _current_issue_matches(
                    repo, item, trusted_bots, allow_actions_bot_issues)
                if not current:
                    defer_reasons["stale-issue"] += 1
                    print(f"defer {repo}#{number}: {reason}")
                    continue
                resolved = _route_matches(repo, item, policy_doc, routing, policy_module)
                if item["deferred"]:
                    # #500 task-side honest-decline escalation. This runs BEFORE the ordinary
                    # deferred-attempt budget and BEFORE allocator.claim(), so the second
                    # no_change cannot be swallowed by generic needs-user budgeting or launch the
                    # cached impl route. The model-health module owns validation/window pruning;
                    # dispatch consumes its ledger READ-ONLY.
                    if not bot_login or not _target_token(repo):
                        defer_reasons["no-target-token"] += 1
                        print(f"defer {repo}#{number}: deferred retry needs the target App token")
                        continue
                    if not health_window_loaded:
                        health_window = _read_model_health_window(
                            model_health, registry_repo, int(time.time()))
                        health_window_loaded = True
                    if health_window is None:
                        defer_reasons["decline-ledger-unreadable"] += 1
                        print(f"::error::defer {repo}#{number}: no_change escalation evidence "
                              "is unavailable; issue remains deferred with NO escalation")
                        continue
                    no_changes = _issue_no_change_outcomes(
                        model_health, health_window, number)
                    comments = None
                    if len(no_changes) >= DECLINE_ESCALATION_MIN:
                        comments = _pr_comments(repo, number)
                        decline_result = _escalate_repeated_declines(
                            repo, item, no_changes, comments, bot_login, script_dir)
                        if decline_result != "proceed":
                            defer_reasons[f"decline-{decline_result}"] += 1
                            print(f"escalated {repo}#{number}: repeated no_change outcomes -> "
                                  f"{decline_result}; cached {item['role']} claim cancelled")
                            continue
                    # Deferred-retry budget (locked decision 20): re-dispatch is bounded by the
                    # SAME durable attempt markers the worker records; exhausted -> the
                    # MACHINE-owned status:parked soft hold + a maintainer-visible comment,
                    # never another silent attempt. Budget exhaustion is budget-driven, not a
                    # human question (park_policy.py defect 1): needs:user here terminally
                    # stripped the issue's open PR from the review loop (2026-07-18 mass park).
                    #
                    # Finding B + round-3 finding 1: the durable count is WINDOWED by the
                    # human-readmission cutoff (park_policy.readmission_cutoff over the
                    # issue's own label timeline, strict maintainer probe), and the bounded
                    # escalation is the LABEL-INDEPENDENT ladder
                    # (park_policy.park_ladder_decision): EVERY consumed budget window — the
                    # initial no-cutoff window included — is receipted
                    # (PARK_GENERATION_MARKER), generations are counted from receipts alone
                    # (a veto-suppressed label re-apply never stalls the ladder), the
                    # receipt-dedupe silences COMMENTS only, an unreadable timeline FREEZES
                    # the ladder, and PARK_ESCALATION_GENERATIONS consumed windows escalate
                    # to the QUESTION-class terminal whose needs:user write is veto-checked
                    # with an HONEST comment when suppressed.
                    comments = comments if comments is not None else _pr_comments(repo, number)
                    used = worker_issue.count_attempts(comments, bot_login)
                    if used >= resolved["max_attempts"]:
                        cutoff = _park_policy.readmission_cutoff(
                            repo, number, None, _issue_timeline_events,
                            is_human=lambda login: _target_is_human_maintainer(repo, login),
                            on_unreadable=_park_policy.WINDOW_UNREADABLE)
                        windowed = used
                        if cutoff and cutoff != _park_policy.WINDOW_UNREADABLE:
                            windowed = worker_issue.count_attempts_since(
                                comments, bot_login, cutoff)
                        if windowed < resolved["max_attempts"]:
                            print(f"readmission window open for {repo}#{number}: a human "
                                  f"unlabeled a park label at {cutoff}; the attempt budget "
                                  f"charges {windowed} of {used} recorded attempt(s) — "
                                  "allocation re-enabled")
                            # fall through: the allocator + the `retry` label flip run again.
                        else:
                            action, window_key, generation = (
                                _park_policy.park_ladder_decision(
                                    cutoff,
                                    worker_pr.park_generation_cutoffs(comments, bot_login),
                                    already_labeled="status:parked" in item["labels"]))
                            if action == "freeze":
                                # Unreadable timeline: the ladder never advances on unproven
                                # data — no window, no receipt, no label, no comment.
                                defer_reasons["budget-exhausted"] += 1
                                print(f"defer {repo}#{number}: deferred-retry budget "
                                      "exhausted and the label timeline is unreadable — "
                                      "ladder frozen (no readmission credit, no generation "
                                      "receipt) until the timeline reads clean")
                                continue
                            if action == "dedupe":
                                # This window is already receipted (its park or terminal was
                                # recorded once, honestly): re-defer QUIETLY until a FRESH
                                # human gesture. Dedupe covers comments/labels only — the
                                # generation progression is already durable in the receipts.
                                defer_reasons["budget-exhausted"] += 1
                                print(f"defer {repo}#{number}: deferred-retry budget "
                                      f"exhausted; window {window_key} already consumed "
                                      "(receipted)")
                                continue
                            if action == "legacy-quiet":
                                # Pre-receipt park: already status:parked, no gesture, no
                                # receipts — stay quiet; the ladder starts counting with the
                                # first receipted window.
                                defer_reasons["budget-exhausted"] += 1
                                print(f"defer {repo}#{number}: deferred-retry budget "
                                      "exhausted; already status:parked (legacy "
                                      "pre-receipt park)")
                                continue
                            if action == "terminal":
                                # Bounded escalation: PARK_ESCALATION_GENERATIONS windows
                                # consumed — repeated post-readmission failure IS a human
                                # question now. The needs:user write is veto-checked at the
                                # write point (worker-issue set_status), and the comment is
                                # HONEST when the veto suppressed it (round-3 finding 1:
                                # never claim a label that did not land).
                                landed = _issue_needs_user_landed(script_dir, repo, number)
                                label_note = (
                                    " Escalated as a human question (`needs:user`)."
                                    if landed else
                                    " The escalation is TERMINAL, but the `needs:user` "
                                    "label write was SUPPRESSED by a standing human "
                                    "unlabel (sticky veto) — no label was applied; this "
                                    "receipt alone records it.")
                                _run_gh_target_comment(
                                    repo, number,
                                    f"> 🤖 SPARQ agent — deferred-retry budget exhausted "
                                    f"AGAIN after a human readmission ({windowed}/"
                                    f"{resolved['max_attempts']} attempts since {cutoff}; "
                                    f"generation {generation}). Repeated post-readmission "
                                    f"failure needs a decision.{label_note} "
                                    f"@{os.environ.get('MAINTAINER_HANDLE', 'jeswr')}: this "
                                    "item keeps failing its attempt budget after each "
                                    "readmission — a decision is needed, not another retry."
                                    f"\n\n{worker_pr.PARK_GENERATION_MARKER} "
                                    f"gen={generation} cutoff={window_key} -->")
                                defer_reasons["budget-exhausted-escalated"] += 1
                                print(f"escalated {repo}#{number}: deferred-retry budget "
                                      f"exhausted post-readmission (generation "
                                      f"{generation}) -> question-class terminal"
                                      f"{'' if landed else ' (label suppressed)'}")
                                continue
                            # action == "park": consume this window — soft park (veto-gated
                            # label, best-effort) + the MANDATORY receipt. The receipt
                            # comment lands exactly once per window even when the sticky
                            # veto suppressed the label — it IS the durable ladder and what
                            # keeps every later tick quiet.
                            parked = _park_source_issue(script_dir, repo, number)
                            label_note = (
                                "Parked with the machine-owned `status:parked` soft hold: "
                                "the whole PR surface holds (no review/fix dispatch, no "
                                "new implementation attempt) until a human readmission. "
                                if parked else
                                "The `status:parked` label write was SUPPRESSED by a "
                                "standing human unlabel (sticky veto); this receipt "
                                "records the consumed budget window without a label. ")
                            _run_gh_target_comment(
                                repo, number,
                                f"> 🤖 SPARQ agent — deferred-retry budget exhausted "
                                f"({windowed}/{resolved['max_attempts']} attempts"
                                f"{f' since the readmission at {cutoff}' if cutoff else ''}"
                                f"). {label_note}"
                                f"@{os.environ.get('MAINTAINER_HANDLE', 'jeswr')}: the "
                                "attempt budget is spent — approve a retry or decide "
                                f"the route.\n\n{worker_pr.PARK_GENERATION_MARKER} "
                                f"gen={generation} cutoff={window_key} -->")
                            defer_reasons["budget-exhausted"] += 1
                            print(f"escalated {repo}#{number}: deferred-retry budget "
                                  f"exhausted (generation {generation}"
                                  f"{'' if parked else ', label suppressed'})")
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
                    # Issue #116: a SINGLE zero-headroom usage snapshot is TRANSIENT, pipeline-owned
                    # rate-limit exhaustion — not a semantic routing failure. Promoting it straight
                    # to a park strands pipeline-owned work behind a wait for the same capacity to
                    # refill. So keep the issue status:deferred (auto-retry), alert ops with a
                    # durable receipt, and park it (machine-owned status:parked — park_policy.py)
                    # ONLY once the starvation has PERSISTED past the bounded grace
                    # (escalate_persist_decision). Security surfaces still never degrade to a
                    # weaker model — the route stays deferred (undispatched) throughout; the grace
                    # only defers the persistent-shortage park.
                    try:
                        comments = _pr_comments(repo, number)
                        escalate_now, since = escalate_persist_decision(
                            comments, bot_login, now, worker_issue.ATTEMPT_MARKER)
                        if escalate_now:
                            # Persistent capacity starvation is CAPACITY-driven, never a human
                            # question (park_policy.py defect 1): the machine-owned
                            # status:parked soft hold replaces the old needs:user terminal. The
                            # issue stays in the deferred lane, so the park lifts automatically
                            # the moment capacity recovers (the retry flip strips it) — an
                            # already-parked, still-starved issue just re-defers quietly.
                            if "status:parked" in item["labels"]:
                                defer_reasons["escalate-tier-starved"] += 1
                                print(f"defer {repo}#{number}: escalate-tier starved since "
                                      f"{since}; already status:parked — auto-readmits when "
                                      "capacity recovers")
                            elif _park_source_issue(script_dir, repo, number):
                                _run_gh_target_comment(
                                    repo, number,
                                    "> 🤖 SPARQ agent — this task routes to the restricted "
                                    f"`{'/'.join(resolved['model_chain'])}` tier (a security/"
                                    "soundness surface, `escalate = true` in routing.toml), and "
                                    "NO account has had usage headroom to run that tier since "
                                    f"{since} — past the auto-retry grace, so this is a "
                                    "persistent shortage, not a blip. Parked with the "
                                    "machine-owned `status:parked` soft hold; it clears "
                                    "automatically when capacity recovers (the route never "
                                    "degrades to a weaker model). "
                                    f"@{os.environ.get('MAINTAINER_HANDLE', 'jeswr')} (ops): "
                                    "persistent escalate-tier capacity shortage.")
                                defer_reasons["escalate-tier-starved"] += 1
                                print(f"escalated {repo}#{number}: escalate-tier starved since "
                                      f"{since} (persistent past the auto-retry grace)")
                            else:
                                defer_reasons["escalate-tier-starved"] += 1
                                print(f"defer {repo}#{number}: escalate-tier starved since "
                                      f"{since}; park suppressed by a sticky human unpark")
                        else:
                            # Keep it recoverable: status:deferred re-enters the deferred-retry path
                            # every tick, so the moment capacity refills the same item dispatches
                            # normally. Alert ops ONCE per streak (the first receipt is also the
                            # persistence clock start) — later transient ticks stay quiet, no spam.
                            _run_target_helper(script_dir, repo, "worker-issue.py", [
                                "status", "--repo", repo, "--issue", str(number),
                                "--status", "deferred"])
                            if not since:
                                _run_gh_target_comment(
                                    repo, number,
                                    "> 🤖 SPARQ agent — this task routes to the restricted "
                                    f"`{'/'.join(resolved['model_chain'])}` tier, and no account "
                                    "currently has usage headroom to run it. This is transient, "
                                    "pipeline-owned rate-limit exhaustion, so the issue stays "
                                    "`status:deferred` and auto-retries as capacity recovers — no "
                                    "human action is needed unless it persists. "
                                    f"@{os.environ.get('MAINTAINER_HANDLE', 'jeswr')} (ops): "
                                    f"escalate-tier capacity is exhausted.{STARVE_ALERT_MARKER}")
                            defer_reasons["escalate-tier-starved-transient"] += 1
                            print(f"defer {repo}#{number}: escalate-tier starved (transient "
                                  "capacity); status:deferred, auto-retrying until it recovers")
                    except DispatchError as exc:
                        defer_reasons["escalate-tier-starved"] += 1
                        print(f"defer {repo}#{number}: escalate-tier starved, escalation "
                              f"failed ({exc}); retried next tick")
                    continue
                elif resolved.get("escalate"):
                    # Issue #116 (round 1): effective_cap > 0 here — LIVE capacity RECOVERED for
                    # this escalate-tier route. If a prior starvation streak is still open, persist a
                    # durable recovery receipt so a LATER shortage starts a FRESH transient streak
                    # instead of inheriting this (now-ended) streak's age. Recovery MUST be recorded
                    # even though it produced no worker attempt — the claim below may still find no
                    # slot or the launch may fail; the receipt, not a subsequent attempt, is what
                    # ends "continuous starvation". Best-effort: a failed post retries next tick, and
                    # escalate_recovery_pending caps this at one receipt per streak (no spam). Then
                    # fall through to normal dispatch (no `continue`).
                    try:
                        recovery_comments = _pr_comments(repo, number)
                        if escalate_recovery_pending(
                                recovery_comments, bot_login, worker_issue.ATTEMPT_MARKER):
                            _run_gh_target_comment(
                                repo, number,
                                "> 🤖 SPARQ agent — escalate-tier capacity has RECOVERED: an "
                                "account now has usage headroom for the restricted "
                                f"`{'/'.join(resolved['model_chain'])}` tier. Closing the prior "
                                "starvation streak — normal dispatch resumes and any later shortage "
                                f"starts a fresh grace window.{STARVE_RESET_MARKER}")
                            print(f"recovery {repo}#{number}: escalate-tier capacity recovered; "
                                  "starvation streak reset")
                    except DispatchError as exc:
                        print(f"note {repo}#{number}: escalate-tier recovery receipt failed "
                              f"({exc}); retried next tick")
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
                lanes["worker"]["error"] += 1
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
                # Issue #118: confirm the release before logging it. A failed release leaves
                # the lease active until expiry, so it is a COUNTED worker-lane error + hard
                # `::error::` rather than a green "released + skipped" that falsely claims
                # recovery and hides the leaked account/package.
                released = _release_failed_dispatch(allocator, registry_repo, str(claim_id or ""))
                if not released:
                    lanes["worker"]["error"] += 1
                    defer_reasons["unsafe-claim-release-failed"] += 1
                    print(f"::error::worker {repo}#{number}: allocator returned an unsafe/"
                          "out-of-policy claim; lease release FAILED (claim still active "
                          "until expiry)")
                    continue
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
                # Same hard-error classification as the review/fix lanes: a failed launch must
                # not derive as `deferred` in the lane summary.
                lanes["worker"]["error"] += 1
                print(f"defer {repo}#{number}: worker dispatch failed; skipped")
                continue
            dispatched += 1
            lanes["worker"]["launched"] += 1
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
                defer_reasons, lanes=lanes, ledger_root=ledger_root,
                fix_dispatch=fix_dispatch)
    print(f"dispatcher complete: {dispatched} worker/review/fix run(s) launched")
    print(_fix_dispatch_line(fix_dispatch))
    # Per-lane tick summary (issue #108) — coarse counts only (no issue numbers/handles). A stalled
    # review/fix lane or a failed safety disarm is visible here even when the worker lane launched.
    for name in DISPATCH_LANES:
        counts = lanes[name]
        print(f"lane {name}: planned={counts.get('planned', 0)} "
              f"launched={counts.get('launched', 0)} error={counts.get('error', 0)}")

    # Final summary (registry #28/#32): overwrite the early claim-start write with the real
    # launched count + defer-reason histogram + per-lane counts.
    _write_dispatch_summary(planned, dispatched, defer_reasons, lanes)

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


def _lane_summary(lanes):
    """Serialize the per-lane accumulator (issue #108) into the summary's `lanes` field: for every
    lane {planned, launched, deferred, error}, with deferred DERIVED (planned-launched-error,
    clamped at 0) so escalations and capacity holds — neither launches nor hard errors — are counted
    without instrumenting every defer path. Coarse counts only (no issue numbers/handles)."""
    summary = {}
    for name in DISPATCH_LANES:
        counts = (lanes or {}).get(name) or {}
        planned = int(counts.get("planned", 0) or 0)
        launched = int(counts.get("launched", 0) or 0)
        error = int(counts.get("error", 0) or 0)
        summary[name] = {"planned": planned, "launched": launched,
                         "deferred": max(0, planned - launched - error), "error": error}
    return summary


def _write_dispatch_summary(planned, dispatched, defer_reasons, lanes=None):
    """Zero-dispatch visibility (registry #28/#32): emit a compact, privacy-safe summary
    ({planned, dispatched, frontier_size, ledger, defer_reasons histogram, lanes}) for the CLAIM
    step to render + record. `frontier_size` is the ready-frontier size the tick observed (==
    planned) and `ledger` is ok|error — together they let the run summary distinguish an empty
    frontier from a lease-ledger failure (issue #28), which both otherwise present as a green
    0-dispatch tick. `lanes` (issue #108) carries the worker/review/fix/disarm decomposition so the
    tick-health recorder can surface a stalled lane — or a failed safety disarm — regardless of
    activity in the other lanes. NO issue numbers or account handles — only coarse category counts.
    Best-effort file write; a failure here must never fail dispatch. Called at claim START (planned
    only — review defect #6) and again at the end with the launched counts."""
    summary_path = os.environ.get("DISPATCH_SUMMARY_FILE")
    if not summary_path:
        return
    try:
        with open(summary_path, "w", encoding="utf-8") as handle:
            json.dump({"planned": planned, "dispatched": dispatched,
                       "frontier_size": planned, "ledger": _ledger_health(defer_reasons),
                       "defer_reasons": dict(defer_reasons),
                       "lanes": _lane_summary(lanes)}, handle)
    except OSError as exc:
        print(f"::warning::dispatch summary write failed ({exc}); continuing")


def _review_fix_workflow_values():
    """Extract the trust-critical timeout / local-claim-TTL literals straight from
    .github/workflows/review-fix.yml so the self-test can pin the DISPATCHER TTL derivation to
    the WORKFLOW it must outlive (issue #159), not just to sibling constants in this module. A
    raised job timeout or an edited local `ttl=` that is not mirrored back into `_WF_*` /
    REVIEW_TTL / FIX_TTL flips the asserts below red instead of silently re-expiring a still-live
    lease. Text-parsed (no PyYAML dependency in the self-test path) but JOB-SCOPED, so a timeout
    in a non-critical-path job is never mistaken for a critical-path one. A missing/unparsable
    workflow raises AssertionError — fail closed, never a skipped check."""
    path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "review-fix.yml"
    assert path.is_file(), f"review-fix.yml not found for TTL sync check: {path}"
    text = path.read_text(encoding="utf-8")
    marker = "\njobs:\n"
    assert marker in text, "review-fix.yml has no top-level jobs: block"
    jobs_at = text.index(marker)
    # Top-level job headers sit at exactly two-space indent under `jobs:` with nothing after the
    # colon; every nested key inside a job is indented four or more spaces, so this never matches
    # a step-level `run:`/`timeout-minutes:` or an `on:`/`concurrency:` key above `jobs:`.
    heads = [m for m in re.finditer(r"(?m)^  ([a-z_]+):$", text) if m.start() > jobs_at]
    assert heads, "review-fix.yml exposed no job headers"
    spans = {}
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        spans[m.group(1)] = text[m.start():end]

    def _fixed_minutes(job):
        span = spans.get(job)
        assert span is not None, f"review-fix.yml is missing the {job} job"
        m = re.search(r"(?m)^    timeout-minutes: (\d+)$", span)
        assert m, f"{job} job has no plain integer timeout-minutes"
        return int(m.group(1))

    run_span = spans.get("run")
    assert run_span is not None, "review-fix.yml is missing the run job"
    run_m = re.search(
        r"timeout-minutes:\s*\$\{\{[^}]*?'review'\s*&&\s*(\d+)\s*\|\|\s*(\d+)", run_span)
    assert run_m, "run job timeout expression (review && N || M) not found"
    claim_span = spans.get("claim")
    assert claim_span is not None, "review-fix.yml is missing the claim job"
    ttl_review = re.search(r'prefix="review:";[^\n]*\bttl=(\d+)', claim_span)
    ttl_fix = re.search(r'prefix="fix:";[^\n]*\bttl=(\d+)', claim_span)
    assert ttl_review and ttl_fix, "claim job local review/fix ttl= literals not found"
    return {
        "resolve_s": _fixed_minutes("resolve") * 60,
        "claim_s": _fixed_minutes("claim") * 60,
        "release_s": _fixed_minutes("release") * 60,
        "run_review_s": int(run_m.group(1)) * 60,
        "run_fix_s": int(run_m.group(2)) * 60,
        "local_review_ttl": int(ttl_review.group(1)),
        "local_fix_ttl": int(ttl_fix.group(1)),
    }


def _self_test():
    # _run_gh_target_api MUST return the CompletedProcess on success — callers read .stdout
    # (decline reroute re-read, #505). A missing `return result` made it fall off to None and
    # crash the CLAIM job with AttributeError on every escalation tick (run 29982184587).
    import subprocess as _subprocess
    _saved_run = _subprocess.run
    try:
        _subprocess.run = lambda *_a, **_k: types.SimpleNamespace(returncode=0, stdout="{}", stderr="")
        _saved_token = globals().get("_target_token")
        globals()["_target_token"] = lambda _repo: "tok"
        _probe = _run_gh_target_api("example/repo", "GET", "repos/example/repo/issues/1")
        assert _probe is not None and _probe.stdout == "{}", (
            "_run_gh_target_api must return the CompletedProcess on success")
    finally:
        _subprocess.run = _saved_run
        if _saved_token is not None:
            globals()["_target_token"] = _saved_token

    # STRUCTURAL ENFORCEMENT (maintainer directive 2026-07-18): terra + sonnet are DOCS-ONLY
    # models — they must never appear in any review/fix chain (review-fix.yml asserts the same
    # over its own chain tables, worker-pr.py over ESCALATION_LADDERS).
    docs_only = {"terra", "sonnet"}
    for name, table in (("REVIEW_CHAIN", REVIEW_CHAIN), ("FIX_CHAIN", FIX_CHAIN)):
        offenders = docs_only & {alias for chain in table.values() for alias in chain}
        assert not offenders, f"docs-only model in {name}: {sorted(offenders)}"

    # Lease TTL must outlive the owning review-fix.yml workflow (issue #159): a lease that expires
    # mid-run lets the allocator reclaim a live account, racing two sessions on one credential /
    # write-back. Every mode's TTL must EXCEED its run-job timeout alone (the pre-#159 1200/3600 did
    # not) and cover the whole claim -> run -> release DAG path plus queue slack. These re-derive if
    # review-fix.yml raises a job bound; the asserts flip red if a TTL is ever cut below the bound.
    for _mode, _run_to in _WF_RUN_TIMEOUT.items():
        _ttl = _lease_ttl(_mode)
        assert _ttl > _run_to, f"{_mode} lease TTL {_ttl} <= run timeout {_run_to} (issue #159)"
        assert _ttl >= (_WF_RESOLVE_TIMEOUT + _WF_CLAIM_TIMEOUT + _run_to
                        + _WF_RELEASE_TIMEOUT + _WF_QUEUE_SLACK), f"{_mode} TTL under DAG bound"
    assert REVIEW_TTL == _lease_ttl("review") == 4200, REVIEW_TTL
    assert FIX_TTL == _lease_ttl("fix") == 6300, FIX_TTL
    # Fail-closed: an unknown mode never gets a shorter hold than the longest known mode.
    assert _lease_ttl("bogus") >= max(_lease_ttl("review"), _lease_ttl("fix"))
    # The asserts above only tie the derivation to THIS module's `_WF_*` mirror; on their own
    # they stay green if review-fix.yml raises a job timeout or edits its local claim TTL without
    # updating the mirror — the exact silent drift that re-expires a live lease (issue #159 round
    # 1 finding). Pin the mirror to the WORKFLOW itself: parse review-fix.yml and require every
    # critical-path job timeout AND both local claim-TTL literals to agree with what the
    # dispatcher derives / claims. Any workflow-only change now flips these red.
    _wf = _review_fix_workflow_values()
    assert _wf["resolve_s"] == _WF_RESOLVE_TIMEOUT, _wf["resolve_s"]
    assert _wf["claim_s"] == _WF_CLAIM_TIMEOUT, _wf["claim_s"]
    assert _wf["release_s"] == _WF_RELEASE_TIMEOUT, _wf["release_s"]
    assert _wf["run_review_s"] == _WF_RUN_TIMEOUT["review"], _wf["run_review_s"]
    assert _wf["run_fix_s"] == _WF_RUN_TIMEOUT["fix"], _wf["run_fix_s"]
    # The workflow's own adopt-path claim TTLs (dispatch.yml comment: kept in sync with these)
    # must equal the dispatcher bound, or a DISPATCHER-claimed lease and a workflow self-claim
    # would hold the same account for different windows.
    assert _wf["local_review_ttl"] == REVIEW_TTL, _wf["local_review_ttl"]
    assert _wf["local_fix_ttl"] == FIX_TTL, _wf["local_fix_ttl"]

    # #500 round-2: execute the REAL dispatch() call site for every decline-escalation tripwire.
    # The round-1 helper-only checks could stay green if dispatch stopped calling the helper; this
    # harness drives a deferred PLAN row through validated model-health ledger reads and captures
    # the same target API/helper mutations production uses. Each successful assertion prints an
    # explicit line, making --self-test output prove that all five tripwires actually executed.
    model_health = _load_module(
        "registry_model_health_decline_tripwire",
        Path(__file__).resolve().parent / "model-health.py")
    decline_now = int(time.time())
    no_change_a = model_health.make_record(
        "openai", "a" * 16, "codex", "no_change", "5001.1", decline_now - 20,
        issue=500, input_tokens=10, output_tokens=2, wall_seconds=5)
    no_change_b = model_health.make_record(
        "openai", "b" * 16, "codex", "no_change", "5002.1", decline_now - 10,
        issue=500, input_tokens=12, output_tokens=3, wall_seconds=6)

    def run_decline_tripwire(records, role="impl", comments=(), malformed=False,
                             unreadable=False):
        """One complete deferred dispatch tick with fake GitHub transports and real validators."""
        labels = sorted([
            "area:dispatch", "priority:P1", f"role:{role}", "status:deferred",
        ])
        body = "Investigate and implement the dispatch boundary."
        item = {
            "number": 500, "priority": 1, "package": "dispatch", "role": role,
            "model_chain": ["sol"], "agent": "registry-impl", "escalate": False,
            "labels": labels, "author": "maintainer",
            "body_sha": hashlib.sha256(body.encode()).hexdigest(), "deferred": True,
        }
        live_issue = {
            "number": 500, "state": "open", "user": {"login": "maintainer"},
            "author_association": "MEMBER", "labels": [{"name": label} for label in labels],
            "body": body,
        }
        plan = {
            "schema": SCHEMA, "generated_at": "2026-07-21T00:00:00Z",
            "repositories": [{"target_repo": "example/repo", "target_sha": "a" * 40,
                              "items": [item]}],
            "review_items": [], "disarm_items": [], "snapshot_skips": [],
        }
        policy = {
            "trusted_bots": [], "allow_actions_bot_issues": False,
            "routing": "orchestration/routing.toml", "usage_safety_margin": 0.10,
        }

        class FakePolicy:
            @staticmethod
            def _policy_row(repo, document):
                assert repo == "example/repo" and document["repos"][repo]["enabled"] is True
                return policy

            @staticmethod
            def resolve(repo, issue_labels, policy_doc, routing_doc):
                assert repo == "example/repo" and issue_labels == labels
                return {
                    "model_chain": item["model_chain"], "agent": item["agent"],
                    "escalate": item["escalate"], "max_attempts": 9,
                    "worker_timeout_minutes": 10, "usage_safety_margin": 0.10,
                    "require_usage": False, "max_concurrent": 1, "account_pool": [],
                }

        class FakeAllocator:
            def __init__(self):
                self.claim_calls = 0

            def claim(self, *_args, **_kwargs):
                self.claim_calls += 1
                return None

            @staticmethod
            def release(*_args, **_kwargs):
                return True

        class FakeWorkerIssue:
            ATTEMPT_MARKER = "<!-- sparq-worker-attempt:v1 -->"

            @staticmethod
            def count_attempts(_comments, _bot_login):
                return 0

        class FakeWorkerPr:
            pass

        class FakeHealthAPI:
            def request(self, method, path, body=None, allow_404=False,
                        retry_conflict=False):
                assert method == "GET" and path == model_health.ledger_read_path(
                    "example/registry")
                if unreadable:
                    raise model_health.HealthError("fixture transport failed")
                document = ({"records": [{"not": "a typed model-health record"}]}
                            if malformed else {"records": list(records)})
                return {
                    "content": base64.b64encode(json.dumps(document).encode()).decode(),
                    "sha": "deadbeef",
                }

        allocator = FakeAllocator()
        api_calls = []
        helper_calls = []
        comment_reads = []

        class FakeResult:
            def __init__(self, stdout=""):
                self.stdout = stdout
                self.returncode = 0
                self.stderr = ""

        def fake_gh_json(args):
            path = args[-1]
            if path == "repos/example/repo":
                return {"default_branch": "main"}
            if path == "repos/example/repo/branches/main":
                return {"protected": True, "commit": {"sha": "b" * 40}}
            if path.startswith("repos/example/repo/contents/orchestration/routing.toml?ref="):
                return {"type": "file", "content": base64.b64encode(b"").decode()}
            if path == "repos/example/repo/pulls?state=open&per_page=100":
                return [[]]
            if path == "repos/example/repo/issues?state=open&per_page=100":
                return [[live_issue]]
            if path == "repos/example/repo/issues/500":
                return live_issue
            if path == "repos/example/repo/issues/500/comments?per_page=100":
                comment_reads.append(path)
                return [list(comments)]
            raise AssertionError(f"unexpected fake gh read: {path}")

        def fake_target_api(repo, method, path, input_doc=None):
            assert repo == "example/repo"
            api_calls.append((method, path, input_doc))
            return FakeResult(json.dumps(live_issue) if method == "GET" else "")

        def fake_target_helper(script_dir, repo, script, args):
            helper_calls.append((script, list(args)))
            return FakeResult()

        def fake_load(name, path):
            return {
                "registry_policy_resolve": FakePolicy,
                "registry_select_and_claim": allocator,
                "registry_worker_pr": FakeWorkerPr,
                "registry_worker_issue": FakeWorkerIssue,
                "registry_model_health": model_health,
            }[name]

        real_globals = (
            globals()["_load_module"], globals()["_gh_json"],
            globals()["_run_gh_target_api"], globals()["_run_target_helper"],
            globals()["_run_gh"], model_health.GitHubAPI,
        )
        env_keys = ("TARGET_GH_TOKENS", "TARGET_GH_TOKEN", "TARGET_GH_TOKEN_OWNER",
                    "WORKER_USAGE_FILE", "DISPATCH_SUMMARY_FILE")
        prior_env = {key: os.environ.get(key) for key in env_keys}
        output = io.StringIO()
        try:
            globals()["_load_module"] = fake_load
            globals()["_gh_json"] = fake_gh_json
            globals()["_run_gh_target_api"] = fake_target_api
            globals()["_run_target_helper"] = fake_target_helper
            globals()["_run_gh"] = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("decline tripwire unexpectedly launched a workflow"))
            model_health.GitHubAPI = lambda _token: FakeHealthAPI()
            os.environ["TARGET_GH_TOKENS"] = json.dumps({"example": "test-token"})
            os.environ.pop("TARGET_GH_TOKEN", None)
            os.environ.pop("TARGET_GH_TOKEN_OWNER", None)
            os.environ.pop("WORKER_USAGE_FILE", None)
            with tempfile.TemporaryDirectory() as root:
                root_path = Path(root)
                plan_path = root_path / "plan.json"
                policy_path = root_path / "repos.toml"
                leases_path = root_path / "data" / "leases.json"
                leases_path.parent.mkdir(parents=True)
                plan_path.write_text(json.dumps(plan), encoding="utf-8")
                policy_path.write_text(
                    '[repos."example/repo"]\nenabled = true\n', encoding="utf-8")
                leases_path.write_text('{"leases": []}\n', encoding="utf-8")
                os.environ["DISPATCH_SUMMARY_FILE"] = str(root_path / "summary.json")
                with contextlib.redirect_stdout(output):
                    dispatch(
                        plan_path, policy_path, "example/registry", "master", Path("."),
                        registry_root=root, bot_login="sparq[bot]", ledger_root=root)
        finally:
            (globals()["_load_module"], globals()["_gh_json"],
             globals()["_run_gh_target_api"], globals()["_run_target_helper"],
             globals()["_run_gh"], model_health.GitHubAPI) = real_globals
            for key, value in prior_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        return {
            "api_calls": api_calls, "helper_calls": helper_calls,
            "claim_calls": allocator.claim_calls, "comment_reads": comment_reads,
            "output": output.getvalue(),
        }

    # (a) The real dispatch call observes the SECOND validated no_change, posts the marker, swaps
    # role:impl -> role:research, and cancels the cached impl claim before allocation.
    trip_a = run_decline_tripwire([no_change_a, no_change_b])
    assert [call[0] for call in trip_a["api_calls"]] == ["POST", "GET", "PATCH"], trip_a
    assert DECLINE_ESCALATION_MARKER in trip_a["api_calls"][0][2]["body"], trip_a
    assert trip_a["api_calls"][-1][2]["labels"] == [
        "area:dispatch", "priority:P1", "role:research", "status:deferred"], trip_a
    assert trip_a["helper_calls"] == [] and trip_a["claim_calls"] == 0, trip_a
    print("  ok   decline tripwire (a): second no_change reroutes impl to research + marker")

    # (b) One validated record is below threshold: no mutation/comment and the ordinary deferred
    # claim path remains live. Lowering the threshold to one makes this assertion red.
    trip_b = run_decline_tripwire([no_change_a])
    assert trip_b["api_calls"] == [] and trip_b["helper_calls"] == [], trip_b
    assert trip_b["claim_calls"] == 1, trip_b
    print("  ok   decline tripwire (b): one no_change performs no escalation")

    # (c) A repeated decline already on role:research parks and must never PATCH another
    # research reroute. Removing the loop guard turns this red. Park-policy defect 1: the park
    # is the MACHINE-owned status:parked capacity/decline soft hold — a capacity/decline park
    # must NEVER write the human-question terminal needs:user.
    trip_c = run_decline_tripwire([no_change_a, no_change_b], role="research")
    assert [call[0] for call in trip_c["api_calls"]] == ["POST"], trip_c
    assert len(trip_c["helper_calls"]) == 1, trip_c
    assert trip_c["helper_calls"][0][0] == "worker-issue.py", trip_c
    assert trip_c["helper_calls"][0][1][-2:] == ["--status", "parked"], trip_c
    assert "needs-user" not in trip_c["helper_calls"][0][1], trip_c
    assert trip_c["claim_calls"] == 0, trip_c
    print("  ok   decline tripwire (c): research decline parks status:parked without reroute loop")

    # (d) Poisoned and unreadable ledgers both fail closed: no target action, no cached claim, and
    # an Actions error annotation that explicitly says escalation did not fire.
    for bad in (run_decline_tripwire([], malformed=True),
                run_decline_tripwire([], unreadable=True)):
        assert bad["api_calls"] == [] and bad["helper_calls"] == [], bad
        assert bad["claim_calls"] == 0, bad
        assert "::error::dispatch decline escalation" in bad["output"], bad["output"]
        assert "NO task escalation will fire" in bad["output"], bad["output"]
    print("  ok   decline tripwire (d): malformed/unreadable ledger logs loudly and does not escalate")

    # (e) Only the bot's durable marker suppresses duplicate writes. The same marker text from a
    # third party is ignored, so the research-route escalation still comments and parks.
    _, marker_key = _decline_escalation_evidence([no_change_a, no_change_b])
    marker_body = (f"<!-- {DECLINE_ESCALATION_MARKER} key={marker_key} "
                   "action=research -->")
    bot_marked = run_decline_tripwire(
        [no_change_a, no_change_b], role="research",
        comments=[{"user": {"login": "sparq[bot]"}, "body": marker_body}])
    assert bot_marked["api_calls"] == [] and bot_marked["helper_calls"] == [], bot_marked
    assert bot_marked["claim_calls"] == 1, bot_marked
    forged = run_decline_tripwire(
        [no_change_a, no_change_b], role="research",
        comments=[{"user": {"login": "mallory"}, "body": marker_body}])
    assert [call[0] for call in forged["api_calls"]] == ["POST"], forged
    assert len(forged["helper_calls"]) == 1 and forged["claim_calls"] == 0, forged
    print("  ok   decline tripwire (e): bot marker is idempotent; third-party forgery is ignored")

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
                "model_chain": ["fable", "sol"],
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
                "model_chain": ["fable", "sol"],
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
    # issue #112: the multi-area conflict partition. plan_package reduces a collection of
    # area:* sections to the SINGLE partition a plan/lease row reserves — exactly one area is
    # that area, zero or multiple collapse to the serializing global partition (every assert
    # flips if it regresses to the old alphabetically-first `sorted(areas)[0]`).
    assert plan_package(["usage"]) == "usage"
    assert plan_package([]) == GLOBAL_PACKAGE
    assert plan_package(["worker", "usage"]) == GLOBAL_PACKAGE
    assert plan_package(["usage", "usage"]) == "usage"   # duplicate collapses to one area
    # BEHAVIORAL proof the fix closes the defect: a busy SECONDARY area must exclude a
    # multi-area row. area-b holds a live sibling lease; the global-reserving A+B row is
    # dropped while a disjoint single-area (area-a) row still co-runs. Under the old
    # areas[0]="area-a" reduction the A+B row would carry package "area-a", survive the area-b
    # lease, and double-dispatch onto B — the exact bug.
    p112_repo = "example/repo"
    b_lease = [{"holder": f"{p112_repo}#99@run.1", "package": "area-b", "expires_at": 600}]
    multi_row = {"number": 5, "package": plan_package(["area-a", "area-b"]), "deferred": False}
    solo_row = {"number": 6, "package": plan_package(["area-a"]), "deferred": False}
    assert filter_busy_area_items([multi_row], p112_repo, [], {}, {}, leases=b_lease, now=0) == []
    assert filter_busy_area_items(
        [solo_row], p112_repo, [], {}, {}, leases=b_lease, now=0) == [solo_row]
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
        # Issue #108: a worker launch must NOT mask a failed safety disarm or a stalled review/fix
        # lane. Feed a tick where the worker lane launched but disarm ERRORED and the review lane
        # planned work yet launched nothing (all errored) — the summary must carry those per-lane
        # counts distinctly so the tick-health recorder can alert regardless of the worker launch.
        masking_lanes = _new_lane_counts()
        masking_lanes["worker"].update({"planned": 1, "launched": 1})
        masking_lanes["review"].update({"planned": 2, "error": 2})
        masking_lanes["fix"].update({"planned": 1, "launched": 1})
        masking_lanes["disarm"].update({"planned": 1, "error": 1})
        try:
            _write_dispatch_summary(5, 0, folded)
            with open(summary_file, encoding="utf-8") as handle:
                planned_only = json.load(handle)
            _write_dispatch_summary(4, 2, Counter(), masking_lanes)
            with open(summary_file, encoding="utf-8") as handle:
                masked = json.load(handle)
        finally:
            if prior_summary is None:
                del os.environ["DISPATCH_SUMMARY_FILE"]
            else:
                os.environ["DISPATCH_SUMMARY_FILE"] = prior_summary
    assert planned_only["defer_reasons"]["snapshot-skip:check-runs-overflow"] == 1
    # Issue #28: the summary carries the ready-frontier size and lease-ledger health so a
    # 0-dispatch tick can be told apart from a ledger failure. A snapshot-skip-only tick has a
    # HEALTHY ledger (no lease-error), so ledger == "ok".
    assert planned_only["frontier_size"] == 5, planned_only
    assert planned_only["ledger"] == "ok", planned_only
    # The lanes field is always present; an unpopulated call reports all-zero lanes (never absent,
    # so the workflow's .get never has to guess a default).
    assert planned_only["lanes"]["disarm"] == {
        "planned": 0, "launched": 0, "deferred": 0, "error": 0}, planned_only
    # Issue #108 core assertion: even though the fleet DISPATCHED 2 (worker+fix launched), the
    # disarm lane's error and the review lane's stall are preserved verbatim — the exact signals the
    # tick-health recorder keys on to alert past a productive worker launch. Every field below flips
    # if the per-lane accounting is dropped back to a single conflated launched count.
    assert masked["lanes"]["disarm"]["error"] == 1, masked
    assert masked["lanes"]["review"] == {
        "planned": 2, "launched": 0, "deferred": 0, "error": 2}, masked
    assert masked["lanes"]["worker"]["launched"] == 1 and masked["dispatched"] == 2, masked
    # deferred is DERIVED (planned-launched-error, clamped): a lane with a capacity hold (no error)
    # counts as deferred, a fully-errored lane has deferred 0, and over-count never goes negative.
    assert _lane_summary({"review": Counter({"planned": 3, "launched": 1})})["review"] == {
        "planned": 3, "launched": 1, "deferred": 2, "error": 0}
    assert _lane_summary({"fix": Counter({"planned": 1, "launched": 2})})["fix"]["deferred"] == 0
    # Every REVIEW_STATE maps to exactly one lane and the split is EXHAUSTIVE (a new state would
    # KeyError the assertion below rather than silently land in the fix lane): needs-review + the
    # stranded escalation are the review lane; the three fix-run states are the fix lane.
    assert {state: _review_item_lane(state) for state in REVIEW_STATES} == {
        "needs-review": "review", "stranded": "review",
        "needs-fix": "fix", "needs-ci-fix": "fix", "needs-rebase": "fix"}
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
    # issue #111: EXACT allowlist trust, no "[bot]" suffix match. Every assertion flips red if the
    # suffix shortcut is reintroduced or a trust leg is dropped.
    allow = {"reg-app[bot]"}
    assert _issue_is_trusted({"user": {"login": "maintainer"}, "author_association": "MEMBER"}, allow)
    assert _issue_is_trusted({"user": {"login": "owner"}, "author_association": "OWNER"}, set())
    assert _issue_is_trusted({"user": {"login": "reg-app[bot]"}, "author_association": "NONE"}, allow)
    # an arbitrary bot login is DENIED even though it ends in "[bot]" (the closed defect) ...
    assert not _issue_is_trusted({"user": {"login": "evil[bot]"}, "author_association": "NONE"}, allow)
    # ... and with an empty allowlist NO bot is trusted by suffix
    assert not _issue_is_trusted({"user": {"login": "worker[bot]"}, "author_association": "NONE"}, set())
    # a non-collaborator human is never trusted; malformed shapes fail closed
    assert not _issue_is_trusted({"user": {"login": "external"}, "author_association": "CONTRIBUTOR"}, allow)
    assert not _issue_is_trusted({"user": None, "author_association": "MEMBER"}, allow)
    # a truthy non-dict `user` must DENY, never raise (an AttributeError would escape the CLAIM
    # loop's DispatchError-only handler and abort the whole dispatch)
    assert not _issue_is_trusted({"user": "malformed", "author_association": "MEMBER"}, allow)
    assert not _issue_is_trusted({"user": ["x"], "author_association": "OWNER"}, allow)
    assert not _issue_is_trusted("nope", allow)

    # ---- issue #119: CLAIM reads the trusted routing revision from the PROTECTED default-branch
    # tip it resolves ITSELF, never from the plan's `target_sha` (the hostile target planner's
    # `git rev-parse HEAD`). Drive _protected_routing through a fake GitHub reader and prove it
    # (a) resolves the tip via the repo's own default branch, (b) reads routing AT that tip, and
    # (c) never lets an attacker-shaped target_sha reach any fetch — every leg fails closed. ----
    saved_gh_119 = _gh_json
    try:
        attacker_sha = "a" * 40           # what a hostile planner could park HEAD on
        protected_tip = "9" * 40          # the real default-branch tip CLAIM must trust instead
        routing_b64 = base64.b64encode(
            b"[models.fable]\nprovider_model = \"x\"\n").decode()
        seen_refs = []

        def _fake_ok(args):
            path = args[-1]
            if path == "repos/example/repo":
                return {"default_branch": "main"}
            if path == "repos/example/repo/branches/main":
                return {"name": "main", "commit": {"sha": protected_tip}, "protected": True}
            if path.startswith("repos/example/repo/contents/"):
                seen_refs.append(path)
                return {"type": "file", "content": routing_b64}
            raise AssertionError(f"unexpected gh path {path}")

        globals()["_gh_json"] = _fake_ok
        routing119 = _protected_routing("example/repo", "policy/routing.toml")
        assert routing119 == {"models": {"fable": {"provider_model": "x"}}}, routing119
        # routing was read at the INDEPENDENTLY-resolved protected tip — not the plan sha
        assert seen_refs == [
            f"repos/example/repo/contents/policy/routing.toml?ref={protected_tip}"], seen_refs
        assert all(attacker_sha not in ref for ref in seen_refs), seen_refs
        # fail-closed: a tip that is not a 40-hex sha (the exact class the old format-only check
        # would have waved through) must DEFER, never route
        globals()["_gh_json"] = lambda args: (
            {"default_branch": "main"} if args[-1] == "repos/example/repo"
            else {"commit": {"sha": "z" * 40}, "protected": True})
        try:
            _protected_default_tip("example/repo")
            raise AssertionError("non-hex protected tip must fail closed")
        except DispatchError:
            pass
        # fail-closed: a missing/unreadable default branch must DEFER
        globals()["_gh_json"] = lambda args: (
            {} if args[-1] == "repos/example/repo" else {"commit": {"sha": protected_tip}})
        try:
            _protected_default_tip("example/repo")
            raise AssertionError("missing default branch must fail closed")
        except DispatchError:
            pass
        # fail-closed: an UNPROTECTED default branch is not the branch-protected control surface
        # the routing catalog's trust rests on, so its tip must be rejected even though it is a
        # valid 40-hex sha. This assertion goes red if the `protected is True` check is removed.
        globals()["_gh_json"] = lambda args: (
            {"default_branch": "main"} if args[-1] == "repos/example/repo"
            else {"commit": {"sha": protected_tip}, "protected": False})
        try:
            _protected_default_tip("example/repo")
            raise AssertionError("unprotected default branch must fail closed")
        except DispatchError:
            pass
        # fail-closed: a MISSING/non-bool protection field is not proof of protection either —
        # absence must never be read as protected. Also red if the protection check is removed.
        globals()["_gh_json"] = lambda args: (
            {"default_branch": "main"} if args[-1] == "repos/example/repo"
            else {"commit": {"sha": protected_tip}})
        try:
            _protected_default_tip("example/repo")
            raise AssertionError("missing protection field must fail closed")
        except DispatchError:
            pass
    finally:
        globals()["_gh_json"] = saved_gh_119

    # ---- issue #102: CLAIM independently RE-PROVES the readiness predicate (non-dispatchable
    # epic + live blocker state) from registry-owned code, never trusting the hostile planner's
    # frontier. Every assertion flips red if either leg is removed from _current_issue_matches. ----
    prev_gh_json = _gh_json

    def ready_issue(labels, body):
        return {"state": "open", "user": {"login": "maintainer"},
                "author_association": "MEMBER",
                "labels": [{"name": name} for name in labels], "body": body}

    def match_with(main_issue, blockers, item, trusted_bots=frozenset(),
                   allow_actions_bot_issues=False):
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
            return _current_issue_matches(
                "example/repo", item, trusted_bots, allow_actions_bot_issues)
        finally:
            globals()["_gh_json"] = prev_gh_json

    ready_labels = sorted(["area:crate-a", "priority:P1", "role:impl", "status:ready"])
    plain_body = "do the work"
    item102 = {"number": 700, "labels": ready_labels, "author": "maintainer",
               "body_sha": hashlib.sha256(plain_body.encode()).hexdigest(), "deferred": False}
    # baseline: a ready, non-epic, unblocked issue passes every leg
    passed, _ = match_with(ready_issue(ready_labels, plain_body), {}, item102)
    assert passed, "ready unblocked non-epic issue must claim"
    # issue #111: the author-trust allowlist is THREADED through _current_issue_matches. An
    # otherwise-ready issue authored by a "[bot]" login claims ONLY when that exact login is in the
    # allowlist — an empty allowlist fails it closed (no suffix trust reaches the CLAIM gate).
    bot_body = "bot-authored work"
    bot_issue = {"state": "open", "user": {"login": "reg-app[bot]"}, "author_association": "NONE",
                 "labels": [{"name": name} for name in ready_labels], "body": bot_body}
    bot_item = dict(item102, author="reg-app[bot]",
                    body_sha=hashlib.sha256(bot_body.encode()).hexdigest())
    ok_bot, _ = match_with(bot_issue, {}, bot_item, {"reg-app[bot]"})
    assert ok_bot, "allowlisted bot author must claim"
    denied_bot, denied_reason = match_with(bot_issue, {}, bot_item, frozenset())
    assert not denied_bot and "authored" in denied_reason, denied_reason
    # Issue #487: an own-workflow issue is admitted ONLY behind this repository's explicit flag.
    # These go red if the flag leg is removed, defaults permissive, or the exception is widened to
    # unrelated bots/authors. `github-actions[bot]` is intentionally NOT in trusted_bots here, so
    # the test exercises the new policy leg rather than the older exact allowlist.
    actions_body = "drift scanner finding"
    actions_issue = {
        "state": "open", "user": {"login": "github-actions[bot]"},
        "author_association": "NONE",
        "labels": [{"name": name} for name in ready_labels], "body": actions_body,
    }
    actions_item = dict(item102, author="github-actions[bot]",
                        body_sha=hashlib.sha256(actions_body.encode()).hexdigest())
    actions_ok, _ = match_with(
        actions_issue, {}, actions_item, allow_actions_bot_issues=True)
    assert actions_ok, "actions-bot issue must claim when its repository opts in"
    actions_off, actions_off_reason = match_with(
        actions_issue, {}, actions_item, allow_actions_bot_issues=False)
    assert not actions_off and "authored" in actions_off_reason, actions_off_reason
    actions_default, actions_default_reason = match_with(actions_issue, {}, actions_item)
    assert not actions_default and "authored" in actions_default_reason, actions_default_reason
    outsider_body = "untrusted automation"
    outsider_issue = {
        "state": "open", "user": {"login": "third-party[bot]"},
        "author_association": "NONE",
        "labels": [{"name": name} for name in ready_labels], "body": outsider_body,
    }
    outsider_item = dict(item102, author="third-party[bot]",
                         body_sha=hashlib.sha256(outsider_body.encode()).hexdigest())
    outsider_ok, outsider_reason = match_with(
        outsider_issue, {}, outsider_item, allow_actions_bot_issues=True)
    assert not outsider_ok and "authored" in outsider_reason, outsider_reason
    # a malformed nested `user` shape DENIES the item on the author leg — it must never surface as
    # an AttributeError, which the per-item DispatchError handler would not catch (whole-run abort)
    mal_issue = {"state": "open", "user": "malformed", "author_association": "MEMBER",
                 "labels": [{"name": name} for name in ready_labels], "body": plain_body}
    mal_ok, mal_reason = match_with(mal_issue, {}, item102)
    assert not mal_ok and "author" in mal_reason, mal_reason
    # kind:epic is independently rejected even though the plan emitted it (and its labels match)
    epic_labels = sorted(ready_labels + [NON_DISPATCHABLE])
    epic_item = dict(item102, labels=epic_labels)
    epic_ok, epic_reason = match_with(ready_issue(epic_labels, plain_body), {}, epic_item)
    assert not epic_ok and "epic" in epic_reason, epic_reason
    # Park-policy readmission semantics: status:parked GATES the ordinary ready lane (no NEW
    # implementation dispatch on a parked issue) ...
    parked_ready_labels = sorted(ready_labels + ["status:parked"])
    parked_ready_ok, parked_ready_reason = match_with(
        ready_issue(parked_ready_labels, plain_body), {},
        dict(item102, labels=parked_ready_labels))
    assert not parked_ready_ok and "busy or gated" in parked_ready_reason, parked_ready_reason
    # ... while the DEFERRED-retry lane deliberately ADMITS a parked+deferred issue: that lane
    # is the machine park's readmission hook (the retry flip strips status:parked exactly when
    # the allocator proves capacity exists). Removing status:parked from the DEFERRED_GATED
    # carve-out turns this red.
    parked_deferred_labels = sorted(
        ["area:crate-a", "priority:P1", "role:impl", "status:deferred", "status:parked"])
    parked_deferred_ok, parked_deferred_reason = match_with(
        ready_issue(parked_deferred_labels, plain_body), {},
        dict(item102, labels=parked_deferred_labels, deferred=True))
    assert parked_deferred_ok, parked_deferred_reason
    # ... and every OTHER busy/gated label still gates the deferred lane (locked decision 20).
    blocked_deferred_labels = sorted(parked_deferred_labels + ["status:blocked"])
    blocked_deferred_ok, blocked_deferred_reason = match_with(
        ready_issue(blocked_deferred_labels, plain_body), {},
        dict(item102, labels=blocked_deferred_labels, deferred=True))
    assert not blocked_deferred_ok and "busy or gated" in blocked_deferred_reason, \
        blocked_deferred_reason
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
    # stays busy in status:in-progress-review while the PR cycles). Linking is draft-agnostic, so
    # this is structural; asserted here against regression.
    linked_repo = "example/repo"
    linked = _linked_open_pr_issues([[
        # (1) same-repo App worker branch: pipeline-owned provenance, ref AND body admissible
        # even though its author association is NONE (the App's own dedup must not need it).
        {"head": {"ref": "sparq-agent/issue-7-1-1", "repo": {"full_name": linked_repo}},
         "author_association": "NONE", "body": "Fixes #8", "draft": True},
        # (2) trusted collaborator PR (from a fork): body closing keyword admissible after the
        # explicit author-association check; its non-worker branch text contributes nothing.
        {"head": {"ref": "topic", "repo": {"full_name": "collab/fork"}},
         "author_association": "MEMBER", "body": "Fixes #9"},
    ]], linked_repo)
    assert linked == {7, 8, 9}, linked
    # issue #110: a FORK contributor's `Fixes #N` (and a worker-SHAPED head ref on the fork) must
    # NOT suppress any issue — deleting the head-repo/author gates flips each of these red.
    assert _linked_open_pr_issues([[
        {"head": {"ref": "topic", "repo": {"full_name": "mallory/fork"}},
         "author_association": "CONTRIBUTOR", "body": "Fixes #9 closes #10"},
    ]], linked_repo) == set()
    assert _linked_open_pr_issues([[
        {"head": {"ref": "sparq-agent/issue-7-1-1", "repo": {"full_name": "mallory/fork"}},
         "author_association": "NONE", "body": ""},
    ]], linked_repo) == set()
    # a same-repo branch that is NOT worker-shaped, from an untrusted author, links nothing
    assert _linked_open_pr_issues([[
        {"head": {"ref": "issue-7-oops", "repo": {"full_name": linked_repo}},
         "author_association": "NONE", "body": "fixes #7"},
    ]], linked_repo) == set()
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
             "impl_alias": "sol", "impl_account_h": "cd" * 8, "issue": 9,
             "recorded_at_run": "2.1"},
    }
    issue_labels = {7: ["area:crate-a", "role:impl"], 9: ["area:sparq-zk", "role:impl"]}

    # ---- issue #460 SNAPSHOT -> WORKFLOW ROW -> ENUMERATOR end-to-end regression ----
    # Start at plan-snapshot.py's raw document shape (a complete wrapper around the verbatim
    # pulls-list REST row), then execute the ACTUAL field-selection block embedded in
    # dispatch.yml. This is deliberately not a hand-built enumerate_review_items row: changing
    # or dropping a production projection field makes this test fail at the same boundary as
    # PLAN. PR #442 supplies the concrete live shape and its ledger provenance field set.
    snapshot_repo = "jeswr/agent-account-registry"
    snapshot_sha = "3" * 40
    snapshot_doc = {"complete": True, "items": [{
        "number": 442,
        "state": "open",
        "draft": False,
        "body": "Fixes #144",
        "labels": [{"id": 1, "name": "review:changes"}],
        "head": {
            "ref": "sparq-agent/issue-144-29694084610-1",
            "sha": snapshot_sha,
            "repo": {"full_name": snapshot_repo},
        },
        "user": {"login": "sparq-orchestrator[bot]", "type": "Bot"},
    }]}
    workflow_source = (Path(__file__).resolve().parents[1] / ".github" / "workflows"
                       / "dispatch.yml").read_text(encoding="utf-8")
    projection_start = workflow_source.index("              pr_snapshot = []\n")
    projection_end = workflow_source.index(
        '              Path(out_dir, f"pulls-{index}.json")', projection_start)
    projection_namespace = {"pulls": snapshot_doc["items"]}
    exec(textwrap.dedent(workflow_source[projection_start:projection_end]),
         projection_namespace)  # noqa: S102 — repository-owned workflow source
    snapshot_rows = projection_namespace["pr_snapshot"]
    snapshot_provenance = {442: {
        "pr_number": 442,
        "head_sha_at_open": "6eb5c28aa2e9441ecd19fb8aa460bc70e2912e80",
        "impl_provider": "anthropic",
        "impl_alias": "opus",
        "impl_account_h": "9e13ea21abf27e68",
        "issue": 144,
        "recorded_at_run": "29694084610.1",
    }}
    snapshot_items = enumerate_review_items(
        snapshot_repo, snapshot_rows, snapshot_provenance, [],
        {144: ["area:dispatch", "role:impl", "status:in-progress-review"]}, now)
    assert [(item["pr_number"], item["state"], item["package"])
            for item in snapshot_items] == [(442, "needs-fix", "dispatch")], snapshot_items

    # Every snapshot-visible SIGNALLED PR (review:changes OR review:needs) excluded before emit
    # names its exact reason, and the optional exclusions Counter aggregates it. Missing
    # provenance is representative of an early trust-gate rejection; the valid twin above must
    # remain quiet. Restoring the pre-#456 `if draft:` wrapper makes the READY twin produce zero,
    # which is the mutation check run explicitly by issue #460's gate command.
    excluded_log = io.StringIO()
    excluded_counts = Counter()
    with contextlib.redirect_stdout(excluded_log):
        assert enumerate_review_items(
            snapshot_repo, snapshot_rows, {}, [],
            {144: ["area:dispatch", "role:impl"]}, now, exclusions=excluded_counts) == []
    assert excluded_log.getvalue().strip() == (
        "review-enumeration: exclude jeswr/agent-account-registry#442: "
        "provenance record is not a JSON object"), excluded_log.getvalue()
    # Park-policy defect 3 (aggregate correctness): the Counter carries the same reason with
    # the same count as the per-item line, so PLAN's one-line summary can never read zero while
    # a labeled worker PR was excluded.
    assert excluded_counts == Counter({"provenance record is not a JSON object": 1}), \
        excluded_counts

    # Defect 3 core regression: a review:NEEDS-labeled PR (the state the old review:changes-only
    # telemetry silently dropped) excluded for a human hold prints its reason AND aggregates —
    # "0 review item(s)" can never again coexist with labeled worker PRs and zero logged
    # exclusions.
    needs_row = {**snapshot_rows[0], "labels": ["review:needs", "needs:user"]}
    needs_log = io.StringIO()
    needs_counts = Counter()
    with contextlib.redirect_stdout(needs_log):
        assert enumerate_review_items(
            snapshot_repo, [needs_row], snapshot_provenance, [],
            {144: ["area:dispatch", "role:impl"]}, now, exclusions=needs_counts) == []
    assert needs_log.getvalue().strip() == (
        "review-enumeration: exclude jeswr/agent-account-registry#442: "
        "PR carries a human-owned hold label"), needs_log.getvalue()
    assert needs_counts == Counter({"PR carries a human-owned hold label": 1}), needs_counts

    # ONE park predicate (round-3 finding 2): a PR is capacity-parked iff EITHER machine
    # label is live. status:parked on the SOURCE issue alone excludes the PR — the old
    # AND-predicate let a half-cleared pair re-enter enumeration and (with the PR-side label
    # gone) dispatch with NO proof at all.
    machine_park_reason = ("machine capacity park stands (review:parked on the PR or "
                           "status:parked on the source issue)")
    source_park_counts = Counter()
    source_park_log = io.StringIO()
    with contextlib.redirect_stdout(source_park_log):
        assert enumerate_review_items(
            snapshot_repo, snapshot_rows, snapshot_provenance, [],
            {144: ["area:dispatch", "role:impl", "status:parked", "status:deferred"]}, now,
            exclusions=source_park_counts) == []
    assert source_park_counts == Counter({machine_park_reason: 1}), source_park_counts
    assert "machine capacity park stands" in source_park_log.getvalue()

    # ... review:parked on the PR alone excludes the same way (whatever the source says) ...
    parked_pr_row = {**snapshot_rows[0], "labels": ["review:parked"]}
    machine_park_log = io.StringIO()
    machine_park_counts = Counter()
    with contextlib.redirect_stdout(machine_park_log):
        assert enumerate_review_items(
            snapshot_repo, [parked_pr_row], snapshot_provenance, [],
            {144: ["area:dispatch", "role:impl", "status:parked", "status:deferred"]}, now,
            exclusions=machine_park_counts) == []
    assert machine_park_counts == Counter({machine_park_reason: 1}), machine_park_counts
    assert "machine capacity park stands" in machine_park_log.getvalue()
    half_cleared_counts = Counter()
    with contextlib.redirect_stdout(io.StringIO()):
        assert enumerate_review_items(
            snapshot_repo, [parked_pr_row], snapshot_provenance, [],
            {144: ["area:dispatch", "role:impl", "status:deferred"]}, now,
            exclusions=half_cleared_counts) == []
    assert half_cleared_counts == Counter({machine_park_reason: 1}), half_cleared_counts

    # ... and a PR with BOTH machine labels cleared re-enumerates: CLAIM then re-proves the
    # human gesture from the durable receipts + label timelines before any dispatch.
    readmitted = enumerate_review_items(
        snapshot_repo, snapshot_rows, snapshot_provenance, [],
        {144: ["area:dispatch", "role:impl", "status:deferred"]}, now)
    assert [(item["pr_number"], item["state"]) for item in readmitted] == \
        [(442, "needs-fix")], readmitted
    # A live per-PR review lease still single-flights a label-free re-entry — WITH telemetry
    # (finding D: this exit used to be silent for labeled PRs).
    label_free_row = {**snapshot_rows[0], "labels": ["review:needs"]}
    lease_log = io.StringIO()
    lease_counts = Counter()
    with contextlib.redirect_stdout(lease_log):
        assert enumerate_review_items(
            snapshot_repo, [label_free_row], snapshot_provenance,
            [{"holder": f"review:{snapshot_repo}#442@run.1", "expires_at": now + 100}],
            {144: ["area:dispatch", "role:impl"]}, now, exclusions=lease_counts) == []
    assert lease_counts == Counter(
        {"a live per-PR review lease already owns this PR": 1}), lease_counts

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

    # reviewed-sha binding still suppresses the UNLABELLED legacy fallback (no advance).
    marked = pull(41, "sparq-agent/issue-7-1-1", sha_a,
                  body=f"x <!-- sparq-reviewed-sha:{sha_a} -->")
    assert enumerate_review_items(repo, [marked], provenance, [], issue_labels, now) == []

    # Issue #450 re-entry: review:needs on a READY PR is authoritative even when an old
    # reviewed-sha marker matches. An external adjudication deliberately chose re-review; the
    # drafted equivalent stays suppressed so red CI may enter needs-ci-fix.
    marked_needs = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["review:needs"],
                        body=f"x <!-- sparq-reviewed-sha:{sha_a} -->", draft=False)
    assert [item["state"] for item in enumerate_review_items(
        repo, [marked_needs], provenance, [], issue_labels, now)] == ["needs-review"]

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
    # Issue #450 mutation guard: a READY (non-draft) worker PR with valid provenance and an
    # explicit changes label re-enters as a fix item. Restoring the old `if draft:` wrapper makes
    # this disappear and flips the assertion red. Human/non-bot PRs remain outside the surface.
    ready_changes = pull(41, "sparq-agent/issue-7-1-1", sha_a, draft=False,
                         labels=["review:changes"])
    assert [item["state"] for item in enumerate_review_items(
        repo, [ready_changes], provenance, [], issue_labels, now)] == ["needs-fix"]
    assert enumerate_review_items(
        repo, [pull(41, "sparq-agent/issue-7-1-1", sha_a, draft=False,
                    login="human", labels=["review:changes"])],
        provenance, [], issue_labels, now) == []

    # ---- [round-5 P1] CROSS-LANE SUPERSESSION (park -> sibling-launch -> UNPARK): while a
    # PR sat human-parked its crate was freed and a SIBLING claimed a lease there (an impl
    # lease — a prefix the review lane's partition never checks). The moment the human
    # unparks, the enumerator must keep the PR EXCLUDED until the sibling lease resolves. ----
    unparked = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["review:needs"])
    sibling_impl = {"holder": f"{repo}#12@dispatch-9.1", "package": "crate-a",
                    "expires_at": now + 600}
    assert enumerate_review_items(repo, [unparked], provenance, [sibling_impl],
                                  issue_labels, now) == []
    # a sibling REVIEW/FIX-lane lease on the same crate supersedes the same way
    assert enumerate_review_items(
        repo, [unparked], provenance,
        [{"holder": f"fix:{repo}#88@run.1", "package": "crate-a", "expires_at": now + 600}],
        issue_labels, now) == []
    # sibling resolves (released/expired) -> the unparked PR re-enters
    assert [item["pr_number"] for item in enumerate_review_items(
        repo, [unparked], provenance, [dict(sibling_impl, expires_at=now - 1)],
        issue_labels, now)] == [41]
    # the PR's OWN source-issue impl lease never supersedes it (same work item, not a sibling)
    assert [item["pr_number"] for item in enumerate_review_items(
        repo, [unparked], provenance,
        [{"holder": f"{repo}#7@dispatch-9.1", "package": "crate-a", "expires_at": now + 600}],
        issue_labels, now)] == [41]
    # a live sibling lease in a DISJOINT crate does not exclude
    assert [item["pr_number"] for item in enumerate_review_items(
        repo, [unparked], provenance,
        [{"holder": f"{repo}#12@dispatch-9.1", "package": "crate-z",
          "expires_at": now + 600}],
        issue_labels, now)] == [41]
    # a GLOBAL sibling lease serializes against every crate
    assert enumerate_review_items(
        repo, [unparked], provenance,
        [{"holder": f"{repo}#12@dispatch-9.1", "package": GLOBAL_PACKAGE,
          "expires_at": now + 600}],
        issue_labels, now) == []
    # [round-6 P1] a live lease held in ANOTHER target repository never supersedes this
    # repo's PR — same-named crate AND __global__ are per-repository partitions
    assert [item["pr_number"] for item in enumerate_review_items(
        repo, [unparked], provenance,
        [{"holder": "other-org/other-target#12@d.1", "package": "crate-a",
          "expires_at": now + 600},
         {"holder": "fix:other-org/other-target#9@r.1", "package": GLOBAL_PACKAGE,
          "expires_at": now + 600}],
        issue_labels, now)] == [41]
    # ambiguity fails toward exclusion: malformed row / holder / package / expiry
    for bad_lease in ("junk",
                      {"holder": None, "package": "crate-a", "expires_at": now + 600},
                      {"holder": f"{repo}#12@d.1", "package": None, "expires_at": now + 600},
                      {"holder": f"{repo}#12@d.1", "package": "crate-a",
                       "expires_at": "soon"}):
        assert enumerate_review_items(repo, [unparked], provenance, [bad_lease],
                                      issue_labels, now) == [], bad_lease
    # sibling_lease_conflict unit facets: a non-list ledger is ambiguity; empty packages
    # collapse to the serializing global partition; a bool expiry is unparseable
    assert sibling_lease_conflict(repo, set(), {"crate-a"}, None, now) is True
    assert sibling_lease_conflict(repo, set(), set(), [sibling_impl], now) is True
    assert sibling_lease_conflict(
        repo, set(), {"crate-z"},
        [{"holder": "x#1@r.1", "package": "crate-a", "expires_at": True}], now) is True
    assert sibling_lease_conflict(repo, {f"{repo}#12"}, {"crate-a"},
                                  [sibling_impl], now) is False
    assert sibling_lease_conflict(repo, set(), {"crate-a"}, [], now) is False

    # ---- [round-6 P1] REPOSITORY SCOPE: the ledger is fleet-wide but package/__global__
    # partitions are PER-REPO — a live lease in ANOTHER target must never block this
    # target (unscoped, the sibling check itself recreates cross-repo frontier collapse).
    # Mixed-repository battery, BOTH directions + __global__ scoped per-repo. ----
    other_repo = "other-org/other-target"

    def foreign(package, lane=""):
        return {"holder": f"{lane}{other_repo}#12@d.1", "package": package,
                "expires_at": now + 600}

    # direction 1: a foreign-target lease (same-named crate) never conflicts here...
    assert sibling_lease_conflict(repo, set(), {"crate-a"}, [foreign("crate-a")], now) is False
    assert sibling_lease_conflict(
        repo, set(), {"crate-a"}, [foreign("crate-a", "review:")], now) is False
    assert sibling_lease_conflict(
        repo, set(), {"crate-a"}, [foreign("crate-a", "fix:")], now) is False
    # ... even a foreign __global__ lease: global serializes WITHIN its repo only
    assert sibling_lease_conflict(
        repo, set(), {"crate-a"}, [foreign(GLOBAL_PACKAGE)], now) is False
    assert sibling_lease_conflict(
        repo, set(), {GLOBAL_PACKAGE}, [foreign("crate-a")], now) is False
    # direction 2 (the mirror): this repo's lease never blocks the OTHER target either
    assert sibling_lease_conflict(other_repo, set(), {"crate-a"}, [sibling_impl], now) is False
    assert sibling_lease_conflict(
        other_repo, set(), {GLOBAL_PACKAGE},
        [{"holder": f"review:{repo}#41@run.1", "package": GLOBAL_PACKAGE,
          "expires_at": now + 600}], now) is False
    # same-repo conflicts are UNCHANGED by the scoping (regression guard on the round-5 fix)
    assert sibling_lease_conflict(repo, set(), {"crate-a"}, [sibling_impl], now) is True
    assert sibling_lease_conflict(other_repo, set(), {"crate-a"},
                                  [foreign("crate-a")], now) is True
    # an UNPARSEABLE holder cannot be proven foreign — ambiguity still excludes (fail
    # closed): no slash in the repo part, no #number suffix, or an unscoped candidate
    assert sibling_lease_conflict(
        repo, set(), {"crate-a"},
        [{"holder": "no-slash#1@r.1", "package": "crate-a", "expires_at": now + 600}],
        now) is True
    assert sibling_lease_conflict(
        repo, set(), {"crate-a"},
        [{"holder": "owner/name@r.1", "package": "crate-a", "expires_at": now + 600}],
        now) is True
    assert sibling_lease_conflict(
        repo, set(), {"crate-a"},
        [{"holder": "owner/name#notanumber@r.1", "package": "crate-a",
          "expires_at": now + 600}], now) is True
    assert sibling_lease_conflict("", set(), {"crate-a"}, [], now) is True
    # _lease_holder_repo grammar facets (the ONE holder->repo parse the scope rests on)
    assert _lease_holder_repo(f"{repo}#12") == repo
    assert _lease_holder_repo(f"review:{repo}#41") == repo
    assert _lease_holder_repo(f"fix:{repo}#41") == repo
    assert _lease_holder_repo("no-slash#1") == ""
    assert _lease_holder_repo("owner/name") == ""
    assert _lease_holder_repo("owner/name#1x") == ""

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
    # [issue #160] ONLY literal `success` is green. A COMPLETED gate whose conclusion is a
    # broken/incomplete run (cancelled, never-started, stale, needs-a-human) is NOT green — it
    # takes the same ci-fix rerun/escalation path as a hard failure. Pre-fix EVERY one of these
    # fell through to gate="success", suppressing repair on a PR that required checks won't merge.
    for broken in ("cancelled", "action_required", "startup_failure", "stale",
                   "neutral", "skipped"):
        assert interpret_check_runs([{"name": "gate", "status": "completed",
                                      "conclusion": broken}])["gate"] == "failure", broken
    # ... but an UNRECOGNISED conclusion on a "completed" run (None / hostile garbage) is NOT a
    # known non-pass: it degrades to unknown (never ACT on a poisoned snapshot), not to failure
    # (no spurious repair) and never to success (pre-fix bug: both collapsed to green).
    for junk in (None, "wat", 42, [], {"x": 1}):
        assert interpret_check_runs([{"name": "gate", "status": "completed",
                                      "conclusion": junk}])["gate"] == "unknown", junk
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
    # [round-5 P2] the arm bit is STRICT tri-state: a malformed auto_merge shape (a garbage
    # string, a list, a bool) is UNKNOWN (None), never "unarmed" — unknown never frees a
    # crate and never proves the stranded posture (the old isinstance read failed OPEN).
    assert pr_ci_status({**record, "auto_merge": "garbage"})["armed"] is None
    assert pr_ci_status({**record, "auto_merge": []})["armed"] is None
    assert pr_ci_status({**record, "auto_merge": True})["armed"] is None
    # [round-6 P2] ABSENCE != NULL: a record with NO auto_merge field at all (a projected /
    # degraded / pre-round-6 detail shape) is UNKNOWN (None), never "unarmed" — the old
    # record.get() read collapsed absence to the explicit-null unarmed and freed a parked
    # crate whose latch state was never observed (fail OPEN).
    assert pr_ci_status(
        {key: value for key, value in record.items() if key != "auto_merge"}
    )["armed"] is None
    assert pr_ci_status({**record, "head_sha": "zz"}) == {}
    assert pr_ci_status("junk") == {}
    # [round-4 P1] the detail draft bit is STRICT-bool tri-state: absent (the pre-round-4
    # record shape) and garbage both degrade to None — unknown never frees a crate.
    assert pr_ci_status(record)["draft"] is None
    assert pr_ci_status({**record, "draft": True})["draft"] is True
    assert pr_ci_status({**record, "draft": False})["draft"] is False
    assert pr_ci_status({**record, "draft": "yes"})["draft"] is None
    assert pr_ci_status({**record, "draft": 1})["draft"] is None
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
    # ... but never SILENTLY (finding D): the drafted already-reviewed fall-through names its
    # residue for signalled PRs and feeds the aggregate Counter — "0 review item(s)" can never
    # again coexist with a labeled, bound-head worker PR and zero logged exclusions.
    fallthrough_log = io.StringIO()
    fallthrough_counts = Counter()
    with contextlib.redirect_stdout(fallthrough_log):
        assert enumerate_review_items(
            repo, [starved], provenance, [], issue_labels, now,
            pr_status={41: status_of(sha_a, gate="pending")},
            exclusions=fallthrough_counts) == []
    assert fallthrough_counts == Counter(
        {"head already reviewed; no live repair trigger (gate not concluded-red, "
         "posture not stranded)": 1}), fallthrough_counts
    assert "no live repair trigger" in fallthrough_log.getvalue()

    # Finding E: a malformed timeline PAGE containing (or hiding) the newest human unlabel must
    # RAISE — park_policy then keeps the FULL budget count (its documented fail direction)
    # instead of silently minting or missing a readmission window on a truncated view.
    newest_unlabel_page = [{"event": "unlabeled", "label": {"name": "needs:user"},
                            "created_at": "2026-07-23T09:18:19Z",
                            "actor": {"login": "jeswr"}}]
    real_timeline_json = globals()["_gh_json"]
    globals()["_gh_json"] = lambda args: [newest_unlabel_page, "garbage-page"]
    try:
        try:
            _issue_timeline_events(repo, 41)
            raise AssertionError("malformed timeline page did not raise")
        except DispatchError as exc:
            assert "timeline page is malformed" in str(exc), exc
        # ... and the readmission window consumer lands on the conservative full count.
        cutoff_log = io.StringIO()
        with contextlib.redirect_stdout(cutoff_log):
            assert _park_policy.readmission_cutoff(
                repo, 41, 7, _issue_timeline_events,
                is_human=lambda login: login == "jeswr") is None
        assert "timeline read failed" in cutoff_log.getvalue()
    finally:
        globals()["_gh_json"] = real_timeline_json
    # ... while a concluded-GREEN gate on a drafted, unarmed, reviewed head is the STRANDED
    # posture (no other autonomous exit exists) — enumerated so CLAIM can hand it to a human
    green = {41: status_of(sha_a, gate="success")}
    stranded_items = enumerate_review_items(repo, [starved], provenance, [], issue_labels, now,
                                            pr_status=green)
    assert [(item["state"], item["context"]) for item in stranded_items] == [
        ("stranded", "")], stranded_items
    # [round-5 P2] an UNKNOWN arm bit (garbage auto_merge -> armed=None) never proves the
    # stranded posture: only an EXPLICIT armed=False acts
    assert enumerate_review_items(
        repo, [starved], provenance, [], issue_labels, now,
        pr_status={41: dict(status_of(sha_a), armed=None)}) == []
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
    # Issue #351 (the #256 limbo): a non-draft review:pass PR (decision-7 armable) on a
    # CONFLICTING base is NOT a terminal arm-and-wait — the arm can never merge a conflicting
    # base, so the conflict-first block emits needs-rebase REGARDLESS of the pass verdict
    # (review-state-agnostic). GAP-B still beats GAP-A here: a red gate on the conflicted base
    # is noise, so the pass PR emits needs-rebase, NOT needs-ci-fix. (Gating the conflict block
    # on review state would flip this to needs-ci-fix and re-strand #256 — the mutation check.)
    passed_conflicting = {41: status_of(sha_a, gate="failure", conflicting=True, legs=["js"])}
    assert [(item["state"], item["context"]) for item in enumerate_review_items(
        repo, [passed], provenance, [], issue_labels, now,
        pr_status=passed_conflicting)] == [("needs-rebase", "")]
    # ... and a live review/fix lease suppresses it exactly like any other repair state
    for holder in (f"review:{repo}#41@run.1", f"fix:{repo}#41@run.1"):
        assert enumerate_review_items(
            repo, [passed], provenance, [{"holder": holder, "expires_at": now + 100}],
            issue_labels, now, pr_status=passed_conflicting) == []
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
    # unknown snapshot / stale snapshot head / missing provenance are all DO-NOTHING
    assert enumerate_disarm_items(repo, [moved], {}, provenance) == []
    assert enumerate_disarm_items(repo, [moved], {41: status_of(sha_a, armed=True)},
                                  provenance) == []
    assert enumerate_disarm_items(
        repo, [pull(90, "sparq-agent/issue-1-1-1", sha_b, draft=False)],
        {90: status_of(sha_b, armed=True)}, provenance) == []
    # Issue #105: a human hold (review:needs-user / needs:user) parks pushes/reviews but must NOT
    # suppress the safety-only latch retraction — a held ARMED mismatch is STILL emitted so the
    # sweep retracts the latch (worker-pr.py disarm --when mismatch preserves the hold, dropping
    # only the relabel). Red if the old human-hold skip is restored (would flip these to []).
    for hold in ("review:needs-user", "needs:user"):
        parked = pull(41, "sparq-agent/issue-7-1-1", sha_b, draft=False,
                      labels=[hold], body=f"x <!-- sparq-reviewed-sha:{sha_a} -->")
        assert enumerate_disarm_items(repo, [parked], armed_status, provenance) == [
            {"pr_number": 41, "head_sha": sha_b, "reviewed_sha": sha_a, "repo": repo}]
    # ... but a held DRAFTED-unarmed PR still has nothing latched and nothing interrupted — the
    # hold never manufactures a safety violation where none exists (DO-NOTHING).
    for hold in ("review:needs-user", "needs:user"):
        held_draft = pull(41, "sparq-agent/issue-7-1-1", sha_b, draft=True,
                          labels=[hold], body=f"x <!-- sparq-reviewed-sha:{sha_a} -->")
        assert enumerate_disarm_items(repo, [held_draft], {41: status_of(sha_b)},
                                      provenance) == []
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
    # [round-5 P2] tri-state arm bit: unknown (None) never proves stranded — only an
    # explicit False does
    assert stranded_live(True, None, True, True, "success") is False
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
        if "/timeline" in path:
            # The readmission-window probe (PR + source-issue label timelines). A missing
            # entry serves an EMPTY timeline (no human unlabel — the full-count behaviour
            # every pre-existing expectation assumes); timeline_error simulates a failed read.
            if fake.get("timeline_error"):
                raise RuntimeError("timeline unavailable")
            match = re.search(r"/issues/(\d+)/timeline", path)
            return [fake.get("timeline", {}).get(int(match.group(1)), [])]
        if "/issues/41/comments" in path:
            return [fake.get("comments", [])]
        if "/issues/7" in path:
            return {"labels": [{"name": name} for name in fake.get("issue_labels", [])]}
        if "/compare/" in path:
            return {"status": "ahead", "files": [{"filename": "src/a.rs"}]}
        raise AssertionError(f"unexpected API read: {path}")

    def fake_helper(script_dir, target_repo, script, args):
        helper_calls.append((script, args))

    def live_pull(*, draft, labels=(), body="", auto_merge=None, mergeable=True,
                  base_ref="main"):
        # base.ref defaults to the repo default branch ("main"): the review-lane invariant
        # (issue #164) is base == protected default; a test passes base_ref!="main" to exercise
        # the retargeted-PR exclusion.
        return {"number": 41, "state": "open", "draft": draft, "body": body,
                "mergeable": mergeable, "auto_merge": auto_merge,
                "head": {"ref": "sparq-agent/issue-7-1-1", "sha": sha_a,
                         "repo": {"full_name": repo}},
                "base": {"ref": base_ref, "repo": {"default_branch": "main"}},
                "user": {"login": bot, "type": "Bot"},
                "labels": [{"name": name} for name in labels]}

    def run_items(items, allocator=None, routing=None, policy=None, usage=None):
        helper_calls.clear()
        reasons = Counter()
        # Issue #108: a fresh per-lane accumulator each call; run_items.lanes exposes it for the
        # review/fix stall assertions below without changing the (launched, reasons) return arity.
        lanes = _new_lane_counts()
        fix_dispatch = Counter()
        launched = _dispatch_review_items(
            items, repo, policy or {"max_review_rounds": 3, "account_pool": []},
            routing or {}, allocator, wiring_worker_pr, "reg/repo",
            wiring_root, "main", bot, usage, 0.10, reasons, lanes=lanes,
            ledger_root=wiring_ledger_root, fix_dispatch=fix_dispatch)
        run_items.lanes = lanes
        run_items.fix_dispatch = fix_dispatch
        return launched, reasons

    ci_item = {"pr_number": 41, "head_sha": sha_a, "state": "needs-ci-fix",
               "impl_provider": "anthropic", "repo": repo, "package": "crate-a",
               "security": False, "context": "js"}
    real_io = (_gh_json, _run_target_helper, _target_token, _target_is_human_maintainer)
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
            # The strict maintainer probe (park-policy hygiene finding): jeswr is the trusted
            # human; bots/outsiders/unverifiable actors are not.
            globals()["_target_is_human_maintainer"] = (
                lambda repo, login: login == "jeswr")
            gate_red = [{"name": "gate", "status": "completed", "conclusion": "failure",
                         "started_at": "T1"}]
            gate_green = [{"name": "gate", "status": "completed", "conclusion": "success",
                           "started_at": "T1"}]
            # trigger evaporated (gate re-ran green): the ready PR is NOT defused — no mutation
            fake.update(pull=live_pull(draft=False, auto_merge={"merge_method": "squash"}),
                        check_runs=gate_green, issue_labels=["area:crate-a"])
            launched, reasons = run_items([ci_item])
            assert helper_calls == [], helper_calls
            # Issue #450 no-silent-defer: even a pre-claim live-trigger drift gets a coarse
            # non-empty shared telemetry reason (the exact detail remains in the per-PR log).
            assert launched == 0 and reasons["fix:preclaim-defer"] == 1, reasons
            # Issue #460: this item was already ENUMERATED into the fix lane. Live trigger drift
            # may defer it, but must not rewrite that fact as `0 eligible`; the aggregate reason
            # stays privacy-safe while the per-PR line above carries the exact cause.
            assert _fix_dispatch_line(run_items.fix_dispatch) == (
                "fix-dispatch: 1 eligible, 0 launched, 1 deferred "
                "(reasons: preclaim-defer=1)"), run_items.fix_dispatch
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
            # stranded RECOVERY (issue #161): {draft, unarmed, reviewed head, green gate} is the
            # residue of an interrupted defuse/disarm, so CLAIM RE-REVIEWS the current head under
            # the bounded round budget instead of a terminal hand-off — the reviewed-sha marker
            # matching the head (which DEFERS a plain needs-review) is bypassed for the recovery.
            stranded_item = dict(ci_item, state="stranded", context="")
            fake.update(pull=live_pull(
                draft=True, labels=["review:needs"],
                body=f"x <!-- sparq-reviewed-sha:{sha_a} -->"),
                check_runs=gate_green, comments=[])
            strand_routing = {"models": {
                "sol": {"provider_model": "TBD", "harness": "codex"},
                "luna": {"provider_model": "TBD", "harness": "codex"}}}

            class StrandAllocator:
                def __init__(self):
                    self.calls = []

                def claim(self, _repo, _package, role, chain, *_args, **_kwargs):
                    self.calls.append((role, list(chain)))
                    return None      # no account free: the recovery review DEFERS, no hand-off

                def release(self, *_args, **_kwargs):
                    return True

            # budget remaining (0 recorded rounds): the cross-provider REVIEW chain is offered and
            # NO needs-user is applied (recovery, not escalation)
            alloc = StrandAllocator()
            launched, reasons = run_items(
                [stranded_item], allocator=alloc, routing=strand_routing)
            assert helper_calls == [], helper_calls
            assert alloc.calls == [("review", ["sol", "luna"])], alloc.calls
            assert launched == 0 and reasons["review:no-slot"] == 1, reasons
            # repeated failed recovery: the round budget is spent (hard cap) -> loud needs-user,
            # and no review is dispatched — terminal escalation is RESERVED for this case
            fake["comments"] = [
                {"user": {"login": bot},
                 "body": f"x {wiring_worker_pr.ROUND_MARKER} n={i} run={i}.1 -->"}
                for i in range(1, wiring_worker_pr.HARD_CAP_ROUNDS + 1)]
            alloc = StrandAllocator()
            run_items([stranded_item], allocator=alloc, routing=strand_routing)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "needs-user")], helper_calls
            assert alloc.calls == [], alloc.calls
            # stranded DO-NOTHING: the posture failed to re-derive (gate red again) -> defer,
            # neither a review dispatch nor a hand-off
            fake.update(check_runs=gate_red, comments=[])
            alloc = StrandAllocator()
            run_items([stranded_item], allocator=alloc, routing=strand_routing)
            assert helper_calls == [], helper_calls
            assert alloc.calls == [], alloc.calls

            # ---- round-budget escalation (directive 2026-07-17): decide_budget replaces the
            # flat rounds>=max needs-user at CLAIM, the fix chain honours the pinned floor, and
            # a starved pinned chain DEFERS (defer-not-fallback: fable is never re-offered) ----
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
                "fable": {"provider_model": "claude-fable-5", "harness": "claude"},
                "opus": {"provider_model": "claude-opus-4-8", "harness": "claude"},
                "sol": {"provider_model": "TBD", "harness": "codex"},
                "luna": {"provider_model": "TBD", "harness": "codex"},
            }}
            fake.update(pull=live_pull(draft=True, labels=["review:changes"]),
                        check_runs=gate_green, issue_labels=["area:crate-a"])
            fix_model = wiring_worker_pr.FIX_MODEL_MARKER
            pin_marker = wiring_worker_pr.MODEL_PIN_MARKER

            # Issue #450 CLAIM re-entry + mutation guard: an externally supplied changes label
            # with valid provenance and NO bot round marker starts from synthetic round 0 (workflow
            # round 1), is counted fix-eligible, and reaches the allocator. Restoring the old
            # `if rounds < 1: continue` makes both assertions red. The trusted round-1 verdict
            # remains mandatory input to the verdict-seeded fixer.
            fake.update(pull=live_pull(draft=False, labels=["review:changes"]), comments=[])
            write_verdict(1, None)
            alloc = FakeAllocator()
            launched, reasons = run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert launched == 0 and alloc.chains == [["fable", "opus"]], \
                (launched, alloc.chains)
            assert run_items.fix_dispatch["eligible"] == 1, run_items.fix_dispatch
            assert reasons["fix:no-slot"] == 1, reasons
            disarm_calls = [args for script, args in helper_calls
                            if script == "worker-pr.py" and args[0] == "disarm"]
            assert disarm_calls and "--preserve-review-state" in disarm_calls[0], disarm_calls
            synthetic_rounds = [args for script, args in helper_calls
                                if script == "worker-pr.py" and args[0] == "round-record"]
            assert synthetic_rounds and synthetic_rounds[0][
                synthetic_rounds[0].index("--round") + 1] == "1", synthetic_rounds
            fake.update(pull=live_pull(draft=True, labels=["review:changes"]), comments=[])

            # ACT: base budget spent on OPUS -> extension escalates UP the ladder
            # (opus < fable, sol r2 f2), fable pin converged, and a chain WITHOUT opus;
            # the None claim then defers with a missed marker, NOT needs-user
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->"),
                bot_comment(f"x {fix_model} round=2 model=opus run=2.9 -->")]
            write_verdict(3, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-model-pin"),
                ("worker-pr.py", "record-marker")], helper_calls
            pin_args = helper_calls[0][1]
            assert pin_args[pin_args.index("--tier") + 1] == "fable", pin_args
            assert alloc.chains == [["fable"]], alloc.chains

            # DO-NOTHING flip: under budget -> no pin call, the DEFAULT fix chain is offered
            fake["comments"] = round_markers(2)
            write_verdict(2, None)
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-marker")], helper_calls
            assert alloc.chains == [["fable", "opus"]], alloc.chains

            # a recorded bot pin governs the chain even under budget (the floor never lowers) —
            # a fable floor offers ONLY fable (tiers below the floor are never offered) ...
            fake["comments"] = round_markers(2) + [
                bot_comment(f"z {pin_marker} round=1 tier=fable run=1.5 -->")]
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [["fable"]], alloc.chains
            # ... while a NON-bot forged pin marker is inert (bot-login trust filter)
            fake["comments"] = round_markers(2) + [
                {"user": {"login": "mallory"},
                 "body": f"z {pin_marker} round=1 tier=fable run=6.6 -->"}]
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [["fable", "opus"]], alloc.chains

            # top tier ran + latest verdict improving -> progress extension (pin floor kept)
            fake["comments"] = round_markers(4) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->"),
                bot_comment(f"x {fix_model} round=3 model=fable run=3.9 -->"),
                bot_comment(f"z {pin_marker} round=3 tier=fable run=3.9 -->")]
            write_verdict(4, "improving")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-marker")], helper_calls
            assert alloc.chains == [["fable"]], alloc.chains

            # flip-goes-red: top tier + stagnant -> the loud terminal needs-user, no claim
            fake["comments"] = round_markers(4) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->"),
                bot_comment(f"x {fix_model} round=3 model=fable run=3.9 -->")]
            write_verdict(4, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "needs-user")], helper_calls
            assert alloc.chains == [], alloc.chains

            # ---- round-budget human-readmission window (live defect sparq#2804/PR#3442,
            # 2026-07-23: the maintainer unlabeled needs:user at 09:18:19Z and the CLAIM
            # re-derivation re-parked at 09:40:55Z on 5 broken-CI-era rounds): a HUMAN
            # unlabel restarts the budget; bot/absent/failed reads keep the full count ----
            def stamped_rounds(count, created, start=1):
                return [dict(bot_comment(
                    f"x {wiring_worker_pr.ROUND_MARKER} n={i} run={i}.1 -->"),
                    created_at=created) for i in range(start, start + count)]

            def unlabel_event(ts, login):
                return {"event": "unlabeled", "label": {"name": "needs:user"},
                        "created_at": ts, "actor": {"login": login}}

            def needs_user_reasons():
                return [args[args.index("--reason") + 1] for script, args in helper_calls
                        if script == "worker-pr.py" and args[0] == "needs-user"]

            burned_era = stamped_rounds(5, "2026-07-22T05:00:00Z") + [
                dict(bot_comment(f"x {fix_model} round=4 model=fable run=4.9 -->"),
                     created_at="2026-07-22T05:30:00Z")]
            # (1) human unlabel on the SOURCE ISSUE after 5 burned rounds => effective count
            # 0 => NO budget park; the fix chain is offered again (the missed-marker defer is
            # the allocator saying no slot, not an escalation).
            fake["comments"] = burned_era
            fake["timeline"] = {7: [unlabel_event("2026-07-23T09:18:19Z", "jeswr")]}
            write_verdict(5, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-marker")], helper_calls
            assert alloc.chains == [["fable", "opus"]], alloc.chains
            # (2) rounds recorded AFTER the unlabel count normally: 2 post-unlabel rounds
            # (base 3) stay under budget even though the GLOBAL count (7) is at the hard cap.
            fake["comments"] = burned_era + stamped_rounds(
                2, "2026-07-23T10:00:00Z", start=6)
            write_verdict(7, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-marker")], helper_calls
            assert alloc.chains == [["fable", "opus"]], alloc.chains
            # (3) a BOT unlabel does NOT reset: the full 5-round count stands and the
            # terminal park fires with the historical charge.
            fake["comments"] = burned_era
            fake["timeline"] = {
                7: [unlabel_event("2026-07-23T09:18:19Z", "sparq-orchestrator[bot]")]}
            write_verdict(5, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [], alloc.chains
            assert ["exhausted at 5 round(s)" in reason
                    for reason in needs_user_reasons()] == [True], helper_calls
            # (4) no unlabel event anywhere => behaviour unchanged (the full count parks).
            fake.pop("timeline", None)
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [], alloc.chains
            assert ["exhausted at 5 round(s)" in reason
                    for reason in needs_user_reasons()] == [True], helper_calls
            # (5) a timeline read failure keeps the FULL count (the OLD conservative park —
            # never a fresh budget on unproven data) and logs the failure LOUDLY.
            fake["timeline_error"] = True
            alloc = FakeAllocator()
            probe_log = io.StringIO()
            with contextlib.redirect_stdout(probe_log):
                run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [], alloc.chains
            assert ["exhausted at 5 round(s)" in reason
                    for reason in needs_user_reasons()] == [True], helper_calls
            assert "timeline read failed" in probe_log.getvalue(), probe_log.getvalue()
            fake.pop("timeline_error", None)
            # (2) wrote a LEGACY round-7 verdict; the ledger-first resolution tests below
            # depend on the legacy round-7 copy being absent — remove the fixture residue.
            (Path(wiring_root) / wiring_worker_pr.verdict_path(repo, 41, 7)).unlink()

            # ---- finding A CLAIM glue: a review:parked item that PLAN re-admitted on label
            # STATE must re-prove the human gesture on the label TIMELINES here. No gesture
            # newer than the park application => defer with NO mutation and NO claim; a
            # proven newer gesture => the stale review:parked converges to review:needs
            # BEFORE dispatch (review-fix.yml admission rejects review:parked). ----
            def park_event(kind, label, ts, login):
                return {"event": kind, "label": {"name": label},
                        "created_at": ts, "actor": {"login": login}}

            parked_claim_item = dict(fix_item, state="needs-review")
            fake.update(pull=live_pull(draft=True, labels=["review:parked"]))
            fake["comments"] = []
            fake["timeline"] = {41: [park_event("labeled", "review:parked",
                                                "2026-07-23T10:00:00Z",
                                                "sparq-orchestrator[bot]")], 7: []}
            alloc = FakeAllocator()
            run_items([parked_claim_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [], helper_calls
            assert alloc.chains == [], alloc.chains
            # bot gestures / stale gestures never re-admit either
            fake["timeline"][7] = [park_event("unlabeled", "status:parked",
                                              "2026-07-23T11:00:00Z",
                                              "sparq-orchestrator[bot]")]
            alloc = FakeAllocator()
            run_items([parked_claim_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [] and alloc.chains == [], (helper_calls, alloc.chains)
            # a PROVEN human gesture strictly newer than the park application re-admits:
            # the strip lands first, then the review chain is offered.
            fake["timeline"][7] = [park_event("unlabeled", "status:parked",
                                              "2026-07-23T11:00:00Z", "jeswr")]
            alloc = FakeAllocator()
            run_items([parked_claim_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[:2]) for script, args in helper_calls] == [
                ("worker-pr.py", ["review-state", "set"])], helper_calls
            assert "--state" in helper_calls[0][1] and "needs" in helper_calls[0][1], \
                helper_calls
            assert alloc.chains == [["sol", "luna"]], alloc.chains

            # ---- round-3 finding 2: the proof gate triggers off the DURABLE RECEIPTS, not
            # the live label. A triage-side dismissal of review:parked (label GONE, receipts
            # standing, no proven-human gesture) still re-proves here — and DECLINES. ----
            fake.update(pull=live_pull(draft=True, labels=[]))
            fake["comments"] = [bot_comment(
                f"parked {wiring_worker_pr.PARK_GENERATION_MARKER} gen=1 cutoff=none -->")]
            fake["timeline"] = {
                41: [park_event("labeled", "review:parked", "2026-07-23T10:00:00Z",
                                "sparq-orchestrator[bot]"),
                     park_event("unlabeled", "review:parked", "2026-07-23T10:30:00Z",
                                "drive-by-triage")],
                7: []}
            alloc = FakeAllocator()
            park_gate_log = io.StringIO()
            with contextlib.redirect_stdout(park_gate_log):
                run_items([parked_claim_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [] and alloc.chains == [], (helper_calls, alloc.chains)
            assert "machine capacity park stands (durable receipts/label" \
                in park_gate_log.getvalue(), park_gate_log.getvalue()
            # ... a PROVEN human gesture (newer than the park application, unconsumed) on
            # the SOURCE issue re-admits the label-free PR — with NO strip call (nothing to
            # strip) and the review chain offered.
            fake["timeline"][7] = [park_event("unlabeled", "status:parked",
                                              "2026-07-23T11:00:00Z", "jeswr")]
            alloc = FakeAllocator()
            run_items([parked_claim_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [], helper_calls
            assert alloc.chains == [["sol", "luna"]], alloc.chains
            # ... but a gesture whose window is already CONSUMED (receipted) never
            # re-admits: the veto-suppressed label re-apply leaves no fresh application to
            # out-date it, so without the receipt check this stale gesture would re-admit
            # forever.
            fake["comments"] = [bot_comment(
                f"parked {wiring_worker_pr.PARK_GENERATION_MARKER} gen=2 "
                "cutoff=2026-07-23T11:00:00Z -->")]
            alloc = FakeAllocator()
            run_items([parked_claim_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [] and alloc.chains == [], (helper_calls, alloc.chains)
            # ---- the one-predicate race guard: status:parked live on the SOURCE at CLAIM
            # defers outright (a fresh park landed in the PLAN->CLAIM window) ----
            fake["comments"] = []
            fake["issue_labels"] = ["area:crate-a", "status:parked"]
            alloc = FakeAllocator()
            run_items([parked_claim_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [] and alloc.chains == [], (helper_calls, alloc.chains)
            fake["issue_labels"] = ["area:crate-a"]
            fake.pop("timeline", None)
            fake.update(pull=live_pull(draft=True, labels=["review:changes"]))

            # hard cap: 6 rounds stop even with a weaker tier + an improving grade
            fake["comments"] = round_markers(6) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->")]
            write_verdict(6, "improving")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "needs-user")], helper_calls

            # a corrupt bot-authored pin tier is LOUD (needs-user) — silently ignoring it
            # would run the unpinned chain, the exact fall-back-down the pin forbids
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=fable run=1.9 -->"),
                bot_comment(f"z {pin_marker} round=1 tier=gpt-omega run=1.1 -->")]
            write_verdict(3, "improving")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "needs-user")], helper_calls
            assert alloc.chains == [], alloc.chains

            # ACT (terminal-grant orphan defect): the pinned FABLE fix EXECUTED and PUSHED
            # (state review:needs) must get its re-review — the fable fix-model marker
            # falsifies the top-tier escalation predicate and the recorded round-3 grade
            # (stagnant) predates the fable fix, so without the pending-fix authorization
            # this exact posture went needs-user with the top-tier round burned unreviewed.
            # The allocator is offered the cross-provider REVIEW chain (round 4), no
            # needs-user and no pin mutation.
            review_item = dict(fix_item, state="needs-review")
            fake.update(pull=live_pull(draft=True, labels=["review:needs"]))
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->"),
                bot_comment(f"x {fix_model} round=2 model=opus run=2.9 -->"),
                bot_comment(f"z {pin_marker} round=3 tier=fable run=3.5 -->"),
                bot_comment(f"x {fix_model} round=3 model=fable run=3.9 -->")]
            write_verdict(3, "stagnant")
            alloc = FakeAllocator()
            run_items([review_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [], helper_calls
            assert alloc.chains == [["sol", "luna"]], alloc.chains

            # issue #164: the SAME needs-review posture whose worker PR is RETARGETED off the
            # protected default branch is EXCLUDED here (the review-lane invariant: base ==
            # default). The wrong-base empty-diff probe never runs and no reviewer slot is spent
            # on a PR the arm could never merge. Contrast the dispatch immediately above:
            # identical comments/verdict, only base.ref differs ("release" != default "main"),
            # yet this one defers with no claim and no mutation.
            fake.update(pull=live_pull(draft=True, labels=["review:needs"], base_ref="release"))
            alloc = FakeAllocator()
            run_items([review_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [], helper_calls
            assert alloc.chains == [], alloc.chains
            fake.update(pull=live_pull(draft=True, labels=["review:needs"]))

            # flip-goes-red: the same posture whose latest fix ran BELOW the recorded fable
            # floor (a pin violation / forged marker) mints NO re-review — with the top tier
            # already graded stagnant it is the loud terminal instead
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=fable run=1.9 -->"),
                bot_comment(f"z {pin_marker} round=1 tier=fable run=1.5 -->"),
                bot_comment(f"x {fix_model} round=3 model=opus run=3.9 -->")]
            alloc = FakeAllocator()
            run_items([review_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "needs-user")], helper_calls
            assert alloc.chains == [], alloc.chains

            # ordering regression (#454 review round 1): the retargeted-base exclusion runs
            # BEFORE the round-budget processing. Each posture below took a MUTATING budget
            # action when base == default (asserted above: record-model-pin for the first,
            # the terminal needs-user for the second); retargeted, both must defer with NO
            # helper call and NO claim — a human retarget removes the PR from the loop, so
            # the loop must not label/pin it on the way out.
            fake.update(pull=live_pull(draft=True, labels=["review:changes"],
                                       base_ref="release"))
            # would-be extend-model-pin (the ACT posture above)
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->"),
                bot_comment(f"x {fix_model} round=2 model=opus run=2.9 -->")]
            write_verdict(3, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [], helper_calls
            assert alloc.chains == [], alloc.chains
            # would-be terminal needs-user (the flip-goes-red posture above)
            fake["comments"] = round_markers(4) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->"),
                bot_comment(f"x {fix_model} round=3 model=fable run=3.9 -->")]
            write_verdict(4, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert helper_calls == [], helper_calls
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
            # issue #156: a HOST-ENVELOPE record (the new on-disk format) is unwrapped so the
            # nested verdict's progress grade is still read (the reader is not fooled into
            # reading progress off the envelope top level, which would degrade to None).
            env_rel = wiring_worker_pr.verdict_path(repo, 41, 6)
            env_path = Path(wiring_ledger_root) / env_rel
            env_path.parent.mkdir(parents=True, exist_ok=True)
            env_path.write_text(json.dumps(wiring_worker_pr.verdict_envelope(
                repo, 41, 6, "a" * 40,
                {"verdict": "request_changes", "injection_detected": False, "summary": "s",
                 "issues": [], "progress": "regressing"})), encoding="utf-8")
            assert latest_recorded_progress(wiring_worker_pr, wiring_root, repo, 41, 6, [],
                                            bot, ledger_root=wiring_ledger_root) == "regressing"
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
            assert alloc.chains == [["fable", "opus"]], alloc.chains
            # a deferring (None-claim) allocator is contention, NOT ledger rot: no lease-error,
            # ledger stays ok, and the zero-dispatch tick stays green
            assert launched == 0 and reasons["lease-error"] == 0, (launched, reasons)
            assert _ledger_health(reasons) == "ok", reasons
            assert _ledger_rot_zeroed_dispatch(launched, reasons) is False
            # Issue #108: a needs-fix item is the FIX lane. Capacity contention (None claim) is a
            # DEFER, not an error — the fix lane records planned=1, launched=0, error=0, so the
            # health recorder does NOT read it as a hard stall while accounts are simply busy.
            assert _lane_summary(run_items.lanes)["fix"] == {
                "planned": 1, "launched": 0, "deferred": 1, "error": 0}, run_items.lanes

            # Issue #117: a FAILED durable missed-fix marker write on the None-claim path is NOT a
            # healthy defer. Swallowing it (except DispatchError: pass) left the missed-fix budget
            # stuck at zero forever, so the MISSED_FIX_LIMIT human escalation never fired and the PR
            # was silently stranded. The failure must surface as a COUNTED fix-lane error + a
            # rolling-alert defer reason, and must NOT report the normal "no lease free" defer.
            def failing_marker_helper(script_dir, target_repo, script, args):
                helper_calls.append((script, args))
                if script == "worker-pr.py" and "record-marker" in args and "missed" in args:
                    raise DispatchError("record-marker missed: target helper failed")

            globals()["_run_target_helper"] = failing_marker_helper
            try:
                alloc = FakeAllocator()   # claim() returns None: the missed marker is attempted
                launched, reasons = run_items([fix_item], allocator=alloc, routing=routing_ok)
            finally:
                globals()["_run_target_helper"] = fake_helper
            assert launched == 0, launched
            # the write WAS attempted (the missed record-marker call is present) ...
            assert ("worker-pr.py", "record-marker") in [
                (script, args[0]) for script, args in helper_calls], helper_calls
            # ... and its failure is a counted error + rolling alert, not a silent green defer
            assert reasons["missed-marker-write-failed"] == 1, reasons
            assert _lane_summary(run_items.lanes)["fix"] == {
                "planned": 1, "launched": 0, "deferred": 0, "error": 1}, run_items.lanes
            # Issue #165: because the durable marker (the SOLE budget input) could not be written,
            # the MISSED_FIX_LIMIT terminal can never fire — so the failure escalates DIRECTLY to a
            # human. needs-user succeeds here (failing_marker_helper only rejects record-marker), so
            # the PR is now bounded and the escalation is NOT re-counted as an escalation failure.
            assert ("worker-pr.py", "needs-user") in [
                (script, args[0]) for script, args in helper_calls], helper_calls
            assert reasons["missed-escalation-failed"] == 0, reasons

            # Issue #165: a PERSISTENT target-API outage fails the escalation POST too (same API as
            # the failed marker). Both the marker AND the human escalation fail, so neither terminal
            # is confirmed: the tick counts the escalation failure and the item stays a RETRYABLE
            # defer (auto-retry until the marker or the escalation finally lands) — never silently
            # lost, never a green "no lease free" defer that hides the unbounded PR.
            def failing_all_helper(script_dir, target_repo, script, args):
                helper_calls.append((script, args))
                raise DispatchError(f"{script} {args[0]}: target helper failed")

            globals()["_run_target_helper"] = failing_all_helper
            try:
                alloc = FakeAllocator()
                launched, reasons = run_items([fix_item], allocator=alloc, routing=routing_ok)
            finally:
                globals()["_run_target_helper"] = fake_helper
            assert launched == 0, launched
            assert reasons["missed-marker-write-failed"] == 1, reasons
            assert reasons["missed-escalation-failed"] == 1, reasons
            assert _lane_summary(run_items.lanes)["fix"]["error"] == 1, run_items.lanes
            # the human escalation WAS attempted after the marker write failed (it did not silently
            # give up once the marker was unrecordable)
            assert ("worker-pr.py", "needs-user") in [
                (script, args[0]) for script, args in helper_calls], helper_calls

            # regression guard: a SUCCESSFUL missed marker (default helper) stays a clean defer —
            # no spurious error/alert/escalation when the durable marker is confirmed
            alloc = FakeAllocator()
            _, reasons = run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert reasons["missed-marker-write-failed"] == 0, reasons
            assert reasons["missed-escalation-failed"] == 0, reasons
            assert _lane_summary(run_items.lanes)["fix"]["error"] == 0, run_items.lanes
            assert ("worker-pr.py", "needs-user") not in [
                (script, args[0]) for script, args in helper_calls], helper_calls

            # ---- issue #115: require_usage HOLDS a review/fix claim during a WHOLESALE usage-
            # probe outage (usage=None), matching the worker loop's fail-closed hold, with an
            # explicit carve-out for a chain served entirely by probe-exempt (codex/openai)
            # accounts. Before the fix the review/fix loop passed usage=None straight to the
            # allocator's UNGATED static selection, so anthropic review/fix work could start
            # despite require_usage=true and a total probe failure. ----
            usage_gated = {"max_review_rounds": 3, "account_pool": [], "require_usage": True}
            # A routing catalog carrying the model `provider` field (as the live routing.toml
            # does): anthropic models are probe-GATED, openai/codex models are probe-EXEMPT.
            routing_prov = {"models": {
                "fable": {"provider": "anthropic", "provider_model": "claude-fable-5",
                          "harness": "claude"},
                "opus": {"provider": "anthropic", "provider_model": "claude-opus-4-8",
                         "harness": "claude"},
                "sol": {"provider": "openai", "provider_model": "TBD", "harness": "codex"},
                "luna": {"provider": "openai", "provider_model": "TBD", "harness": "codex"},
            }}
            fake.update(pull=live_pull(draft=True, labels=["review:changes"]),
                        check_runs=gate_green, issue_labels=["area:crate-a"])
            fake["comments"] = round_markers(2)
            write_verdict(2, None)
            # (a) an anthropic (probe-GATED) FIX chain + usage=None + require_usage HOLDS: the
            # claim is NEVER offered and the outage is counted, exactly like the worker loop.
            alloc = FakeAllocator()
            _, reasons = run_items([fix_item], allocator=alloc, routing=routing_prov,
                                   policy=usage_gated, usage=None)
            assert alloc.chains == [], alloc.chains
            assert reasons["usage-probe-unavailable"] == 1, reasons
            # (b) the hold is CONDITIONED on require_usage: the SAME outage under the default
            # policy (require_usage unset) still dispatches — a non-opted-in repo is unchanged.
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_prov, usage=None)
            assert alloc.chains == [["fable", "opus"]], alloc.chains
            # (c) the hold is CONDITIONED on the OUTAGE: require_usage with a LIVE usage map
            # dispatches (usage!=None is not a probe failure).
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_prov,
                      policy=usage_gated, usage={"acct01": {"ok": True}})
            assert alloc.chains == [["fable", "opus"]], alloc.chains
            # (d) a probe-EXEMPT (codex/openai) REVIEW chain PROCEEDS despite usage=None: absent
            # usage is its expected steady state (reactive backoff), so the hold must NOT gate it.
            exempt_review = dict(fix_item, state="needs-review")
            fake.update(pull=live_pull(draft=True, labels=["review:needs"]),
                        check_runs=gate_green, issue_labels=["area:crate-a"])
            fake["comments"] = round_markers(1)
            alloc = FakeAllocator()
            _, reasons = run_items([exempt_review], allocator=alloc, routing=routing_prov,
                                   policy=usage_gated, usage=None)
            assert alloc.chains == [["sol", "luna"]], alloc.chains
            assert reasons["usage-probe-unavailable"] == 0, reasons
            # (e) fail-closed on an UNKNOWN provider: a chain whose alias carries no exempt
            # provider is treated as probe-gated (never silently exempted) and HOLDS.
            routing_unknown = {"models": {
                "fable": {"provider": "mystery", "provider_model": "x", "harness": "claude"},
                "opus": {"provider": "mystery", "provider_model": "y", "harness": "claude"},
            }}
            fake.update(pull=live_pull(draft=True, labels=["review:changes"]),
                        check_runs=gate_green, issue_labels=["area:crate-a"])
            fake["comments"] = round_markers(2)
            write_verdict(2, None)
            alloc = FakeAllocator()
            _, reasons = run_items([fix_item], allocator=alloc, routing=routing_unknown,
                                   policy=usage_gated, usage=None)
            assert alloc.chains == [], alloc.chains
            assert reasons["usage-probe-unavailable"] == 1, reasons
            fake.update(pull=live_pull(draft=True, labels=["review:changes"]))

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
            # Issue #108: the SAME raise also lands in the FIX lane's error tally (launched 0,
            # error 1) — so "every fix item fails forever" is visible per-lane even when the worker
            # lane launched on the same tick and the fleet dispatched>0 hid the ledger-rot signal.
            # A needs-fix plan row is the fix lane, so the review lane stays clean this tick.
            errored = _lane_summary(run_items.lanes)
            assert errored["fix"] == {
                "planned": 1, "launched": 0, "deferred": 0, "error": 1}, run_items.lanes
            assert errored["review"]["planned"] == 0, run_items.lanes

            # ---- review/fix workflow-launch failure is a LANE ERROR (PR #321 review): a
            # nonzero `gh workflow run` is a hard dispatch failure, not capacity contention.
            # It must fold into the lane's error tally + the shared dispatch-launch-failed
            # histogram, so an all-launch-failed fix lane reads stalled (planned>0,
            # launched=0, error>0) instead of deriving as `deferred` and dodging the
            # tick-health recorder while another lane launched. ----
            class ClaimingAllocator:
                def __init__(self):
                    self.released = []

                def claim(self, _repo, _package, _role, chain, *_args, **_kwargs):
                    return {"account": "acct01", "claim_id": "ab" * 16,
                            "model": chain[0], "provider": "anthropic"}

                def release(self, _repo, claim_id, _now):
                    self.released.append(claim_id)
                    return True

            gh_runs = []
            real_run_gh = _run_gh

            def fake_run_gh(args, *, check=True):
                gh_runs.append(list(args))
                return subprocess.CompletedProcess(args, fake_run_gh.returncode)

            try:
                globals()["_run_gh"] = fake_run_gh
                fake_run_gh.returncode = 1
                alloc = ClaimingAllocator()
                launched, reasons = run_items([fix_item], allocator=alloc,
                                              routing=routing_ok)
                assert gh_runs and gh_runs[0][:3] == [
                    "workflow", "run", "review-fix.yml"], gh_runs
                assert launched == 0 and reasons["dispatch-launch-failed"] == 1, \
                    (launched, reasons)
                assert alloc.released == ["ab" * 16], alloc.released  # lease not leaked
                assert _lane_summary(run_items.lanes)["fix"] == {
                    "planned": 1, "launched": 0, "deferred": 0, "error": 1}, run_items.lanes
                # flip-goes-green: the SAME posture with a zero-exit launch is a lane launch,
                # not an error, and the lease stays held for the launched workflow
                gh_runs.clear()
                fake_run_gh.returncode = 0
                alloc = ClaimingAllocator()
                launched, reasons = run_items([fix_item], allocator=alloc,
                                              routing=routing_ok)
                assert launched == 1 and reasons["dispatch-launch-failed"] == 0, \
                    (launched, reasons)
                assert alloc.released == [], alloc.released
                assert _lane_summary(run_items.lanes)["fix"] == {
                    "planned": 1, "launched": 1, "deferred": 0, "error": 0}, run_items.lanes
            finally:
                globals()["_run_gh"] = real_run_gh

            # ---- issue #448: one dispatch tick fans eligible fixes out to LIVE account slots ----
            # Five distinct-package, trust-admitted fix rows over S=3 slots must launch exactly
            # min(N,S)=3 distinct PR workflows.  This is deliberately an end-to-end test of the
            # production _dispatch_review_items loop/lease call/gh argv, not a slice helper: a
            # mutation that restores a one-item break or a static max_holder_concurrent=1 makes
            # the launch-count assertion red.
            fanout_numbers = list(range(51, 56))
            fanout_items = []
            fanout_pulls = {}
            fanout_issues = {}
            for offset, pr_number in enumerate(fanout_numbers):
                issue_number = 700 + offset
                head_sha = f"{pr_number:040x}"
                fanout_pulls[pr_number] = {
                    "number": pr_number, "state": "open", "draft": True,
                    "body": "", "mergeable": True, "auto_merge": None,
                    "head": {"ref": f"sparq-agent/issue-{issue_number}-1-1",
                             "sha": head_sha, "repo": {"full_name": repo}},
                    "base": {"ref": "main", "repo": {"default_branch": "main"}},
                    "user": {"login": bot, "type": "Bot"},
                    "labels": [{"name": "review:changes"},
                               {"name": f"area:fanout-{offset}"}],
                }
                fanout_issues[issue_number] = {
                    "labels": [{"name": f"area:fanout-{offset}"}]}
                fanout_items.append({
                    "pr_number": pr_number, "head_sha": head_sha,
                    "state": "needs-ci-fix", "impl_provider": "openai", "repo": repo,
                    "package": f"fanout-{offset}", "security": False, "context": "gate",
                })
                path = Path(wiring_root) / wiring_worker_pr.provenance_path(repo, pr_number)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({
                    "head_sha_at_open": head_sha, "impl_account_h": "ef" * 8,
                    "impl_alias": "sol", "impl_provider": "openai",
                    "issue": issue_number, "pr_number": pr_number,
                    "recorded_at_run": "448.1",
                }), encoding="utf-8")

            def fanout_gh_json(args):
                path = args[-1]
                match = re.search(r"/pulls/([0-9]+)$", path)
                if match:
                    return fanout_pulls[int(match.group(1))]
                if "/check-runs" in path:
                    return {"check_runs": gate_red}
                match = re.search(r"/issues/([0-9]+)/comments(?:\?.*)?$", path)
                if match:
                    return [[]]
                match = re.search(r"/issues/([0-9]+)$", path)
                if match:
                    return fanout_issues[int(match.group(1))]
                raise AssertionError(f"unexpected fan-out API read: {path}")

            class SlotAllocator:
                def __init__(self, slots, conflict_pr=None):
                    self.slots = slots
                    self.conflict_pr = conflict_pr
                    self.claimed_prs = []
                    self.calls = []

                def claim(self, _registry_repo, package, role, chain, holder, *_args, **kwargs):
                    match = re.search(r"#([0-9]+)@", holder)
                    assert match, holder
                    pr_number = int(match.group(1))
                    self.calls.append((pr_number, package, role, list(chain), dict(kwargs)))
                    # These are the load-bearing production arguments: repository-local package
                    # partition plus the live account-slot bound, with NO coarse row cap.
                    assert kwargs.get("holder_prefix") == f"fix:{repo}#", kwargs
                    assert kwargs.get("account_slot_bound") is True, kwargs
                    assert kwargs.get("max_holder_concurrent") is None, kwargs
                    assert kwargs.get("return_reason") is True, kwargs
                    if pr_number == self.conflict_pr:
                        return None, "package-single-flight"
                    if self.slots <= 0:
                        return None, "no-account-slots"
                    self.slots -= 1
                    self.claimed_prs.append(pr_number)
                    return ({"account": "acct09", "claim_id": f"{pr_number:032x}",
                             "model": chain[0], "provider": "openai"}, "")

                def release(self, *_args, **_kwargs):
                    return True

            fanout_runs = []

            def successful_fanout_run(args, *, check=True):
                fanout_runs.append(list(args))
                return subprocess.CompletedProcess(args, 0)

            def launched_prs():
                return [int(arg.split("=", 1)[1]) for args in fanout_runs for arg in args
                        if arg.startswith("pr_number=")]

            try:
                globals()["_gh_json"] = fanout_gh_json
                globals()["_run_gh"] = successful_fanout_run
                fanout_routing = {"models": {
                    "sol": {"provider": "openai", "provider_model": "TBD",
                            "harness": "codex"},
                    "luna": {"provider": "openai", "provider_model": "TBD",
                             "harness": "codex"},
                }}

                alloc = SlotAllocator(3)
                launched, _ = run_items(fanout_items, allocator=alloc, routing=fanout_routing)
                assert launched == min(len(fanout_items), 3) == 3, launched
                assert launched_prs() == fanout_numbers[:3], launched_prs()
                assert len(launched_prs()) == len(set(launched_prs())), launched_prs()
                assert _fix_dispatch_line(run_items.fix_dispatch) == (
                    "fix-dispatch: 5 eligible, 3 launched, 2 deferred "
                    "(reasons: no-account-slots=2)"), run_items.fix_dispatch

                # S=0 is fail-closed: every eligible item defers and no workflow is launched.
                fanout_runs.clear()
                alloc = SlotAllocator(0)
                launched, _ = run_items(fanout_items, allocator=alloc, routing=fanout_routing)
                assert launched == 0 and launched_prs() == [], (launched, launched_prs())
                assert _fix_dispatch_line(run_items.fix_dispatch) == (
                    "fix-dispatch: 5 eligible, 0 launched, 5 deferred "
                    "(reasons: no-account-slots=5)"), run_items.fix_dispatch

                # A first-writer-wins package conflict defers only that PR; distinct PRs still
                # fan out, and the conflicted PR can never appear in the workflow argv.
                fanout_runs.clear()
                conflicted_pr = fanout_numbers[1]
                alloc = SlotAllocator(5, conflict_pr=conflicted_pr)
                launched, _ = run_items(fanout_items, allocator=alloc, routing=fanout_routing)
                assert launched == 4, launched
                assert conflicted_pr not in launched_prs(), launched_prs()
                assert len(launched_prs()) == len(set(launched_prs())), launched_prs()
                assert run_items.fix_dispatch["defer:package-single-flight"] == 1, \
                    run_items.fix_dispatch
            finally:
                globals()["_gh_json"] = fake_gh_json
                globals()["_run_gh"] = real_run_gh

            # ---- issue #118: an unsafe/out-of-policy claim whose lease release FAILS (a CAS
            # conflict, or the garbage claim_id that was itself the violation) is a COUNTED
            # fix-lane error, NEVER a green "released + skipped" defer. The buggy path ignored
            # `_release_failed_dispatch`'s boolean and logged recovery while the lease stayed
            # active until expiry, consuming its account + package. This test is non-vacuous:
            # under the old code BOTH branches printed "released" and left the error tally at 0,
            # so the release_ok=False assertions below would flip red. ----
            class UnsafeClaimAllocator:
                def __init__(self, release_ok):
                    self.release_ok = release_ok
                    self.released = []

                def claim(self, _repo, _package, _role, chain, *_args, **_kwargs):
                    # account fails the acct-regex assertion -> unsafe/out-of-policy violation,
                    # reached BEFORE any provider/salt leg, so it is mode- and env-independent.
                    return {"account": "BADACCT", "claim_id": "cd" * 16,
                            "model": chain[0], "provider": "anthropic"}

                def release(self, _repo, claim_id, _now):
                    self.released.append(claim_id)
                    return self.release_ok

            # release FAILS: hard `::error::` reason + counted lane error, NO launch, and NOT
            # the plain unsafe-claim green defer.
            alloc = UnsafeClaimAllocator(release_ok=False)
            launched, reasons = run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert launched == 0, launched
            assert alloc.released == ["cd" * 16], alloc.released  # release WAS attempted
            assert reasons["unsafe-claim-release-failed"] == 1, reasons
            assert _lane_summary(run_items.lanes)["fix"]["error"] == 1, run_items.lanes
            # release SUCCEEDS: the SAME unsafe claim is a clean released+skipped defer with NO
            # lane error and NO hard-error reason — proving the boolean is actually consulted.
            alloc = UnsafeClaimAllocator(release_ok=True)
            launched, reasons = run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert launched == 0, launched
            assert alloc.released == ["cd" * 16], alloc.released
            assert reasons["unsafe-claim-release-failed"] == 0, reasons
            assert _lane_summary(run_items.lanes)["fix"]["error"] == 0, run_items.lanes
        finally:
            (globals()["_gh_json"], globals()["_run_target_helper"],
             globals()["_target_token"], globals()["_target_is_human_maintainer"]) = real_io

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
    kept = filter_busy_area_items(plan_items, repo, [in_review], issue_labels, busy_prov,
                                  leases=[], now=now)
    assert [item["number"] for item in kept] == [9], kept  # crate-a busy via issue 7's area
    assert filter_busy_area_items(plan_items, repo, [], issue_labels, busy_prov,
                                  leases=[], now=now) == plan_items
    # draft-agnostic, review-state-agnostic: a non-draft review:pass PR still reserves its area
    ready_pr = pull(41, "sparq-agent/issue-7-1-1", sha_a, draft=False, labels=["review:pass"])
    assert [item["number"] for item in filter_busy_area_items(
        plan_items, repo, [ready_pr], issue_labels, busy_prov, leases=[], now=now)] == [9]
    # area:* labels on the PR itself union in as well
    labelled = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=["area:crate-b"])
    assert filter_busy_area_items(plan_items, repo, [labelled], issue_labels, busy_prov,
                                  leases=[], now=now) == []
    # a known source issue with NO areas reserves the serializing global partition
    assert filter_busy_area_items(plan_items, repo,
                                  [pull(60, "sparq-agent/issue-8-1-1", sha_a)],
                                  {8: ["role:impl"]}, busy_prov, leases=[], now=now) == []
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
                                  repo, [in_review], issue_labels, busy_prov,
                                  leases=[], now=now) == []
    # ---- [round-5 P1] the impl lane shares the SAME crate-ownership view: a live
    # review/fix-lane lease on a crate defers that crate's impl items even with NO open PR
    # reserving it (the parked-inert-draft carve-out freed the crate while a review/fix run
    # could still hold a live lease there) ----
    assert filter_busy_area_items(
        plan_items, repo, [], issue_labels, busy_prov,
        leases=[{"holder": f"review:{repo}#41@run.1", "package": "crate-a",
                 "expires_at": now + 600}], now=now) == [plan_items[1]]
    # an expired cross-lane lease frees the crate again
    assert filter_busy_area_items(
        plan_items, repo, [], issue_labels, busy_prov,
        leases=[{"holder": f"review:{repo}#41@run.1", "package": "crate-a",
                 "expires_at": now - 1}], now=now) == plan_items
    # the item's OWN impl lease does not self-exclude (duplicate-work suppression stays the
    # allocator partition's job)
    assert filter_busy_area_items(
        plan_items, repo, [], issue_labels, busy_prov,
        leases=[{"holder": f"{repo}#7@run.1", "package": "crate-a",
                 "expires_at": now + 600}], now=now) == plan_items
    # [round-6 P1] a live lease held in ANOTHER target repository never defers this repo's
    # impl items — same-named crate and __global__ alike (per-repo partitions; the ledger
    # is fleet-wide and PLAN iterates every target over the ONE lease list)
    assert filter_busy_area_items(
        plan_items, repo, [], issue_labels, busy_prov,
        leases=[{"holder": "review:other-org/other-target#41@run.1", "package": "crate-a",
                 "expires_at": now + 600},
                {"holder": "other-org/other-target#12@d.1", "package": GLOBAL_PACKAGE,
                 "expires_at": now + 600}], now=now) == plan_items
    # an ABSENT/unreadable ledger view is ambiguity: everything defers (fail closed)
    assert filter_busy_area_items(plan_items, repo, [], issue_labels, busy_prov,
                                  leases=None, now=now) == []
    # fork-headed imposters do not reserve (filtered BEFORE the fail-closed linkage read)
    assert filter_busy_area_items(plan_items, repo,
                                  [pull(62, "sparq-agent/issue-7-1-1", sha_a,
                                        head_repo="mallory/fork")],
                                  issue_labels, busy_prov, leases=[], now=now) == plan_items

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

    def confirmed_draft(sha=sha_a):
        # [round-4] the coherent NEWER detail read the carve-out requires: head-matched,
        # arm bit exactly False, draft CONFIRMED by the detail's own bit (production
        # shape: plan-snapshot's per-PR pulls/N read via pr_ci_status).
        return {"head_sha": sha, "armed": False, "draft": True}

    collapse_status = {75: confirmed_draft(), 76: confirmed_draft()}
    assert busy_packages_of_pulls(repo, collapse_pulls, collapse_labels,
                                  busy_prov, collapse_status) == {"crate-c"}
    kept = filter_busy_area_items(frontier, repo, collapse_pulls, collapse_labels, busy_prov,
                                  collapse_status, leases=[], now=now)
    assert [item["number"] for item in kept] == [70, 71, 73], kept
    # a needs:user PR label parks just as terminally as review:needs-user
    assert filter_busy_area_items(
        frontier, repo, [pull(78, "sparq-agent/issue-81-1-1", sha_a, labels=["needs:user"])],
        collapse_labels, busy_prov, {78: confirmed_draft()}, leases=[], now=now) == frontier
    # the GLOBAL-freeze slice of the same bug: a PARKED PR whose known source issue has no
    # area labels must not reserve the serializing global partition (pre-fix it froze the
    # ENTIRE repo frontier); the unparked twin still does.
    assert filter_busy_area_items(
        frontier, repo, [pull(79, "sparq-agent/issue-84-1-1", sha_a)],
        {84: ["needs:user", "role:impl"]}, busy_prov, {79: confirmed_draft()},
        leases=[], now=now) == frontier
    assert filter_busy_area_items(
        frontier, repo, [pull(79, "sparq-agent/issue-84-1-1", sha_a)],
        {84: ["role:impl"]}, busy_prov, {79: confirmed_draft()}, leases=[], now=now) == []
    # a parked PR's own area:* labels are discarded with it (the whole PR is terminal)
    assert filter_busy_area_items(
        frontier, repo, [pull(78, "sparq-agent/issue-81-1-1", sha_a,
                              labels=["needs:user", "area:crate-d"])],
        collapse_labels, busy_prov, {78: confirmed_draft()}, leases=[], now=now) == frontier

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
    # Conditional-spread keys (ABSENCE != NULL fields like auto_merge, sol review on #517:
    # a plain .get() would fabricate a proven-null from an absent upstream key, so such
    # fields project via **({"k": pull["k"]} if "k" in pull else {}) and are pinned here).
    snapshot_fields |= {match.group(1) for match in
                        re.finditer(r'\*\*\(\{"([a-z_]+)"', projection.group(1))}
    assert snapshot_fields == {"number", "state", "draft", "body", "labels",
                               "head", "user", "auto_merge"}, snapshot_fields

    # ---- Issue #109: the tick-health recorder must make a snapshot-skip-only tick VISIBLE.
    # Snapshot skips fold into the defer histogram (snapshot_skip_reasons) but are NOT `planned`
    # items, so the recorder's planned>0 gate used to record such a tick as a quiet `none`. Exec
    # the EXACT classification block from dispatch.yml (not a re-implemented copy) so this pins the
    # workflow's real behavior: a nonempty defer histogram with nothing dispatched is the degraded
    # zero-dispatch class, while a genuinely empty frontier (no histogram) stays recordless. ----
    recorder = re.search(
        r'\n( *planned = \(summary or \{\}\)\.get\("planned", 0\).*?else "none")',
        workflow, re.DOTALL)
    assert recorder, "dispatch.yml lost the tick-state classification block"
    recorder_block = textwrap.dedent(recorder.group(1))

    def tick_state(summary, claim_outcome="success"):
        # The block reads only os.environ.get (CLAIM_OUTCOME / GITHUB_STEP_SUMMARY) up to the
        # `state` assignment; a step_summary of None skips every file write, so no real I/O runs.
        namespace = {"summary": summary,
                     "os": type("_os", (), {"environ":
                                            {"CLAIM_OUTCOME": claim_outcome}})()}
        exec(recorder_block, namespace)  # noqa: S102 — trusted workflow source, no external input
        return namespace["state"]

    # the exact defect: snapshot-skip-only tick — planned 0, nothing dispatched, but the defer
    # histogram carries the plan-snapshot degradation -> degraded zero-dispatch, NOT a quiet `none`
    assert tick_state({"planned": 0, "dispatched": 0,
                       "defer_reasons": {"snapshot-skip:check-runs-overflow": 1}}) == "zero"
    # a genuinely empty/quiet frontier (no histogram at all) still records nothing
    assert tick_state({"planned": 0, "dispatched": 0, "defer_reasons": {}}) == "none"
    # the pre-existing classes are unchanged by the degraded rescue
    assert tick_state({"planned": 3, "dispatched": 0,
                       "defer_reasons": {"existing-pr": 3}}) == "zero"
    assert tick_state({"planned": 3, "dispatched": 2, "defer_reasons": {}}) == "ok"
    assert tick_state(None, "failure") == "abort"
    # a PRODUCTIVE tick that also deferred some items must NOT be hijacked to zero by `degraded`
    # (degraded requires dispatched == 0), else every healthy tick with a single defer flips red
    assert tick_state({"planned": 3, "dispatched": 1,
                       "defer_reasons": {"existing-pr": 2}}) == "ok"

    # ---- [issue #111, round 2] PLAN's trusted() author filter, exec'd from dispatch.yml itself
    # (not a re-implemented copy) so these pin the workflow's REAL advisory behavior. Two pinned
    # regressions: (1) a NONEMPTY additional policy allowlist must NOT strand the pipeline's own
    # App bot — PLAN cannot resolve the runtime bot_login (no token), so an unlisted "[bot]"
    # author stays an advisory over-proposal for CLAIM's exact authoritative check to settle;
    # (2) a truthy non-dict nested `user` in the untrusted snapshot DENIES that item instead of
    # raising the AttributeError that would abort planning for every repository. ----
    plan_trusted_src = re.search(
        r"\n( *def trusted\(issue, trusted_bots\):.*?)\n\s*\n *def linked_issue_numbers",
        workflow, re.DOTALL)
    assert plan_trusted_src, "dispatch.yml lost the PLAN trusted() author filter"
    plan_ns = {"trusted_associations": {"OWNER", "MEMBER", "COLLABORATOR"}}
    exec(textwrap.dedent(plan_trusted_src.group(1)), plan_ns)  # noqa: S102 — trusted workflow source
    plan_trusted = plan_ns["trusted"]
    own_app = {"user": {"login": "our-app[bot]"}, "author_association": "NONE"}
    # the round-2 defect: an ADDITIONAL policy bot must not exclude the unlisted own App bot
    assert plan_trusted(own_app, {"other[bot]"}), \
        "nonempty allowlist strands the pipeline's own App bot at PLAN"
    assert plan_trusted(own_app, set())
    # exact allowlist members pass even without a "[bot]" suffix; non-collaborator humans never do
    assert plan_trusted({"user": {"login": "machine-user"}, "author_association": "NONE"},
                        {"machine-user"})
    assert not plan_trusted({"user": {"login": "external"}, "author_association": "CONTRIBUTOR"},
                            {"other[bot]"})
    assert plan_trusted({"user": {"login": "maintainer"}, "author_association": "MEMBER"}, set())
    # malformed shapes DENY without raising (the whole-PLAN-abort defect)
    assert not plan_trusted({"user": "malformed", "author_association": "MEMBER"}, set())
    assert not plan_trusted({"user": ["x"], "author_association": "OWNER"}, {"other[bot]"})
    assert not plan_trusted({"user": None, "author_association": "NONE"}, set())
    assert not plan_trusted("nope", set())

    def snapshot_row(number, ref, *, draft, labels=()):
        # EXACTLY the dispatch.yml projection: top-level keys pinned to the workflow read
        # above; labels are plain STRINGS (not {"name": ...} dicts); head/user sub-shapes
        # mirror the projection's nested selections.
        row = {"number": number, "state": "open", "draft": draft, "body": "",
               "labels": list(labels), "auto_merge": None,
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
    # parked DRAFT with a coherent confirming detail — the production frontier-collapse
    # population (26/27 open sparq worker PRs on 2026-07-18): provably inert, frees its
    # crate. A present detail remains the authoritative read (see the split-race block below).
    assert busy_packages_of_pulls(repo, [parked_draft()], collapse_labels,
                                  busy_prov, {76: confirmed_draft()}) == set()
    # ... and the SAME confirmation in the production record shape end-to-end: a raw
    # plan-snapshot detail record interpreted by pr_ci_status carries the draft bit.
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: pr_ci_status({"head_sha": sha_a, "mergeable": True, "auto_merge": None,
                           "draft": True, "check_runs": []})}) == set()
    # parked DRAFT whose fresher PLAN detail record says the arm is still latched: a
    # crashed-disarm artifact — busy despite the listing's explicit-null latch signal
    assert busy_packages_of_pulls(repo, [parked_draft()], collapse_labels, busy_prov,
                                  {76: {"head_sha": sha_a, "armed": True}}) == {"crate-b"}
    # ---- [round-4 P1] SPLIT-SNAPSHOT RACE: the pulls LISTING (draft bit) predates the
    # per-PR detail read; a draft that flipped ready(->queued) between the two reads
    # presents as stale listing draft=True + a newer unlatched detail. The carve-out
    # frees on a coherent, head-matched DETAIL when one exists. Every incoherent present
    # detail below stays BUSY (fail closed); only an entirely absent detail may fall back to
    # the post-#517 listing row's atomic draft:true + present auto_merge:null proof. ----
    # (a) detail record entirely ABSENT (pre-detail snapshot skip / census overflow): the
    #     complete post-#517 listing is sufficient, in both no-map and empty-map call shapes
    assert busy_packages_of_pulls(repo, [parked_draft()], collapse_labels,
                                  busy_prov) == set()
    assert busy_packages_of_pulls(repo, [parked_draft()], collapse_labels,
                                  busy_prov, {}) == set()
    print("  ok   issue-519 tripwire (a): parked listing draft+null frees without detail")
    # (b) newer detail is NON-DRAFT-shaped (draft went ready in the window — the exact
    #     race): busy, in the hand-rolled AND the production pr_ci_status record shape
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: {"head_sha": sha_a, "armed": False, "draft": False}}) == {"crate-b"}
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: pr_ci_status({"head_sha": sha_a, "mergeable": True, "auto_merge": None,
                           "draft": False, "check_runs": []})}) == {"crate-b"}
    # (c) detail's draft field ABSENT (the pre-round-4 record shape): proves nothing — busy
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: {"head_sha": sha_a, "armed": False}}) == {"crate-b"}
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: pr_ci_status({"head_sha": sha_a, "mergeable": True, "auto_merge": None,
                           "check_runs": []})}) == {"crate-b"}
    # (d) HEAD-MISMATCHED detail (the head moved between the reads: the listing row —
    #     including its draft bit — is stale): busy even though the detail says draft
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: confirmed_draft(sha_b)}) == {"crate-b"}
    # (e) unknown/garbage arm bit on an otherwise-confirming detail: busy (only an
    #     explicit armed=False frees; absent is unknown, never inert)
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: {"head_sha": sha_a, "draft": True}}) == {"crate-b"}
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: {"head_sha": sha_a, "armed": None, "draft": True}}) == {"crate-b"}
    # [round-5 P2] the production record shape end-to-end: a GARBAGE auto_merge string in
    # the raw detail is UNKNOWN through pr_ci_status (armed=None), so the parked draft
    # stays BUSY — the old isinstance read collapsed it to unarmed and FREED the crate
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: pr_ci_status({"head_sha": sha_a, "mergeable": True, "auto_merge": "garbage",
                           "draft": True, "check_runs": []})}) == {"crate-b"}
    # [round-6 P2] ABSENCE != NULL end-to-end: a detail with a matching head and a
    # confirming draft:true but NO auto_merge field AT ALL must NOT prove the PR inactive —
    # armed reads UNKNOWN through pr_ci_status and the parked draft stays BUSY (the old
    # detail.get() plumbing collapsed absence to explicit-null=unarmed and freed the crate)
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: pr_ci_status({"head_sha": sha_a, "mergeable": True, "draft": True,
                           "check_runs": []})}) == {"crate-b"}
    # ... while the EXPLICIT-null + draft-coherent detail still frees (the carve-out's
    # one legitimate free path is unchanged by the presence-preservation)
    assert busy_packages_of_pulls(
        repo, [parked_draft()], collapse_labels, busy_prov,
        {76: pr_ci_status({"head_sha": sha_a, "mergeable": True, "auto_merge": None,
                           "draft": True, "check_runs": []})}) == set()
    # A present malformed DETAIL is authoritative too: it cannot fall back to the friendly row.
    assert busy_packages_of_pulls(repo, [parked_draft()], collapse_labels,
                                  busy_prov, {76: None}) == {"crate-b"}
    print("  ok   issue-519 tripwire (b): latched detail overrides parked listing")
    # parked DRAFT with a latched listing: same crashed-disarm artifact — busy
    assert busy_packages_of_pulls(repo, [parked_draft(auto_merge=latched)],
                                  collapse_labels, busy_prov) == {"crate-b"}
    # [round-6] the pre-#517 listing shape has no auto_merge KEY. Even with draft:true it
    # cannot use the listing fallback: ABSENCE != NULL, and with no detail the reason is loud.
    legacy_parked = {key: value for key, value in parked_draft().items()
                     if key != "auto_merge"}
    assert busy_packages_of_pulls(repo, [legacy_parked], collapse_labels,
                                  busy_prov) == {"crate-b"}
    assert _pull_inactivity_decision(legacy_parked) == (False, "no-detail")
    print("  ok   issue-519 tripwire (c): absent listing auto_merge key stays busy")
    # malformed listing latch/draft fields also fail closed instead of collapsing into null
    assert busy_packages_of_pulls(repo, [parked_draft(auto_merge="yes")], collapse_labels,
                                  busy_prov) == {"crate-b"}
    assert busy_packages_of_pulls(repo, [parked_draft(auto_merge="yes")], collapse_labels,
                                  busy_prov, {76: confirmed_draft()}) == {"crate-b"}
    assert busy_packages_of_pulls(repo, [parked_draft(draft=None)], collapse_labels,
                                  busy_prov) == {"crate-b"}
    # parked NON-draft in the production row shape: busy
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
    # A draft with no park surface remains review-loop-owned and therefore busy.
    unparked_draft = snapshot_row(76, "sparq-agent/issue-81-1-1", draft=True,
                                  labels=["review:needs"])
    assert busy_packages_of_pulls(repo, [unparked_draft], collapse_labels,
                                  busy_prov) == {"crate-b"}
    print("  ok   issue-519 tripwire (d): non-parked draft stays busy")

    # The assembler consumes the reason from the SAME decision that reserved the crate.
    assembler_output = io.StringIO()
    with contextlib.redirect_stdout(assembler_output):
        assembler_kept = filter_busy_area_items(
            [frontier[1]], repo, [parked_draft()], collapse_labels, busy_prov,
            {76: {"head_sha": sha_a, "armed": True}}, leases=[], now=now)
    expected_assembler_log = \
        "assembler defer #71: crate crate-b busy via pr#76 [latched]"
    assert assembler_kept == [], assembler_kept
    assert assembler_output.getvalue().splitlines() == [expected_assembler_log], \
        assembler_output.getvalue()
    print("  ok   issue-519 tripwire (e): assembler defer names artifact and gate reason")
    # source-issue parks compose the same way: issue 80 is needs:user-parked; its
    # NON-draft worker PR still reserves crate-a...
    assert busy_packages_of_pulls(
        repo, [snapshot_row(75, "sparq-agent/issue-80-1-1", draft=False,
                            labels=["review:needs"])],
        collapse_labels, busy_prov) == {"crate-a"}
    # ...while its detail-confirmed parked-DRAFT twin frees it
    assert busy_packages_of_pulls(
        repo, [snapshot_row(75, "sparq-agent/issue-80-1-1", draft=True,
                            labels=["review:needs"])],
        collapse_labels, busy_prov, {75: confirmed_draft()}) == set()

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
    # enumerator skips it (human-owned), and the detail-confirmed provably-inert draft
    # frees its crates the same way (pre-fix the branch-derived linkage kept crate-c
    # reserved -> frontier collapse preserved).
    cross_parked = pull(86, "sparq-agent/issue-82-1-1", sha_a, labels=["review:needs"])
    assert busy_packages_of_pulls(repo, [cross_parked], collapse_labels,
                                  busy_prov, {86: confirmed_draft()}) == set()
    assert enumerate_review_items(repo, [cross_parked], busy_prov, [],
                                  collapse_labels, now) == []
    # ... and the SAME divergent-linkage PR with the arm latched stays busy on the
    # provenance-linked crate (P1's HELD != INACTIVE composes with P2's parity)
    assert busy_packages_of_pulls(repo, [dict(cross_parked, auto_merge=latched)],
                                  collapse_labels, busy_prov) == {"crate-a"}

    # ---- [round-4 P1] CLAIM-side PLAN->CLAIM revalidation over the LIVE pull listing ----
    def live_row(number, ref, *, draft, auto_merge=None, labels=(), sha=sha_a):
        # a raw `/pulls?state=open` listing row: unlike the PLAN projection it carries
        # BOTH `draft` and `auto_merge` from the same single read
        return dict(pull(number, ref, sha, draft=draft, labels=labels),
                    auto_merge=auto_merge)

    parked_live = live_row(76, "sparq-agent/issue-81-1-1", draft=True,
                           labels=["review:needs-user"])
    # a full raw row is its own coherent head-matched detail...
    assert live_pull_detail_stub(parked_live) == \
        {"head_sha": sha_a, "armed": False, "draft": True}
    assert live_pull_detail_stub(dict(parked_live, auto_merge=latched))["armed"] is True
    assert live_pull_detail_stub(dict(parked_live, draft="yes"))["draft"] is None
    # [round-5 P2] a garbage auto_merge shape on the live row is UNKNOWN (armed=None) —
    # the carve-out then reads BUSY instead of freeing on an unprovable latch state
    assert live_pull_detail_stub(dict(parked_live, auto_merge="garbage"))["armed"] is None
    # ...but a partial/projected row never self-confirms (missing latch or draft surface,
    # or a malformed head sha -> None -> the carve-out fails closed to BUSY)
    assert live_pull_detail_stub(pull(76, "sparq-agent/issue-81-1-1", sha_a)) is None
    assert live_pull_detail_stub(
        {k: v for k, v in parked_live.items() if k != "draft"}) is None
    assert live_pull_detail_stub(live_row(76, "x", draft=True, sha="zz")) is None
    assert live_pull_detail_stub("junk") is None

    # ---- [issue #509] CLAIM must apply the parked carve-out to its OWN live occupancy
    # read, including curator's status:blocked terminal posture, without weakening the
    # round-4/round-5 coherence guard. These are explicit mutation tripwires: deleting the
    # carve-out makes (a) red; skipping _pull_inactivity_decision makes (b)/(c) red. ----
    expected_free_log = "claim-revalidation free: crate crate-b freed via parked pr#76"
    for parked_label in ("needs:user", "review:needs-user", "status:blocked"):
        parked_output = io.StringIO()
        with contextlib.redirect_stdout(parked_output):
            parked_result = revalidate_items_against_live_pulls(
                frontier, repo,
                [[live_row(76, "sparq-agent/issue-81-1-1", draft=True,
                           labels=[parked_label])]],
                collapse_labels, busy_prov, leases=[], now=now)
        assert parked_result == {70, 71, 72, 73}, (parked_label, parked_result)
        assert expected_free_log in parked_output.getvalue(), parked_output.getvalue()
    print("  ok   claim-revalidation tripwire (a): parked draft labels free the live crate")

    needs_user_live = live_row(76, "sparq-agent/issue-81-1-1", draft=True,
                               labels=["needs:user"])
    expected_defer_log = "claim-revalidation defer #71: crate crate-b busy via pr#76"
    for coherent_busy in (dict(needs_user_live, draft=False),
                          dict(needs_user_live, auto_merge=latched)):
        busy_output = io.StringIO()
        with contextlib.redirect_stdout(busy_output):
            busy_result = revalidate_items_against_live_pulls(
                frontier, repo, [[coherent_busy]], collapse_labels, busy_prov,
                leases=[], now=now)
        assert busy_result == {70, 72, 73}, busy_result
        assert expected_defer_log in busy_output.getvalue(), busy_output.getvalue()
    print("  ok   claim-revalidation tripwire (b): non-draft or latch-visible parks stay busy")

    unparked_output = io.StringIO()
    with contextlib.redirect_stdout(unparked_output):
        unparked_result = revalidate_items_against_live_pulls(
            frontier, repo,
            [[live_row(76, "sparq-agent/issue-81-1-1", draft=True,
                       labels=["review:needs"])]],
            collapse_labels, busy_prov, leases=[], now=now)
    assert unparked_result == {70, 72, 73}, unparked_result
    print("  ok   claim-revalidation tripwire (c): live unparked draft stays busy")
    assert expected_defer_log in unparked_output.getvalue(), unparked_output.getvalue()
    print("  ok   claim-revalidation tripwire (d): defer log names crate and blocking PR")

    # the revalidation recomputes the SAME partition over the live rows: a parked draft
    # (unlatched, single-read-confirmed) still frees its crate at CLAIM time...
    assert revalidate_items_against_live_pulls(
        frontier, repo, [[parked_live]], collapse_labels, busy_prov, leases=[], now=now) \
        == {70, 71, 72, 73}
    # ...the EXACT round-4 window race — the same PR re-read NON-draft (went ready
    # between PLAN and CLAIM) — re-reserves crate-b and defers item 71...
    assert revalidate_items_against_live_pulls(
        frontier, repo, [[dict(parked_live, draft=False)]], collapse_labels,
        busy_prov, leases=[], now=now) == {70, 72, 73}
    # ...a re-latched arm on the live row re-reserves the same way...
    assert revalidate_items_against_live_pulls(
        frontier, repo, [[dict(parked_live, auto_merge=latched)]], collapse_labels,
        busy_prov, leases=[], now=now) == {70, 72, 73}
    # ...[round-5 P2] a GARBAGE auto_merge shape on the live row is UNKNOWN — busy, exactly
    # like the latched row (the old isinstance read collapsed it to unarmed and freed)...
    assert revalidate_items_against_live_pulls(
        frontier, repo, [[dict(parked_live, auto_merge="garbage")]], collapse_labels,
        busy_prov, leases=[], now=now) == {70, 72, 73}
    # ...a brand-new LIVE worker PR invisible to the PLAN reserves its crate...
    assert revalidate_items_against_live_pulls(
        frontier, repo,
        [[parked_live], [live_row(77, "sparq-agent/issue-82-1-1", draft=False)]],
        collapse_labels, busy_prov, leases=[], now=now) == {70, 71, 73}
    # ...and non-list pages / non-dict rows are skipped (the listing was already
    # shape-validated by _linked_open_pr_issues before this runs)
    assert revalidate_items_against_live_pulls(
        frontier, repo, [None, ["junk"], [parked_live]], collapse_labels, busy_prov,
        leases=[], now=now) == {70, 71, 72, 73}
    print("  ok   claim-revalidation tripwire (e): round-4/round-5 fixtures remain green")
    print("  ok   issue-519 tripwire (f): existing issue-509/516 fixtures remain green")

    # the local provenance map mirrors the PLAN precedence: legacy-first, ledger wins
    with tempfile.TemporaryDirectory() as prov_tmp:
        for root, issue_n in (("legacy", 81), ("ledger", 99)):
            prov_dir = Path(prov_tmp) / root / "orchestration" / "provenance"
            prov_dir.mkdir(parents=True)
            (prov_dir / "example--repo--pr76.json").write_text(
                json.dumps(busy_record(76, issue_n)), encoding="utf-8")
        legacy_root = str(Path(prov_tmp) / "legacy")
        ledger_dir = str(Path(prov_tmp) / "ledger")
        assert _claim_provenance_map(repo, legacy_root)[76]["issue"] == 81
        assert _claim_provenance_map(repo, legacy_root, ledger_dir)[76]["issue"] == 99
        # garbage records and foreign names are skipped, not fatal (the PR then
        # reserves fail-closed as missing-linkage)
        prov_dir = Path(prov_tmp) / "legacy" / "orchestration" / "provenance"
        (prov_dir / "example--repo--pr77.json").write_text("{not json", encoding="utf-8")
        (prov_dir / "other--repo--pr9.json").write_text("{}", encoding="utf-8")
        assert set(_claim_provenance_map(repo, legacy_root)) == {76}
        assert _claim_provenance_map(repo, str(Path(prov_tmp) / "absent")) == {}

    # the live issue-label read: PR rows skipped, malformed listings fail LOUD
    prev_live_gh = globals()["_gh_json"]
    try:
        globals()["_gh_json"] = lambda args: [[
            {"number": 81, "labels": [{"name": "area:crate-b"}, {"name": "needs:user"}]},
            {"number": 90, "labels": [{"name": "x"}], "pull_request": {}},
            {"number": "bad", "labels": []},
            {"number": 82, "labels": [{"name": 5}, "loose", {"name": "role:impl"}]},
        ]]
        assert _live_issue_labels(repo) == {81: ["area:crate-b", "needs:user"],
                                            82: ["role:impl"]}
        globals()["_gh_json"] = lambda args: "garbage"
        try:
            _live_issue_labels(repo)
        except DispatchError:
            pass
        else:
            raise AssertionError("a malformed live issue listing must fail loud")
        globals()["_gh_json"] = lambda args: ["garbage-page"]
        try:
            _live_issue_labels(repo)
        except DispatchError:
            pass
        else:
            raise AssertionError("a malformed live issue page must fail loud")
        # round-3 finding 3: a malformed COMMENTS page could hide a durable receipt
        # (round/attempt/park-generation marker) — _pr_comments must RAISE, never drop it.
        globals()["_gh_json"] = lambda args: [[{"user": {"login": "b[bot]"}}], "garbage"]
        try:
            _pr_comments(repo, 41)
        except DispatchError as exc:
            assert "comments page is malformed" in str(exc), exc
        else:
            raise AssertionError("a malformed PR comments page must fail loud")
    finally:
        globals()["_gh_json"] = prev_live_gh

    # ---- round-3 Opus finding: a maintainer probe-CALL failure emits the distinct loud
    # ::warning:: diagnostic (and still fails toward not-human); a genuine not-a-maintainer
    # permission stays quiet ----
    prev_target_api = globals()["_run_gh_target_api"]
    try:
        def broken_target_api(*_args, **_kwargs):
            raise DispatchError("target token mint failed")

        globals()["_run_gh_target_api"] = broken_target_api
        probe_out = io.StringIO()
        with contextlib.redirect_stdout(probe_out):
            assert _target_is_human_maintainer("example/repo", "jeswr") is False
        assert ("::warning::maintainer probe FAILED for example/repo actor=jeswr "
                "(DispatchError) — treating as not-human") in probe_out.getvalue(), \
            probe_out.getvalue()

        def denying_target_api(*_args, **_kwargs):
            return types.SimpleNamespace(stdout=json.dumps({"permission": "read"}))

        globals()["_run_gh_target_api"] = denying_target_api
        probe_out = io.StringIO()
        with contextlib.redirect_stdout(probe_out):
            assert _target_is_human_maintainer("example/repo", "drive-by") is False
        assert probe_out.getvalue() == "", probe_out.getvalue()

        def granting_target_api(*_args, **_kwargs):
            return types.SimpleNamespace(stdout=json.dumps({"permission": "admin"}))

        globals()["_run_gh_target_api"] = granting_target_api
        assert _target_is_human_maintainer("example/repo", "jeswr") is True

        def malformed_target_api(*_args, **_kwargs):
            return types.SimpleNamespace(stdout=json.dumps(["not", "a", "dict"]))

        globals()["_run_gh_target_api"] = malformed_target_api
        probe_out = io.StringIO()
        with contextlib.redirect_stdout(probe_out):
            assert _target_is_human_maintainer("example/repo", "jeswr") is False
        assert "maintainer probe FAILED" in probe_out.getvalue(), probe_out.getvalue()
    finally:
        globals()["_run_gh_target_api"] = prev_target_api

    # deferred-retry lease filter: a live lease suppresses the retry, expiry re-admits it
    deferred_items = [{"number": 9, "deferred": True}, {"number": 7, "deferred": False}]
    live_impl = [{"holder": f"{repo}#9@run.1", "expires_at": now + 100}]
    assert filter_deferred_items(deferred_items, repo, live_impl, now) == [
        {"number": 7, "deferred": False}]
    assert filter_deferred_items(deferred_items, repo, [], now) == deferred_items

    # Inverse-chain resolvability (locked decision 14): a CODEX alias with a missing/TBD
    # provider_model resolves to the CLI default (the proven drain passes no --model flag), so
    # the common anthropic->sol direction is live from day one; a CLAUDE alias still needs a
    # concrete id; an alias absent from routing stays unresolvable.
    routing = {"models": {"sol": {"provider_model": "TBD", "harness": "codex"},
                          "opus": {"provider_model": "claude-opus-4-8", "harness": "claude"},
                          "fable": {"provider_model": "TBD", "harness": "claude"}}}
    assert _resolvable_chain(["sol"], routing) == ["sol"]
    assert _resolvable_chain(["opus"], routing) == ["opus"]
    assert _resolvable_chain(["fable"], routing) == []
    assert _resolvable_chain(["ghost"], routing) == []
    del routing["models"]["sol"]["provider_model"]
    assert _resolvable_chain(["sol"], routing) == ["sol"]
    routing["models"]["sol"]["provider_model"] = "gpt-5.6-codex"
    assert _resolvable_chain(["sol"], routing) == ["sol"]

    # Probe-exempt chain classification (issue #115): exempt ONLY when EVERY alias maps to a
    # positively probe-exempt provider; anything else (mixed, unknown/missing provider, empty
    # chain, no catalog) is non-exempt so the require_usage hold applies. Fail-closed.
    prov_routing = {"models": {
        "sol": {"provider": "openai", "harness": "codex"},
        "luna": {"provider": "openai", "harness": "codex"},
        "opus": {"provider": "anthropic", "harness": "claude"},
        "fable": {"provider": "anthropic", "harness": "claude"},
        "mystery": {"harness": "codex"},                 # no provider field
        "typo": {"provider": "openia", "harness": "codex"},  # misspelled provider
    }}
    assert _chain_probe_exempt(["sol", "luna"], prov_routing) is True
    assert _chain_probe_exempt(["opus", "fable"], prov_routing) is False   # anthropic gated
    assert _chain_probe_exempt(["sol", "opus"], prov_routing) is False     # mixed -> gated
    assert _chain_probe_exempt(["sol", "mystery"], prov_routing) is False  # missing provider
    assert _chain_probe_exempt(["sol", "typo"], prov_routing) is False     # unknown provider
    assert _chain_probe_exempt([], prov_routing) is False                  # empty chain
    assert _chain_probe_exempt(["sol"], {}) is False                       # no catalog

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
        disarm_counts = Counter()
        _apply_disarm_items([
            {"pr_number": 13, "head_sha": "1" * 40, "reviewed_sha": "none",
             "repo": "example/repo"},
            {"pr_number": 14, "head_sha": "1" * 40, "reviewed_sha": "none",
             "repo": "example/repo"},
        ], "example/repo", Path("."), "reg[bot]", disarm_counts)
        # a failing item SKIPS (never aborts the sweep) and every call is the strict
        # mismatch-only mode — CLAIM never requests an unconditional disarm from the plan
        assert [args[4] for args in calls] == ["13", "14"], calls
        assert all(args[0] == "disarm" and args[-1] == "mismatch" for args in calls)
        # Issue #108: PR 13's raise lands in the disarm lane's ERROR tally (a stale auto-merge latch
        # that could NOT be retracted — safety-critical), while PR 14's clean retraction is a
        # `launched`. This error MUST alert the tick regardless of worker/review/fix launches, so it
        # is recorded per-lane rather than swallowed by a bare per-item skip.
        assert disarm_counts["error"] == 1 and disarm_counts["launched"] == 1, disarm_counts
        assert disarm_counts["deferred"] == 0, disarm_counts
        calls.clear()
        # No bot identity -> DEFER with NO mutation attempted, and the disarm lane records it as
        # `deferred` (never `error`): we could not even attempt the safety retraction this tick.
        no_token = Counter()
        _apply_disarm_items([{"pr_number": 15, "head_sha": "1" * 40, "reviewed_sha": "none",
                              "repo": "example/repo"}], "example/repo", Path("."), "", no_token)
        assert calls == []
        assert no_token["deferred"] == 1 and no_token["error"] == 0 \
            and no_token["launched"] == 0, no_token
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
    # whose restricted tier has ZERO usage-eligible accounts is STARVED — but ONLY on a live usage
    # signal (no probe => defer, the require_usage hold + usage-alert own that), and NEVER for
    # non-escalate routes (they starve fail-closed and retry next tick). Whether that momentary
    # starvation becomes a human terminal is escalate_persist_decision's bounded call (issue #116).
    assert escalate_starved(True, {"acct01": {}}, 0) is True
    assert escalate_starved(True, {}, 0) is True            # empty-but-present map still signals
    assert escalate_starved(True, None, 0) is False         # no probe -> unknown -> defer
    assert escalate_starved(True, {"acct01": {}}, 1) is False
    assert escalate_starved(False, {"acct01": {}}, 0) is False
    assert escalate_starved(None, {"acct01": {}}, 0) is False

    # Issue #116: a starved escalate route must NOT convert one transient usage snapshot into a
    # permanent human terminal. escalate_persist_decision separates the momentary-starved predicate
    # (escalate_starved, above) from the bounded, PERSISTENT decision to escalate to needs:user.
    now116 = 1_800_000_000
    attempt = "<!-- sparq-worker-attempt:v1"  # worker_issue.ATTEMPT_MARKER (durable receipt format)
    iso116 = lambda ago: time.strftime(  # noqa: E731 — trivial epoch->ISO helper for the fixtures
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now116 - ago))
    starve = lambda ago: {"user": {"login": "app[bot]"},  # noqa: E731
                          "body": f"ops alert {STARVE_ALERT_MARKER}", "created_at": iso116(ago)}
    # (i) FIRST observation (no prior receipt): defer + alert, never escalate. THIS is the
    # regression the issue names — a single snapshot going straight to needs:user.
    assert escalate_persist_decision([], "app[bot]", now116, attempt) == (False, "")
    # (ii) a fresh alert (well within the grace) still defers — transient, keep retrying.
    assert escalate_persist_decision([starve(60)], "app[bot]", now116, attempt) \
        == (False, iso116(60))
    # (iii) an alert streak that has PERSISTED past the grace escalates to a human, reporting the
    # streak's OLDEST receipt (bounded persistent failure, not one blip).
    persisted = [starve(ESCALATE_PERSIST_SECONDS + 120), starve(300)]
    assert escalate_persist_decision(persisted, "app[bot]", now116, attempt) \
        == (True, iso116(ESCALATE_PERSIST_SECONDS + 120))
    # (iv) RECOVERY RESETS the clock: a worker attempt receipt AFTER an old alert means capacity
    # recovered and dispatched; a later alert begins a fresh transient streak, so an old
    # past-grace alert can no longer force an immediate terminal on the new episode.
    recovered = [starve(ESCALATE_PERSIST_SECONDS + 600),
                 {"user": {"login": "app[bot]"}, "body": f"{attempt} run=7 -->",
                  "created_at": iso116(ESCALATE_PERSIST_SECONDS + 300)},
                 starve(120)]
    assert escalate_persist_decision(recovered, "app[bot]", now116, attempt) \
        == (False, iso116(120))
    # (v) only the bot's own receipts count — a spoofed alert from another login is ignored, so a
    # third party cannot fabricate persistence to force a needs:user terminal.
    spoof = [{"user": {"login": "someone"}, "body": STARVE_ALERT_MARKER,
              "created_at": iso116(ESCALATE_PERSIST_SECONDS + 999)}]
    assert escalate_persist_decision(spoof, "app[bot]", now116, attempt) == (False, "")
    # (vi) RECOVERY WITHOUT A WORKER ATTEMPT still resets the streak (issue #116 round 1). Capacity
    # refilled — a live-recovery receipt — but no worker started (allocator found no slot / the
    # launch failed / a later hold intervened). An old past-grace alert BEFORE that reset is stale,
    # so a fresh post-reset alert opens a NEW transient streak and does NOT escalate. This is the
    # exact counterexample the attempt-only reset missed: observed recovery, then a first fresh
    # snapshot, must not read as continuously starved.
    reset = lambda ago: {"user": {"login": "app[bot]"},  # noqa: E731
                         "body": f"recovered {STARVE_RESET_MARKER}", "created_at": iso116(ago)}
    recovered_noattempt = [starve(ESCALATE_PERSIST_SECONDS + 600),
                           reset(ESCALATE_PERSIST_SECONDS + 300),
                           starve(120)]
    assert escalate_persist_decision(recovered_noattempt, "app[bot]", now116, attempt) \
        == (False, iso116(120))
    # (vii) a reset must NOT suppress a GENUINELY persistent NEW streak: an old reset followed by a
    # post-reset alert that has itself aged past the grace still escalates to a human (fail-closed
    # toward the human terminal when starvation is truly continuous after recovery).
    persisted_after_reset = [reset(ESCALATE_PERSIST_SECONDS + 900),
                             starve(ESCALATE_PERSIST_SECONDS + 60)]
    assert escalate_persist_decision(persisted_after_reset, "app[bot]", now116, attempt) \
        == (True, iso116(ESCALATE_PERSIST_SECONDS + 60))
    # (viii) escalate_recovery_pending gates the reset-receipt write: True while an alert is open,
    # then False once a reset (or attempt) supersedes every alert — exactly one receipt per streak
    # (no per-tick spam), and nothing to write when there was never an alert.
    assert escalate_recovery_pending([], "app[bot]", attempt) is False
    assert escalate_recovery_pending([starve(120)], "app[bot]", attempt) is True
    assert escalate_recovery_pending([starve(600), reset(300)], "app[bot]", attempt) is False
    attempt_closed = [starve(600), {"user": {"login": "app[bot]"},
                                    "body": f"{attempt} run=9 -->", "created_at": iso116(300)}]
    assert escalate_recovery_pending(attempt_closed, "app[bot]", attempt) is False
    # a post-reset alert is once again an OPEN streak (recovery recurred into a new shortage).
    assert escalate_recovery_pending(recovered_noattempt, "app[bot]", attempt) is True

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
