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
import inspect
import io
import json
import os
from pathlib import Path
import re
import subprocess
import types
import sys
import urllib.parse
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
# v4 -> v5 (registry #677): the plan carries `partition_starvation` — the ONE fact about a
# starved tick that CLAIM cannot recompute for itself. CLAIM re-reads the live pull listing, so it
# can re-derive WHO holds the serializing `__global__` partition; what it cannot re-derive is how
# many READY issue rows the busy partition dropped, because the plan only carries the SURVIVORS.
# Without that count, "planned == 0" cannot be told apart from "the backlog is empty" — and parking
# a holder on an empty backlog is pure cost. This field carries the count, and nothing else: the
# holder itself is RE-PROVEN live at CLAIM time, so a hostile plan can at most make CLAIM look for
# a starvation that the live state then refuses to confirm. It can never name a PR to park.
SCHEMA = "registry-dispatch-plan/v5"
PLAN_FIELDS = {"schema", "generated_at", "repositories", "review_items", "disarm_items",
               "snapshot_skips", "partition_starvation"}
REPOSITORY_FIELDS = {"target_repo", "target_sha", "items"}
PARTITION_STARVATION_FIELDS = {"repo", "deferred"}
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
    # [OPUS-5 #657] True iff this item was admitted by the orchestrator-class path, i.e. its
    # provenance record is SELF-attested. REQUIRED, not optional, and validated below: every
    # consumer that resolves a reviewer side or an arm decision has to see it, and
    # _require_exact_fields makes a producer that forgets to emit it fail loudly instead of
    # defaulting the safe-looking way. False for every worker-lane item.
    "self_attested",
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
# reviewer of anthropic-authored content (luna is its fallback); opus5 (Opus 5) is the SOLE
# anthropic tier and reviews openai-authored content.
# [OPUS-5] 2026-07-26 ("deprecate the use of fable and opus entirely in favour of opus5"): the
# opus/fable tail fallbacks are GONE from both tables. The degradation path they provided is
# replaced by an EXPLICIT exit, not by silence — `_resolvable_chain` returning [] calls
# _pr_needs_user(), so an opus5 outage parks the PR for a human instead of quietly serving it
# from a retired model. terra and sonnet remain DOCS-ONLY and must NEVER appear in a review/fix
# chain (asserted in _self_test; review-fix.yml + worker-pr.py ESCALATION_LADDERS enforce the
# same). The retired aliases are asserted out of BOTH tables at import time, below.
REVIEW_CHAIN = {"anthropic": ["sol", "luna"], "openai": ["opus5"]}
# FIX_CHAIN is the UNPINNED allocator PREFERENCE walk (strongest tier FIRST — choose_account
# takes the first serving account, and the frontier tier leads per the sol-first doctrine;
# the anthropic walk is opus5 ALONE since the 2026-07-26 deprecation).
# It is deliberately the REVERSE of worker_pr.ESCALATION_LADDERS, which are capability-
# ASCENDING (weakest first, terminal strongest LAST; capability order luna < opus5 < sol since
# the 2026-07-26 deprecation removed opus and fable from the order entirely) and govern
# exhaustion escalation + pinned floors (sol r2 f2 fixed the previously inverted ladders).
FIX_CHAIN = {"anthropic": ["opus5"], "openai": ["sol", "luna"]}
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
# "not probed yet" sentinel for the per-PR readmission-cutoff memo (#555 recurrence gap): the
# cutoff's own falsy value (None = no proven human gesture) is a MEANINGFUL result, so it cannot
# double as the not-yet-read marker.
_UNPROBED = object()
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
    sections (registry issue #112) — DELEGATED to lease_schema.plan_package, which is the one
    canonical reduction.

    It used to be a local copy carrying a comment promising it "mirrors dispatch-plan.py
    byte-for-byte". That promise held; the one it did NOT make — that review-fix.yml's `resolve`
    job derives the same value — is the one that broke, and a prose promise is not a test. The
    adopt step compares the dispatcher's minted `package` against resolve's re-derived `package`
    for EQUALITY, so a third un-migrated copy turned every multi-area PR into a claim the
    dispatcher minted and the adopter refused, forever. Sharing the function removes the drift
    axis entirely; `_plan_package_agreement()` in the self-test pins the one copy that CANNOT
    share it (dispatch-plan.py ships in the target repos, which have no lease_schema.py)."""
    return _lease_schema.plan_package(areas)


class DispatchError(RuntimeError):
    """A concise fail-closed error suitable for Actions logs."""


class RouteDivergenceError(DispatchError):
    """PLAN's planned route and CLAIM's re-derivation of it disagree.

    A SUBCLASS, because the failure mode is categorically different from the other per-item
    trust/policy failures this dispatcher tolerates. Those are situational — a stale issue, a
    revoked token, a lost race — and clear on their own. This one is a pure function of the item's
    labels and the target's protected routing table, so it recurs on EVERY tick with the identical
    result: the affected issues never dispatch again. It means the two resolvers implement
    different rules, which is an operator-visible configuration outage rather than a deferral.
    """


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise DispatchError(f"cannot load registry helper {Path(path).name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# [OPUS-5] The deprecation register is IMPORTED, not re-declared — a second hand-maintained copy
# of the retired-alias list is how a model returns in one of them. Asserting at MODULE SCOPE means
# a retired alias reintroduced into either table fails on import, i.e. on the PR that does it,
# rather than on a live dispatch tick where it would surface as a mystery needs:user park.
_deprecated_models = _load_module(
    "registry_deprecated_models",
    str(Path(__file__).resolve().with_name("deprecated_models.py")))
_deprecated_models.assert_table_clean("REVIEW_CHAIN", REVIEW_CHAIN)
_deprecated_models.assert_table_clean("FIX_CHAIN", FIX_CHAIN)

# Shared park-label policy (park_policy.py): the round-budget human-readmission window
# (readmission_cutoff) consumed by the CLAIM review loop. Loaded at module scope, same idiom as
# groom.py, so the per-item review sweep never re-imports it.
_park_policy = _load_module(
    "registry_park_policy", Path(__file__).resolve().with_name("park_policy.py"))

# Shared bounded-retry mechanics for IDEMPOTENT gh reads (registry #563 adoption item 4;
# sparq#3759 / #558 transient-red class). READ paths ONLY: _gh_json and _run_gh_target_api GETs.
# The ledger CAS writers, `gh workflow run` dispatch realizations, label flips, and comment posts
# keep their deliberate fail-loud single-attempt semantics (#558's own design) — a replayed
# mutation could double-dispatch a worker, which is exactly incident #559's storm class.
_gh_retry = _load_module(
    "registry_gh_retry", Path(__file__).resolve().with_name("gh_retry.py"))

# THE canonical area->package partition reduction, shared with review-fix.yml's `resolve` job and
# worker.yml's self-claim + adopt steps (the other independent derivers of this value) so an adopt
# step's equality check can never reject a claim this module minted. See lease_schema.plan_package
# for the 2026-07-26 incident.
_lease_schema = _load_module(
    "registry_lease_schema", Path(__file__).resolve().with_name("lease_schema.py"))

# [OPUS-5] registry #701. THE no_change routing decision: a worker exit that produced no diff must
# not re-dispatch the tier that produced it. Same shared-module idiom — the vocabulary and the
# decision live in ONE place, consumed here (routing), by model-health (storage), and by
# worker-live.sh (production).
_no_change_routing = _load_module(
    "registry_no_change_routing", Path(__file__).resolve().with_name("no_change_routing.py"))


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
    # [registry #677] Same doctrine for the starvation evidence: ONE production sort, called by
    # the PLAN assembler, so the deterministic order validate_plan demands is produced by the code
    # the self-test exercises rather than by an inline workflow sort that can drift.
    document["partition_starvation"].sort(key=lambda entry: entry["repo"])
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
        if not isinstance(item["self_attested"], bool):
            raise DispatchError(f"{where} self_attested must be boolean")
        # The review-only invariant, re-asserted at the SCHEMA boundary (issue #657). The
        # enumerator already refuses to emit anything else for the class, but PLAN and CLAIM are
        # different processes reading a serialised artifact: a hand-edited or
        # future-producer-mangled plan must not be able to hand CLAIM a self-attested item in a
        # code-writing state. Two independent gates, one invariant.
        if item["self_attested"] and state != "needs-review":
            raise DispatchError(
                f"{where} is self-attested but in state {state!r} — the orchestrator class is "
                "review-only (research/657-orchestrator-pr-admission.md Option 2(b))")
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
    # [registry #677] The starvation evidence. Validated as strictly as every other plan section
    # because the plan is HOSTILE INPUT: it is assembled in a job that ran target planner code.
    # It can only ever ASSERT a count for a repository the plan already carries — it names no PR,
    # so no plan value can select the PR this evidence eventually leads CLAIM to park.
    starvation = document["partition_starvation"]
    if not isinstance(starvation, list):
        raise DispatchError("plan partition_starvation must be a list")
    prior_starved = None
    seen_starved = set()
    for starved_index, entry in enumerate(starvation, 1):
        where = f"partition starvation #{starved_index}"
        _require_exact_fields(entry, PARTITION_STARVATION_FIELDS, where)
        repo = _safe_string(entry["repo"], SAFE_REPO, f"{where} repo")
        if repo not in seen_repositories:
            raise DispatchError(f"{where} repo is not a planned repository")
        deferred = entry["deferred"]
        if not isinstance(deferred, int) or isinstance(deferred, bool) or deferred <= 0:
            raise DispatchError(f"{where} deferred must be a positive integer")
        if repo in seen_starved:
            raise DispatchError(f"plan repeats partition starvation for {repo}")
        seen_starved.add(repo)
        if prior_starved is not None and repo < prior_starved:
            raise DispatchError("plan partition starvation entries are not in deterministic order")
        prior_starved = repo
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


# The rank instant for a check-run whose started_at cannot be parsed (round-6 finding 1):
# the oldest representable aware instant, so unparseable data never beats a parseable stamp.
_CHECK_RUN_EPOCH = _park_policy.parse_ts("0001-01-01T00:00:00Z")


def interpret_check_runs(check_runs, log=print):
    """PURE interpreter for a commit's check-runs listing (hostile-tolerant: malformed input
    degrades to gate=unknown, never a crash and never an ACT). Re-runs of the same check name
    are superseded by the latest `started_at`, ordered by PARSED INSTANT
    (park_policy.parse_ts — round-6 finding 1: the old raw-string compare read an older
    failed gate "2026-07-23T09:00:00Z" as newer than a successful rerun spelled
    "2026-07-23 10:00:00Z" — the space sorts before "T" — retaining the stale failure, so
    the needs-ci-fix admission dispatched a fixer against a green head). A run with a
    malformed/unparseable `started_at` ranks OLDEST with a loud log — unparseable data can
    never supersede a parseable stamp (two unparseable stamps keep the old last-listed-wins
    tie rule). Returns {"gate", "failing_legs"} where gate is one of
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
        started_raw = run.get("started_at")
        try:
            # Rank tuples order parseable (1, instant) strictly above every unparseable
            # (0, epoch) entry, so hostile/garbage stamps can only LOSE to real ones.
            started = (1, _park_policy.parse_ts(started_raw))
        except ValueError:
            started = (0, _CHECK_RUN_EPOCH)
            log(f"::warning::check-run {_sanitize_leg(name)!r} carries an unparseable "
                f"started_at {str(started_raw)[:64]!r} — ranked OLDEST (an unparseable "
                "stamp never supersedes a parseable rerun)")
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
                occupancy.append(("parked-free", number, frozenset(areas), reason, inactive))
            continue                      # provably inert human-parked PR — frees its crates
        if isinstance(occupancy, list):
            # [registry #677] The 5th element is `inactive` — the SAME _pull_inactivity_decision
            # bit the parked-free carve-out above turns on, carried out to the caller instead of
            # being discarded. The starvation sweep needs it and must NOT re-derive it: a second
            # copy of "would parking this PR actually free its crates?" is exactly the
            # mint-vs-adopt drift #707 exists to prevent. For an UN-parked PR the `reason` slot
            # says only "not-parked", so without this the answer is unrecoverable downstream.
            occupancy.append(("busy", number, frozenset(areas),
                              reason if parked else "not-parked", inactive))
        busy |= areas
    return busy


def filter_busy_area_items(items, repo, pulls, issue_labels, provenance, pr_status=None,
                           leases=None, now=0, starvation=None):
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
    sibling_lease_conflict's ambiguity rule — callers must pass the real ledger list.

    [registry #677] `starvation`, when a dict is passed, is filled with the ONE measurement CLAIM
    cannot recompute: `deferred` = how many READY issue rows this partition dropped while some
    occupant held the serializing `__global__` package, and `kept` = how many survived. The plan
    artifact carries only the survivors, so without this a starved tick (`kept == 0` because one
    PR reserves all 54 crates) is indistinguishable downstream from an EMPTY BACKLOG — and the
    self-healing sweep must never fire on an empty backlog. Counted here, at the exact branch that
    makes the decision, rather than re-derived later from a different view."""
    occupancy = []
    busy = busy_packages_of_pulls(
        repo, pulls, issue_labels, provenance, pr_status, occupancy=occupancy)
    global_reserved = GLOBAL_PACKAGE in busy
    global_deferred = 0
    kept = []
    for item in items:
        package = item.get("package")
        if busy and (GLOBAL_PACKAGE in busy or package == GLOBAL_PACKAGE or package in busy):
            blocker = next(
                ((pr_number, reason)
                 for decision, pr_number, packages, reason, *_ in occupancy
                 if decision == "busy" and
                 (GLOBAL_PACKAGE in packages or package == GLOBAL_PACKAGE or package in packages)),
                ("unknown", "unknown"))
            print(f"assembler defer #{item.get('number')}: crate {package} busy via "
                  f"pr#{blocker[0]} [{blocker[1]}]")
            # Only a drop that a `__global__` OCCUPANT caused is starvation evidence. An item
            # dropped because its OWN package is `__global__`, or because a sibling holds its one
            # crate, is the partition working as designed and no park would help it.
            if global_reserved:
                global_deferred += 1
            continue
        if sibling_lease_conflict(
                repo, {f"{repo}#{item.get('number')}"},
                {package} if isinstance(package, str) else set(),
                leases, now):
            print(f"exclude {repo}#{item.get('number')}: superseded-until-sibling-resolves — "
                  "a live sibling lease (any lane) holds its package")
            continue
        kept.append(item)
    if isinstance(starvation, dict):
        starvation["deferred"] = global_deferred
        starvation["kept"] = len(kept)
    return kept


# [registry #677] How many `__global__` holders ONE tick may park, per target repository. One.
# The recurrence in #677 is that parking a holder by hand simply PROMOTES the next one, so a
# sweep that drained the whole holder set in a single tick would be exactly that mistake
# automated — it would park PRs whose reservation was never the binding one, and each park costs
# real review progress. One per tick converges over ticks (each park frees the partition and the
# NEXT tick re-measures whether the lane is still starved) and never over-shoots.
STARVATION_PARKS_PER_TICK_MAX = 1


def starvation_park_target(planned_items, deferred, occupancy, log=print):
    """PURE. The ONE `__global__` occupant to park because the issue lane is STARVED, or None.

    This is the trigger for the self-healing sweep in registry #677. It fires on the MEASURED
    condition, never on a timer, and every clause below is load-bearing:

    - `planned_items` must be EMPTY. While the lane is planning anything at all the plan is
      healthy, and parking a holder would cost review progress to buy throughput that is already
      flowing. This is the "do not park while healthy" guard.
    - `deferred` must be POSITIVE. It is filter_busy_area_items' count of ready rows dropped while
      a `__global__` occupant was reserving everything. Zero means the backlog is genuinely empty,
      which is not starvation and must never park anybody.
    - The occupant must be BUSY (not already parked-free), must hold `__global__`, and must be
      UN-PARKED. An already-parked holder is skipped, which is what makes the sweep IDEMPOTENT:
      re-running it against its own output selects nobody.
    - The occupant must be provably INACTIVE (_pull_inactivity_decision, carried out of
      busy_packages_of_pulls rather than re-derived). THIS IS THE CLAUSE THAT MAKES THE ACTION
      USEFUL RATHER THAN MERELY EXPENSIVE: busy_packages_of_pulls frees a parked PR's crates only
      when it is `parked AND inactive`, so parking an ACTIVE (non-draft, or latched, or
      unprovable) holder writes a label, costs that PR its place in the review lane, and does not
      free one single crate. Registry #677 measured exactly that outcome by hand. A holder whose
      park would not demonstrably free the partition is not a candidate.

    Deterministic and bounded: candidates are considered in ascending PR number and exactly one is
    returned, so at most STARVATION_PARKS_PER_TICK_MAX == 1 holder is parked per repository per
    tick, and two runs over the same input pick the same PR."""
    if planned_items:
        return None                       # the plan is HEALTHY — never park a holder
    if not isinstance(deferred, int) or isinstance(deferred, bool) or deferred <= 0:
        return None                       # nothing was starved (empty backlog / unreadable count)
    candidates = []
    for row in occupancy if isinstance(occupancy, list) else []:
        if not isinstance(row, tuple) or len(row) < 5:
            continue                      # an occupancy shape this function cannot read is not
            # evidence to act on — fail toward parking NOBODY
        decision, pr_number, packages, reason, inactive = row[:5]
        if decision != "busy":
            continue
        if GLOBAL_PACKAGE not in packages:
            continue                      # holds real crates, not the serializing partition
        if reason != "not-parked":
            continue                      # already parked (its park simply is not freeing it)
        if inactive is not True:
            continue                      # parking it would NOT free the partition
        if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
            continue
        candidates.append(pr_number)
    if not candidates:
        log("starvation sweep: the issue lane planned 0 item(s) behind "
            f"{deferred} partition-deferred row(s), but no UN-PARKED, provably-inert "
            f"`{GLOBAL_PACKAGE}` holder was found — parking nobody")
        return None
    target = min(candidates)
    log(f"starvation sweep: issue lane planned 0 item(s) while {deferred} ready row(s) deferred "
        f"behind the `{GLOBAL_PACKAGE}` partition; {len(candidates)} un-parked inert holder(s) "
        f"{sorted(candidates)} — parking pr#{target} (cap {STARVATION_PARKS_PER_TICK_MAX}/tick)")
    return target


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
                                        leases=None, now=0, occupancy=None):
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
    leases=None fails toward exclusion.

    [registry #677] `occupancy`, when a list is passed, receives the LIVE occupancy rows this
    function already computes. The starvation sweep acts on the live view — never on the PLAN
    artifact's minutes-old one — and it must read the SAME view that the launch decision reads:
    two independent derivations of "who holds `__global__`" is the drift class #707 exists to
    prevent. Nothing here is re-derived for the sweep; the rows are simply not thrown away."""
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
    live_occupancy = occupancy if isinstance(occupancy, list) else []
    busy = busy_packages_of_pulls(
        repo, rows, issue_labels, provenance, live_status,
        parked_pr_labels=CLAIM_REVALIDATION_PARK_LABELS, occupancy=live_occupancy)

    for decision, pr_number, packages, _reason, *_ in live_occupancy:
        if decision == "parked-free":
            for package in sorted(packages):
                print(f"claim-revalidation free: crate {package} freed via parked pr#{pr_number}")

    dispatchable = set()
    for item in items:
        number = item["number"]
        package = item.get("package")
        if busy and (GLOBAL_PACKAGE in busy or package == GLOBAL_PACKAGE or package in busy):
            blocker = next(
                (pr_number for decision, pr_number, packages, _reason, *_ in live_occupancy
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


# --- provenance ATTESTATION CLASSES (issue #657) --------------------------------------------------
# The trust BASIS an implementer-provenance record rests on, derived ONLY from the shape of its
# `recorded_at_run` stamp.
#
# MACHINE-ATTESTED (admissible) — the stamp names a GitHub Actions run that wrote the record
# HOST-SIDE, in a job that executes no target code and that the implementing model could not
# influence:
#   "<run>.<attempt>"              worker.yml's dedicated `provenance` job, after publish
#   "backfill:<run>.<attempt>"     backfill-provenance.yml / scripts/backfill-provenance.py
#
# SELF-ATTESTED (recognised, NAMED, and REFUSED here) — the record was written by an actor holding
# a registry credential (an orchestrator, or a maintainer running a script by hand), i.e. by
# something that may ALSO have authored the diff:
#   "orchestrator:<run>.<attempt>"
# The review lane resolves the REVIEWER by inverting this record's `impl_provider`. In a
# self-attested record that field is an assertion by the implementer about itself, so admitting
# the class would let a record choose its own reviewer's provider — silently collapsing the
# cross-provider inversion into a same-provider review that still LOOKS cross-provider. It is
# refused under its OWN diagnostic (never the generic malformed-stamp one) so that an audit can
# tell which trust basis every record rests on, and so a future admission path for the class has a
# discriminator that already exists in the schema and in every consumer.
#
# HONEST SCOPE — this taxonomy is a fail-closed hardening plus the distinguishability primitive,
# NOT an anti-forgery guarantee: an actor with registry write can simply write a machine-shaped
# stamp instead. The property that survives a forged provider declaration is not encoded here; it
# is "never read the declared provider to pick the reviewer". See
# research/657-orchestrator-pr-admission.md.
# The SELF-ATTESTED class: the actor that wrote the diff also wrote the record. Named here so
# the stamp table, the admission opt-in and the enumerator all spell it ONE way — a rename that
# reaches only the table would silently make the opt-in below unreachable, i.e. a quiet revert.
ORCHESTRATOR_CLASS = "orchestrator"
PROVENANCE_ATTESTATION_STAMPS = (
    ("worker-run", re.compile(r"\d+\.\d+")),
    ("backfill", re.compile(r"backfill:\d+\.\d+")),
    (ORCHESTRATOR_CLASS, re.compile(r"orchestrator:\d+\.\d+")),
)
# Deliberately EXCLUDES ORCHESTRATOR_CLASS — admitting it is an explicit, per-consumer opt-in
# (provenance_admission_error(..., admit_orchestrator=True)), never a property of the taxonomy.
MACHINE_ATTESTED_CLASSES = frozenset({"worker-run", "backfill"})
# Consumer-facing refusal reasons (CLAIM defer lines, review-fix.yml SystemExit). Named constants
# because the self-test pins them: collapsing the two into one reason destroys exactly the
# audit distinction — "nobody stamped this" vs "an actor holding a registry credential stamped its
# own work" — that this class exists to preserve.
ATTESTATION_UNRECOGNISED_REASON = (
    "provenance attestation stamp is missing or malformed (recorded_at_run must name the "
    "host-side run that wrote the record)")


def attestation_not_machine_reason(attestation):
    """The refusal reason for a RECOGNISED but self-attested provenance class."""
    return (f"provenance record is {attestation}-attested, not machine-attested (the review "
            "loop admits only records written host-side by a run the implementing model could "
            "not influence)")


def provenance_attestation_class(record):
    """Return the ATTESTATION CLASS of provenance ``record`` — the trust basis its implementer
    identity rests on — or None when it carries no stamp in a recognised shape.

    Derived ONLY from `recorded_at_run`, matched FULL-STRING against the closed
    PROVENANCE_ATTESTATION_STAMPS table; a missing, wrong-typed, malformed, or unknown-prefix
    stamp is None (fail closed). Never raises: like provenance_admission_error this runs inside
    the PLAN/groom walk, where an exception aborts the whole run instead of parking one orphan."""
    stamp = record.get("recorded_at_run") if isinstance(record, dict) else None
    if not isinstance(stamp, str):
        return None
    for name, pattern in PROVENANCE_ATTESTATION_STAMPS:
        if pattern.fullmatch(stamp):
            return name
    return None


def provenance_admission_error(record, pr_number, *, admit_orchestrator=False):
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
      assertion, review-fix.yml resolve),
    - a MACHINE-ATTESTED ``recorded_at_run`` stamp (issue #657): the record must have been
      written host-side by a run the implementing model could not influence. See
      PROVENANCE_ATTESTATION_STAMPS. Until #657 this field was never inspected at admission, so
      a record carrying no stamp at all — or a hand-written one — was admitted at FULL worker-run
      trust and its self-declared ``impl_provider`` chose the reviewer.

    EVERY consumer calls this ONE function — enumerate_review_items (PLAN), the CLAIM record
    re-read below, review-fix.yml's resolve step (imports this module from the registry
    checkout), and groom.py's draft age-park carve-out (is_enumerable_provenance): a stale
    draft worker PR is review-loop-owned (exempt from the terminal needs:user park) exactly
    when this returns None. Adding a field constraint HERE updates every consumer in the same
    commit — the partial-replica drift that groom-preserved a review-rejected draft (round-3
    finding: alias/issue unchecked) is structurally impossible to reintroduce.

    ``admit_orchestrator`` (issue #657, research/657-orchestrator-pr-admission.md §6) is the
    ONE opt-in that relaxes the machine-attestation requirement, and only to the recognised
    ``orchestrator`` class. It DEFAULTS FALSE, so every existing caller keeps refusing that
    class byte-for-byte — the shared predicate stays fail-closed and a new consumer inherits
    the strict posture unless it names the relaxation.

    It is a PARAMETER rather than a widening of MACHINE_ATTESTED_CLASSES because the class is
    NOT safe for every consumer. An orchestrator record is self-attested: the actor that wrote
    the diff also wrote the record, so its ``impl_provider`` is an assertion about itself and
    nothing may INVERT that field to pick a reviewer. Consumers that only READ a PR are safe;
    consumers that PUSH CODE or ARM on the record's authority are not. Passing True is
    therefore a per-consumer decision that has to be written down and tested:
      admit_orchestrator=True   enumerate_review_items (review-only states; see its docstring)
      admit_orchestrator=False  everything else, including groom's draft carve-out and every
                                fix/rebase path — an orchestrator PR is not a pipeline-owned
                                draft and the fix lane must never push to one."""
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
    # ATTESTATION BASIS (issue #657), last so every field diagnostic above keeps its exact text.
    # Two SEPARATE refusals on purpose — an unrecognised stamp and a recognised-but-self-attested
    # one are different audit facts, and the second is the discriminator a future admission path
    # for orchestrator-authored PRs will key on. Measured on the live `ledger` branch 2026-07-26:
    # 350 records, 349 machine-attested (`<run>.<attempt>` / `backfill:...`), 1 hand-stamped
    # `human:30209757201.1` — which this refuses, on an already-MERGED PR (sparq#4185).
    attestation = provenance_attestation_class(record)
    if attestation is None:
        return ATTESTATION_UNRECOGNISED_REASON
    admitted = MACHINE_ATTESTED_CLASSES | ({ORCHESTRATOR_CLASS} if admit_orchestrator else set())
    if attestation not in admitted:
        return attestation_not_machine_reason(attestation)
    return None


def is_enumerable_provenance(record, pr_number):
    """True iff the review loop will admit target PR ``pr_number``'s provenance record —
    a thin predicate over provenance_admission_error (the single source of truth; see its
    docstring for the field set and the consumer list).

    Deliberately has NO orchestrator opt-in: its callers (groom's draft age-park carve-out) ask
    "is this a pipeline-owned worker draft?", and an orchestrator PR is not one."""
    return provenance_admission_error(record, pr_number) is None


def admits_orchestrator_pr(record, pr_number, login, enrolled_authors):
    """True iff PR ``pr_number`` qualifies for the #657 orchestrator-class review admission.

    TOTAL and fail-closed — never raises, and returns False for every malformed input, because
    it runs inside the PLAN walk where an exception aborts the whole tick instead of skipping
    one PR. It is a PREDICATE ONLY: it decides that the head-ref and author SHAPE gates may be
    waived for this PR, and nothing else. The fork gate, the provenance FIELD admission, the
    human holds, the machine parks, the source-issue hold and every lease rule are applied by
    the caller either side of it and are not waivable.

    Both halves are required, and they are deliberately sourced from branches of DIFFERENT
    authority (see policy-resolve.review_enrolment_authors):
    - ``record`` is `orchestrator`-attested. Records live on the unprotected `ledger` branch
      (issue #96), so this half is a low-authority, per-PR gesture.
    - ``login`` is in ``enrolled_authors``, the repo's master-protected allowlist, compared
      CASEFOLDED because GitHub logins are case-insensitive. A `[bot]` login can never appear
      there (policy-resolve refuses one), so this path cannot be used to widen the author gate
      to some other App.

    An EMPTY ``enrolled_authors`` — the default, and the shipped state for every repo — makes
    this constantly False, so the enumerator's behaviour is byte-for-byte unchanged until a
    reviewed master commit opts a login in."""
    if not enrolled_authors or not isinstance(login, str) or not login:
        return False
    if provenance_attestation_class(record) != ORCHESTRATOR_CLASS:
        return False
    # The record must still BE this PR's record. Without this, an orchestrator record minted
    # for PR #7 would waive the shape gates on PR #9 — the field admission below would then
    # reject #9, but the waiver decision itself must not depend on a later check to be sound.
    number = record.get("pr_number") if isinstance(record, dict) else None
    if not isinstance(number, int) or isinstance(number, bool) or number != pr_number:
        return False
    return login.casefold() in {
        author.casefold() for author in enrolled_authors if isinstance(author, str)
    }


def enumerate_review_items(repo, pulls, provenance, leases, issue_labels, now, bot_login="",
                           pr_status=None, exclusions=None, enrolled_authors=()):
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
        # FORK GATE FIRST, and unconditional (issue #657 admission). It used to sit BETWEEN the
        # two shape gates, which was safe only because nothing could skip them. Now that the
        # orchestrator admission below waives the head-ref and author gates, the fork gate has
        # to be the one no waiver can reach — so it is hoisted above every waivable predicate
        # rather than left to the accident of ordering. `head_repo != repo` is the single
        # attacker-facing predicate here: a fork head is attacker-controlled and is NEVER
        # reviewed, admitted, or enrolled, on any path.
        if head_repo != repo:
            exclude_signalled("head repo is not the target repo")
            continue
        record = provenance.get(number)
        # ORCHESTRATOR-PR ADMISSION (issue #657 / research/657-orchestrator-pr-admission.md §6,
        # Option 2(b)). The two gates below select the population the WORKER lane produces. A PR
        # the orchestrator authored itself is invisible to every path that can run a model
        # against a PR — measured on sparq 2026-07-27: 30 of 34 open non-draft PRs, all
        # `jeswr`-authored, ALL failing BOTH gates, 0 holding any ledger verdict.
        #
        # `admits_orchestrator_pr` is a pure conjunction of TWO independently-authored facts:
        # an `orchestrator`-attested record on the `ledger` branch, and the PR author's login in
        # the repo's MASTER-protected `review_enrolment_authors`. Neither alone admits anything.
        # Default is an EMPTY allowlist, i.e. the gates below stand exactly as they do today.
        orchestrator_admitted = admits_orchestrator_pr(record, number, login, enrolled_authors)
        if not orchestrator_admitted and not HEAD_REF_RE.match(ref):
            exclude_signalled("head ref is not a worker branch")
            continue
        if not orchestrator_admitted and (
                not login.endswith("[bot]") or (bot_login and login != bot_login)):
            exclude_signalled("author is not the trusted App bot")
            continue
        record_error = provenance_admission_error(
            record, number, admit_orchestrator=orchestrator_admitted)
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
            # REVIEW-ONLY for the #657 orchestrator class (design record Option 2(b)). ONE
            # choke point on purpose: every state this enumerator can produce passes through
            # here, so the restriction cannot be defeated by a later branch that learns to
            # emit a new state. `needs-review` posts a comment; every other state dispatches a
            # run that PUSHES COMMITS to the PR head (needs-fix / needs-ci-fix / needs-rebase)
            # or re-enters the arm path (stranded). A self-attested record must never buy write
            # access to its own branch: the actor that wrote the record wrote the diff.
            if orchestrator_admitted and state != "needs-review":
                exclude_signalled(
                    f"orchestrator-class PR is review-only; {state} would dispatch a "
                    "code-writing run on a self-attested record")
                return
            items.append({
                "pr_number": number,
                "head_sha": sha,
                "state": state,
                "impl_provider": impl_provider,
                "repo": repo,
                "package": plan_package(areas),
                "security": _security_flagged(set(labels) | set(source_labels)),
                # The reviewer side must NOT be resolved by inverting `impl_provider` for a
                # self-attested record (design record §3): a false declaration would yield a
                # same-provider review that still looks cross-provider. Consumers key on this
                # flag to pin a CONSTANT review side and to refuse the auto-arm.
                "self_attested": orchestrator_admitted,
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


def _run_gh(args, *, check=True, retry_transient=False):
    # retry_transient is opt-in and READ-ONLY by policy: _gh_json (all idempotent `gh api` GETs)
    # sets it; the direct `gh workflow run` dispatch realizations never do — an ambiguous replay
    # there double-dispatches a worker (incident #559's class), so they stay single-attempt.
    if retry_transient:
        result = _gh_retry.run_gh(args)
    else:
        result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        operation = args[0] if args else "request"
        raise DispatchError(f"GitHub {operation} failed")
    return result


def _gh_json(args):
    # Every _gh_json call site is an idempotent READ (issue/PR/compare/check-run/timeline reads),
    # so transient 5xx/secondary-403/connection blips get gh_retry's bounded backoff instead of
    # deferring the item or redding the sweep (registry #563 item 4).
    result = _run_gh(args, retry_transient=True)
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
                   park_cause="",
                   bot_login="", head_sha="", attempt_key=""):
    """Stop the loop for a PR. `park_class` picks the label PAIR (park_policy.py ownership):
    "question" (default) -> the human-owned pair (review:needs-user on the PR, needs:user on
    the source issue) for genuine human questions; "capacity" -> the machine-owned soft-hold
    pair (review:parked on the PR, status:parked on the source issue) for capacity/decline/
    budget-driven stops — veto-gated, receipted per readmission window, and escalating to the
    question class after PARK_ESCALATION_GENERATIONS consumed windows (worker-pr needs_user
    owns all of that; `bot_login` feeds its receipt parser's trust filter).

    `head_sha` + `attempt_key` are the capacity park's ATTEMPT FINGERPRINT (#555 recurrence
    gap; park_policy.park_fingerprint): the live head plus a MONOTONE counter of work
    attempted. EVERY capacity park on this path supplies them, so an exhaustion re-derived
    from unchanged per-PR state is skipped quietly instead of consuming the readmission window
    a human just granted (the live sparq #3488 7-minute bounce). Question-class parks are
    unconditional human holds and pass neither."""
    args = ["needs-user", "--repo", repo, "--pr", str(pr_number), "--reason", reason,
            "--park-class", park_class]
    # [registry #677] State the capacity park's cause so the park EPISODE is attributable in its
    # own receipt. Omitted, worker-pr records `capacity-unspecified` — honest, and still a
    # receipt, which is what closes the "a stale cause receipt stays newest forever" hole.
    if park_cause:
        args += ["--park-cause", park_cause]
    if bot_login:
        args += ["--bot-login", bot_login]
    if head_sha and attempt_key:
        args += ["--head-sha", head_sha, "--attempt-key", attempt_key]
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


def capacity_park_proof_required(labels, park_receipts):
    """True when the CLAIM sweep must re-prove a human readmission gesture before touching a
    worker PR: EITHER the live review:parked label OR any durable park-generation receipt
    triggers the ONE proof gate (round-3 finding 2; round-4 finding 2). The receipt leg is
    load-bearing for the crash window: park writers post the receipt BEFORE any label write
    (RECEIPT-FIRST), so a crash mid-park leaves receipt-no-label — this predicate still
    demands the proof, and a triage-side label removal can re-enumerate the PR but never
    strip the park. Label-no-receipt is impossible by the writers' ordering."""
    return MACHINE_PARK_PR_LABEL in labels or bool(park_receipts)


def _run_gh_target_api(repo, method, path, input_doc=None):
    """One target-owner issue mutation in the same token-isolated API style as every existing
    dispatch-side target write. The registry token is never used as a fallback for another
    owner's issue mutation."""
    token = _target_token(repo)
    if not token:
        raise DispatchError("target-scoped App token is unavailable")
    args = ["api", "-X", method, path]
    if input_doc is not None:
        args += ["--input", "-"]
    env = {**os.environ, "GH_TOKEN": token}
    payload = json.dumps(input_doc) if input_doc is not None else None
    if method.upper() == "GET":
        # Idempotent target READ (issue re-reads, collaborator-permission probes): transient
        # 5xx/secondary-403 blips get gh_retry's bounded backoff (registry #563 item 4 — the
        # 14:42 RemoteDisconnected class; a 422 stays fatal and is never retried).
        result = _gh_retry.run_gh(args, env=env, input=payload)
    else:
        # Mutations get NO transparent replay: an ambiguous transient failure cannot prove the
        # attempt was skipped — a replayed POST duplicates comments and a replayed PATCH can
        # repeat a label transition. Fail-loud single attempt is deliberate (#558).
        result = subprocess.run(
            ["gh", *args], input=payload,
            capture_output=True, text=True, check=False, env=env,
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
    _issue_timeline_events.

    ENTRIES are validated at read time too (round-4 finding 4): each must be a dict with the
    user(dict)/body(str)/created_at(str) shape every counter and marker parser relies on — a
    `[[null]]` payload passed the old page-only check and crashed the first consumer
    (_bot_comments None.get()) with an unhandled AttributeError that ABORTED the whole CLAIM
    sweep. A malformed entry raises exactly like a malformed page, and the raise is a
    DispatchError — which every sweep call site already catches PER ITEM (the review/worker
    loops' per-item `except DispatchError` and the escalate-starved inner handlers), so one
    hostile/ghost comment now defers ONE item to its documented conservative result instead
    of stranding the entire tick."""
    pages = _gh_json([
        "api", "--paginate", "--slurp", f"repos/{repo}/issues/{pr_number}/comments?per_page=100",
    ])
    if not isinstance(pages, list):
        raise DispatchError("target PR comments are malformed")
    for page in pages:
        if not isinstance(page, list):
            raise DispatchError("target PR comments page is malformed")
        for entry in page:
            if (not isinstance(entry, dict)
                    or not isinstance(entry.get("user"), dict)
                    or not isinstance(entry.get("body"), str)
                    or not isinstance(entry.get("created_at"), str)):
                raise DispatchError("target PR comments entry is malformed")
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


def _capacity_recovery_probe(model_health, health_window, now):
    """The recovery-evidence probe park_policy.capacity_park_admission calls with the canonical
    stamp of the latest park application: model-health's per-account cause-recovery predicate over
    the SAME validated health window the decline ladder and #604's auth cooldowns read (never a
    parallel store). An unreadable window (None) or an unparseable park stamp yields no evidence,
    which the admission reads as STAY PARKED.

    THE LAYER THAT BINDS (registry #691). This is where a park's machine exit is actually decided
    — capacity_park_admission consumes whatever this returns, and everything else (the migration
    precondition below, the label writes, the receipts) is downstream of it. It offers exactly two
    exits, STRONGEST FIRST, and the order is the safety property:

      1. capacity_recovery_evidence — GENUINE evidence that THIS park's own starvation cause
         cleared. Always tried first, and if it fires nothing else is consulted.
      2. If it did not fire but park_cause_provable says the park's cause is STILL OBSERVABLE, the
         strong exit is REACHABLE and this probe returns None on purpose: a park that can still
         earn a real proof must WAIT for it, never be released on a weaker one. Substituting the
         proxy here would silently downgrade every ordinary capacity park.
      3. Only once the strong exit is UNREACHABLE — the park's cause has aged out of the window,
         or the park was applied while the fleet was healthy — does the labelled
         sustained_fleet_health_evidence HEURISTIC apply (registry #691). Without it those parks
         have no machine exit at all: measured 2026-07-25, all 32 sparq legacy parks deferred on
         exactly that condition, and a hold with no machine exit turns a transient outage into a
         permanent stall.

    Both exits return the SAME evidence shape and are consumed by the SAME admission, so both
    inherit — unchanged, and this is deliberate rather than incidental — the unconditional refusal
    on any human-owned hold or human-applied park, the strictly-after-the-park ordering check, the
    consumed-exactly-once evidence key, and the AUTO_READMISSION_MAX cap."""
    def probe(parked_at):
        if health_window is None or not parked_at:
            return None
        parked_epoch = int(_park_policy.parse_ts(parked_at).timestamp())
        evidence = model_health.capacity_recovery_evidence(health_window, parked_epoch, now)
        if evidence is not None:
            return evidence
        if model_health.park_cause_provable(health_window, parked_epoch, now):
            return None                 # the real proof can still arrive — wait for it
        return model_health.sustained_fleet_health_evidence(health_window, parked_epoch, now)

    return probe


def _legacy_migration_provable(model_health, health_window, now):
    """The legacy-park migration precondition, as ONE named production function so the self-test
    binds the expression main() actually evaluates instead of restating it.

    It must agree with _capacity_recovery_probe about what "releasable" means — if it is wider,
    the migration converts parks into a class that cannot release them (the exact harm
    park_cause_provable exists to prevent); if it is narrower, parks stall on the human terminal
    forever (registry #691). model_health.park_exit_reachable is the disjunction of exactly the
    two exits the probe offers, in the same order, which is how the two are kept from drifting.

    An unreadable window (None) defers the migration, consuming nothing."""
    if health_window is None:
        return False
    return model_health.park_exit_reachable(health_window, now, now)


# groom's durable age-park receipt (groom.STALE_PR_MARKER). Kept as a literal here rather than
# imported: groom is a separate entry point with its own checkout root, and this is a READ of a
# marker groom already writes, never a second writer of it.
GROOM_STALE_PR_MARKER = "<!-- registry-groom-stale-pr:v1 -->"
# How many legacy parks one tick may migrate. The migration is one-shot per PR (its own reason
# marker is the receipt that makes reclassify_legacy_park refuse a second pass), so this only
# paces the re-entry: 21 PRs re-entering the review lane in one tick would starve the very
# allocator whose starvation parked most of them.
LEGACY_PARK_MIGRATION_MAX = 5
# How many machine capacity parks one tick may RE-ADMIT (registry #698, found reviewing #697).
#
# THE BOUND WAS PROVEN FOR THE WRONG POPULATION. There are TWO paths into this sweep's label
# writes, and only one of them was paced:
#   * the MIGRATION path — a PR with no live machine park — is capped by LEGACY_PARK_MIGRATION_MAX
#     above, for the stated reason that "21 PRs re-entering the review lane in one tick would
#     starve the very allocator whose starvation parked most of them"; and
#   * the RE-ADMISSION path — a PR that ALREADY carries `review:parked`, or whose source issue
#     carries `status:parked` — had NO ceiling at all. It is fed by the migration, by the review
#     loop's own capacity parks, and by hand.
# That reason applies to the second path identically: a re-admission is exactly the same re-entry
# into exactly the same lane. MEASURED on the live sparq population while reviewing #697: 9 PRs
# sat on `review:parked` with no human hold, none of them reachable by the migration path, and
# #697's aged-out exit mints for all 9 against the live ledger — so without this they would all
# have re-entered on the FIRST tick after merge.
#
# Same value as the migration cap because it is the same lane and the same reason; deliberately
# a SEPARATE constant because the two populations are independent and either may need tuning
# alone. A re-admission deferred by this ceiling consumes NOTHING (the evidence probe is not even
# called), the sweep walks PRs in ascending number order so the drain is deterministic rather
# than starving, and each deferred park is simply re-admitted on a later tick.
AUTO_READMISSION_PER_TICK_MAX = 5


def _migrate_legacy_park(repo, number, issue_number, comments, labels, bot_login, provable,
                         post_comment, convert_labels, source_labels=(),
                         issue_hold_machine_owned=None, log=print):
    """[G1] Re-classify ONE legacy prose-only park out of the human terminal (sparq-org/sparq#3809).

    31 of the 33 stalled sparq draft PRs were parked BEFORE the capacity/question split, so they
    carry the HUMAN-owned `review:needs-user` for an INFRA cause. capacity_park_admission keys on
    `review:parked` plus bot receipts, which they do not have, so NOTHING will ever re-classify
    them: they are stalled permanently by construction. This is the migration that ends that.

    Returns True iff this PR was migrated. Every gate fails toward LEAVING THE PARK ALONE:

    - Only a PR sitting on the human terminal is a candidate at all.
    - The cause must be recognised from the BOT'S OWN comments, and an injection / human-arm
      signal ANYWHERE in that history refuses the PR forever (park_policy.reclassify_legacy_park;
      the six genuine sparq escalations are pinned as its fixtures).
    - A QUESTION-class cause is RECORDED but never moved: the human terminal is already correct
      for it, and the marker just makes the reason machine-readable from now on.
    - `provable` (_legacy_migration_provable => model_health.park_exit_reachable at the
      conversion instant) must hold. This is the gate that keeps the migration from doing HARM:
      converting a park into a machine class that cannot release it trades a VISIBLE stall a
      human can see and clear for a SILENT one nothing will ever clear. It holds when EITHER
      exit is reachable — the park's own starvation cause is still observable (the strong,
      genuine-evidence exit), or the health ledger is readable and the fleet is presently healthy
      (the labelled aged-out heuristic, registry #691). Neither => defer to a later tick,
      consuming nothing.

    ONE-SHOT BY CONSTRUCTION: the reason marker this writes is itself the receipt that makes
    reclassify_legacy_park treat the PR as no-longer-legacy, so no second migration can happen —
    and RECEIPT-FIRST like every other park write, so a crash between the receipt and the labels
    leaves receipt-no-label (the next tick's ordinary admission converges it), never the reverse.
    """
    if _park_policy.HUMAN_PR_PARK_LABEL not in labels:
        return False
    stale_marker = any(
        GROOM_STALE_PR_MARKER in str(comment.get("body", ""))
        and str((comment.get("user") or {}).get("login", "")).casefold() == bot_login.casefold()
        for comment in comments if isinstance(comment, dict))
    cause, park_class, detail = _park_policy.reclassify_legacy_park(
        comments, bot_login, stale_marker=stale_marker, log=log)
    if cause is None:
        log(f"legacy park stands {repo}#{number}: {detail}")
        return False
    if park_class != _park_policy.PARK_CLASS_CAPACITY:
        # Record the cause; never move the label. A question-class park is where it belongs.
        post_comment(repo, number,
                     "> 🤖 SPARQ agent — recording this park's stop reason in machine-readable "
                     f"form. The cause is `{cause}`, which is a genuine human question: the "
                     "`review:needs-user` hold is CORRECT and is deliberately left in place. "
                     "This comment only makes the reason readable to automation.\n\n"
                     f"{_park_policy.park_reason_marker(cause)}")
        log(f"legacy park classified (not moved) {repo}#{number}: {detail}")
        return False
    if not provable:
        log(f"legacy park deferred {repo}#{number}: cause {cause!r} is machine-owned, but the "
            "machine class has NO exit that could open for it right now (neither an observable "
            "starvation cause nor a readable, presently-healthy fleet) — deferring rather than "
            "trading a visible stall for a silent one")
        return False
    # THE HOLD AXIS. A park is a PAIR: `review:needs-user` on the PR AND `needs:user` on the
    # source issue. Clearing only the PR half leaves the issue half live, and
    # capacity_park_admission refuses unconditionally on ANY live `needs:*` — so the PR would be
    # re-classified, its recovery evidence would be minted, and it would STILL never re-admit.
    # MEASURED on the live sparq population: 24 of the 33 source issues carry `needs:user`.
    #
    # The issue half may only be cleared when it is the MACHINE's own park half. If a PROVEN
    # HUMAN applied it, it is a real human question about the ISSUE and clearing it would erase
    # a human hold — so that PR defers instead (and an unreadable timeline defers too).
    # The migration may clear EXACTLY ONE label: `needs:user`, the issue-side half of the park
    # pair that the park writer itself created. Nothing else. Any OTHER `needs:*` on the source
    # issue is somebody else's hold with its own meaning — `needs:external-audit` is the sq-qhy4
    # external accredited-cryptographer audit gate — and the migration has no business forming an
    # opinion about it. Those fall through to migration_residual_holds below, which DEFERS.
    #
    # Ownership is proven for THAT LABEL specifically (label_application_machine_owned), not
    # inferred from the newest event across READMISSION_LABELS: authorising the deletion of one
    # label with evidence about three different ones is a domain mismatch, and it cleared
    # human-applied holds and treated "no events at all" as permission.
    clearing = []
    if _park_policy.HUMAN_PARK_LABEL in set(source_labels):
        if issue_number and issue_hold_machine_owned is not None \
                and issue_hold_machine_owned(issue_number, _park_policy.HUMAN_PARK_LABEL):
            clearing = [_park_policy.HUMAN_PARK_LABEL]
        else:
            log(f"legacy park deferred {repo}#{number}: the source issue's "
                f"`{_park_policy.HUMAN_PARK_LABEL}` is human-owned or unprovable — the migration "
                "may not clear it, and leaving it would strand the PR permanently")
            return False
    residual = _park_policy.migration_residual_holds(
        set(labels) - {_park_policy.HUMAN_PR_PARK_LABEL}, source_labels, clearing=clearing)
    if residual:
        log(f"legacy park deferred {repo}#{number}: {'/'.join(residual)} would still block "
            "re-admission after the conversion — refusing to migrate a park into a state it "
            "could not leave")
        return False
    post_comment(repo, number,
                 "> 🤖 SPARQ agent — re-classifying this park. It was applied for the INFRA "
                 f"cause `{cause}` before park causes were split into machine-owned and "
                 "human-owned classes, so it landed on the human-owned `review:needs-user` "
                 "terminal and nothing could ever re-admit it. It becomes the MACHINE-owned "
                 f"`{MACHINE_PARK_PR_LABEL}` soft hold. BOTH halves of the park pair are "
                 "converted — the PR label here and the machine-applied `needs:user` on the "
                 "source issue — because either one left standing would block re-admission on "
                 "its own. It re-admits once its starvation cause is proven recovered, or — if "
                 "that cause has aged out of the health window and can no longer be proven — "
                 "once the fleet has been demonstrably healthy for a sustained period, which is "
                 "a labelled heuristic rather than proof of this park's own cause. Either exit "
                 "is capped at two automatic re-admissions, after which a human decides. A "
                 "human can still clear it by unlabeling at any time. No review judgement is "
                 "implied or changed.\n\n"
                 f"{_park_policy.park_reason_marker(cause)}")
    convert_labels(number, issue_number)
    log(f"legacy park MIGRATED {repo}#{number}: {detail}")
    return True


def _readmit_capacity_parks(repo, pull_pages, issue_labels, provenance, bot_login, script_dir,
                            worker_pr, evidence_probe, comments_fn=None, timeline_fn=None,
                            post_comment=None, clear_labels=None, log=print,
                            migration_provable=False, convert_labels=None):
    """AUTOMATIC re-admission of MACHINE capacity parks whose starvation cause has demonstrably
    cleared (registry #614) — the sweep that closes the structural stall: a MACHINE-owned park
    could only ever be cleared by a HUMAN, so a capacity outage stranded every PR it parked even
    after the outage ended. Live evidence 2026-07-25: acct01 (the fleet's only cross-provider
    review account) failed every review with exit-class=auth (#596) and capacity-parked registry
    PRs #587/#590/#585/#593 + issues #574/#577/#582/#572 and 6 sparq PRs; the credential fix
    restores capacity but recovers NONE of those parks without a hand-unlabel of each one.

    Runs over the LIVE pull listing CLAIM already fetched, and only ever touches a MACHINE park:
    a PR carrying a human-owned hold on either surface, or whose LATEST park application was made
    by a proven human, is skipped by park_policy.capacity_park_admission itself. Ordering is
    RECEIPT-FIRST like every other park write (#610 round-4 finding 2): the durable
    AUTO_READMIT_MARKER receipt is posted BEFORE any label is cleared, so a crash between them
    leaves receipt-no-label — which the receipt-driven proof gate admits and this sweep converges
    on the next tick — never label-no-receipt, which would erase the re-admission from every proof
    surface and re-strand the PR. Every failure is PER-PR: one unreadable PR never stops the rest.

    Returns the number of PRs re-admitted this tick."""
    comments_fn = comments_fn or _pr_comments
    timeline_fn = timeline_fn or _issue_timeline_events
    post_comment = post_comment or _run_gh_target_comment
    if convert_labels is None:
        def convert_labels(pr_number, issue_number):
            # The legacy migration writes the labels DIRECTLY rather than through worker-pr's
            # `review-state set`, and that is deliberate: set_review_state REFUSES every
            # automated transition away from review:needs-user (issue #138), which is exactly
            # the guard that stops automation silently unparking a human hold. That guard is
            # left completely intact — this path is not a general transition, it is a
            # cause-classified, deny-gated, provability-gated, one-shot migration whose
            # authorisation is the durable reason receipt posted immediately above it.
            _run_gh_target_api(
                repo, "DELETE",
                f"repos/{repo}/issues/{pr_number}/labels/"
                + urllib.parse.quote(_park_policy.HUMAN_PR_PARK_LABEL, safe=""))
            _run_gh_target_api(repo, "POST", f"repos/{repo}/issues/{pr_number}/labels",
                               {"labels": [MACHINE_PARK_PR_LABEL]})
            if issue_number:
                # The ISSUE half of the park pair. worker-issue's `parked` transition does NOT
                # remove `needs:user` (its remove-set is the status:* labels only), and
                # capacity_park_admission refuses on ANY live `needs:*` — so without this delete
                # the migrated PR could never re-admit. Only reached once the caller has proven
                # the hold is machine-owned; a human-applied one defers instead.
                # ONLY `needs:user` — the half of the park pair the park writer created. Any
                # other needs:* is somebody else's hold and deferred the migration upstream.
                if _park_policy.HUMAN_PARK_LABEL in set(
                        issue_labels.get(issue_number, []) if issue_number else []):
                    _run_gh_target_api(
                        repo, "DELETE",
                        f"repos/{repo}/issues/{issue_number}/labels/"
                        + urllib.parse.quote(_park_policy.HUMAN_PARK_LABEL, safe=""))
                _run_target_helper(script_dir, repo, "worker-issue.py", [
                    "status", "--repo", repo, "--issue", str(issue_number),
                    "--status", "parked"])
    if clear_labels is None:
        def clear_labels(pr_number, issue_number):
            # The SAME label writes a human readmission gesture triggers on the CLAIM path:
            # review:parked -> review:needs on the PR, and status:parked cleared on the source
            # issue. Both helpers are idempotent, so converging a crashed strip is safe.
            _run_target_helper(script_dir, repo, "worker-pr.py", [
                "review-state", "set", "--repo", repo, "--pr", str(pr_number),
                "--state", "needs"])
            if issue_number:
                _run_target_helper(script_dir, repo, "worker-issue.py", [
                    "status", "--repo", repo, "--issue", str(issue_number),
                    "--status", "readmitted"])

    rows = []
    for page in pull_pages if isinstance(pull_pages, list) else []:
        if isinstance(page, list):
            rows.extend(row for row in page if isinstance(row, dict))
    readmitted = migrated = 0
    for row in sorted(rows, key=lambda row: row.get("number") or 0):
        number = row.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            continue
        if row.get("state") != "open":
            continue
        head = row.get("head") or {}
        if (head.get("repo") or {}).get("full_name") != repo \
                or not HEAD_REF_RE.match(str(head.get("ref", ""))):
            continue                      # not a same-repo worker branch — never ours to re-admit
        login = str((row.get("user") or {}).get("login", ""))
        if not bot_login or login != bot_login:
            continue                      # only the trusted App bot's own worker PRs
        try:
            # EVERYTHING that can fail on hostile/degraded data lives inside the per-PR try: a
            # malformed label list, an unreadable comments page, or a failed timeline read must
            # skip THIS PR (its park simply stands) and never abort the sweep — the whole tick's
            # claim runs under this call.
            labels = set(_labels(row))
            record = provenance.get(number)
            issue_number = record.get("issue") if isinstance(record, dict) else None
            if not isinstance(issue_number, int) or isinstance(issue_number, bool) \
                    or issue_number <= 0:
                issue_number = None
            source_labels = set(issue_labels.get(issue_number, []) if issue_number else [])
            if MACHINE_PARK_PR_LABEL not in labels and "status:parked" not in source_labels:
                # [G1] No machine park — but this may be a LEGACY park stranded on the human
                # terminal for an infra cause (sparq-org/sparq#3809). Re-classify it (at most
                # LEGACY_PARK_MIGRATION_MAX per tick) so it re-enters the machine class and
                # inherits the exit above; it is re-admitted on a LATER tick, on its own proof,
                # never here and never in the same breath as the conversion.
                if migrated < LEGACY_PARK_MIGRATION_MAX and _migrate_legacy_park(
                        repo, number, issue_number, comments_fn(repo, number), labels,
                        bot_login, migration_provable, post_comment, convert_labels,
                        source_labels=source_labels,
                        # The issue-side hold may only be cleared when the MACHINE applied it.
                        # park_applications is the same helper the admission uses to decide
                        # ownership, so "human-owned there" and "may not clear here" cannot
                        # drift; an unreadable timeline yields False and the PR defers.
                        issue_hold_machine_owned=(
                            lambda issue, label:
                                _park_policy.label_application_machine_owned(
                                    repo, issue, label, timeline_fn,
                                    is_human=lambda probe: _target_is_human_maintainer(
                                        repo, probe),
                                    log=log)),
                        log=log):
                    migrated += 1
                continue                  # no live machine park — nothing to re-admit
            # PACING, the second half of the bound (registry #698). Checked BEFORE the timeline
            # and comment reads so a paced tick is also a cheap one, and before the evidence
            # probe so a deferred park consumes NO evidence and mints NO receipt — it is simply
            # re-admitted on a later tick.
            if readmitted >= AUTO_READMISSION_PER_TICK_MAX:
                log(f"auto-readmit deferred {repo}#{number}: this tick has already re-admitted "
                    f"{readmitted} park(s) (cap {AUTO_READMISSION_PER_TICK_MAX}) — the park "
                    "stands until the next tick so the re-entry cannot starve the allocator "
                    "whose starvation parked most of them")
                continue
            # ONE spelling of the hold rule (park_policy.human_owned_holds), shared with
            # capacity_park_admission's own refusal and the migration precondition, so the
            # sweep cannot drift from the admission it feeds.
            holds = _park_policy.human_owned_holds(set(labels) | set(source_labels))
            comments = comments_fn(repo, number)
            # ONE timeline read per surface per PR: the admission consults the timelines several
            # times (the human cutoff, the park applications, the ownership probe) and every read
            # must see the SAME view anyway — a mid-decision change would mix two worlds.
            timelines = {}

            def cached_timeline(_repo, timeline_number, _cache=timelines):
                if timeline_number not in _cache:
                    _cache[timeline_number] = timeline_fn(_repo, timeline_number)
                return _cache[timeline_number]

            action, evidence, detail = _park_policy.capacity_park_admission(
                repo, number, issue_number, cached_timeline,
                is_human=lambda probe_login: _target_is_human_maintainer(repo, probe_login),
                consumed=worker_pr.park_generation_cutoffs(comments, bot_login),
                auto_receipts=worker_pr.auto_readmission_records(comments, bot_login),
                auto_marker_count=worker_pr.auto_readmission_marker_count(comments, bot_login),
                auto_evidence=evidence_probe, live_holds=holds, log=log)
            if action == "auto-mint":
                # RECEIPT FIRST, then the labels (see the docstring).
                post_comment(repo, number, worker_pr.auto_readmission_receipt(
                    evidence["key"], evidence["at"]))
                clear_labels(number, issue_number)
                readmitted += 1
                log(f"auto-readmit {repo}#{number}: machine capacity park cleared — {detail}")
            elif action == "auto-receipt":
                clear_labels(number, issue_number)
                readmitted += 1
                log(f"auto-readmit {repo}#{number}: converging an already-receipted automatic "
                    f"re-admission — {detail}")
            else:
                log(f"park stands {repo}#{number}: {detail}"
                    + (" (a human readmission gesture is proven; the CLAIM proof gate owns it)"
                       if action == "human" else ""))
        except (DispatchError, worker_pr.WorkerPrError) as exc:
            log(f"::warning::auto-readmit skipped for {repo}#{number}: {exc}; the capacity "
                "park stands")
    return readmitted


# [registry #677] How many partition-starvation parks ONE tick may UN-park, per repository. The
# park side is capped at 1 because each park changes the measured condition; the un-park side is
# capped at the same value the ordinary capacity re-admission uses, for the same stated reason —
# a whole cohort re-entering the review lane in one tick starves the allocator that parked most of
# them. An un-park deferred by this ceiling writes nothing and is simply retried next tick.
STARVATION_UNPARKS_PER_TICK_MAX = AUTO_READMISSION_PER_TICK_MAX

# The park cause this sweep owns. It is written into the park receipt and re-read before any
# un-park, so the un-park half can only ever release what the PARK half applied.
STARVATION_PARK_CAUSE = "partition"


def starvation_unpark_targets(occupancy, owned, log=print):
    """PURE. The PRs whose partition-starvation park has demonstrably STOPPED being necessary.

    A park with no machine exit is the failure this whole change exists to remove (registry #703),
    so the sweep is SYMMETRIC: the same tick that can park a holder also releases every park it
    made whose cause has cleared. Both halves read the SAME live occupancy.

    - `owned` is the set of PR numbers whose LATEST park application is a machine park carrying
      this sweep's own cause receipt. It is the caller's job to prove that (bot-authored marker +
      machine-owned label application); nothing else is ever released here. A park applied by a
      human, or by another mechanism for another reason, is not this sweep's to clear.
    - THE CAUSE IS RE-DERIVED, NEVER TIMED. The occupancy rows are produced by the real
      busy_packages_of_pulls over the live pull listing, and a park is released only when that
      PR's re-derived area set NO LONGER CONTAINS `__global__` — i.e. it would not seize the
      serializing partition if it were un-parked right now. A timed release would put the holder
      straight back and re-stall the lane on the very next tick, which is worse than the park.

    Returns at most STARVATION_UNPARKS_PER_TICK_MAX PR numbers in ascending order."""
    released = []
    for row in occupancy if isinstance(occupancy, list) else []:
        if not isinstance(row, tuple) or len(row) < 5:
            continue
        _decision, pr_number, packages, _reason, _inactive = row[:5]
        if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
            continue
        if pr_number not in (owned or ()):
            continue                      # not a park this sweep applied
        if GLOBAL_PACKAGE in packages:
            log(f"starvation park stands pr#{pr_number}: it still reserves "
                f"`{GLOBAL_PACKAGE}` — un-parking would re-stall the lane on the next tick")
            continue
        released.append(pr_number)
    released.sort()
    if len(released) > STARVATION_UNPARKS_PER_TICK_MAX:
        log(f"starvation un-park paced: {len(released)} park(s) are releasable; taking "
            f"{STARVATION_UNPARKS_PER_TICK_MAX} this tick, the rest on later ticks")
        released = released[:STARVATION_UNPARKS_PER_TICK_MAX]
    return released


def starvation_unpark_body(packages):
    """The un-park comment. It names the condition that cleared, so the label change reads as a
    closed loop rather than a mystery."""
    reserved = ", ".join(f"`{package}`" for package in sorted(packages)) or "nothing"
    return (
        "> 🤖 **SPARQ agent** — un-parking. The condition this PR was parked for has cleared.\n\n"
        f"It was parked because it reserved the serializing `{GLOBAL_PACKAGE}` crate partition "
        "while the issue lane was fully starved behind it. Re-derived against the live pull "
        f"listing on this tick, it now reserves {reserved} and **not** `{GLOBAL_PACKAGE}` — "
        "usually because its registry provenance record has since been recorded, so its area "
        "linkage resolves.\n\n"
        f"The `{MACHINE_PARK_PR_LABEL}` label is removed and the PR re-enters the ordinary review "
        "lane unchanged. No review judgement was made when it was parked, and none is made now. "
        "Human-owned holds are never touched by this sweep — if one is live, the park stands.\n\n"
        # THE EPISODE BOUNDARY. This marker is why the park receipt above it cannot authorise a
        # second release: starvation_park_owner refuses on any release marker at or after the
        # receipt it is reading. Without it a stale `cause=partition` receipt would stay newest
        # forever and release a later park applied by a different mechanism entirely.
        f"{STARVATION_UNPARK_MARKER}")


# The durable marker this sweep's RELEASE posts. It is what makes a park receipt bind to a park
# EPISODE instead of living forever: once a release is on record, every receipt older than it
# belongs to a closed episode and can never authorise another un-park.
STARVATION_UNPARK_MARKER = "<!-- sparq-starvation-unpark:v1 -->"

# worker-pr.py's capacity-ladder receipt prefix, kept as a LITERAL here for the same reason
# GROOM_STALE_PR_MARKER is: worker-pr is a separate entry point with its own checkout root, and
# this is a READ of a marker it already writes, never a second writer of it. Pinned against the
# real module in the self-test so the two cannot drift.
PARK_GENERATION_MARKER_PREFIX = "<!-- sparq-park-generation:v1"


def _bot_receipt_instants(comments, bot_login, log=print):
    """[(instant, body)] for the BOT's own comments, oldest first, by PARSED instant.

    Ordering is by parsed instant and never by list position or raw string (the round-5 finding
    on this file: a space-separator stamp sorts lexicographically before every `T`-form stamp of
    the same day). An UNPARSEABLE stamp on a bot comment raises the ambiguity to the caller as
    None, which every caller here turns into a refusal — a receipt whose age cannot be
    established must never be used to authorise a label write."""
    rows = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        if not bot_login or login.casefold() != str(bot_login).casefold():
            continue
        stamp = comment.get("created_at")
        if not _park_policy.valid_timestamp(stamp):
            log(f"::warning::bot receipt carries an unreadable stamp {stamp!r}; the park's "
                "episode boundary cannot be established, so the park stands")
            return None
        rows.append((_park_policy.parse_ts(stamp), str(comment.get("body", ""))))
    rows.sort(key=lambda row: row[0])
    return rows


def starvation_park_owner(comments, labels, bot_login, machine_owned, log=print):
    """True iff the live `review:parked` on this PR is THIS sweep's park, in the CURRENT park
    EPISODE, and therefore this sweep's to release.

    THE DEFECT THIS SHAPE EXISTS TO PREVENT (found in review of the first version, reproduced
    end to end with production comment bodies). The first version proved ownership from the
    NEWEST park-reason receipt alone. But `worker-pr.needs_user(park_class="capacity")` — the
    round-budget / no_change / gatefail ladder, i.e. exactly the registry #703 mechanisms — writes
    `review:parked` with only a `sparq-park-generation:v1` receipt and NO park-reason receipt at
    all. So a `cause=partition` receipt from an earlier, already-released park stayed newest
    forever and authorised releasing a park this sweep never applied. Downstream that is worse
    than a spurious un-park: per park_ladder_decision's contract the release is neither a human
    gesture nor an AUTO_READMIT_MARKER, so the ladder's window stays receipted, the next park call
    returns `dedupe` before any label write, and the PR ends up un-parked AND un-parkable. Nothing
    bound a receipt to an episode.

    FIVE proofs, all required, and clauses 4 and 5 are the episode binding:

    1. the machine park label is live;
    2. `machine_owned` — park_policy.label_application_machine_owned for that label — proving the
       latest application was not made by a proven human. A human's park is a human's to clear;
    3. the NEWEST bot-authored park-reason receipt names this sweep's cause. Only the BOT's own
       comments are receipts (park_policy's trust filter), so a third party cannot forge a cause
       and talk a park open;
    4. NO release marker of this sweep's own (STARVATION_UNPARK_MARKER) is at or after that
       receipt. This sweep's release CLOSES the episode its park opened, so a receipt that has
       already been acted on can never authorise a second release;
    5. NO capacity-ladder receipt (PARK_GENERATION_MARKER_PREFIX) is at or after that receipt.
       That receipt is MANDATORY on worker-pr's capacity path — it lands even when the label write
       is veto-suppressed, and on the terminal escalation too — so it is a reliable witness that
       another mechanism has parked, or re-parked, since this sweep did. It covers both directions
       the review found: a ladder park layered ON TOP of a live starvation park, and a ladder
       re-park AFTER a starvation release.

    Ties count as NEWER (>=), deliberately: two receipts sharing a one-second stamp is exactly the
    ambiguous case, and the fail-closed direction is to leave the park alone.

    Any ambiguity — no receipts, an unreadable comment stamp, an unreadable timeline, a different
    newest cause — fails toward LEAVING THE PARK ALONE."""
    if MACHINE_PARK_PR_LABEL not in set(labels):
        return False
    if not machine_owned:
        return False
    rows = _bot_receipt_instants(comments, bot_login, log=log)
    if rows is None:
        return False                      # an unreadable stamp is not an episode boundary
    newest_reason_at = None
    newest_reason_cause = None
    for at, body in rows:
        record = _park_policy.parse_park_reason(body, log=log)
        if record:
            newest_reason_at, newest_reason_cause = at, record.get("cause")
    if newest_reason_at is None:
        return False                      # nothing here states a cause at all
    if newest_reason_cause != STARVATION_PARK_CAUSE:
        return False                      # the current episode belongs to another mechanism
    for at, body in rows:
        if at < newest_reason_at:
            continue
        if STARVATION_UNPARK_MARKER in body:
            log(f"starvation park NOT ours to release: this sweep already released the episode "
                f"that receipt opened (release at {at.isoformat()}) — a receipt cannot authorise "
                "a second un-park")
            return False
        if PARK_GENERATION_MARKER_PREFIX in body:
            log(f"starvation park NOT ours to release: the capacity ladder receipted a park at "
                f"{at.isoformat()}, at or after this sweep's receipt — the PR is parked by "
                "worker-pr's budget ladder now, and releasing it would strand it un-parked AND "
                "un-parkable (park_ladder_decision would dedupe)")
            return False
    return True


def unpark_starved_partition_holder(repo, pr_number, packages, labels, unpark_pr, post_comment,
                                    log=print):
    """Release ONE partition-starvation park. Returns True iff the label was removed.

    Refusals, all failing toward LEAVING THE PARK IN PLACE:
    - the machine park label is not live (nothing to release; idempotent against its own output);
    - ANY human-owned hold is live. Un-parking is strictly `review:parked` -> normal and must
      never promote a PR past a human decision, so a live `review:needs-user` / `needs:*` stops
      this dead. This sweep removes exactly ONE label and never any other.

    RECEIPT-FIRST, matching the park half: the explanation lands before the label change, so a
    crash between them leaves an explained PR that is still parked — the next tick converges it —
    never a silent label change."""
    live = set(labels)
    if MACHINE_PARK_PR_LABEL not in live:
        log(f"starvation un-park skipped {repo}#{pr_number}: no live "
            f"`{MACHINE_PARK_PR_LABEL}`")
        return False
    held = _park_policy.human_owned_holds(live)
    if held:
        log(f"starvation un-park REFUSED {repo}#{pr_number}: human-owned hold(s) live "
            f"({'/'.join(held)}) — a machine never un-parks past a human decision")
        return False
    post_comment(repo, pr_number, starvation_unpark_body(packages))
    unpark_pr(pr_number)
    log(f"starvation un-park APPLIED {repo}#{pr_number}: the `{GLOBAL_PACKAGE}` reservation is "
        f"gone (now {sorted(packages)}), so `{MACHINE_PARK_PR_LABEL}` is removed")
    return True


def starvation_park_body(repo, pr_number, deferred, issue_url):
    """The park comment for a partition-starvation park. Modelled on the hand-written comments on
    sparq-org/sparq#4185 and #4212, because the reader of this comment is the PR's author and the
    review lane, and the FIRST thing they must learn is that no review judgement was made.

    It states the mechanism, the measurement that triggered it, the un-park condition, and — the
    part a machine action must never omit — that the machine will un-park it itself."""
    return (
        "> 🤖 **SPARQ agent** — parking this PR to unblock the fleet. "
        "**This is not a review judgement, and nothing is wrong with the change itself.**\n\n"
        "## What happened\n\n"
        f"This PR is currently reserving the serializing `{GLOBAL_PACKAGE}` crate partition, so "
        "it excludes against **every** crate in the workspace at once. On this dispatch tick the "
        f"issue lane planned **0** items while **{deferred}** ready issue row(s) were deferred "
        "behind that reservation — the worker lane was fully starved.\n\n"
        "The usual cause is a **missing or unreadable registry provenance record** for this PR: "
        "`busy_packages_of_pulls` fails closed on unresolvable linkage and adds "
        f"`{GLOBAL_PACKAGE}` to the reservation. Adding `area:*` labels to the PR cannot remove "
        "it — the fail-closed default is unioned in on top of them.\n\n"
        "## Why this PR\n\n"
        "It is the lowest-numbered open worker PR that (a) holds that partition, (b) is not "
        "already parked, and (c) is a provably inert draft with no arm latch — so parking it "
        "**demonstrably frees the partition**. A holder whose park would not free anything is "
        "never selected. At most one holder is parked per tick.\n\n"
        "## What the label means\n\n"
        f"`{MACHINE_PARK_PR_LABEL}` is the **machine-recoverable capacity** class. A parked, "
        "inactive PR releases its crate reservation — that release is the entire purpose of this "
        "label here. It is **not** `needs:user`, it is not a terminal human hold, and this sweep "
        "never writes one.\n\n"
        "## How it comes back — automatically\n\n"
        "The same sweep un-parks it. On every dispatch tick this PR's area set is re-derived "
        f"against the live pull listing; the moment it no longer reserves `{GLOBAL_PACKAGE}` "
        "(normally as soon as its registry provenance record is recorded, so its area linkage "
        "resolves) the label is removed and an un-park comment is posted. **No human gesture is "
        "required, and the un-park is proven from the re-derived reservation, never a timer.** "
        "A human can also simply remove the label at any time; a human un-park is sticky and "
        "this sweep will not undo it.\n\n"
        f"Mechanism, and the work to stop this happening at all: {issue_url}\n\n"
        # THE ATTRIBUTABLE REASON. This receipt is not decoration: the un-park half re-reads it to
        # prove the park it is about to release is one this sweep applied, so without it the
        # release could never be scoped and the park would have no machine exit at all.
        f"{_park_policy.park_reason_marker(STARVATION_PARK_CAUSE)}")


def park_starved_partition_holder(repo, pr_number, deferred, labels, park_pr, post_comment,
                                  vetoed=None, log=print):
    """Apply ONE partition-starvation park. Returns True iff the label was written.

    `park_pr(pr_number)` writes the label and `post_comment(repo, pr_number, body)` posts the
    receipt; both are injected so the self-test observes the EXACT mutation set this function
    performs — the named test asserts that `needs:user` / `review:needs-user` / `status:parked`
    are never among them.

    The three refusals, all failing toward DOING NOTHING:

    - `labels` already carries the machine park -> nothing to do (idempotence, defence in depth;
      starvation_park_target already declines an already-parked holder).
    - `labels` carries a HUMAN-owned hold -> a human is already holding this PR and the machine
      has no business writing a second hold on top of it.
    - `vetoed(pr_number)` -> park_policy's sticky human-unpark veto. A human who un-parked this PR
      has overruled the machine, and re-parking it would be the machine overruling the human. An
      unreadable timeline vetoes too (park_vetoed's own fail direction).

    RECEIPT-FIRST, like every other park writer here (#610 round-4 finding 2): the comment lands
    BEFORE the label. A crash between them leaves an explained PR with no label — visibly nothing
    happened — never an unexplained label, which is the mysterious action registry #703 is about.

    This function deliberately does NOT route through worker-pr's `needs-user --park-class
    capacity` ladder. That ladder counts park generations and ESCALATES an exhausted capacity park
    into the human `needs:user` terminal, which is precisely the conveyor registry #703 documents.
    A scheduling action must never be able to graduate into a human question."""
    live = set(labels)
    if MACHINE_PARK_PR_LABEL in live:
        log(f"starvation park skipped {repo}#{pr_number}: already carries "
            f"`{MACHINE_PARK_PR_LABEL}`")
        return False
    held = _park_policy.human_owned_holds(live)
    if held:
        log(f"starvation park REFUSED {repo}#{pr_number}: human-owned hold(s) live "
            f"({'/'.join(held)}) — the machine does not write a hold on top of a human's")
        return False
    if vetoed is not None and vetoed(pr_number):
        log(f"starvation park REFUSED {repo}#{pr_number}: a human un-parked this PR (or the "
            "timeline is unreadable) — the sticky unpark veto stands")
        return False
    post_comment(repo, pr_number, starvation_park_body(
        repo, pr_number, deferred,
        "https://github.com/jeswr/agent-account-registry/issues/677"))
    park_pr(pr_number)
    log(f"starvation park APPLIED {repo}#{pr_number}: `{MACHINE_PARK_PR_LABEL}` written to free "
        f"the `{GLOBAL_PACKAGE}` partition ({deferred} ready row(s) were deferred behind it); "
        "the ordinary capacity-park re-admission sweep owns its exit")
    return True


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
                                apply_action=None, post_comment=None,
                                min_outcomes=DECLINE_ESCALATION_MIN):
    """Apply or reconcile one repeated-decline escalation.

    Returns ``proceed`` below threshold and after a previously completed impl->research reroute;
    every other result means the caller must stop this cached claim. The audit marker is written
    BEFORE the label mutation so a mutation failure can be reconciled next tick without a second
    loud comment. Conversely, a failed comment performs no label mutation and safely retries.
    Injectable mutation/comment callables keep the --self-test tripwires on the real control flow.

    `min_outcomes` (registry #701) is the threshold this call is allowed to fire at. It stays
    DECLINE_ESCALATION_MIN for the historical "two honest declines" ladder, and drops to 1 for the
    ONE case where a second outcome could add nothing: the resolved model chain has no tier left
    that has not already produced a `no_change` for this issue, so the only remaining choices are
    "run the failed tier again" or "decompose". The caller — never this function — decides that,
    from `no_change_routing.retry_decision`.
    """
    if len(outcomes) < min_outcomes:
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


def _missed_fix_budget(worker_pr, comments, bot_login, round_number, cutoff_fn, repo, number):
    """The MISSED-FIX-dispatch budget as (charged, lifetime) counts — the #555 RECURRENCE fix
    for the second exhaustion branch.

    THE BUG: `missed` markers are durable per-round state that nothing resets, and the
    MISSED_FIX_LIMIT capacity park read the LIFETIME count. #555 windowed the ROUND budget by
    the human-readmission cutoff but left this counter unwindowed — so a re-admitted PR
    re-derived "N consecutive fix dispatches missed for round R" from the very same markers on
    the very next tick, with an UNCHANGED head and no work attempted, and (with a gen-1 receipt
    already standing) the ladder went straight to its question-class terminal. That is the
    observed bounce: sparq PR #3488 re-admitted 2026-07-22T16:36:56Z, re-escalated 16:44:10Z;
    PR #3472 re-escalated seconds later with byte-identical boilerplate, five days after the
    last commit or review round on either PR. This counter is the purest case of it: it needs
    NO head advance and NO review round to grow — it grows purely from allocator starvation,
    identically across every PR in a sweep.

    THE FIX: the LIMIT decision charges only markers recorded at or after `cutoff` (the same
    readmission window the round budget uses — one timeline read per PR per tick), so a human
    readmission grants real dispatch capacity. The LIFETIME count is still returned: it is the
    monotone axis of the park's attempt fingerprint (a window-relative count resets and would
    read as "unchanged" across two genuinely distinct windows).

    `cutoff_fn` is the PR's memoized readmission-cutoff getter, called ONLY once the LIFETIME
    count has reached the limit — below it the decision is the same either way, exactly like the
    round budget's `rounds >= max_rounds` gate — so no extra timeline read is spent on the
    common case."""
    lifetime = len(worker_pr.marker_runs(comments, bot_login, "missed", round_number))
    if lifetime < MISSED_FIX_LIMIT:
        return lifetime, lifetime
    cutoff = cutoff_fn()
    if not cutoff:
        return lifetime, lifetime
    charged = len(worker_pr.marker_runs_since(
        comments, bot_login, "missed", round_number, cutoff))
    if charged != lifetime:
        print(f"readmission window open for {repo}#{number}: a park label was cleared at "
              f"{cutoff} (a human unlabel or a proven automatic re-admission); the missed-fix "
              f"budget for round {round_number} charges {charged} of {lifetime} recorded "
              f"miss(es)")
    return charged, lifetime


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
            if capacity_park_proof_required(labels, park_receipts):
                # ONE proof gate (round-3 finding 2): the trigger is the DURABLE receipt
                # state OR a live review:parked label — never the label alone. A triage-side
                # label dismissal leaves the receipts standing, so CLAIM still re-proves the
                # human gesture from the label TIMELINES (strict maintainer probe;
                # most-recent-event-wins against the park application, receipted windows
                # consumed) before anything mutates or dispatches — a spoofed/stale label
                # state can re-enumerate, but it can never mint budget or strip the park.
                # Round-4 finding 2 pairs this with RECEIPT-FIRST park writers: a crash
                # mid-park leaves receipt-no-label, which this gate still catches.
                # The proof admits on EITHER authority (registry #614): an unconsumed
                # proven-human readmission gesture (unchanged), or a bot-authored AUTOMATIC
                # re-admission receipt that is newer than every park application — the durable
                # gesture the readmission sweep left behind when it proved the starvation cause
                # had cleared. Nothing is MINTED here (auto_evidence is not passed): this gate
                # only reads proof, so re-admission still requires the sweep's evidence-gated,
                # receipted decision.
                park_action, _park_evidence, park_detail = \
                    _park_policy.capacity_park_admission(
                        repo, number, issue_number, _issue_timeline_events,
                        is_human=lambda login: _target_is_human_maintainer(repo, login),
                        consumed=park_receipts,
                        auto_receipts=worker_pr.auto_readmission_records(comments, bot_login),
                        auto_marker_count=worker_pr.auto_readmission_marker_count(
                            comments, bot_login),
                        live_holds=sorted(HUMAN_HOLD_PR_LABELS & set(labels)))
                if not park_action:
                    print(f"defer review {repo}#{number}: machine capacity park stands "
                          f"(durable receipts/label; {park_detail})")
                    continue
                if MACHINE_PARK_PR_LABEL in labels:
                    # Proven gesture: converge the stale PR-side park back into the loop (the
                    # review-fix.yml admission rejects review:parked, so the strip must
                    # precede any dispatch). set_review_state drops review:parked for
                    # review:needs.
                    _run_target_helper(script_dir, repo, "worker-pr.py", [
                        "review-state", "set", "--repo", repo, "--pr", str(number),
                        "--state", "needs"])
                    print(f"re-admit review {repo}#{number}: {park_detail}; review:parked "
                          "converged to review:needs")
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
                # The marker retraction this recovery needs to be executable at all (issue #708)
                # happens at the LAUNCH INVARIANT below, not here: every escalation, hold and defer
                # between this point and the dispatch must be able to stand the item down without
                # this branch having already written to the PR.
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
            # LAZY + MEMOIZED (#555 recurrence gap): the SAME cutoff also windows the missed-fix
            # marker budget further down, and both call sites must agree on one readmission
            # window per PR per tick — so the timeline is read at most once, and only when a
            # park decision actually hangs on it.
            # [registry #614] The window is the LATER of the human gesture and any AUTOMATIC
            # re-admission receipt on this PR. Clearing a machine park WITHOUT granting a budget
            # window would leave the PR enumerable but permanently un-dispatchable: the missed-fix
            # marker budget grows purely from allocator starvation, so an outage pins it and every
            # later tick would re-derive the SAME exhausted lifetime count and quietly re-defer
            # forever. An automatic re-admission therefore grants exactly the window a human
            # gesture grants — bounded by the same two things that bound the re-admission itself
            # (fresh unconsumed recovery evidence, and park_policy.AUTO_READMISSION_MAX).
            readmission_cutoff = _UNPROBED

            def _readmission_cutoff(_repo=repo, _number=number, _issue=issue_number):
                nonlocal readmission_cutoff
                if readmission_cutoff is _UNPROBED:
                    readmission_cutoff = _park_policy.effective_readmission_cutoff(
                        _park_policy.readmission_cutoff(
                            _repo, _number, _issue, _issue_timeline_events,
                            is_human=lambda login: _target_is_human_maintainer(_repo, login)),
                        worker_pr.auto_readmission_stamps(comments, bot_login))
                return readmission_cutoff

            budget_rounds = rounds
            if rounds >= max_rounds:
                cutoff = _readmission_cutoff()
                if cutoff:
                    budget_rounds = worker_pr.count_rounds_since(comments, bot_login, cutoff)
                    if budget_rounds != rounds:
                        print(f"readmission window open for {repo}#{number}: a park label "
                              f"was cleared at {cutoff} (a human unlabel or a proven "
                              f"automatic re-admission); the round budget charges "
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
                #
                # The park's ATTEMPT FINGERPRINT (#555 recurrence gap) is the live head plus
                # the GLOBAL round count `rounds` — deliberately NOT the window-relative
                # `budget_rounds`, which resets on every readmission and would therefore read
                # as "unchanged" across two genuinely distinct windows.
                _pr_needs_user(script_dir, repo, number, issue_number,
                               f"the review round budget is exhausted at {budget_rounds} "
                               f"round(s) "
                               f"(base {max_rounds}, hard cap {worker_pr.HARD_CAP_ROUNDS}) "
                               "with no extension left — the top fix tier has run, the latest "
                               "verdict does not grade the PR improving, and no pushed fix at "
                               "or above the pinned floor awaits re-review; a human must "
                               "decide", park_class="capacity", park_cause="budget",
                               bot_login=bot_login,
                               head_sha=head_sha, attempt_key=f"rounds={rounds}")
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
                missed, missed_total = _missed_fix_budget(
                    worker_pr, comments, bot_login, round_number, _readmission_cutoff,
                    repo, number)
                if missed >= MISSED_FIX_LIMIT:
                    # Missed dispatches ARE capacity starvation (the allocator found no slot
                    # every tick) -> the machine-owned park, never a fake human question. The
                    # charge is WINDOWED by the readmission cutoff (#555 recurrence gap) so a
                    # human unpark grants real dispatch capacity; the fingerprint carries the
                    # LIFETIME count, which is monotone across windows.
                    _pr_needs_user(script_dir, repo, number, issue_number,
                                   f"{missed} consecutive fix dispatches missed for round "
                                   f"{round_number}; a human must unstick this PR",
                                   park_class="capacity",
                                   # [registry #677] the taxonomy's own name for this cause
                                   park_cause="dispatch-missed", bot_login=bot_login,
                                   head_sha=head_sha,
                                   attempt_key=f"missed{round_number}={missed_total}")
                    continue
                chain = _resolvable_chain(fix_aliases, routing)
                holder_namespace, ttl = "fix:", FIX_TTL
            else:
                # Externally relabelled review:changes is a first-class re-entry even when no
                # bot round marker survived/exists.  Round 1 is the positive workflow round that
                # corresponds to the clean synthetic round-0 budget posture; the trusted verdict
                # record is still required below before a verdict-seeded fixer may run.
                round_number = max(rounds, 1)
                missed, missed_total = _missed_fix_budget(
                    worker_pr, comments, bot_login, round_number, _readmission_cutoff,
                    repo, number)
                if missed >= MISSED_FIX_LIMIT:
                    # Same capacity-starvation classification — and the same readmission
                    # windowing + attempt fingerprint — as the repair-state branch above.
                    _pr_needs_user(script_dir, repo, number, issue_number,
                                   f"{missed} consecutive fix dispatches missed for round "
                                   f"{round_number}; a human must unstick this PR",
                                   park_class="capacity",
                                   # [registry #677] the taxonomy's own name for this cause
                                   park_cause="dispatch-missed", bot_login=bot_login,
                                   head_sha=head_sha,
                                   attempt_key=f"missed{round_number}={missed_total}")
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
        # ---- ISSUE #708: THE REVIEW LANE'S LAUNCH INVARIANT, ENFORCED AND COUNTED ----------------
        # review-fix.yml's resolve step computes `already_done = (reviewed-sha marker == head_sha)`
        # and its `run` job is gated on `needs.claim.outputs.acquired == 'true'`, which the
        # already_done skip step sets to false. So a mode=review dispatch whose target head is still
        # marker-bound CANNOT run a model, by construction — it only consumes a reviewer lease, a
        # repository/package partition and a workflow run, then reports `success`.
        #
        # Three live states reached this point on master with a bound marker: the `stranded`
        # recovery (which bypasses the enumerator's guard by design — now repaired above by
        # retracting the disproved assertion), an explicitly review:needs-labelled READY PR that
        # CLAIM redrafts (enumerate_review_items emits it via `if not draft or not reviewed_match`),
        # and any future state that forgets. State-by-state carve-outs are what let this go unnoticed
        # for so long, so state the INVARIANT once, here, over every review dispatch.
        #
        # This is a COUNTED LANE ERROR, not a green defer. It is not capacity contention: retrying
        # it next tick cannot succeed, so a green "deferred" would be exactly the silent accounting
        # that hid 117 no-op runs behind `lane review: planned=12 launched=4 error=0` (issue #700 —
        # per-stage health cannot express a missing edge BETWEEN stages). An error makes the tick
        # recorder's `_lane_stalled` predicate able to see it and the alert ladder able to page.
        if mode == "review":
            if item["state"] == "stranded":
                # The stranded posture IS the disproof of the marker's assertion: review-fix.yml's
                # outcome job binds the marker LAST (after the lane label and the arm), so a PR that
                # is STILL a draft and STILL unarmed cannot have completed the outcome the marker
                # claims. Retract it — the same remedy, for the same reason, as the #560 fix-lane
                # hand-over one lane over (whose own self-test comment already NAMES this spin).
                # review-fix.yml's already_done predicate is left byte-identical and keeps its full
                # strength; what changes is that the assertion it reads is now true.
                # stranded_recover applies the #560/#584 stand-down surface (human hold, machine
                # capacity park, review:pass) plus a tri-state arm/draft guard of its own, and this
                # runs only AFTER every escalation/hold/defer above has declined to stand the item
                # down — so the recovery never writes to a PR it was about to park.
                try:
                    _run_target_helper(script_dir, repo, "worker-pr.py", [
                        "stranded-recover", "--repo", repo, "--pr", str(number),
                        "--head-sha", head_sha, *(["--issue", str(issue_number)]
                                                  if issue_number else [])])
                except DispatchError as exc:
                    lanes[lane]["error"] += 1
                    defer_reasons["stranded-retract-failed"] += 1
                    print(f"::error::defer review {repo}#{number}: the stranded recovery could "
                          f"not retract the disproved reviewed-sha assertion ({exc}); NOT "
                          "dispatching, because a review run on a marker-bound head exits "
                          "already_done without running a model")
                    continue
                # Do NOT trust the helper's report — re-read the PR and let the invariant below
                # adjudicate the POSTCONDITION. Every stand-down inside stranded_recover therefore
                # converges to a loud, counted, attributed refusal instead of a silent no-op run.
                pull = _gh_json(["api", f"repos/{repo}/pulls/{number}"])
            bound = REVIEWED_SHA_RE.search(pull.get("body") or "")
            if bound and bound.group(1) == head_sha:
                lanes[lane]["error"] += 1
                defer_reasons["review-noop-head-already-bound"] += 1
                print(f"::error::defer review {repo}#{number}: the reviewed-sha marker already "
                      f"names the live head {head_sha[:12]}, so review-fix.yml resolves "
                      "already_done and SKIPS the model job — refusing to spend a reviewer lease "
                      f"on a dispatch that cannot review anything (state={item['state']})")
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
    # [OPUS-5] NAME THE DISAGREEMENT. This equality is a pure function of the item's labels and the
    # protected routing table, so when it fails it fails IDENTICALLY on every subsequent tick: the
    # item is deferred forever. Reporting only "route no longer matches" left the sparq #4211
    # round-2 defect (a chain-order rule PLAN implemented and CLAIM did not) visible as nothing but
    # a `route-policy-failed` counter. Emit the field and BOTH values so one defer line identifies
    # the divergence, and raise a DISTINCT class so the caller can count and annotate it apart from
    # ordinary per-item trust/policy failures.
    divergent = {key: (value, resolved[key]) for key, value in expected.items()
                 if resolved[key] != value}
    if divergent:
        detail = "; ".join(f"{key}: PLAN {plan!r} vs CLAIM {claim!r}"
                           for key, (plan, claim) in sorted(divergent.items()))
        raise RouteDivergenceError(
            f"PLAN and CLAIM derive different routes for {repo}#{item['number']} "
            f"(labels {sorted(item['labels'])}) — {detail}. This is a routing-table/resolver "
            f"divergence, not a transient: it repeats every tick until the two resolvers agree")
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


def _receipt_instants(comments, bot, marker):
    """(instant, created_at-string) pairs — instants PARSED to aware datetimes via
    park_policy.parse_ts (round-5 finding 2: receipt ordering is by parsed instant, never raw
    string — a space-separator spelling sorts lexicographically before every 'T' spelling of
    a LATER time) — for comments authored by `bot` (casefolded login) that carry `marker`.
    RAISES ValueError on a matching receipt whose created_at cannot be parsed: these receipts
    ARE the persistence clock, and both consumers FREEZE the starvation ladder on an
    unreadable clock (never escalate to a park, never mint a recovery receipt, on unprovable
    time). Shared helper for the starvation-persistence + recovery-reset logic."""
    return [
        (_park_policy.parse_ts(c.get("created_at")), str(c.get("created_at")))
        for c in comments
        if str(c.get("user", {}).get("login", "")).casefold() == bot
        and marker in str(c.get("body", ""))
    ]


def escalate_persist_decision(comments, bot_login, now, attempt_marker,
                              persist_seconds=ESCALATE_PERSIST_SECONDS, log=print):
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
    never one snapshot. Ordering is by PARSED instants (park_policy.parse_ts — round-5 finding
    2: a raw-string compare read a space-separator alert stamp as both pre-reset AND
    past-grace, so a 60-second-old snapshot could escalate straight to a park); a receipt
    whose stamp cannot be parsed FREEZES the ladder — (False, "") with a loud log — because an
    unreadable clock can prove neither persistence nor recovery."""
    bot = bot_login.casefold()
    # The continuous-starvation streak ENDS on any durable end-of-starvation signal, not solely a
    # worker attempt: a live-capacity RECOVERY receipt (STARVE_RESET_MARKER) closes it too (issue
    # #116 round 1). Recovery is a real streak end even when it produced no attempt (allocator
    # returned no slot, the launch failed, or a later pre-dispatch hold intervened), so alerts at or
    # before the NEWER of {last attempt, last reset} are stale and must not age a later snapshot.
    try:
        resets = (_receipt_instants(comments, bot, attempt_marker)
                  + _receipt_instants(comments, bot, STARVE_RESET_MARKER))
        alerts = _receipt_instants(comments, bot, STARVE_ALERT_MARKER)
    except ValueError as exc:
        log(f"::warning::starvation-ladder clock unreadable ({exc}) — freezing: no "
            "escalation on unprovable time")
        return False, ""
    reset_at = max((instant for instant, _stamp in resets), default=None)
    streak = sorted((instant, stamp) for instant, stamp in alerts
                    if reset_at is None or instant > reset_at)
    if not streak:
        return False, ""
    threshold = _park_policy.parse_ts(
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - persist_seconds)))
    return streak[0][0] <= threshold, streak[0][1]


def escalate_recovery_pending(comments, bot_login, attempt_marker, log=print):
    """True when an escalate-tier issue carries an ACTIVE starvation alert — a STARVE_ALERT_MARKER
    posted strictly after the latest reset/attempt receipt — so an observed live-capacity recovery
    should now persist a STARVE_RESET_MARKER that closes the streak (issue #116 round 1). Returns
    False once a reset (or attempt) already supersedes every alert, which keeps recovery recording to
    ONE receipt per streak — no per-tick comment spam while capacity stays healthy. Ordering is
    by PARSED instants (park_policy.parse_ts — round-5 finding 2: a space-separator alert
    stamp sorts lexicographically before a 'T'-form reset stamp of an EARLIER instant, so the
    raw-string compare read a fresh post-reset alert as already closed); an unparseable
    receipt stamp FREEZES the ladder (False, loud log) — same fail direction as
    escalate_persist_decision."""
    bot = bot_login.casefold()
    try:
        resets = (_receipt_instants(comments, bot, attempt_marker)
                  + _receipt_instants(comments, bot, STARVE_RESET_MARKER))
        alerts = _receipt_instants(comments, bot, STARVE_ALERT_MARKER)
    except ValueError as exc:
        log(f"::warning::starvation-ladder clock unreadable ({exc}) — freezing: no "
            "recovery receipt on unprovable time")
        return False
    reset_at = max((instant for instant, _stamp in resets), default=None)
    return any(reset_at is None or instant > reset_at for instant, _stamp in alerts)


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
        # ONE live view per repo per tick, shared by the busy revalidation and the capacity-park
        # readmission sweep below (they must not disagree about the live hold/linkage state, and
        # the issue listing is a paginated API read worth spending once).
        live_issue_labels = _live_issue_labels(repo)
        claim_provenance = _claim_provenance_map(repo, registry_root, ledger_root)
        # [registry #677] The SAME live occupancy the revalidation computes, kept for the
        # starvation sweep below rather than re-derived from a second view.
        live_occupancy = []
        live_dispatchable = revalidate_items_against_live_pulls(
            repository["items"], repo, pull_pages, live_issue_labels, claim_provenance,
            # [round-5 P1] the cross-lane lease partition reads the ledger-branch checkout;
            # an unreadable ledger view yields None and the partition fails toward exclusion.
            leases=_ledger_leases(ledger_root), now=int(time.time()),
            occupancy=live_occupancy)

        # Safety invariant FIRST (issue #42): stale arm latches are retracted before any fix or
        # review admission can push onto (or re-review past) an armed, mutated head. The disarm lane
        # folds its own launched/error/deferred into `lanes` (issue #108) — an error here alerts
        # regardless of the worker/review/fix outcome below.
        _apply_disarm_items(
            [entry for entry in plan["disarm_items"] if entry["repo"] == repo],
            repo, script_dir, bot_login, lanes["disarm"])

        # [registry #614] AUTOMATIC re-admission of MACHINE capacity parks whose starvation cause
        # has demonstrably cleared. It runs on the LIVE listing because PLAN's pure walk excludes
        # every parked PR outright (nothing downstream can see them), and it re-admits by doing
        # exactly what a human gesture does — receipt FIRST, then clear the machine label(s) — so
        # the PR re-enters the ordinary enumeration next tick with a real budget window. Skipped
        # without the App bot login or the target token: the receipts are bot-authored and the
        # label writes need that token, and a re-admission that cannot be receipted must not
        # happen. An unreadable health window re-admits NOTHING (fail closed).
        if bot_login and _target_token(repo):
            if not health_window_loaded:
                health_window = _read_model_health_window(
                    model_health, registry_repo, int(time.time()))
                health_window_loaded = True
            if health_window is None:
                print(f"::warning::auto-readmit skipped for {repo}: the model-health window is "
                      "unreadable, so no capacity park can prove its cause cleared — every park "
                      "stands (fail closed)")
            else:
                _now = int(time.time())
                _readmit_capacity_parks(
                    repo, pull_pages, live_issue_labels, claim_provenance, bot_login,
                    script_dir, worker_pr,
                    _capacity_recovery_probe(model_health, health_window, _now),
                    # [G1] The legacy migration converts a park only when the machine class it is
                    # converting INTO has an exit that can actually open for it — otherwise the
                    # migration would trade a visible stall for a silent one. ONE named function
                    # (registry #691) so this call site and the admission probe above cannot
                    # drift apart.
                    migration_provable=_legacy_migration_provable(
                        model_health, health_window, _now))

        # [registry #677] THE MACHINE EXIT FOR A STARVED PLAN. Four times on 2026-07-26 the
        # issue lane went to `PLAN complete: 0 issue item(s)` / `lane worker: planned=0 launched=0`
        # while ONE un-parked PR reserved all 54 crates, and the only thing that cleared it was a
        # human parking the holder by hand. A conservative hold with no machine exit converts a
        # transient fault into a permanent stall (#677 point 2), so the fleet performs that same
        # action itself — on the MEASURED condition, never a timer.
        #
        # `deferred` is the ONE input from the plan: how many ready rows the busy partition dropped
        # behind a `__global__` occupant. Everything else — who holds the partition, whether they
        # are parked, whether parking them would free anything — is RE-PROVEN against the live
        # occupancy computed moments ago, so a stale or hostile plan can make this look for a
        # starvation but never name the PR that gets parked.
        #
        # SYMMETRIC BY CONSTRUCTION. The un-park half runs FIRST and unconditionally — before the
        # park half, and regardless of whether the lane is starved this tick. A park-only sweep
        # would industrialise the exact mistake this replaces: a hold whose stated exit condition
        # nothing enforces, converging on the maintainer's desk (registry #703). Both halves read
        # the SAME `live_occupancy`, so "would this PR seize the partition right now" has one
        # answer per tick, not two.
        if bot_login and _target_token(repo):
            _owned = set()
            for _row in live_occupancy:
                _n = _row[1]
                if not isinstance(_n, int) or isinstance(_n, bool) or _n <= 0:
                    continue
                if GLOBAL_PACKAGE in _row[2]:
                    continue              # still a holder — cheapest refusal first, and it
                    # keeps the comment/timeline reads off every un-releasable park
                try:
                    _live = next(
                        (row for page in pull_pages if isinstance(page, list) for row in page
                         if isinstance(row, dict) and row.get("number") == _n), None)
                    if _live is None or MACHINE_PARK_PR_LABEL not in set(_labels(_live)):
                        continue
                    if starvation_park_owner(
                            _pr_comments(repo, _n), _labels(_live), bot_login,
                            _park_policy.label_application_machine_owned(
                                repo, _n, MACHINE_PARK_PR_LABEL, _issue_timeline_events,
                                is_human=lambda probe: _target_is_human_maintainer(repo, probe))):
                        _owned.add(_n)
                except DispatchError as exc:
                    print(f"::warning::starvation un-park skipped {repo}#{_n}: {exc}; the park "
                          "stands")
            for _release in starvation_unpark_targets(live_occupancy, _owned):
                try:
                    _live = next(
                        (row for page in pull_pages if isinstance(page, list) for row in page
                         if isinstance(row, dict) and row.get("number") == _release), None)
                    _packages = next((row[2] for row in live_occupancy
                                      if row[1] == _release), frozenset())
                    if _live is not None:
                        unpark_starved_partition_holder(
                            repo, _release, _packages, _labels(_live),
                            unpark_pr=lambda number: _run_gh_target_api(
                                repo, "DELETE",
                                f"repos/{repo}/issues/{number}/labels/"
                                + urllib.parse.quote(MACHINE_PARK_PR_LABEL, safe="")),
                            post_comment=_run_gh_target_comment)
                except DispatchError as exc:
                    print(f"::warning::starvation un-park FAILED {repo}#{_release}: {exc}; the "
                          "park stands and the next tick retries")

        starved = next((entry["deferred"] for entry in plan["partition_starvation"]
                        if entry["repo"] == repo), 0)
        starvation_target = starvation_park_target(
            repository["items"], starved, live_occupancy)
        if starvation_target is not None and bot_login and _target_token(repo):
            try:
                _live_row = next(
                    (row for page in pull_pages if isinstance(page, list)
                     for row in page
                     if isinstance(row, dict) and row.get("number") == starvation_target), None)
                if _live_row is None:
                    print(f"::warning::starvation park skipped {repo}#{starvation_target}: the "
                          "holder vanished from the live listing between the two reads")
                elif park_starved_partition_holder(
                        repo, starvation_target, starved, _labels(_live_row),
                        park_pr=lambda number: _run_gh_target_api(
                            repo, "POST", f"repos/{repo}/issues/{number}/labels",
                            {"labels": [MACHINE_PARK_PR_LABEL]}),
                        post_comment=_run_gh_target_comment,
                        vetoed=lambda number: _park_policy.park_vetoed(
                            repo, number, MACHINE_PARK_PR_LABEL, _issue_timeline_events,
                            is_human=lambda probe: _target_is_human_maintainer(repo, probe))):
                    defer_reasons["partition-starvation-park"] += 1
            except DispatchError as exc:
                # One failed park never stops the tick: the lane is already starved, and the next
                # tick re-measures and retries. Loud, because a park that cannot be applied is the
                # difference between a self-healing fleet and a stalled one.
                print(f"::warning::starvation park FAILED {repo}#{starvation_target}: {exc}; the "
                      f"`{GLOBAL_PACKAGE}` partition is still held")

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
                    # [#701] THE LAYER THAT BINDS: escalate-the-tier vs decompose is decided HERE,
                    # from the validated ledger, BEFORE allocator.claim() picks a model — because
                    # the claim is what would otherwise walk the resolved chain from its head and
                    # re-run the exact tier that just returned nothing. Measured 2026-07-26: the
                    # same hard issue was retried up to 3x on the SAME model, so ~64% of worker
                    # capacity produced no diff at all.
                    #
                    # `decision` is one of:
                    #   proceed           — no attributable in-window no_change evidence; unchanged
                    #                       behaviour, the full chain claims as before.
                    #   retry-other-tier  — dispatch, but ONLY on chain tiers with no recent
                    #                       no_change for this issue. A strict, order-preserving
                    #                       subsequence, so the "claimed model must be in the
                    #                       resolved chain" guard below and worker.yml's adopt-side
                    #                       membership check both still hold.
                    #   decompose         — nothing left to escalate TO (or the model declared the
                    #                       task's SHAPE is the blocker). Fire the #500 reroute at
                    #                       a threshold of ONE, because a second identical outcome
                    #                       cannot inform a decision this evidence has already
                    #                       made.
                    #
                    # FAIL-CLOSED, restated because both directions are load-bearing: an unreadable
                    # health window already `continue`d above with NO escalation, so an unreadable
                    # exit class is neither no_change nor success; and an in-window row whose
                    # model_alias is empty retires no tier at all (it cannot prove which tier ran).
                    nc_decision, nc_chain = _no_change_routing.retry_decision(
                        resolved["model_chain"], no_changes, int(time.time()))
                    decline_threshold = (
                        1 if nc_decision == _no_change_routing.DECOMPOSE else DECLINE_ESCALATION_MIN)
                    if len(no_changes) >= decline_threshold:
                        comments = _pr_comments(repo, number)
                        decline_result = _escalate_repeated_declines(
                            repo, item, no_changes, comments, bot_login, script_dir,
                            min_outcomes=decline_threshold)
                        if decline_result != "proceed":
                            defer_reasons[f"decline-{decline_result}"] += 1
                            print(f"escalated {repo}#{number}: repeated no_change outcomes -> "
                                  f"{decline_result}; cached {item['role']} claim cancelled")
                            continue
                        # `proceed` after a DECOMPOSE decision means the reroute for this exact
                        # evidence is already applied and reconciled — the issue is on its new
                        # route. The evidence is spent: it must not also narrow the new route's
                        # chain to nothing, which would defer the decomposition forever. Fall
                        # through on the FULL chain and let the (now research-side) ladder bound it.
                        nc_decision, nc_chain = _no_change_routing.PROCEED, resolved["model_chain"]
                    if nc_decision == _no_change_routing.RETRY_OTHER_TIER:
                        # Narrowing, not degrading: the chain keeps routing.toml's order, so a
                        # security/soundness route that resolved to a single frontier tier can
                        # never fall to a weaker one — it has no other tier, so it took the
                        # `decompose` arm above instead.
                        print(f"reroute {repo}#{number}: a previous attempt exited no_change on "
                              f"{sorted(set(resolved['model_chain']) - set(nc_chain))}; this "
                              f"dispatch is restricted to {nc_chain}")
                        resolved = dict(resolved, model_chain=list(nc_chain))
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
                                # question now. RECEIPT-FIRST ordering (round-4 finding 2):
                                # the sticky veto is PROBED first (so the receipt is honest
                                # about a suppressed write), the durable receipt posts
                                # SECOND, and the veto-checked needs:user write (worker-issue
                                # set_status re-checks it at the write point) comes LAST — a
                                # crash after the receipt leaves receipt-no-label, which the
                                # receipt-driven ladder/proof reads cover; the old
                                # label-first order could die label-no-receipt, and a
                                # triage-side label removal then erased the escalation from
                                # every durable surface.
                                vetoed = _park_policy.park_vetoed(
                                    repo, number, "needs:user", _issue_timeline_events,
                                    is_human=lambda login: _target_is_human_maintainer(
                                        repo, login))
                                label_note = (
                                    " Escalated as a human question (`needs:user`; the "
                                    "label write follows this receipt)."
                                    if not vetoed else
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
                                landed = (False if vetoed else
                                          _issue_needs_user_landed(script_dir, repo, number))
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
                            # keeps every later tick quiet. RECEIPT-FIRST ordering (round-4
                            # finding 2): veto probe, then the receipt, then the label write
                            # — a crash after the receipt leaves receipt-no-label (the
                            # ladder/proof reads key on receipts), never label-no-receipt.
                            vetoed = _park_policy.park_vetoed(
                                repo, number, "status:parked", _issue_timeline_events,
                                is_human=lambda login: _target_is_human_maintainer(
                                    repo, login))
                            label_note = (
                                "Parking with the machine-owned `status:parked` soft hold "
                                "(the label write follows this receipt): the whole PR "
                                "surface holds (no review/fix dispatch, no new "
                                "implementation attempt) until a human readmission. "
                                if not vetoed else
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
                            parked = (False if vetoed else
                                      _park_source_issue(script_dir, repo, number))
                            defer_reasons["budget-exhausted"] += 1
                            print(f"escalated {repo}#{number}: deferred-retry budget "
                                  f"exhausted (generation {generation}"
                                  f"{'' if parked else ', label suppressed'})")
                            continue
            except RouteDivergenceError as exc:
                # [OPUS-5] Counted and annotated SEPARATELY from the situational failures below.
                # A divergence never self-clears, so folding it into `route-policy-failed` made a
                # permanent, whole-label-class outage indistinguishable from a handful of stale
                # issues — the review finding on sparq PR #4211. `::error::` puts it in the run's
                # annotations; it does not fail the tick, because the OTHER items must still go.
                defer_reasons["route-plan-claim-divergence"] += 1
                print(f"::error::defer {repo}#{number}: {exc}")
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
    # Issue #708 / #700: a planned-but-not-launched item must be ATTRIBUTED in the run output, not
    # merely subtracted. `deferred` was previously derivable only by arithmetic, and the defer-reason
    # histogram was rendered by the workflow's tick-health step ONLY on a zero/degraded tick — so a
    # review lane that planned 12 and launched 4 printed no reason for the other 8 whenever another
    # lane was productive. That is the missing edge BETWEEN stages #700 describes; print it
    # unconditionally, from the same counters the summary file carries (coarse categories only).
    lane_summary = _lane_summary(lanes)
    for name in DISPATCH_LANES:
        counts = lanes[name]
        print(f"lane {name}: planned={counts.get('planned', 0)} "
              f"launched={counts.get('launched', 0)} "
              f"deferred={lane_summary[name]['deferred']} "
              f"error={counts.get('error', 0)}")
    print("defer attribution: " + (", ".join(
        f"{reason}={count}" for reason, count in sorted(defer_reasons.items())) or "none"))

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


def _review_fix_workflow_values(source=None):
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
    text = path.read_text(encoding="utf-8") if source is None else source
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
    # Issue #560 lane-hand-over wiring, pinned to the WORKFLOW (the python halves cannot see it):
    # the `run` job must EXPORT stage-verdict's staged/stale_reason, the `outcome` job must ADMIT
    # the staged-nothing path (its old `if` skipped the whole job, which is why review:changes was
    # never cleared), it must INVOKE worker-pr.py fix-lane-defer, and the `release` job that frees
    # the `fix:<repo>#<pr>` claim must stay UNCONDITIONAL and independent of the outcome job.
    release_span = spans.get("release")
    assert release_span is not None, "review-fix.yml is missing the release job"
    outcome_span = spans.get("outcome")
    assert outcome_span is not None, "review-fix.yml is missing the outcome job"
    release_if = re.search(r"(?m)^    if: (.+)$", release_span)
    release_needs = re.search(r"(?m)^    needs: (.+)$", release_span)
    outcome_if = re.search(r"(?m)^    if: (.+)$", outcome_span)
    run_if = re.search(r"(?m)^    if: (.+)$", run_span)
    assert release_if and release_needs and outcome_if, "review-fix.yml if/needs not parsable"
    return {
        "resolve_s": _fixed_minutes("resolve") * 60,
        "claim_s": _fixed_minutes("claim") * 60,
        "release_s": _fixed_minutes("release") * 60,
        "run_review_s": int(run_m.group(1)) * 60,
        "run_fix_s": int(run_m.group(2)) * 60,
        "local_review_ttl": int(ttl_review.group(1)),
        "local_fix_ttl": int(ttl_fix.group(1)),
        "run_exports_staged": "verdict_staged: ${{ steps.stage-verdict.outputs.staged }}"
                              in run_span,
        "run_exports_stale_reason":
            "verdict_stale_reason: ${{ steps.stage-verdict.outputs.stale_reason }}" in run_span,
        "outcome_if": outcome_if.group(1),
        "outcome_hands_over": "worker-pr.py fix-lane-defer" in outcome_span,
        # Round-2 finding 1: the hand-over must also be told WHICH head the verdict was not bound
        # to, or it can only flip the label and the spin relocates into the review lane's
        # already_done exit. The CLI makes --head-sha required, so a workflow that stops passing it
        # fails the step loudly — but pin the wiring statically too, since a red step every tick is
        # still a regression this gate should catch before merge.
        "outcome_passes_head_sha": bool(re.search(
            r"fix-lane-defer(?:[^\n]|\n)*?--head-sha \"\$\{\{ needs\.resolve\.outputs\.head_sha "
            r"\}\}\"", outcome_span)),
        "release_if": release_if.group(1),
        "release_needs": release_needs.group(1),
        # Issue #708: the two workflow facts that make this script's review-launch invariant TRUE.
        # The dispatcher refuses to spend a reviewer lease on a head whose reviewed-sha marker is
        # already bound BECAUSE (1) the claim job's `already_done` step writes acquired=false and
        # (2) the run job — the only job that executes a model — is gated on acquired == 'true'.
        # Both live in YAML that no python half can see, and a `count(...)`/substring assertion in
        # this module would not notice either of them being edited away. Parse them, so the
        # invariant is pinned to the workflow it is derived from.
        "run_if": run_if.group(1) if run_if else "",
        # Tempered so the match cannot run past the end of the already_done STEP into a sibling
        # step that happens to write acquired=false (the rc=3 none-free branch does).
        "claim_skips_already_done": bool(re.search(
            r"if: \$\{\{ needs\.resolve\.outputs\.already_done == 'true' \}\}"
            r"(?:(?!\n      - name:)[\s\S])*?acquired=false", claim_span)),
    }


# The `already_done` idempotence predicate embedded in review-fix.yml's resolve step, addressed by
# LINE-ANCHORED regexes rather than by exact indentation-bearing literals (#584 follow-up finding 3).
_RF_ALREADY_DONE_ANCHOR = r"(?m)^[ \t]*already_done = False$"
_RF_ALREADY_DONE_END = r"(?m)^[ \t]*#[ \t]*REGISTRY provenance"

# ---- THE MINT-vs-ADOPT AGREEMENT ANCHORS (registry issue #112 / the 2026-07-26 review-lane loop).
# Both adopt paths (review-fix.yml's `claim` job and worker.yml's `claim` job) compare a value the
# DISPATCHER minted against a value the run RE-DERIVES, for EQUALITY. Every such value is therefore
# a drift axis, and a prose comment promising two copies "mirror" each other is not a test: that is
# precisely how #3528 burned ~20% of one day's review-lane capacity. Each anchor below addresses a
# re-derivation so the self-test can EXECUTE the workflow's own code and require agreement with the
# canonical definition. Line-anchored regexes (never indentation-bearing literals) per #584 f3.

# review-fix.yml `resolve`: the `package` partition must come from THIS module's plan_package — the
# same function object the dispatcher mints the claim with.
_RF_PACKAGE_ANCHOR = r"(?m)^[ \t]*package = dispatch_claim\.plan_package\(packages\)$"
_RF_PACKAGE_END = r"(?m)^[ \t]*values = \{"

# review-fix.yml `policy`: the review/fix/escalation ROUTING TABLES. These are re-derived inline and
# were held to dispatch-claim.REVIEW_CHAIN / FIX_CHAIN and worker-pr.ESCALATION_LADDERS by a comment
# only. A drift here makes the adopt step's `model not in models` guard fire on every affected PR.
_RF_CHAINS_ANCHOR = r"(?m)^[ \t]*review_chain = \{"
_RF_CHAINS_END = r"(?m)^[ \t]*docs_only = \{"

# worker.yml `claim`, self-claim SHELL step: the lease partition must be COMPUTED by the canonical
# reduction's CLI, not open-coded in bash.
_WK_SELF_PACKAGE_ANCHOR = r"(?m)^[ \t]*lease_package=.*$"
_WK_SELF_PACKAGE_END = r"(?m)^[ \t]*set \+e$"
_WK_SELF_PACKAGE_CALL = 'python3 registry/scripts/lease_schema.py --plan-package "$PACKAGES"'

# worker.yml `claim`, adopt-validator PYTHON step: the expected partition must be IMPORTED from
# lease_schema, so the impl lane's own mint-vs-adopt equality cannot drift the way the review
# lane's did.
_WK_ADOPT_PACKAGE_ANCHOR = r"(?m)^[ \t]*import importlib\.util as _ilu$"
_WK_ADOPT_PACKAGE_END = r"(?m)^[ \t]*if account != os\.environ\[\"EXPECTED_ACCOUNT\"\]"
_WK_ADOPT_PACKAGE_CALL = "lease_schema.plan_package(areas)"


def _workflow_step_python(workflow, job, anchor, end_anchor, what, source=None):
    """`_review_fix_step_python` generalised over the WORKFLOW file, so the same PARSED extraction
    can pin worker.yml's two copies of the partition reduction (the review of #702 measured that
    both could be reverted to the pre-#112 rule with the whole enrolled suite staying green)."""
    import yaml  # self-test-only, same lazy import shape as resolve-conflicts.validate_syntax_blob
    if source is None:
        path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / workflow
        assert path.is_file(), f"{workflow} not found for the {what} pin: {path}"
        source = path.read_text(encoding="utf-8")
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise AssertionError(
            f"{workflow} does not parse as YAML, so the {what} pin cannot be derived: "
            f"{exc}") from None
    steps = (((document or {}).get("jobs") or {}).get(job) or {}).get("steps")
    assert isinstance(steps, list), (
        f"{workflow} exposes no jobs.{job}.steps list, so the {what} pin cannot be derived — "
        f"if the `{job}` job was renamed, re-point the `job=` argument in dispatch-claim.py")
    matches = [step["run"] for step in steps
               if isinstance(step, dict) and isinstance(step.get("run"), str)
               and re.search(anchor, step["run"])]
    assert len(matches) == 1, (
        f"expected EXACTLY ONE `run:` step in {workflow}'s `{job}` job to match the {what} "
        f"anchor {anchor!r}; found {len(matches)}. The workflow's {what} was moved, renamed or "
        f"rewritten — re-point the anchor constant in dispatch-claim.py so this cross-script pin "
        f"keeps EXECUTING the workflow's real code instead of failing on a text address.")
    run = matches[0]
    begin = re.search(anchor, run)
    end = re.search(end_anchor, run[begin.start():])
    assert end, (
        f"{workflow}'s {what} block starts at {anchor!r} but no longer ends at "
        f"{end_anchor!r} — re-point the end-anchor constant in dispatch-claim.py so the extracted "
        f"block still stops before the code that follows it.")
    return textwrap.dedent(run[begin.start():begin.start() + end.start()])


# The PARSED nodes that carry the partition value from the resolve job into each adopt/self-claim
# step. Compared for EQUALITY against the parsed document, never grepped: `if: false`, a deleted
# step, and an `env:` input re-pointed at the neighbouring `packages` output are ALL invisible to a
# substring or `count(...) == N` assertion over the workflow text, and every one of them silently
# disables the partition agreement rather than failing loudly.
_PARTITION_SEAM = {
    "review-fix.yml": {
        "resolve_outputs": {"package": "${{ steps.pr.outputs.package }}",
                            "packages": "${{ steps.pr.outputs.packages }}"},
        "steps": {
            "claim": {"if": "${{ inputs.claim_id == '' && "
                            "needs.resolve.outputs.already_done != 'true' }}",
                      "env": {"PACKAGE": "${{ needs.resolve.outputs.package }}"}},
            "adopt": {"if": "${{ inputs.claim_id != '' && "
                            "needs.resolve.outputs.already_done != 'true' }}",
                      "env": {"PACKAGE": "${{ needs.resolve.outputs.package }}"}},
        },
    },
    "worker.yml": {
        "resolve_outputs": {"packages": "${{ steps.issue.outputs.packages }}"},
        "steps": {
            "claim": {"if": "${{ inputs.claim_id == '' }}",
                      "env": {"PACKAGES": "${{ needs.resolve.outputs.packages }}"}},
            "adopt": {"if": "${{ inputs.claim_id != '' }}",
                      "env": {"PACKAGES": "${{ needs.resolve.outputs.packages }}"}},
        },
    },
}


# [OPUS-5] registry #701 — THE YAML SEAM of the no_change evidence path, in worker.yml.
#
# Everything the routing decision does is downstream of ONE wire: worker-live.sh classifies the
# exit, the `exit-class` step lifts it (plus the no-change envelope carrying `why:<index>`) into the
# `worker` job's outputs, and the separate no-target-code `model_health` job turns those outputs
# into the validated ledger row that dispatch later routes on. Cut that wire anywhere and the
# dispatcher sees NO no_change evidence — every issue looks freshly dispatchable, and the fleet goes
# straight back to retrying the same tier. That failure is SILENT: no job goes red.
#
# STRUCTURAL, on PARSED nodes, for the standing measured reason: a substring or `count(...) == N`
# assertion over the workflow TEXT cannot tell a live step from one carrying `if: false`, cannot see
# a deleted step, and cannot see an `env:` input re-pointed at a neighbouring output. Every entry
# below is one parsed node, and the self-test mutates each in memory and demands the violation back.
_NO_CHANGE_SEAM = {
    # The `worker` job must EXPORT the exit class and the (envelope-bearing) reset hint...
    "worker_outputs": {
        "exit_class": "${{ steps.exit-class.outputs.class }}",
        "reset_hint": "${{ steps.exit-class.outputs.reset_hint }}",
    },
    # ...from a step that runs on EVERY path. `always()` is load-bearing: the classes that matter
    # most are failures, and a success-only guard would record nothing exactly when it matters.
    "worker_step": ("exit-class", "${{ always() && !inputs.dry_run }}"),
    # The recorder job must be gated on the class being NON-EMPTY (never on success), must depend
    # on `worker` for its outputs, and must feed BOTH values through as env — never inline in the
    # `run:` shell, where provider-derived text would execute (issue #199).
    "health_if": "${{ always() && !inputs.dry_run && needs.claim.outputs.acquired == 'true' "
                 "&& needs.worker.outputs.exit_class != '' }}",
    "health_needs": "worker",
    "health_step_name": "Append the model-access health record (salted account hash only)",
    "health_env": {
        "EXIT_CLASS": "${{ needs.worker.outputs.exit_class }}",
        "RESET_HINT": "${{ needs.worker.outputs.reset_hint }}",
    },
    # ...and the recorder must actually PASS the hint to the script that decodes the envelope.
    "health_run_fragments": ("model-health.py record", '--exit-class "$EXIT_CLASS"',
                             '--reset-hint "$RESET_HINT"'),
}


def _no_change_seam_violations(document):
    """The #701 evidence-path seam, checked STRUCTURALLY against a PARSED worker.yml document.
    Returns a sorted list of violation strings; empty means the wire is intact."""
    out = []
    jobs = (document or {}).get("jobs") or {}
    worker_outputs = (jobs.get("worker") or {}).get("outputs") or {}
    for name, value in _NO_CHANGE_SEAM["worker_outputs"].items():
        if worker_outputs.get(name) != value:
            out.append(f"worker.yml: jobs.worker.outputs.{name} must be {value!r} (found "
                       f"{worker_outputs.get(name)!r}) — the model_health job reads it, so a "
                       f"deleted or re-pointed output records the wrong outcome (or none)")
    step_id, wanted_if = _NO_CHANGE_SEAM["worker_step"]
    worker_steps = (jobs.get("worker") or {}).get("steps")
    if not isinstance(worker_steps, list):
        out.append("worker.yml: jobs.worker.steps is not a list, so the exit-class seam is gone")
    else:
        step = next((s for s in worker_steps
                     if isinstance(s, dict) and s.get("id") == step_id), None)
        if step is None:
            out.append(f"worker.yml is missing the `{step_id}` step in jobs.worker — nothing else "
                       "classifies the model exit, so no no_change evidence is ever produced")
        elif step.get("if") != wanted_if:
            out.append(f"worker.yml: jobs.worker step `{step_id}` `if:` is not the always()-guard "
                       f"(found {step.get('if')!r}) — `if: false`, or a success-only guard, drops "
                       "the exit class SILENTLY on exactly the failing runs that matter")
    health = jobs.get("model_health")
    if not isinstance(health, dict):
        out.append("worker.yml is missing the `model_health` job — the exit class is never "
                   "recorded, so the dispatcher has no no_change evidence to route on")
        return sorted(out)
    if health.get("if") != _NO_CHANGE_SEAM["health_if"]:
        out.append("worker.yml: jobs.model_health `if:` is not the non-empty-exit-class guard "
                   f"(found {health.get('if')!r}) — `if: false` or a success-only condition "
                   "silently stops recording the failures this routes on")
    if _NO_CHANGE_SEAM["health_needs"] not in (health.get("needs") or []):
        out.append("worker.yml: jobs.model_health must `needs:` the worker job — without that "
                   "edge its needs.worker.outputs.* reads are empty")
    steps = health.get("steps")
    step = next((s for s in steps if isinstance(s, dict)
                 and s.get("name") == _NO_CHANGE_SEAM["health_step_name"]), None) \
        if isinstance(steps, list) else None
    if step is None:
        out.append("worker.yml is missing the model_health record step — no ledger row is written")
        return sorted(out)
    env = step.get("env") or {}
    for key, value in _NO_CHANGE_SEAM["health_env"].items():
        if env.get(key) != value:
            out.append(f"worker.yml: model_health record step env.{key} must be {value!r} (found "
                       f"{env.get(key)!r}) — a deleted or re-pointed input records the wrong "
                       "class, or drops the no-change envelope that carries why_no_diff")
    run = step.get("run")
    if not isinstance(run, str):
        out.append("worker.yml: the model_health record step has no `run:` script")
        return sorted(out)
    for fragment in _NO_CHANGE_SEAM["health_run_fragments"]:
        if fragment not in run:
            out.append(f"worker.yml: the model_health record step no longer passes {fragment!r} — "
                       "the exit class or the no-change envelope never reaches the ledger")
    return sorted(out)


def _partition_seam_violations(workflow, document):
    """The YAML SEAM of the mint-vs-adopt partition agreement, checked STRUCTURALLY against a
    PARSED workflow document. Returns a sorted list of violation strings; empty means intact.

    Structural on purpose. The standing measured finding on this repo is that every uncaught mutant
    lives at the YAML seam rather than in the Python, and each check below reads one specific parsed
    node so the self-test can prove NON-VACUITY by mutating that node in memory and requiring the
    matching violation back. Takes the parsed document (not text) so a mutant needs no round-trip."""
    expected = _PARTITION_SEAM[workflow]
    out = []
    jobs = (document or {}).get("jobs") or {}
    resolve_outputs = (jobs.get("resolve") or {}).get("outputs") or {}
    for name, value in expected["resolve_outputs"].items():
        if resolve_outputs.get(name) != value:
            out.append(f"{workflow}: jobs.resolve.outputs.{name} must be {value!r} (found "
                       f"{resolve_outputs.get(name)!r}) — the adopt step's partition agreement "
                       f"reads it, so a re-pointed or deleted output compares the wrong value")
    steps = (jobs.get("claim") or {}).get("steps")
    if not isinstance(steps, list):
        out.append(f"{workflow}: jobs.claim.steps is not a list, so the partition seam is gone")
        return sorted(out)
    by_id = {step.get("id"): step for step in steps if isinstance(step, dict)}
    for step_id, wanted in expected["steps"].items():
        step = by_id.get(step_id)
        if step is None:
            out.append(f"{workflow} is missing the `{step_id}` step in jobs.claim — the partition "
                       f"reduction it carries cannot run, and NOTHING else derives it on that "
                       f"entry path")
            continue
        if step.get("if") != wanted["if"]:
            out.append(f"{workflow}: jobs.claim step `{step_id}` `if:` is not the expected "
                       f"claim-id entry guard (found {step.get('if')!r}) — `if: false` or an "
                       f"inverted comparison skips the partition derivation SILENTLY")
        env = step.get("env") or {}
        for key, value in wanted["env"].items():
            if env.get(key) != value:
                out.append(f"{workflow}: jobs.claim step `{step_id}` env.{key} must be {value!r} "
                           f"(found {env.get(key)!r}) — re-pointing it at the neighbouring "
                           f"packages/package output feeds the reduction the wrong input")
    return sorted(out)


def _review_fix_step_python(anchor, end_anchor, what, job="resolve", source=None):
    """Extract a python block VERBATIM out of a review-fix.yml step's `run:` script so a
    cross-script self-test can execute the WORKFLOW's real predicate instead of a re-implemented
    copy that can silently drift from it.

    PARSED, not text-sliced (#584 follow-up finding 3). The previous implementation sliced the raw
    file with two `str.index()` calls on indentation-bearing literals ("          already_done =
    False\\n"), so ANY reflow of that YAML — re-indenting the job, changing the block-scalar style,
    moving the step — killed the REQUIRED `gate` check with a bare `ValueError: substring not found`
    that named neither the file, the anchor, nor what to update. Loading the YAML makes block-scalar
    indentation the parser's problem (a `run:` scalar comes back already de-indented, so a reflow
    that preserves the script is invisible here) and EVERY failure mode now raises an ACTIONABLE
    AssertionError naming the anchor and the edit that fixes it.

    PyYAML is already a hard dependency of the enrolled self-test suite (resolve-conflicts.py's
    validate_syntax_blob imports it, and its --self-test exercises that path), and pr-gate.yml
    installs it version+hash-locked BEFORE running the suite — so this adds no new gate dependency.

    `source` (the workflow text) exists so the self-test can feed a REFLOWED copy through and prove
    the extraction survives it.

    Thin wrapper over `_workflow_step_python` (which generalises it over the workflow FILE so
    worker.yml's copies of the partition reduction are pinned by the same idiom)."""
    return _workflow_step_python("review-fix.yml", job, anchor, end_anchor, what, source=source)


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
    # Issue #560 lane-hand-over wiring (see _review_fix_workflow_values). Without these the fix
    # lane silently re-acquires the SAME deferred PR every dispatch tick: the enumerator's bucket
    # is the review:changes label, and only this wiring clears it.
    assert _wf["run_exports_staged"], "review-fix.yml run job must export verdict_staged (#560)"
    assert _wf["run_exports_stale_reason"], (
        "review-fix.yml run job must export verdict_stale_reason (#560)")
    assert "needs.run.outputs.verdict_stale_reason != ''" in _wf["outcome_if"], (
        "review-fix.yml outcome job must ADMIT the staged-nothing fix path (#560): "
        f"{_wf['outcome_if']}")
    assert _wf["outcome_hands_over"], (
        "review-fix.yml outcome job must invoke worker-pr.py fix-lane-defer (#560)")
    assert _wf["outcome_passes_head_sha"], (
        "review-fix.yml outcome job must pass --head-sha to fix-lane-defer (#560 round-2 finding "
        "1): without the disproved head the stale reviewed-sha assertion cannot be retracted and "
        "the hand-over only RELOCATES the spin into the review lane's already_done exit")
    # The claim/lease release must not depend on the hand-over: it frees `fix:<repo>#<pr>` on
    # EVERY path (always() + acquired) from a job that does not `needs:` the outcome job, so a
    # deferred fix never holds the per-PR single-flight lease into the next tick.
    assert "always()" in _wf["release_if"] \
        and "needs.claim.outputs.acquired == 'true'" in _wf["release_if"], _wf["release_if"]
    assert "outcome" not in _wf["release_needs"], (
        "review-fix.yml release must not depend on the outcome job (#560 lease release): "
        f"{_wf['release_needs']}")

    # ---- ISSUE #708: THE YAML SEAM THE REVIEW-LAUNCH INVARIANT RESTS ON -------------------------
    # This module refuses to spend a reviewer lease on a head whose reviewed-sha marker is already
    # bound. That refusal is only correct while review-fix.yml keeps BOTH halves of the behaviour it
    # is derived from, and both halves are pure YAML/`run:` text that no python assertion in this
    # module would otherwise see:
    #   1. resolve computes `already_done = (marker == head_sha)` — executed for real below,
    #   2. claim's already_done step writes `acquired=false`, and
    #   3. the `run` job (the ONLY job that executes a model) is gated on acquired == 'true'.
    # Delete (2) or (3) and the dispatcher would be refusing dispatches that WOULD have run a model
    # — a self-inflicted starvation exactly as bad as the spin this closes. Pin them.
    assert _wf["claim_skips_already_done"], (
        "review-fix.yml's claim job must still write acquired=false on already_done (#708): the "
        "dispatcher's review-launch invariant refuses marker-bound heads BECAUSE that step skips "
        "the model")
    assert "needs.claim.outputs.acquired == 'true'" in _wf["run_if"], (
        "review-fix.yml's run job must stay gated on claim.acquired (#708): "
        f"{_wf['run_if']!r}")
    # NON-VACUITY at the seam. A substring/count assertion cannot catch `if: false`, so mutate the
    # workflow STRUCTURALLY and require each mutant to be caught. (Measured on this project: every
    # uncaught mutant of an earlier fix lived at the YAML seam, not in the python.)
    _rf_text = (Path(__file__).resolve().parents[1] / ".github" / "workflows"
                / "review-fix.yml").read_text(encoding="utf-8")
    for _mutant, _field, _want in (
            (_rf_text.replace(
                "    if: ${{ needs.claim.outputs.acquired == 'true' }}\n"
                "    runs-on: ubuntu-latest\n"
                "    timeout-minutes: ${{ inputs.mode == 'review'",
                "    if: ${{ always() }}\n"
                "    runs-on: ubuntu-latest\n"
                "    timeout-minutes: ${{ inputs.mode == 'review'"),
             "run_if", "needs.claim.outputs.acquired == 'true'"),
            (_rf_text.replace("printf 'acquired=false\\n' >> \"$GITHUB_OUTPUT\"\n"
                              "          printf 'This head was already reviewed",
                              "printf 'acquired=true\\n' >> \"$GITHUB_OUTPUT\"\n"
                              "          printf 'This head was already reviewed"),
             "claim_skips_already_done", True)):
        assert _mutant != _rf_text, (
            "the #708 YAML-seam mutation matched nothing — the anchor drifted, re-point it")
        _mutated = _review_fix_workflow_values(source=_mutant)
        if _field == "run_if":
            assert _want not in _mutated[_field], (
                "an ungated review-fix run job must FLIP the #708 seam assertion red, but the "
                f"extractor still reported {_mutated[_field]!r}")
        else:
            assert _mutated[_field] is not _want, (
                "a claim step that no longer writes acquired=false must FLIP the #708 seam "
                "assertion red")
    # And the predicate itself: execute review-fix.yml's REAL `already_done` block on exactly the
    # {body, head_sha} pair this module refuses to dispatch, so the refusal is justified by the
    # LIVE workflow rather than by a re-implemented copy that can drift from it.
    _708_head = "e" * 40
    _708_src = _review_fix_step_python(
        _RF_ALREADY_DONE_ANCHOR, _RF_ALREADY_DONE_END, "already_done idempotence predicate")
    for _708_body, _708_want, _708_why in (
            (f"x <!-- sparq-reviewed-sha:{_708_head} -->", True,
             "a marker-bound head resolves already_done -> the model job is skipped"),
            (f"x <!-- sparq-reviewed-sha:{'f' * 40} -->", False,
             "a marker naming another head is reviewable"),
            ("<!-- sparq-reviewed-sha:none -->", False,
             "a RETRACTED marker is reviewable — this is what stranded-recover produces"),
            ("no marker at all", False, "an absent marker is reviewable")):
        _708_ns = {"re": re, "mode": "review", "head_sha": _708_head,
                   "pull": {"body": _708_body}}
        exec(compile(_708_src, "<review-fix.yml already_done>", "exec"), _708_ns)  # noqa: S102
        assert _708_ns["already_done"] is _708_want, (_708_why, _708_body)
    print("  ok   #708: the review-launch invariant is pinned to review-fix.yml's LIVE "
          "already_done predicate, its acquired=false skip, and its acquired-gated run job — "
          "each seam mutated structurally")
    print("  ok   #560: review-fix.yml exports the defer reason, admits the staged-nothing "
          "outcome path, invokes fix-lane-defer, and still releases the fix lease "
          "unconditionally")

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
                             unreadable=False, model_chain=("sol",)):
        """One complete deferred dispatch tick with fake GitHub transports and real validators."""
        labels = sorted([
            "area:dispatch", "priority:P1", f"role:{role}", "status:deferred",
        ])
        body = "Investigate and implement the dispatch boundary."
        item = {
            "number": 500, "priority": 1, "package": "dispatch", "role": role,
            "model_chain": list(model_chain), "agent": "registry-impl", "escalate": False,
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
            "partition_starvation": [],
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
                # [#701] The chain the dispatcher actually offered the allocator. THE tripwire for
                # "a no_change never re-dispatches the tier that produced it": positional arg 3 of
                # allocator.claim(registry_repo, package, role, model_chain, ...).
                self.claimed_chains = []

            def claim(self, *args, **_kwargs):
                self.claim_calls += 1
                self.claimed_chains.append(list(args[3]))
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
            "claimed_chains": allocator.claimed_chains,
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
        comments=[{"user": {"login": "sparq[bot]"}, "body": marker_body,
                   "created_at": "2026-07-23T09:00:00Z"}])
    assert bot_marked["api_calls"] == [] and bot_marked["helper_calls"] == [], bot_marked
    assert bot_marked["claim_calls"] == 1, bot_marked
    forged = run_decline_tripwire(
        [no_change_a, no_change_b], role="research",
        comments=[{"user": {"login": "mallory"}, "body": marker_body,
                   "created_at": "2026-07-23T09:00:00Z"}])
    assert [call[0] for call in forged["api_calls"]] == ["POST"], forged
    assert len(forged["helper_calls"]) == 1 and forged["claim_calls"] == 0, forged
    print("  ok   decline tripwire (e): bot marker is idempotent; third-party forgery is ignored")

    # (f) [registry #596] `auth` is NOT a decline. A whole window of credential-outage outcomes for
    # the SAME issue — more than DECLINE_ESCALATION_MIN of them — must perform NO escalation: no
    # marker, no impl->research reroute, no park, and the ordinary deferred claim stays live.
    # This is the ladder half of #596: acct01's hourly-expiring codex token produced runs of `auth` outcomes
    # that must never read as "the model gave up on this task".
    auth_records = [
        model_health.make_record("openai", "a" * 16, "codex", "auth", f"600{i}.1",
                                 decline_now - 60 + (i * 10))
        for i in range(DECLINE_ESCALATION_MIN + 3)
    ]
    assert len(auth_records) > DECLINE_ESCALATION_MIN, auth_records
    assert {r["exit_class"] for r in auth_records} == {model_health.CLASS_AUTH}, auth_records
    trip_f = run_decline_tripwire(auth_records)
    assert trip_f["api_calls"] == [] and trip_f["helper_calls"] == [], trip_f
    assert trip_f["claim_calls"] == 1, trip_f
    assert DECLINE_ESCALATION_MARKER not in trip_f["output"], trip_f["output"]
    # The evidence selector itself is the guard: auth rows never enter the decline window, while a
    # genuine no_change pair still does (so the ladder is not disabled, only made honest).
    assert _issue_no_change_outcomes(model_health, auth_records, 500) == [], auth_records
    assert len(_issue_no_change_outcomes(
        model_health, auth_records + [no_change_a, no_change_b], 500)) == 2
    print("  ok   decline tripwire (f): a run of auth outcomes never advances the decline ladder")

    # ---- [registry #701] NO_CHANGE MUST NOT RE-DISPATCH THE TIER THAT PRODUCED IT ---------------
    # Measured 2026-07-26: 196 completed worker runs, 70 success / 126 failure, dominated by
    # `no_change`, and the same hard issue retried up to 3x on the SAME model with no record of why
    # the previous attempt produced nothing. Every tripwire below drives the REAL dispatch() call
    # site and asserts on the chain the allocator was actually offered — a helper-only assertion
    # would stay green if dispatch stopped consulting the decision.
    def nc_record(alias, ts_offset, why=None, issue=500):
        return model_health.make_record(
            "openai" if alias in ("sol", "luna", "terra", "codex") else "anthropic",
            "c" * 16, alias, "no_change", f"7{ts_offset:03d}.1", decline_now + ts_offset,
            issue=issue, why_no_diff=why)

    # (g) THE HEADLINE GUARD, escalate arm. One no_change on `sol` with an UNTRIED tier left: the
    # issue still dispatches (no escalation, no park — it is not intractable yet), but the chain
    # offered to the allocator EXCLUDES the tier that just returned nothing. Deleting the
    # `resolved = dict(resolved, model_chain=...)` line turns the chain assertion red while the
    # claim-count assertion stays green — which is exactly the pre-fix behaviour.
    trip_g = run_decline_tripwire([nc_record("sol", -20)], model_chain=("opus5", "sol"))
    assert trip_g["api_calls"] == [] and trip_g["helper_calls"] == [], trip_g
    assert trip_g["claim_calls"] == 1, trip_g
    assert trip_g["claimed_chains"] == [["opus5"]], trip_g["claimed_chains"]
    assert "sol" not in trip_g["claimed_chains"][0], trip_g["claimed_chains"]
    print("  ok   #701 (g): a no_change on `sol` re-dispatches on the UNTRIED tier, never on sol")

    # (h) THE HEADLINE GUARD, decompose arm. One no_change on the ONLY tier the route has: there is
    # nothing to escalate to, so the #500 reroute fires at a threshold of ONE — impl -> research —
    # and the cached impl claim is cancelled. Before this change the same input produced a second,
    # identical `sol` dispatch.
    trip_h = run_decline_tripwire([nc_record("sol", -20)], model_chain=("sol",))
    assert [call[0] for call in trip_h["api_calls"]] == ["POST", "GET", "PATCH"], trip_h
    assert DECLINE_ESCALATION_MARKER in trip_h["api_calls"][0][2]["body"], trip_h
    assert trip_h["api_calls"][-1][2]["labels"] == [
        "area:dispatch", "priority:P1", "role:research", "status:deferred"], trip_h
    assert trip_h["claim_calls"] == 0 and trip_h["claimed_chains"] == [], trip_h
    print("  ok   #701 (h): a spent single-tier chain decomposes on the FIRST no_change, and "
          "launches nothing")

    # (i) why_no_diff is LOAD-BEARING, not decoration: a declared `too_large` decomposes even
    # though an untried tier exists, because a different model does not make a task fit in one
    # session. Removing the DECOMPOSE_REASONS check turns this into a (g)-shaped lateral retry.
    trip_i = run_decline_tripwire([nc_record("sol", -20, why="too_large")],
                                  model_chain=("opus5", "sol"))
    assert [call[0] for call in trip_i["api_calls"]] == ["POST", "GET", "PATCH"], trip_i
    assert trip_i["claim_calls"] == 0, trip_i
    # ...while the DEFAULT (undeclared) reason must NOT: that is the fail-closed direction, and
    # collapsing it would mark every silent failure intractable.
    trip_i2 = run_decline_tripwire([nc_record("sol", -20)], model_chain=("opus5", "sol"))
    assert trip_i2["claim_calls"] == 1 and trip_i2["claimed_chains"] == [["opus5"]], trip_i2
    print("  ok   #701 (i): a declared too_large decomposes; an UNDECLARED reason does not")

    # (j) AN UNREADABLE EXIT CLASS IS NEITHER no_change NOR SUCCESS. `unknown` is the fold target
    # model-health uses when the host observed no attributable CLI exit. A whole window of them
    # must narrow nothing, escalate nothing, and leave the FULL chain claimable.
    unknown_records = [
        model_health.make_record("openai", "c" * 16, "sol", "unknown", f"80{i}.1",
                                 decline_now - 50 + (i * 10))
        for i in range(4)
    ]
    assert {r["exit_class"] for r in unknown_records} == {model_health.CLASS_UNKNOWN}
    trip_j = run_decline_tripwire(unknown_records, model_chain=("opus5", "sol"))
    assert trip_j["api_calls"] == [] and trip_j["helper_calls"] == [], trip_j
    assert trip_j["claim_calls"] == 1, trip_j
    assert trip_j["claimed_chains"] == [["opus5", "sol"]], trip_j["claimed_chains"]
    print("  ok   #701 (j): `unknown` exit classes are neither no_change nor success — full chain")

    # (k) THE TERMINAL IS MACHINE-RECOVERABLE. An issue already on the non-implementation route
    # whose only tier is spent takes the MACHINE-owned `status:parked` soft hold — never
    # `needs:user` (registry #703: human-only parks become a conveyor onto the maintainer's desk).
    # The park clears on its own once the evidence ages out of the health window.
    trip_k = run_decline_tripwire([nc_record("opus5", -20)], role="research",
                                  model_chain=("opus5",))
    assert [call[0] for call in trip_k["api_calls"]] == ["POST"], trip_k
    assert len(trip_k["helper_calls"]) == 1, trip_k
    assert trip_k["helper_calls"][0][1][-2:] == ["--status", "parked"], trip_k
    assert "needs:user" not in json.dumps(trip_k["helper_calls"]), trip_k
    assert "needs-user" not in json.dumps(trip_k["helper_calls"]), trip_k
    assert trip_k["claim_calls"] == 0, trip_k
    print("  ok   #701 (k): the terminal is status:parked (machine-recoverable), never needs:user")

    # (k2) [OPUS-5] registry #738 — THE SINGLE-RUNG `role:impl` CHAIN TAKES THE DECOMPOSE ARM.
    # Removing sol from the impl fallback left `role:impl` at `["opus5"]`, so #733's
    # `retry-other-tier` arm has no other tier to narrow TO. It must therefore take the `decompose`
    # arm — reroute at a threshold of ONE — and must NOT dead-end (no second identical opus5
    # dispatch, no silent defer with the evidence unspent). Driven through the REAL dispatch() call
    # site with the impl role, not by asserting on retry_decision in isolation.
    #
    # MUTANT: make retry_decision return PROCEED on an emptied chain => `claim_calls` becomes 1 and
    # the reroute API calls vanish => RED.
    assert _no_change_routing.retry_decision(
        ["opus5"], [nc_record("opus5", -20)], decline_now) == (_no_change_routing.DECOMPOSE, [])
    trip_k2 = run_decline_tripwire([nc_record("opus5", -20)], role="impl",
                                   model_chain=("opus5",))
    assert [call[0] for call in trip_k2["api_calls"]] == ["POST", "GET", "PATCH"], trip_k2
    assert DECLINE_ESCALATION_MARKER in trip_k2["api_calls"][0][2]["body"], trip_k2
    assert trip_k2["api_calls"][-1][2]["labels"] == [
        "area:dispatch", "priority:P1", "role:research", "status:deferred"], trip_k2
    assert trip_k2["claim_calls"] == 0 and trip_k2["claimed_chains"] == [], trip_k2
    assert "needs:user" not in json.dumps(trip_k2["api_calls"]), trip_k2
    print("  ok   #738 (k2): a no_change on the OPUS5-ONLY impl chain decomposes on the FIRST "
          "outcome — never a second identical opus5 dispatch, never a needs:user park")

    # (l) NO DEADLOCK AFTER THE REROUTE. Once the reroute for this exact evidence is receipted and
    # the issue sits on its new route, the SAME evidence must not also narrow the new route's chain
    # to nothing — that would defer the decomposition forever. The spent evidence falls through on
    # the FULL chain, and the ladder (now research-side) is what bounds it from there.
    _, nc_key = _decline_escalation_evidence([nc_record("opus5", -20)])
    trip_l = run_decline_tripwire(
        [nc_record("opus5", -20)], role="research", model_chain=("opus5",),
        comments=[{"user": {"login": "sparq[bot]"},
                   "body": f"<!-- {DECLINE_ESCALATION_MARKER} key={nc_key} action=research -->",
                   "created_at": "2026-07-26T09:00:00Z"}])
    assert trip_l["api_calls"] == [] and trip_l["helper_calls"] == [], trip_l
    assert trip_l["claim_calls"] == 1 and trip_l["claimed_chains"] == [["opus5"]], trip_l
    print("  ok   #701 (l): a receipted reroute does not strand the new route on an empty chain")

    # (m) THE LADDER TERMINATES, driven through the REAL call site rather than argued about.
    # Walk a THREE-rung impl chain: every tick must either dispatch on a strictly smaller chain or
    # decompose. The bound is min(len(chain), DECLINE_ESCALATION_MIN) — the tier narrowing is not
    # the only bound, the pre-existing #500 ladder still caps the number of no_change outcomes an
    # issue may accumulate, and the TIGHTER of the two is what actually binds. Each dispatch runs
    # on a tier no earlier dispatch used, so no attempt in this walk is ever an identical retry.
    _term_chain = ("opus5", "sol", "luna")
    _term_bound = min(len(_term_chain), DECLINE_ESCALATION_MIN)
    _term_records, _term_dispatches, _term_tiers = [], 0, []
    while True:
        _trip = run_decline_tripwire(list(_term_records), model_chain=_term_chain)
        if _trip["claim_calls"] == 0:
            assert [call[0] for call in _trip["api_calls"]] == ["POST", "GET", "PATCH"], _trip
            break
        _term_dispatches += 1
        assert _term_dispatches <= _term_bound, (_term_dispatches, _term_records)
        _term_tiers.append(_trip["claimed_chains"][0][0])
        _term_records.append(nc_record(_term_tiers[-1], -30 + _term_dispatches))
    assert _term_dispatches == _term_bound, (_term_dispatches, _term_bound)
    assert len(set(_term_tiers)) == len(_term_tiers), _term_tiers
    print(f"  ok   #701 (m): the ladder terminates in decomposition after exactly "
          f"{_term_dispatches} dispatches on {_term_tiers} — no tier is ever asked twice")

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
            "self_attested": False,
            "context": "",
        }, {
            "pr_number": 44,
            "head_sha": "e" * 40,
            "state": "needs-ci-fix",
            "impl_provider": "openai",
            "repo": "example/repo",
            "package": "crate-b",
            "security": False,
            "self_attested": False,
            "context": "docs-quality, opt-in wasm feature-OFF equality",
        }, {
            "pr_number": 46,
            "head_sha": "e" * 40,
            "state": "stranded",
            "impl_provider": "anthropic",
            "repo": "example/repo",
            "package": "crate-a",
            "security": False,
            "self_attested": False,
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
        "partition_starvation": [{
            "repo": "example/repo",
            "deferred": 3,
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

    # ---- issue #560 OWNERSHIP TRANSFER (cross-script, end-to-end, across every CI state) -----
    # The FIX lane spun on unbound legacy verdicts: the fixer refused to stage a verdict that is
    # not bound to the live head, deferred "to a fresh review", and left review:changes on the
    # PR — so THIS enumerator re-admitted it as needs-fix on every ~8min dispatch tick while the
    # review lane (keyed on review:needs) never saw it. Live 2026-07-24: sparq#3523/#3542/#3572/
    # #3573/#3608 burned ~35 fix runs/hour that way until the labels were flipped by hand.
    #
    # ROUND-2 FINDING 1: a LABEL FLIP ALONE ONLY RELOCATES THAT SPIN. The production state is a
    # COMPLETED request-changes review, so the PR body carries `sparq-reviewed-sha == head` (the
    # marker is bound LAST in review-fix.yml's outcome job). A DRAFTED PR whose marker matches the
    # live head is NOT re-emitted as needs-review by the block above; what happens instead depends
    # entirely on CI — green becomes `stranded` (whose review dispatch then exits `already_done`
    # with no work done: the same successful spin one lane over), red becomes needs-ci-fix (the fix
    # lane again), and pending/unknown matches nothing at all, leaving NO lane owning the PR.
    #
    # So assert OWNERSHIP, not a label: drive the REAL post-defer PR state (labels AND reviewed-sha
    # marker) out of worker-pr.py's projections and require, for EVERY CI state, exactly ONE item
    # owned by the REVIEW lane. Every fixture carries the marker. The label-only counterfactual is
    # asserted right below it, so none of this is vacuous: deleting either half of the hand-over —
    # the label transition or the marker retraction — flips these red.
    _worker_pr = _load_module(
        "registry_worker_pr", Path(__file__).resolve().with_name("worker-pr.py"))
    _bound_body = f"desc\n\n<!-- sparq-reviewed-sha:{sha_a} -->\n"

    def _ci_states():
        """The four CI postures the ownership proof must hold over. `None` is the UNKNOWN posture
        (no snapshot at all — a degraded/absent check-run read); a stale head_sha collapses to the
        same thing inside the enumerator."""
        base = {"head_sha": sha_a, "conflicting": False, "armed": False, "failing_legs": []}
        return {
            "green": {41: {**base, "gate": "success"}},
            "red": {41: {**base, "gate": "failure", "failing_legs": ["workspace clippy"]}},
            "pending": {41: {**base, "gate": "pending"}},
            "unknown": None,
        }

    # ---- #584 FOLLOW-UP FINDING 3: the `already_done` predicate is PARSED out of review-fix.yml,
    # not text-sliced. Extract it ONCE (the old code re-sliced the raw file inside the reason loop).
    _ad_src = _review_fix_step_python(
        _RF_ALREADY_DONE_ANCHOR, _RF_ALREADY_DONE_END, "already_done idempotence predicate")
    assert "already_done = False" in _ad_src and "sparq-reviewed-sha" in _ad_src, _ad_src
    _spun = pull(41, "sparq-agent/issue-7-1-1", sha_a,
                 labels=[_worker_pr.FIX_LANE_PR_LABEL], body=_bound_body)
    for _ci, _status in _ci_states().items():
        assert [item["state"] for item in enumerate_review_items(
            repo, [_spun], provenance, [], issue_labels, now, pr_status=_status)] == \
            ["needs-fix"], ("pre-defer lane", _ci)
    for _reason in _worker_pr.FIX_LANE_DEFER_REASONS:
        _action = _worker_pr.fix_lane_defer_action({_worker_pr.FIX_LANE_PR_LABEL})
        _after = sorted(_worker_pr.fix_lane_defer_labels(
            {_worker_pr.FIX_LANE_PR_LABEL}, _action))
        _marker = _worker_pr.fix_lane_defer_marker_action(_action, sha_a, sha_a)
        # The hand-over removed the fix lane's admission label AND retracted the stale marker.
        assert _worker_pr.FIX_LANE_PR_LABEL not in _after, (_reason, _after)
        assert _marker == "invalidate", (_reason, _marker)
        _handed_sha = _worker_pr.UNBOUND_REVIEWED_SHA
        _handed = pull(41, "sparq-agent/issue-7-1-1", sha_a, labels=_after,
                       body=f"desc\n\n<!-- sparq-reviewed-sha:{_handed_sha} -->\n")
        for _ci, _status in _ci_states().items():
            _items = enumerate_review_items(repo, [_handed], provenance, [], issue_labels, now,
                                            pr_status=_status)
            _states = [item["state"] for item in _items]
            # EXACTLY ONE lane owns the PR, and it is the REVIEW lane — the only lane that can
            # mint the head-bound verdict the fixer refuses to run without. No CI state may leave
            # the PR ownerless, and none may hand it back to the fix lane.
            assert _states == ["needs-review"], (_reason, _ci, _after, _states)
            assert _review_item_lane(_states[0]) == "review", (_reason, _ci, _states)
            assert "needs-fix" not in _states, (_reason, _ci, _after, _states)
        # The review lane then provably TAKES ownership at review-fix.yml's own admission
        # boundary: execute the ACTUAL `already_done` predicate embedded in its resolve step
        # against the post-defer body. A retained marker would make it skip without working.
        # (Extracted via the PARSED helper — #584 follow-up finding 3 — so a reflow of that YAML
        # can no longer red this REQUIRED gate with a bare `ValueError: substring not found`.)
        for _body, _want in ((_bound_body, True), (_handed["body"], False)):
            _ns = {"re": re, "mode": "review", "head_sha": sha_a, "pull": {"body": _body}}
            exec(_ad_src, _ns)  # noqa: S102 — repository-owned workflow source
            assert _ns["already_done"] is _want, (_reason, _want, _body)
    # NON-VACUITY / counterfactual: the round-1 fix (flip the label, KEEP the marker) does NOT
    # transfer ownership. It only moves the spin — green strands (whose review dispatch exits
    # already_done), red returns to the fix lane, and pending/unknown owns nothing at all.
    _label_only = pull(41, "sparq-agent/issue-7-1-1", sha_a,
                       labels=[_worker_pr.REVIEW_LANE_PR_LABEL], body=_bound_body)
    _relocated = {_ci: [item["state"] for item in enumerate_review_items(
        repo, [_label_only], provenance, [], issue_labels, now, pr_status=_status)]
        for _ci, _status in _ci_states().items()}
    assert _relocated == {"green": ["stranded"], "red": ["needs-ci-fix"],
                          "pending": [], "unknown": []}, _relocated
    # A hold/park defers WITHOUT a lane change or a marker write (the park itself already excludes
    # the PR from both lanes, so the spin cannot recur): review:parked keeps it out entirely.
    _parked_after = sorted(_worker_pr.fix_lane_defer_labels(
        {_worker_pr.FIX_LANE_PR_LABEL}, "hold"))
    assert _parked_after == [_worker_pr.FIX_LANE_PR_LABEL], _parked_after
    assert _worker_pr.fix_lane_defer_marker_action("hold", sha_a, sha_a) == "keep"
    for _ci, _status in _ci_states().items():
        assert enumerate_review_items(
            repo, [pull(41, "sparq-agent/issue-7-1-1", sha_a, body=_bound_body,
                        labels=_parked_after + [MACHINE_PARK_PR_LABEL])],
            provenance, [], issue_labels, now, pr_status=_status) == [], _ci
    # ...and finding 2's abort leaves the parked PR byte-identical on BOTH axes: the park is never
    # converted into review:needs-user and the marker is never touched.
    _aborted = sorted(_worker_pr.fix_lane_defer_labels(
        {_worker_pr.FIX_LANE_PR_LABEL, MACHINE_PARK_PR_LABEL},
        _worker_pr.FIX_LANE_ABORT_ACTION))
    assert _aborted == [_worker_pr.FIX_LANE_PR_LABEL, MACHINE_PARK_PR_LABEL], _aborted
    assert "review:needs-user" not in _aborted, _aborted
    assert _worker_pr.fix_lane_defer_marker_action(
        _worker_pr.FIX_LANE_ABORT_ACTION, sha_a, sha_a) == "keep"
    print("  ok   #560: the unbound-verdict defer transfers OWNERSHIP to the review lane in every "
          "CI state (label flip + stale reviewed-sha retraction; no needs-fix re-admission, no "
          "already_done skip, no ownerless posture) and a park aborts it untouched")

    # ---- #584 FOLLOW-UP FINDING 1, CROSS-SCRIPT: THE HAND-OVER MUST NOT DISARM A PASSED PR. ------
    # The fix lane does NOT only admit review:changes: GAP-A emits `needs-ci-fix` from a
    # concluded-RED gate on the current head alone, review-state-AGNOSTIC. So a NON-DRAFT,
    # review:pass, ARMED PR with a red gate is routed into the FIX lane, stage-verdict finds no
    # head-bound FIX verdict and defers — and the pre-fix hand-over retracted the reviewed-sha
    # marker on it (action "noop": review:changes was never live). enumerate_disarm_items reads
    # `marker != head` on an ARMED PR as a safety violation, so the very next tick would
    # disable-auto + dequeue + REDRAFT a passed, armed, ready PR. LIVE at the time of this fix:
    # sparq#2521 (review:pass + trust-surface, non-draft, --auto armed, `docs-quality quick-gates`
    # genuinely failing) was the ONLY review:pass PR in the sparq repo and sat on exactly this path.
    # The hand-over's REAL projection over this namespace drives the fixture — nothing here is
    # hard-coded to the fixed behaviour, so a regression in worker-pr.py reaches the consequence
    # assertion below instead of being caught by a restatement of the fix.
    _pass_labels = {_worker_pr.PASS_LANE_PR_LABEL}
    _pass_decided = _worker_pr.fix_lane_defer_action(_pass_labels)
    _pass_after = sorted(_worker_pr.fix_lane_defer_labels(_pass_labels, _pass_decided))
    _pass_marker = _worker_pr.fix_lane_defer_marker_action(_pass_decided, sha_a, sha_a)
    _pass_body_sha = (_worker_pr.UNBOUND_REVIEWED_SHA if _pass_marker == "invalidate" else sha_a)

    def _armed_pass_pull(reviewed, labels=None):
        """The live sparq#2521 posture: non-draft, review:pass, auto-merge armed, marker `reviewed`."""
        return pull(41, "sparq-agent/issue-7-1-1", sha_a, draft=False,
                    labels=_pass_after if labels is None else labels,
                    body=f"desc\n\n<!-- sparq-reviewed-sha:{reviewed} -->\n")

    _armed_status = {41: {"head_sha": sha_a, "conflicting": False, "armed": True,
                          "gate": "failure", "failing_legs": ["docs-quality quick-gates"]}}
    # THE CONSEQUENCE, through the real projection: the post-hand-over PR must NOT be emitted for
    # disarm. If the hand-over retracts this PR's marker, `_pass_body_sha` becomes `none` and the
    # safety net fires — disable-auto + dequeue + REDRAFT on a passed, armed, ready PR.
    _pass_disarm = enumerate_disarm_items(repo, [_armed_pass_pull(_pass_body_sha)], _armed_status,
                                          provenance, bot_login=bot)
    assert _pass_disarm == [], (
        "the fix-lane hand-over's own projection would DISARM + REDRAFT a passed armed PR "
        f"(marker action {_pass_marker!r} -> reviewed_sha {_pass_body_sha!r}): {_pass_disarm}")
    assert _pass_decided == _worker_pr.FIX_LANE_PASS_ACTION, _pass_decided
    assert _pass_after == [_worker_pr.PASS_LANE_PR_LABEL], _pass_after
    assert _pass_marker == "keep", _pass_marker
    # NON-VACUITY: the SAME enumerator DOES emit the PR once the marker is retracted, so the
    # assertion above is a live property of this fixture and not a quiet no-op. This is also the
    # exact pre-fix behaviour — the old projection took `noop` on this namespace and `noop`
    # retracts — so the counterfactual is the history, not a straw man.
    _would_disarm = enumerate_disarm_items(
        repo, [_armed_pass_pull(_worker_pr.UNBOUND_REVIEWED_SHA)], _armed_status, provenance,
        bot_login=bot)
    assert [(item["pr_number"], item["reviewed_sha"]) for item in _would_disarm] == \
        [(41, _worker_pr.UNBOUND_REVIEWED_SHA)], _would_disarm
    assert _worker_pr.fix_lane_defer_marker_action("noop", sha_a, sha_a) == "invalidate"
    # The route in: GAP-A admits this PR to the FIX lane on the red gate ALONE, with no review:changes
    # anywhere — which is why the hand-over ever ran on it. (Asserted so a future enumerator change
    # that stops routing passed PRs into the fix lane makes this whole block visibly moot instead of
    # quietly vacuous.)
    _pass_admission = [item["state"] for item in enumerate_review_items(
        repo, [_armed_pass_pull(sha_a)], provenance, [], issue_labels, now,
        pr_status=_armed_status)]
    assert _pass_admission == ["needs-ci-fix"], _pass_admission
    assert _review_item_lane("needs-ci-fix") == "fix", "needs-ci-fix must be a FIX-lane state"
    # The DISCRIMINATION: the normal review:changes namespace still retracts (asserted above as
    # _marker == "invalidate"), so the guard is scoped to the pass and did not disable the fix.
    assert _worker_pr.fix_lane_defer_marker_action(
        _worker_pr.fix_lane_defer_action({_worker_pr.FIX_LANE_PR_LABEL}), sha_a, sha_a) == \
        "invalidate"
    print("  ok   #584 f1: the lane hand-over stands down on review:pass — the marker survives, so "
          "enumerate_disarm_items does NOT disarm+redraft a passed armed PR (the retracted-marker "
          "counterfactual does), while review:changes still retracts")

    # ---- #584 FOLLOW-UP FINDING 3: A REFLOW OF review-fix.yml MUST NOT RED THIS GATE WITH A BARE
    # `ValueError: substring not found`. The old extraction addressed the block by two exact
    # indentation-bearing literals via str.index(). Round-trip the workflow through the YAML parser
    # to produce a REFLOWED-BUT-EQUIVALENT document (a different serialisation entirely — the old
    # slice literal is gone from the text) and require the SAME block back. ----
    import yaml as _yaml  # already a hard self-test-suite dependency (resolve-conflicts.py)
    _rf_text = (Path(__file__).resolve().parents[1] / ".github" / "workflows"
                / "review-fix.yml").read_text(encoding="utf-8")
    _rf_reflowed = _yaml.safe_dump(_yaml.safe_load(_rf_text), default_flow_style=False, width=4096)
    assert "          already_done = False\n" not in _rf_reflowed, \
        "the reflow fixture is vacuous — the old text-slice literal survived it"
    assert _review_fix_step_python(
        _RF_ALREADY_DONE_ANCHOR, _RF_ALREADY_DONE_END, "already_done idempotence predicate",
        source=_rf_reflowed) == _ad_src, "a reflowed-but-equivalent workflow changed the extraction"
    # ...and when the anchor is GENUINELY gone the failure is an ACTIONABLE AssertionError naming
    # the anchor and the edit — never a bare ValueError, and never a silent skip.
    _rf_broken = _rf_text.replace("already_done = False", "already_done = bool(0)")
    _rf_error = None
    try:
        _review_fix_step_python(_RF_ALREADY_DONE_ANCHOR, _RF_ALREADY_DONE_END,
                                "already_done idempotence predicate", source=_rf_broken)
    except AssertionError as _exc:
        _rf_error = ("actionable", str(_exc))
    except ValueError as _exc:                       # the pre-fix failure mode
        _rf_error = ("bare-valueerror", str(_exc))
    assert _rf_error is not None, "a missing anchor must FAIL, never pass silently"
    assert _rf_error[0] == "actionable", _rf_error
    assert "already_done" in _rf_error[1] and "re-point the anchor" in _rf_error[1] \
        and "review-fix.yml" in _rf_error[1], _rf_error
    # A second matching step (an ambiguous address) is just as loud as none.
    _rf_dupe = _rf_text.replace("          already_done = False\n",
                                "          already_done = False\n          already_done = False\n")
    _rf_dupe_error = None
    try:
        _review_fix_step_python(_RF_ALREADY_DONE_ANCHOR, _RF_ALREADY_DONE_END,
                                "already_done idempotence predicate", source=_rf_dupe)
        _rf_dupe_extract = "extracted"
    except AssertionError as _exc:
        _rf_dupe_error, _rf_dupe_extract = str(_exc), "raised"
    # Two anchors inside ONE step is still one matching step, so extraction succeeds — the
    # ambiguity that must be loud is two matching STEPS.
    assert _rf_dupe_extract == "extracted", _rf_dupe_error
    _rf_two_steps = _yaml.safe_load(_rf_text)
    _rf_two_steps["jobs"]["resolve"]["steps"].append(
        {"name": "a copy of the predicate", "run": _ad_src})
    _rf_two_error = None
    try:
        _review_fix_step_python(_RF_ALREADY_DONE_ANCHOR, _RF_ALREADY_DONE_END,
                                "already_done idempotence predicate",
                                source=_yaml.safe_dump(_rf_two_steps, width=4096))
    except AssertionError as _exc:
        _rf_two_error = str(_exc)
    assert _rf_two_error and "found 2" in _rf_two_error, _rf_two_error
    print("  ok   #584 f3: review-fix.yml's already_done predicate is PARSED (a reflowed-equivalent "
          "workflow yields the identical block) and every missing/ambiguous anchor raises an "
          "actionable AssertionError instead of a bare ValueError")

    # ---- THE 2026-07-26 REVIEW-LANE LOOP: the adopt step rejected its own dispatcher's claim on
    # every tick because review-fix.yml's `resolve` job still carried the pre-#112 alphabetically-
    # first `package` reduction while this module had migrated to multi-area -> __global__.
    # sparq-org/sparq#3528 (source issue #2582: `area:ci` + `area:site`) re-failed on every tick;
    # 53 of that day's 77 review-fix failures were this one rejection, ~20% of the review lane.
    #
    # `package` is not the only value derived twice on these lanes. Each layer below pins ONE
    # mint-vs-adopt derivation by EXECUTING the workflow's own code and requiring it to agree with
    # the canonical definition, and each proves its own non-vacuity by mutating the LIVE tree:
    #   L1  the three Python copies of the reduction agree
    #   L2  review-fix.yml `resolve` derives `package` through the minter's own function
    #   L3  review-fix.yml `policy` routing TABLES agree with REVIEW_CHAIN/FIX_CHAIN/LADDERS
    #   L4  worker.yml self-claim SHELL computes the partition via the canonical CLI
    #   L5  worker.yml adopt validator IMPORTS the canonical reduction
    #   L6  the YAML seam that carries the value into each of those steps, on PARSED nodes
    # ----
    import copy as _copy
    _ls = _load_module("registry_lease_schema", Path(__file__).resolve().with_name(
        "lease_schema.py"))
    _dp = _load_module("registry_dispatch_plan", Path(__file__).resolve().with_name(
        "dispatch-plan.py"))
    _wf_dir = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    _rf_live = (_wf_dir / "review-fix.yml").read_text(encoding="utf-8")
    _wk_live = (_wf_dir / "worker.yml").read_text(encoding="utf-8")
    assert GLOBAL_PACKAGE == _ls.GLOBAL_PACKAGE == _dp.GLOBAL, (
        GLOBAL_PACKAGE, _ls.GLOBAL_PACKAGE, _dp.GLOBAL)
    # L1. dispatch-plan.py ships INSIDE the target repos, which have no lease_schema.py, so it is
    # the one copy that cannot import the canonical function. Pin it by AGREEMENT instead —
    # including the live incident's two-area row, the case the pre-#112 reduction got wrong.
    _area_matrix = ([], ["ci"], ["site"], ["ci", "site"], ["site", "ci"], ["ci", "ci"],
                    ["a", "b", "c"])
    for _areas in _area_matrix:
        _canonical = _ls.plan_package(_areas)
        assert plan_package(_areas) == _canonical, (_areas, plan_package(_areas), _canonical)
        assert _dp._plan_package([f"area:{a}" for a in _areas]) == _canonical, (
            "dispatch-plan.py's target-shipped copy drifted from the canonical reduction", _areas)
    assert _ls.plan_package(["ci", "site"]) == GLOBAL_PACKAGE, "the incident row must serialize"
    print("  ok   adopt-loop L1: all THREE python derivations of the area->package partition agree, "
          "the live two-area incident row (area:ci + area:site) included")

    # L1b. AGREEMENT IS NOT DELEGATION. Every assertion above is satisfied by a private copy that
    # happens to agree today — the exact prose-promise mechanism this incident came from — so the
    # MINTER, the one caller whose delegation is not carried by an executed workflow anchor
    # (L2/L4/L5 carry the other three), gets a shared-CODE leg: swap the canonical function object
    # out from under it and the minter's result MUST follow. A re-inlined copy cannot observe the
    # swap. This is the pin the README's "even one that agrees today" sentence promises.
    _pp_sentinel = "__delegation-probe__"
    _pp_real = _lease_schema.plan_package
    try:
        _lease_schema.plan_package = lambda areas: _pp_sentinel
        _pp_observed = plan_package(["ci"])
    finally:
        _lease_schema.plan_package = _pp_real
    assert _pp_observed == _pp_sentinel, (
        "dispatch-claim.plan_package must DELEGATE to lease_schema.plan_package, not re-implement "
        "it: replacing the canonical function object did not change the minter's result "
        f"(got {_pp_observed!r}), so this is a private copy that merely AGREES today — the drift "
        "axis that produced the 2026-07-26 adopt loop")
    assert plan_package(["ci"]) == "ci" and plan_package(["ci", "site"]) == GLOBAL_PACKAGE, \
        "the canonical lease_schema.plan_package must be restored after the delegation probe"
    print("  ok   adopt-loop L1b: dispatch-claim.plan_package (the MINTER) reaches the canonical "
          "reduction by SHARED CODE — a private-but-agreeing copy is caught, not just a drifted one")

    # L2. review-fix.yml's resolve job derives `package` by CALLING this module's plan_package —
    # EXECUTED, not grepped. The extracted slice is the workflow's real line.
    def _resolve_package(areas, source=None):
        """Run review-fix.yml's OWN `package` derivation over `areas`."""
        src = _review_fix_step_python(
            _RF_PACKAGE_ANCHOR, _RF_PACKAGE_END, "resolve-job package partition derivation",
            source=source)
        ns = {"dispatch_claim": types.SimpleNamespace(plan_package=plan_package),
              "packages": sorted(areas)}
        exec(src, ns)  # noqa: S102 — repository-owned workflow source
        return ns["package"]

    for _areas in _area_matrix:
        assert _resolve_package(_areas) == _ls.plan_package(_areas), (
            "review-fix.yml's resolve job derives a package the dispatcher would not have minted",
            _areas, _resolve_package(_areas), _ls.plan_package(_areas))
    assert _resolve_package(["ci", "site"]) == GLOBAL_PACKAGE
    # NON-VACUITY: reinstate the exact pre-#112 reduction in the workflow text and require the
    # comparison above to go red. This is the mutant that ran in production for a day.
    _rf_prefix_bug = _rf_live.replace(
        "package = dispatch_claim.plan_package(packages)",
        'package = packages[0] if packages else "__global__"')
    assert _rf_prefix_bug != _rf_live, "the pre-#112-reduction mutant fixture is vacuous"
    _bug_caught = None
    try:
        _bug_caught = ("derived", _resolve_package(["ci", "site"], source=_rf_prefix_bug))
    except AssertionError as _exc:                 # the anchor is gone -> also a caught mutant
        _bug_caught = ("anchor-gone", str(_exc))
    assert _bug_caught[0] == "anchor-gone" or _bug_caught[1] != _ls.plan_package(["ci", "site"]), \
        "the pre-#112 reduction mutant was NOT caught — this check is vacuous"
    print("  ok   adopt-loop L2: review-fix.yml's resolve job derivation is EXECUTED and agrees "
          "with the minter on every row; restoring the pre-#112 `packages[0]` reduction is caught")

    # L3. The OTHER unpinned mint-vs-adopt derivation on the review lane: review-fix.yml's `policy`
    # job re-derives review_chain / fix_chain / ladders inline, held to this module's REVIEW_CHAIN /
    # FIX_CHAIN and worker-pr.ESCALATION_LADDERS by a COMMENT ("Mirrors dispatch-claim.py
    # REVIEW_CHAIN/FIX_CHAIN") and nothing else. A drift makes the adopt step's `model not in
    # models` guard fire on every affected PR — the identical forever-loop shape as the package
    # drift, on a value nothing was checking. EXECUTE the workflow's tables and require agreement.
    _wpr_chains = _load_module("registry_worker_pr_chains",
                              Path(__file__).resolve().with_name("worker-pr.py"))

    def _workflow_chains(source=None):
        src = _review_fix_step_python(
            _RF_CHAINS_ANCHOR, _RF_CHAINS_END, "policy-job routing tables", job="resolve",
            source=source)
        ns = {}
        exec(src, ns)  # noqa: S102 — repository-owned workflow source
        return {name: ns[name] for name in ("review_chain", "fix_chain", "ladders")}

    _chains = _workflow_chains()
    assert _chains["review_chain"] == REVIEW_CHAIN, (
        "review-fix.yml's review_chain drifted from dispatch-claim.REVIEW_CHAIN; the dispatcher "
        "mints a claim on a model the run then rejects", _chains["review_chain"], REVIEW_CHAIN)
    assert _chains["fix_chain"] == FIX_CHAIN, (
        "review-fix.yml's fix_chain drifted from dispatch-claim.FIX_CHAIN", _chains["fix_chain"],
        FIX_CHAIN)
    assert _chains["ladders"] == _wpr_chains.ESCALATION_LADDERS, (
        "review-fix.yml's ladders drifted from worker-pr.ESCALATION_LADDERS; a pinned fix floor "
        "then resolves to a chain the dispatcher never claimed against",
        _chains["ladders"], _wpr_chains.ESCALATION_LADDERS)
    # NON-VACUITY: drift each table in the LIVE workflow text and require the matching assertion to
    # go red. (The review of #702 measured that drifting `review_chain` left the whole enrolled
    # suite green.) Each mutant keeps the table SHAPE, so only an equality pin can see it.
    for _table, _from, _to in (
            ("review_chain", '"anthropic": ["sol", "luna"], "openai": ["opus5"]',
             '"anthropic": ["luna"], "openai": ["opus5"]'),
            ("fix_chain", '"anthropic": ["opus5"], "openai": ["sol", "luna"]',
             '"anthropic": ["opus5"], "openai": ["luna", "sol"]'),
            ("ladders", '"anthropic": ["opus5"], "openai": ["luna", "sol"]',
             '"anthropic": ["opus5"], "openai": ["sol", "luna"]')):
        _line = f"{_table} = {{{_from}}}"
        assert _line in _rf_live, f"the {_table} drift fixture is stale: {_line}"
        _drifted = _workflow_chains(source=_rf_live.replace(_line, f"{_table} = {{{_to}}}"))
        _live_table = {"review_chain": REVIEW_CHAIN, "fix_chain": FIX_CHAIN,
                       "ladders": _wpr_chains.ESCALATION_LADDERS}[_table]
        assert _drifted[_table] != _live_table, (
            f"drifting {_table} in review-fix.yml did NOT change the executed table — this "
            f"agreement pin is vacuous", _table)
    print("  ok   adopt-loop L3: review-fix.yml's review_chain/fix_chain/ladders are EXECUTED out "
          "of the workflow and pinned to REVIEW_CHAIN/FIX_CHAIN/ESCALATION_LADDERS; drifting any "
          "one of the three is caught")

    # L3b. [OPUS-5] THE SIXTH SITE. The input-validation model_pin ALLOWLIST is a sixth place that
    # names the model aliases, and PR #707's L3 pin does not reach it (it slices only the resolve
    # job's review_chain..ladders block). It was covered by NOTHING. That matters now: it is the
    # first thing an in-flight PR's pin meets, so a bare deletion of fable/opus there would
    # SystemExit on every tick forever for every PR that had already escalated. EXECUTE the real
    # workflow allowlist and pin BOTH halves of its contract — legacy pins migrate, unknown pins
    # are still rejected.
    _PIN_ANCHOR = r"(?m)^[ \t]*legacy_pins = \{"
    _PIN_END = r"(?m)^[ \t]*if mode == \"review\" and model_pin:"

    def _workflow_pin(pin, source=None):
        src = _review_fix_step_python(_PIN_ANCHOR, _PIN_END, "model_pin allowlist",
                                      job="resolve", source=source)
        ns = {"model_pin": pin, "SystemExit": SystemExit}
        try:
            exec(src, ns)  # noqa: S102 — repository-owned workflow source
        except SystemExit as exc:
            return ("rejected", str(exc))
        return ("accepted", ns["model_pin"])

    for _legacy in ("fable", "opus"):
        assert _workflow_pin(_legacy) == ("accepted", "opus5"), (
            "review-fix.yml's guard must MIGRATE a pre-deprecation model_pin up to opus5, not "
            "reject it — rejecting permanently stalls every PR that escalated before "
            "2026-07-26", _legacy, _workflow_pin(_legacy))
    for _current in ("opus5", "sol", "luna"):
        assert _workflow_pin(_current) == ("accepted", _current), (_current,
                                                                   _workflow_pin(_current))
    assert _workflow_pin("")[0] == "accepted", "an empty pin must stay legal"
    for _bad in ("sonnet", "terra", "gpt-omega"):
        assert _workflow_pin(_bad)[0] == "rejected", (
            "the allowlist must still reject a non-ladder pin — the migration must not become a "
            "hole that launders any alias into opus5", _bad)
    # NON-VACUITY: drift the migration map in the LIVE workflow text and require the pin to see
    # it. Without this the assertions above could pass against a stale extraction.
    _pin_line = 'legacy_pins = {"fable": "opus5", "opus": "opus5"}'
    assert _pin_line in _rf_live, f"the legacy-pin fixture is stale: {_pin_line}"
    _drifted_pin = _workflow_pin("fable", source=_rf_live.replace(_pin_line, "legacy_pins = {}"))
    assert _drifted_pin[0] == "rejected", (
        "deleting the legacy-pin migration from review-fix.yml did NOT change the executed "
        "allowlist — this pin is vacuous", _drifted_pin)
    print("  ok   adopt-loop L3b: review-fix.yml's model_pin allowlist is EXECUTED out "
          "of the workflow — legacy fable/opus pins MIGRATE to opus5 (no forever-stall on "
          "in-flight PRs) while non-ladder pins are still rejected; deleting the migration is "
          "caught")

    # L3c. [OPUS-5] THE SEVENTH SITE, and the one that is not in this repository at all: the
    # TARGET-side PLAN resolver. Every layer above pins two derivations that live in the registry.
    # This one pins the derivation that crosses the repository boundary — `dispatch-plan` running
    # the TARGET's `route-resolve.py` versus `_route_matches` re-deriving the same route through
    # registry-owned `policy-resolve.py`. NOTHING in either repository asserted their agreement,
    # which is how sparq PR #4211 shipped two review rounds of a chain-order carve-out that PLAN
    # implemented and CLAIM did not: 34 of 35 `area:gui` issues would have deferred
    # `route-policy-failed` on every tick, permanently, behind a generic counter.
    _agree = _load_module("registry_cross_resolver_agreement",
                          Path(__file__).resolve().with_name("cross-resolver-agreement.py"))
    _sparq_shaped = tomllib.loads(_agree.SPARQ_SHAPED)
    _sparq_declared = tomllib.loads(_agree.SPARQ_SHAPED + _agree.GUI_DECLARATION)
    for _label, _doc in (("the registry's own live routing table",
                          tomllib.loads((Path(__file__).resolve().parents[1] / "orchestration"
                                         / "routing.toml").read_text(encoding="utf-8"))),
                         ("a target table with NO chain_preference", _sparq_shaped),
                         ("a target table DECLARING the area:gui carve-out", _sparq_declared)):
        _matrix = tuple((n, lb) for n, lb in _agree.AGREEMENT_MATRIX
                        if all(x[5:] in {r.get("role") for r in _doc.get("route", [])}
                               for x in lb if x.startswith("role:")))
        _bad = _agree.compare(_doc, matrix=_matrix)
        assert not _bad, (f"PLAN and CLAIM disagree on {_label}", _bad)
        assert len(_matrix) >= 10, ("the agreement matrix collapsed to almost nothing, which "
                                    "would make the assertion above pass vacuously", _label,
                                    len(_matrix))
    # NON-VACUITY: reproduce the #4211 defect exactly — a carve-out the PLAN resolver knows and the
    # CLAIM resolver does not — and require the comparison to report the affected rows.
    def _plan_only(labels, doc):
        _chain, _agent, _esc = _agree._ROUTE.resolve(labels, doc)
        if "area:gui" in set(labels) and {"sol", "opus5"} <= set(_chain):
            _chain = ["sol"] + [m for m in _chain if m != "sol"]
        return _chain, _agent, _esc

    _reported = _agree.compare(_sparq_shaped, plan_resolver=_plan_only)
    assert ("area:gui", "role:impl") in {lb for _n, lb, _p, _c in _reported}, (
        "a PLAN-only chain-order rule was NOT reported — this agreement pin is vacuous")
    assert not _agree.compare(_sparq_declared), (
        "declaring the rule in the routing table must make the two resolvers agree again")

    # ...and the CLAIM-side diagnostic the review asked for: a divergence must raise its OWN error
    # class (so the tick counts it apart from situational per-item failures) and must NAME both
    # chains, rather than surfacing as an unattributable defer counter.
    _div_item = {"number": 3367, "labels": ["area:gui", "role:impl", "priority:P2"],
                 "model_chain": ["sol", "opus5"], "agent": "sparq-rust-impl", "escalate": False,
                 "role": "impl", "priority": 2, "package": "gui"}
    _div_policy = {"repos": {"probe/target": dict(_agree.PROBE_POLICY["repos"]["probe/target"])}}
    try:
        _route_matches("probe/target", _div_item, _div_policy, _sparq_shaped, _agree._POLICY)
    except RouteDivergenceError as _exc:
        _div_msg = str(_exc)
    else:                                                   # pragma: no cover — a caught mutant
        _div_msg = None
    assert _div_msg is not None, (
        "_route_matches accepted a plan chain the protected routing does not derive")
    assert "model_chain" in _div_msg and "['sol', 'opus5']" in _div_msg \
        and "['opus5', 'sol']" in _div_msg and "area:gui" in _div_msg, (
        "the divergence diagnostic must name the field, BOTH chains and the labels — without them "
        "the operator sees only that 'the route no longer matches'", _div_msg)
    assert isinstance(RouteDivergenceError("x"), DispatchError), (
        "RouteDivergenceError must remain a DispatchError so the existing per-item resilience "
        "still contains it")
    # The SAME item against the table that DECLARES the rule resolves cleanly — so the assertion
    # above is detecting a real divergence, not rejecting every item.
    assert _route_matches("probe/target", _div_item, _div_policy, _sparq_declared,
                          _agree._POLICY)["model_chain"] == ["sol", "opus5"]
    print("  ok   adopt-loop L3c: the PLAN resolver and the CLAIM resolver derive IDENTICAL routes "
          "over a 22-row label matrix on the live registry table and on a target table with and "
          "without a chain_preference declaration; a PLAN-only carve-out (the sparq #4211 defect) "
          "is reported, and a live divergence raises RouteDivergenceError naming both chains")

    # ---- THE IMPL LANE. worker.yml runs the SAME mint-vs-adopt equality with its OWN two copies of
    # the reduction, and the review of #702 MEASURED that both could be reverted to the pre-#112
    # rule with the entire 34-script enrolled suite staying green. Both now go through the canonical
    # function, and both are pinned by EXECUTION. ----
    @contextlib.contextmanager
    def _registry_cwd():
        """A cwd whose `registry/` is this checkout, i.e. the layout worker.yml's steps run in
        (actions/checkout with `path: registry`). Makes the workflow's own relative
        `registry/scripts/lease_schema.py` reference LOAD-BEARING in the test."""
        with tempfile.TemporaryDirectory() as tmp:
            os.symlink(Path(__file__).resolve().parents[1], os.path.join(tmp, "registry"))
            saved = os.getcwd()
            try:
                os.chdir(tmp)
                yield tmp
            finally:
                os.chdir(saved)

    # L4. worker.yml's self-claim SHELL step. The bash `if [[ "$PACKAGES" != *,* ]]` reduction is
    # replaced by a call to the canonical CLI, and this runs that shell with `bash` over the matrix.
    def _worker_self_package(areas, source=None):
        src = _workflow_step_python(
            "worker.yml", "claim", _WK_SELF_PACKAGE_ANCHOR, _WK_SELF_PACKAGE_END,
            "self-claim lease partition reduction", source=source)
        assert _WK_SELF_PACKAGE_CALL in src, (
            "worker.yml's self-claim step no longer COMPUTES the lease partition with the canonical "
            "reduction (lease_schema.py --plan-package) — a re-implementation that agrees today is "
            "exactly the drift axis the 2026-07-26 review-lane loop rode", src)
        with _registry_cwd():
            done = subprocess.run(
                ["bash", "-c", f'set -euo pipefail\n{src}\nprintf "%s" "$lease_package"'],
                capture_output=True, text=True,
                env={**os.environ, "PACKAGES": ",".join(sorted(areas))})
        assert done.returncode == 0, (done.returncode, done.stdout, done.stderr)
        return done.stdout

    for _areas in _area_matrix:
        assert _worker_self_package(_areas) == _ls.plan_package(_areas), (
            "worker.yml's self-claim step leases a partition the dispatcher would not have minted",
            _areas, _worker_self_package(_areas), _ls.plan_package(_areas))
    # NON-VACUITY, both legs of the pin:
    #  (a) restore the EXACT pre-#112 open-coded bash reduction -> caught by the shared-code leg
    #      (agreeing today is not the property being pinned; the defect class is "another copy");
    #  (b) keep the canonical call but OVERRIDE its result -> caught by the executed VALUE leg, so
    #      the agreement assertion is not carried by the substring check alone.
    _wk_self_call_line = ('          lease_package="$(python3 registry/scripts/lease_schema.py'
                          ' --plan-package "$PACKAGES")"\n')
    assert _wk_self_call_line in _wk_live, "the worker.yml self-claim call fixture is stale"
    _wk_pre112 = _wk_live.replace(
        _wk_self_call_line,
        '          if [[ -n "$PACKAGES" ]]; then\n'
        '            lease_package="${PACKAGES%%,*}"\n'
        "          else\n"
        "            lease_package=__global__\n"
        "          fi\n")
    _pre112_caught = None
    try:
        _pre112_caught = ("value", _worker_self_package(["ci", "site"], source=_wk_pre112))
    except AssertionError as _exc:
        _pre112_caught = ("assertion", str(_exc))
    assert _pre112_caught[0] == "assertion" and "canonical reduction" in _pre112_caught[1], (
        "reverting worker.yml's self-claim reduction to the pre-#112 open-coded bash rule was NOT "
        "caught", _pre112_caught)
    _wk_override = _wk_live.replace(
        _wk_self_call_line, _wk_self_call_line + '          lease_package="${PACKAGES%%,*}"\n')
    assert _wk_override != _wk_live, "the worker.yml self-claim override fixture is stale"
    assert _worker_self_package(["ci", "site"], source=_wk_override) != GLOBAL_PACKAGE, (
        "overriding the canonical reduction's result in worker.yml's self-claim step was NOT "
        "caught — the executed value agreement is vacuous")
    print("  ok   adopt-loop L4: worker.yml's self-claim shell step computes the lease partition "
          "through the canonical reduction (run under bash over every row); restoring the pre-#112 "
          "open-coded bash rule and overriding the canonical result are both caught")

    # L5. worker.yml's adopt validator. The `expected_package` re-derivation is executed WITH its
    # own importlib load, out of the workflow, in the checkout layout the step really runs in — so
    # deleting the import is a NameError here, not a runtime surprise on the impl lane.
    def _worker_adopt_package(areas, source=None):
        src = _workflow_step_python(
            "worker.yml", "claim", _WK_ADOPT_PACKAGE_ANCHOR, _WK_ADOPT_PACKAGE_END,
            "adopt-validator expected-partition derivation", source=source)
        assert _WK_ADOPT_PACKAGE_CALL in src, (
            "worker.yml's adopt validator no longer derives the expected partition with the "
            "canonical lease_schema.plan_package — the impl lane's mint-vs-adopt equality is back "
            "on two independent copies of one reduction", src)
        ns = {"os": os}
        saved = os.environ.get("PACKAGES")
        with _registry_cwd():
            try:
                os.environ["PACKAGES"] = ",".join(sorted(areas))
                exec(src, ns)  # noqa: S102 — repository-owned workflow source
            finally:
                if saved is None:
                    os.environ.pop("PACKAGES", None)
                else:
                    os.environ["PACKAGES"] = saved
        return ns["expected_package"]

    for _areas in _area_matrix:
        assert _worker_adopt_package(_areas) == _ls.plan_package(_areas), (
            "worker.yml's adopt validator expects a partition the dispatcher would not have minted",
            _areas, _worker_adopt_package(_areas), _ls.plan_package(_areas))
    # NON-VACUITY, three mutants: the pre-#112 rule (the shared-code leg), a derivation that keeps
    # the canonical call but overrides it on the incident row (the executed VALUE leg), and deleting
    # the import (what makes the derivation SHARED rather than merely equal today).
    _wk_adopt_pre112 = _wk_live.replace(
        "expected_package = lease_schema.plan_package(areas)",
        'expected_package = areas[0] if areas else "__global__"')
    assert _wk_adopt_pre112 != _wk_live, "the worker.yml adopt pre-#112 mutant fixture is stale"
    _adopt_caught = None
    try:
        _adopt_caught = ("value", _worker_adopt_package(["ci", "site"], source=_wk_adopt_pre112))
    except AssertionError as _exc:
        _adopt_caught = ("assertion", str(_exc))
    assert _adopt_caught[0] == "assertion" and "canonical lease_schema" in _adopt_caught[1], (
        "reverting worker.yml's adopt reduction to the pre-#112 rule was NOT caught", _adopt_caught)
    _wk_adopt_override = _wk_live.replace(
        "expected_package = lease_schema.plan_package(areas)",
        "expected_package = lease_schema.plan_package(areas) if len(areas) != 2 else areas[0]")
    assert _wk_adopt_override != _wk_live, "the worker.yml adopt override fixture is stale"
    assert _worker_adopt_package(["ci", "site"], source=_wk_adopt_override) != GLOBAL_PACKAGE, (
        "overriding the canonical reduction on the two-area row in worker.yml's adopt validator was "
        "NOT caught — the executed value agreement is vacuous")
    _wk_no_import = _wk_live.replace("          import importlib.util as _ilu\n", "")
    assert _wk_no_import != _wk_live, "the worker.yml adopt import-deletion fixture is stale"
    _no_import_caught = None
    try:
        _worker_adopt_package(["ci"], source=_wk_no_import)
    except (AssertionError, NameError) as _exc:
        _no_import_caught = f"{type(_exc).__name__}: {_exc}"
    assert _no_import_caught, (
        "deleting the canonical-reduction import from worker.yml's adopt validator was NOT caught")
    print("  ok   adopt-loop L5: worker.yml's adopt validator IMPORTS the canonical reduction and "
          "is executed in the real checkout layout; the pre-#112 rule and a deleted import are "
          "both caught")

    # L6. THE YAML SEAM, on PARSED nodes. A substring or `count(...) == N` assertion over the
    # workflow text cannot distinguish a live step from one carrying `if: false`, cannot see a
    # deleted step, and cannot see an `env:` input re-pointed at the neighbouring output. Every
    # mutant below is built by editing ONE parsed node and must come back as a named violation.
    _rf_doc = _yaml.safe_load(_rf_live)
    _wk_doc = _yaml.safe_load(_wk_live)
    for _wf, _doc in (("review-fix.yml", _rf_doc), ("worker.yml", _wk_doc)):
        assert _partition_seam_violations(_wf, _doc) == [], (
            _wf, _partition_seam_violations(_wf, _doc))

    def _mutate(document, edit):
        clone = _copy.deepcopy(document)
        edit(clone)
        return clone

    def _step(document, step_id):
        return next(s for s in document["jobs"]["claim"]["steps"] if s.get("id") == step_id)

    def _drop_step(document, step_id):
        document["jobs"]["claim"]["steps"] = [
            s for s in document["jobs"]["claim"]["steps"] if s.get("id") != step_id]

    _seam_mutants = (
        ("review-fix.yml", _rf_doc, "adopt step if: false",
         lambda d: _step(d, "adopt").__setitem__("if", "${{ false }}"), "`if:`"),
        ("review-fix.yml", _rf_doc, "self-claim step if: false",
         lambda d: _step(d, "claim").__setitem__("if", "${{ false }}"), "`if:`"),
        ("review-fix.yml", _rf_doc, "adopt env.PACKAGE re-pointed at the packages CSV",
         lambda d: _step(d, "adopt")["env"].__setitem__(
             "PACKAGE", "${{ needs.resolve.outputs.packages }}"), "env.PACKAGE"),
        ("review-fix.yml", _rf_doc, "self-claim env.PACKAGE deleted",
         lambda d: _step(d, "claim")["env"].pop("PACKAGE"), "env.PACKAGE"),
        ("review-fix.yml", _rf_doc, "resolve outputs.package re-pointed at packages",
         lambda d: d["jobs"]["resolve"]["outputs"].__setitem__(
             "package", "${{ steps.pr.outputs.packages }}"), "outputs.package"),
        ("review-fix.yml", _rf_doc, "resolve outputs.package deleted",
         lambda d: d["jobs"]["resolve"]["outputs"].pop("package"), "outputs.package"),
        ("review-fix.yml", _rf_doc, "the adopt step deleted",
         lambda d: _drop_step(d, "adopt"), "missing the `adopt` step"),
        ("worker.yml", _wk_doc, "adopt step if: false",
         lambda d: _step(d, "adopt").__setitem__("if", "${{ false }}"), "`if:`"),
        ("worker.yml", _wk_doc, "self-claim step if: false",
         lambda d: _step(d, "claim").__setitem__("if", "${{ false }}"), "`if:`"),
        ("worker.yml", _wk_doc, "adopt env.PACKAGES re-pointed at the single package",
         lambda d: _step(d, "adopt")["env"].__setitem__(
             "PACKAGES", "${{ needs.resolve.outputs.package }}"), "env.PACKAGES"),
        ("worker.yml", _wk_doc, "self-claim env.PACKAGES deleted",
         lambda d: _step(d, "claim")["env"].pop("PACKAGES"), "env.PACKAGES"),
        ("worker.yml", _wk_doc, "resolve outputs.packages deleted",
         lambda d: d["jobs"]["resolve"]["outputs"].pop("packages"), "outputs.packages"),
        ("worker.yml", _wk_doc, "the self-claim step deleted",
         lambda d: _drop_step(d, "claim"), "missing the `claim` step"),
        ("worker.yml", _wk_doc, "the whole claim job's steps list replaced by a scalar",
         lambda d: d["jobs"]["claim"].__setitem__("steps", "gutted"), "steps is not a list"),
    )
    for _wf, _doc, _label, _edit, _needle in _seam_mutants:
        _violations = _partition_seam_violations(_wf, _mutate(_doc, _edit))
        assert _violations, f"YAML-seam mutant NOT caught ({_wf}: {_label})"
        assert any(_needle in v for v in _violations), (_wf, _label, _needle, _violations)
    print(f"  ok   adopt-loop L6: the partition YAML seam is checked on PARSED nodes across "
          f"review-fix.yml + worker.yml, and all {len(_seam_mutants)} seam mutants "
          "(`if: false`, deleted step, deleted/re-pointed env input, deleted job output) are caught")

    # ---- [registry #701] THE EVIDENCE-PATH YAML SEAM. The routing decision above is only as real
    # as the wire that carries a no_change exit into the ledger. Cutting that wire fails SILENTLY:
    # no job goes red, the dispatcher simply never sees any no_change evidence and goes straight
    # back to retrying the same tier. Same parsed-node discipline as L6, same mutation proof. ----
    assert _no_change_seam_violations(_wk_doc) == [], _no_change_seam_violations(_wk_doc)

    def _wstep(document, job, step_id):
        return next(s for s in document["jobs"][job]["steps"] if s.get("id") == step_id)

    def _named_step(document, job, name):
        return next(s for s in document["jobs"][job]["steps"] if s.get("name") == name)

    _health_step_name = _NO_CHANGE_SEAM["health_step_name"]
    _nc_seam_mutants = (
        ("the exit-class step carries if: false",
         lambda d: _wstep(d, "worker", "exit-class").__setitem__("if", "${{ false }}"), "`if:`"),
        ("the exit-class step is gated on success only (the failures stop recording)",
         lambda d: _wstep(d, "worker", "exit-class").__setitem__(
             "if", "${{ steps.model.outcome == 'success' }}"), "`if:`"),
        ("the exit-class step is deleted",
         lambda d: d["jobs"]["worker"].__setitem__(
             "steps", [s for s in d["jobs"]["worker"]["steps"] if s.get("id") != "exit-class"]),
         "missing the `exit-class` step"),
        ("jobs.worker.outputs.reset_hint deleted (the why_no_diff envelope's only path out)",
         lambda d: d["jobs"]["worker"]["outputs"].pop("reset_hint"), "outputs.reset_hint"),
        ("jobs.worker.outputs.exit_class re-pointed at the neighbouring reset hint",
         lambda d: d["jobs"]["worker"]["outputs"].__setitem__(
             "exit_class", "${{ steps.exit-class.outputs.reset_hint }}"), "outputs.exit_class"),
        ("the model_health job carries if: false",
         lambda d: d["jobs"]["model_health"].__setitem__("if", "${{ false }}"),
         "model_health `if:`"),
        ("the model_health gate is flipped to success-only",
         lambda d: d["jobs"]["model_health"].__setitem__(
             "if", "${{ always() && needs.worker.outputs.exit_class == 'success' }}"),
         "model_health `if:`"),
        ("the model_health job loses its needs edge on worker",
         lambda d: d["jobs"]["model_health"].__setitem__("needs", ["resolve", "claim"]),
         "must `needs:` the worker job"),
        ("the whole model_health job is deleted",
         lambda d: d["jobs"].pop("model_health"), "missing the `model_health` job"),
        ("the record step is deleted",
         lambda d: d["jobs"]["model_health"].__setitem__(
             "steps", [s for s in d["jobs"]["model_health"]["steps"]
                       if s.get("name") != _health_step_name]),
         "missing the model_health record step"),
        ("record step env.RESET_HINT deleted (why_no_diff silently stops being stored)",
         lambda d: _named_step(d, "model_health", _health_step_name)["env"].pop("RESET_HINT"),
         "env.RESET_HINT"),
        ("record step env.EXIT_CLASS re-pointed at the attempt output",
         lambda d: _named_step(d, "model_health", _health_step_name)["env"].__setitem__(
             "EXIT_CLASS", "${{ needs.worker.outputs.outcome_attempt }}"), "env.EXIT_CLASS"),
        ("the record step stops passing --reset-hint",
         lambda d: _named_step(d, "model_health", _health_step_name).__setitem__(
             "run", _named_step(d, "model_health", _health_step_name)["run"].replace(
                 '--reset-hint "$RESET_HINT"', "")), "--reset-hint"),
        ("the record step's run: script is gutted",
         lambda d: _named_step(d, "model_health", _health_step_name).__setitem__("run", None),
         "no `run:` script"),
    )
    for _label, _edit, _needle in _nc_seam_mutants:
        _violations = _no_change_seam_violations(_mutate(_wk_doc, _edit))
        assert _violations, f"#701 evidence-seam mutant NOT caught ({_label})"
        assert any(_needle in v for v in _violations), (_label, _needle, _violations)
    print(f"  ok   #701 (n): the no_change EVIDENCE-PATH yaml seam is checked on PARSED nodes, and "
          f"all {len(_nc_seam_mutants)} mutants (`if: false`, success-only gate, deleted step/job/"
          "output/needs-edge, re-pointed env input, dropped --reset-hint) are caught")

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

    # ---- provenance ATTESTATION CLASS: the trust BASIS a record rests on (issue #657) ----------
    # Before this, `recorded_at_run` was the ONE provenance field admission never inspected. A
    # record with no stamp at all, or a hand-written one, was admitted at FULL worker-run trust —
    # and the review lane resolves the REVIEWER by inverting that record's `impl_provider`, so a
    # self-attested record could choose its own reviewer's provider and yield a same-provider
    # review that still looks cross-provider.
    assert provenance_attestation_class(provenance[41]) == "worker-run", \
        "a bare '<run>.<attempt>' stamp is worker.yml's host-side provenance job"
    assert provenance_attestation_class(
        {**provenance[41], "recorded_at_run": "backfill:29572728300.1"}) == "backfill", \
        "backfill-provenance.py's host-side stamp is machine-attested too"
    assert provenance_attestation_class(
        {**provenance[41], "recorded_at_run": "orchestrator:30209757201.1"}) == "orchestrator", \
        "the self-attested class is RECOGNISED (so an audit can name it), not merely malformed"
    # Fail closed on every non-shape. `human:30209757201.1` is the REAL live stamp of the one
    # hand-written record on the ledger branch (sparq#4185, already merged): an ad-hoc stamp is
    # NOT silently promoted to a class.
    for _bad_stamp in ("human:30209757201.1", "30209757201", "30209757201.", ".1",
                       "backfill:abc.1", "backfill:1.1.1", "orchestrator:", "orchestrator:1",
                       "1.1 ", " 1.1", "worker-run", "", "x1.1", "1.1x", None, 1.1, 11, True,
                       [], {}, ["1.1"]):
        assert provenance_attestation_class(
            {**provenance[41], "recorded_at_run": _bad_stamp}) is None, repr(_bad_stamp)
    assert provenance_attestation_class(
        {key: value for key, value in provenance[41].items()
         if key != "recorded_at_run"}) is None, "an ABSENT stamp is no trust basis at all"
    # Never raises on a malformed record: this runs inside the PLAN/groom walk, where an
    # exception aborts the whole run instead of parking the one orphan.
    for _junk in ("not-a-dict", None, [], 7):
        assert provenance_attestation_class(_junk) is None, repr(_junk)
    # ADMISSION, through the SAME parity battery every other field check uses — the predicate
    # refuses AND the enumerator refuses to emit the PR. Deleting either attestation check in
    # provenance_admission_error reds these.
    assert _rejected_everywhere(
        {key: value for key, value in provenance[41].items() if key != "recorded_at_run"})
    assert _rejected_everywhere({**provenance[41], "recorded_at_run": "human:30209757201.1"})
    assert _rejected_everywhere({**provenance[41], "recorded_at_run": ""})
    assert _rejected_everywhere({**provenance[41], "recorded_at_run": 11})
    # A SELF-DECLARED record cannot buy admission by naming its own trust class — the
    # orchestrator class is recognised precisely so it can be REFUSED by name (issue #657's
    # fail-closed requirement; registry #681 was rejected for resting on forgeable evidence).
    assert _rejected_everywhere(
        {**provenance[41], "recorded_at_run": "orchestrator:30209757201.1"})
    # ...and the two refusals stay DISTINCT. Collapsing them into one reason destroys the audit
    # distinction between "nobody stamped this" and "an actor holding a registry credential
    # stamped its own work" — the distinction the whole class exists to record.
    assert provenance_admission_error(
        {**provenance[41], "recorded_at_run": "human:30209757201.1"}, 41) \
        == ATTESTATION_UNRECOGNISED_REASON
    assert provenance_admission_error(
        {**provenance[41], "recorded_at_run": "orchestrator:30209757201.1"}, 41) \
        == attestation_not_machine_reason("orchestrator")
    assert ATTESTATION_UNRECOGNISED_REASON != attestation_not_machine_reason("orchestrator")
    assert "orchestrator-attested" in attestation_not_machine_reason("orchestrator")
    # ...and this must NOT de-admit the live population. Measured on the `ledger` branch
    # 2026-07-26: 350 records, 349 in exactly these two machine shapes, 1 `human:` (merged PR).
    assert provenance_admission_error(
        {**provenance[41], "recorded_at_run": "backfill:29572728300.1"}, 41) is None
    assert provenance_admission_error(
        {**provenance[41], "recorded_at_run": "30212384278.1"}, 41) is None
    assert MACHINE_ATTESTED_CLASSES == {"worker-run", "backfill"}, \
        "widening the machine-attested set is an admission change and must be reviewed as one"
    assert ORCHESTRATOR_CLASS not in MACHINE_ATTESTED_CLASSES, \
        ("the self-attested class must never become machine-attested — admitting it is a "
         "per-consumer opt-in, not a property of the taxonomy")

    # ---- #657 ORCHESTRATOR-CLASS ADMISSION (design record section 6, Option 2(b)) -------------
    # THE GAP. Measured on sparq-org/sparq 2026-07-27 (paginated `gh api /pulls?state=open`,
    # cross-checked against `gh search prs` and GraphQL totalCount — all three said 117 open):
    # 34 open non-draft PRs, 4 reachable by the review lane, 30 unreachable. All 30 are authored
    # by `jeswr` on ordinary branches, and ALL 30 fail the head-ref AND author gates TOGETHER —
    # 0 fail on only one. 4/4 reachable hold a ledger verdict; 0/30 unreachable do.
    _ENROLLED = frozenset({"jeswr"})
    _orch = dict(provenance[41], recorded_at_run="orchestrator:30209757201.1")

    def _enrol_pull(number=41, *, ref="fix/readiness-visibility-opus5", login="jeswr",
                    head_repo=repo, labels=("review:needs",), draft=False, body=""):
        return pull(number, ref, sha_a, head_repo=head_repo, login=login, draft=draft,
                    labels=labels, body=body)

    def _enrol_states(pulls_in, prov_in, *, authors=_ENROLLED, status=None, issues=None):
        return [(item["state"], item["self_attested"]) for item in enumerate_review_items(
            repo, pulls_in, prov_in, [], issues if issues is not None else issue_labels, now,
            pr_status=status, enrolled_authors=authors)]

    # (1) THE HEADLINE GUARD: an owner-authored PR on an ordinary branch becomes reviewable.
    # Deleting either waiver clause in enumerate_review_items reds exactly this line.
    assert _enrol_states([_enrol_pull()], {41: _orch}) == [("needs-review", True)], \
        "an enrolled orchestrator PR must reach the review lane"
    # ...and it is genuinely BOTH gates being waived, not one: the same PR keeps its ordinary
    # branch AND its non-bot author. Restoring either gate unconditionally reds the line above.
    assert not HEAD_REF_RE.match("fix/readiness-visibility-opus5")
    assert not "jeswr".endswith("[bot]")

    # (2) DEFAULT OFF. With no allowlist — the shipped state of every repo — the identical PR
    # and the identical record are refused, by the ORIGINAL reason. This is the assertion that
    # makes "this PR changes no live behaviour until a reviewed master commit opts a login in"
    # a tested claim rather than a promise.
    assert _enrol_states([_enrol_pull()], {41: _orch}, authors=frozenset()) == []
    assert _enrol_states([_enrol_pull()], {41: _orch}, authors=()) == []
    _off_log = io.StringIO()
    with contextlib.redirect_stdout(_off_log):
        enumerate_review_items(repo, [_enrol_pull()], {41: _orch}, [], issue_labels, now)
    assert "head ref is not a worker branch" in _off_log.getvalue()

    # (3) A FORK PR IS NEVER ADMITTED — the one predicate no waiver can reach. The record is
    # valid, the author is enrolled, the branch would be waived: only the fork gate stands, and
    # it must stand FIRST. Hoisting it above the waivable gates is what this pins; moving it
    # back below them reds this because the head-ref reason would win instead.
    _fork_log = io.StringIO()
    with contextlib.redirect_stdout(_fork_log):
        assert enumerate_review_items(
            repo, [_enrol_pull(head_repo="attacker/repo")], {41: _orch}, [], issue_labels, now,
            enrolled_authors=_ENROLLED) == []
    assert "head repo is not the target repo" in _fork_log.getvalue(), _fork_log.getvalue()
    # ...including a fork whose head ref is SPOOFED into worker shape.
    assert enumerate_review_items(
        repo, [_enrol_pull(ref="sparq-agent/issue-7-1-1", head_repo="attacker/repo")],
        {41: _orch}, [], issue_labels, now, enrolled_authors=_ENROLLED) == []

    # (4) AN ARBITRARY THIRD PARTY IS NEVER ADMITTED. Same PR, same valid orchestrator record,
    # a login the master-protected allowlist does not name. Dropping the allowlist half of
    # admits_orchestrator_pr reds this — and it is the difference between "a bounded named set"
    # and "any same-repo author".
    assert _enrol_states([_enrol_pull(login="mallory")], {41: _orch}) == []
    assert _enrol_states([_enrol_pull(login="jeswr-attacker")], {41: _orch}) == []
    assert _enrol_states([_enrol_pull(login="")], {41: _orch}) == []
    # GitHub logins are case-insensitive, so the comparison is casefolded — otherwise the SAME
    # human is admitted or refused depending on how the listing happened to capitalise them.
    assert _enrol_states([_enrol_pull(login="JesWR")], {41: _orch}) == [("needs-review", True)]

    # (5) THE RECORD HALF IS REQUIRED TOO. An enrolled author with a worker-run/backfill record
    # is NOT orchestrator-admitted — such a record asserts a host-side writer that this PR does
    # not have, and admitting it would let the lane invert its `impl_provider` to pick a
    # reviewer. It falls back to the shape gates and is refused.
    assert _enrol_states([_enrol_pull()], {41: provenance[41]}) == []
    assert _enrol_states([_enrol_pull()], {41: dict(
        provenance[41], recorded_at_run="backfill:29572728300.1")}) == []
    assert _enrol_states([_enrol_pull()], {41: dict(
        provenance[41], recorded_at_run="human:30209757201.1")}) == []
    assert _enrol_states([_enrol_pull()], {}) == []
    # A record minted for a DIFFERENT PR waives nothing. The field admission would reject it a
    # few lines later anyway, but the waiver decision must not depend on a LATER check to be
    # sound — that is how a reordering turns a redundant guard into a hole.
    assert not admits_orchestrator_pr(dict(_orch, pr_number=40), 41, "jeswr", _ENROLLED)
    assert _enrol_states([_enrol_pull()], {41: dict(_orch, pr_number=40)}) == []
    # TOTAL and non-raising on every malformed input — it runs inside the PLAN walk.
    for _junk in (None, "not-a-dict", [], 7, {}, {"pr_number": 41}):
        assert admits_orchestrator_pr(_junk, 41, "jeswr", _ENROLLED) is False, repr(_junk)
    for _bad_login in (None, "", 7, [], {}):
        assert admits_orchestrator_pr(_orch, 41, _bad_login, _ENROLLED) is False, repr(_bad_login)
    assert admits_orchestrator_pr(_orch, 41, "jeswr", None) is False

    # (6) REVIEW-ONLY. Every state other than needs-review dispatches a run that PUSHES COMMITS
    # to the PR head (needs-fix / needs-ci-fix / needs-rebase) or re-enters the arm path
    # (stranded). A self-attested record must never buy write access to its own branch.
    _conflicting = {"head_sha": sha_a, "conflicting": True, "armed": False}
    assert _enrol_states([_enrol_pull()], {41: _orch}, status={41: _conflicting}) == []
    _red_gate = {"head_sha": sha_a, "conflicting": False, "armed": False, "gate": "failure",
                 "failing_legs": ["test"]}
    assert _enrol_states([_enrol_pull(labels=())], {41: _orch}, status={41: _red_gate}) == []
    assert _enrol_states([_enrol_pull(labels=("review:changes",))], {41: _orch}) == []
    _green = {"head_sha": sha_a, "conflicting": False, "armed": False, "gate": "success"}
    assert _enrol_states(
        [_enrol_pull(draft=True, labels=(), body=f"<!-- sparq-reviewed-sha:{sha_a} -->")],
        {41: _orch}, status={41: _green}) == []
    # ...and the refusal is VISIBLE, never a silent drop: an operator who enrols a PR that then
    # produces nothing must be able to read why.
    _ro_log = io.StringIO()
    with contextlib.redirect_stdout(_ro_log):
        enumerate_review_items(repo, [_enrol_pull(labels=("review:changes",))], {41: _orch}, [],
                               issue_labels, now, enrolled_authors=_ENROLLED)
    assert "review-only" in _ro_log.getvalue(), _ro_log.getvalue()
    # The SAME conflicting/red-gate/stranded postures on a WORKER PR still produce their repair
    # states — the restriction is scoped to the class, not a global regression.
    _worker = pull(41, "sparq-agent/issue-7-1-1", sha_a, login=bot, draft=False)
    assert [item["state"] for item in enumerate_review_items(
        repo, [_worker], provenance, [], issue_labels, now, pr_status={41: _conflicting},
        enrolled_authors=_ENROLLED)] == ["needs-rebase"]

    # (7) THE PREVIOUSLY REACHABLE POPULATION IS UNAFFECTED. A worker PR enumerates identically
    # with the allowlist on and off, and carries self_attested=False.
    _worker_needs = pull(41, "sparq-agent/issue-7-1-1", sha_a, login=bot, draft=False,
                         labels=("review:needs",))
    assert enumerate_review_items(repo, [_worker_needs], provenance, [], issue_labels, now) == \
        enumerate_review_items(repo, [_worker_needs], provenance, [], issue_labels, now,
                               enrolled_authors=_ENROLLED)
    assert enumerate_review_items(
        repo, [_worker_needs], provenance, [], issue_labels, now)[0]["self_attested"] is False

    # (8) THE ISSUE BINDING SURVIVES, and it was NEVER the head ref. HEAD_REF_RE's capture group
    # is not consumed anywhere in this repository (`grep -rn HEAD_REF_RE scripts/ .github/` —
    # 8 sites, all boolean `.match()`); the issue number a review item is bound to comes from
    # `record["issue"]`, which provenance_admission_error still requires to be a positive int.
    # So an enrolled PR is bound to a real issue and its needs:* human hold still parks the PR.
    assert _enrol_states([_enrol_pull()], {41: _orch},
                         issues={7: ["needs:user"]}) == []
    assert _enrol_states([_enrol_pull()], {41: dict(_orch, issue=0)}) == []
    assert _enrol_states([_enrol_pull()], {41: dict(_orch, issue=True)}) == []
    # ...and the human holds / machine parks are not waived either.
    for _hold in ("needs:user", "review:needs-user", MACHINE_PARK_PR_LABEL):
        assert _enrol_states([_enrol_pull(labels=("review:needs", _hold))], {41: _orch}) == [], _hold

    # (9) THE SCHEMA RE-ASSERTS REVIEW-ONLY. PLAN and CLAIM are different processes reading a
    # serialised artifact, so the enumerator's guard is not sufficient on its own.
    _plan_item = {"pr_number": 41, "head_sha": sha_a, "state": "needs-fix",
                  "impl_provider": "anthropic", "repo": repo, "package": "crate-a",
                  "security": False, "self_attested": True, "context": ""}
    # Built from the SAME `fixture` every other plan-schema assertion uses, so a future required
    # field cannot make this test quietly stop exercising the schema.
    _plan_doc = {**fixture, "review_items": [_plan_item], "disarm_items": []}
    try:
        validate_plan(_plan_doc)
    except DispatchError as _exc:
        assert "review-only" in str(_exc), str(_exc)
    else:
        raise AssertionError("a self-attested item in a code-writing state must be refused")
    assert validate_plan({**_plan_doc, "review_items": [
        {**_plan_item, "state": "needs-review"}]}) is not None
    for _bad in (None, "true", 1, 0, [], {}):
        try:
            validate_plan({**_plan_doc, "review_items": [
                {**_plan_item, "state": "needs-review", "self_attested": _bad}]})
        except DispatchError:
            pass
        else:
            raise AssertionError(f"self_attested={_bad!r} must be refused")
    assert "self_attested" in REVIEW_ITEM_FIELDS, \
        "dropping the field from the schema makes every consumer default the unsafe way"

    # YAML SEAM: the attestation checks live in provenance_admission_error, so they are only
    # load-bearing on the path that actually runs a model against a PR if review-fix.yml's
    # resolve step both CALLS that function and DIES on its result. Asserted against the PARSED
    # workflow (a reflow cannot make it vacuous) and mutation-proven immediately below — the
    # measured lesson is that uncaught mutants live at the YAML seam, not in the Python.
    _RF_ADMISSION_ANCHOR = (
        r"(?m)^[ \t]*admission_error = dispatch_claim\.provenance_admission_error\(")
    _RF_ADMISSION_END = r"(?m)^[ \t]*impl_provider = record\["
    _rf_admission = _review_fix_step_python(
        _RF_ADMISSION_ANCHOR, _RF_ADMISSION_END, "provenance admission consumption")
    assert "raise SystemExit(admission_error)" in _rf_admission, \
        ("review-fix.yml's resolve step must FAIL CLOSED on the shared admission predicate; "
         "without the raise, every check in provenance_admission_error — the #657 attestation "
         f"basis included — is vacuous on the review path. Extracted:\n{_rf_admission}")
    # The seam assertion is only worth its line count if it actually reds. Remove the raise from
    # a COPY of the workflow and prove the extraction no longer satisfies it.
    _rf_no_raise = _rf_text.replace("raise SystemExit(admission_error)",
                                    "admission_error = None")
    assert _rf_no_raise != _rf_text, "the seam mutation fixture no longer matches the workflow"
    assert "raise SystemExit(admission_error)" not in _review_fix_step_python(
        _RF_ADMISSION_ANCHOR, _RF_ADMISSION_END, "provenance admission consumption",
        source=_rf_no_raise), \
        "the seam assertion is VACUOUS — it passes with the fail-closed raise deleted"

    # ---- interpret_check_runs / pr_ci_status (pure CI interpreters, GAP-A inputs) ----
    runs = [
        {"name": "gate", "status": "completed", "conclusion": "failure",
         "started_at": "2026-07-23T02:00:00Z"},
        {"name": "docs-quality", "status": "completed", "conclusion": "failure",
         "started_at": "2026-07-23T01:00:00Z"},
        {"name": "js", "status": "completed", "conclusion": "timed_out",
         "started_at": "2026-07-23T01:00:00Z"},
        {"name": "green", "status": "completed", "conclusion": "success",
         "started_at": "2026-07-23T01:00:00Z"},
    ]
    assert interpret_check_runs(runs) == {"gate": "failure",
                                          "failing_legs": ["docs-quality", "js"]}
    # a later re-run supersedes an earlier conclusion of the same check name
    rerun = runs + [{"name": "gate", "status": "completed", "conclusion": "success",
                     "started_at": "2026-07-23T03:00:00Z"}]
    assert interpret_check_runs(rerun)["gate"] == "success"
    # [round-6 f1] rerun supersession is by PARSED INSTANT, never raw strings: the EXACT
    # spelling pair — an older failed gate "2026-07-23T09:00:00Z" lexicographically BEATS a
    # newer successful rerun "2026-07-23 10:00:00Z" (space sorts before "T"), so the old
    # string compare retained the stale failure and needs-ci-fix dispatched a fixer against
    # a green head. Order-independent: the parsed compare wins both listing orders.
    spelling_pair = [
        {"name": "gate", "status": "completed", "conclusion": "failure",
         "started_at": "2026-07-23T09:00:00Z"},
        {"name": "gate", "status": "completed", "conclusion": "success",
         "started_at": "2026-07-23 10:00:00Z"},
    ]
    assert interpret_check_runs(spelling_pair)["gate"] == "success"
    assert interpret_check_runs(list(reversed(spelling_pair)))["gate"] == "success"
    # ... and the inverse spelling (older space-form failure vs newer T-form success) too.
    assert interpret_check_runs([
        {"name": "gate", "status": "completed", "conclusion": "failure",
         "started_at": "2026-07-23 09:00:00Z"},
        {"name": "gate", "status": "completed", "conclusion": "success",
         "started_at": "2026-07-23T10:00:00Z"},
    ])["gate"] == "success"
    # [round-6 f1] a malformed started_at ranks OLDEST with a loud log — a hostile
    # lexicographically-huge garbage stamp must never retain a stale conclusion over a
    # parseable rerun (unparseable never beats parseable, in either listing order).
    ic_logs = []
    garbage_stamped = [
        {"name": "gate", "status": "completed", "conclusion": "failure",
         "started_at": "zzz-later-than-everything"},
        {"name": "gate", "status": "completed", "conclusion": "success",
         "started_at": "2026-07-23T09:00:00Z"},
    ]
    assert interpret_check_runs(garbage_stamped, log=ic_logs.append)["gate"] == "success"
    assert interpret_check_runs(list(reversed(garbage_stamped)),
                                log=ic_logs.append)["gate"] == "success"
    assert any("unparseable started_at" in line for line in ic_logs), ic_logs
    # two unparseable stamps keep the deterministic last-listed-wins tie rule
    assert interpret_check_runs([
        {"name": "gate", "status": "completed", "conclusion": "failure",
         "started_at": None},
        {"name": "gate", "status": "completed", "conclusion": "success",
         "started_at": "not-a-timestamp"},
    ], log=ic_logs.append)["gate"] == "success"
    # [issue #160] ONLY literal `success` is green. A COMPLETED gate whose conclusion is a
    # broken/incomplete run (cancelled, never-started, stale, needs-a-human) is NOT green — it
    # takes the same ci-fix rerun/escalation path as a hard failure. Pre-fix EVERY one of these
    # fell through to gate="success", suppressing repair on a PR that required checks won't merge.
    quiet = ic_logs.append  # absent started_at logs loudly by design; keep the suite quiet
    for broken in ("cancelled", "action_required", "startup_failure", "stale",
                   "neutral", "skipped"):
        assert interpret_check_runs([{"name": "gate", "status": "completed",
                                      "conclusion": broken}],
                                    log=quiet)["gate"] == "failure", broken
    # ... but an UNRECOGNISED conclusion on a "completed" run (None / hostile garbage) is NOT a
    # known non-pass: it degrades to unknown (never ACT on a poisoned snapshot), not to failure
    # (no spurious repair) and never to success (pre-fix bug: both collapsed to green).
    for junk in (None, "wat", 42, [], {"x": 1}):
        assert interpret_check_runs([{"name": "gate", "status": "completed",
                                      "conclusion": junk}],
                                    log=quiet)["gate"] == "unknown", junk
    assert interpret_check_runs([{"name": "gate", "status": "in_progress",
                                  "conclusion": None}], log=quiet)["gate"] == "pending"
    assert interpret_check_runs([])["gate"] == "missing"
    assert interpret_check_runs("junk") == {"gate": "unknown", "failing_legs": []}
    assert interpret_check_runs([
        {"name": "gate", "status": "completed", "conclusion": "failure"},
        {"name": "lég\nx", "status": "completed", "conclusion": "failure"},
    ], log=quiet)["failing_legs"] == ["l?g?x"]

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
        # Issue #708: worker-pr.py `stranded-recover` retracts the disproved reviewed-sha
        # assertion on the LIVE PR body, and CLAIM re-reads the PR to confirm the postcondition
        # rather than trusting the report. Model both: `stranded_retract` False simulates every
        # stand-down inside stranded_recover (hold / review:pass / armed / marker-mismatch), which
        # must converge to the loud counted refusal, never to another silent no-op dispatch.
        if args and args[0] == "stranded-recover" and fake.get("stranded_retract", True):
            fake["pull"] = dict(
                fake["pull"],
                body=wiring_worker_pr.replace_reviewed_sha(
                    fake["pull"].get("body") or "", wiring_worker_pr.UNBOUND_REVIEWED_SHA))
        if args and args[0] == "stranded-recover" and fake.get("stranded_retract_raises"):
            raise DispatchError("simulated retraction failure")

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
               "security": False, "self_attested": False, "context": "js"}
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
                         "started_at": "2026-07-23T01:00:00Z"}]
            gate_green = [{"name": "gate", "status": "completed", "conclusion": "success",
                           "started_at": "2026-07-23T01:00:00Z"}]
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
            # ISSUE #708: the recovery RETRACTS the disproved reviewed-sha assertion BEFORE it
            # claims the lease. Without this call review-fix.yml's resolve step exits already_done,
            # skips the model job and reports success — the recovery never once executed on master.
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "stranded-recover")], helper_calls
            assert helper_calls[0][1] == [
                "stranded-recover", "--repo", repo, "--pr", "41",
                "--head-sha", sha_a, "--issue", "7"], helper_calls
            assert alloc.calls == [("review", ["sol", "luna"])], alloc.calls
            assert launched == 0 and reasons["review:no-slot"] == 1, reasons
            # repeated failed recovery: the round budget is spent (hard cap) -> loud needs-user,
            # and no review is dispatched — terminal escalation is RESERVED for this case.
            # Re-bind the marker first: the recovery above RETRACTED it (issue #708), and an
            # already-retracted PR is no longer stranded at all — it re-enters as plain
            # needs-review. This case is specifically the still-bound posture.
            fake["pull"] = live_pull(draft=True, labels=["review:needs"],
                                     body=f"x <!-- sparq-reviewed-sha:{sha_a} -->")
            fake["comments"] = [
                {"user": {"login": bot}, "created_at": "2026-07-30T00:00:00Z",
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

            # ---- ISSUE #708: the review lane never spends a lease on a dispatch that cannot run a
            # model, and every such refusal is a COUNTED, ATTRIBUTED lane error ------------------
            # A launching allocator + a launching _run_gh, so "did a review-fix run start?" is a
            # real observation of the production argv rather than an allocator side effect.
            launch_runs = []

            class LaunchingAllocator:
                def __init__(self):
                    self.calls = []

                def claim(self, _repo, _package, role, chain, *_args, **_kwargs):
                    self.calls.append((role, list(chain)))
                    return ({"account": "acct09", "claim_id": "ab" * 16, "model": chain[0],
                             "provider": "openai"}, "")

                def release(self, *_args, **_kwargs):
                    return True

            def launching_run_gh(args, *, check=True):
                launch_runs.append(list(args))
                return subprocess.CompletedProcess(args, 0)

            real_launch_gh = _run_gh
            try:
                globals()["_run_gh"] = launching_run_gh
                os.environ["PROVENANCE_SALT"] = "pepper"
                # (a) THE REPAIRED RECOVERY: the retraction lands, so the SAME stranded posture that
                #     produced 117 no-op runs on master now actually launches a review run.
                fake.update(pull=live_pull(draft=True, labels=["review:needs"],
                                           body=f"x <!-- sparq-reviewed-sha:{sha_a} -->"),
                            check_runs=gate_green, comments=[], stranded_retract=True)
                alloc = LaunchingAllocator()
                launched, reasons = run_items([stranded_item], allocator=alloc,
                                              routing=strand_routing)
                assert [(script, args[0]) for script, args in helper_calls] == [
                    ("worker-pr.py", "stranded-recover")], helper_calls
                assert launched == 1, (launched, reasons)
                assert [arg for args in launch_runs for arg in args
                        if arg.startswith("mode=")] == ["mode=review"], launch_runs
                assert reasons["review-noop-head-already-bound"] == 0, reasons
                assert _lane_summary(run_items.lanes)["review"] == {
                    "planned": 1, "launched": 1, "deferred": 0, "error": 0}, run_items.lanes

                # (b) THE STAND-DOWN: stranded_recover mutated nothing (a hold / review:pass /
                #     armed / marker-mismatch), so the marker still names the head. review-fix.yml
                #     would resolve already_done and skip the model, so NOTHING may be claimed or
                #     launched — and the refusal is a counted lane ERROR with its own attribution,
                #     not a green "deferred" that another productive lane can hide (issue #700).
                launch_runs.clear()
                fake.update(pull=live_pull(draft=True, labels=["review:needs"],
                                           body=f"x <!-- sparq-reviewed-sha:{sha_a} -->"),
                            stranded_retract=False)
                alloc = LaunchingAllocator()
                launched, reasons = run_items([stranded_item], allocator=alloc,
                                              routing=strand_routing)
                assert launched == 0 and launch_runs == [], (launched, launch_runs)
                assert alloc.calls == [], alloc.calls          # no reviewer lease was spent
                assert reasons["review-noop-head-already-bound"] == 1, reasons
                assert _lane_summary(run_items.lanes)["review"] == {
                    "planned": 1, "launched": 0, "deferred": 0, "error": 1}, run_items.lanes

                # (c) THE OTHER LIVE SOURCE: a review:needs-labelled item whose head is already
                #     marker-bound reaches the same dispatch point WITHOUT the stranded branch
                #     (enumerate_review_items emits it via `if not draft or not reviewed_match`,
                #     and CLAIM redrafts it). The invariant is stated over EVERY review dispatch,
                #     so it is refused here too — no helper call, no lease, no launch.
                launch_runs.clear()
                needs_review_item = dict(ci_item, state="needs-review", context="")
                fake.update(pull=live_pull(draft=True, labels=["review:needs"],
                                           body=f"x <!-- sparq-reviewed-sha:{sha_a} -->"))
                alloc = LaunchingAllocator()
                launched, reasons = run_items([needs_review_item], allocator=alloc,
                                              routing=strand_routing)
                assert helper_calls == [], helper_calls
                assert launched == 0 and launch_runs == [] and alloc.calls == [], launch_runs
                assert reasons["review-noop-head-already-bound"] == 1, reasons

                # (d) A FAILED retraction is a counted error and NEVER a dispatch: a review run we
                #     cannot make reviewable must not consume a lease on the chance it works.
                launch_runs.clear()
                fake.update(pull=live_pull(draft=True, labels=["review:needs"],
                                           body=f"x <!-- sparq-reviewed-sha:{sha_a} -->"),
                            stranded_retract=False, stranded_retract_raises=True)
                alloc = LaunchingAllocator()
                launched, reasons = run_items([stranded_item], allocator=alloc,
                                              routing=strand_routing)
                assert launched == 0 and launch_runs == [] and alloc.calls == [], launch_runs
                assert reasons["stranded-retract-failed"] == 1, reasons
                assert _lane_summary(run_items.lanes)["review"] == {
                    "planned": 1, "launched": 0, "deferred": 0, "error": 1}, run_items.lanes
                fake.pop("stranded_retract_raises", None)
                fake["stranded_retract"] = True

                # (e) NON-VACUITY, and the reason the guard is worded as an invariant rather than a
                #     state carve-out: the refusal must fire on an UNREVIEWABLE head, never on a
                #     reviewable one. Same item, marker naming a DIFFERENT head -> launches.
                launch_runs.clear()
                fake.update(pull=live_pull(draft=True, labels=["review:needs"],
                                           body=f"x <!-- sparq-reviewed-sha:{sha_b} -->"))
                alloc = LaunchingAllocator()
                launched, reasons = run_items([needs_review_item], allocator=alloc,
                                              routing=strand_routing)
                assert launched == 1 and reasons["review-noop-head-already-bound"] == 0, \
                    (launched, reasons)
            finally:
                globals()["_run_gh"] = real_launch_gh
                os.environ.pop("PROVENANCE_SALT", None)
                fake.pop("stranded_retract", None)
                fake.pop("stranded_retract_raises", None)
            print("  ok   #708: the review lane retracts the assertion its stranded posture "
                  "disproves, and refuses — loudly, counted, attributed — to spend a reviewer "
                  "lease on any head review-fix.yml would resolve already_done")

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
                # created_at postdates every fixture cutoff below, preserving the old
                # missing-timestamp-is-charged semantics now that the validated reader
                # (round-4 finding 4) requires the full comment shape.
                return {"user": {"login": bot}, "body": body,
                        "created_at": "2026-07-30T00:00:00Z"}

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
                        "security": False, "self_attested": False, "context": ""}
            routing_ok = {"models": {
                "opus5": {"provider_model": "claude-opus-5", "harness": "claude"},
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
            assert launched == 0 and alloc.chains == [["opus5"]], \
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

            # [OPUS-5] ACT: base budget spent on a LEGACY tier (opus). Before the 2026-07-26
            # deprecation this escalated UP the ladder and pinned `fable`. The anthropic ladder is
            # now single-rung, so the legacy history MIGRATES to opus5 — the terminal tier — and
            # the model-pin mechanism correctly cannot fire. The important property is that the
            # PR still has an EXIT: it escalates to a human rather than looping or silently
            # re-running a retired model. (Model escalation itself is still exercised on the
            # openai ladder, which retains two tiers — see the worker-pr.py budget self-tests.)
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->"),
                bot_comment(f"x {fix_model} round=2 model=opus run=2.9 -->")]
            write_verdict(3, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert not any(args[0] == "record-model-pin"
                           for script, args in helper_calls), helper_calls
            assert alloc.chains == [], alloc.chains

            # DO-NOTHING flip: under budget -> no pin call, the DEFAULT fix chain is offered
            fake["comments"] = round_markers(2)
            write_verdict(2, None)
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-marker")], helper_calls
            assert alloc.chains == [["opus5"]], alloc.chains

            # a recorded bot pin governs the chain even under budget (the floor never lowers) —
            # a fable floor offers only floor-and-above (fable + opus5; tiers below the floor
            # are never offered) ...
            fake["comments"] = round_markers(2) + [
                bot_comment(f"z {pin_marker} round=1 tier=fable run=1.5 -->")]
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [["opus5"]], alloc.chains
            # ... while a NON-bot forged pin marker is inert (bot-login trust filter)
            fake["comments"] = round_markers(2) + [
                {"user": {"login": "mallory"}, "created_at": "2026-07-30T00:00:00Z",
                 "body": f"z {pin_marker} round=1 tier=fable run=6.6 -->"}]
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [["opus5"]], alloc.chains

            # top tier (opus5, 2026-07-24) ran + latest verdict improving -> progress
            # extension (pin floor kept)
            fake["comments"] = round_markers(4) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->"),
                bot_comment(f"x {fix_model} round=3 model=opus5 run=3.9 -->"),
                bot_comment(f"z {pin_marker} round=3 tier=opus5 run=3.9 -->")]
            write_verdict(4, "improving")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-marker")], helper_calls
            assert alloc.chains == [["opus5"]], alloc.chains

            # flip-goes-red: top tier + stagnant -> the loud terminal needs-user, no claim
            fake["comments"] = round_markers(4) + [
                bot_comment(f"x {fix_model} round=1 model=opus run=1.9 -->"),
                bot_comment(f"x {fix_model} round=3 model=opus5 run=3.9 -->")]
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
                dict(bot_comment(f"x {fix_model} round=4 model=opus5 run=4.9 -->"),
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
            assert alloc.chains == [["opus5"]], alloc.chains
            # (2) rounds recorded AFTER the unlabel count normally: 2 post-unlabel rounds
            # (base 3) stay under budget even though the GLOBAL count (7) is at the hard cap.
            fake["comments"] = burned_era + stamped_rounds(
                2, "2026-07-23T10:00:00Z", start=6)
            write_verdict(7, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-marker")], helper_calls
            assert alloc.chains == [["opus5"]], alloc.chains
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

            # ---- #555 RECURRENCE GAP: the MISSED-FIX exhaustion branch must honour the
            # readmission window and be IDEMPOTENT against an unchanged head.
            #
            # THE DEFECT (live): sparq PR #3488 was re-admitted 2026-07-22T16:36:56Z and
            # re-escalated at 16:44:10Z — ~7 minutes later, UNCHANGED head, no work attempted;
            # re-admitted again 19:37:39Z and re-escalated 2026-07-23T09:48:39Z. PR #3472
            # re-escalated seven seconds after #3488's with byte-identical boilerplate, five
            # days after the last commit or review round on either PR. `missed` markers are
            # durable per-round state that NOTHING resets and this branch read the LIFETIME
            # count — so the very next tick after any re-admission re-derived the same
            # exhaustion and (with a gen-1 receipt standing) went straight to the ladder's
            # question-class terminal. It needs no head advance and no review round to fire,
            # which is exactly why it hit every PR in a sweep identically. ----
            def stamped_missed(count, created, round_n, start=1):
                return [dict(bot_comment(
                    f"x {wiring_worker_pr.MARKER_KINDS['missed']} round={round_n} "
                    f"run={i}.1 -->"), created_at=created)
                    for i in range(start, start + count)]

            def needs_user_flag(flag):
                return [args[args.index(flag) + 1] for script, args in helper_calls
                        if script == "worker-pr.py" and args[0] == "needs-user"
                        and flag in args]

            def label_event(kind, label, ts, login):
                return {"event": kind, "label": {"name": label},
                        "created_at": ts, "actor": {"login": login}}

            # rounds=2 keeps the ROUND budget (base 3) out of the way, so the missed-fix branch
            # is the one under test; round_number = max(rounds, 1) = 2.
            fake.update(pull=live_pull(draft=True, labels=["review:changes"]))
            write_verdict(2, None)
            burned_misses = stamped_rounds(2, "2026-07-22T05:00:00Z") + stamped_missed(
                MISSED_FIX_LIMIT, "2026-07-22T05:30:00Z", 2)
            # (baseline, unchanged behaviour) no readmission gesture => the lifetime count
            # parks, and the park carries its attempt fingerprint (live head + LIFETIME count).
            fake["comments"] = burned_misses
            fake.pop("timeline", None)
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [], alloc.chains
            assert [f"{MISSED_FIX_LIMIT} consecutive fix dispatches missed for round 2"
                    in reason for reason in needs_user_reasons()] == [True], helper_calls
            assert needs_user_flag("--head-sha") == [sha_a], helper_calls
            assert needs_user_flag("--attempt-key") == [
                f"missed2={MISSED_FIX_LIMIT}"], helper_calls
            # (e) THE 7-MINUTE BOUNCE, reproduced: the maintainer re-admits (a proven-human
            # unlabel of the machine park at the observed 16:36:56Z) and the sweep ticks again
            # with an UNCHANGED head and NO new work attempted. Pre-fix the lifetime count
            # re-derived the same exhaustion and re-escalated. It must now grant REAL capacity:
            # zero chargeable misses in the window => NO park, and the fix chain is offered
            # again (the trailing record-marker is the allocator saying "no slot", which is a
            # fresh miss inside the new window — not an escalation).
            fake["timeline"] = {41: [label_event("labeled", "review:parked",
                                                "2026-07-22T16:00:00Z",
                                                "sparq-orchestrator[bot]"),
                                     label_event("unlabeled", "review:parked",
                                                "2026-07-22T16:36:56Z", "jeswr")], 7: []}
            alloc = FakeAllocator()
            bounce_log = io.StringIO()
            with contextlib.redirect_stdout(bounce_log):
                run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert needs_user_reasons() == [], helper_calls
            assert [(script, args[0]) for script, args in helper_calls] == [
                ("worker-pr.py", "record-marker")], helper_calls
            assert alloc.chains == [["opus5"]], alloc.chains
            assert "the missed-fix budget for round 2 charges 0 of " \
                f"{MISSED_FIX_LIMIT}" in bounce_log.getvalue(), bounce_log.getvalue()
            # (c) a re-admission grants a FRESH allowance, not an unbounded one: once the
            # WINDOW itself accumulates MISSED_FIX_LIMIT misses the park fires again — charged
            # on the window (6), fingerprinted on the LIFETIME count (12, monotone across
            # windows so two genuinely distinct windows can never read as "unchanged").
            fake["comments"] = burned_misses + stamped_missed(
                MISSED_FIX_LIMIT, "2026-07-23T10:00:00Z", 2, start=MISSED_FIX_LIMIT + 1)
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [], alloc.chains
            assert [f"{MISSED_FIX_LIMIT} consecutive fix dispatches missed for round 2"
                    in reason for reason in needs_user_reasons()] == [True], helper_calls
            assert needs_user_flag("--attempt-key") == [
                f"missed2={MISSED_FIX_LIMIT * 2}"], helper_calls
            # (3'/5') a BOT unlabel opens no window and a timeline read failure keeps the FULL
            # count — the missed-fix budget fails in the SAME conservative direction as the
            # round budget (never a fresh allowance on unproven data).
            fake["comments"] = burned_misses
            fake["timeline"] = {41: [label_event("unlabeled", "review:parked",
                                                "2026-07-22T16:36:56Z",
                                                "sparq-orchestrator[bot]")], 7: []}
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [] and needs_user_reasons(), (alloc.chains, helper_calls)
            fake["timeline_error"] = True
            alloc = FakeAllocator()
            missed_probe_log = io.StringIO()
            with contextlib.redirect_stdout(missed_probe_log):
                run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert alloc.chains == [] and needs_user_reasons(), (alloc.chains, helper_calls)
            assert "timeline read failed" in missed_probe_log.getvalue(), \
                missed_probe_log.getvalue()
            fake.pop("timeline_error", None)
            # The ROUND-budget park on this same path also carries its fingerprint (live head +
            # the GLOBAL round count — never the window-relative charge, which resets).
            fake["comments"] = burned_era
            fake.pop("timeline", None)
            write_verdict(5, "stagnant")
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_ok)
            assert ["exhausted at 5 round(s)" in reason
                    for reason in needs_user_reasons()] == [True], helper_calls
            assert (needs_user_flag("--head-sha"), needs_user_flag("--attempt-key")) == (
                [sha_a], ["rounds=5"]), helper_calls
            (Path(wiring_root) / wiring_worker_pr.verdict_path(repo, 41, 2)).unlink()

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

            # [OPUS-5] flip-goes-red: the same posture whose latest fix ran BELOW the recorded
            # floor (a pin violation) mints NO re-review — with the top tier already graded
            # stagnant it is the loud terminal instead.
            #
            # After the 2026-07-26 deprecation this case is NOT EXPRESSIBLE on the anthropic
            # ladder: it has a single rung (opus5), so nothing can be below the floor, and a
            # legacy `model=opus` marker MIGRATES to opus5 (= at the floor) rather than reading
            # as a violation. Rather than delete the invariant, it is asserted here on a tier the
            # ladder genuinely does not contain, and — for the real two-tier form — on the openai
            # ladder in worker-pr.py's budget self-tests ("pending fix BELOW the pinned floor
            # never extends (openai, two-tier)"). Deleting either assertion must red one of the
            # two suites.
            fake["comments"] = round_markers(3) + [
                bot_comment(f"x {fix_model} round=1 model=opus5 run=1.9 -->"),
                bot_comment(f"z {pin_marker} round=1 tier=opus5 run=1.5 -->"),
                bot_comment(f"x {fix_model} round=3 model=sonnet run=3.9 -->")]
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
                bot_comment(f"x {fix_model} round=3 model=opus5 run=3.9 -->")]
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
            assert alloc.chains == [["opus5"]], alloc.chains
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
                "opus5": {"provider": "anthropic", "provider_model": "claude-opus-5",
                          "harness": "claude"},
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
            assert alloc.chains == [["opus5"]], alloc.chains
            # (c) the hold is CONDITIONED on the OUTAGE: require_usage with a LIVE usage map
            # dispatches (usage!=None is not a probe failure).
            alloc = FakeAllocator()
            run_items([fix_item], allocator=alloc, routing=routing_prov,
                      policy=usage_gated, usage={"acct01": {"ok": True}})
            assert alloc.chains == [["opus5"]], alloc.chains
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
            # [OPUS-5] the alias here must be one the LIVE anthropic fix chain actually names,
            # or the chain fails to resolve first and this fixture stops exercising the
            # unknown-provider hold at all (it silently became a preclaim-defer when the chain
            # lost its fable/opus rungs). opus5 is that alias.
            routing_unknown = {"models": {
                "opus5": {"provider": "mystery", "provider_model": "x", "harness": "claude"},
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
                    "package": f"fanout-{offset}", "security": False,
                    "self_attested": False, "context": "gate",
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
        good_comment = {"user": {"login": "b[bot]"}, "body": "x",
                        "created_at": "2026-07-23T09:00:00Z"}
        globals()["_gh_json"] = lambda args: [[good_comment], "garbage"]
        try:
            _pr_comments(repo, 41)
        except DispatchError as exc:
            assert "comments page is malformed" in str(exc), exc
        else:
            raise AssertionError("a malformed PR comments page must fail loud")
        # round-4 finding 4: ENTRY validation — [[null]] passed the old page-only check and
        # the first consumer (_bot_comments None.get()) crashed with an AttributeError that
        # aborted the ENTIRE claim sweep. Each malformed shape must raise DispatchError at
        # read time (the sweep's per-item handlers then defer just that item).
        for bad_entry in (None, "loose-string", {**good_comment, "user": None},
                          {**good_comment, "body": None},
                          {**good_comment, "created_at": None}):
            globals()["_gh_json"] = lambda args: [[good_comment, bad_entry]]
            try:
                _pr_comments(repo, 41)
            except DispatchError as exc:
                assert "comments entry is malformed" in str(exc), (bad_entry, exc)
            else:
                raise AssertionError(f"a malformed comments entry must fail loud: {bad_entry!r}")
        globals()["_gh_json"] = lambda args: [[good_comment]]
        assert _pr_comments(repo, 41) == [good_comment]
    finally:
        globals()["_gh_json"] = prev_live_gh

    # ---- round-4 finding 2 (the crash window, CLAIM side): the ONE proof-gate trigger is
    # receipt-OR-label. Receipt-posted-label-missing (a park writer died between its durable
    # receipt and its label write — the only crash residue RECEIPT-FIRST ordering permits)
    # still requires the readmission proof; label-no-receipt is impossible by the writers'
    # ordering (worker-pr's self-test asserts the call order), and a live label alone still
    # gates (a pre-receipt legacy park). ----
    assert capacity_park_proof_required([], {"2026-07-23T09:00:00Z"}) is True
    assert capacity_park_proof_required([], {"none"}) is True
    assert capacity_park_proof_required(["review:parked"], set()) is True
    assert capacity_park_proof_required(["review:parked"], {"none"}) is True
    assert capacity_park_proof_required(["review:needs"], set()) is False
    assert capacity_park_proof_required([], set()) is False

    # ---- [registry #614] the AUTOMATIC re-admission sweep: a MACHINE capacity park whose
    # starvation cause has demonstrably cleared re-admits ITSELF, receipt-first. THE DEFECT it
    # closes: only a HUMAN could clear a MACHINE-owned park, so the acct01 auth outage (#596)
    # parked PRs that the credential fix could not recover — each needed a hand-unlabel. ----
    model_health_mod = _load_module(
        "registry_model_health_readmit", Path(__file__).resolve().parent / "model-health.py")
    worker_pr_mod = _load_module(
        "registry_worker_pr_readmit", Path(__file__).resolve().parent / "worker-pr.py")
    readmit_bot = "sparq-orchestrator[bot]"
    readmit_salt = "s3cret"
    readmit_account = model_health_mod.account_hash("acct01", readmit_salt)
    readmit_now = 1_800_000
    park_epoch = readmit_now - 3600                 # the park landed an hour ago
    park_stamp = model_health_mod._iso_z(park_epoch)

    def health_record(cls, dt, run):
        return model_health_mod.make_record("openai", readmit_account, "sol", cls, run,
                                            readmit_now + dt)

    # The live shape: the sole review account failed `auth` before the park, then recorded a
    # SUCCESSFUL run after it (the credential fix landed).
    recovered_window = [health_record("auth", -4000, "6001.1"),
                        health_record("auth", -3800, "6002.1"),
                        health_record(model_health_mod.SUCCESS, -600, "6003.1")]
    still_broken_window = recovered_window[:2]
    parked_row = {
        "number": 41, "state": "open", "draft": True,
        "user": {"login": readmit_bot},
        "head": {"sha": "a" * 40, "ref": "sparq-agent/issue-7-abc",
                 "repo": {"full_name": "example/repo"}},
        "labels": [{"name": MACHINE_PARK_PR_LABEL}],
    }
    park_timeline = {
        41: [{"event": "labeled", "label": {"name": MACHINE_PARK_PR_LABEL},
              "created_at": park_stamp, "actor": {"login": readmit_bot},
              "performed_via_github_app": None}],
        7: [],
    }

    def readmit_sweep(window, rows=None, labels=None, comments=(), holds=None, timeline=None):
        """Run the sweep with every GitHub seam injected; returns (count, posted, cleared)."""
        posted, cleared = [], []
        count = _readmit_capacity_parks(
            "example/repo", rows if rows is not None else [[parked_row]],
            labels if labels is not None else {7: ["status:in-progress-review"]},
            {41: {"issue": 7}}, readmit_bot, Path("."), worker_pr_mod,
            _capacity_recovery_probe(model_health_mod, window, readmit_now),
            comments_fn=lambda _repo, _number: list(comments),
            timeline_fn=lambda _repo, number: list((timeline or park_timeline).get(number, [])),
            post_comment=lambda _repo, number, body: posted.append((number, body)),
            clear_labels=lambda pr, issue: cleared.append((pr, issue)),
            log=lambda _line: None)
        return count, posted, cleared

    # A(a): the machine park + a post-park success on the failing account => re-admitted ONCE,
    # RECEIPT FIRST, and the receipt names the evidence the admission consumed.
    prev_target_probe = globals()["_target_is_human_maintainer"]
    globals()["_target_is_human_maintainer"] = lambda _repo, login: login == "jeswr"
    try:
        count, posted, cleared = readmit_sweep(recovered_window)
        assert count == 1 and cleared == [(41, 7)], (count, cleared)
        assert len(posted) == 1 and posted[0][0] == 41, posted
        receipt_body = posted[0][1]
        assert worker_pr_mod.AUTO_READMIT_MARKER in receipt_body, receipt_body
        assert f"openai/{readmit_account}/6003.1" in receipt_body, receipt_body
        assert "acct01" not in receipt_body, receipt_body
        print("  ok   auto-readmit (a): proven cause-recovery re-admits a machine park, "
              "receipt-first")
        # A(b): the SAME evidence, now receipted, never re-admits again — and because the receipt
        # is not superseded by a NEWER park it converges the label strip idempotently instead.
        receipted = [{"user": {"login": readmit_bot}, "body": receipt_body}]
        count, posted, cleared = readmit_sweep(recovered_window, comments=receipted)
        assert count == 1 and posted == [] and cleared == [(41, 7)], (count, posted, cleared)
        print("  ok   auto-readmit (b): a receipted re-admission consumes NO new evidence "
              "(converge only)")
        # ... and once a NEWER park application supersedes that receipt, the same evidence is
        # refused outright: a fresh park needs a fresh outage-and-recovery pair.
        superseded = {41: park_timeline[41] + [
            {"event": "labeled", "label": {"name": MACHINE_PARK_PR_LABEL},
             "created_at": model_health_mod._iso_z(readmit_now - 60),
             "actor": {"login": readmit_bot}, "performed_via_github_app": None}], 7: []}
        count, posted, cleared = readmit_sweep(recovered_window, comments=receipted,
                                              timeline=superseded)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        print("  ok   auto-readmit (b): the SAME evidence cannot re-earn a re-admission after a "
              "NEW park")
        # A(c): no post-park success => the park stands, nothing is written.
        count, posted, cleared = readmit_sweep(still_broken_window)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        print("  ok   auto-readmit (c): no proven recovery => the park stands, no mutation")
        # A(d): an unreadable health window => the park stands (the probe yields no evidence).
        count, posted, cleared = readmit_sweep(None)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        # ... as does a malformed record inside the window.
        poisoned = recovered_window + [dict(recovered_window[-1], exit_class="totally-new")]
        count, posted, cleared = readmit_sweep(poisoned)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        print("  ok   auto-readmit (d): an unreadable/ambiguous health record => the park stands")
        # A(e): a HUMAN-owned hold on EITHER surface is never auto-re-admitted.
        human_pr = dict(parked_row, labels=[{"name": MACHINE_PARK_PR_LABEL},
                                            {"name": "review:needs-user"}])
        count, posted, cleared = readmit_sweep(recovered_window, rows=[[human_pr]])
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        count, posted, cleared = readmit_sweep(
            recovered_window, labels={7: ["status:parked", "needs:user"]})
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        print("  ok   auto-readmit (e): a human-owned hold on either surface is never "
              "auto-re-admitted")
        # A(e'): a park the MAINTAINER applied is human-owned — only a human clears it.
        human_park = {41: [{"event": "labeled", "label": {"name": MACHINE_PARK_PR_LABEL},
                            "created_at": park_stamp, "actor": {"login": "jeswr"},
                            "performed_via_github_app": None}], 7: []}
        count, posted, cleared = readmit_sweep(recovered_window, timeline=human_park)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        print("  ok   auto-readmit (e): a MAINTAINER-applied park is never auto-re-admitted")
        # A(g): the per-PR cap terminates — AUTO_READMISSION_MAX markers (well-formed or not)
        # refuse the next re-admission even with fresh evidence.
        capped = [{"user": {"login": readmit_bot},
                   "body": f"x {worker_pr_mod.AUTO_READMIT_MARKER} evidence=openai/x/{i} "
                           f"at=zzz -->"}
                  for i in range(_park_policy.AUTO_READMISSION_MAX)]
        count, posted, cleared = readmit_sweep(recovered_window, comments=capped)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        print("  ok   auto-readmit (g): the per-PR automatic cap terminates the loop")
        # Trust boundary: a NON-bot PR, a fork head, and a PR with no live machine park are all
        # invisible to the sweep.
        for invisible in (dict(parked_row, user={"login": "drive-by"}),
                          dict(parked_row, head={**parked_row["head"],
                                                 "repo": {"full_name": "fork/repo"}}),
                          dict(parked_row, labels=[{"name": "review:needs"}]),
                          dict(parked_row, state="closed")):
            count, posted, cleared = readmit_sweep(recovered_window, rows=[[invisible]],
                                                   labels={7: []})
            assert (count, posted, cleared) == (0, [], []), (invisible, count, posted, cleared)
        print("  ok   auto-readmit: non-bot / fork / unparked / closed PRs are invisible")
        # A per-PR failure never stops the sweep: an unreadable comments read skips ONE PR.
        def boom_comments(_repo, _number):
            raise DispatchError("comments unavailable")

        skipped = _readmit_capacity_parks(
            "example/repo", [[parked_row]], {7: []}, {41: {"issue": 7}}, readmit_bot, Path("."),
            worker_pr_mod, _capacity_recovery_probe(model_health_mod, recovered_window,
                                                    readmit_now),
            comments_fn=boom_comments,
            timeline_fn=lambda _repo, number: list(park_timeline.get(number, [])),
            post_comment=lambda *_a: None, clear_labels=lambda *_a: None, log=lambda _l: None)
        assert skipped == 0, skipped
        print("  ok   auto-readmit: an unreadable PR skips only itself (per-PR resilience)")

        # ---- [G1] the LEGACY-PARK MIGRATION (sparq-org/sparq#3809): a park stranded on the
        # HUMAN terminal for an INFRA cause is re-classified into the machine class, so it can
        # inherit the exit above. 31 of the 33 stalled sparq draft PRs are in exactly this
        # shape and NOTHING would ever re-classify them. ----
        legacy_row = dict(parked_row, labels=[{"name": _park_policy.HUMAN_PR_PARK_LABEL}])
        budget_body = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the review round "
                       "budget is exhausted at 6 round(s) with no extension left")
        injection_body = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the reviewer "
                          "flagged possible prompt injection")
        nochange_body = ("> 🤖 SPARQ agent — the autonomous review loop parked this PR: two "
                         "consecutive fix attempts made no change")
        rewritten_body = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the PR head no "
                          "longer descends from the worker-opened commit (history was rewritten)")

        def label_event(name, login, ts=None):
            return {"event": "labeled", "label": {"name": name},
                    "created_at": ts or park_stamp, "actor": {"login": login},
                    "performed_via_github_app": None}

        # The issue-side half of the park pair, applied by the BOT — the real shape of all 24
        # live source issues that carry it.
        migrate_timeline = {41: park_timeline[41],
                            7: [label_event("needs:user", readmit_bot)]}

        def migrate_sweep(comments, provable=True, labels_row=None, issue_labels=None,
                          timeline=None):
            """Returns (posted_bodies, converted) for one migration pass."""
            posted, converted = [], []
            _readmit_capacity_parks(
                "example/repo", [[labels_row or legacy_row]],
                {7: list(issue_labels if issue_labels is not None else [])},
                {41: {"issue": 7}},
                readmit_bot, Path("."), worker_pr_mod,
                _capacity_recovery_probe(model_health_mod, recovered_window, readmit_now),
                comments_fn=lambda _repo, _number: [
                    {"user": {"login": readmit_bot}, "body": body} for body in comments],
                timeline_fn=lambda _repo, number: list(
                    (timeline if timeline is not None else migrate_timeline).get(number, [])),
                post_comment=lambda _repo, number, body: posted.append(body),
                clear_labels=lambda *_a: None, log=lambda _l: None,
                migration_provable=provable,
                convert_labels=lambda pr, issue: converted.append((pr, issue)))
            return posted, converted

        posted, converted = migrate_sweep([budget_body])
        assert converted == [(41, 7)], converted
        assert len(posted) == 1 and _park_policy.PARK_REASON_MARKER in posted[0], posted
        assert "cause=budget" in posted[0] and "class=capacity" in posted[0], posted
        print("  ok   legacy-migration: an infra park on the human terminal is re-classified "
              "into the machine class, receipt-first")

        # THE guard: a genuine escalation is NEVER migrated — including the live sparq#3743
        # shape, where the injection flag is OLDER than a later capacity-park comment.
        for name, bodies in (
                ("#3542-shape", [injection_body]),
                ("#3743-shape", [injection_body, nochange_body]),
                ("#3608-shape", [nochange_body, injection_body])):
            posted, converted = migrate_sweep(bodies)
            assert (posted, converted) == ([], []), (name, posted, converted)
        print("  ok   legacy-migration: a genuine injection escalation is never migrated, at "
              "any position in its history")

        # A question-class cause is RECORDED but never moved — the human terminal is correct.
        posted, converted = migrate_sweep([rewritten_body])
        assert converted == [], converted
        assert len(posted) == 1 and "cause=history-rewritten" in posted[0], posted
        assert "class=question" in posted[0], posted
        print("  ok   legacy-migration: a question-class cause is made machine-readable but "
              "its human hold is left in place")

        # THE do-no-harm gate: not provable => defer, consuming nothing. Without this the
        # migration would convert a VISIBLE stall into a SILENT one.
        posted, converted = migrate_sweep([budget_body], provable=False)
        assert (posted, converted) == ([], []), (posted, converted)
        print("  ok   legacy-migration: an unprovable park is DEFERRED, never converted into a "
              "state it could not leave")

        # ONE-SHOT: the reason marker it wrote makes the PR no longer legacy.
        posted, converted = migrate_sweep([budget_body, budget_body
                                           + _park_policy.park_reason_marker("budget")])
        assert (posted, converted) == ([], []), (posted, converted)
        print("  ok   legacy-migration: a PR that already carries a reason marker is never "
              "migrated twice")

        # An unrecognised cause, and a PR already in the machine class, are both untouched.
        assert migrate_sweep(["something went wrong"]) == ([], []), "unrecognised cause moved"
        assert migrate_sweep([budget_body], labels_row=parked_row)[1] == [], \
            "a PR already in the machine class was migrated"
        print("  ok   legacy-migration: an unrecognised cause and an already-machine park are "
              "left alone")

        # THE guard the human-terminal precondition actually exists for: a PR that is NOT PARKED
        # AT ALL still reaches _migrate_legacy_park (it has no machine park, so the sweep's outer
        # check lets it through) and still carries budget prose from an EARLIER, since-cleared
        # park. Migrating it would APPLY review:parked to a live, unparked PR — parking work that
        # nobody parked. Only a PR sitting on the human terminal is a migration candidate.
        live_row = dict(parked_row, labels=[{"name": "review:needs"}])
        posted, converted = migrate_sweep([budget_body], labels_row=live_row)
        assert (posted, converted) == ([], []), (posted, converted)
        print("  ok   legacy-migration: an UNPARKED PR carrying stale park prose is never "
              "parked by the migration")

        # ---- THE COMPOSED TEST: migrate, then re-admit the RESULTING state. ------------------
        # A park is a PAIR (review:needs-user on the PR + needs:user on the source issue) and the
        # first cut cleared only the PR half. Each stage passed its own fixture in isolation —
        # migration with `{7: []}`, re-admission with `{7: ["status:in-progress-review"]}` — and
        # the defect lived exactly in the seam they never composed. MEASURED on the live sparq
        # population: 24 of 33 source issues carry needs:user, so 19 of 20 migrated PRs would
        # have become permanently unreleasable. This test composes the two stages.
        composed_pr_labels = {"review:needs-user"}
        composed_issue_labels = {"status:deferred", "needs:user", "role:impl"}

        def composed_convert(pr, issue):
            """What the production convert_labels does, applied to the fixture state."""
            composed_pr_labels.discard(_park_policy.HUMAN_PR_PARK_LABEL)
            composed_pr_labels.add(MACHINE_PARK_PR_LABEL)
            for hold in _park_policy.human_owned_holds(composed_issue_labels):
                composed_issue_labels.discard(hold)
            composed_issue_labels.add("status:parked")

        stage1_row = dict(parked_row, labels=[{"name": n} for n in composed_pr_labels])
        migrated_count = _readmit_capacity_parks(
            "example/repo", [[stage1_row]], {7: sorted(composed_issue_labels)},
            {41: {"issue": 7}}, readmit_bot, Path("."), worker_pr_mod,
            _capacity_recovery_probe(model_health_mod, still_broken_window, readmit_now),
            comments_fn=lambda _repo, _number: [
                {"user": {"login": readmit_bot}, "body": budget_body}],
            timeline_fn=lambda _repo, number: list(migrate_timeline.get(number, [])),
            post_comment=lambda *_a: None, clear_labels=lambda *_a: None, log=lambda _l: None,
            migration_provable=True, convert_labels=composed_convert)
        assert migrated_count == 0, "the migration must not re-admit in the same breath"
        assert composed_pr_labels == {MACHINE_PARK_PR_LABEL}, composed_pr_labels
        assert "needs:user" not in composed_issue_labels, composed_issue_labels

        # Stage 2 — the SAME PR, on the state stage 1 actually produced, with proven recovery.
        stage2_row = dict(parked_row, labels=[{"name": n} for n in sorted(composed_pr_labels)])
        composed_readmitted, composed_cleared = 0, []
        composed_readmitted = _readmit_capacity_parks(
            "example/repo", [[stage2_row]], {7: sorted(composed_issue_labels)},
            {41: {"issue": 7}}, readmit_bot, Path("."), worker_pr_mod,
            _capacity_recovery_probe(model_health_mod, recovered_window, readmit_now),
            comments_fn=lambda _repo, _number: [],
            timeline_fn=lambda _repo, number: list(park_timeline.get(number, [])),
            post_comment=lambda *_a: None,
            clear_labels=lambda pr, issue: composed_cleared.append((pr, issue)),
            log=lambda _l: None, migration_provable=False)
        assert composed_readmitted == 1, (composed_readmitted, sorted(composed_issue_labels))
        assert composed_cleared == [(41, 7)], composed_cleared
        print("  ok   legacy-migration COMPOSED: a migrated PR whose source issue carried "
              "needs:user actually re-admits on proven recovery (both halves of the pair)")

        # ...and a HUMAN-applied `needs:user` is NOT clearable: that PR defers instead.
        posted, converted = migrate_sweep(
            [budget_body], issue_labels=["needs:user"],
            timeline={41: park_timeline[41], 7: [label_event("needs:user", "jeswr")]})
        assert (posted, converted) == ([], []), (posted, converted)
        print("  ok   legacy-migration: a HUMAN-applied issue hold is never cleared — that PR "
              "defers rather than having a real human hold erased")

        # The residual-hold precondition, on a state the fleet can actually reach: groom's
        # age-park writes `needs:user` onto the PR ITSELF (groom.py adds it to
        # /issues/<pr>/labels), so a PR can carry BOTH review:needs-user and needs:user. The
        # conversion removes only review:needs-user, so the PR-side needs:user SURVIVES and
        # would block re-admission exactly like the issue-side one did. That hold is groom's
        # orphan/wedged-merge hand-off — a genuine human question — so the right answer is to
        # DEFER, not to clear it. (No PR is in this state today; it is reachable, and this seam
        # is precisely where the issue-half defect lived.)
        groom_row = dict(parked_row, labels=[{"name": _park_policy.HUMAN_PR_PARK_LABEL},
                                             {"name": "needs:user"}])
        posted, converted = migrate_sweep([budget_body], labels_row=groom_row)
        assert (posted, converted) == ([], []), (posted, converted)
        print("  ok   legacy-migration: a hold that would SURVIVE the conversion (groom's "
              "PR-side needs:user) defers the migration instead of stranding the PR")

        # ---- the ownership proof must be ABOUT THE LABEL BEING CLEARED ----------------------
        # Authorising a delete with evidence about a DIFFERENT label failed in three directions.
        # Each of these was a live hole, demonstrated by execution before the fix.
        #
        # (i) a human-applied needs:user, with a LATER bot park event on another label. Reading
        # the newest event across READMISSION_LABELS said "machine"; the needs:user application
        # itself was a human's.
        posted, converted = migrate_sweep(
            [budget_body], issue_labels=["needs:user"],
            timeline={41: park_timeline[41], 7: [
                label_event("needs:user", "jeswr", model_health_mod._iso_z(readmit_now - 900)),
                label_event("status:parked", readmit_bot,
                            model_health_mod._iso_z(readmit_now - 60))]})
        assert (posted, converted) == ([], []), (posted, converted)
        print("  ok   legacy-migration: a HUMAN-applied needs:user is not clearable just because "
              "a LATER bot park event exists on a different label")

        # (ii) another party's needs:* is never touched and never reasoned about. The migration
        # may only ever clear `needs:user`; anything else defers via the residual precondition.
        # `needs:external-audit` is the sq-qhy4 external accredited-cryptographer audit gate —
        # silently deleting it is the worst single outcome available on this path.
        for foreign in ("needs:external-audit", "needs:ec2", "needs:maintainer"):
            posted, converted = migrate_sweep(
                [budget_body], issue_labels=["needs:user", foreign],
                timeline={41: park_timeline[41], 7: [
                    label_event("needs:user", readmit_bot),
                    label_event(foreign, "jeswr")]})
            assert (posted, converted) == ([], []), (foreign, posted, converted)
        print("  ok   legacy-migration: a foreign needs:* (incl. the sq-qhy4 external-audit "
              "gate) defers the migration and is never deleted")

        # (iii) ABSENCE OF EVIDENCE IS NOT PROOF. A needs:user with no `labeled` event at all
        # previously read as machine-owned, because "no park application" returned not-human.
        posted, converted = migrate_sweep(
            [budget_body], issue_labels=["needs:user"],
            timeline={41: park_timeline[41], 7: []})
        assert (posted, converted) == ([], []), (posted, converted)
        print("  ok   legacy-migration: a needs:user with NO labeled event is not clearable "
              "(absence of evidence is not proof of machine ownership)")

        # ---- THE WRITER BINDING: exercise the PRODUCTION convert_labels ---------------------
        # Every other test injects its own convert_labels, so the real writer — the code that
        # actually mutates GitHub — was executed by NOTHING. That is the defect class this PR
        # kept repeating: a test that restates the policy instead of binding the writer. Here
        # the GitHub seams are injected the way the suite already injects
        # _target_is_human_maintainer, convert_labels is left as None so the PRODUCTION closure
        # runs, and the exact API calls are asserted.
        api_calls, helper_calls = [], []
        prev_api = globals()["_run_gh_target_api"]
        prev_helper = globals()["_run_target_helper"]
        globals()["_run_gh_target_api"] = (
            lambda repo, method, path, input_doc=None: api_calls.append((method, path, input_doc))
            or types.SimpleNamespace(stdout="{}"))
        globals()["_run_target_helper"] = (
            lambda script_dir, repo, script, args: helper_calls.append((script, args)))
        try:
            _readmit_capacity_parks(
                "example/repo", [[legacy_row]], {7: ["needs:user", "status:deferred"]},
                {41: {"issue": 7}}, readmit_bot, Path("."), worker_pr_mod,
                _capacity_recovery_probe(model_health_mod, recovered_window, readmit_now),
                comments_fn=lambda _repo, _number: [
                    {"user": {"login": readmit_bot}, "body": budget_body}],
                timeline_fn=lambda _repo, number: list(migrate_timeline.get(number, [])),
                post_comment=lambda *_a: None, clear_labels=lambda *_a: None,
                log=lambda _l: None, migration_provable=True)   # convert_labels=None => REAL
        finally:
            globals()["_run_gh_target_api"] = prev_api
            globals()["_run_target_helper"] = prev_helper
        assert api_calls == [
            ("DELETE", "repos/example/repo/issues/41/labels/review%3Aneeds-user", None),
            ("POST", "repos/example/repo/issues/41/labels",
             {"labels": [MACHINE_PARK_PR_LABEL]}),
            ("DELETE", "repos/example/repo/issues/7/labels/needs%3Auser", None),
        ], api_calls
        assert helper_calls == [("worker-issue.py", [
            "status", "--repo", "example/repo", "--issue", "7", "--status", "parked"])], \
            helper_calls
        print("  ok   legacy-migration WRITER: the PRODUCTION convert_labels clears BOTH halves "
              "of the park pair — asserted on the real API calls, not a fixture restatement")

        # BOUNDED RE-ENTRY: one tick may migrate at most LEGACY_PARK_MIGRATION_MAX PRs. 21 PRs
        # re-entering at once would starve the very allocator whose starvation parked most of
        # them — the migration must not recreate its own cause.
        # Assert the BOUND ITSELF first, before sizing any fixture from it: a per-tick pacing cap
        # that is not small is not a pacing cap, and a fixture sized from an unbounded constant
        # would hang instead of failing (which is how this test first went wrong).
        assert 0 < LEGACY_PARK_MIGRATION_MAX <= 10, LEGACY_PARK_MIGRATION_MAX
        many_rows = [dict(legacy_row, number=n,
                          head=dict(legacy_row["head"], ref=f"sparq-agent/issue-{n}-abc"))
                     for n in range(41, 41 + LEGACY_PARK_MIGRATION_MAX + 3)]
        many_converted = []
        _readmit_capacity_parks(
            "example/repo", [many_rows], {}, {row["number"]: {"issue": 7} for row in many_rows},
            readmit_bot, Path("."), worker_pr_mod,
            _capacity_recovery_probe(model_health_mod, recovered_window, readmit_now),
            comments_fn=lambda _repo, _number: [
                {"user": {"login": readmit_bot}, "body": budget_body}],
            timeline_fn=lambda _repo, number: list(park_timeline.get(number, [])),
            post_comment=lambda *_a: None, clear_labels=lambda *_a: None, log=lambda _l: None,
            migration_provable=True,
            convert_labels=lambda pr, issue: many_converted.append(pr))
        assert len(many_converted) == LEGACY_PARK_MIGRATION_MAX, many_converted
        print(f"  ok   legacy-migration: one tick migrates at most "
              f"{LEGACY_PARK_MIGRATION_MAX} parks (bounded re-entry)")

        # ---- [registry #691] THE AGED-OUT PARK EXIT, AT THE LAYER THAT BINDS ---------------
        # _capacity_recovery_probe is where a park's machine exit is actually decided; the
        # migration precondition is only a PREDICTOR of it. Every test below therefore drives
        # the PRODUCTION probe and the PRODUCTION precondition function — nothing here restates
        # the policy, and `migration_provable` is never hand-set to True.
        #
        # THE DEFECT: capacity_recovery_evidence fixes a park's cause at its APPLICATION
        # INSTANT and the health window is a rolling 48 h, so a park older than the window has
        # no record at or before `parked_at` at all and can never satisfy condition 1. Measured
        # 2026-07-25: all 32 sparq legacy parks deferred with "no starvation cause is
        # observable". Safe, but the hold was permanent while the label claimed otherwise.
        span_secs = model_health_mod.SUSTAINED_HEALTH_SPAN_SECONDS
        readmit_account2 = model_health_mod.account_hash("acct02", readmit_salt)
        aged_park_epoch = readmit_now - 5 * 24 * 3600      # the live sparq shape: days old
        aged_park_stamp = model_health_mod._iso_z(aged_park_epoch)

        def hrec(provider, account, cls, dt, run):
            return model_health_mod.make_record(provider, account, "sol", cls, run,
                                                readmit_now + dt)

        # A fleet that has been demonstrably healthy for a full span and is succeeding NOW.
        healthy_window = (
            # coverage anchor: the window reaches back as far as the health claim does
            [hrec("openai", readmit_account, model_health_mod.SUCCESS, -span_secs - 600, "h0")]
            + [hrec("openai", readmit_account, model_health_mod.SUCCESS, -300 - 600 * k,
                    f"h{k + 1}") for k in range(3)]
            + [hrec("anthropic", readmit_account2, model_health_mod.SUCCESS, -600 - 600 * k,
                    f"j{k}") for k in range(3)])
        aged_timeline = {41: [{"event": "labeled", "label": {"name": MACHINE_PARK_PR_LABEL},
                               "created_at": aged_park_stamp, "actor": {"login": readmit_bot},
                               "performed_via_github_app": None}], 7: []}
        fleet_health_key = f"fleet-health/openai/{readmit_account}/h1"

        # (1) THE LIVENESS FIX, end to end through the production sweep: the aged-out park is
        # re-admitted on the labelled fleet-health heuristic, receipt-first, and the receipt
        # names which gate released it.
        count, posted, cleared = readmit_sweep(healthy_window, timeline=aged_timeline)
        assert count == 1 and cleared == [(41, 7)], (count, cleared)
        assert len(posted) == 1 and fleet_health_key in posted[0][1], posted
        assert worker_pr_mod.AUTO_READMIT_MARKER in posted[0][1], posted
        assert "acct01" not in posted[0][1] and "acct02" not in posted[0][1], posted
        # HONESTY: the receipt must say what it actually knows. Claiming the strong gate's
        # finding here — "the account that was failing when this park landed has since
        # succeeded" — would be false for a park whose own cause aged out.
        assert "not proof that this park's own cause cleared" in posted[0][1], posted[0][1]
        assert "demonstrably CLEARED" not in posted[0][1], posted[0][1]
        print("  ok   aged-out exit: a park whose own cause aged out of the health window is "
              "re-admitted on sustained fleet health, receipt-first")

        # (2) FAIL CLOSED. An unhealthy fleet, an unreadable window and a malformed record all
        # leave the aged-out park exactly where it is. This is the direction the whole design
        # fails in, and a liveness fix that failed open would be a worse trade than the stall.
        unhealthy = healthy_window + [hrec("openai", readmit_account, model_health_mod.CLASS_AUTH,
                                           -1200, "bad1")]
        for name, window in (("a launch failure inside the proven span", unhealthy),
                             ("an unreadable health window", None),
                             ("a malformed health record",
                              healthy_window + [dict(healthy_window[-1],
                                                     exit_class="totally-new")])):
            count, posted, cleared = readmit_sweep(window, timeline=aged_timeline)
            assert (count, posted, cleared) == (0, [], []), (name, count, posted, cleared)
        print("  ok   aged-out exit: an unhealthy fleet, an unreadable window and a malformed "
              "record all DEFER — the aged-out park stands")

        # (3) PRECEDENCE — the heuristic never displaces a proof that can still arrive.
        # (3a) when the park's OWN cause is observable and has recovered, the STRONG gate mints
        # and the key is its shape, not the proxy's.
        strong_park_epoch = readmit_now - span_secs - 1200
        strong_timeline = {41: [{"event": "labeled", "label": {"name": MACHINE_PARK_PR_LABEL},
                                 "created_at": model_health_mod._iso_z(strong_park_epoch),
                                 "actor": {"login": readmit_bot},
                                 "performed_via_github_app": None}], 7: []}
        strong_window = healthy_window + [
            hrec("openai", readmit_account, model_health_mod.CLASS_AUTH, -span_secs - 1400, "x1")]
        count, posted, cleared = readmit_sweep(strong_window, timeline=strong_timeline)
        assert count == 1 and len(posted) == 1, (count, posted)
        # The strong gate's earliest qualifying recovery — the coverage anchor h0, NOT the
        # heuristic's newest-success anchor h1 — and the receipt states the proof it has.
        assert f"evidence=openai/{readmit_account}/h0 " in posted[0][1], posted
        assert "fleet-health" not in posted[0][1], posted
        assert "demonstrably CLEARED" in posted[0][1], posted
        print("  ok   aged-out exit: the STRONG cause-recovery proof is tried first and its "
              "evidence — not the heuristic — is what gets receipted")
        # (3b) THE ORDER IS THE SAFETY PROPERTY. Here the strong exit is REACHABLE but not yet
        # satisfied (the fleet pseudo-account was starved before the park and has recorded no
        # success since), while the fleet-health proxy WOULD fire on this very window. The probe
        # must mint NOTHING. Assert the proxy would have fired, so this cannot pass vacuously.
        fleet_hash = model_health_mod.account_hash("fleet01", readmit_salt)
        reachable_window = healthy_window + [
            hrec("fleet", fleet_hash, model_health_mod.CLASS_ZERO_DISPATCH,
                 -span_secs - 1400, "z1"),
            hrec("fleet", fleet_hash, model_health_mod.CLASS_ZERO_DISPATCH, -1000, "z2")]
        assert model_health_mod.park_cause_provable(
            reachable_window, strong_park_epoch, readmit_now) is True
        assert model_health_mod.capacity_recovery_evidence(
            reachable_window, strong_park_epoch, readmit_now) is None
        assert model_health_mod.sustained_fleet_health_evidence(
            reachable_window, strong_park_epoch, readmit_now) is not None
        count, posted, cleared = readmit_sweep(reachable_window, timeline=strong_timeline)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        print("  ok   aged-out exit: while the STRONG proof is still reachable the park WAITS "
              "for it — the weaker heuristic is refused even though it would have fired")

        # (4) BOUNDED RE-ENTRY. The heuristic is consumed through the same cap as every other
        # automatic re-admission. Assert the BOUND ITSELF, then size the fixture from a literal
        # (a fixture sized from the constant shrinks with it and survives a raised cap).
        assert _park_policy.AUTO_READMISSION_MAX == 2, _park_policy.AUTO_READMISSION_MAX
        two_markers = [{"user": {"login": readmit_bot},
                        "body": f"x {worker_pr_mod.AUTO_READMIT_MARKER} evidence=fleet-health/o/"
                                f"x/{i} at=zzz -->"} for i in range(2)]
        count, posted, cleared = readmit_sweep(healthy_window, timeline=aged_timeline,
                                               comments=two_markers)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        count, posted, cleared = readmit_sweep(healthy_window, timeline=aged_timeline,
                                               comments=two_markers[:1])
        assert count == 1, count
        print("  ok   aged-out exit: exactly AUTO_READMISSION_MAX automatic re-admissions are "
              "available to it — the cap terminates the aged-out path too")
        # ...and the evidence itself is consumed EXACTLY ONCE: the same fleet-health key can
        # never re-earn a re-admission after a NEWER park application.
        # THE RE-PARK MUST BE OLDER THAN THE SPAN. A fresh re-park is refused by the
        # park-younger-than-the-span guard, so the same-key check would never be reached and
        # this test would pass for the wrong reason (MEASURED: it did — deleting the
        # consumed-key check left this line green until the fixture was fixed). The receipt
        # stamp deliberately PREDATES the re-park too, so the idempotent auto-receipt branch
        # does not short-circuit ahead of the check under test.
        reparked_epoch = readmit_now - span_secs - 100
        consumed = [{"user": {"login": readmit_bot},
                     "body": worker_pr_mod.auto_readmission_receipt(
                         fleet_health_key,
                         model_health_mod._iso_z(readmit_now - 2 * span_secs))}]
        reparked = {41: aged_timeline[41] + [
            {"event": "labeled", "label": {"name": MACHINE_PARK_PR_LABEL},
             "created_at": model_health_mod._iso_z(reparked_epoch),
             "actor": {"login": readmit_bot}, "performed_via_github_app": None}], 7: []}
        # Prove the fixture actually reaches the check: the SAME evidence is available again.
        assert (model_health_mod.sustained_fleet_health_evidence(
            healthy_window, reparked_epoch, readmit_now) or {}).get("key") == fleet_health_key
        count, posted, cleared = readmit_sweep(healthy_window, timeline=reparked,
                                               comments=consumed)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        print("  ok   aged-out exit: its evidence is consumed EXACTLY ONCE — the same "
              "fleet-health key cannot re-earn a re-admission after a new park")

        # (4b) BOUNDED RE-ENTRY, THE OTHER PATH (registry #698). The migration cap paces only
        # PRs with NO live machine park; a PR ALREADY on `review:parked` never reaches it, so the
        # re-admission path had no ceiling at all and the herd bound was proven for the wrong
        # population. MEASURED while reviewing #697: 9 live sparq PRs sat in exactly that state,
        # unreachable by the migration, and the aged-out exit mints for all 9 — they would have
        # re-entered the review lane in ONE tick. Assert the BOUND ITSELF, then size the fixture
        # from a LITERAL so lowering the ceiling cannot shrink the fixture with it.
        assert 0 < AUTO_READMISSION_PER_TICK_MAX <= 10, AUTO_READMISSION_PER_TICK_MAX
        herd_rows = [dict(parked_row, number=n,
                          head=dict(parked_row["head"], ref=f"sparq-agent/issue-{n}-abc"))
                     for n in range(60, 60 + AUTO_READMISSION_PER_TICK_MAX + 4)]
        herd_cleared = []
        herd_count = _readmit_capacity_parks(
            "example/repo", [herd_rows], {}, {row["number"]: {"issue": 7} for row in herd_rows},
            readmit_bot, Path("."), worker_pr_mod,
            _capacity_recovery_probe(model_health_mod, healthy_window, readmit_now),
            comments_fn=lambda _repo, _number: [],
            timeline_fn=lambda _repo, number: list(
                aged_timeline[41] if number != 7 else []),
            post_comment=lambda *_a: None,
            clear_labels=lambda pr, issue: herd_cleared.append(pr),
            log=lambda _l: None, migration_provable=False)
        assert herd_count == AUTO_READMISSION_PER_TICK_MAX, (herd_count, herd_cleared)
        assert len(herd_cleared) == AUTO_READMISSION_PER_TICK_MAX, herd_cleared
        # ...and the drain is DETERMINISTIC, not starving: ascending PR order, so the parks this
        # tick deferred are the ones the next tick reaches first.
        assert herd_cleared == sorted(herd_cleared) == [
            row["number"] for row in herd_rows[:AUTO_READMISSION_PER_TICK_MAX]], herd_cleared
        print(f"  ok   aged-out exit: one tick RE-ADMITS at most "
              f"{AUTO_READMISSION_PER_TICK_MAX} parks in ascending order — the re-admission "
              f"path is paced too, not just the migration path")

        # (5) STRICTLY NARROWER THAN THE DENY. A human-owned hold on either surface still
        # refuses, unconditionally, on the aged-out path.
        human_aged = dict(parked_row, labels=[{"name": MACHINE_PARK_PR_LABEL},
                                              {"name": "review:needs-user"}])
        count, posted, cleared = readmit_sweep(healthy_window, rows=[[human_aged]],
                                               timeline=aged_timeline)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        count, posted, cleared = readmit_sweep(healthy_window, timeline=aged_timeline,
                                               labels={7: ["status:parked", "needs:user"]})
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        human_aged_park = {41: [{"event": "labeled",
                                 "label": {"name": MACHINE_PARK_PR_LABEL},
                                 "created_at": aged_park_stamp, "actor": {"login": "jeswr"},
                                 "performed_via_github_app": None}], 7: []}
        count, posted, cleared = readmit_sweep(healthy_window, timeline=human_aged_park)
        assert (count, posted, cleared) == (0, [], []), (count, posted, cleared)
        print("  ok   aged-out exit: a human-owned hold and a MAINTAINER-applied park refuse it "
              "exactly as they refuse the cause-recovery path")

        # ---- the MIGRATION PRECONDITION, as the production function computes it -------------
        # Never hand-set: _legacy_migration_provable is the expression main() evaluates.
        assert _legacy_migration_provable(model_health_mod, healthy_window, readmit_now) is True
        assert _legacy_migration_provable(model_health_mod, None, readmit_now) is False
        # An OBSERVED but SILENT fleet is not a healthy one, and no cause is observable either:
        # neither exit is reachable, so the migration defers exactly as it did before #691.
        stale_window = [hrec("openai", readmit_account, model_health_mod.SUCCESS,
                             -span_secs - 600, "s0")]
        assert _legacy_migration_provable(model_health_mod, stale_window, readmit_now) is False
        # A BROKEN fleet still admits the migration — but via the STRONG exit, not the
        # heuristic: an account failing right now means a park applied now can later prove its
        # own cause recovered. That is the pre-#691 behaviour, unchanged.
        broken_window = healthy_window + [
            hrec("anthropic", readmit_account2, model_health_mod.CLASS_LIMIT, -60, "L1")]
        assert (model_health_mod.park_cause_provable(broken_window, readmit_now, readmit_now),
                model_health_mod.sustained_health_exit_reachable(broken_window, readmit_now),
                _legacy_migration_provable(model_health_mod, broken_window, readmit_now)) \
            == (True, False, True)
        real_provable = _legacy_migration_provable(model_health_mod, healthy_window, readmit_now)
        print("  ok   aged-out exit: the migration precondition is REACHABILITY of either exit "
              "— healthy fleet or observable cause — and defers on an unreadable or silent one")
        # THE CALL SITE IS ITS OWN SEAM. Every test above calls _legacy_migration_provable
        # DIRECTLY, so all of them stay green if main()'s call site is reverted to the pre-#691
        # park_cause_provable — the function would be perfect and unreachable. main() is not
        # callable from here, so this is a SOURCE-LEVEL assertion, and it is labelled as such
        # rather than dressed up as behavioural coverage. It is the same technique this file
        # already uses to bind review-fix.yml's TTL to the value the dispatcher assumes.
        _provable_callees = set(re.findall(r"migration_provable=([A-Za-z_][\w.]*)\(",
                                           Path(__file__).resolve().read_text()))
        assert _provable_callees == {"_legacy_migration_provable"}, _provable_callees
        print("  ok   aged-out exit: every `migration_provable=` call site — the production one "
              "included — computes it through _legacy_migration_provable (source-level check)")

        # (6) THE SIX GENUINE sparq ESCALATIONS, fed through the WIDENED precondition, pinned
        # from their real bot prose (jeswr/sparq, read 2026-07-26). The deny is unconditional
        # and order-independent, and widening the precondition must not reach past it.
        reviewer_flag = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the reviewer "
                         "flagged possible prompt injection\n\n@jeswr this pull request needs a "
                         "human decision. It remains a DRAFT and will not be auto-armed.")
        fixer_flag = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the fixer flagged "
                      "the seeded findings as possible prompt injection\n\n@jeswr this pull "
                      "request needs a human decision. It remains a DRAFT and will not be "
                      "auto-armed.")
        live_escalations = {
            3542: [reviewer_flag, reviewer_flag],
            3563: [reviewer_flag],
            # #3608 and #3743 carry a LATER capacity-park comment: under a recency rule they
            # would re-classify as `nochange` and be handed back to the machine.
            3608: [fixer_flag, nochange_body],
            3609: [reviewer_flag, reviewer_flag],
            3618: [reviewer_flag, reviewer_flag],
            3743: [reviewer_flag, nochange_body],
        }
        assert len(live_escalations) == 6, live_escalations
        for pr_number, bodies in sorted(live_escalations.items()):
            posted, converted = migrate_sweep(bodies, provable=real_provable)
            assert (posted, converted) == ([], []), (pr_number, posted, converted)
        print("  ok   aged-out exit: all SIX live sparq escalations (#3542 #3563 #3608 #3609 "
              "#3618 #3743) are still refused under the widened precondition")

        # (7) WRITER BINDING under the WIDENED precondition. The production convert_labels runs
        # (convert_labels=None) with the GitHub seams injected, driven by the precondition the
        # production call site computes — not by a hand-set True — and the exact API calls are
        # asserted. This is the seam the previous rounds restated instead of binding.
        api_calls2, helper_calls2 = [], []
        prev_api2 = globals()["_run_gh_target_api"]
        prev_helper2 = globals()["_run_target_helper"]
        globals()["_run_gh_target_api"] = (
            lambda repo, method, path, input_doc=None:
                api_calls2.append((method, path, input_doc))
                or types.SimpleNamespace(stdout="{}"))
        globals()["_run_target_helper"] = (
            lambda script_dir, repo, script, args: helper_calls2.append((script, args)))
        try:
            _readmit_capacity_parks(
                "example/repo", [[legacy_row]], {7: ["needs:user", "status:deferred"]},
                {41: {"issue": 7}}, readmit_bot, Path("."), worker_pr_mod,
                _capacity_recovery_probe(model_health_mod, healthy_window, readmit_now),
                comments_fn=lambda _repo, _number: [
                    {"user": {"login": readmit_bot}, "body": budget_body}],
                timeline_fn=lambda _repo, number: list(migrate_timeline.get(number, [])),
                post_comment=lambda *_a: None, clear_labels=lambda *_a: None,
                log=lambda _l: None,
                migration_provable=_legacy_migration_provable(
                    model_health_mod, healthy_window, readmit_now))
        finally:
            globals()["_run_gh_target_api"] = prev_api2
            globals()["_run_target_helper"] = prev_helper2
        assert api_calls2 == [
            ("DELETE", "repos/example/repo/issues/41/labels/review%3Aneeds-user", None),
            ("POST", "repos/example/repo/issues/41/labels",
             {"labels": [MACHINE_PARK_PR_LABEL]}),
            ("DELETE", "repos/example/repo/issues/7/labels/needs%3Auser", None),
        ], api_calls2
        assert helper_calls2 == [("worker-issue.py", [
            "status", "--repo", "example/repo", "--issue", "7", "--status", "parked"])], \
            helper_calls2
        print("  ok   aged-out exit WRITER: the PRODUCTION convert_labels runs off the "
              "PRODUCTION precondition on a healthy fleet — asserted on the real API calls")

        # (8) THE WHOLE CHAIN. A legacy park that could not migrate before #691 (the fleet is
        # healthy, so no starvation cause is observable) migrates now, and the park it becomes
        # is ACTUALLY RELEASED one span later by the production probe. Fixing one layer above
        # where the invariant binds is how the previous rounds failed; this composes both.
        assert model_health_mod.park_cause_provable(
            healthy_window, readmit_now, readmit_now) is False, \
            "the pre-#691 precondition must be the one that blocked this park"
        chain_pr_labels = {"review:needs-user"}
        chain_issue_labels = {"status:deferred", "needs:user", "role:impl"}

        def chain_convert(pr, issue):
            chain_pr_labels.discard(_park_policy.HUMAN_PR_PARK_LABEL)
            chain_pr_labels.add(MACHINE_PARK_PR_LABEL)
            for hold in _park_policy.human_owned_holds(chain_issue_labels):
                chain_issue_labels.discard(hold)
            chain_issue_labels.add("status:parked")

        chain_migrated = _readmit_capacity_parks(
            "example/repo", [[dict(parked_row,
                                   labels=[{"name": n} for n in sorted(chain_pr_labels)])]],
            {7: sorted(chain_issue_labels)}, {41: {"issue": 7}}, readmit_bot, Path("."),
            worker_pr_mod,
            _capacity_recovery_probe(model_health_mod, healthy_window, readmit_now),
            comments_fn=lambda _repo, _number: [
                {"user": {"login": readmit_bot}, "body": budget_body}],
            timeline_fn=lambda _repo, number: list(migrate_timeline.get(number, [])),
            post_comment=lambda *_a: None, clear_labels=lambda *_a: None, log=lambda _l: None,
            migration_provable=_legacy_migration_provable(
                model_health_mod, healthy_window, readmit_now),
            convert_labels=chain_convert)
        assert chain_migrated == 0, "the migration must not re-admit in the same breath"
        assert chain_pr_labels == {MACHINE_PARK_PR_LABEL}, chain_pr_labels
        assert "needs:user" not in chain_issue_labels, chain_issue_labels
        # One span later, with the same health continuing, the park it became is released.
        later_now = readmit_now + span_secs
        continued_window = healthy_window + [
            hrec("openai", readmit_account, model_health_mod.SUCCESS,
                 span_secs - 300 - 600 * k, f"c{k}") for k in range(3)] + [
            hrec("anthropic", readmit_account2, model_health_mod.SUCCESS,
                 span_secs - 600 - 600 * k, f"e{k}") for k in range(3)]
        chain_timeline = {41: [{"event": "labeled",
                                "label": {"name": MACHINE_PARK_PR_LABEL},
                                "created_at": model_health_mod._iso_z(readmit_now),
                                "actor": {"login": readmit_bot},
                                "performed_via_github_app": None}], 7: []}
        chain_cleared = []
        chain_readmitted = _readmit_capacity_parks(
            "example/repo", [[dict(parked_row,
                                   labels=[{"name": n} for n in sorted(chain_pr_labels)])]],
            {7: sorted(chain_issue_labels)}, {41: {"issue": 7}}, readmit_bot, Path("."),
            worker_pr_mod,
            _capacity_recovery_probe(model_health_mod, continued_window, later_now),
            comments_fn=lambda _repo, _number: [],
            timeline_fn=lambda _repo, number: list(chain_timeline.get(number, [])),
            post_comment=lambda *_a: None,
            clear_labels=lambda pr, issue: chain_cleared.append((pr, issue)),
            log=lambda _l: None, migration_provable=False)
        assert chain_readmitted == 1, (chain_readmitted, sorted(chain_issue_labels))
        assert chain_cleared == [(41, 7)], chain_cleared
        print("  ok   aged-out exit CHAIN: a legacy park that could not migrate before #691 "
              "migrates AND is actually released one span later (both layers, end to end)")
    finally:
        globals()["_target_is_human_maintainer"] = prev_target_probe

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
        "opus5": {"provider": "anthropic", "harness": "claude"},
        "fable": {"provider": "anthropic", "harness": "claude"},
        "mystery": {"harness": "codex"},                 # no provider field
        "typo": {"provider": "openia", "harness": "codex"},  # misspelled provider
    }}
    assert _chain_probe_exempt(["sol", "luna"], prov_routing) is True
    assert _chain_probe_exempt(["opus", "fable"], prov_routing) is False   # anthropic gated
    assert _chain_probe_exempt(["opus5", "opus"], prov_routing) is False   # opus5 gated too
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

    # [OPUS-5] registry #738 — `role:impl` IS NOW ONE OF THOSE ROUTES, and the composition is what
    # matters, not the predicate in isolation. Removing sol left a single-rung `["opus5"]` impl
    # chain; without `escalate = true` an opus5 capacity outage could only defer, and defer again,
    # forever, with nobody notified. So the LIVE routing table's `role:impl` route is resolved here
    # and its own `escalate` value is fed into the starvation ladder.
    #
    # MUTANT: delete `escalate = true` from the role:impl route in orchestration/routing.toml, or
    # from a target's, => the first assertion goes red. MUTANT: make `escalate_starved` require a
    # multi-rung chain => the second goes red.
    _impl_route = _POLICY_FOR_IMPL = None
    for _r in tomllib.loads(
            (Path(__file__).resolve().parents[1] / "orchestration" / "routing.toml")
            .read_text(encoding="utf-8")).get("route", []):
        if _r.get("role") == "impl" and "match_labels" not in _r:
            _impl_route = _r
            break
    assert _impl_route is not None, "the live routing table declares no role:impl route"
    assert _impl_route["model_chain"] == ["opus5"], _impl_route
    assert _impl_route.get("escalate") is True, (
        "role:impl is a SINGLE-RUNG chain: without escalate = true, an opus5 capacity outage is a "
        "silent permanent stall with no counted reason and no ops alert")
    # A starved single-rung impl route IS detected as starved (so the defer is attributable) ...
    assert escalate_starved(_impl_route.get("escalate"), {"acct01": {}}, 0) is True
    # ... and the FIRST such tick is TRANSIENT: no park, no human terminal, keep retrying. This is
    # the "defer must terminate and be attributable, not park" obligation, asserted rather than
    # assumed.
    assert escalate_persist_decision([], "app[bot]", int(time.time()),
                                     "<!-- sparq-worker-attempt:v1") == (False, "")
    # ... and the counted reasons are DISTINGUISHABLE from the generic capacity defer, so a starved
    # impl frontier cannot hide inside `no-eligible-account`.
    assert len({"escalate-tier-starved-transient", "escalate-tier-starved",
                "no-eligible-account"}) == 3
    _dispatch_src = Path(__file__).resolve().read_text(encoding="utf-8")
    for _reason in ("escalate-tier-starved-transient", "escalate-tier-starved"):
        assert f'defer_reasons["{_reason}"]' in _dispatch_src, _reason
    print("  ok   #738: role:impl is single-rung AND escalating; starvation defers transiently with "
          "its own counted reason before any park")

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
    # (ix) Round-5 finding 2: receipt ordering is by PARSED instant, never raw string. A
    # space-separator stamp sorts lexicographically before every 'T'-form stamp of the same
    # day, so the old string compare (a) read a 60-second-old space-form alert as already past
    # the grace threshold — escalating one snapshot straight to a park — and (b) read a fresh
    # space-form alert posted AFTER a 'T'-form reset as pre-reset, suppressing the recovery
    # receipt.
    space116 = lambda ago: {  # noqa: E731 — space-separator spelling of iso116
        "user": {"login": "app[bot]"}, "body": f"ops alert {STARVE_ALERT_MARKER}",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(now116 - ago))}
    assert escalate_persist_decision([space116(60)], "app[bot]", now116, attempt) \
        == (False, time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(now116 - 60)))
    assert escalate_persist_decision([reset(300), space116(60)], "app[bot]", now116, attempt) \
        == (False, time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(now116 - 60)))
    assert escalate_recovery_pending([reset(300), space116(60)], "app[bot]", attempt) is True
    # a genuinely persistent space-form streak still escalates (instants, not spellings).
    assert escalate_persist_decision(
        [space116(ESCALATE_PERSIST_SECONDS + 120)], "app[bot]", now116, attempt) \
        == (True, time.strftime("%Y-%m-%d %H:%M:%SZ",
                                time.gmtime(now116 - ESCALATE_PERSIST_SECONDS - 120)))
    # (x) an unparseable receipt stamp FREEZES the starvation ladder loudly: no escalation, no
    # recovery receipt, on unprovable time.
    bad_clock = [{"user": {"login": "app[bot]"}, "body": f"x {STARVE_RESET_MARKER}",
                  "created_at": "not-a-timestamp"},
                 starve(ESCALATE_PERSIST_SECONDS + 120)]
    freeze_logs = []
    assert escalate_persist_decision(bad_clock, "app[bot]", now116, attempt,
                                     log=freeze_logs.append) == (False, "")
    assert any("clock unreadable" in line and "freezing" in line for line in freeze_logs)
    freeze_logs = []
    assert escalate_recovery_pending(bad_clock, "app[bot]", attempt,
                                     log=freeze_logs.append) is False
    assert any("clock unreadable" in line and "freezing" in line for line in freeze_logs)

    _starvation_sweep_self_test()

    print("dispatch-claim self-test PASSED")


# ---- [registry #677] THE STARVED-PLAN MACHINE EXIT ------------------------------------
# Every guard below has a NAMED test that goes RED when the guard is deleted or inverted. The
# discriminating fixtures are the ones where the sweep must do NOTHING: a healthy plan, an empty
# backlog, an already-parked holder, an ACTIVE holder whose park would free nothing, and a holder
# that reserves real crates instead of the serializing partition. A sweep that fires on those is
# strictly worse than the hand-parking it replaces, because it costs review progress and buys no
# throughput.
_STARVE_SHA = "c" * 40


def _starvation_row(number, *, packages, parked=False, inactive=True, decision="busy"):
    """One occupancy row in the exact 5-tuple shape busy_packages_of_pulls appends."""
    return (decision, number, frozenset(packages),
            "detail" if parked else "not-parked", inactive)


def _starvation_sweep_self_test():
    item = {"number": 900, "package": "crate-a", "deferred": False}
    holder = _starvation_row(41, packages={GLOBAL_PACKAGE})

    # ---- TRIGGER: fires only on the measured starvation --------------------------------------
    logs = []
    assert starvation_park_target([], 12, [holder], log=logs.append) == 41
    assert any("planned 0 item(s)" in line and "parking pr#41" in line for line in logs), logs
    print("  ok   #677 starvation sweep: a starved lane behind an inert __global__ holder "
          "selects exactly that holder")

    # A HEALTHY plan is the guard the brief calls out by name: over-parking costs real review
    # progress, so ANY planned item must stand the sweep down. Deleting the `if planned_items`
    # clause reds HERE.
    assert starvation_park_target([item], 12, [holder]) is None
    assert starvation_park_target([item], 0, [holder]) is None
    print("  ok   #677 starvation sweep: NEVER fires while the plan is healthy (>=1 planned item)")

    # An EMPTY backlog is not starvation. Deleting the `deferred <= 0` clause reds HERE — and
    # this is the case that would otherwise park a holder for no throughput at all.
    assert starvation_park_target([], 0, [holder]) is None
    assert starvation_park_target([], -1, [holder]) is None
    assert starvation_park_target([], True, [holder]) is None      # bool is not a count
    assert starvation_park_target([], "12", [holder]) is None      # unreadable count
    print("  ok   #677 starvation sweep: an EMPTY backlog (0 deferred rows) parks nobody")

    # ---- CANDIDATE SELECTION: each declining clause, one at a time ----------------------------
    # already parked -> idempotence. Re-running the sweep against its own output selects nobody.
    assert starvation_park_target(
        [], 12, [_starvation_row(41, packages={GLOBAL_PACKAGE}, parked=True)]) is None
    # parked AND inert -> busy_packages_of_pulls already freed it (decision `parked-free`)
    assert starvation_park_target(
        [], 12, [_starvation_row(41, packages={GLOBAL_PACKAGE}, parked=True,
                                 decision="parked-free")]) is None
    # ...and the decision filter is checked INDEPENDENTLY of the reason slot. Today a
    # `parked-free` row always carries a park reason, so the two guards overlap and deleting
    # either alone still declines. This fixture is the row that separates them: a NON-`busy`
    # decision whose reason slot reads "not-parked". It cannot arise from the current
    # busy_packages_of_pulls, and that is exactly why it is here — a new decision kind added
    # later must not silently become a park candidate.
    assert starvation_park_target(
        [], 12, [("parked-free", 41, frozenset({GLOBAL_PACKAGE}), "not-parked", True)]) is None
    assert starvation_park_target(
        [], 12, [("some-future-decision", 41, frozenset({GLOBAL_PACKAGE}),
                  "not-parked", True)]) is None
    print("  ok   #677 starvation sweep: an ALREADY-PARKED holder is never re-parked "
          "(idempotent), and only a `busy` decision is ever a candidate")

    # ACTIVE holder -> parking it would write a label and free NOTHING (busy_packages_of_pulls
    # frees only `parked AND inactive`). Deleting the `inactive is not True` clause reds HERE.
    assert starvation_park_target(
        [], 12, [_starvation_row(41, packages={GLOBAL_PACKAGE}, inactive=False)]) is None
    assert starvation_park_target(
        [], 12, [_starvation_row(41, packages={GLOBAL_PACKAGE}, inactive=None)]) is None
    print("  ok   #677 starvation sweep: an ACTIVE holder — whose park would free NOTHING — "
          "is never parked")

    # a holder of REAL crates is not a __global__ holder: parking it does not unstarve the lane.
    assert starvation_park_target(
        [], 12, [_starvation_row(41, packages={"crate-a", "crate-b"})]) is None
    # a malformed occupancy row is not evidence to act on
    assert starvation_park_target([], 12, [("busy", 41, frozenset({GLOBAL_PACKAGE}))]) is None
    assert starvation_park_target([], 12, ["junk"]) is None
    assert starvation_park_target([], 12, None) is None
    assert starvation_park_target(
        [], 12, [_starvation_row(0, packages={GLOBAL_PACKAGE})]) is None
    print("  ok   #677 starvation sweep: crate-only holders and malformed occupancy rows are "
          "not candidates")

    # ---- BOUND: at most ONE per tick, deterministically -------------------------------------
    many = [_starvation_row(n, packages={GLOBAL_PACKAGE}) for n in (77, 41, 63)]
    assert STARVATION_PARKS_PER_TICK_MAX == 1
    assert starvation_park_target([], 12, many) == 41
    assert starvation_park_target([], 12, list(reversed(many))) == 41
    print("  ok   #677 starvation sweep: THREE eligible holders yield exactly ONE target, the "
          "lowest-numbered, order-independently")

    # ---- THE WRITE: the exact mutation set, and what it must never contain --------------------
    def run_park(labels, *, vetoed=None):
        calls, comments, logs = [], [], []
        applied = park_starved_partition_holder(
            "o/r", 41, 12, labels,
            park_pr=lambda number: calls.append(("label", number)),
            post_comment=lambda repo, number, body: comments.append((repo, number, body)),
            vetoed=vetoed, log=logs.append)
        return applied, calls, comments, logs

    applied, calls, comments, _ = run_park(["review:needs"])
    assert applied is True
    assert calls == [("label", 41)], calls
    assert [(repo, number) for repo, number, _ in comments] == [("o/r", 41)], comments
    body = comments[0][2]
    # THE non-negotiable: this is a capacity action, and registry #703 documents how parks become
    # a conveyor into the terminal human hold. Inverting the label constant reds HERE.
    assert MACHINE_PARK_PR_LABEL in body
    for terminal in (_park_policy.HUMAN_PARK_LABEL, _park_policy.HUMAN_PR_PARK_LABEL,
                     _park_policy.MACHINE_PARK_LABEL):
        assert terminal not in str(calls), (terminal, calls)
    assert f"**not** `{_park_policy.HUMAN_PARK_LABEL}`" in body, body
    assert _park_policy.park_reason_marker("partition") in body
    assert _park_policy.park_cause_class("partition") == _park_policy.PARK_CLASS_CAPACITY
    assert "not a review judgement" in body and "un-park" in body
    # The comment is the ONLY thing a human or another agent reads to understand why a label
    # appeared, so its framing is a guard too (registry #703: an unexplained park is the failure
    # mode). It must self-identify as an agent, it must open by saying it is parking to unblock
    # the fleet, and it must never open by announcing a human hold.
    assert body.startswith("> 🤖 **SPARQ agent** — parking this PR to unblock the fleet."), \
        body.splitlines()[0]
    assert _park_policy.HUMAN_PARK_LABEL not in body.splitlines()[0], body.splitlines()[0]
    print("  ok   #677 starvation park: writes review:parked + ONE receipt and NOTHING else — "
          "never needs:user, review:needs-user or status:parked")

    # RECEIPT-FIRST: a crash between the two leaves an explained PR with no label, never a
    # mysterious label with no explanation.
    order = []

    def exploding_label(number):
        order.append("label")
        raise DispatchError("label write failed")

    try:
        park_starved_partition_holder(
            "o/r", 41, 12, ["review:needs"], park_pr=exploding_label,
            post_comment=lambda repo, number, b: order.append("comment"), log=lambda _m: None)
    except DispatchError:
        pass
    assert order == ["comment", "label"], order
    print("  ok   #677 starvation park: RECEIPT-FIRST — the comment lands before the label")

    # ---- THE REFUSALS on the write path ------------------------------------------------------
    applied, calls, comments, logs = run_park(["review:needs", MACHINE_PARK_PR_LABEL])
    assert (applied, calls, comments) == (False, [], [])
    assert any("already carries" in line for line in logs), logs
    for hold in (_park_policy.HUMAN_PARK_LABEL, _park_policy.HUMAN_PR_PARK_LABEL):
        applied, calls, comments, logs = run_park(["review:needs", hold])
        assert (applied, calls, comments) == (False, [], []), hold
        assert any("human-owned hold" in line for line in logs), logs
    applied, calls, comments, logs = run_park(["review:needs"], vetoed=lambda number: True)
    assert (applied, calls, comments) == (False, [], [])
    assert any("un-parked this PR" in line for line in logs), logs
    print("  ok   #677 starvation park: refuses an already-parked PR, a human-owned hold, and a "
          "sticky human unpark veto — writing nothing in each case")

    # ---- THE MEASUREMENT filter_busy_area_items hands the plan --------------------------------
    def busy_pull(number, ref, labels):
        return {"number": number, "state": "open", "draft": False, "auto_merge": None,
                "labels": [{"name": name} for name in labels],
                "head": {"ref": ref, "sha": _STARVE_SHA, "repo": {"full_name": "o/r"}}}

    prov = {41: {"pr_number": 41, "issue": 7, "impl_provider": "anthropic",
                 "impl_alias": "sol", "impl_account_h": "0" * 16,
                 "head_sha_at_open": _STARVE_SHA,
                 # MACHINE-ATTESTED stamp (registry #657/#732): admission requires a
                 # `recorded_at_run` naming the host-side run that wrote the record.
                 "recorded_at_run": "29694084610.1"}}
    # THIS assert is what fails loudly if the stamp is ever dropped — measured: it fires before
    # anything else, so the counterfactual below is NOT what catches a dropped stamp. It is kept
    # only because it pins the exact refusal CONSTANT (an unstamped record must be refused under
    # ATTESTATION_UNRECOGNISED_REASON specifically, not merged into some other reason), which the
    # assert above cannot see. An earlier version of this file claimed the counterfactual was the
    # thing that made a dropped stamp fail loudly; that claim was wrong and is retracted.
    assert provenance_admission_error(prov[41], 41) is None, \
        provenance_admission_error(prov[41], 41)
    _unstamped = {key: value for key, value in prov[41].items() if key != "recorded_at_run"}
    assert provenance_admission_error(_unstamped, 41) == ATTESTATION_UNRECOGNISED_REASON, \
        provenance_admission_error(_unstamped, 41)
    rows = [{"number": 900, "package": "crate-a", "deferred": False},
            {"number": 901, "package": "crate-b", "deferred": False}]
    starvation = {}
    with contextlib.redirect_stdout(io.StringIO()):
        # a holder with unreadable linkage reserves __global__ -> both rows deferred by IT
        kept = filter_busy_area_items(
            rows, "o/r", [busy_pull(41, "sparq-agent/issue-7-1-1", ["review:needs"])],
            {}, {}, leases=[], now=0, starvation=starvation)
    assert kept == [] and starvation == {"deferred": 2, "kept": 0}, starvation
    # ... and with the SAME holder carrying a real crate label plus a readable source issue, the
    # partition is NOT global, so nothing it defers is starvation evidence.
    narrow = {}
    with contextlib.redirect_stdout(io.StringIO()):
        kept = filter_busy_area_items(
            rows, "o/r", [busy_pull(41, "sparq-agent/issue-7-1-1",
                                    ["review:needs", "area:crate-a"])],
            {7: ["area:crate-a"]}, prov, leases=[], now=0, starvation=narrow)
    assert [row["number"] for row in kept] == [901], kept
    assert narrow == {"deferred": 0, "kept": 1}, narrow
    print("  ok   #677 starvation evidence: only drops caused by a __global__ OCCUPANT count; a "
          "crate-scoped occupant records ZERO deferred")

    # ---- END TO END: the inactive bit must come from the REAL decision -----------------------
    # Every selection test above feeds occupancy rows directly, so all of them stay green if
    # busy_packages_of_pulls hard-codes the 5th element to True — and that mutant is severe: it
    # makes EVERY busy holder read as inert, so the sweep would park a live non-draft PR and free
    # nothing. This runs the production producer and the production consumer against each other.
    def occupancy_of(row, status=None, labels=None, provenance=None):
        rows = []
        busy_packages_of_pulls("o/r", [row], labels or {}, provenance or {}, status,
                               occupancy=rows)
        return rows

    inert_draft = {"number": 41, "state": "open", "draft": True, "auto_merge": None,
                   "labels": [], "head": {"ref": "sparq-agent/issue-7-1-1", "sha": _STARVE_SHA,
                                          "repo": {"full_name": "o/r"}}}
    active_ready = dict(inert_draft, draft=False)
    latched_draft = dict(inert_draft, auto_merge={"enabled_by": {"login": "x"}})
    for row, want_inactive, want_target in ((inert_draft, True, 41),
                                            (active_ready, False, None),
                                            (latched_draft, False, None)):
        produced = occupancy_of(row)
        assert len(produced) == 1 and produced[0][0] == "busy", produced
        # the bit the sweep reads IS _pull_inactivity_decision's own answer, not a constant
        assert produced[0][4] is _pull_inactivity_decision(row)[0] is want_inactive, produced
        assert starvation_park_target([], 12, produced) == want_target, (row, produced)
    print("  ok   #677 starvation end-to-end: the inertness bit is PRODUCED by "
          "busy_packages_of_pulls — a live non-draft or latched holder is never selected")

    # ---- THE `parked-free` ROW IS THE UN-PARK HALF'S SOLE INPUT -------------------------------
    # A parked, provably-inert PR leaves busy_packages_of_pulls through the `parked-free` branch,
    # and that row is the ONLY thing the un-park half ever reads. Dropping its 5th element (or
    # letting the branch stop emitting a row at all) does not make anything reserve the wrong
    # crate — it silently DISABLES the machine exit, which is a mutant that reds nothing unless a
    # test walks the whole path. Both halves are asserted against the real producer here.
    parked_inert = dict(inert_draft, labels=[{"name": MACHINE_PARK_PR_LABEL}])
    parked_rows = occupancy_of(parked_inert)
    assert len(parked_rows) == 1, parked_rows
    assert parked_rows[0][0] == "parked-free", parked_rows
    assert len(parked_rows[0]) == 5, (
        "the parked-free occupancy row must carry the 5-element shape — it is the SOLE producer "
        "of starvation_unpark_targets' input, so a 4-tuple silently disables the un-park half")
    assert parked_rows[0][4] is _pull_inactivity_decision(parked_inert)[0] is True, parked_rows
    # its area set is the one the un-park decision reads, and it must be the REAL reservation:
    # unreadable linkage here means the PR still holds __global__, so the park must STAND...
    assert GLOBAL_PACKAGE in parked_rows[0][2], parked_rows
    assert starvation_unpark_targets(parked_rows, {41}) == []
    # ...and with linkage that resolves to a real crate, the SAME producer yields the release.
    resolved_rows = occupancy_of(
        dict(parked_inert, head={"ref": "sparq-agent/issue-7-1-1", "sha": _STARVE_SHA,
                                 "repo": {"full_name": "o/r"}}),
        labels={7: ["area:crate-a"]}, provenance=prov)
    assert resolved_rows[0][0] == "parked-free" and len(resolved_rows[0]) == 5, resolved_rows
    assert resolved_rows[0][2] == frozenset({"crate-a"}), resolved_rows
    assert starvation_unpark_targets(resolved_rows, {41}) == [41]
    print("  ok   #677 parked-free arity: the un-park half's SOLE input row is produced with the "
          "5-element shape and the REAL area set — park stands on __global__, releases on a crate")

    # ---- THE PLAN SEAM: v5 validation of the evidence field -----------------------------------
    base_plan = {
        "schema": SCHEMA, "generated_at": "2026-07-26T00:00:00Z",
        "repositories": [{"target_repo": "o/r", "target_sha": "a" * 40, "items": []}],
        "review_items": [], "disarm_items": [], "snapshot_skips": [],
        "partition_starvation": [{"repo": "o/r", "deferred": 4}],
    }
    assert validate_plan(json.loads(json.dumps(base_plan))) is not None
    for mutate, why in (
        (lambda d: d.pop("partition_starvation"), "field deleted"),
        (lambda d: d.update(partition_starvation={}), "not a list"),
        (lambda d: d.update(partition_starvation=[{"repo": "o/r"}]), "missing deferred"),
        (lambda d: d.update(partition_starvation=[{"repo": "o/r", "deferred": 0}]), "zero"),
        (lambda d: d.update(partition_starvation=[{"repo": "o/r", "deferred": True}]), "bool"),
        (lambda d: d.update(partition_starvation=[{"repo": "o/r", "deferred": "4"}]), "string"),
        (lambda d: d.update(partition_starvation=[{"repo": "x/y", "deferred": 4}]), "unplanned"),
        (lambda d: d.update(partition_starvation=[{"repo": "o/r", "deferred": 4},
                                                  {"repo": "o/r", "deferred": 5}]), "duplicate"),
        (lambda d: d.update(schema="registry-dispatch-plan/v4"), "the v4 schema is refused"),
    ):
        candidate = json.loads(json.dumps(base_plan))
        mutate(candidate)
        try:
            validate_plan(candidate)
        except DispatchError:
            continue
        raise AssertionError(f"validate_plan accepted a v5 plan it must reject: {why}")
    # the ONE production sort, so the workflow never sorts inline
    unsorted = json.loads(json.dumps(base_plan))
    unsorted["repositories"].append(
        {"target_repo": "a/b", "target_sha": "b" * 40, "items": []})
    unsorted["partition_starvation"] = [{"repo": "o/r", "deferred": 4},
                                        {"repo": "a/b", "deferred": 2}]
    assert [entry["repo"] for entry in
            normalize_plan_order(unsorted)["partition_starvation"]] == ["a/b", "o/r"]
    assert validate_plan(unsorted) is not None
    print("  ok   #677 plan seam: v5 validates partition_starvation strictly and refuses v4")

    # ---- THE UN-PARK HALF: the machine exit for the machine's own park -----------------------
    bot = "sparq-orchestrator[bot]"
    _minute = 0

    def _stamp():
        # distinct, ASCENDING stamps so ordering is by PARSED INSTANT and the fixtures cannot
        # accidentally depend on list position
        nonlocal _minute
        _minute += 1
        return f"2026-07-26T00:{_minute:02d}:00Z"

    def receipt(cause, login=bot, at=None):
        return {"user": {"login": login},
                "body": f"> park\n\n{_park_policy.park_reason_marker(cause)}",
                "created_at": at or _stamp()}

    def ladder_receipt(login=bot, at=None):
        # EXACTLY what worker-pr.needs_user(park_class="capacity") writes on the `park` action:
        # a generation receipt and NO park-reason receipt. This is the production body shape the
        # first version of this sweep was blind to.
        return {"user": {"login": login},
                "body": ("> 🤖 SPARQ agent — the autonomous review loop parked this PR: the "
                         "review round budget is exhausted at 3 round(s)\n\n"
                         f"{PARK_GENERATION_MARKER_PREFIX} gen=1 cutoff=none -->"),
                "created_at": at or _stamp()}

    def release_receipt(login=bot, at=None):
        return {"user": {"login": login}, "body": starvation_unpark_body(frozenset({"crate-a"})),
                "created_at": at or _stamp()}

    parked_labels = ["review:changes", MACHINE_PARK_PR_LABEL]
    ours = [receipt(STARVATION_PARK_CAUSE)]
    # OWNERSHIP: only this sweep's own park, proven five ways.
    assert starvation_park_owner(ours, parked_labels, bot, True) is True
    assert starvation_park_owner(ours, ["review:changes"], bot, True) is False   # not parked
    assert starvation_park_owner(ours, parked_labels, bot, False) is False       # human-applied
    assert starvation_park_owner([], parked_labels, bot, True) is False          # no receipt
    assert starvation_park_owner(ours, parked_labels, "", True) is False         # untrusted
    assert starvation_park_owner(
        [receipt(STARVATION_PARK_CAUSE, login="drive-by")], parked_labels, bot, True) is False
    # a LATER park by another mechanism THAT STATES ITS CAUSE takes ownership away (control case)
    assert starvation_park_owner(
        [receipt(STARVATION_PARK_CAUSE), receipt("budget")], parked_labels, bot, True) is False
    assert starvation_park_owner(
        [receipt("budget"), receipt(STARVATION_PARK_CAUSE)], parked_labels, bot, True) is True
    print("  ok   #677 un-park ownership: releases ONLY a park whose newest bot receipt names "
          "this sweep's cause AND whose label was machine-applied")

    # ---- THE FAILURE DIRECTION THE FIRST VERSION GOT WRONG -----------------------------------
    # The control case above (a later park that DOES state a cause) was the only thing modelled,
    # so it was green for the wrong reason on the one guard whose failure direction matters most.
    # worker-pr's capacity ladder writes review:parked with a GENERATION receipt and NO reason
    # receipt, so a stale `cause=partition` receipt stayed newest forever.
    #
    # (a) the reported sequence, end to end: park here -> release here -> the LADDER re-parks.
    resurrection = [receipt(STARVATION_PARK_CAUSE), release_receipt(), ladder_receipt()]
    assert starvation_park_owner(resurrection, parked_labels, bot, True) is False, \
        "a stale partition receipt must not authorise releasing a LADDER park"
    assert starvation_unpark_targets(
        [_starvation_row(41, packages={"crate-a"}, parked=True, decision="parked-free")],
        {41} if starvation_park_owner(resurrection, parked_labels, bot, True) else set()) == []
    # (b) the release marker alone closes the episode — even with no later park at all, a receipt
    #     that has ALREADY been acted on can never authorise a second un-park.
    assert starvation_park_owner(
        [receipt(STARVATION_PARK_CAUSE), release_receipt()], parked_labels, bot, True) is False
    # (c) a LADDER park layered on top of a LIVE starvation park (no release in between): the PR
    #     is the ladder's now, and releasing it would strand it un-parked AND un-parkable.
    assert starvation_park_owner(
        [receipt(STARVATION_PARK_CAUSE), ladder_receipt()], parked_labels, bot, True) is False
    # (d) ...and the ladder receipt only takes ownership when it is AT OR AFTER ours: a ladder
    #     park from an EARLIER episode, followed by our own park, is still ours.
    assert starvation_park_owner(
        [ladder_receipt(), receipt(STARVATION_PARK_CAUSE)], parked_labels, bot, True) is True
    # (e) a TIE counts as NEWER — the ambiguous case fails toward leaving the park alone.
    tied = "2026-07-26T12:00:00Z"
    assert starvation_park_owner(
        [receipt(STARVATION_PARK_CAUSE, at=tied), ladder_receipt(at=tied)],
        parked_labels, bot, True) is False
    # (f) only the BOT's markers close an episode; a third party cannot re-open one either
    assert starvation_park_owner(
        [receipt(STARVATION_PARK_CAUSE), ladder_receipt(login="drive-by")],
        parked_labels, bot, True) is True
    # (g) an UNREADABLE bot comment stamp is no episode boundary at all -> refuse, loudly
    _stamp_logs = []
    assert starvation_park_owner(
        [receipt(STARVATION_PARK_CAUSE), {"user": {"login": bot}, "body": "x",
                                          "created_at": "not-a-timestamp"}],
        parked_labels, bot, True, log=_stamp_logs.append) is False
    assert any("unreadable stamp" in line for line in _stamp_logs), _stamp_logs
    # (h) ORDER IS BY PARSED INSTANT, never by list position. Two reason receipts delivered out
    #     of chronological order: the CHRONOLOGICALLY newest (budget) must win, so the park is
    #     not ours. Reading them in list order would take `partition` as newest and release a
    #     budget park. This is the fixture that discriminates the sort — every other fixture
    #     here is already in ascending order, so the sort is a no-op for them.
    assert starvation_park_owner(
        [receipt("budget", at="2026-07-26T09:00:00Z"),
         receipt(STARVATION_PARK_CAUSE, at="2026-07-26T08:00:00Z")],
        parked_labels, bot, True) is False, \
        "the newest reason receipt must be chosen by PARSED INSTANT, not by list position"
    # ...and the same pair in the other list order agrees, which is the point of ordering at all
    assert starvation_park_owner(
        [receipt(STARVATION_PARK_CAUSE, at="2026-07-26T08:00:00Z"),
         receipt("budget", at="2026-07-26T09:00:00Z")],
        parked_labels, bot, True) is False
    # the literal is a READ of worker-pr's own marker — pin it so the two cannot drift
    _wp = _load_module("registry_worker_pr_pin",
                       Path(__file__).resolve().parent / "worker-pr.py")
    assert PARK_GENERATION_MARKER_PREFIX == _wp.PARK_GENERATION_MARKER, (
        PARK_GENERATION_MARKER_PREFIX, _wp.PARK_GENERATION_MARKER)
    assert PARK_GENERATION_MARKER_PREFIX in ladder_receipt()["body"]
    # This fixture models the PRE-#677 ladder body, which is what is on live PRs right now: a
    # generation receipt and NO park-reason receipt. worker-pr now emits a reason receipt on that
    # path too, so clause 3 alone would catch a FUTURE ladder park — but every capacity park
    # already on record predates that, so clause 5 is what covers the existing population and it
    # stays load-bearing until those PRs age out.
    assert _park_policy.parse_park_reason(ladder_receipt()["body"]) is None, \
        "this fixture must model the pre-#677 cause-less ladder body — that shape is the whole " \
        "reason clause 5 exists"
    # ...and the CURRENT worker-pr body does state a cause, which clause 3 catches on its own.
    _wp_cause = _park_policy.park_reason_marker("budget", generation=1)
    assert starvation_park_owner(
        [receipt(STARVATION_PARK_CAUSE),
         {"user": {"login": bot}, "body": f"parked\n\n{_wp_cause}",
          "created_at": _stamp()}], parked_labels, bot, True) is False
    print("  ok   #677 un-park EPISODE binding: a stale partition receipt cannot release a "
          "capacity-ladder park (re-park after release, park layered on top, ties, and an "
          "unreadable stamp all refuse)")

    # CAUSE RE-DERIVATION, never a timer.
    cleared = _starvation_row(41, packages={"crate-a"}, parked=True, decision="parked-free")
    still_global = _starvation_row(41, packages={GLOBAL_PACKAGE}, parked=True,
                                   decision="parked-free")
    assert starvation_unpark_targets([cleared], {41}) == [41]
    assert starvation_unpark_targets([still_global], {41}) == []
    assert starvation_unpark_targets(
        [_starvation_row(41, packages={GLOBAL_PACKAGE, "crate-a"}, parked=True)], {41}) == []
    assert starvation_unpark_targets([cleared], set()) == []          # not ours to release
    assert starvation_unpark_targets([cleared], {99}) == []
    assert starvation_unpark_targets(None, {41}) == []
    print("  ok   #677 un-park cause: a park is released ONLY when its re-derived area set no "
          "longer contains __global__ — a still-holding PR stays parked")

    # BOUNDED + deterministic.
    many_parked = [_starvation_row(n, packages={"crate-a"}, parked=True, decision="parked-free")
                   for n in (90, 12, 55, 71, 33, 44, 27)]
    owned_all = {row[1] for row in many_parked}
    released = starvation_unpark_targets(many_parked, owned_all)
    assert len(released) == STARVATION_UNPARKS_PER_TICK_MAX
    assert released == sorted(released) == [12, 27, 33, 44, 55]
    assert starvation_unpark_targets(list(reversed(many_parked)), owned_all) == released
    print(f"  ok   #677 un-park bound: 7 releasable parks yield exactly "
          f"{STARVATION_UNPARKS_PER_TICK_MAX} per tick, lowest-first, order-independently")

    # THE WRITE: exactly one label removed, receipt first, never past a human hold.
    def run_unpark(labels):
        removed, comments, logs = [], [], []
        applied = unpark_starved_partition_holder(
            "o/r", 41, frozenset({"crate-a"}), labels,
            unpark_pr=lambda number: removed.append(number),
            post_comment=lambda repo, number, body: comments.append((repo, number, body)),
            log=logs.append)
        return applied, removed, comments, logs

    applied, removed, comments, _ = run_unpark(parked_labels)
    assert (applied, removed) == (True, [41])
    assert [(r, n) for r, n, _ in comments] == [("o/r", 41)]
    unpark_body = comments[0][2]
    assert unpark_body.startswith("> 🤖 **SPARQ agent** — un-parking.")
    assert "`crate-a`" in unpark_body and GLOBAL_PACKAGE in unpark_body
    assert applied is True
    for hold in (_park_policy.HUMAN_PARK_LABEL, _park_policy.HUMAN_PR_PARK_LABEL):
        applied, removed, comments, logs = run_unpark(parked_labels + [hold])
        assert (applied, removed, comments) == (False, [], []), hold
        assert any("human-owned hold" in line for line in logs), logs
    applied, removed, comments, logs = run_unpark(["review:changes"])
    assert (applied, removed, comments) == (False, [], [])
    # RECEIPT-FIRST on this half too: a crash between the two must leave an explained PR that is
    # STILL PARKED (the next tick converges it), never a silent label change nobody can account
    # for — which is the mystery-label failure registry #703 is about.
    unpark_order = []

    def exploding_unpark(number):
        unpark_order.append("label")
        raise DispatchError("label delete failed")

    try:
        unpark_starved_partition_holder(
            "o/r", 41, frozenset({"crate-a"}), parked_labels, unpark_pr=exploding_unpark,
            post_comment=lambda repo, number, b: unpark_order.append("comment"),
            log=lambda _m: None)
    except DispatchError:
        pass
    assert unpark_order == ["comment", "label"], unpark_order
    print("  ok   #677 un-park write: removes ONLY review:parked, receipt-first, and refuses "
          "outright while any human-owned hold is live")

    # ROUND TRIP: park under the starvation condition, clear the cause, un-park. This fails if
    # EITHER half is deleted — the park half must produce the receipt the un-park half reads.
    trip_calls, trip_comments = [], []
    assert park_starved_partition_holder(
        "o/r", 41, 9, ["review:needs"],
        park_pr=lambda number: trip_calls.append(("add", number)),
        post_comment=lambda repo, number, body: trip_comments.append(body),
        log=lambda _m: None) is True
    trip_receipt = {"user": {"login": bot}, "body": trip_comments[-1],
                    "created_at": "2026-07-26T00:00:00Z"}
    # the park's OWN receipt is what proves ownership on the way back out
    assert starvation_park_owner([trip_receipt], parked_labels, bot, True) is True
    # while the cause stands, the round trip does NOT complete
    assert starvation_unpark_targets([still_global], {41}) == []
    # once the area set resolves, it does
    assert starvation_unpark_targets([cleared], {41}) == [41]
    assert unpark_starved_partition_holder(
        "o/r", 41, frozenset({"crate-a"}), parked_labels,
        unpark_pr=lambda number: trip_calls.append(("remove", number)),
        post_comment=lambda repo, number, body: trip_comments.append(body),
        log=lambda _m: None) is True
    assert trip_calls == [("add", 41), ("remove", 41)], trip_calls
    # ...and the release CLOSES the episode using the PRODUCTION un-park body: replay the whole
    # conversation the two halves actually posted and the sweep must no longer own the park. This
    # is the leg that reds if the release marker is dropped from the un-park comment, which would
    # silently disable the episode binding.
    trip_history = [{"user": {"login": bot}, "body": trip_comments[0],
                     "created_at": "2026-07-26T20:00:00Z"},
                    {"user": {"login": bot}, "body": trip_comments[1],
                     "created_at": "2026-07-26T20:05:00Z"}]
    assert starvation_park_owner(trip_history, parked_labels, bot, True) is False, \
        "the sweep's own release must close the episode its park opened"
    # and a LADDER re-park after that release is still not ours
    assert starvation_park_owner(
        trip_history + [ladder_receipt(at="2026-07-26T21:00:00Z")],
        parked_labels, bot, True) is False
    print("  ok   #677 ROUND TRIP: park -> cause clears -> un-park, and the PRODUCTION un-park "
          "body closes the episode so the receipt cannot release a later park")

    # ---- THE PRODUCTION CALL SITE IS ITS OWN SEAM --------------------------------------------
    # Everything above calls the two functions DIRECTLY, so all of it stays green if main()'s
    # call site is deleted, guarded away, or re-pointed at the human terminal — the functions
    # would be perfect and unreachable, which is the exact vacuity class this repo keeps
    # measuring. main() is not callable from here, so these are SOURCE-LEVEL assertions and are
    # labelled as such rather than dressed up as behavioural coverage. Same technique the
    # `migration_provable=` call-site pin above uses.
    _dispatch_src = inspect.getsource(dispatch)
    assert "starvation_park_target(" in _dispatch_src, \
        "main()'s dispatch loop no longer CALLS starvation_park_target — the starved-plan sweep " \
        "is unreachable and every test above is vacuous"
    assert "park_starved_partition_holder(" in _dispatch_src, \
        "main()'s dispatch loop no longer CALLS park_starved_partition_holder — the sweep " \
        "selects a holder and then does nothing"
    assert 'plan["partition_starvation"]' in _dispatch_src, \
        "main()'s dispatch loop no longer reads the plan's starvation evidence, so `deferred` " \
        "is always 0 and the sweep can never fire"
    # The UN-PARK half is the machine exit. A park-only sweep industrialises exactly the failure
    # it replaces (registry #703), so its absence from the loop is a blocking defect, not a
    # missing nicety.
    for required, why in (
        ("starvation_unpark_targets(", "nothing ever releases a starvation park"),
        ("unpark_starved_partition_holder(", "releasable parks are selected and then left alone"),
    ):
        assert required in _dispatch_src, \
            f"main()'s dispatch loop no longer calls {required} — {why}"
    # The ownership proof must GATE the release, not merely be present. `if True or owner(...)`
    # leaves the call in the source and releases every park in sight, so a presence-only pin is
    # a test that passes for the wrong reason.
    assert re.search(r"(?m)^\s*if starvation_park_owner\($", _dispatch_src), \
        "main()'s un-park half no longer GATES on starvation_park_owner — a short-circuited or " \
        "inverted condition would release parks this sweep never applied, including parks " \
        "another mechanism is relying on"
    _unpark_write = re.search(
        r"unpark_pr=lambda number: _run_gh_target_api\(\s*repo, \"DELETE\","
        r"(?:.|\n)*?urllib\.parse\.quote\(([A-Za-z_]+), safe=\"\"\)", _dispatch_src)
    assert _unpark_write and _unpark_write.group(1) == "MACHINE_PARK_PR_LABEL", (
        "the un-park's production label DELETE must target MACHINE_PARK_PR_LABEL "
        f"(found {_unpark_write.group(1) if _unpark_write else None!r}) — this sweep must never "
        "be able to remove a human-owned hold")
    assert _dispatch_src.index("starvation_unpark_targets(") \
        < _dispatch_src.index("starvation_park_target("), \
        "the un-park half must run BEFORE the park half in the tick, so a tick that releases a " \
        "holder re-measures the lane before deciding whether to park another"
    # The label the production call site actually writes. The injected `park_pr` in the tests
    # above cannot see this, so without it the sweep could be re-pointed at `needs:user` and the
    # whole suite would stay green.
    _park_write = re.search(
        r"park_pr=lambda number: _run_gh_target_api\((?:.|\n)*?\{\"labels\": \[([A-Za-z_]+)\]\}",
        _dispatch_src)
    assert _park_write and _park_write.group(1) == "MACHINE_PARK_PR_LABEL", (
        "the starvation park's production label write must be MACHINE_PARK_PR_LABEL "
        f"(found {_park_write.group(1) if _park_write else None!r}) — registry #703: this action "
        "must never become a conveyor into the human terminal")
    # ...and it must not route through the escalating capacity-park ladder either.
    _sweep_block = _dispatch_src[_dispatch_src.index("starvation_park_target("):]
    _sweep_block = _sweep_block[:_sweep_block.index("for item in repository[\"items\"]")]
    for forbidden in ("_pr_needs_user", "_park_source_issue", "_issue_needs_user_landed"):
        assert forbidden not in _sweep_block, (
            f"the starvation sweep must not call {forbidden}: those paths write the human "
            "terminal or count park generations toward it")
    print("  ok   #677 call-site seam (source-level): the production loop CALLS the sweep, reads "
          "the plan evidence, and writes MACHINE_PARK_PR_LABEL — never the human terminal")

    # ---- THE YAML SEAM: structural, on PARSED nodes ------------------------------------------
    _starvation_yaml_seam_self_test()


# The PARSED dispatch.yml nodes the starved-plan sweep depends on. Compared for equality against
# the parsed document, never grepped: `if: false`, a deleted step, and a re-pointed `id:` are all
# invisible to a substring or `count(...) == N` assertion over the workflow text, and each one
# silently disables the sweep rather than failing loudly. The standing MEASURED finding on this
# repo is that every uncaught mutant lives at this seam, not in the Python.
_STARVATION_SEAM_JOB = "plan"
_STARVATION_ASSEMBLE_ANCHOR = r"(?m)^\s*partition_starvation = \[\]$"
_STARVATION_ASSEMBLE_END = r"(?m)^\s*review_exclusions = Counter\(\)$"
_STARVATION_CLAIM_STEP = "claim"


def _starvation_seam_violations(document):
    """Structural violations of the starved-plan seam in a PARSED dispatch.yml. Empty == intact."""
    out = []
    jobs = (document or {}).get("jobs") or {}
    plan_steps = (jobs.get(_STARVATION_SEAM_JOB) or {}).get("steps")
    if not isinstance(plan_steps, list):
        out.append("dispatch.yml: jobs.plan.steps is not a list — the starvation evidence is "
                   "not produced at all")
        return sorted(out)
    assemble = [step for step in plan_steps
                if isinstance(step, dict) and isinstance(step.get("run"), str)
                and "partition_starvation" in step["run"]]
    if len(assemble) != 1:
        out.append(f"dispatch.yml: expected EXACTLY ONE jobs.plan `run:` step to build "
                   f"`partition_starvation`; found {len(assemble)} — the PLAN half of the "
                   "starved-plan sweep was moved, split or deleted")
        return sorted(out)
    step = assemble[0]
    if step.get("if") is not None:
        out.append(f"dispatch.yml: the plan-assembly step carries an `if:` ({step['if']!r}) — "
                   "`if: false` (or any condition) would skip the starvation evidence SILENTLY "
                   "and the sweep would simply never fire")
    run = step["run"]
    for fragment, why in (
        ("starvation=starvation",
         "filter_busy_area_items is no longer asked for the measurement"),
        ('"partition_starvation": partition_starvation',
         "the measurement never reaches the plan artifact"),
        ('"schema": "registry-dispatch-plan/v5"',
         "the plan is not STAMPED with the schema that carries the evidence — CLAIM's "
         "validate_plan would refuse the artifact and every tick would hard-fail"),
        ('starvation.get("kept") == 0',
         "the healthy-plan guard is gone from the PLAN half — evidence would be recorded for "
         "a lane that planned work"),
        ('starvation.get("deferred", 0) > 0',
         "the empty-backlog guard is gone from the PLAN half"),
    ):
        if fragment not in run:
            out.append(f"dispatch.yml: the plan-assembly step lost {fragment!r} — {why}")
    if "registry-dispatch-plan/v4" in run:
        out.append("dispatch.yml: the plan-assembly step still mentions the v4 schema — a "
                   "reverted stamp or a reverted inline check would ship a plan CLAIM refuses")
    claim_steps = (jobs.get(_STARVATION_CLAIM_STEP) or {}).get("steps")
    if not isinstance(claim_steps, list):
        out.append("dispatch.yml: jobs.claim.steps is not a list — the sweep has no runner")
        return sorted(out)
    by_id = {step.get("id"): step for step in claim_steps if isinstance(step, dict)}
    claim = by_id.get("claim")
    if claim is None:
        out.append("dispatch.yml: jobs.claim has no `claim` step — dispatch-claim.py, which "
                   "carries the sweep, is not invoked")
    elif "dispatch-claim.py" not in str(claim.get("run", "")):
        out.append("dispatch.yml: the `claim` step no longer runs dispatch-claim.py, so the "
                   "starved-plan sweep never executes")
    return sorted(out)


def _starvation_yaml_seam_self_test():
    import yaml  # self-test-only, same lazy import as _workflow_step_python
    path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "dispatch.yml"
    live = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert _starvation_seam_violations(live) == [], _starvation_seam_violations(live)

    def mutant(edit):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        edit(document)
        return _starvation_seam_violations(document)

    def assemble_step(document):
        return next(step for step in document["jobs"]["plan"]["steps"]
                    if isinstance(step.get("run"), str)
                    and "partition_starvation" in step["run"])

    def drop_fragment(fragment):
        def edit(document):
            step = assemble_step(document)
            step["run"] = step["run"].replace(fragment, "")
        return edit

    seam_mutants = {
        "assemble step guarded by if: false":
            lambda d: assemble_step(d).__setitem__("if", "${{ false }}"),
        "assemble step deleted":
            lambda d: d["jobs"]["plan"].__setitem__(
                "steps", [s for s in d["jobs"]["plan"]["steps"]
                          if not (isinstance(s.get("run"), str)
                                  and "partition_starvation" in s["run"])]),
        "plan steps replaced by a scalar":
            lambda d: d["jobs"]["plan"].__setitem__("steps", "nope"),
        "the filter is no longer asked for the measurement":
            drop_fragment("starvation=starvation"),
        "the measurement never reaches the artifact":
            drop_fragment('"partition_starvation": partition_starvation,'),
        "the plan is stamped v4 again":
            lambda d: assemble_step(d).__setitem__(
                "run", assemble_step(d)["run"].replace(
                    '"schema": "registry-dispatch-plan/v5"',
                    '"schema": "registry-dispatch-plan/v4"')),
        "the v5 stamp is deleted outright":
            drop_fragment('"schema": "registry-dispatch-plan/v5"'),
        "the PLAN-half healthy-plan guard is deleted":
            drop_fragment('starvation.get("kept") == 0'),
        "the PLAN-half empty-backlog guard is deleted":
            drop_fragment('starvation.get("deferred", 0) > 0'),
        "the claim step is deleted":
            lambda d: d["jobs"]["claim"].__setitem__(
                "steps", [s for s in d["jobs"]["claim"]["steps"] if s.get("id") != "claim"]),
        "the claim step no longer runs dispatch-claim.py":
            lambda d: next(s for s in d["jobs"]["claim"]["steps"]
                           if s.get("id") == "claim").__setitem__("run", "echo hi"),
        "claim steps replaced by a scalar":
            lambda d: d["jobs"]["claim"].__setitem__("steps", "nope"),
    }
    survivors = [name for name, edit in seam_mutants.items() if not mutant(edit)]
    assert not survivors, f"dispatch.yml seam mutants NOT caught: {survivors}"
    print(f"  ok   #677 YAML seam: all {len(seam_mutants)} structural dispatch.yml mutants are "
          "caught as named violations")


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
