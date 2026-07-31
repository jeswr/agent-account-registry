#!/usr/bin/env python3
# [GPT-5.6] REG-5 fail-closed maintenance sweep for the registry orchestrator.
"""Reclaim dead worker leases and conservatively repair target orchestration state.

The live path uses deliberately separate credentials: ``REGISTRY_GH_TOKEN`` may only update the
registry lease ledger and inspect registry Actions runs, while ``TARGET_GH_TOKENS`` is a
JSON ``{owner: token}`` map of per-owner target-scoped GitHub App tokens used for issue and
pull-request reads/writes — one token per enabled-policy owner, so a target under a second owner is
never read or written with the wrong owner's token (issue #168: a single sparq-org-scoped token
404s every read and fails every write on jeswr/agent-account-registry, aborting the sweep before
dead leases are released). The single-owner legacy env ``TARGET_GH_TOKEN`` (with
``TARGET_GH_TOKEN_OWNER``) is still honoured as a fallback. Tokens are never accepted on the
command line or included in diagnostics.

Policy ``worker_timeout_minutes`` supplies both the uncorrelated-worker and stale-object age
threshold. Policy ``max_attempts`` supplies the durable retry cap. The policy rows are validated
by the existing policy-resolve.py core before any GitHub write is attempted.
"""

from __future__ import annotations

import argparse
import ast
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


_schema_spec = importlib.util.spec_from_file_location(
    "registry_lease_schema", Path(__file__).resolve().with_name("lease_schema.py")
)
if _schema_spec is None or _schema_spec.loader is None:
    raise RuntimeError("cannot load shared lease schema")
lease_schema = importlib.util.module_from_spec(_schema_spec)
_schema_spec.loader.exec_module(lease_schema)

# Shared park-label ownership + the sticky human-unpark veto (park_policy.py): groom's
# budget-exhaustion defer writes the MACHINE-owned status:parked, its stale-PR hand-off writes
# the human-owned needs:user, and BOTH consult the timeline veto before any label lands.
_park_spec = importlib.util.spec_from_file_location(
    "registry_park_policy", Path(__file__).resolve().with_name("park_policy.py")
)
if _park_spec is None or _park_spec.loader is None:
    raise RuntimeError("cannot load shared park policy")
park_policy = importlib.util.module_from_spec(_park_spec)
_park_spec.loader.exec_module(park_policy)


LEDGER_PATH = "data/leases.json"
# Mutable data plane lives on a dedicated non-code branch (issue #28): required-status-check
# protection on the default branch rejects the bot's contents-API PUTs, so every ledger read and
# write pins this ref. Keep in sync with select-and-claim.py / model-health.py LEDGER_REF.
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")
ATTEMPT_MARKER = "<!-- sparq-worker-attempt:v1"
STALE_PR_MARKER = "<!-- registry-groom-stale-pr:v1 -->"
DEFUSE_PR_MARKER = "<!-- registry-groom-auto-defuse:v1 -->"
# Registry provenance records — same location and <owner>--<name>--pr<N>.json naming as
# worker-pr.provenance_path / dispatch-claim's fail-closed review lookup. Groom runs from the
# registry checkout root (groom.yml), so the directory is reachable relatively.
PROVENANCE_DIR = "orchestration/provenance"
# Reason for age-parking a draft worker PR that has NO VALID registry provenance record —
# missing, unreadable, or schema-invalid (bad pr_number/provider/alias/issue/head-sha/
# account-hash). Such a draft is owned by NO automated loop: dispatch-claim's PLAN, its CLAIM
# re-read, and review-fix.yml's resolve step all fail closed on every one of those cases via the
# ONE shared admission function (dispatch-claim.provenance_admission_error, surfaced here as
# is_enumerable_provenance), and groom's issue-side orphan repair skips it (an open draft links
# its source issue). Age-parking to needs:user is the human hand-off — the closure guarantee that
# no draft is ever silently stranded. Phrased to read after "…threshold, and {reason}." in the
# park comment.
ORPHAN_DRAFT_REASON = (
    "the worker pull request is still a draft with no valid registry provenance record, so the "
    "review loop (which fails closed on missing or invalid provenance) will never pick it up"
)
WORKER_PR_MARKER = "> 🤖 SPARQ agent"
SAFE_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
SAFE_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[bot\])?")
SAFE_CLAIM = re.compile(r"[0-9a-f]{32}")
SAFE_ACCOUNT_HASH = re.compile(r"[0-9a-f]{16}")
HOLDER = re.compile(
    r"(?P<repo>[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)"
    r"#(?P<issue>[1-9][0-9]*)@(?P<run>[^\r\n]+)"
)
# WORKFLOW SEAM (#1130): this parses a string ANOTHER file renders — worker.yml's `run-name:`,
# `worker <target_repo> claim=<id>`. The target segment was added for the throughput-metrics
# collector (scripts/metrics.py reads the same shape) and this pattern did not follow, so
# `.fullmatch` matched NO real worker run title: every claim read as uncorrelated, the walk in
# _correlate_claim_runs never took its early return, and classify_lease lost the exact run
# evidence it exists to use. The target segment is OPTIONAL because the walk pages back through
# up to WORKER_RUN_PAGE_CEILING x 100 runs of history, which reaches runs named before that
# change; the claim id is the correlation key either way. _self_test renders worker.yml's OWN
# run-name and asserts this matches it, so the next run-name edit reds instead of silently
# disabling the correlation.
WORKER_RUN_NAME = re.compile(
    r"worker (?:(?P<target>\S+) )?claim=(?P<claim>[0-9a-f]{32}|self)"
)
# Cross-provider review/fix repair leases (dispatch-claim prefixes `review:` / `fix:`) carry no
# target-issue holder; they are TTL-managed by groom-leases. Groom must SKIP them, never
# issue-map them, and never fail the whole sweep on their holder shape (live incident
# 2026-07-17: every scheduled sweep aborted while a review lease existed).
REPAIR_HOLDER_PREFIXES = ("review:", "fix:")
HUMAN_HOLD_PR_LABELS = frozenset({"needs:user", "review:needs-user"})
DEFAULT_STALE_HOURS = 6
MAX_AUTO_DEFUSES_PER_TICK = 10


def is_repair_holder(value: Any) -> bool:
    return lease_schema.is_repair_holder(value)
WORKER_BRANCH = re.compile(r"^sparq-agent/issue-(?P<issue>[1-9][0-9]*)-")
LINKED_ISSUE = re.compile(
    r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#(?P<issue>[1-9][0-9]*)\b"
)
ACTIVE_RUN_STATUSES = {"queued", "in_progress", "requested", "waiting", "pending"}
MAX_TERMINAL_REAPS_PER_TICK = 20
BAD_MERGE_STATES = {
    "blocked": "required checks are blocked or pending",
    "dirty": "the branch has merge conflicts",
    "behind": "the branch is stale behind its base",
    "unstable": "checks are not clean",
    "unknown": "GitHub cannot establish a clean merge state",
}
LABELS = {
    "status:ready": ("0e8a16", "Ready for trusted automated dispatch"),
    "status:deferred": ("d4c5f9", "Private-registry worker orchestration state"),
    # Keep in sync with park_policy.MACHINE_PARK_DESCRIPTION: a machine park clears on a human
    # unlabel, on proven cause-recovery (registry #614 — the automatic re-admission path), or on
    # the capped sustained-fleet-health retry once that proof has aged out (registry #691).
    "status:parked": ("1d76db",
                      "Machine-owned capacity park (soft hold; human unlabel, proven recovery, "
                      "or capped retry)"),
    "needs:user": ("b60205", "Human attention required"),
    # The PR-side machine park (park_policy.MACHINE_PARK_PR_LABEL). Groom now writes it for the
    # age hand-off, so groom must be able to CREATE it on a target that has never seen one.
    "review:parked": ("1d76db",
                      "Machine-owned capacity park (soft hold; human unlabel, proven recovery, "
                      "or capped retry)"),
}

# ---- the age-park CLASS split (a TIMEOUT is not a human question) --------------------------------
# Age says "this took too long". It does NOT say "a human must answer a question". Every reason
# THIS sweep derives comes from an age threshold crossing plus a MACHINE-READABLE cause, and each
# such cause has a MACHINE-CHECKABLE recovery predicate (age_park_cause_recovered), so the park it
# writes is park_policy's MACHINE-owned soft hold, not the human-owned terminal.
#
# Why this mattered enough to change: `needs:user` / `review:needs-user` are exactly the labels
# park_policy.capacity_park_admission treats as a HUMAN-OWNED hold and refuses to auto-re-admit
# ("ANY `needs:*` label or `review:needs-user` among them ... blocks the automatic path
# outright"). Stamping one on a PR that ALREADY carried the machine soft hold therefore did not
# merely mislabel it — it DISABLED the automatic cause-recovery exit registry #614/#691 built, and
# handed the item to the maintainer permanently. Measured on sparq-org/sparq 2026-07-27: of 11 open
# age-parks, 6 also carried `review:parked`, and 3 (#3912/#3916/#3942) had a PROVABLY recovered
# cause — an admissible provenance record on the live ledger ref — yet were still human-held.
#
# The mapping is CLOSED and keyed on the exact reason strings stale_worker_pr_reason returns.
# An UNMAPPED reason keeps the HUMAN hand-off: a cause this table cannot name is a cause
# age_park_cause_recovered cannot prove recovered, and a soft hold with no provable exit is a
# SILENT permanent hold — strictly worse than a visible one.
AGE_PARK_CAUSES: dict[str, str] = {ORPHAN_DRAFT_REASON: "orphan-draft"}
AGE_PARK_CAUSES.update(
    {reason: f"merge-{state}" for state, reason in BAD_MERGE_STATES.items()}
)
# At most this many AUTOMATIC re-admissions may ever be granted to one PR by the age sweep, and
# the cap is enforced ONCE, at park time: a park in generation N > AGE_UNPARK_MAX is written in
# the HUMAN class outright, so the un-park sweep can never see an over-cap park. A PR that keeps
# re-entering the same machine-recoverable cause is not a capacity blip — it is a genuine human
# question ("this flaps"), and the right disposition is escalation, not another retry.
AGE_UNPARK_MAX = 2
# Machine-readable park/un-park receipts. Bot-authored, durable, and the ONLY record the un-park
# sweep reads: it never infers a park's class from prose or from label state alone. `cause` is an
# AGE_PARK_CAUSES value, `head` the head SHA at park time, `gen` the 1-based park generation.
# The (cause, head, gen) triple is the CONSUME-ONCE key: an un-park is granted for a given triple
# at most once, so the same recovery can never be re-earned.
#
# The two marker spellings live in park_policy, NOT here (registry #769). groom WRITES them and
# dispatch-claim's automatic re-admission sweep READS them — it must recognise a groom age park
# in order to leave it alone — and those are separate entry points with separate checkout roots.
# A hand-copied literal in the reader is a spelling that can drift silently from the writer's,
# and the failure it produces is not a crash but a sweep that quietly stops recognising the class
# it was written to skip. One spelling, imported by both, cannot drift; the aliases below keep
# every existing call site in this file unchanged.
AGE_PARK_MARKER = park_policy.GROOM_AGE_PARK_MARKER
AGE_UNPARK_MARKER = park_policy.GROOM_AGE_UNPARK_MARKER
# The un-park STALL correction (issue #83). A grant receipt announces "re-admitted, this PR
# re-enters the ordinary review loop"; when the park label is STILL LIVE under a human-owned hold,
# the convergence retry below refuses PERMANENTLY (a machine never clears a human hold), so the
# PR's public record contradicts its own labels and nothing automatic can resolve it. The
# correction says so ON THE PR — the only surface the human who has to act actually reads. The
# sweep's log is a cron nobody watches, which is exactly why four sparq PRs sat in this
# contradiction for ~17 hours: the last thing written on them said they had been unparked.
#
# Declared HERE rather than in park_policy, unlike the two markers above: this one has no reader
# in another checkout root — groom writes it and groom reads it back, for dedupe only. It must
# CONTAIN neither receipt marker: age_receipts would read a correction carrying the GRANT marker
# as a grant, and since [registry #1292] age_park_generation counts exactly those, a correction
# would SPEND one of the AGE_UNPARK_MAX automatic re-admissions the machine never made. The
# self-test asserts both directions on the real rendered body.
AGE_UNPARK_STALL_MARKER = "<!-- registry-groom-unpark-stalled:v1"
_AGE_RECEIPT = re.compile(
    r"cause=(?P<cause>[a-z-]{1,40}) head=(?P<head>[0-9a-f]{40}) gen=(?P<gen>[1-9][0-9]{0,3}) -->"
)


def age_park_cause(reason: str) -> str | None:
    """The machine-readable cause token for an age-park reason, or None when unmapped."""
    return AGE_PARK_CAUSES.get(reason)


def age_park_label(reason: str, generation: int) -> str:
    """The park label this age hand-off must write — the ONE place the class is decided.

    MACHINE (`review:parked`) when the reason names a cause with a machine recovery predicate AND
    the PR is still within its automatic-re-admission cap; HUMAN (`needs:user`) otherwise, i.e.
    for an unmapped cause (no provable exit) or a park past AGE_UNPARK_MAX (a flap)."""
    if age_park_cause(reason) is None:
        return park_policy.HUMAN_PARK_LABEL
    if generation > AGE_UNPARK_MAX:
        return park_policy.HUMAN_PARK_LABEL
    return park_policy.MACHINE_PARK_PR_LABEL


def age_receipts(comments: list[dict[str, Any]], marker: str, bot_login: str
                 ) -> list[dict[str, Any]]:
    """Well-formed BOT-AUTHORED receipts of one kind, oldest-first.

    Trust filter first (the worker-pr receipt-parser pattern): a receipt any other actor could
    author is not a durable record of what THIS loop did, so a non-bot comment carrying the
    marker is ignored entirely. A malformed receipt is DROPPED here but still counted by
    age_park_generation, so a corrupt receipt can never buy an extra automatic re-admission."""
    found: list[dict[str, Any]] = []
    if not bot_login:
        return found
    for comment in comments:
        if comment["user"]["login"].casefold() != bot_login.casefold():
            continue
        body = comment["body"]
        index = body.find(marker)
        if index < 0:
            continue
        match = _AGE_RECEIPT.match(body[index + len(marker):].lstrip(), 0)
        if match is None:
            continue
        found.append({"cause": match.group("cause"), "head": match.group("head"),
                      "gen": int(match.group("gen")),
                      # The comment's own creation stamp. park_policy's receipt readers all key
                      # recency off this, and without it a receipt cannot be compared against a
                      # park application — which is the guard this file was missing.
                      "at": comment.get("created_at")})
    return found


def age_park_generation(comments: list[dict[str, Any]], bot_login: str) -> int:
    """The re-admission generation a NEW age-park would occupy: one past every automatic
    RE-ADMISSION already GRANTED on this PR, CLAMPED at AGE_UNPARK_MAX + 1.

    [registry #1292] IT COUNTS GRANTS, NOT PARKS — and that is the whole point. AGE_UNPARK_MAX
    says what it bounds in its own name and comment: "at most this many AUTOMATIC RE-ADMISSIONS
    may ever be granted to one PR". age_park_label spends that budget, escalating to the
    human-owned `needs:user` at generation > AGE_UNPARK_MAX. Until this change the counter
    summed AGE_PARK_MARKER receipts — how many times the sweep had PARKED, which is a different
    quantity and, on the live population, an unrelated one.

    WHY THAT WAS AN ABSORBING STATE, AND WHY IT WAS SELF-DRIVEN. The park receipt embeds
    `gen={generation}`, and the hand-off's comment dedupe searches for that exact receipt string.
    With the generation derived from the park count, the string a new park mints is BY
    CONSTRUCTION one that has never been written, so the dedupe could never fire; the comment was
    re-posted; posting it bumped the PR's `updated_at`; and `stale_worker_pr_reason` re-derives
    staleness from `updated_at`, so the sweep's own comment guaranteed the next threshold
    crossing. Three crossings — no push, no review, no re-admission, nothing but the clock the
    sweep wound itself — reached generation 3 and applied `needs:user`, which
    park_policy.capacity_park_admission refuses to auto-re-admit and
    dispatch-claim.enumerate_review_items excludes. The machine retired its own PRs into the one
    class no machine re-enters, on evidence it manufactured.

    MEASURED, live open PRs 2026-07-29: all 16 age-park escalations then standing had reached
    generation 3 with ZERO un-park grants on record and the SAME head SHA across all three
    generations. Not one had been re-admitted even once; not one had moved. Those 16 were 15 of
    the 18 human-terminal holds applied that day. The escalation comment already SAID so — #769
    made its prose honest ("the machine granted NO automatic re-admission on this PR") without
    making its arithmetic honest, so the sweep printed an accurate description of its own defect
    on every PR it absorbed.

    Counting grants makes all three of the cap's claims true at once: the escalation happens
    only after the machine really did re-admit the PR AGE_UNPARK_MAX times and it really did come
    back, the receipt fingerprint stops moving while nothing is granted (so the dedupe becomes
    load-bearing and the self-wound clock stops), and a park nobody re-admitted stays in the
    MACHINE class, where age_park_cause_recovered can still prove its cause recovered and let it
    out. Grants are bounded and consume-once (age_unpark_state keys them on the whole
    (cause, head, gen) triple), so the ladder still terminates.

    Counts MARKERS, not well-formed records — a malformed grant receipt still consumed the
    re-admission it recorded, exactly as park_policy's `auto_marker_count` counts markers rather
    than parsed records, so a corrupt comment can never buy an extra one.

    The clamp stays. It is no longer what stops the escalation comment repeating (a stable
    generation does that now), but it still pins the terminal: once the budget is spent the
    generation cannot climb further, so the receipt stops changing and the dedupe holds. (The
    head SHA remains in the fingerprint, so genuinely NEW work pushed after an escalation does
    re-state it once — one comment per head, the same bound park_policy's park fingerprints
    use.)"""
    if not bot_login:
        return 1
    return min(
        AGE_UNPARK_MAX + 1,
        1 + sum(
            1 for comment in comments
            if comment["user"]["login"].casefold() == bot_login.casefold()
            and AGE_UNPARK_MARKER in comment["body"]
        ),
    )


def age_unpark_state(comments: list[dict[str, Any]], bot_login: str
                     ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """``(park_receipt, grant_receipt)`` for the newest age park on record.

    ``park_receipt`` is None when this is not an age park of ours, or when the park is OVER THE
    CAP (generation > AGE_UNPARK_MAX) — an over-cap park was written in the HUMAN class by
    age_park_label and must never be automatically re-admitted, so the exit phase must not even
    consider it.

    ``grant_receipt`` is the un-park receipt carrying the SAME (cause, head, gen) triple, or None
    when the recovery is still unconsumed. That is the consume-exactly-once invariant: the
    recovery can never be re-earned, and a further re-admission requires a NEW park at a new
    fingerprint. The RECEIPT is returned rather than a bool because the caller needs its
    TIMESTAMP: convergence is only legitimate while no park application is newer than the grant.

    The two are returned SEPARATELY rather than collapsed into "owed or not" because the caller
    needs to distinguish two states that look identical from the label alone (registry #614's
    `auto-receipt` branch, mirrored):

      - granted AND the machine label is GONE — the normal, finished case;
      - granted AND the machine label is STILL LIVE — the receipt landed and the unlabel did
        not. Receipt-first ordering guarantees this is the only crash residue possible, and
        collapsing it into None strands the PR under `review:parked` FOREVER: nothing re-parks it
        (its cause has recovered, so the hand-off derives no reason) and nothing clears it. One
        plain HTTP transient on the DELETE is enough to reach it. The caller CONVERGES on that
        state by retrying the unlabel, consuming no new evidence and minting no new receipt.

    THE LABEL DOES NOT IDENTIFY ITS WRITER. `review:parked` is a SHARED MULTI-WRITER label —
    dispatch-claim writes it at two sites and worker-pr's capacity park writes it too — so its
    presence proves *a* writer parked this PR, never that THIS sweep did. The caller must
    therefore also prove the grant is NEWER than every park application before converging."""
    parks = age_receipts(comments, AGE_PARK_MARKER, bot_login)
    if not parks:
        return None, False
    latest = parks[-1]
    if latest["gen"] > AGE_UNPARK_MAX:
        return None, False
    key = (latest["cause"], latest["head"], latest["gen"])
    for grant in age_receipts(comments, AGE_UNPARK_MARKER, bot_login):
        if (grant["cause"], grant["head"], grant["gen"]) == key:
            return latest, grant
    return latest, None


def unpark_stall_pending(
    comments: list[dict[str, Any]], bot_login: str, grant: dict[str, Any]
) -> bool:
    """Is the stall correction for THIS grant still owed? PURE (issue #83).

    Deduped on the grant's OWN (cause, head, gen) triple — the same consume-once key the grant
    carries — so a PR held for days is corrected exactly once per re-admission, never once per
    tick. A re-park mints a new fingerprint, so a genuinely new stall is still reported.

    A malformed or non-bot comment carrying the marker is not a correction: age_receipts drops
    both, and the fail direction of that drop is a repeated correction, never a silent one."""
    key = (grant["cause"], grant["head"], grant["gen"])
    return not any(
        (posted["cause"], posted["head"], posted["gen"]) == key
        for posted in age_receipts(comments, AGE_UNPARK_STALL_MARKER, bot_login)
    )


def unpark_stall_comment(park_label: str, held: list[str], grant: dict[str, Any]) -> str:
    """The correction body: what a PR's own record must say when the re-admission it advertises
    did not put it back in the review loop (issue #83).

    IT CLAIMS ONLY WHAT THE LABELS IN HAND PROVE — the park label is live, these human-owned
    holds are live, therefore this PR is out of every automatic lane and the machine may clear
    neither label. It deliberately does NOT assert that the un-park's DELETE failed: the identical
    contradiction is reached when the un-park DID land and another writer re-parked the PR
    afterwards, and a machine stating a cause it cannot prove is how a maintainer learns to skip
    reading these. The action it asks for is the same either way."""
    receipt = (f"{AGE_UNPARK_STALL_MARKER} cause={grant['cause']} head={grant['head']} "
               f"gen={grant['gen']} -->")
    holds = ", ".join(f"`{label}`" for label in held)
    return (
        "> 🤖 SPARQ agent\n\n"
        "**Correction — this pull request is NOT in the review loop the automatic re-admission "
        f"above announced.** `{park_label}` is still live on it, and so are human-owned hold(s) "
        f"({holds}) which keep it out of every automatic lane. A machine never clears a "
        "human-owned hold, and the retry that would otherwise complete the un-park refuses for as "
        "long as one is live — so this state cannot self-heal.\n\n"
        "**A human is the only exit here**: remove the hold to let the re-admission complete, or "
        f"remove `{park_label}` and keep the hold if this PR really is waiting on a person. Until "
        "one of those happens, read the re-admission comment above as withdrawn.\n\n"
        f"{receipt}"
    )


class GroomError(RuntimeError):
    """A concise fail-closed error which never contains credentials, and no SUCCESSFUL response body.

    TWO deliberate exceptions, both produced ONLY through the one masking contract
    (_masked_detail: single-line, bounded at GH_DETAIL_LIMIT, credential-masked):

      1. issue #644 — a `gh` subprocess diagnostic (_gh_failure_detail). Three hours of
         `parked PR redraft failed for sparq-org/sparq#3427` carried no cause at all, so no reader
         could tell a permission refusal from a GitHub-side restriction.
      2. issue #647 — the error envelope of a FAILED GitHub API call (_http_failure_detail). The
         per-object writes in the stale-PR hand-off and issue-repair loops are `api.request` calls;
         "HTTP 403" alone cannot distinguish a permission refusal from a bad payload, and those
         loops now DEFER per object instead of aborting, so a causeless deferral would be silent.

    Neither is a response body in the sense this contract guards: they are the operator's only
    witness to a failure, never the content of a successful read.
    """


class GroomConflict(GroomError):
    """A retryable contents-API compare-and-swap conflict."""


class RedraftUnavailable(GroomError):
    """A parked-PR redraft failure that is NOT a property of the pull request (issue #644).

    A missing `gh` binary, or no App token for the PR's owner, is a property of the RUN: every
    remaining candidate fails identically, so this must never be reported as one PR's deferral.
    It still does not abort the sweep — dead-lease reclaim runs — it forces the run's exit status
    non-zero at the very end (defuse_exit_failure, precedence rule 1).
    """


@dataclass(frozen=True)
class Limits:
    worker_timeout_minutes: int
    max_attempts: int
    # [registry #835] The repo's MASTER-protected `review_enrolment_authors` allowlist — the
    # half of the #657 orchestrator-PR admission that lives behind branch protection. Groom is
    # otherwise CLASS-BLIND: every one of its suppression guards (_admitted_review_prs,
    # _live_issue_admission, _current_links) keys on WORKER identity, so an enrolled
    # orchestrator PR under review could not hold its source issue out of the exhaustion park —
    # and a parked source issue de-enumerates the PR from the review lane
    # (dispatch-claim.enumerate_review_items excludes on `status:parked` / any `needs:*` there).
    # Nothing alarmed, because groom's run SUCCEEDED and the PR was simply absent from the next
    # enumeration. Empty (every repo's default) means groom behaves exactly as it did before.
    enrolled_authors: tuple[str, ...] = ()

    @property
    def threshold_seconds(self) -> int:
        return self.worker_timeout_minutes * 60


@dataclass(frozen=True)
class Holder:
    repo: str
    issue: int
    run_id: int | None
    dispatcher_run: bool


@dataclass(frozen=True)
class LeaseDecision:
    state: str  # live | dead | unknown
    reason: str
    run_id: int | None = None


@dataclass(frozen=True)
class IssueAction:
    repo: str
    number: int
    mode: str  # ready | defer
    reason: str


@dataclass(frozen=True)
class PullAction:
    repo: str
    number: int
    reason: str
    mode: str = "park"  # park | defuse
    head_sha: str = ""
    updated_at: str = ""


def _epoch(value: str, where: str) -> int:
    if not isinstance(value, str):
        raise GroomError(f"{where} timestamp is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GroomError(f"{where} timestamp is malformed") from exc
    if parsed.tzinfo is None:
        raise GroomError(f"{where} timestamp has no timezone")
    return int(parsed.timestamp())


def _positive_int(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise GroomError(f"{where} must be a positive integer")
    return value


def parse_holder(value: Any) -> Holder:
    if not isinstance(value, str):
        raise GroomError("lease holder is malformed")
    match = HOLDER.fullmatch(value)
    if match is None:
        raise GroomError("lease holder does not identify a safe target issue")
    run_text = match.group("run")
    direct = re.fullmatch(r"(?P<id>[1-9][0-9]*)\.(?:[1-9][0-9]*)", run_text)
    dispatched = re.fullmatch(
        r"dispatch-(?P<id>[1-9][0-9]*)\.(?:[1-9][0-9]*)", run_text
    )
    run_id = int((direct or dispatched).group("id")) if direct or dispatched else None
    return Holder(
        repo=match.group("repo"),
        issue=int(match.group("issue")),
        run_id=run_id,
        dispatcher_run=dispatched is not None,
    )


def validate_ledger(document: Any) -> list[dict[str, Any]]:
    try:
        return lease_schema.validate_ledger(document)
    except lease_schema.LeaseSchemaError as exc:
        raise GroomError(str(exc)) from exc


def _run_status(run: dict[str, Any]) -> str:
    status = run.get("status")
    if status == "completed":
        return "dead"
    if status in ACTIVE_RUN_STATUSES:
        return "live"
    raise GroomError("worker run returned an unknown status")


def classify_lease(
    lease: dict[str, Any],
    limits: Limits,
    now: int,
    claim_runs: dict[str, dict[str, Any]],
    holder_runs: dict[int, dict[str, Any] | None],
) -> LeaseDecision:
    """Conservatively classify one lease from exact run evidence or its policy timeout."""
    claim = lease["claim_id"]
    if claim in claim_runs:
        run = claim_runs[claim]
        state = _run_status(run)
        conclusion = run.get("conclusion") or "active"
        run_id = run.get("id")
        return LeaseDecision(
            state,
            f"claim-correlated worker is {state} ({conclusion})",
            run_id if isinstance(run_id, int) and not isinstance(run_id, bool) else None,
        )

    holder = parse_holder(lease["holder"])
    holder_run = holder_runs.get(holder.run_id) if holder.run_id is not None else None
    if holder_run is not None:
        path = str(holder_run.get("path", "")).split("@", 1)[0]
        if not holder.dispatcher_run and path == ".github/workflows/worker.yml":
            state = _run_status(holder_run)
            conclusion = holder_run.get("conclusion") or "active"
            return LeaseDecision(
                state, f"holder worker is {state} ({conclusion})", holder.run_id
            )

    deadline = lease["issued_at"] + limits.threshold_seconds
    if now >= deadline:
        return LeaseDecision(
            "dead", "no active worker was correlated before the policy timeout"
        )
    if now >= lease["expires_at"]:
        return LeaseDecision(
            "dead", "lease expiry passed without an active correlated worker"
        )
    return LeaseDecision(
        "unknown", "worker correlation is unavailable inside the policy timeout"
    )


def count_attempts(comments: list[dict[str, Any]], bot_login: str) -> int:
    bot = bot_login.casefold()
    return sum(
        1
        for comment in comments
        if str(comment.get("user", {}).get("login", "")).casefold() == bot
        and ATTEMPT_MARKER in str(comment.get("body", ""))
    )


def attempts_fetch_needed(
    comment_count: int, labels: set[str], stale: bool, max_attempts: int
) -> bool:
    """Can either guard that consumes this issue's attempt count still FIRE? (registry #1303 —
    the groom sweep's dominant request cost.)

    One `/issues/{n}/comments` GET per commented issue, every tick, is 500 of the ~650 requests a
    sweep of the two enabled targets issues (measured 2026-07-29). They are spent on the
    CONTENDED rate-limit partition: `/repos/{o}/{r}/issues/{n}/comments` shares a counter with
    every `issues`, `pulls`, `contents` and `/repos/{o}/{r}` read the whole estate makes, while
    `/actions/artifacts` and `/actions/workflows/{f}/runs` sit in a different partition with its
    own reset stamp. (registry #1228 measured that split on `github.token`; re-measured
    2026-07-29 on a user token with the REPOSITORY HELD FIXED and only the route varied — 11
    requests spent on `/pulls` moved the `issues` counter by 11 and the `artifacts` counter by 0.
    `GET /rate_limit` reports the OTHER partition's reset stamp, which is the mechanism behind
    #796: the estate's rate-limit instrument reads healthy straight through an outage of the
    partition its sweeps actually spend.)

    `count_attempts` counts a SUBSET of an issue's comments — the bot's, carrying ATTEMPT_MARKER
    — so the `comments` count the LIST payload already handed us is a hard upper bound on it, for
    free. That bound is only USEFUL where it decides a guard, and there are TWO guards in
    `_plan_actions`, not one:

        exhaustion park   `used >= max_attempts`   (+ live/admitted suppression)
        orphan repair     `used >= 1`              (+ stale, needs:user, status-label conjuncts)

    Missing the second one is a live trap: `used >= 1` is sensitive at 0-vs-1, where an upper
    bound says nothing at all, so a filter written against the cap alone silently re-readies
    issues that never saw a worker. That version was written, and groom's own call-site test
    caught it — see `_self_test`.

    So the question is not "is the count decided" but "can either guard still fire". Every other
    conjunct of both guards is free — labels and `updated_at` are in the list payload — so:

      * `comment_count >= max_attempts` keeps the exhaustion park reachable. Below the cap the
        park is unreachable whatever the fetch returns.  (`>=`, not `>`: an issue with exactly
        `max_attempts` comments could have every one of them be an attempt comment.)
      * the orphan repair needs a comment to exist at all, AND its own label/staleness conjuncts.
        `status:in-progress` is excluded because `_plan_actions` returns on that branch BEFORE
        the repair, without ever reading the count.

    `live_by_issue` / `admitted` are deliberately NOT consulted: both would only ever make this
    answer smaller, they are not known this early in the sweep, and an error in this predicate
    has to point at FETCHING, never at skipping.
    """
    if comment_count >= max_attempts:
        return True          # the exhaustion park is still reachable
    if comment_count < 1:
        return False         # no comments => no attempt comments => neither guard can fire
    if not stale or "needs:user" in labels or "status:in-progress" in labels:
        return False         # the orphan repair's free conjuncts already refuse it
    has_status = any(label.startswith("status:") for label in labels)
    return not has_status or "status:in-progress-review" in labels


def label_transition(labels: set[str], mode: str) -> tuple[set[str], set[str]]:
    # status:in-progress-review is removed by BOTH modes: the orphan repair (a worker PR that
    # closed without merging) must not leave the review-loop label behind on a re-readied issue.
    # `defer` (attempt budget exhausted) is BUDGET-driven, so it writes the MACHINE-owned
    # status:parked soft hold (park_policy.py defect 1) — never the human-question terminal
    # needs:user, which would strip the issue's PR surface from the review loop and absorb it
    # until a human intervened (2026-07-18 mass-park incident). The `ready` repair also clears
    # a leftover machine park: a re-readied issue is dispatchable again by definition.
    if mode == "ready":
        desired = {"status:ready"}
        remove = {"status:in-progress", "status:in-progress-review", "status:deferred",
                  "status:parked"}
    elif mode == "defer":
        desired = {"status:parked", "status:deferred"}
        remove = {"status:ready", "status:in-progress", "status:in-progress-review"}
    else:
        raise GroomError("unknown issue label transition")
    return desired - labels, remove & labels


def linked_issue_numbers(pull: dict[str, Any]) -> set[int]:
    numbers: set[int] = set()
    head = pull.get("head", {}).get("ref", "")
    body = pull.get("body") or ""
    if not isinstance(head, str) or not isinstance(body, str):
        raise GroomError("pull request linkage fields are malformed")
    branch = WORKER_BRANCH.match(head)
    if branch:
        numbers.add(int(branch.group("issue")))
    numbers.update(int(match.group("issue")) for match in LINKED_ISSUE.finditer(body))
    return numbers


_REVIEW_LOOP_MODULE: Any = None


def _review_loop_module() -> Any:
    """Cached dispatch-claim.py module — the review loop's own provenance-admission schema.

    Loaded lazily from this script's directory so ``is_enumerable_provenance`` is IMPORTED,
    never replicated: groom's "is this draft review-loop-owned?" decision and dispatch-claim's
    "will the review loop actually drive this PR?" decision cannot drift. dispatch-claim.py is
    import-side-effect-free (constants and defs only)."""
    global _REVIEW_LOOP_MODULE
    if _REVIEW_LOOP_MODULE is None:
        _REVIEW_LOOP_MODULE = _load_module(
            Path(__file__).resolve().parent / "dispatch-claim.py", "registry_dispatch_claim"
        )
    return _REVIEW_LOOP_MODULE


def worker_pr_provenance_enumerable(
    repo: str, number: int, registry_root: Path = Path("."),
    ledger_root: Path | None = None,
) -> bool:
    """True when the registry provenance record for target PR ``repo#number`` exists on disk
    AND is valid by the review loop's OWN admission schema (dispatch-claim.
    is_enumerable_provenance: JSON object, strict-int matching pr_number (float/bool
    excluded — 41.0 == 41 and True == 1 under lax equality), registered impl provider,
    safe-atom impl alias, positive-int issue, well-formed 40-hex head sha, salted 16-hex
    account hash, and a MACHINE-ATTESTED ``recorded_at_run`` stamp (issue #657 — the record's
    trust basis must be a host-side run the implementing model could not influence) — the
    COMPLETE field set; see provenance_admission_error, the one function every consumer calls).

    Mirrors worker-pr.provenance_path / dispatch-claim's review lookup: the record lives at
    ``orchestration/provenance/<owner>--<name>--pr<N>.json`` in the registry checkout, which is
    groom's working directory (groom.yml runs from the checkout root). VALIDITY — not mere file
    existence — decides draft ownership: the review enumerator/claimer fail-close on an
    unreadable or schema-invalid record exactly as on a missing one, so a draft carrying such a
    record is owned by no automated loop and must keep the age-park hand-off. (A bare existence
    check would groom-preserve that draft while the review loop never admits it — the same
    silent-strand deadlock class, for the malformed case.)

    Record location (issue #96): the ``ledger`` data-plane branch checkout is PRIMARY — master's
    required `gate` status check rejects every direct contents-API PUT, so post-outage records
    exist ONLY there — and the legacy master registry checkout is the fallback so pre-outage
    records (<= sparq#2542) stay visible. A present-but-invalid ledger record is judged as-is
    (never falls back: the fallback is for the missing-file migration case only)."""
    return (
        _provenance_record(repo, number, registry_root, ledger_root=ledger_root)
        is not None
    )


def _provenance_record(
    repo: str, number: int, registry_root: Path = Path("."),
    ledger_root: Path | None = None,
) -> dict[str, Any] | None:
    """The PARSED registry provenance record for target PR ``repo#number`` IFF it is admissible
    by the review loop's one shared schema, else None (missing, unreadable, or schema-invalid —
    every case the review loop fails closed on). Resolution and validity semantics are documented
    on worker_pr_provenance_enumerable, the boolean wrapper."""
    record = _read_provenance_json(repo, number, registry_root, ledger_root=ledger_root)
    if record is None:
        return None
    if not _review_loop_module().is_enumerable_provenance(record, number):
        return None
    return record


def _read_provenance_json(
    repo: str, number: int, registry_root: Path = Path("."),
    ledger_root: Path | None = None,
) -> dict[str, Any] | None:
    """The PARSED record for ``repo#number`` with NO admission applied, or None when it is
    missing or not readable JSON.

    [registry #835] Split out of ``_provenance_record`` because the two classes admit through
    DIFFERENT predicates over the SAME bytes: a worker record through
    ``is_enumerable_provenance`` (which deliberately has no orchestrator opt-in), an enrolled
    orchestrator record through ``admits_orchestrator_pr`` + ``provenance_admission_error(...,
    admit_orchestrator=True)``. Resolution is unchanged: the ``ledger`` data-plane checkout is
    primary (issue #96), the master checkout is the legacy pre-outage fallback."""
    owner, _, name = repo.partition("/")
    if not owner or not name:
        raise GroomError("target repository name is malformed")
    record_name = f"{owner}--{name}--pr{number}.json"
    record_path = registry_root / PROVENANCE_DIR / record_name
    if ledger_root is not None:
        ledger_path = Path(ledger_root) / PROVENANCE_DIR / record_name
        if ledger_path.is_file():
            record_path = ledger_path
    if not record_path.is_file():
        return None
    try:
        return json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None  # unreadable/malformed JSON — the review loop fails closed on it too


def _orchestrator_admission(repo: str, pull: dict[str, Any], enrolled_authors: Any) -> Any:
    """[registry #835] The #657 orchestrator-class admission PREDICATE for one open PR, as a
    ``(record, number) -> bool`` callable — or None when this PR is not even a candidate.

    Returning None (rather than a predicate that always says False) is what lets the callers
    skip the record read entirely for the overwhelming majority of PRs, and it keeps the two
    NON-waivable facts at the top where no later change can reorder past them:

    - the FORK GATE. ``head.repo == repo`` is the single attacker-facing predicate here; a fork
      head is attacker-controlled and is never admitted, on any path, by any waiver.
    - a non-empty allowlist and a plausible login. An EMPTY ``review_enrolment_authors`` — every
      repo's default — makes this None for every PR, so groom behaves byte-for-byte as it did.

    The returned predicate is ``admits_orchestrator_pr`` (#821's ONE waiver decision, reused
    rather than re-derived, so "admitted at PLAN/CLAIM" and "suppresses groom's park here"
    cannot drift) conjoined with the shared FIELD admission under its orchestrator opt-in. The
    waived properties are exactly the two producer-shape gates the worker identity applies (the
    head-ref pattern, the App-bot author and its body marker); nothing else."""
    head = pull.get("head") or {}
    head_repo = head.get("repo") or {}
    if (head_repo.get("full_name") if isinstance(head_repo, dict) else None) != repo:
        return None
    login = (pull.get("user") or {}).get("login", "")
    if not enrolled_authors or not isinstance(login, str) or not login:
        return None
    review = _review_loop_module()

    def admits(record: Any, pr_number: int) -> bool:
        return bool(
            review.admits_orchestrator_pr(record, pr_number, login, enrolled_authors)
            and review.provenance_admission_error(
                record, pr_number, admit_orchestrator=True) is None)

    return admits


def _orchestrator_source_issue(
    repo: str, number: int, pull: dict[str, Any], enrolled_authors: Any,
    registry_root: Path = Path("."), ledger_root: Path | None = None,
) -> int | None:
    """[registry #835] The source issue an ADMITTED orchestrator-class PR is bound to, else None.

    The binding is the RECORD's ``issue`` field and nothing else. That is not a weakening: it is
    the same binding the review loop itself dispatches on, and
    research/657-orchestrator-pr-admission.md §7.2 measured that the head ref was never the
    binding for a worker PR either (``HEAD_REF_RE``'s capture group is not consumed anywhere in
    this repository). A worker PR additionally cross-checks branch-vs-record because it HAS a
    branch to cross-check; an orchestrator PR has an ordinary branch by definition."""
    admits = _orchestrator_admission(repo, pull, enrolled_authors)
    if admits is None:
        return None
    record = _read_provenance_json(repo, number, registry_root, ledger_root=ledger_root)
    if not admits(record, number):
        return None
    issue = record["issue"]  # a positive int — guaranteed by the field admission above
    return issue


def _live_provenance_record(
    registry_api: "GitHubAPI", registry_repo: str, repo: str, number: int,
    admits: Any = None,
) -> tuple[str, dict[str, Any] | None]:
    """Read target PR ``repo#number``'s registry provenance record from the LIVE authoritative
    ``ledger`` ref, returning ``(state, record)`` where ``state`` is one of:

    - ``"admits"``       — a schema-admissible record (dispatch-claim.is_enumerable_provenance,
                           the review loop's OWN predicate) exists on the live ref RIGHT NOW;
                           ``record`` is the parsed object. A terminal ``needs:user`` park must be
                           CANCELLED — the PR is review-loop-owned.
    - ``"denies"``       — the live ref conclusively holds NO admissible record: a clean 404 pinned
                           to the VERIFIED ledger tip, or a cleanly-read record the predicate
                           rejects (``record`` is None). The park may proceed — the same fail-closed
                           orphan hand-off the on-disk path makes.
    - ``"indeterminate"``— the read was UNAVAILABLE (registry API/network failure, or a
                           missing/unresolvable ``LEDGER_REF``) or CONFLICTING (a non-file shape,
                           undecodable content, or malformed JSON): admissibility cannot be
                           determined, so the caller must SKIP the terminal mutation and raise an
                           operational alert (never park on an unusable read).

    Both planning and the on-disk mutation-boundary re-check read the IMMUTABLE workflow checkout
    (``registry_root`` / ``--ledger-root``), so a delayed provenance job or backfill that lands
    DURING the sweep is invisible and groom would terminally park an already-valid PR (issue #174).
    This live read is the FINAL gate immediately before the write — it can only CANCEL a park, never
    cause one. Records live in the REGISTRY repo, so it reads via the registry client
    (``REGISTRY_GH_TOKEN``) pinned to the commit sha ``LEDGER_REF`` resolves to at read time —
    the ref is verified to exist before any 404 is trusted, as _read_ledger's branch probe does.

    [registry #835] ``admits`` overrides the ADMISSION only — never the read, the ref probe or
    any of the indeterminate cases. It is the ``(record, number) -> bool`` predicate the caller's
    CLASS admits by, defaulting to the worker one (``is_enumerable_provenance``, which
    deliberately has no orchestrator opt-in). One live-read function, one place where an
    unreadable ledger becomes ``indeterminate``; only the predicate over the bytes differs."""
    owner, _, name = repo.partition("/")
    if not owner or not name:
        raise GroomError("target repository name is malformed")
    record_name = f"{owner}--{name}--pr{number}.json"
    # A Contents 404 does NOT prove the ledger REF exists (review round 1): the API answers 404
    # both for a missing file and for a missing/inaccessible ref or repository, so a deleted or
    # misconfigured LEDGER_REF would read as "no record" and green-light every terminal park.
    # Resolve the ref to its commit sha FIRST (the same file-vs-branch probe _read_ledger makes)
    # and pin the record read to that sha: a 404 below then conclusively means "absent on the
    # verified live tip", while an unresolvable ref is indeterminate — never a park.
    try:
        ref = registry_api.request(
            "GET", f"/repos/{registry_repo}/git/ref/heads/{LEDGER_REF}", allow_404=True
        )
    except GroomError:
        return "indeterminate", None  # unavailable ref resolution — cannot confirm, fail closed
    tip = ref.get("object") if isinstance(ref, dict) else None
    sha = tip.get("sha") if isinstance(tip, dict) else None
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40,64}", sha):
        return "indeterminate", None  # missing/malformed ledger ref — the live source is unreadable
    path = (
        f"/repos/{registry_repo}/contents/{PROVENANCE_DIR}/"
        f"{quote(record_name, safe='')}?ref={sha}"
    )
    try:
        result = registry_api.request("GET", path, allow_404=True)
    except GroomError:
        return "indeterminate", None  # unavailable live read — cannot confirm, fail closed
    if result is None:
        return "denies", None  # clean 404 pinned to the verified tip — genuinely no record
    if (
        not isinstance(result, dict)
        or result.get("type") != "file"
        or not isinstance(result.get("content"), str)
    ):
        return "indeterminate", None  # non-file / malformed metadata — a conflicting read
    try:
        record = json.loads(
            base64.b64decode("".join(result["content"].split()), validate=True).decode()
        )
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return "indeterminate", None  # present-but-undecodable — conflicting, never strand
    if admits is None:
        admits = _review_loop_module().is_enumerable_provenance
    if admits(record, number):
        return "admits", record
    return "denies", None  # cleanly read but not admissible — the orphan-park hand-off stands


def _live_issue_admission(
    registry_api: "GitHubAPI", registry_repo: str, repo: str, number: int,
    pulls: dict[int, dict[str, Any]], bot_login: str, enrolled_authors: Any = (),
) -> str:
    """Live-ref admission for a SINGLE source issue at the terminal mutation boundary (issue #174).

    Among ``pulls`` (freshly re-read open PRs), is a PR BOUND TO ``number`` admitted by a
    schema-valid record on the LIVE ``ledger`` ref? Returns ``"admitted"`` (a valid record for
    its PR now exists live → cancel the exhaustion park), ``"indeterminate"`` (a candidate PR's
    live read was unavailable or conflicting → skip the park and raise an operational alert), or
    ``"denied"`` (the live ref conclusively admits none → the park may proceed).

    Mirrors _admitted_review_prs' identity + issue-binding so the on-disk and live admissions
    cannot drift; only the record SOURCE differs (the live ref instead of the immutable
    checkout). That includes the [#835] orchestrator class: a PR the on-disk admission would
    suppress on but the live boundary would not is the same drift the worker path already
    forbids. An indeterminate read is scoped to THIS issue's candidate PRs, so an unusable read
    on an unrelated PR never blocks this park."""
    bot = bot_login.casefold()
    if not bot:
        return "denied"  # no bot identity — nothing proven, fail closed (park may proceed)
    indeterminate = False
    for pr_number, pull in pulls.items():
        branch = _worker_pr_identity(repo, pull, bot)
        if branch is not None:
            if int(branch.group("issue")) != number:
                continue  # only a worker PR bound to THIS issue can suppress its park
            admits = None                 # the worker predicate (is_enumerable_provenance)
        else:
            # [registry #835] Not worker-shaped — the #657 orchestrator class may still be
            # admitted, on the SAME terms the on-disk admission applies. `None` here means "not
            # even a candidate" (a fork head, an unenrolled author, an empty allowlist), which
            # is the pre-#835 outcome for every PR.
            admits = _orchestrator_admission(repo, pull, enrolled_authors)
            if admits is None:
                continue
        state, record = _live_provenance_record(
            registry_api, registry_repo, repo, pr_number, admits=admits
        )
        if state == "indeterminate":
            indeterminate = True
            continue
        if record is not None and record["issue"] == number:
            return "admitted"  # record and branch agree on the source issue — review-loop-owned
    return "indeterminate" if indeterminate else "denied"


def _worker_pr_identity(
    repo: str, pull: dict[str, Any], bot: str
) -> re.Match[str] | None:
    """The worker-branch match for ``pull`` IFF it clears the worker-PR IDENTITY gate for
    ``repo`` — a worker-pattern head branch, a same-repository head (a fork head is
    attacker-controlled), the App-bot author, and the worker PR body marker — else None.

    This is the identity subset shared by two admissions so they cannot drift: `_admitted_review_prs`
    (which additionally requires the registry-provenance root of trust) and `_current_links`
    (recovery-suppression linkage, issue #172). An outsider's fork PR, a non-bot author, or a PR
    whose body merely says `Fixes #N` must never pass — any of those could otherwise hold a stale
    issue out of recovery or exhaustion-park indefinitely. ``bot`` MUST be the casefolded, non-empty
    bot login; callers fail closed on an unresolved identity before calling."""
    head = pull.get("head") or {}
    ref = head.get("ref", "")
    branch = WORKER_BRANCH.match(ref) if isinstance(ref, str) else None
    if branch is None:
        return None
    head_repo = head.get("repo") or {}
    author = (pull.get("user") or {}).get("login", "")
    body = pull.get("body") or ""
    if (
        (head_repo.get("full_name") if isinstance(head_repo, dict) else None) != repo
        or not isinstance(author, str)
        or author.casefold() != bot
        or not isinstance(body, str)
        or not body.lstrip().startswith(WORKER_PR_MARKER)
    ):
        return None
    return branch


def _admitted_review_prs(
    repo: str,
    pulls: dict[int, dict[str, Any]],
    bot_login: str,
    registry_root: Path = Path("."),
    ledger_root: Path | None = None,
    enrolled_authors: Any = (),
) -> set[int]:
    """Source-issue numbers among ``pulls`` (open PRs) with a PROVEN admitted attempt —
    the ONLY linkage strong enough to suppress the exhausted-attempt defer (issue #170, review
    round 1).

    [registry #835] Named for what it answers — "which source issues does the REVIEW LOOP
    already own a PR for?" — because it is no longer worker-only. Groom was class-blind: an
    enrolled #657 orchestrator PR could not suppress its source issue's exhaustion park, and a
    parked source issue de-enumerates that PR from the review lane silently (no `review:*` label
    means `exclude_signalled` prints nothing, and the park's own machine exit could not see the
    PR either — the other half of #835). The orchestrator class is admitted here on the SAME
    terms a worker PR is, with the two producer-shape gates waived and nothing else; see
    _orchestrator_source_issue.

    Linkage weaker than these admissions (a worker-looking branch or a `Fixes #N` body
    reference) is deliberately NOT trusted for suppression: anyone can open a PR whose body says `Fixes #N`,
    and a fork can spoof a worker-shaped head ref — under loose linkage either would hold an
    exhausted issue out of `needs:user` indefinitely. Suppression instead requires the SAME
    identity and provenance admissions the review loop applies before it will drive a PR
    (dispatch-claim.enumerate_review_items):
    - the head branch matches the worker pattern,
    - the head repo IS the target repo (a fork head is attacker-controlled — never admitted),
    - the author is the App bot,
    - the body self-identifies with the worker PR marker,
    - a VALID registry provenance record exists for the PR (the root of trust — the target
      model cannot write the registry), and its ``issue`` field — the binding the review loop
      itself dispatches on — agrees with the branch-encoded issue (exact repo/issue binding).
    A PR failing ANY admission never suppresses: the review loop will never drive that PR, so
    parking the exhausted issue is the correct fail-closed outcome."""
    admitted: set[int] = set()
    bot = bot_login.casefold()
    if not bot:
        return admitted  # no bot identity resolved — nothing can be proven, fail closed
    for number, pull in pulls.items():
        branch = _worker_pr_identity(repo, pull, bot)
        if branch is None:
            # [registry #835] Not worker-shaped. The #657 orchestrator class is admitted on the
            # same terms; an empty allowlist (every repo's default) makes this constantly None.
            issue = _orchestrator_source_issue(
                repo, number, pull, enrolled_authors, registry_root, ledger_root=ledger_root)
            if issue is not None:
                admitted.add(issue)
            continue
        record = _provenance_record(repo, number, registry_root, ledger_root=ledger_root)
        if record is None:
            continue
        issue = record["issue"]  # a positive int — guaranteed by the admission schema
        if issue != int(branch.group("issue")):
            continue  # record and branch disagree on the source issue — admit neither
        admitted.add(issue)
    return admitted


def stale_worker_pr_reason(
    pull: dict[str, Any],
    bot_login: str,
    threshold_seconds: int,
    now: int,
    *,
    has_valid_provenance: bool,
) -> str | None:
    """Return why an old worker PR needs HUMAN attention, or None when it should remain untouched.

    Scope: this age sweep escalates (1) a NON-DRAFT worker PR wedged in a BAD_MERGE_STATE
    (conflicting/dirty/behind/blocked/unstable/unknown) — a state no automation recovers — and
    (2) a DRAFT worker PR with NO VALID registry provenance record (missing, unreadable, or
    schema-invalid — worker_pr_provenance_enumerable), which no automated loop will ever pick
    up (genuine orphan). A DRAFT worker PR with a VALID provenance record is review-loop-owned
    and is NEVER escalated here — see the draft branch below. Together: no draft is ever
    silently stranded, and no pipeline-owned draft is ever terminally parked."""
    updated = _epoch(pull.get("updated_at"), "pull request")
    if now - updated < threshold_seconds:
        return None
    head = pull.get("head", {}).get("ref", "")
    author = pull.get("user", {}).get("login", "")
    body = pull.get("body") or ""
    if (
        not isinstance(head, str)
        or WORKER_BRANCH.match(head) is None
        or not isinstance(author, str)
        or author.casefold() != bot_login.casefold()
        or not isinstance(body, str)
        or not body.lstrip().startswith(WORKER_PR_MARKER)
    ):
        return None
    if pull.get("draft") is True:
        # [FABLE-5] A DRAFT worker PR with a VALID registry provenance record is
        # REVIEW-LOOP-OWNED, never age-parked here (deadlock fix, live PRs
        # jeswr/agent-account-registry#3472 / #3470). Draft is the NORMAL pre-review pipeline
        # state: dispatch-claim.enumerate_review_items picks the draft up, the review-fix loop
        # reviews it, then undrafts + arms it. A draft awaiting review gets NO `updated_at`
        # bump, so it ages past worker_timeout_minutes purely by WAITING for a (backed-up)
        # review lane — being old is NOT being stuck. Applying `needs:user` here is TERMINAL:
        # it (and a `needs:` label on the source issue) is in
        # dispatch-claim.HUMAN_HOLD_PR_LABELS, which EXCLUDES the PR from
        # enumerate_review_items — so parking a pipeline-owned draft removes it from the exact
        # loop that would otherwise drive it, a self-inflicted deadlock the maintainer reported
        # as "can't be drained". (A starved-but-owned review lane's paging mechanism — a
        # NON-terminal alert keyed on policy `review_queue_ttl_minutes` — is NOT YET WIRED to
        # any consumer; that future mechanism is tracked separately in issue #90 and is NOT
        # relied on here.)
        if has_valid_provenance:
            return None
        # A DRAFT with NO VALID provenance record is a GENUINE ORPHAN owned by no automated
        # loop: the review loop's PLAN, CLAIM, and review-fix.yml resolve all fail closed on a
        # missing/mismatched/malformed record via the ONE shared admission function
        # (dispatch-claim.provenance_admission_error, called here as is_enumerable_provenance —
        # validity means EXACTLY what that loop will admit, alias and issue included), and groom's
        # issue-side orphan repair skips it too (an open draft links its source issue, so
        # `number in links`). Keeping the age-park for exactly this case preserves master's
        # closure guarantee — a human hand-off instead of silence — without re-arming the
        # deadlock for the valid-provenance majority above. (Gating on FILE EXISTENCE alone
        # would strand the malformed-record case: groom-preserved, never enumerated.)
        return ORPHAN_DRAFT_REASON
    merge_state = pull.get("mergeable_state")
    if merge_state is None:
        merge_state = "unknown"
    if not isinstance(merge_state, str):
        raise GroomError("pull request merge state is malformed")
    return BAD_MERGE_STATES.get(merge_state)


# ---- the ONE diagnostic-masking contract (issue #644 defect 1, extended by issue #647) ----------
# #644: `gh` writes its failure cause to stderr and groom CAPTURED then DISCARDED it, so every
# failing run said only "parked PR redraft failed for <repo>#<n>" — three hours of identical
# failures with zero diagnostic information, and it cost a full incident to characterise.
# #647: the SAME discard exists on the HTTP side. Every per-object write in the stale-PR hand-off
# and issue-repair loops is an `api.request`, and its GroomError reported only
# "<purpose> GitHub API POST failed with HTTP 403" — GitHub's own error envelope ("Resource not
# accessible by integration", "Validation Failed: …"), the one thing that distinguishes a
# permission refusal from a bad payload, was thrown away with the exception. A silent failure in a
# loop is exactly what made the last one expensive, so both surfaces report their cause through
# this ONE helper: BOUNDED — a runaway body must not flood the operator log — and credential-MASKED.
GH_DETAIL_LIMIT = 400
# Belt-and-braces on top of the exact-token replacement: any GitHub credential SHAPE is masked, so
# a token this call does not own (an ambient GH_TOKEN, a nested gh diagnostic, an echoed header)
# cannot reach the log either.
_TOKEN_SHAPE = re.compile(r"(?:gh[pousra]|github_pat)_[A-Za-z0-9_]{8,}")


def _masked_detail(text: str, token: str) -> str:
    """One single-line, bounded, credential-masked diagnostic — the shared masking contract."""
    text = " ".join((text or "").split())
    if token:
        text = text.replace(token, "***")
    text = _TOKEN_SHAPE.sub("***", text)
    if len(text) > GH_DETAIL_LIMIT:
        text = text[:GH_DETAIL_LIMIT] + "…"
    return text


def _http_failure_detail(exc: HTTPError, token: str) -> str:
    """GitHub's own masked, bounded error envelope for a failed call, or "" when it carried none.

    The envelope is a DIAGNOSTIC, not resource content: GitHub answers a failed call with
    ``{"message": …, "documentation_url": …}``. Reading it must never itself raise — an HTTPError
    constructed without a body (or already consumed) has no readable stream — so every failure
    mode here degrades to the status line's own reason rather than replacing one lost cause with
    another (issue #647).
    """
    raw: Any = b""
    try:
        raw = exc.read()
    except Exception:  # noqa: BLE001 — a diagnostic read must never mask the real failure
        raw = b""
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", "replace")
    else:
        text = str(raw or "")
    detail = _masked_detail(text, token)
    if detail:
        return detail
    return _masked_detail(
        str(getattr(exc, "msg", "") or getattr(exc, "reason", "") or ""), token
    )


class GitHubAPI:
    def __init__(self, token: str, purpose: str):
        if not token:
            raise GroomError(f"{purpose} token is missing")
        self._token = token
        self._purpose = purpose

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        allow_404: bool = False,
        retry_conflict: bool = False,
    ) -> Any:
        if not path.startswith("/") or "\n" in path or "\r" in path:
            raise GroomError("unsafe GitHub API path")
        payload = json.dumps(body).encode() if body is not None else None
        request = Request(
            "https://api.github.com" + path,
            data=payload,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "private-registry-groom-reg5",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if payload is not None else {}),
            },
        )
        retryable = method.upper() in _IDEMPOTENT_METHODS
        for attempt in range(1, _TRANSIENT_RETRIES + 1):
            try:
                with urlopen(request, timeout=30) as response:
                    raw = response.read()
                break
            except HTTPError as exc:
                if allow_404 and exc.code == 404:
                    return None
                # Issue #647: report WHY. This exception is the only witness a per-object write
                # failure ever gets, and the loops that call it now defer per object instead of
                # aborting the sweep — a deferral whose cause is "HTTP 403" and nothing else is
                # the #644 discarded-cause defect wearing a different hat. Read HERE, before the
                # branches below: `exc.read()` is single-shot, and issue #240's 422 classifier
                # needs the same envelope the fail-loud raise reports.
                detail = _http_failure_detail(exc, self._token)
                if retry_conflict and _is_cas_conflict(
                    exc.code, detail, create=_is_create_put(method, body)
                ):
                    raise GroomConflict("lease ledger compare-and-swap conflict") from exc
                if (retryable and _is_transient_status(exc.code)
                        and attempt < _TRANSIENT_RETRIES):
                    _sleep_transient(attempt, _retry_after_seconds(exc.headers))
                    continue
                raise GroomError(
                    f"{self._purpose} GitHub API {method} failed with HTTP {exc.code}"
                    + (f": {detail}" if detail else "")
                ) from exc
            except (URLError, TimeoutError, ConnectionResetError) as exc:
                if retryable and _is_transient_network(exc) and attempt < _TRANSIENT_RETRIES:
                    _sleep_transient(attempt)
                    continue
                raise GroomError(f"{self._purpose} GitHub API request failed") from exc
        try:
            return json.loads(raw or b"null")
        except json.JSONDecodeError as exc:
            raise GroomError(
                f"{self._purpose} GitHub API returned malformed JSON"
            ) from exc

    def paginate(self, path: str) -> list[Any]:
        # The page walk continues until a short page; the explicit ceiling only guards a runaway
        # snapshot. It was raised from 1000 -> 5000 ahead of the full bd->issue migration (~900
        # new open issues would otherwise hard-stop grooming; /issues also counts open PRs).
        separator = "&" if "?" in path else "?"
        items: list[Any] = []
        for page in range(1, 51):
            result = self.request("GET", f"{path}{separator}per_page=100&page={page}")
            if not isinstance(result, list):
                raise GroomError(
                    f"{self._purpose} GitHub API returned a malformed page"
                )
            items.extend(result)
            if len(result) < 100:
                return items
        raise GroomError(f"{self._purpose} snapshot may be truncated at 5000 entries")


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise GroomError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _policy_document(policy_file: Path) -> Any:
    try:
        with policy_file.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GroomError("repository policy could not be read") from exc


def _enrolled_authors(resolver: Any, repo: str, document: Any) -> tuple[str, ...]:
    """[registry #835] The repo's master-protected `review_enrolment_authors`, sorted.

    Resolved through ``policy-resolve.review_enrolment_authors`` — the accessor that validates
    the whole policy row — for the same reason PLAN, CLAIM and review-fix.yml resolve it that
    way (#657): a hand-rolled read of the TOML key would happily parse a malformed or
    `[bot]`-bearing list, and with the head-ref gate waived a `[bot]` entry would widen the
    trusted-App author gate to ANY installed App. Absent/empty => enrolment OFF."""
    return tuple(sorted(resolver.review_enrolment_authors(repo, document)))


def load_limits(policy_file: Path, resolver_file: Path) -> dict[str, Limits]:
    document = _policy_document(policy_file)
    repos = document.get("repos") if isinstance(document, dict) else None
    if not isinstance(repos, dict) or not repos:
        raise GroomError("repository policy has no target rows")
    resolver = _load_module(resolver_file, "registry_policy_resolve")
    limits: dict[str, Limits] = {}
    for repo, raw in repos.items():
        if not isinstance(repo, str) or SAFE_REPO.fullmatch(repo) is None:
            raise GroomError("repository policy contains an unsafe target name")
        if not isinstance(raw, dict) or not isinstance(raw.get("enabled"), bool):
            raise GroomError(f"repository policy enablement is malformed for {repo}")
        if not raw["enabled"]:
            continue
        try:
            row = resolver._policy_row(repo, document)
        except (
            Exception
        ) as exc:  # PolicyError is owned by the dynamically loaded module.
            raise GroomError(f"repository policy validation failed for {repo}") from exc
        limits[repo] = Limits(
            worker_timeout_minutes=_positive_int(
                row.get("worker_timeout_minutes"), f"worker timeout for {repo}"
            ),
            max_attempts=_positive_int(
                row.get("max_attempts"), f"max attempts for {repo}"
            ),
            # [registry #835] Read through policy-resolve's OWN accessor, never a hand-rolled
            # TOML read: that accessor VALIDATES the whole row, and its validation is the only
            # thing keeping a `[bot]` login (i.e. another GitHub App) out of the allowlist.
            enrolled_authors=_enrolled_authors(resolver, repo, document),
        )
    if not limits:
        raise GroomError("repository policy has no enabled target rows")
    return limits


# Exact owner -> GITHUB_OUTPUT key map for the per-owner App-token mint steps in groom.yml
# (issue #168). The workflow's mint steps are STATIC (one step per known owner), so the
# resolver below fails LOUD when policy's enabled owner set drifts from this map — a silently
# dropped owner would reintroduce the wrong-owner-token bug.
EXPECTED_TARGET_OWNERS = {"sparq-org": "sparq_names", "jeswr": "jeswr_names"}


def owner_repos_from_names(names: Any) -> dict[str, list[str]]:
    """Group an ``owner/name`` sequence into ``{owner: [name, ...]}`` — EVERY repo per owner, in
    input order, duplicates collapsed. Shared by the policy path (groom/curate/conflict-resolver)
    and dispatch.yml's ``DISPATCH_TARGET_REPOS`` manifest path (issue #273): both mint ONE App
    token per owner, so keeping a single "representative" repo per owner scopes that token to one
    repo and 404s every read/write on the owner's other targets. Unsafe names fail closed."""
    if not isinstance(names, list) or not names:
        raise GroomError("target repo list is empty or not a JSON array")
    owners: dict[str, list[str]] = {}
    for repo in names:
        if not isinstance(repo, str) or SAFE_REPO.fullmatch(repo) is None:
            raise GroomError("target repo list contains an unsafe name")
        owner, name = repo.split("/", 1)
        bucket = owners.setdefault(owner, [])
        if name not in bucket:
            bucket.append(name)
    return owners


def enabled_owner_repos(document: Any) -> dict[str, list[str]]:
    """EVERY enabled repo name per owner (issue #168, review round 1). Each per-owner App-token
    mint must be scoped to ALL of that owner's enabled repositories — a single "representative"
    repo would mint a token that 404s the owner's other enabled repos, and groom (which routes
    tokens per OWNER) would then abort mid-sweep on a supported policy shape."""
    repos = document.get("repos") if isinstance(document, dict) else None
    if not isinstance(repos, dict) or not repos:
        raise GroomError("repository policy has no target rows")
    enabled: list[str] = []
    for repo, raw in repos.items():
        if not isinstance(repo, str) or SAFE_REPO.fullmatch(repo) is None:
            raise GroomError("repository policy contains an unsafe target name")
        if not isinstance(raw, dict) or not isinstance(raw.get("enabled"), bool):
            raise GroomError(f"repository policy enablement is malformed for {repo}")
        if raw["enabled"]:
            enabled.append(repo)
    if not enabled:
        raise GroomError("repository policy has no enabled target rows")
    return owner_repos_from_names(enabled)


def _owner_repo_lines(owners: dict[str, list[str]], source: str) -> list[str]:
    """GITHUB_OUTPUT lines (``<key>=name1,name2``) scoping each static mint step's
    ``repositories`` input to that owner's FULL repo list. Fails LOUD unless the owner set is
    exactly ``EXPECTED_TARGET_OWNERS`` — never silently drops an owner's token."""
    if set(owners) != set(EXPECTED_TARGET_OWNERS):
        raise GroomError(
            f"unexpected target owners {sorted(owners)}; {source} mints tokens for exactly "
            f"{sorted(EXPECTED_TARGET_OWNERS)} — add a mint step before widening the target set"
        )
    return [f"{key}={','.join(owners[owner])}" for owner, key in EXPECTED_TARGET_OWNERS.items()]


def owner_repo_output_lines(document: Any) -> list[str]:
    """Mint-scope GITHUB_OUTPUT lines for the POLICY-driven sweeps (groom/curate/
    conflict-resolver), covering every enabled repo of every enabled owner."""
    return _owner_repo_lines(enabled_owner_repos(document), "groom.yml")


def manifest_owner_repo_output_lines(raw: Any) -> list[str]:
    """Mint-scope GITHUB_OUTPUT lines for dispatch.yml (issue #273), whose owners come from the
    ``DISPATCH_TARGET_REPOS`` manifest (a JSON array of ``owner/name``) rather than from policy.
    CLAIM routes the minted token by OWNER, so each owner's token must carry every manifest repo
    under that owner. A manifest that is not a JSON array of safe names fails CLOSED."""
    try:
        targets = json.loads(raw)
    except (TypeError, ValueError):
        raise GroomError("target manifest is not valid JSON") from None
    return _owner_repo_lines(owner_repos_from_names(targets), "dispatch.yml")


def ledger_read_path(registry_repo: str) -> str:
    """Contents-API GET path for the lease ledger, pinned to the data-plane branch."""
    return f"/repos/{registry_repo}/contents/{LEDGER_PATH}?ref={LEDGER_REF}"


def ledger_put_body(message: str, encoded: str, sha: str | None) -> dict[str, str]:
    """Contents-API PUT body for the lease ledger, pinned to the data-plane branch (a PUT
    without `branch` commits to the protected default branch and is rejected). A falsy sha is
    OMITTED: that is the contents-API create-if-absent form for a file 404 on a PRESENT branch."""
    body = {"message": message, "content": encoded, "branch": LEDGER_REF}
    if sha:
        body["sha"] = sha
    return body


def _read_ledger(
    api: GitHubAPI, registry_repo: str
) -> tuple[list[dict[str, Any]], str | None]:
    result = api.request("GET", ledger_read_path(registry_repo), allow_404=True)
    if result is None:
        # File-absent vs branch-absent (issue #28, review round 1): a missing FILE on a PRESENT
        # ledger branch seeds an empty ledger (sha=None → the next CAS PUT creates it); a missing
        # BRANCH fails LOUD, never silently-empty — grooming against a missing ledger branch
        # would mask the exact outage class this ref exists to prevent.
        branch = api.request(
            "GET", f"/repos/{registry_repo}/git/ref/heads/{LEDGER_REF}", allow_404=True
        )
        if branch is None:
            raise GroomError(
                f"registry lease ledger read returned 404 and the '{LEDGER_REF}' ledger branch "
                "is missing — create it (see data/README.md)"
            )
        return [], None
    if not isinstance(result, dict):
        raise GroomError("registry lease ledger response is malformed")
    content = result.get("content")
    sha = result.get("sha")
    if not isinstance(content, str) or not isinstance(sha, str) or not sha:
        raise GroomError("registry lease ledger metadata is malformed")
    try:
        document = json.loads(
            base64.b64decode("".join(content.split()), validate=True).decode()
        )
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GroomError("registry lease ledger content is malformed") from exc
    return validate_ledger(document), sha


# ---- CAS retry backoff (issue #179) -------------------------------------------------------------
# groom-leases (select-and-claim reclaim) and this sweep both CAS-write the shared ledger tip on
# overlapping crons; immediate no-backoff retries let a synchronized burst (claim/release/heartbeat/
# model-health) re-collide on every attempt and exhaust all six. A full-jitter exponential sleep
# between attempts decorrelates the writers so a loser waits a random amount and re-reads a settled
# tip. Ceiling is deterministic (unit-tested) and the RNG only draws within it. Kept in sync with
# select-and-claim.py's identical schedule.
def _backoff_ceiling(attempt: int, base: float = 0.5, cap: float = 8.0) -> float:
    """Upper bound (seconds) for the sleep before CAS retry `attempt` (1-based): exponential
    base*2**(attempt-1), clamped to `cap`."""
    return min(cap, base * (2 ** (attempt - 1)))


def _sleep_backoff(attempt: int) -> None:
    """Sleep a full-jitter exponential backoff before CAS retry `attempt` (module-level so the
    self-test can stub it without sleeping)."""
    time.sleep(random.uniform(0, _backoff_ceiling(attempt)))


# ---- which failures the caller's CAS re-read loop owns (issue #240) -----------------------------
# `retry_conflict` used to read EVERY HTTP 422 as lost contention, so an ordinary request-validation
# failure (bad payload, missing branch) was retried until `_release_claims` exhausted its attempts
# and reported "lease ledger CAS conflicts did not settle" — GitHub's real cause discarded on the
# way, which is the #644/#647 lost-diagnostic defect wearing a third hat.
#
# HTTP 409 is always a lost-SHA race. A 422 is one in exactly ONE shape: a sha-less
# create-if-absent PUT whose file appeared concurrently, which the contents API answers with
# 'Invalid request.\n\n"sha" wasn't supplied.'. That is the same narrowing PR #229 applied to
# select-and-claim's `_is_cas_conflict`, and the signature is taken from the SHARED ledger_retry
# policy so the two ledger writers cannot drift apart on it.
_ledger_retry = _load_module(
    Path(__file__).resolve().with_name("ledger_retry.py"), "registry_ledger_retry"
)
_CREATE_RACE_SIGNATURE = _ledger_retry.CREATE_RACE_SIGNATURE


def _is_create_put(method: str, body: Any) -> bool:
    """True for the contents-API CREATE-IF-ABSENT form: a PUT carrying no `sha` (`ledger_put_body`
    omits it when the ledger file was 404 on a present branch). Only that form can lose the create
    race — an update PUT already names the revision it expects, so its 422 is validation."""
    return method.upper() == "PUT" and not (isinstance(body, dict) and body.get("sha"))


def _is_cas_conflict(code: int, detail: str, *, create: bool) -> bool:
    """True only for a compare-and-swap race the caller's ledger re-read loop owns.

    `detail` is GitHub's error envelope exactly as `_http_failure_detail` returns it: raw JSON
    SOURCE, never parsed (it is a diagnostic), so the message's inner quotes arrive backslash-
    escaped as ``\\"sha\\"`` — the backslashes are dropped before matching so the one shared
    signature string stays the single source of truth. A `detail` bounded short of the signature
    simply fails LOUD, which is the safe direction: the next scheduled sweep re-reads the ledger,
    whereas a mis-classified validation error spins the retry loop to the same failure.
    """
    if code == 409:
        return True
    return code == 422 and create and _CREATE_RACE_SIGNATURE in (detail or "").replace("\\", "")


# ---- transient-network retry (issue #494) -------------------------------------------------------
# A scheduled sweep died on a raw http.client.RemoteDisconnected out of api.paginate -> request():
# one transient TCP hiccup killed the ENTIRE hygiene pass, and groom's O(issues) comment fetches
# (#36) maximise the exposure. request() now retries only genuinely TRANSIENT failures — the
# RemoteDisconnected / ConnectionReset / timeout family and every 5xx (issue #291 — this was a
# {502, 503, 504} allow-list, so a plain HTTP 500 killed two sweeps in 4.5h) — with bounded
# full-jitter backoff, honouring a (capped) Retry-After. It still fails closed on every 4xx
# (auth/permission) and on a CAS conflict (409, or the create-race 422 above), which has its own
# caller-owned ledger re-read loop.
#
# Retries apply ONLY to reads. A dropped connection or gateway 5xx on a mutation does not prove
# GitHub skipped the attempt — replaying a POST duplicates comments and replaying a PATCH/PUT can
# repeat or overwrite a state transition. PUT/DELETE are nominally idempotent in HTTP but not in
# effect here (the ledger contents PUT is CAS-keyed on a sha a completed first attempt consumes),
# so mutations get NO transparent replay: an ambiguous failure fails loud and the next scheduled
# sweep reconciles from re-read state, exactly as before #494.
#
# The loop/sleep MECHANICS (attempt bound, exponential-jitter schedule, Retry-After cap) are the
# fleet-shared gh_retry policy (registry #563 adoption item 4 — one tuned copy, not N drifting
# ones). The CLASSIFICATION predicates are groom's own POLICY, exactly as reviewed in #494 and
# widened in #291 — but since registry #552 they are DECLARED, not re-implemented here: the
# classifier and groom's opt-in live in the shared `http_transient` taxonomy, beside
# plan-snapshot's, so the deliberate difference between the two (groom excludes 429 and the whole
# 4xx family; plan-snapshot opts 429 in) is visible and asserted in ONE place instead of being
# implied by two hand-written tables in two files that nothing compared.
#
# The names below are ALIASES of the shared definitions, never second copies — rebinding is what
# makes divergence impossible, and `#552 the transient classifier IS the shared one` in the
# self-test pins the delegation so nobody can quietly re-inline it.
_gh_retry = _load_module(Path(__file__).resolve().with_name("gh_retry.py"), "registry_gh_retry")
_http_transient = _load_module(
    Path(__file__).resolve().with_name("http_transient.py"), "registry_http_transient"
)
_IDEMPOTENT_METHODS = {"GET", "HEAD"}
_TRANSIENT_RETRIES = _gh_retry.MAX_ATTEMPTS  # total attempts before a transient failure fails loud
_RETRY_AFTER_CAP = _gh_retry.RETRY_AFTER_CAP  # never let a hostile Retry-After stall the sweep

# groom's declared opt-in: the WHOLE 5xx range and no 4xx at all (429 and 403 excluded — see the
# policy's own `rationale`, which carries the #291/#494 history that used to live in the docstring
# of the predicate it replaces). The retry it feeds is additionally gated on `_IDEMPOTENT_METHODS`,
# so no mutation ever reaches it.
_TRANSIENT_STATUS_POLICY = _http_transient.GROOM_SWEEP
_is_transient_status = _TRANSIENT_STATUS_POLICY.retries
_is_transient_network = _http_transient.is_transient_network


def _retry_after_seconds(headers: Any) -> float | None:
    """Parse a numeric Retry-After (seconds) into a capped delay; None when absent/unparseable so
    the caller falls back to exponential backoff. HTTP-date forms are treated as absent (rare from
    GitHub) rather than mis-parsed, and a negative value is ignored."""
    raw = headers.get("Retry-After") if headers is not None else None
    if raw is None:
        return None
    try:
        seconds = float(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if seconds < 0:
        return None
    return min(seconds, _RETRY_AFTER_CAP)


def _sleep_transient(attempt: int, retry_after: float | None = None) -> None:
    """Sleep before a transient retry: honour a (capped) Retry-After when the server sent one, else
    gh_retry's shared exponential-jitter schedule (2s->30s). Module-level so the self-test can stub
    it without sleeping."""
    _gh_retry.sleep_backoff(attempt, retry_after)


def _release_claims(
    api: GitHubAPI, registry_repo: str, claims: set[str], retries: int = 6
) -> int:
    if not claims:
        return 0
    for attempt in range(retries):
        if attempt:
            _sleep_backoff(attempt)
        leases, sha = _read_ledger(api, registry_repo)
        present = {lease["claim_id"] for lease in leases} & claims
        if not present:
            return 0
        remaining = [lease for lease in leases if lease["claim_id"] not in present]
        encoded = base64.b64encode(
            (json.dumps({"leases": remaining}, indent=1) + "\n").encode()
        ).decode()
        try:
            result = api.request(
                "PUT",
                f"/repos/{registry_repo}/contents/{LEDGER_PATH}",
                ledger_put_body(f"groom {len(present)} dead lease(s)", encoded, sha),
                retry_conflict=True,
            )
        except GroomConflict:
            continue
        if isinstance(result, dict) and isinstance(result.get("content"), dict):
            for claim in sorted(present):
                print(f"WRITE lease release claim={claim[:8]}")
            return len(present)
    raise GroomError("lease ledger CAS conflicts did not settle")


# ---- burned account-slot report (issue #245) ----------------------------------------------------
#
# `set-up-account` takes ATOMIC ownership of an account slot by creating `refs/acct-claims/acctNN`
# BEFORE the `gh secret set` upsert (#186, hardened after review round 1 of #236), and a run that
# fails AFTER claiming deliberately PRESERVES its claim: the slot is burned, never reused, because
# releasing it would let a different credential overwrite an in-flight one — exactly the race the
# claim exists to close. The manual runbook in README.md observes the same protocol.
#
# Burned slots are therefore SAFE but INVISIBLE — nothing ever counted them, so a broker whose
# enrolments keep failing burns numbers indefinitely with no signal. This report names them.
#
# DELIBERATELY REPORT-ONLY, and deliberately in groom (the maintenance sweep) rather than in the
# broker: it never deletes a claim ref and offers no opt-in mode that would, because deletion
# re-opens the credential-overwrite race the claim closes.
#
# PRIVACY (locked decision 22b — public logs never carry an account handle): an ORPHANED slot names
# NO account. Carrying neither an acctNN issue nor an ACCTNN_TOKEN secret is precisely what makes it
# orphaned, so there is no account, no credential and no usage to correlate it with, and the claim
# ref it names is already a world-readable git ref on this PUBLIC repo. Slots that DO back an
# account are only ever COUNTED here, never named.
ACCT_CLAIM_REF_RE = re.compile(r"^refs/acct-claims/acct([0-9]+)$")
ACCT_ISSUE_TITLE_RE = re.compile(r"^acct([0-9]+)$")
ACCT_SECRET_NAME_RE = re.compile(r"^ACCT([0-9]+)_TOKEN$")
# The names-only ACCTNN_TOKEN inventory groom.yml's least-exposure filter step derives from the
# job's `toJSON(secrets)` context (dispatch.yml's `acct-secrets` pattern): only that tiny inline
# step ever sees the secrets map, and only NAMES reach this process.
ACCT_SECRET_NAMES_ENV = "ACCT_SECRET_NAMES"
ORPHAN_CLAIM_NOTE = (
    "ORPHAN-CLAIMS report-only — NEVER delete a claim ref: a burned slot is harmless, while "
    "recycling its number re-opens the credential-overwrite race the claim closes "
    "(`gh secret set` is an upsert, and GitHub does not enforce unique issue titles)."
)


def claim_ref_slots(refs: Any) -> dict[int, str]:
    """Pure: {slot number: ref} for every `refs/acct-claims/acctNN` in a matching-refs payload.

    FAIL CLOSED on a malformed payload instead of returning whatever parsed. A silently short
    CLAIM listing under-reports burned slots; a silently short issue/secret listing OVER-reports
    them, and naming a live credential's slot as burned is what would invite a maintainer to
    "clean up" the very ref protecting it.

    An AMBIGUOUS listing fails closed for the same reason (review round 1 of #1167). Refs are
    distinct as STRINGS but this map — like every allocation reader in the estate — keys on the
    NUMBER, so `acct1` and `acct01` are two real claims and one key. Keeping the last writer would
    silently drop the other from `claims=`, from `burned=` and from the named rows, which is
    exactly the short claim listing this function exists to refuse."""
    if not isinstance(refs, list):
        raise GroomError("acct-claims ref listing is malformed")
    slots: dict[int, str] = {}
    for entry in refs:
        ref = entry.get("ref") if isinstance(entry, dict) else None
        if not isinstance(ref, str):
            raise GroomError("acct-claims ref listing is malformed")
        match = ACCT_CLAIM_REF_RE.match(ref)
        if match:
            slot = int(match.group(1))
            if slot in slots:
                # Deliberately names NEITHER ref NOR slot number, matching the messages above:
                # locked decision 22b keeps account-backed slots counted, never named.
                raise GroomError(
                    "acct-claims ref listing is ambiguous — two distinct refs name the same "
                    "account slot number"
                )
            slots[slot] = ref
    return slots


def account_issue_slots(issues: Any) -> set[int]:
    """Pure: slot numbers of `acctNN` ACCOUNT ISSUES in ANY state, from an /issues payload.

    Pull requests are skipped — /issues returns both, and a PR titled `acctNN` is not an account
    record (the same `select(has("pull_request") | not)` filter the broker's slot union applies).
    Closed and retired account issues DO count: their numbers stay permanently reserved, so a
    claim behind one is allocated, not burned."""
    if not isinstance(issues, list):
        raise GroomError("account issue listing is malformed")
    slots: set[int] = set()
    for item in issues:
        if not isinstance(item, dict):
            raise GroomError("account issue listing is malformed")
        if "pull_request" in item:
            continue
        title = item.get("title")
        if not isinstance(title, str):
            raise GroomError("account issue listing is malformed")
        match = ACCT_ISSUE_TITLE_RE.match(title)
        if match:
            slots.add(int(match.group(1)))
    return slots


def account_secret_slots(names: Any) -> set[int]:
    """Pure: slot numbers of the `ACCTNN_TOKEN` names in the derived secret inventory."""
    if not isinstance(names, list):
        raise GroomError(f"{ACCT_SECRET_NAMES_ENV} is malformed")
    slots: set[int] = set()
    for name in names:
        if not isinstance(name, str):
            raise GroomError(f"{ACCT_SECRET_NAMES_ENV} is malformed")
        match = ACCT_SECRET_NAME_RE.match(name)
        if match:
            slots.add(int(match.group(1)))
    return slots


def parse_acct_secret_names(raw: Any) -> list[str]:
    """Pure: the ACCTNN_TOKEN secret NAMES groom.yml's least-exposure filter derived from the
    job's secrets context, as a JSON array of strings.

    FAIL CLOSED on absent, blank or malformed input. Without a PROVEN secret inventory a slot
    holding a live credential is indistinguishable from a burned one, so an unproven "no secret"
    would report live slots as burned — the one wrong answer that could get a real credential's
    claim ref deleted. An empty array is a PROVEN-empty inventory and is accepted."""
    if not isinstance(raw, str) or not raw.strip():
        raise GroomError(
            f"{ACCT_SECRET_NAMES_ENV} is unset or empty, so no ACCTNN_TOKEN secret can be proven "
            "absent — refusing to report any slot as burned (fail closed)"
        )
    try:
        names = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GroomError(
            f"{ACCT_SECRET_NAMES_ENV} is not valid JSON — refusing to report any slot as burned "
            "(fail closed)"
        ) from exc
    if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
        raise GroomError(
            f"{ACCT_SECRET_NAMES_ENV} is not a JSON array of secret names — refusing to report "
            "any slot as burned (fail closed)"
        )
    return names


def orphaned_claim_slots(
    claims: dict[int, str] | set[int], issue_slots: set[int], secret_slots: set[int]
) -> list[int]:
    """Pure: sorted slots that own a claim ref but carry NEITHER an acctNN issue NOR an
    ACCTNN_TOKEN secret — the slots a failed enrolment burned.

    Both exclusions are load-bearing. A claim + secret with no issue is a STORED CREDENTIAL (the
    enrolment died between the upsert and the issue), not a burned slot; a claim + issue with no
    secret is an account mid-enrolment. Neither is free, and neither is what this reports.
    Slots with an issue or a secret but NO claim are the legacy/out-of-band numbers the namespace
    was never backfilled for — allocated, not burned, and outside this report."""
    return sorted(set(claims) - issue_slots - secret_slots)


def format_orphan_claim_report(
    claims: dict[int, str], issue_slots: set[int], secret_slots: set[int]
) -> list[str]:
    """Pure: the report lines. One counted summary, one named line per burned slot."""
    orphans = orphaned_claim_slots(claims, issue_slots, secret_slots)
    lines = [
        f"ORPHAN-CLAIMS claims={len(claims)} account_issues={len(issue_slots)} "
        f"account_secrets={len(secret_slots)} burned={len(orphans)}"
    ]
    for slot in orphans:
        lines.append(
            f"ORPHAN-CLAIM {claims[slot]}: slot claimed, but no acct{slot:02d} issue and no "
            f"ACCT{slot:02d}_TOKEN secret exist — burned by a failed enrolment"
        )
    lines.append(
        ORPHAN_CLAIM_NOTE
        if orphans
        else "ORPHAN-CLAIMS none — every claimed slot has an account issue or a stored credential"
    )
    return lines


def report_orphan_claims(args: argparse.Namespace) -> int:
    """Report the burned account slots. READ-ONLY: three listings and a print, no mutation.

    The secret inventory is resolved FIRST and fails closed, so a run that cannot prove which
    ACCTNN_TOKEN secrets exist refuses before it reads anything else — it never degrades into
    reporting every claimed slot as burned."""
    registry_repo = args.registry_repo
    if SAFE_REPO.fullmatch(registry_repo) is None:
        raise GroomError("registry repo must be a safe owner/name")
    secret_slots = account_secret_slots(
        parse_acct_secret_names(os.environ.get(ACCT_SECRET_NAMES_ENV))
    )
    api = GitHubAPI(os.environ.get("REGISTRY_GH_TOKEN", ""), "registry")
    # Both listings are FULLY PAGINATED, for the reason the broker's union is: a capped page
    # silently drops account issues (over-reporting burned slots) or claim refs (under-reporting
    # them). A listing that fails raises — the report refuses rather than guessing.
    claims = claim_ref_slots(
        api.paginate(f"/repos/{registry_repo}/git/matching-refs/acct-claims/")
    )
    issue_slots = account_issue_slots(
        api.paginate(f"/repos/{registry_repo}/issues?state=all")
    )
    for line in format_orphan_claim_report(claims, issue_slots, secret_slots):
        print(line)
    return 0


def _labels(item: dict[str, Any], where: str) -> set[str]:
    raw = item.get("labels")
    if not isinstance(raw, list):
        raise GroomError(f"{where} labels are malformed")
    names: set[str] = set()
    for label in raw:
        name = label.get("name") if isinstance(label, dict) else None
        if not isinstance(name, str) or not name or "\n" in name or "\r" in name:
            raise GroomError(f"{where} carries a malformed label")
        names.add(name)
    return names


def _issues(api: GitHubAPI, repo: str) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for item in api.paginate(f"/repos/{repo}/issues?state=open"):
        if not isinstance(item, dict):
            raise GroomError(f"target issue snapshot is malformed for {repo}")
        if "pull_request" in item:
            continue
        number = item.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise GroomError(f"target issue number is malformed for {repo}")
        _labels(item, f"target issue {repo}#{number}")
        _epoch(item.get("updated_at"), f"target issue {repo}#{number}")
        comments = item.get("comments")
        if not isinstance(comments, int) or isinstance(comments, bool) or comments < 0:
            raise GroomError(
                f"target issue comment count is malformed for {repo}#{number}"
            )
        if number in result:
            raise GroomError(f"target issue snapshot contains duplicates for {repo}")
        result[number] = item
    return result


def _pulls(api: GitHubAPI, repo: str) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for pull in api.paginate(f"/repos/{repo}/pulls?state=open"):
        if not isinstance(pull, dict):
            raise GroomError(f"target pull request snapshot is malformed for {repo}")
        number = pull.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise GroomError(f"target pull request number is malformed for {repo}")
        _epoch(pull.get("updated_at"), f"target pull request {repo}#{number}")
        linked_issue_numbers(pull)
        if number in result:
            raise GroomError(
                f"target pull request snapshot contains duplicates for {repo}"
            )
        result[number] = pull
    return result


def _comments(api: GitHubAPI, repo: str, number: int) -> list[dict[str, Any]]:
    comments = api.paginate(f"/repos/{repo}/issues/{number}/comments")
    for comment in comments:
        if not isinstance(comment, dict):
            raise GroomError(f"target comments are malformed for {repo}#{number}")
        login = comment.get("user", {}).get("login")
        body = comment.get("body")
        if not isinstance(login, str) or not isinstance(body, str):
            raise GroomError(f"target comment fields are malformed for {repo}#{number}")
    return comments


def _configured_stale_hours(args: argparse.Namespace) -> int:
    """Configured quiet period for parked-PR defusing (``STALE_HOURS``, default six)."""
    raw: Any = getattr(args, "stale_hours", None)
    if raw is None:
        raw = os.environ.get("STALE_HOURS", str(DEFAULT_STALE_HOURS))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise GroomError("STALE_HOURS must be a positive integer") from exc
    if isinstance(raw, bool) or value <= 0 or str(raw).strip() != str(value):
        raise GroomError("STALE_HOURS must be a positive integer")
    return value


def _parked_pr_snapshot(
    pull: dict[str, Any], now: int, stale_seconds: int, bot_login: str
) -> tuple[str, str] | None:
    """Return the stable head/activity fingerprint of a defuse candidate, absent its latches."""
    if pull.get("draft") is not False:
        return None
    labels = _labels(pull, "parked pull request")
    if not (labels & HUMAN_HOLD_PR_LABELS):
        return None
    # Defuse exists to stop OUR OWN parked PRs burning target CI while they wait on a human. A
    # human's pull request is not ours to re-draft: the human-hold label means the decision is
    # theirs, and converting their PR to draft is the machine mutating a person's artifact.
    #
    # This is also where a permanent red came from (2026-07-25): sparq-org/sparq#3427 is authored
    # by the maintainer and labelled `needs:user`, so every sweep selected it, every redraft came
    # back `Resource not accessible by integration (convertPullRequestToDraft)`, and — being the
    # only candidate — it tripped precedence rule 2 ("attempted, none completed") on every tick
    # for hours. The fix belongs HERE, in candidate selection, and NOT in phase_exit_failure:
    # weakening the exit rule to tolerate a stuck object would buy exactly the silence that rule
    # is written to prevent. An object that was never ours to touch is not a failed attempt.
    #
    # Fail direction: unknown or malformed authorship SKIPS. The permissive answer here would be
    # to mutate a PR whose owner we could not establish, which is the wrong way round.
    #
    # Ownership is EXACT LOGIN **and** `type == "Bot"`, conjunctively. Two review rounds, two
    # different halves:
    #
    #   r1: `type == "Bot"` ALONE is not ownership — it admits `dependabot[bot]`, `copilot`,
    #       and every third-party App, and the reviewer drove one through live revalidation to
    #       a real `gh pr ready --undo` plus an audit comment. The obligation is "OUR OWN
    #       parked PRs", a single login, so a predicate over the category is the wrong scope.
    #   r2: replacing it with exact login ALONE dropped the type check entirely, so a payload
    #       carrying our login with NO `type`, or with a contradictory `type: "User"`, was
    #       admitted. The r1 "malformed authorship" fixture only ever exercised a FOREIGN
    #       login, so it was rejected for the wrong reason and pinned nothing.
    #
    # Both conjuncts are load-bearing and each has its own test. A well-formed payload for our
    # own App satisfies both; anything that fails either — unknown identity, absent type,
    # contradictory type — is somebody else's PR as far as this guard is concerned, which is
    # the direction that declines to mutate.
    if not bot_login:
        return None
    user = pull.get("user")
    if not isinstance(user, dict):
        return None
    login = user.get("login")
    if not isinstance(login, str) or login.casefold() != bot_login.casefold():
        return None
    if user.get("type") != "Bot":
        return None
    updated_at = pull.get("updated_at")
    updated = _epoch(updated_at, "parked pull request")
    if now - updated < stale_seconds:
        return None
    head = pull.get("head")
    head_sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(head_sha, str) or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
        raise GroomError("parked pull request head sha is malformed")
    assert isinstance(updated_at, str)  # guaranteed by _epoch
    return head_sha, updated_at


def _merge_latch_state(api: GitHubAPI, repo: str, number: int) -> tuple[bool, bool]:
    """Return live ``(queued, auto_merge_requested)`` state, failing closed on shape errors."""
    owner, name = repo.split("/", 1)
    query = (
        "query($owner:String!,$name:String!,$number:Int!){"
        "repository(owner:$owner,name:$name){pullRequest(number:$number){"
        "mergeQueueEntry{id} autoMergeRequest{enabledAt}}}}"
    )
    document = api.request(
        "POST",
        "/graphql",
        {
            "query": query,
            "variables": {"owner": owner, "name": name, "number": number},
        },
    )
    pull = None
    if isinstance(document, dict):
        data = document.get("data")
        repository = data.get("repository") if isinstance(data, dict) else None
        pull = repository.get("pullRequest") if isinstance(repository, dict) else None
    if (
        not isinstance(pull, dict)
        or "mergeQueueEntry" not in pull
        or "autoMergeRequest" not in pull
        or (
            pull["mergeQueueEntry"] is not None
            and not isinstance(pull["mergeQueueEntry"], dict)
        )
        or (
            pull["autoMergeRequest"] is not None
            and not isinstance(pull["autoMergeRequest"], dict)
        )
    ):
        raise GroomError("parked pull request merge-latch state is unknown")
    return pull["mergeQueueEntry"] is not None, pull["autoMergeRequest"] is not None


def _live_defuse_snapshot(
    api: GitHubAPI,
    repo: str,
    number: int,
    pull: dict[str, Any],
    now: int,
    stale_seconds: int,
    bot_login: str,
) -> tuple[str, str] | None:
    """The complete safe-class predicate, including both live merge latch surfaces."""
    if pull.get("state") != "open":
        return None
    snapshot = _parked_pr_snapshot(pull, now, stale_seconds, bot_login)
    if snapshot is None:
        return None
    # REST auto_merge is intentionally an additional fail-closed signal. GraphQL is live and
    # authoritative, but an unexpectedly surviving REST latch must never be redrafted by groom.
    if "auto_merge" not in pull:
        raise GroomError("parked pull request auto_merge state is unknown")
    if pull["auto_merge"] is not None:
        return None
    queued, auto_merge_requested = _merge_latch_state(api, repo, number)
    if queued or auto_merge_requested:
        return None
    return snapshot


def _collect_defuse_prs(
    api: GitHubAPI,
    repo: str,
    pulls: dict[int, dict[str, Any]],
    now: int,
    stale_seconds: int,
    bot_login: str,
) -> dict[tuple[str, int], tuple[str, str]]:
    """Collect live safe-class parked PRs; an unreadable latch skips only that PR."""
    candidates: dict[tuple[str, int], tuple[str, str]] = {}
    for number, listed in sorted(pulls.items()):
        try:
            if _parked_pr_snapshot(listed, now, stale_seconds, bot_login) is None:
                continue
            detail = api.request("GET", f"/repos/{repo}/pulls/{number}", allow_404=True)
            if not isinstance(detail, dict):
                continue
            snapshot = _live_defuse_snapshot(
                api, repo, number, detail, now, stale_seconds, bot_login
            )
        except GroomError as exc:
            print(f"ALERT PR {repo}#{number}: {exc} — defuse deferred")
            continue
        if snapshot is not None:
            candidates[(repo, number)] = snapshot
    return candidates


def _gh_failure_detail(result: Any, token: str) -> str:
    """The masked, bounded, single-line cause of a failed `gh` call — never the token itself."""
    text = _masked_detail(
        " ".join(
            part.strip()
            for part in (getattr(result, "stderr", "") or "", getattr(result, "stdout", "") or "")
            if part.strip()
        ),
        token,
    )
    if not text:
        return f"gh exited {result.returncode} with no output"
    return f"gh exited {result.returncode}: {text}"


def _redraft_pr(repo: str, number: int, token: str) -> None:
    if not token:
        raise RedraftUnavailable(
            f"target token is unavailable for parked PR {repo}#{number}"
        )
    env = dict(os.environ)
    env["GH_TOKEN"] = token
    try:
        result = subprocess.run(
            ["gh", "pr", "ready", str(number), "-R", repo, "--undo"],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except FileNotFoundError as exc:
        raise RedraftUnavailable("gh is unavailable for parked PR defuse") from exc
    if result.returncode != 0:
        raise GroomError(
            f"parked PR redraft failed for {repo}#{number}: "
            f"{_gh_failure_detail(result, token)}"
        )


@dataclass(frozen=True)
class PhaseOutcome:
    """What one per-object sweep phase did, and whether its failures were per-object or systemic.

    Introduced for the defuse phase (issue #644) and made the SHARED shape for every per-object
    phase of the sweep (issue #647), so all of them are judged by the ONE precedence rule below
    instead of each inventing its own leniency.
    """

    label: str = "parked PR defuse"  # phase name, as it reads in the exit report
    changed: int = 0  # objects whose phase work COMPLETED (a deliberate skip counts; see below)
    attempted: int = 0  # objects this phase took up
    deferred: tuple[str, ...] = ()  # per-object deferrals, "<repo>#<n>: <cause>"
    unavailable: tuple[str, ...] = ()  # NON-per-object failures (no gh, no owner token)


def phase_exit_failure(outcome: PhaseOutcome) -> str | None:
    """The systemic reason the run must exit non-zero, or None to leave its status green.

    PRECEDENCE RULE (issue #644, applied to EVERY per-object phase by issue #647 — there is
    exactly one of these in this module, deliberately). The sibling defect class here is
    exit-zero-swallows-failure, so the direction matters: making a failure per-object must never
    buy silence.

      1. A NON-per-object failure DOMINATES. No `gh`, or no App token for the owner, is a property
         of the run, not of the object, so the status goes non-zero even if every other candidate
         completed fine.
      2. Otherwise, if the phase took objects up and NONE completed, the per-object reading is no
         longer credible — a whole-phase failure is systemic in effect — so the status goes
         non-zero and names every deferral.
      3. Otherwise a deferral ALONGSIDE at least one completed object is exactly what it claims to
         be: one object's problem, ALERT-logged and retried next sweep. The status stays green.
      4. In every case this is decided AFTER the sweep has done its work. The exit status is the
         REPORT, never the control flow — that inversion is the #644 defect itself, where one
         un-redraftable PR raised past dead-lease reclaim, stuck-issue repair and the stale-PR
         hand-off. Callers therefore evaluate this last, after _release_claims.

    Rule 2 fires on `deferred` as well as on `attempted` (issue #647). A phase whose per-object
    failure happens in a READ — before it counts the object as attempted — must not be able to
    report nothing-completed-and-something-failed as green; the disjunction makes that swallow
    unrepresentable rather than merely unlikely. It is a no-op for the defuse phase, which counts
    the attempt before anything it records as a deferral.

    A deliberate SKIP counts as a COMPLETED object, not a failure: a phase that correctly decided
    to do nothing to every object it saw is a working phase (this is what keeps rule 2 from
    red-flagging, say, a hand-off loop whose every candidate was revalidated away). Defuse keeps
    its own narrower counting — deferrals from its PRE-redraft revalidation are recorded nowhere,
    since those reads already failed closed per PR before #644 and counting them would change an
    unrelated path's status semantics.
    """
    if outcome.unavailable:
        return (
            f"{outcome.label} is unavailable for the whole run: "
            + "; ".join(outcome.unavailable)
        )
    if (outcome.attempted or outcome.deferred) and not outcome.changed:
        return (
            f"every {outcome.label} failed ({outcome.attempted} attempted, 0 completed): "
            + "; ".join(outcome.deferred)
        )
    return None


def sweep_exit_failure(outcomes: "list[PhaseOutcome] | tuple[PhaseOutcome, ...]") -> str | None:
    """EVERY phase's systemic failure, joined — never just the first (issue #647).

    The sweep has eight per-object phases — stale-PR detection, issue status repair, parked-PR
    defuse, age-park re-admission, stale-PR hand-off, and (issue #649) the target-repo snapshot,
    the attempt-budget read and the terminal-reap revalidation — and they fail independently.
    Reporting only the first would hide a second systemic failure behind a fixed one, so each phase
    is judged by the one precedence rule and every reason is named. A phase whose outcome is built
    and then NOT handed to this function is a swallowed failure by construction; the self-test pins
    the call's argument list against every PhaseOutcome run_sweep constructs.
    """
    reasons = [
        reason
        for outcome in outcomes
        if (reason := phase_exit_failure(outcome)) is not None
    ]
    return " | ".join(reasons) if reasons else None


# Issue #644's names for the defuse instance of the shared shape above. Kept as ALIASES, not
# copies: the enrolled #644 assertions keep their exact call sites while there stays exactly one
# precedence implementation in the module (issue #647 requirement — reuse the rule, do not invent
# a second one).
DefuseOutcome = PhaseOutcome
defuse_exit_failure = phase_exit_failure


def age_park_cause_recovered(
    cause: str,
    pull: dict[str, Any],
    live_provenance: Callable[[], tuple[str, dict[str, Any] | None]],
) -> tuple[bool, str]:
    """Has THIS park's OWN cause provably recovered? Returns (recovered, why).

    This is the machine exit, and it is gated on the CAUSE, never on elapsed time — the same
    discipline park_policy invariant 3 applies to a capacity park. Each cause has one predicate:

    - ``orphan-draft`` — an ADMISSIBLE registry provenance record now exists on the LIVE ledger
      ref. That is exactly the predicate _live_provenance_record already computes to CANCEL a
      park, reused to CLEAR one, so "the review loop will drive this PR" cannot mean two things.
    - ``merge-*``      — the live ``mergeable_state`` is no longer one of BAD_MERGE_STATES.

    Every ambiguity fails toward STAYING PARKED: an unreadable/conflicting provenance read, a
    malformed merge state, and an unrecognised cause token all return False. An unrecognised
    token in particular must never re-admit — a cause we cannot check is a cause we cannot prove
    recovered, and guessing here would turn the bounded exit into an unbounded retry."""
    if cause == "orphan-draft":
        state, _record = live_provenance()
        if state == "admits":
            return True, "an admissible provenance record now exists on the live ledger ref"
        if state == "indeterminate":
            return False, "the live provenance read was unavailable or conflicting"
        return False, "still no admissible provenance record on the live ledger ref"
    if cause.startswith("merge-"):
        merge_state = pull.get("mergeable_state")
        if merge_state is None:
            merge_state = "unknown"
        if not isinstance(merge_state, str):
            return False, "the live merge state is malformed"
        if merge_state in BAD_MERGE_STATES:
            return False, f"the merge state is still {merge_state}"
        return True, f"the merge state recovered to {merge_state}"
    return False, f"cause {cause!r} has no recovery predicate — never auto-re-admitted"


def _execute_age_unpark_actions(
    pulls: dict[str, dict[int, dict[str, Any]]],
    apis: dict[str, GitHubAPI],
    registry_api: "GitHubAPI",
    registry_repo: str,
    bot_login: str,
) -> tuple[PhaseOutcome, int, int, int]:
    """Re-admit MACHINE age-parks whose own cause has provably recovered — the exit that makes the
    class split honest.

    Relabelling an age park from the human terminal to the machine soft hold WITHOUT this phase
    would be strictly worse than the defect it replaces: `needs:user` is at least visible in a
    human census, whereas a `review:parked` nothing can clear is an INVISIBLE permanent hold.
    park_policy's own automatic path cannot supply this exit WHOLESALE — capacity_park_admission is
    gated on per-account model-health recovery evidence that no orphan-draft or wedged-merge-state
    park will ever satisfy, and its cap counts worker-pr's AUTO_READMIT_MARKER, so routing groom's
    age receipts through it would make the two re-admission budgets consume each other. The sweep
    that KNOWS the cause therefore owns clearing it — but every GUARD that mechanism applies is
    obtained by CALLING park_policy (park_vetoed, label_application_machine_owned,
    park_applications for recency, valid_timestamp/parse_ts/canonical_ts), never by reproducing
    it. Two rounds of this PR shipped a mirrored mechanism missing a guard the original had;
    nothing here re-implements a park_policy decision.

    Bounded exactly as invariant 3 bounds the capacity path:
      - CAUSE-GATED. age_park_cause_recovered, never elapsed time.
      - CONSUMED EXACTLY ONCE. The un-park receipt carries the park receipt's own
        (cause, head, gen) triple; age_unpark_state reports that grant, so one recovery can never
        be re-earned — a further re-admission needs a NEW park at a new fingerprint.
      - CAPPED. Enforced upstream at park time by age_park_label: generation > AGE_UNPARK_MAX is
        written in the HUMAN class, so an over-cap park never reaches this phase at all.
      - NEVER CLEARS A LABEL IT CANNOT PROVE IS MACHINE-APPLIED. Every unlabel — the ordinary grant
        AND the convergence retry — is authorised by park_policy.label_application_machine_owned
        for THAT EXACT LABEL (the #690 predicate; park_applications is the wrong API for this and
        is never used for it here). It returns False for every ambiguity: a human-latest
        application, no `labeled` event at all, an unreadable timeline, a malformed shape.
      - RECEIPT-FIRST, WITH A REAL CONVERGENCE BRANCH. The receipt is posted BEFORE the unlabel, so
        the only crash residue is receipt-no-label. That does NOT resolve itself — nothing re-parks
        a PR whose cause has recovered — so the branch below retries the unlabel, gated on the
        grant being STRICTLY NEWER than every park application (registry #614's `auto-receipt`
        recency conjunct). `review:parked` is a SHARED MULTI-WRITER label, so without that conjunct
        a different writer's later park is deleted off this sweep's stale grant.

      - EVERY UNLABEL IS VERIFIED (issue #83). The receipt is public before the DELETE runs, so a
        DELETE that returns 2xx without the label actually leaving would be reported as a
        re-admission that never happened. _label_gone proves the post-state; an unproven removal
        defers the PR instead of counting.
      - AND THE CONTRADICTION IT CANNOT FIX IS REPORTED, NOT SKIPPED. When a human-owned hold
        makes the convergence retry permanently refuse while a grant that is PROVABLY THE LIVE
        LABEL'S OWN (the same recency conjunct, _grant_is_current) is already on record, the PR
        publicly claims a re-admission its labels contradict. That is ALERTed and corrected ON THE
        PR (one comment per grant fingerprint, no label write) — the log alone is a cron nobody
        reads, which is how four sparq PRs stayed in that state for ~17 hours. A grant OLDER than
        the live park is a completed re-admission plus a later, unrelated park: no contradiction,
        and a correction there would point a human at undoing a valid park.

    Every failure is PER-PR: one unreadable PR never stops the rest.

    Returns (outcome, grants, convergences, stalls). GRANTS are new re-admissions and are what
    AGE_UNPARK_MAX governs; CONVERGENCES are retries of one already-authorised, never-effected
    write and change no decision — they are counted apart so neither can be read as the other.
    STALLS are neither: they are a GAUGE of PRs currently in the announced-but-held contradiction,
    re-counted every tick because the state persists until a human acts."""
    attempted = 0
    completed = 0
    unparked = 0      # NEW grants: one per park receipt, governed by AGE_UNPARK_MAX
    converged = 0     # RETRIES of an already-granted, never-effected unlabel: state-change-free
    stalled = 0       # GAUGE: re-admissions announced on PRs a human-owned hold still holds out
    deferrals: list[str] = []
    for repo, api in apis.items():
        for number, listed in sorted(pulls.get(repo, {}).items()):
            labels = _labels(listed, f"target pull request {repo}#{number}")
            if park_policy.MACHINE_PARK_PR_LABEL not in labels:
                continue
            attempted += 1
            failed = False
            try:
                # THE ONE RULE, and this phase must obey it like every other automatic exit
                # (park_policy.human_owned_holds; blocking review finding #769). Measured on the
                # real function before this line existed: a PR wearing BOTH `review:parked` and
                # `needs:user` was granted its re-admission — `grants=1`, one un-park receipt
                # minted, `review:parked` deleted. Nothing human was cleared, so invariant 3 was
                # not violated in the literal sense, and that is exactly what made it easy to
                # miss: the harm is that the ONE automatic recovery this park will ever earn was
                # SPENT on a PR that provably could not re-enter, because the live `needs:user`
                # keeps every downstream admission refusing. The recovery is consume-once, so it
                # could never be re-earned, and the PR's next age park would land a generation
                # higher for no reason it caused.
                #
                # Checked BEFORE both write branches — the ordinary grant AND the convergence
                # retry — because both end in a label DELETE. The park simply stands; a human is
                # the exit, which is what a human-owned hold means.
                #
                # It is checked AFTER the comments read, which the first cut deliberately avoided
                # to save an API call on held PRs (issue #83). That saving bought the silence:
                # "held" and "held while this PR's own record says it was re-admitted" are the
                # same label state and opposite situations, and only the receipts tell them apart.
                # The extra read is bounded to PRs wearing the machine park AND a human hold —
                # the intersection this branch exists for — and it never authorises a write.
                comments = _comments(api, repo, number)
                owed, granted = age_unpark_state(comments, bot_login)
                held = park_policy.human_owned_holds(labels)

                def _grant_is_current(grant: dict[str, Any]) -> tuple[bool, str]:
                    """Is THIS grant STRICTLY NEWER than every park application on the PR?

                    A grant matching the newest park receipt proves a re-admission was once
                    earned. It does NOT prove that the `review:parked` live RIGHT NOW is the label
                    that grant attempted to remove: the label is a SHARED MULTI-WRITER one
                    (dispatch-claim at two sites, worker-pr's capacity park), so a grant that
                    completed perfectly still matches while a LATER, unrelated park stands.

                    BOTH readers of that question ask it here, so they cannot drift:
                      - the convergence retry, which would otherwise DELETE a different writer's
                        later park off this sweep's stale grant (registry #614's recency conjunct);
                      - the stall correction, which would otherwise tell a human that a completed
                        re-admission is "withdrawn" and invite them to remove a park that is a
                        distinct later decision — misleading trust-plane evidence pointing at the
                        wrong action.

                    Fail-closed in every direction: an unreadable receipt stamp, an unreadable
                    timeline and an instant TIE all answer False, and park_applications absorbs a
                    raising timeline into `readable=False` rather than into permission. It
                    AUTHORISES NOTHING — the delete authorisation remains _clearable() /
                    label_application_machine_owned, and the stall caller writes no label at all.
                    """
                    stamp = grant.get("at")
                    if not park_policy.valid_timestamp(stamp):
                        return False, ("the un-park receipt carries no readable timestamp, so it "
                                       "cannot be proven newer than the park")
                    # park_applications is the RIGHT api here, and is NOT the #690 misuse: #690 is
                    # about authorising the DELETE of one specific label with evidence about three.
                    # This asks its documented question — "when was the newest park applied" — and
                    # a park on ANY park label refuses, the conservative direction.
                    latest_park, _human, readable = park_policy.park_applications(
                        repo, number, None,
                        lambda r, n: api.paginate(f"/repos/{r}/issues/{n}/timeline"),
                        is_human=lambda login: _is_human_maintainer(api, repo, login))
                    if not readable:
                        return False, ("the park application timeline could not be read, so the "
                                       "grant cannot be proven current")
                    if latest_park is not None and park_policy.parse_ts(stamp) <= latest_park:
                        return False, (
                            f"a park application at "
                            f"{park_policy.canonical_ts(latest_park.isoformat())} is NEWER than "
                            f"the un-park receipt at {park_policy.canonical_ts(stamp)} — this "
                            "label is a DIFFERENT park, not the one that receipt cleared")
                    return True, "the grant is newer than every park application"

                if held:
                    print(f"age park stands {repo}#{number}: human-owned hold(s) live "
                          f"({'/'.join(held)}) — a machine never un-parks past a human decision, "
                          "and spends no re-admission on a PR that could not re-enter anyway")
                    # ISSUE #83 — THE CONTRADICTION SWEEP. A grant receipt for the newest park is
                    # on record, so this PR publicly says "re-admitted, back in the ordinary
                    # review loop", while the machine park label AND a human-owned hold keep it
                    # out of every lane. That is not a park standing quietly: it is a PR whose
                    # last groom action tells every reader — human included — that nothing needs
                    # doing. It cannot self-heal, because the convergence retry below refuses for
                    # as long as the hold is live and the machine may never clear the hold itself.
                    # Four sparq PRs sat exactly here for ~17h.
                    #
                    # So it is REPORTED, in the one place the human who must act will look, and
                    # NOTHING is written to a label. `granted` is tested for truthiness, not
                    # `is not None`: age_unpark_state's early returns pair a None park with a
                    # literal False.
                    #
                    # SCOPE, deliberately: this is anchored on the MACHINE park still being live,
                    # which is the state where the announcement and the labels contradict each
                    # other. A held PR whose machine park is GONE is not this defect — the
                    # re-admission did exactly what it said, and the hold on top of it is a
                    # separate human decision groom may neither clear nor second-guess. Reporting
                    # that shape would put a comment on every human-held PR the loop ever
                    # re-admitted, which is noise a maintainer learns to filter, and filtered
                    # alerts are how the next 17 hours get missed.
                    #
                    # AND THE GRANT MUST BE PROVABLY THE LIVE LABEL'S GRANT (_grant_is_current,
                    # the same conjunct the convergence branch applies for the same reason). A
                    # matching grant alone is a HISTORICAL fact: age-park -> recover -> grant ->
                    # the un-park lands -> another writer parks the PR later -> a human holds it,
                    # and every receipt still matches while nothing is contradictory at all. The
                    # correction would then tell a human the completed re-admission is withdrawn
                    # and point them at removing a park that is a separate, later decision. An
                    # ALERT that names the wrong action is worse than the silence #83 replaced,
                    # so an unproven grant is reported as the park standing and nothing else.
                    current, why_current = (
                        _grant_is_current(granted) if owed is not None and granted
                        else (False, ""))
                    if why_current and not current:
                        print(f"age park stands {repo}#{number}: a re-admission receipt is on "
                              f"record, but {why_current}; no stall is reported against a park "
                              "this grant cannot be shown to have cleared")
                    if current:
                        stalled += 1
                        print(f"ALERT PR {repo}#{number}: an automatic re-admission for "
                              f"(cause={owed['cause']}, gen={owed['gen']}) is on record, yet "
                              f"`{park_policy.MACHINE_PARK_PR_LABEL}` is still live under "
                              f"human-owned hold(s) ({'/'.join(held)}) — this PR's record says "
                              "re-admitted while its labels hold it out, and no automatic path "
                              "can resolve that")
                        if unpark_stall_pending(comments, bot_login, granted):
                            api.request(
                                "POST", f"/repos/{repo}/issues/{number}/comments",
                                {"body": unpark_stall_comment(
                                    park_policy.MACHINE_PARK_PR_LABEL, held, granted)},
                            )
                            print(f"WRITE un-park stall correction repo={repo} pr={number} "
                                  f"cause={granted['cause']} gen={granted['gen']}")
                    continue
                if owed is None:
                    continue  # not an age park of ours, or over the cap (human class)

                def _clearable() -> bool:
                    """May an automated path delete THIS EXACT label right now?

                    park_policy.label_application_machine_owned, never park_applications
                    (blocking review finding #690). park_applications answers a question about
                    READMISSION_LABELS *collectively* — "when was the newest park applied across
                    needs:user / status:parked / review:parked, and was that human" — and using it
                    to authorise deleting ONE specific label is a domain mismatch that fails in
                    directions this call site reaches: a HUMAN-applied `review:parked` reads as
                    machine-owned the moment any bot writes a LATER `needs:user` event, and a live
                    label with no `labeled` event at all reads absence as permission. The correct
                    predicate proves ownership OF THIS LABEL, and returns False for every
                    ambiguity — human-latest, no event, unreadable, malformed. It is the same
                    function dispatch-claim authorises its own label deletions with, so "may not
                    clear there" and "may not clear here" cannot drift."""
                    return park_policy.label_application_machine_owned(
                        repo, number, park_policy.MACHINE_PARK_PR_LABEL,
                        lambda r, n: api.paginate(f"/repos/{r}/issues/{n}/timeline"),
                        is_human=lambda login: _is_human_maintainer(api, repo, login))

                def _label_gone(response: Any) -> bool:
                    """Did the park label ACTUALLY leave the PR? (issue #83)

                    A 2xx on the DELETE is not the same fact. The receipt is already public by
                    the time this runs, so an unverified removal reported as a removal is how the
                    PR ends up saying "re-admitted" while wearing the park — the contradiction the
                    stall sweep above has to clean up after.

                    GitHub's own 200 body for this endpoint is the post-state (the labels that
                    REMAIN), so when it is a list it settles the question with no extra call.
                    Anything else — a 404 absorbed by allow_404, an empty 204 body, an opaque
                    payload — proves nothing on its own, so the live label set is read back. A
                    read that fails RAISES, and the per-PR handler defers this PR: unverifiable
                    is never treated as verified.

                    A MALFORMED entry is unverifiable too, and it fails the same way. Skipping the
                    entries it cannot parse would make an unreadable post-state look like an empty
                    one — i.e. read "I cannot tell" as "the label is gone", which is the exact
                    direction this whole check exists to close."""
                    remaining = response if isinstance(response, list) else api.paginate(
                        f"/repos/{repo}/issues/{number}/labels")
                    names = set()
                    for item in remaining:
                        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                            return False
                        names.add(item["name"])
                    return park_policy.MACHINE_PARK_PR_LABEL not in names

                def _drop_label() -> None:
                    response = api.request(
                        "DELETE",
                        f"/repos/{repo}/issues/{number}/labels/"
                        f"{quote(park_policy.MACHINE_PARK_PR_LABEL, safe='')}",
                        allow_404=True,
                    )
                    if not _label_gone(response):
                        # Deferred, not swallowed: the grant/convergence counter is never reached,
                        # the phase records the deferral, and the NEXT tick's convergence branch
                        # retries the unlabel off the receipt already on record.
                        raise GroomError(
                            f"the `{park_policy.MACHINE_PARK_PR_LABEL}` DELETE returned success "
                            f"but the label is still live on {repo}#{number}")
                    print(f"WRITE remove label repo={repo} issue={number} "
                          f"label={park_policy.MACHINE_PARK_PR_LABEL}")

                if granted is not None:
                    # CONVERGENCE (registry #614's `auto-receipt` branch). The receipt for this
                    # exact recovery is already on record, yet the machine label is still live.
                    # Receipt-first ordering makes receipt-no-label the only crash residue
                    # possible, and one plain HTTP transient on the DELETE reaches it. Treating it
                    # as "already consumed, skip" strands the PR under `review:parked` permanently
                    # — its cause has recovered, so the hand-off derives no reason and never
                    # re-parks it, and nothing else clears it.
                    #
                    # THE RECENCY CONJUNCT, which the mirrored version dropped and which is what
                    # makes this safe. `auto-receipt` fires only when the receipt is STRICTLY
                    # NEWER than the newest park application (`parse_ts(stamp) > latest_park`).
                    # Without it, "the label is present" was read as "my un-park never landed" —
                    # but `review:parked` is a SHARED MULTI-WRITER label (dispatch-claim at two
                    # sites, worker-pr's capacity park), so its presence proves *a* writer parked
                    # this PR, never that THIS sweep did. A DIFFERENT writer's LATER park was
                    # therefore deleted off this sweep's stale receipt. Live shape: age-park ->
                    # recover -> unpark -> the account starves -> worker-pr capacity-parks ->
                    # every groom tick deletes it -> re-park. Uncapped ping-pong, which is exactly
                    # the flap #614/#691's cap exists to bound, and it sat OUTSIDE that cap
                    # because convergence mints no receipt.
                    #
                    # Recency closes it STRUCTURALLY rather than by counting: a re-park is a NEWER
                    # `labeled` event than the grant, so convergence refuses and the ordinary
                    # capped path handles it as the new park it is. What remains under this branch
                    # is only ever a RETRY of one already-authorised, never-effected write, so it
                    # is counted separately from grants and can never become one.
                    # The delete authorisation remains _clearable() /
                    # label_application_machine_owned; this conjunct only proves WHICH park the
                    # live label is.
                    current, why_current = _grant_is_current(granted)
                    if not current:
                        print(f"age park stands {repo}#{number}: {why_current}")
                        continue
                    if not _clearable():
                        print(f"age park stands {repo}#{number}: "
                              f"`{park_policy.MACHINE_PARK_PR_LABEL}` is not provably "
                              "machine-applied — only a human clears it")
                        continue
                    print(f"CONVERGE PR {repo}#{number}: an un-park receipt for "
                          f"(cause={owed['cause']}, gen={owed['gen']}) is already on record and "
                          "newer than every park application, but the label survived — completing "
                          "the interrupted unlabel")
                    _drop_label()
                    converged += 1
                    continue

                pull = api.request("GET", f"/repos/{repo}/pulls/{number}", allow_404=True)
                if not isinstance(pull, dict) or pull.get("state") != "open":
                    print(f"SKIP PR {repo}#{number}: no longer open")
                    continue
                recovered, why = age_park_cause_recovered(
                    owed["cause"], pull,
                    lambda: _live_provenance_record(
                        registry_api, registry_repo, repo, number),
                )
                if not recovered:
                    print(f"age park stands {repo}#{number} (cause={owed['cause']} "
                          f"gen={owed['gen']}): {why}")
                    continue
                if not _clearable():
                    print(f"age park stands {repo}#{number}: "
                          f"`{park_policy.MACHINE_PARK_PR_LABEL}` is not provably "
                          "machine-applied — only a human clears it")
                    continue
                receipt = (f"{AGE_UNPARK_MARKER} cause={owed['cause']} head={owed['head']} "
                           f"gen={owed['gen']} -->")
                api.request(
                    "POST", f"/repos/{repo}/issues/{number}/comments",
                    {"body": ("> 🤖 SPARQ agent\n\n"
                              f"Automatic re-admission: {why}, so the machine-owned "
                              f"`{park_policy.MACHINE_PARK_PR_LABEL}` age park is cleared and this "
                              "PR re-enters the ordinary review loop. This recovery is now "
                              f"consumed and cannot be re-earned.\n\n{receipt}")},
                )
                print(f"WRITE age-unpark receipt repo={repo} pr={number} cause={owed['cause']} "
                      f"gen={owed['gen']}")
                _drop_label()
                unparked += 1
            except Exception as exc:  # noqa: BLE001 — see below; this PR defers, the sweep runs on
                # DELIBERATELY BROADER than the GroomError the sibling loops catch (issue #647).
                # This phase calls into park_policy, whose timestamp primitives raise ValueError on
                # a shape they reject — and a non-GroomError escaping here aborts the whole sweep
                # before _release_claims, which is precisely the head-of-line abort #644/#647 exist
                # to prevent, reachable from one malformed receipt on one PR. "Each PR defers
                # ITSELF" has to mean every failure, not just the anticipated class. The deferral
                # is LOUD: it is ALERTed and fed to the shared exit precedence, so a systemic
                # failure still reds the run.
                failed = True
                detail = _masked_detail(str(exc), "")
                print(f"ALERT PR {repo}#{number}: {detail} — age un-park deferred")
                deferrals.append(f"{repo}#{number}: {detail}")
                continue
            finally:
                if not failed:
                    completed += 1
    return (
        PhaseOutcome(label="age park re-admission", changed=completed, attempted=attempted,
                     deferred=tuple(deferrals)),
        unparked,
        converged,
        stalled,
    )


def _execute_defuse_actions(
    actions: list[PullAction],
    apis: dict[str, GitHubAPI],
    tokens: dict[str, str],
    now: int,
    stale_seconds: int,
    bot_login: str = "",
) -> DefuseOutcome:
    """Revalidate and redraft bounded safe-class actions, then write one audit comment.

    EVERY per-PR failure mode degrades to "defuse deferred" for THAT PR and continues — including
    the redraft and its audit comment (issue #644). Candidates are processed lowest-number-first,
    so an un-redraftable one used to be a PERMANENT head-of-line block: its uncaught GroomError
    raised past dead-lease reclaim, stuck-issue repair and the stale-PR hand-off, and groom failed
    on every run for hours. A PR that cannot be converted to draft is not a reason to stop
    reclaiming dead leases. The failures are RECORDED, not swallowed: defuse_exit_failure decides
    the run's exit status from this outcome once the sweep has finished.
    """
    changed = 0
    attempted = 0
    deferred: list[str] = []
    unavailable: list[str] = []
    for action in actions:
        if action.mode != "defuse":
            continue
        api = apis[action.repo]
        try:
            pull = api.request(
                "GET", f"/repos/{action.repo}/pulls/{action.number}", allow_404=True
            )
            snapshot = (
                _live_defuse_snapshot(
                    api,
                    action.repo,
                    action.number,
                    pull,
                    now,
                    stale_seconds,
                    bot_login,
                )
                if isinstance(pull, dict)
                else None
            )
        except GroomError as exc:
            print(f"ALERT PR {action.repo}#{action.number}: {exc} — defuse deferred")
            continue
        if snapshot != (action.head_sha, action.updated_at):
            print(
                f"SKIP PR {action.repo}#{action.number}: activity, head, hold, or draft state changed"
            )
            continue
        owner = action.repo.split("/", 1)[0]
        attempted += 1
        body = (
            "> 🤖 SPARQ agent\n\n"
            f"This pull request remained ready-for-review while terminally parked and had no "
            f"head or timeline activity for at least {stale_seconds // 3600} hours. Groom "
            "converted it to draft so it no longer occupies its orchestration partition. "
            "Marking it ready for review resumes it.\n\n"
            f"{DEFUSE_PR_MARKER}"
        )
        # The mutation pair sits INSIDE the same per-PR resilience block as the revalidation above
        # (issue #644 defect 2). RedraftUnavailable is caught FIRST — it is a subclass, and it is
        # the not-a-property-of-this-PR case, so it is recorded separately and reds the run.
        try:
            _redraft_pr(action.repo, action.number, tokens.get(owner, ""))
            api.request(
                "POST",
                f"/repos/{action.repo}/issues/{action.number}/comments",
                {"body": body},
            )
        except RedraftUnavailable as exc:
            print(
                f"ALERT PR {action.repo}#{action.number}: {exc} — defuse deferred "
                "(not a property of this PR; this run fails after the sweep completes)"
            )
            unavailable.append(f"{action.repo}#{action.number}: {exc}")
            continue
        except GroomError as exc:
            print(f"ALERT PR {action.repo}#{action.number}: {exc} — defuse deferred")
            deferred.append(f"{action.repo}#{action.number}: {exc}")
            continue
        print(f"WRITE defuse parked PR repo={action.repo} pr={action.number}")
        changed += 1
    return DefuseOutcome(
        changed=changed,
        attempted=attempted,
        deferred=tuple(deferred),
        unavailable=tuple(unavailable),
    )


# A single newest-100 worker-run page is NOT enough to correlate every live lease (issue #173):
# once >100 newer worker runs exist, an active claim's run ages off page 1. A dispatcher-style
# holder carries no worker run_id, so it has NO other correlation path — the aged-off claim then
# reads as uncorrelated and, past its issuance timeout, classify_lease calls the lease dead even
# though its worker is merely queued or still running, resetting the issue, releasing the slot,
# and permitting a duplicate run. So the walk pages back through worker.yml's history.
WORKER_RUN_PAGE_CEILING = 50  # 50 x 100 = 5000 runs; matches GitHubAPI.paginate's runaway guard.


def _correlate_claim_runs(
    api: GitHubAPI, leases: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Match every ledger claim to its worker run by paging worker.yml's run history.

    GitHub returns runs newest-first, and a claim's worker run is created at/after the lease that
    holds it is written, so no run older than the OLDEST live lease's issuance can correlate a
    still-unmatched claim. The walk therefore stops as soon as EITHER every claim is matched OR a
    page's oldest run predates that issuance (the whole relevant time window is then covered). If
    neither holds within the page ceiling the snapshot is TRUNCATED and this fails CLOSED, rather
    than silently reading an aged-off live claim as an uncorrelated — and, past its timeout, dead
    — lease.
    """
    pending = {lease["claim_id"] for lease in leases}
    oldest_issued = min(lease["issued_at"] for lease in leases)
    registry_repo = _registry_repo(api)
    claim_runs: dict[str, dict[str, Any]] = {}
    for page in range(1, WORKER_RUN_PAGE_CEILING + 1):
        runs_doc = api.request(
            "GET",
            f"/repos/{registry_repo}/actions/workflows/worker.yml/runs"
            f"?per_page=100&page={page}",
        )
        if not isinstance(runs_doc, dict) or not isinstance(
            runs_doc.get("workflow_runs"), list
        ):
            raise GroomError("registry worker-run snapshot is malformed")
        runs = runs_doc["workflow_runs"]
        page_oldest: int | None = None
        for run in runs:
            if not isinstance(run, dict):
                raise GroomError("registry worker-run entry is malformed")
            _run_status(run)
            created = _epoch(run.get("created_at"), "worker run created_at")
            page_oldest = created if page_oldest is None else min(page_oldest, created)
            display = run.get("display_title")
            if isinstance(display, str):
                match = WORKER_RUN_NAME.fullmatch(display)
                if match and match.group("claim") != "self":
                    claim = match.group("claim")
                    if claim in claim_runs:
                        raise GroomError("multiple worker runs claim the same lease id")
                    claim_runs[claim] = run
                    pending.discard(claim)
        if not pending:
            return claim_runs  # every live lease correlated — stop paging.
        if len(runs) < 100:
            return claim_runs  # worker-run history exhausted; remaining claims have no run.
        if page_oldest is not None and page_oldest < oldest_issued:
            return claim_runs  # relevant time window covered; remaining claims have no run.
    raise GroomError(
        "registry worker-run snapshot is truncated before every live lease was correlated"
    )


def _worker_runs(
    api: GitHubAPI, leases: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any] | None]]:
    if not leases:
        return {}, {}
    claim_runs = _correlate_claim_runs(api, leases)

    holder_runs: dict[int, dict[str, Any] | None] = {}
    for lease in leases:
        holder = parse_holder(lease["holder"])
        if holder.run_id is None or holder.run_id in holder_runs:
            continue
        run = api.request(
            "GET",
            f"/repos/{_registry_repo(api)}/actions/runs/{holder.run_id}",
            allow_404=True,
        )
        if run is not None:
            if not isinstance(run, dict):
                raise GroomError("registry holder-run entry is malformed")
            _run_status(run)
        holder_runs[holder.run_id] = run
    return claim_runs, holder_runs


def _registry_repo(api: GitHubAPI) -> str:
    # Set immediately by run_sweep; keeping it on the registry client prevents target-token mixups.
    repo = getattr(api, "registry_repo", None)
    if not isinstance(repo, str) or SAFE_REPO.fullmatch(repo) is None:
        raise GroomError("registry API client has no safe repository binding")
    return repo


SAFE_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")


def _bot_login(api: GitHubAPI, app_slug: str = "") -> str:
    """Resolve the target bot identity. An App INSTALLATION token cannot call GET /user (403), so
    the live path resolves the PUBLIC /users/<app-slug>[bot] endpoint from the slug the token mint
    step exposes — the same canary fix worker.yml already carries. The /user fallback remains only
    for non-App tokens (no slug supplied)."""
    if app_slug:
        if SAFE_SLUG.fullmatch(app_slug) is None:
            raise GroomError("target App slug is unsafe")
        expected = f"{app_slug}[bot]"
        user = api.request("GET", f"/users/{quote(expected, safe='')}")
    else:
        user = api.request("GET", "/user")
        expected = None
    login = user.get("login") if isinstance(user, dict) else None
    if (
        not isinstance(login, str)
        or SAFE_LOGIN.fullmatch(login) is None
        or not login.endswith("[bot]")
        or (expected is not None and login != expected)
    ):
        raise GroomError("target token does not identify a GitHub App bot")
    return login


def _ensure_label(api: GitHubAPI, repo: str, label: str) -> bool:
    """Create `label`; RECONCILE the description of a PARK label whose text is a promise.

    The early return used to make every description write-once-at-creation, so the correct text
    already sitting in LABELS above never reached a repo whose label predated it. Measured live on
    sparq-org/sparq: `status:parked` still carried the superseded #614 wording and `review:parked`
    carried a generic review-loop string, while the machine's automatic exit was being justified by
    what those labels "promise". A promise a reader cannot see is not a promise.

    RECONCILED FOR park_policy.MACHINE_OWNED_PARK_LABELS ONLY — the SAME set the admission rule
    reads, so "the label whose description promises a machine exit" and "the label that gets that
    description reconciled" cannot drift into two different lists. Deliberately NOT all of
    PARK_LABELS: `needs:user` is the human terminal and its description promises no machine exit,
    so narrowing is the conservative direction (its first spelling of this test caught the wider
    set rewriting `needs:user`). Every other label in LABELS is create-only, so a human-curated
    description elsewhere in the repo is never overwritten. The PATCH fires only on a difference."""
    encoded = quote(label, safe="")
    existing = api.request("GET", f"/repos/{repo}/labels/{encoded}", allow_404=True)
    colour, description = LABELS[label]
    reconcilable = label in park_policy.MACHINE_OWNED_PARK_LABELS
    if existing is not None:
        if not reconcilable or not isinstance(existing, dict):
            return False
        if str(existing.get("description") or "") == description:
            return False
        print(f"WRITE reconcile label description repo={repo} label={label}: "
              f"{existing.get('description')!r} -> {description!r}")
        api.request("PATCH", f"/repos/{repo}/labels/{encoded}", {"description": description})
        return False
    api.request(
        "POST",
        f"/repos/{repo}/labels",
        {"name": label, "color": colour, "description": description},
    )
    print(f"WRITE create label repo={repo} label={label}")
    return True


def _is_human_maintainer(api: GitHubAPI, repo: str, login: str) -> bool:
    """The strict maintainer probe for the unpark veto (park-policy hygiene finding; the
    worker-issue._is_human_maintainer pattern): repo collaborator permission in
    park_policy.HUMAN_MAINTAINER_PERMISSIONS. Probe-call FAILURE counts as NOT a maintainer
    and emits the shared distinct ::warning:: diagnostic (park_policy.probe_maintainer,
    round-3 Opus finding); a clean 404 (not a collaborator) or a non-maintainer permission
    stays quiet."""
    def read_permission(probe_login: str):
        payload = api.request(
            "GET", f"/repos/{repo}/collaborators/{probe_login}/permission", allow_404=True
        )
        if payload is None:
            return None  # 404: not a collaborator — a genuine, quiet not-a-maintainer
        if not isinstance(payload, dict):
            raise GroomError("collaborator permission payload is malformed")
        return payload.get("permission")

    return park_policy.probe_maintainer(repo, login, read_permission)


def _apply_labels(
    api: GitHubAPI, repo: str, number: int, current: set[str], mode: str
) -> bool:
    add, remove = label_transition(current, mode)
    for label in sorted(set(add) & set(park_policy.PARK_LABELS)):
        # Sticky human unpark (park_policy.py defect 2): a human who removed this park label
        # more recently than any application VETOES the whole transition — groom must never
        # override a human's explicit unpark, and an unreadable timeline must never park.
        if park_policy.park_vetoed(
                repo, number, label,
                lambda r, n: api.paginate(f"/repos/{r}/issues/{n}/timeline"),
                is_human=lambda login: _is_human_maintainer(api, repo, login)):
            print(f"SKIP issue {repo}#{number}: {mode} park suppressed "
                  "(sticky human unpark)")
            return False
    for label in sorted(add):
        _ensure_label(api, repo, label)
    if add:
        api.request(
            "POST", f"/repos/{repo}/issues/{number}/labels", {"labels": sorted(add)}
        )
        print(
            f"WRITE add labels repo={repo} issue={number} labels={','.join(sorted(add))}"
        )
    for label in sorted(remove):
        api.request(
            "DELETE", f"/repos/{repo}/issues/{number}/labels/{quote(label, safe='')}"
        )
        print(f"WRITE remove label repo={repo} issue={number} label={label}")
    return bool(add or remove)


def _fresh_issue(api: GitHubAPI, repo: str, number: int) -> dict[str, Any] | None:
    item = api.request("GET", f"/repos/{repo}/issues/{number}", allow_404=True)
    if item is None:
        return None
    if not isinstance(item, dict) or "pull_request" in item:
        raise GroomError(f"target issue identity changed for {repo}#{number}")
    return item


def _current_links(
    repo: str, pulls: dict[int, dict[str, Any]], bot_login: str
) -> dict[int, set[int]]:
    """Map source-issue number -> open worker PR numbers, counting ONLY PRs that clear the
    worker-PR identity gate (`_worker_pr_identity`: App-authored, same-repository, worker-pattern
    head branch, worker body marker). An untrusted PR — a fork with a worker-shaped head, or any
    PR whose body merely says `Fixes #N` — is deliberately NOT counted (issue #172): recovery
    suppression keys on this map (a linked issue is skipped by the stale/orphan repair below and by
    the mutation-boundary re-check), so trusting outsider linkage would let anyone hold a stale
    issue out of recovery indefinitely.

    The sole linked issue is the one the head branch encodes — a worker attempt is bound to
    exactly one source issue. Body closing references (`Fixes #N`) are ignored even on an
    authenticated worker PR (review round 1): the branch is not bound to those issues, so
    linking them would suppress stale/orphan recovery for unrelated issues the App is not
    actually working.

    This is the identity gate WITHOUT the registry-provenance record `_admitted_review_prs`
    additionally requires: recovery suppression asks 'is the App itself actively working this issue
    right now', for which the authoring identity is authoritative — provenance-record visibility
    (issue #96) is not, and demanding it here would prematurely reset a legitimately in-progress
    issue whose record is not yet on the read branch."""
    links: dict[int, set[int]] = {}
    bot = bot_login.casefold()
    if not bot:
        return links  # no bot identity resolved — trust no linkage, fail closed
    for number, pull in pulls.items():
        branch = _worker_pr_identity(repo, pull, bot)
        if branch is None:
            continue
        links.setdefault(int(branch.group("issue")), set()).add(number)
    return links


def _area_terminally_parked(labels: set[str]) -> bool:
    """Issue labels that remove an artifact from every autonomous area lane."""
    return any(isinstance(label, str) and label.startswith("needs:") for label in labels)


def _terminal_non_pr_claims(
    issues: dict[str, dict[int, dict[str, Any]]],
    pulls: dict[str, dict[int, dict[str, Any]]],
    leases: list[dict[str, Any]],
    bot_login: str,
) -> set[str]:
    """Claims whose issue-only/orphan artifact provably cannot occupy an area.

    An open authenticated worker PR makes the claim PR-backed; label-only reaping then stands
    down because dispatch-claim owns the stricter head/latch coherence proof for that PR.  With
    no such PR, a ``needs:*`` issue is terminally parked and an issue absent from the open-issue
    snapshot is orphaned, so either claim can be reaped without trusting a split PR snapshot.
    Revalidation immediately before the CAS release repeats this predicate on fresh target reads.
    """
    links = {
        repo: _current_links(repo, pulls.get(repo, {}), bot_login)
        for repo in issues
    }
    reap = set()
    for lease in leases:
        if not isinstance(lease, dict) or is_repair_holder(lease.get("holder")):
            continue
        holder = parse_holder(lease.get("holder"))
        if holder.repo not in issues:
            continue                      # no target view: never infer orphaned
        if holder.issue in links[holder.repo]:
            continue                      # PR-backed: dispatch's coherent proof owns it
        issue = issues[holder.repo].get(holder.issue)
        if issue is None:
            reap.add(lease["claim_id"])   # absent from a complete open-issue listing: orphan
            continue
        labels = _labels(issue, f"target issue {holder.repo}#{holder.issue}")
        if _area_terminally_parked(labels):
            reap.add(lease["claim_id"])
    return reap


def _plan_actions(
    limits: dict[str, Limits],
    issues: dict[str, dict[int, dict[str, Any]]],
    pulls: dict[str, dict[int, dict[str, Any]]],
    admitted: dict[str, set[int]],
    attempts: dict[tuple[str, int], int],
    lease_states: dict[str, LeaseDecision],
    leases: list[dict[str, Any]],
    stale_prs: dict[tuple[str, int], str],
    now: int,
    bot_login: str,
    defuse_prs: dict[tuple[str, int], tuple[str, str]] | None = None,
    unplannable_issues: "frozenset[tuple[str, int]] | set[tuple[str, int]]" = frozenset(),
    unreadable_repos: "frozenset[str] | set[str]" = frozenset(),
) -> tuple[list[IssueAction], list[PullAction], set[str]]:
    terminal_non_pr = _terminal_non_pr_claims(issues, pulls, leases, bot_login)
    live_by_issue: set[tuple[str, int]] = set()
    dead_claims: set[str] = set()
    dead_by_issue: set[tuple[str, int]] = set()
    for lease in leases:
        holder = parse_holder(lease["holder"])
        key = (holder.repo, holder.issue)
        decision = lease_states[lease["claim_id"]]
        # Issue #649: the dead-claim computation is scoped PER REPO. A repo whose target snapshot
        # was unreadable this tick contributes NO releases, whatever its leases' run evidence says.
        # This is the fail direction the snapshot deferral needs, and it is stricter than merely
        # omitting the repo from `issues`: omission alone moves a run-dead TERMINAL claim from the
        # first branch below — where #509's fresh-read boundary can still RETAIN it, e.g. because
        # the issue was unparked under grooming — into the fifth, which releases it unconditionally.
        # A degraded read would then have caused a release the sweep could not prove. Every OTHER
        # repo's reclaim is unaffected, which is the whole point of not aborting the sweep.
        if holder.repo in unreadable_repos:
            print(
                f"SKIP lease release claim={lease['claim_id'][:8]}: {holder.repo}'s target "
                "snapshot was unreadable this tick — the lease is retained for the next sweep"
            )
            continue
        if lease["claim_id"] in terminal_non_pr and decision.state == "dead":
            # Reap the now-ownerless claim, but do not convert its intentional needs:* park
            # into a dead-worker reset. The terminal artifact remains human-owned.
            dead_claims.add(lease["claim_id"])
        elif lease["claim_id"] in terminal_non_pr and decision.state == "live":
            backing_run = decision.run_id if decision.run_id is not None else "UNKNOWN"
            print(
                f"SKIP lease release claim={lease['claim_id'][:8]}: terminal reap deferred: "
                f"backing run {backing_run} live"
            )
            live_by_issue.add(key)
        elif lease["claim_id"] in terminal_non_pr and decision.state == "unknown":
            print(
                f"SKIP lease release claim={lease['claim_id'][:8]}: terminal reap deferred: "
                "backing run liveness UNKNOWN"
            )
            live_by_issue.add(key)
        elif decision.state == "dead":
            dead_claims.add(lease["claim_id"])
            dead_by_issue.add(key)
        else:  # Unknown is deliberately treated as live for issue-state mutation.
            live_by_issue.add(key)

    actions: list[IssueAction] = []
    for repo, repo_issues in issues.items():
        links = _current_links(repo, pulls[repo], bot_login)
        for number, issue in repo_issues.items():
            key = (repo, number)
            # Issue #649: this issue's ATTEMPT BUDGET could not be read this tick, so it is
            # excluded from planning ENTIRELY — no defer, no ready, no orphan repair. This is the
            # skip-set, deliberately NOT a defaulted `attempts[key] = 0`: the guards below do not
            # all consume `used`, so an under-counted budget would SUPPRESS the exhaustion defer
            # while the `status:in-progress` ready repair (which never reads `used`) still fired,
            # re-readying and re-dispatching an issue whose budget is spent. A wrong mutation, not
            # a deferred one — so the whole issue waits for a readable budget instead.
            #
            # The exclusion is scoped to PLANNING only. This issue stays in the `issues` snapshot
            # the lease loop above already read, so its claim's terminal/orphan classification is
            # unchanged: a degraded comments read must not move a lease either.
            if key in unplannable_issues:
                print(
                    f"SKIP issue {repo}#{number}: attempt budget unreadable — excluded from "
                    "planning this tick"
                )
                continue
            labels = _labels(issue, f"target issue {repo}#{number}")
            used = attempts[key]
            # An open PROVEN worker PR for this issue means the final allowed attempt SUCCEEDED —
            # parking the source issue (`needs:user`) would strip that PR from dispatch's review
            # loop (any source `needs:*` is terminal there), so exhaustion never defers while an
            # ADMITTED attempt is open. Admission is `_admitted_review_prs` — the review loop's
            # own identity + registry-provenance checks — never the weaker `links` map below: an
            # arbitrary PR whose body says `Fixes #N` (or a fork with a worker-shaped head) must
            # not hold an exhausted issue out of `needs:user` (review round 1). Since #172 `links`
            # is no longer LOOSE either (it applies the same identity gate and ignores body
            # references); the remaining difference is the provenance RECORD, which this park
            # requires and the repair suppression below deliberately does not — see #279 there.
            # This guard must run FIRST so a successful last attempt is not mis-parked.
            if (
                used >= limits[repo].max_attempts
                and key not in live_by_issue
                and number not in admitted[repo]
            ):
                actions.append(
                    IssueAction(repo, number, "defer", "attempt budget exhausted")
                )
                continue
            # [registry #835] `admitted` is added to the recovery-suppression linkage for the
            # same reason the exhaustion guard above consults it: `links` is WORKER-shaped, so
            # without this an issue whose enrolled orchestrator PR is under review is re-readied
            # as "stale in-progress without PR" and a worker is dispatched onto work that is
            # already in the review lane. It is a NO-OP for the worker class by construction —
            # `_admitted_review_prs`' worker branch is `_current_links`' identity gate plus a
            # record, so every worker issue in `admitted` is already a `links` key (asserted).
            #
            # Issue #279 asked whether this direction should ALSO demand the record — i.e. treat a
            # record-less link as weak enough to suppress only orphan repair. It must not. The
            # availability hole #279 describes ("any PR saying `Fixes #N` delays repair forever")
            # was closed by #172: `links` is the worker-PR identity gate, so an outsider cannot
            # enter this map at all. Dropping a record-less but AUTHENTICATED worker PR out of the
            # suppression would re-ready an issue the App is demonstrably working right now
            # whenever its provenance record has not yet reached the read branch — trading a
            # bounded availability delay for a duplicate dispatch. Suppression stays identity-keyed
            # here and record-keyed at the park above, and both are re-asked at the write boundary.
            if key in live_by_issue or number in links or number in admitted[repo]:
                continue
            stale = (
                now - _epoch(issue["updated_at"], f"target issue {repo}#{number}")
                >= limits[repo].threshold_seconds
            )
            if "status:in-progress" in labels:
                if key in dead_by_issue or stale:
                    reason = (
                        "dead lease"
                        if key in dead_by_issue
                        else "stale in-progress without PR or lease"
                    )
                    actions.append(IssueAction(repo, number, "ready", reason))
                continue
            # Orphan repair: a worker previously ran (durable attempt evidence, used >= 1) but the
            # issue no longer holds any dispatchable state — either its worker PR closed WITHOUT
            # merging after the 'complete' transition stripped every status label (a dead state no
            # other component recovers), or it is parked status:in-progress-review with no open PR
            # (the review loop lost its PR). Issues WITHOUT attempt evidence are never touched: a
            # label-less issue that never saw a worker belongs to triage, not grooming — re-readying
            # it here would bypass the triage trust gate. status:deferred stays untouched: the
            # dispatcher's deferred-retry path (locked decision 20) is its single owner.
            has_status = any(label.startswith("status:") for label in labels)
            in_review = "status:in-progress-review" in labels
            if (
                used >= 1
                and stale
                and "needs:user" not in labels
                and (not has_status or in_review)
            ):
                reason = (
                    "in review without an open worker PR"
                    if in_review
                    else "no orchestration status after a worker attempt"
                )
                actions.append(IssueAction(repo, number, "ready", reason))

    selected_defuses = sorted((defuse_prs or {}).items())[:MAX_AUTO_DEFUSES_PER_TICK]
    selected_defuse_keys = {key for key, _snapshot in selected_defuses}
    pull_actions = [
        PullAction(
            repo,
            number,
            "stale terminal park occupies an orchestration partition",
            mode="defuse",
            head_sha=snapshot[0],
            updated_at=snapshot[1],
        )
        for (repo, number), snapshot in selected_defuses
    ]
    pull_actions.extend(
        PullAction(repo, number, reason)
        for (repo, number), reason in sorted(stale_prs.items())
        if (repo, number) not in selected_defuse_keys
    )
    return actions, pull_actions, dead_claims


def target_tokens_map() -> dict[str, str]:
    """The PER-OWNER target App-token map (issue #168). groom.yml mints one App token per DISTINCT
    enabled-policy owner and passes ``{owner: token}`` as JSON in ``TARGET_GH_TOKENS`` — mirroring
    dispatch.yml, whose CLAIM already routes per owner. A single token scoped to one owner 404s
    every read and fails every write on the other owner's repo, aborting the sweep before dead
    leases are released. The single-owner legacy env ``TARGET_GH_TOKEN`` is still honoured as a
    fallback (mapped to ``TARGET_GH_TOKEN_OWNER``) so a single-target deployment is unchanged.
    Blank owners/tokens are dropped so a partially-minted map never yields a wrong-owner token."""
    raw = os.environ.get("TARGET_GH_TOKENS", "")
    tokens: dict[str, str] = {}
    if raw:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GroomError("TARGET_GH_TOKENS is not valid JSON") from exc
        if not isinstance(data, dict):
            raise GroomError("TARGET_GH_TOKENS must be a {owner: token} object")
        for owner, token in data.items():
            if isinstance(owner, str) and isinstance(token, str) and owner and token:
                tokens[owner] = token
    legacy = os.environ.get("TARGET_GH_TOKEN", "")
    legacy_owner = os.environ.get("TARGET_GH_TOKEN_OWNER", "")
    if legacy and legacy_owner and legacy_owner not in tokens:
        tokens[legacy_owner] = legacy
    return tokens


def target_api_for(repo: str, apis: dict[str, "GitHubAPI"]) -> "GitHubAPI | None":
    """The target GitHubAPI scoped to ``repo``'s OWNER, or None when that owner has no minted
    token. A missing token DEFERS that owner's issue/PR repair (groom skips it loudly) instead of
    404-looping a wrong-owner token — fail closed, never wrong-owner access. ``repo`` is owner/name."""
    if not isinstance(repo, str) or "/" not in repo:
        return None
    return apis.get(repo.split("/", 1)[0])


def run_sweep(args: argparse.Namespace) -> tuple[int, int, int, int]:
    registry_repo = args.registry_repo
    if SAFE_REPO.fullmatch(registry_repo) is None:
        raise GroomError("registry repo must be a safe owner/name")
    defuse_stale_seconds = _configured_stale_hours(args) * 3600
    limits = load_limits(Path(args.policy_file), Path(args.policy_resolver))
    registry_api = GitHubAPI(os.environ.get("REGISTRY_GH_TOKEN", ""), "registry")
    registry_api.registry_repo = registry_repo
    # Per-owner target App-token map (issue #168): one client per enabled-policy owner, so each
    # target repo is read/written under ITS owner's token — never a wrong-owner token that 404s
    # and aborts the whole sweep before dead-lease release.
    target_tokens = target_tokens_map()
    target_apis = {
        owner: GitHubAPI(token, f"target {owner}")
        for owner, token in target_tokens.items()
    }
    groomable = {
        repo: api
        for repo in limits
        if (api := target_api_for(repo, target_apis)) is not None
    }
    for repo in limits:
        if repo not in groomable:
            print(
                f"skip target grooming for {repo}: no App token minted for owner "
                f"{repo.split('/', 1)[0]!r} — its issue/PR repair defers this tick "
                "(dead-lease release still runs)"
            )
    now = int(time.time())
    # The bot identity is the same GitHub App across every owner install, so resolve it once from
    # any groomable owner's token. With no groomable owner nothing on the target side is read or
    # written, so no bot login is needed (dead-lease release below still runs).
    bot_login = (
        _bot_login(next(iter(groomable.values())), getattr(args, "bot_slug", "") or "")
        if groomable
        else ""
    )
    if not groomable:
        print(
            "skip all target grooming: no target App token minted for any enabled owner "
            "(dead-lease release still runs)"
        )
    # Provenance records live on the `ledger` branch checkout first (issue #96), with the
    # master checkout (groom's working directory) as the legacy pre-outage fallback.
    ledger_root = Path(args.ledger_root) if getattr(args, "ledger_root", "") else None

    leases, _sha = _read_ledger(registry_api, registry_repo)
    repair_count = sum(1 for lease in leases if is_repair_holder(lease["holder"]))
    if repair_count:
        print(f"skip {repair_count} review/fix repair lease(s) — TTL-managed by groom-leases")
    leases = [lease for lease in leases if not is_repair_holder(lease["holder"])]
    for lease in leases:
        holder = parse_holder(lease["holder"])
        if holder.repo not in limits:
            raise GroomError("lease holder targets an unknown or disabled policy repo")
    claim_runs, holder_runs = _worker_runs(registry_api, leases)
    lease_states = {
        lease["claim_id"]: classify_lease(
            lease,
            limits[parse_holder(lease["holder"]).repo],
            now,
            claim_runs,
            holder_runs,
        )
        for lease in leases
    }
    for lease in leases:
        decision = lease_states[lease["claim_id"]]
        print(
            f"READ lease claim={lease['claim_id'][:8]} state={decision.state} reason={decision.reason}"
        )

    issues: dict[str, dict[int, dict[str, Any]]] = {}
    pulls: dict[str, dict[int, dict[str, Any]]] = {}
    attempts: dict[tuple[str, int], int] = {}
    stale_prs: dict[tuple[str, int], str] = {}
    defuse_prs: dict[tuple[str, int], tuple[str, str]] = {}
    # Issue #647, THIRD instance of the same shape, found while closing the other two: the per-PR
    # DETAIL read below is an unwrapped per-object operation with reclaim downstream, so one PR
    # whose detail GET is refused (or comes back malformed) aborted the sweep before
    # _release_claims — #644's leak with yet another trigger. It takes the same mechanical change
    # because this read feeds ONLY the stale-PR hand-off candidacy: deferring one PR's DETECTION
    # costs that PR one tick of hand-off and nothing else. (The two OTHER unwrapped reads in this
    # loop needed a DIFFERENT fail direction, closed by issue #649 below — record-and-continue
    # would have been a wrong mutation for each.)
    detect_attempted = 0
    detect_completed = 0
    detect_deferrals: list[str] = []
    # Issue #649 (1): the per-issue ATTEMPT-BUDGET read. Recording a `0` on a failed comments read
    # is a WRONG mutation, not a deferred one — see the skip-set comment in `_plan_actions`. The
    # issue is therefore excluded from PLANNING for the tick and its `attempts` entry is left
    # ABSENT, so any future consumer that forgets the skip-set raises here instead of silently
    # reading an under-count.
    unplannable_issues: set[tuple[str, int]] = set()
    budget_attempted = 0
    budget_completed = 0
    budget_deferrals: list[str] = []
    # Issue #649 (2): the PER-REPO snapshot reads. These fail as a UNIT — a repo whose issue or PR
    # listing is unreadable is dropped from BOTH maps rather than recorded as an empty one. An
    # EMPTY snapshot is the dangerous shape: `_terminal_non_pr_claims` would then read every lease
    # for that repo as orphaned (its issue "absent from a complete open-issue listing") and reap
    # it, and a missing `pulls` entry would additionally erase the PR-backed stand-down. Partial
    # recording is therefore what must never happen: all three reads share ONE try, and nothing is
    # published unless all three returned. The repo is additionally recorded in `unreadable_repos`,
    # which scopes the dead-claim computation per repo (see `_plan_actions`) so that a snapshot we
    # could not read cannot release a lease either way.
    unreadable_repos: set[str] = set()
    snapshot_attempted = 0
    snapshot_completed = 0
    snapshot_deferrals: list[str] = []
    # The per-tick audit of the #1303 saving. Printed rather than assumed, for the same reason
    # plan-snapshot prints its conditional-read split: a request-budget win that is not visible
    # in the log of the tick that took it cannot be told apart from a quiet hour.
    attempts_considered = 0
    attempts_fetched = 0
    for repo, api in groomable.items():
        repo_limits = limits[repo]
        snapshot_attempted += 1
        try:
            repo_issues = _issues(api, repo)
            repo_pulls = _pulls(api, repo)
            repo_defuse = _collect_defuse_prs(
                api, repo, repo_pulls, now, defuse_stale_seconds, bot_login
            )
        except GroomError as exc:
            print(
                f"ALERT repo {repo}: {exc} — target snapshot unreadable, so this repo's "
                "issue/PR grooming AND its lease releases defer this tick (every OTHER repo's "
                "reclaim still runs)"
            )
            snapshot_deferrals.append(f"{repo}: {exc}")
            unreadable_repos.add(repo)
            continue
        snapshot_completed += 1
        issues[repo] = repo_issues
        pulls[repo] = repo_pulls
        defuse_prs.update(repo_defuse)
        for number, issue in issues[repo].items():
            # THE SWEEP'S DOMINANT COST (registry #1303). One request per commented issue, every
            # tick, against the partition every other lane's `issues`/`pulls` reads also draw on
            # — 500 of ~650 requests per tick, measured across the two enabled targets on
            # 2026-07-29. `attempts_fetch_needed` skips the issues on which NEITHER guard that
            # consumes the count can fire, decided entirely from the list payload already in hand.
            #
            # The staleness input must be computed the way `_plan_actions` computes it, or the
            # filter and its consumer disagree about which issues are exempt; the self-test pins
            # the two expressions against each other.
            count = issue["comments"]
            attempts_considered += 1
            budget_attempted += 1
            issue_labels = _labels(issue, f"target issue {repo}#{number}")
            issue_stale = (
                now - _epoch(issue["updated_at"], f"target issue {repo}#{number}")
                >= repo_limits.threshold_seconds
            )
            if attempts_fetch_needed(
                count, issue_labels, issue_stale, repo_limits.max_attempts
            ):
                attempts_fetched += 1
                # Issue #649 (1): the last unwrapped per-issue read in this loop after #648. It
                # aborted the sweep before `_release_claims`, so one issue whose comments GET was
                # refused cost EVERY repo its dead-lease reclaim. The fail direction is a SKIP,
                # not a `0`: this issue leaves planning altogether (see `unplannable_issues`),
                # which is the only degradation that cannot re-ready an issue whose attempt
                # budget is spent.
                try:
                    fetched = count_attempts(_comments(api, repo, number), bot_login)
                except GroomError as exc:
                    print(
                        f"ALERT issue {repo}#{number}: {exc} — attempt-budget read deferred; "
                        "the issue is excluded from planning this tick"
                    )
                    budget_deferrals.append(f"{repo}#{number}: {exc}")
                    unplannable_issues.add((repo, number))
                    continue
                attempts[(repo, number)] = fetched
            else:
                # Record the BOUND, never a hard-coded 0. In this branch it is provably below the
                # cap and the repair's own conjuncts have already refused the issue, so both
                # guards answer as they would on the true count — but a 0 would be an UNDER-count
                # that merely happens to agree today, which is the shape that turns into a silent
                # wrong answer the moment a third consumer reads this map.
                attempts[(repo, number)] = count
            # This issue's budget is USABLE — fetched, or decided from the list payload. The
            # cheap branch is a completed decision, not a skipped object (phase_exit_failure's
            # "a deliberate SKIP counts as a COMPLETED object"), so rule 2 reds this phase only
            # when NO issue at all got a usable budget while at least one read failed.
            budget_completed += 1
        for number, pull in pulls[repo].items():
            if (
                now - _epoch(pull["updated_at"], f"target pull request {repo}#{number}")
                < repo_limits.threshold_seconds
            ):
                continue
            detect_attempted += 1
            try:
                detail = api.request("GET", f"/repos/{repo}/pulls/{number}")
                if not isinstance(detail, dict):
                    raise GroomError(
                        f"target pull request detail is malformed for {repo}#{number}"
                    )
                reason = stale_worker_pr_reason(
                    detail,
                    bot_login,
                    repo_limits.threshold_seconds,
                    now,
                    has_valid_provenance=worker_pr_provenance_enumerable(
                        repo, number, ledger_root=ledger_root),
                )
            except GroomError as exc:
                print(f"ALERT PR {repo}#{number}: {exc} — stale PR detection deferred")
                detect_deferrals.append(f"{repo}#{number}: {exc}")
                continue
            detect_completed += 1
            if reason:
                stale_prs[(repo, number)] = reason
    # [#1303] The realised saving, per tick, from the tick's own counters — never a constant.
    print(
        f"SWEEP attempt-budget reads: {attempts_fetched} of {attempts_considered} open issues "
        f"needed a comments fetch, {attempts_considered - attempts_fetched} decided by the "
        "comment count already in the list payload (0 requests)"
    )
    detect_outcome = PhaseOutcome(
        label="stale PR detection",
        changed=detect_completed,
        attempted=detect_attempted,
        deferred=tuple(detect_deferrals),
    )
    snapshot_outcome = PhaseOutcome(
        label="target repo snapshot",
        changed=snapshot_completed,
        attempted=snapshot_attempted,
        deferred=tuple(snapshot_deferrals),
    )
    budget_outcome = PhaseOutcome(
        label="attempt-budget read",
        changed=budget_completed,
        attempted=budget_attempted,
        deferred=tuple(budget_deferrals),
    )

    admitted = {
        # [registry #835] The repo's master-protected enrolment allowlist, so an ADMITTED
        # orchestrator-class PR suppresses its source issue's exhaustion park exactly as an
        # admitted worker PR does. Hard-coding `()` here re-opens the silent de-enumeration.
        #
        # [#649] Keyed on the repos that HAVE a snapshot, not on `groomable`: a repo whose
        # listing was unreadable has no `pulls[repo]` to derive an allowlist from, and inventing
        # an empty one would be the same silent de-enumeration by another route.
        repo: _admitted_review_prs(repo, pulls[repo], bot_login, ledger_root=ledger_root,
                                   enrolled_authors=limits[repo].enrolled_authors)
        for repo in issues
    }
    issue_actions, pull_actions, dead_claims = _plan_actions(
        limits, issues, pulls, admitted, attempts, lease_states, leases, stale_prs, now,
        bot_login, defuse_prs=defuse_prs, unplannable_issues=unplannable_issues,
        unreadable_repos=unreadable_repos,
    )
    terminal_reap_candidates = (
        _terminal_non_pr_claims(issues, pulls, leases, bot_login) & dead_claims
    )
    if len(terminal_reap_candidates) > MAX_TERMINAL_REAPS_PER_TICK:
        capped_terminal_reaps = set(
            sorted(terminal_reap_candidates)[:MAX_TERMINAL_REAPS_PER_TICK]
        )
        deferred_reaps = terminal_reap_candidates - capped_terminal_reaps
        dead_claims.difference_update(deferred_reaps)
        terminal_reap_candidates = capped_terminal_reaps
        print(f"reap cap reached — {len(deferred_reaps)} deferred")

    # Re-read the mutex before issue mutation. A newly claimed lease suppresses repair; claims
    # already proven dead do not. The remaining cross-repository gap is safe: a retained lease
    # prevents duplicate dispatch if a target-label write wins a race.
    fresh_leases, _fresh_sha = _read_ledger(registry_api, registry_repo)
    fresh_live_issues = {
        (parse_holder(lease["holder"]).repo, parse_holder(lease["holder"]).issue)
        for lease in fresh_leases
        if lease["claim_id"] not in dead_claims
        and not is_repair_holder(lease["holder"])
    }
    # #509 mutation-boundary guard for label/orphan reaping.  A claim selected from the earlier
    # target snapshots is released only if a fresh issue read still says terminal/absent and the
    # fresh pull listing still has no worker PR for it.  An unpark or newly opened PR wins the
    # race and retains the claim; ordinary run-proven dead claims are unaffected.
    # Issue #649 (3): this re-read is the ONE loop in the sweep whose safe degradation is the
    # OPPOSITE of `continue`. Record-and-continue fails OPEN here — an unread issue simply stays
    # absent from `fresh_reap_issues`, `_terminal_non_pr_claims` reads absent as ORPHANED, and the
    # claim is CONFIRMED for release on a read that never returned, which is precisely what #509's
    # boundary exists to prevent. So a refused re-read DROPS its claim from the candidate set and
    # from `dead_claims`: the lease is RETAINED and re-examined next sweep. Every other claim in
    # the batch, and every run-proven dead claim outside it, still reclaims.
    reap_attempted = 0
    reap_completed = 0
    reap_deferrals: list[str] = []
    if terminal_reap_candidates:
        candidate_leases = [
            lease for lease in leases if lease["claim_id"] in terminal_reap_candidates
        ]
        fresh_reap_issues: dict[str, dict[int, dict[str, Any]]] = {
            repo: {} for repo in issues
        }
        unproven_claims: set[str] = set()
        # [#649, review round 1] The fresh PR listing is the OTHER HALF of #509's boundary
        # predicate, and it used to be read — unwrapped, for every snapshotted repo, whether or not
        # anything was up for reaping — between planning and this block. A repo whose listing
        # SUCCEEDED in the snapshot phase and is refused here therefore raised past
        # `_release_claims`, which is exactly the head-of-line abort the rest of this issue closes;
        # the snapshot phase's own try cannot see it, because this is a second, later read.
        #
        # It now runs ONLY when there is a reap to revalidate, ONLY for the repos that actually
        # hold a candidate, and PER REPO. The fail direction is the reap loop's, not
        # record-and-continue: `_terminal_non_pr_claims` reads a missing `pulls` entry as
        # `{}` — "no worker PR" — so an unread listing would CONFIRM a release it never proved.
        # The repo's candidates are withdrawn and their leases RETAINED instead, and every other
        # repo's reap, and every run-proven dead claim, still reclaims this tick.
        current_pulls: dict[str, dict[int, dict[str, Any]]] = {}
        for repo in sorted({parse_holder(lease["holder"]).repo for lease in candidate_leases}):
            try:
                current_pulls[repo] = _pulls(groomable[repo], repo)
            except GroomError as exc:
                withdrawn = [
                    lease for lease in candidate_leases
                    if parse_holder(lease["holder"]).repo == repo
                ]
                print(
                    f"ALERT repo {repo}: {exc} — fresh PR listing unreadable, so terminal reap "
                    f"revalidation defers for {len(withdrawn)} claim(s); the leases are RETAINED "
                    "(an unread pull listing cannot prove the ABSENCE of a worker PR)"
                )
                for lease in withdrawn:
                    reap_attempted += 1
                    reap_deferrals.append(
                        f"{repo}#{parse_holder(lease['holder']).issue}: {exc}"
                    )
                    unproven_claims.add(lease["claim_id"])
        if unproven_claims:
            # Withdrawn before the per-claim re-read below, so a claim this listing failure already
            # disqualified does not spend a fresh-issue request it can no longer act on.
            candidate_leases = [
                lease for lease in candidate_leases
                if lease["claim_id"] not in unproven_claims
            ]
        for lease in candidate_leases:
            holder = parse_holder(lease["holder"])
            reap_attempted += 1
            try:
                issue = _fresh_issue(groomable[holder.repo], holder.repo, holder.issue)
            except GroomError as exc:
                print(
                    f"ALERT lease claim={lease['claim_id'][:8]}: {exc} — terminal reap "
                    f"revalidation deferred for {holder.repo}#{holder.issue}; the lease is "
                    "RETAINED (an unread issue must never confirm a release)"
                )
                reap_deferrals.append(f"{holder.repo}#{holder.issue}: {exc}")
                unproven_claims.add(lease["claim_id"])
                continue
            reap_completed += 1
            if issue is not None and issue.get("state") == "open":
                fresh_reap_issues[holder.repo][holder.issue] = issue
        if unproven_claims:
            # Withdrawn BEFORE the confirmation runs. `candidate_leases` is pruned too — that is
            # defence in depth rather than load-bearing (the confirmation is only ever consulted
            # through `terminal_reap_candidates - confirmed_terminal`), but it keeps a withdrawn
            # claim from being NAMED as confirmed-terminal on the strength of an unread issue.
            terminal_reap_candidates -= unproven_claims
            dead_claims.difference_update(unproven_claims)
            candidate_leases = [
                lease for lease in candidate_leases
                if lease["claim_id"] not in unproven_claims
            ]
        confirmed_terminal = _terminal_non_pr_claims(
            fresh_reap_issues, current_pulls, candidate_leases, bot_login
        )
        for claim in sorted(terminal_reap_candidates - confirmed_terminal):
            print(f"SKIP lease release claim={claim[:8]}: artifact re-entered or gained an open PR")
        dead_claims.difference_update(terminal_reap_candidates - confirmed_terminal)
    reap_outcome = PhaseOutcome(
        label="terminal reap revalidation",
        changed=reap_completed,
        attempted=reap_attempted,
        deferred=tuple(reap_deferrals),
    )

    reset = 0
    deferred = 0
    # Issue #647: the SAME head-of-line abort shape #644 fixed for the defuse phase. Every
    # operation below — the fresh issue re-read, the comment reads, the mutation-boundary PR
    # re-read and _apply_labels' own ensure-label / add / delete writes — was UNWRAPPED, and
    # _release_claims is downstream of this loop, so ONE un-labellable issue aborted the whole
    # sweep before dead-lease reclaim. That is the defect that cost 13 consecutive failed runs and
    # ~4 hours without reclaim. Failures are RECORDED here, never swallowed: phase_exit_failure
    # decides the run's status from this outcome AFTER the sweep has done its work.
    repair_attempted = 0
    repair_completed = 0
    repair_deferrals: list[str] = []
    for action in issue_actions:
        api = groomable[action.repo]
        key = (action.repo, action.number)
        repair_attempted += 1
        repair_failed = False
        try:
            if key in fresh_live_issues:
                print(f"SKIP issue {action.repo}#{action.number}: a live lease appeared")
                continue
            issue = _fresh_issue(api, action.repo, action.number)
            if issue is None or issue.get("state") != "open":
                print(f"SKIP issue {action.repo}#{action.number}: no longer open")
                continue
            labels = _labels(issue, f"target issue {action.repo}#{action.number}")
            mode = action.mode
            if mode == "ready":
                current_comments = (
                    _comments(api, action.repo, action.number)
                    if issue.get("comments", 0)
                    else []
                )
                orphan_repair = action.reason in (
                    "in review without an open worker PR",
                    "no orchestration status after a worker attempt",
                )
                fresh_has_status = any(label.startswith("status:") for label in labels)
                fresh_in_review = "status:in-progress-review" in labels
                if (
                    count_attempts(current_comments, bot_login)
                    >= limits[action.repo].max_attempts
                ):
                    mode = "defer"
                elif not orphan_repair and "status:in-progress" not in labels:
                    print(
                        f"SKIP issue {action.repo}#{action.number}: no longer in progress"
                    )
                    continue
                elif orphan_repair and (
                    "needs:user" in labels
                    or (fresh_has_status and not fresh_in_review)
                ):
                    print(
                        f"SKIP issue {action.repo}#{action.number}: status changed under grooming"
                    )
                    continue
                elif (
                    (action.reason.startswith("stale") or orphan_repair)
                    and now
                    - _epoch(
                        issue.get("updated_at"),
                        f"target issue {action.repo}#{action.number}",
                    )
                    < limits[action.repo].threshold_seconds
                ):
                    print(
                        f"SKIP issue {action.repo}#{action.number}: activity refreshed its threshold"
                    )
                    continue
                else:
                    # Mutation-boundary revalidation of "is this issue already being worked?"
                    # (issue #279), the ready-side mirror of the defer branch's re-read below:
                    # re-read the target's open PRs NOW rather than trusting the pre-loop
                    # snapshot, which is already stale by the time a later action in this loop
                    # reaches its write. A worker (or [#835] enrolled orchestrator) PR that
                    # opened after planning must suppress the status:ready write, or the
                    # dispatcher sends a second worker onto work that already has an open PR.
                    # Placed LAST, so it is the closest read to the write the API permits and
                    # costs a listing only for an action that is otherwise about to mutate.
                    #
                    # The predicate is UNCHANGED — worker linkage (`_current_links`) OR the
                    # class-aware admission — and is deliberately NOT narrowed to the admitted
                    # set (issue #279's open question). `_current_links` is no longer loose:
                    # since #172 it applies the full worker-PR IDENTITY gate and ignores
                    # `Fixes #N` body references entirely, so no outsider PR can hold this
                    # issue out of repair. What it does NOT require is a provenance RECORD, and
                    # requiring one here would be a regression, not a hardening: an in-flight
                    # worker whose record has not yet landed on the read branch would be
                    # re-readied and double-dispatched. Suppressing a repair write is the
                    # conservative direction; granting dispatch is not.
                    boundary_pulls = _pulls(api, action.repo)
                    if action.number in _current_links(
                        action.repo, boundary_pulls, bot_login
                    ) or action.number in _admitted_review_prs(
                        action.repo, boundary_pulls, bot_login, ledger_root=ledger_root,
                        enrolled_authors=limits[action.repo].enrolled_authors,
                    ):
                        print(
                            f"SKIP issue {action.repo}#{action.number}: an open PR appeared"
                        )
                        continue
            else:
                current_comments = (
                    _comments(api, action.repo, action.number)
                    if issue.get("comments", 0)
                    else []
                )
                if (
                    count_attempts(current_comments, bot_login)
                    < limits[action.repo].max_attempts
                ):
                    print(
                        f"SKIP issue {action.repo}#{action.number}: attempt budget is no longer exhausted"
                    )
                    continue
            if mode == "defer":
                # Mutation-boundary revalidation (issue #170, review round 1): re-read the target's
                # open PRs NOW — not the pre-loop snapshot — so a final-attempt worker PR that opened
                # after planning (or while earlier actions were processed) still suppresses the park.
                # Covers BOTH defer paths (a planned exhaustion defer and the ready-path downgrade
                # above). Suppression requires the ADMITTED proven-worker set, never loose linkage.
                # This is as close to the label write as the API permits; the residual window is
                # GitHub's own read-to-write gap. The park is now the machine-owned status:parked
                # soft hold (an admitted PR would keep flowing through review either way), but an
                # open admitted PR means the FINAL allowed attempt SUCCEEDED — parking its issue is
                # simply wrong, so skipping — the fail-closed side, retried next sweep — wins any
                # tie.
                boundary_pulls = _pulls(api, action.repo)
                if action.number in _admitted_review_prs(
                    action.repo, boundary_pulls, bot_login, ledger_root=ledger_root,
                    enrolled_authors=limits[action.repo].enrolled_authors,
                ):
                    print(
                        f"SKIP issue {action.repo}#{action.number}: an admitted PR is open"
                    )
                    continue
                # Issue #174: the checkout the on-disk admission reads is IMMUTABLE for the whole
                # sweep, so a provenance record a delayed job or backfill lands DURING the sweep is
                # invisible above. Re-read this issue's worker-PR provenance from the LIVE `ledger`
                # ref immediately before the park: a raced-in valid record still suppresses it
                # (review-loop-owned — its final attempt succeeded), and an unavailable or
                # conflicting live read skips the park with an operational alert rather than
                # parking on an unusable read (a wrong park mislabels the issue for a full
                # readmission cycle).
                live = _live_issue_admission(
                    registry_api, registry_repo, action.repo, action.number,
                    boundary_pulls, bot_login,
                    enrolled_authors=limits[action.repo].enrolled_authors,
                )
                if live == "admitted":
                    print(
                        f"SKIP issue {action.repo}#{action.number}: a valid provenance record for "
                        "its worker PR now exists on the live ledger ref"
                    )
                    continue
                if live == "indeterminate":
                    print(
                        f"ALERT issue {action.repo}#{action.number}: live provenance revalidation "
                        "was unavailable or conflicting — deferring the status:parked park to "
                        "the next sweep"
                    )
                    continue
            changed = _apply_labels(api, action.repo, action.number, labels, mode)
            if changed and mode == "ready":
                reset += 1
            elif changed:
                deferred += 1
        except GroomError as exc:
            repair_failed = True
            print(
                f"ALERT issue {action.repo}#{action.number}: {exc} — status repair deferred"
            )
            repair_deferrals.append(f"{action.repo}#{action.number}: {exc}")
            continue
        finally:
            # This issue's work COMPLETED unless a GroomError deferred it. A deliberate SKIP
            # (`continue`) is a completed decision, not a failure, so the accounting has to run on
            # every exit path except the deferral — which is what `finally` buys here, since a
            # `continue` inside the block would jump straight past a trailing statement. Rule 2 of
            # phase_exit_failure then reds the run only when NOTHING completed while something was
            # deferred: a repo-wide credential or permission loss stays loud, one issue's refusal
            # stays a per-issue ALERT.
            if not repair_failed:
                repair_completed += 1
    repair_outcome = PhaseOutcome(
        label="issue status repair",
        changed=repair_completed,
        attempted=repair_attempted,
        deferred=tuple(repair_deferrals),
    )

    defuse_outcome = _execute_defuse_actions(
        pull_actions, groomable, target_tokens, now, defuse_stale_seconds, bot_login
    )

    unpark_outcome, unpark_count, converge_count, stalled_count = _execute_age_unpark_actions(
        pulls, groomable, registry_api, registry_repo, bot_login
    )

    stale_count = 0
    # Issue #647, the second surviving instance of #644's shape — and the one whose reclaim
    # exposure is most direct, since _release_claims is the very next statement after this loop.
    # The detail GET, _ensure_label, the label POST, the comment read and the comment POST were all
    # UNWRAPPED per-object operations: one unreachable or un-labellable PR (sparq-org/sparq#3427 is
    # exactly this shape — a human-authored, workflow-touching PR under a token with no `workflows`
    # permission) aborted the sweep before dead-lease reclaim. Each PR now defers ITSELF.
    stale_attempted = 0
    stale_completed = 0
    stale_deferrals: list[str] = []
    for action in pull_actions:
        if action.mode != "park":
            continue
        api = groomable[action.repo]
        stale_attempted += 1
        stale_failed = False
        try:
            pull = api.request(
                "GET", f"/repos/{action.repo}/pulls/{action.number}", allow_404=True
            )
            if not isinstance(pull, dict) or pull.get("state") != "open":
                print(f"SKIP PR {action.repo}#{action.number}: no longer open")
                continue
            reason = stale_worker_pr_reason(
                pull,
                bot_login,
                limits[action.repo].threshold_seconds,
                now,
                has_valid_provenance=worker_pr_provenance_enumerable(
                    action.repo, action.number, ledger_root=ledger_root),
            )
            if reason is None:
                print(f"SKIP PR {action.repo}#{action.number}: no longer stale/failing")
                continue
            # Issue #174: the ORPHAN-draft reason was derived from provenance ABSENCE on the IMMUTABLE
            # checkout (worker_pr_provenance_enumerable, at planning and just above). A delayed
            # provenance job or backfill that lands DURING the sweep is invisible there, so re-read the
            # record from the LIVE `ledger` ref immediately before the terminal park. A raced-in valid
            # record means the draft is review-loop-owned (cancel the park); an unavailable or
            # conflicting live read skips the park with an operational alert rather than terminally
            # parking on an unusable read. Only the provenance-derived orphan reason is revalidated — a
            # NON-draft PR wedged in a bad merge state is parked regardless of provenance, so its
            # (unrelated) escalation is left untouched.
            if reason == ORPHAN_DRAFT_REASON:
                state, _record = _live_provenance_record(
                    registry_api, registry_repo, action.repo, action.number
                )
                if state == "admits":
                    print(
                        f"SKIP PR {action.repo}#{action.number}: a valid provenance record now "
                        "exists on the live ledger ref (review-loop-owned)"
                    )
                    continue
                if state == "indeterminate":
                    print(
                        f"ALERT PR {action.repo}#{action.number}: live provenance revalidation was "
                        "unavailable or conflicting — deferring the age park to the next sweep"
                    )
                    continue
            labels = _labels(pull, f"target pull request {action.repo}#{action.number}")
            # The park CLASS is decided here and nowhere else (age_park_label). Reading the
            # comments BEFORE the label write is what makes that possible: the generation — how
            # many times this sweep has already parked this PR — lives in the durable receipts,
            # and it is the cap that decides machine-vs-human for a flapping PR. Both reads were
            # already made in this block; only their order changed.
            comments = _comments(api, action.repo, action.number)
            generation = age_park_generation(comments, bot_login)
            park_label = age_park_label(reason, generation)
            cause = age_park_cause(reason)
            head_sha = pull.get("head", {}).get("sha")
            if not isinstance(head_sha, str) or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
                raise GroomError(
                    f"target pull request head sha is malformed for {action.repo}#{action.number}")
            machine_park = park_label == park_policy.MACHINE_PARK_PR_LABEL
            # A receipt is minted for EVERY classified cause, machine park or over-cap human
            # escalation alike. Both consume a generation, so both must be on record — and the
            # escalation must not be silenced by the machine receipts that preceded it: those
            # bodies carry STALE_PR_MARKER, so a plain marker dedupe would swallow the one comment
            # that explains the flap and hand the maintainer a bare `needs:user`. An UNMAPPED
            # cause mints nothing and keeps master's once-ever dedupe byte-for-byte.
            receipt = (f"{AGE_PARK_MARKER} cause={cause} head={head_sha} gen={generation} -->"
                       if cause is not None else "")
            label_changed = False
            if park_label not in labels:
                # Sticky human unpark (park_policy.py defect 2): a human who removed THIS label
                # from this PR more recently than any application vetoes the re-park (the whole
                # action — a repeated hand-off comment would spam a PR the human explicitly
                # unparked). The veto is checked against the label actually being written, so the
                # machine class is veto-gated exactly as the human class always was.
                if park_policy.park_vetoed(
                        action.repo, action.number, park_label,
                        lambda r, n: api.paginate(f"/repos/{r}/issues/{n}/timeline"),
                        is_human=lambda login: _is_human_maintainer(
                            api, action.repo, login)):
                    print(f"SKIP PR {action.repo}#{action.number}: {park_label} park suppressed "
                          "(sticky human unpark)")
                    continue
                _ensure_label(api, action.repo, park_label)
                api.request(
                    "POST",
                    f"/repos/{action.repo}/issues/{action.number}/labels",
                    {"labels": [park_label]},
                )
                print(
                    f"WRITE add labels repo={action.repo} issue={action.number} "
                    f"labels={park_label}"
                )
                label_changed = True
            # A MACHINE park dedupes on its own receipt FINGERPRINT, not on "any hand-off comment
            # ever": a PR that machine-parked, provably recovered, was re-admitted and then parked
            # AGAIN must mint a NEW receipt — otherwise generation 2 is invisible, the cap can
            # never be reached, and the escalation to the human class never happens. The HUMAN
            # class keeps the original once-ever dedupe unchanged.
            already_commented = any(
                comment["user"]["login"].casefold() == bot_login.casefold()
                and ((receipt in comment["body"]) if receipt
                     else (STALE_PR_MARKER in comment["body"]))
                for comment in comments
            )
            comment_changed = False
            if not already_commented:
                if machine_park:
                    body = (
                        "> 🤖 SPARQ agent\n\n"
                        f"This worker PR has been untouched beyond the "
                        f"{limits[action.repo].worker_timeout_minutes}-minute maintenance "
                        f"threshold, and {reason}. That is a MACHINE-recoverable cause, not a "
                        f"question for a human, so this is the machine-owned "
                        f"`{park_label}` soft hold: grooming re-admits it automatically once the "
                        "cause is proven recovered, and will not close, merge, or force-push it. "
                        f"No action is required from you.\n\n{STALE_PR_MARKER}\n{receipt}"
                    )
                else:
                    # The human class is now reached only by an UNMAPPED cause (no machine exit
                    # can be proven, so a human really is the exit) or by exceeding the
                    # automatic-re-admission cap. The over-cap case names the flap, because
                    # "this recurred N times" is a genuinely different question from "this took
                    # too long" and is the one a human should be asked.
                    #
                    # THE GRANT COUNT IS READ, NEVER ASSUMED (registry #769). The cap counts PARK
                    # generations, and a generation is consumed by every re-park however the label
                    # was cleared — a human unlabel, or (until #769 bound the class) another
                    # sweep's heuristic. So "generation 3" does NOT imply "the machine granted 2
                    # re-admissions", and the original wording asserted that it did. A comment
                    # that tells a maintainer the machine already tried twice, when the durable
                    # record shows it never tried at all, sends them looking for a flapping cause
                    # instead of the thing that actually kept clearing the label. The grants are
                    # on record as un-park receipts; the sentence states what they say.
                    grants = len(age_receipts(comments, AGE_UNPARK_MARKER, bot_login))
                    if cause is None:
                        flap = ""
                    elif grants:
                        flap = (
                            f" This is age-park generation {generation}; the machine granted "
                            f"{grants} automatic re-admission(s) (cap {AGE_UNPARK_MAX}) and the "
                            "PR returned to the same state, so a repeated failure — not a "
                            "timeout — is what is being escalated."
                        )
                    else:
                        flap = (
                            f" This is age-park generation {generation}, past the cap of "
                            f"{AGE_UNPARK_MAX} automatic re-admissions, so it escalates here. "
                            "Note that the machine granted NO automatic re-admission on this PR: "
                            "it re-parked without its cause ever being proven recovered, so what "
                            "is worth looking at is what kept clearing the park, not a flapping "
                            "cause."
                        )
                    body = (
                        "> 🤖 SPARQ agent\n\n"
                        f"This worker PR has been untouched beyond the {limits[action.repo].worker_timeout_minutes}-"
                        f"minute maintenance threshold, and {reason}. Grooming will not close, merge, or force-push "
                        f"it; human review is required.{flap}\n\n"
                        f"{STALE_PR_MARKER}" + (f"\n{receipt}" if receipt else "")
                    )
                api.request(
                    "POST",
                    f"/repos/{action.repo}/issues/{action.number}/comments",
                    {"body": body},
                )
                print(f"WRITE stale PR comment repo={action.repo} pr={action.number}")
                comment_changed = True
            if label_changed or comment_changed:
                stale_count += 1
        except GroomError as exc:
            stale_failed = True
            print(
                f"ALERT PR {action.repo}#{action.number}: {exc} — stale PR hand-off deferred"
            )
            stale_deferrals.append(f"{action.repo}#{action.number}: {exc}")
            continue
        finally:
            # Same accounting as the issue-repair loop above: a deliberate SKIP is a completed
            # decision, a GroomError is a deferral, and `finally` is what sees both (a `continue`
            # inside the block jumps past any trailing statement).
            if not stale_failed:
                stale_completed += 1
    stale_outcome = PhaseOutcome(
        label="stale PR hand-off",
        changed=stale_completed,
        attempted=stale_attempted,
        deferred=tuple(stale_deferrals),
    )

    reclaimed = _release_claims(registry_api, registry_repo, dead_claims)
    print(
        f"SUMMARY reclaimed={reclaimed} reset={reset} deferred={deferred} "
        f"stale_prs={stale_count} defused_prs={defuse_outcome.changed} "
        f"defuse_deferred={len(defuse_outcome.deferred) + len(defuse_outcome.unavailable)} "
        f"repair_deferred={len(repair_outcome.deferred)} "
        f"stale_pr_deferred={len(stale_outcome.deferred)} "
        f"age_unparked={unpark_count} age_converged={converge_count} "
        f"age_unpark_stalled={stalled_count} "
        f"age_unpark_deferred={len(unpark_outcome.deferred)} "
        f"detect_deferred={len(detect_outcome.deferred)} "
        f"snapshot_deferred={len(snapshot_outcome.deferred)} "
        f"attempt_budget_deferred={len(budget_outcome.deferred)} "
        f"reap_deferred={len(reap_outcome.deferred)}"
    )
    # Issue #644 precedence rule 4, now covering all three per-object phases (issue #647): the
    # sweep's WORK — dead-lease reclaim above included — always completes first, and a systemic
    # failure in ANY phase is reported by the exit status HERE, at the end. A single un-redraftable,
    # unreachable or un-labellable object alongside a completed one stays a per-object ALERT
    # (rule 3) and leaves this green; it does not, and must not, buy silence for a whole-phase
    # failure. The exit status is the report, never the control flow.
    systemic_sweep_failure = sweep_exit_failure(
        (detect_outcome, repair_outcome, defuse_outcome, stale_outcome, unpark_outcome,
         snapshot_outcome, budget_outcome, reap_outcome)
    )
    if systemic_sweep_failure is not None:
        raise GroomError(systemic_sweep_failure)
    return reclaimed, reset, deferred, stale_count


def _self_test() -> int:
    ok = True

    def check(name: str, got: Any, want: Any) -> None:
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    # ---- _ensure_label: reconcile the PARK label descriptions, and ONLY those -----------------
    #
    # The twin of worker-pr's fix. groom already carried the CORRECT text in LABELS, but the
    # early-return meant it never reached a repo whose label predated it — measured live on
    # sparq-org/sparq, `status:parked` still read the superseded #614 wording while the machine's
    # automatic exit was being justified by what that label "promises".
    class _LabelAPI:
        def __init__(self, existing):
            self.existing, self.calls = existing, []

        def request(self, method, path, body=None, allow_404=False, **_kw):
            self.calls.append((method, path, body))
            if method == "GET":
                return self.existing
            return {}

    def ensure_calls(label, existing):
        api = _LabelAPI(existing)
        try:
            _ensure_label(api, "o/r", label)
        except Exception as exc:  # noqa: BLE001
            # TOTAL: a mutant that deletes the `isinstance(existing, dict)` guard makes the
            # PRODUCTION call raise on a non-dict payload; an un-total driver aborts the suite
            # (MEASURED: 308 of 314 checks lost) and the sweep still scores it as a kill.
            return [("raised", type(exc).__name__, None)]
        return [call for call in api.calls if call[0] != "GET"]

    park_desc = LABELS["status:parked"][1]
    check("groom _ensure_label: a DRIFTED park description is PATCHED",
          ensure_calls("status:parked",
                       {"description": "Machine-owned capacity park (soft hold; cleared on "
                                       "readmission)"}),
          [("PATCH", "/repos/o/r/labels/status%3Aparked", {"description": park_desc})])
    check("groom _ensure_label: the PR-side twin is reconciled too",
          len(ensure_calls("review:parked", {"description": "Registry cross-provider "
                                                           "review-loop state"})), 1)
    check("groom _ensure_label: an ALREADY-CORRECT park description writes NOTHING",
          ensure_calls("status:parked", {"description": park_desc}), [])
    check("groom _ensure_label: a NON-MACHINE-park label is NEVER reconciled, however far it has "
          "drifted — including the HUMAN terminal, whose text promises no machine exit",
          [ensure_calls("needs:user", {"description": "something a human wrote"}),
           ensure_calls("status:ready", {"description": "something a human wrote"})], [[], []])
    check("groom reconciles EXACTLY park_policy's machine-owned set, no more and no less",
          sorted(park_policy.MACHINE_OWNED_PARK_LABELS), ["review:parked", "status:parked"])
    check("groom _ensure_label: a MISSING label is still CREATED",
          [call[0] for call in ensure_calls("status:parked", None)], ["POST"])
    check("groom _ensure_label: a non-dict GET payload proves no drift and writes nothing",
          ensure_calls("status:parked", "not-a-label"), [])
    check("groom's park text and park_policy's constant are the SAME string (no drifted copy)",
          {LABELS["status:parked"][1], LABELS["review:parked"][1]},
          {park_policy.MACHINE_PARK_DESCRIPTION})

    now = 10_000
    limits = Limits(worker_timeout_minutes=10, max_attempts=2)
    base = {
        "account": "0123456789abcdef",
        "claim_id": "a" * 32,
        "holder": "owner/repo#7@dispatch-123.1",
        "package": "crate-a",
        "role": "impl",
        "model": "terra",
        "issued_at": now - 100,
        "expires_at": now + 600,
    }
    active = {
        "id": 789,
        "status": "in_progress",
        "conclusion": None,
        "path": ".github/workflows/worker.yml",
    }
    complete = {
        "id": 790,
        "status": "completed",
        "conclusion": "cancelled",
        "path": ".github/workflows/worker.yml",
    }
    check(
        "claim-correlated active lease",
        classify_lease(base, limits, now, {"a" * 32: active}, {}).state,
        "live",
    )
    check(
        "claim-correlated completed lease",
        classify_lease(base, limits, now, {"a" * 32: complete}, {}).state,
        "dead",
    )
    timed = {**base, "issued_at": now - 601, "expires_at": now + 10}
    check(
        "uncorrelated policy timeout",
        classify_lease(timed, limits, now, {}, {}).state,
        "dead",
    )
    check(
        "uncorrelated young lease",
        classify_lease(base, limits, now, {}, {}).state,
        "unknown",
    )
    direct = {**base, "holder": "owner/repo#7@456.1"}
    check(
        "direct holder active worker",
        classify_lease(direct, limits, now, {}, {456: active}).state,
        "live",
    )

    # ---- YAML seam: WORKER_RUN_NAME vs the title worker.yml actually renders (issue #1130) ----
    # A regex over a string another file produces drifts silently the moment that file changes:
    # `${{ inputs.target_repo }}` was added to worker.yml's run-name and this pattern did not
    # follow, so the claim->run correlation matched nothing for months while the fixture-based
    # checks below (which rendered their OWN title) stayed green. Render worker.yml's own
    # `run-name:` and require a match. A missing/unparsable workflow raises — fail closed, never
    # a skipped check.
    #
    # The RENDERER is imported, not written here (#1144): select-and-claim.py needed the identical
    # seam for review-fix.yml and hand-wrote a second copy, and metrics.py — which reads the same
    # two run-names for target attribution — had none at all. `run_name_grammar.py` is the one
    # definition all three now share, and its own self-test reds if any of them re-declares a
    # reader locally. Imported HERE rather than at module scope: groom's production sweep must not
    # gain a new import-time dependency for a check only the self-test runs.
    _grammar_spec = importlib.util.spec_from_file_location(
        "registry_run_name_grammar", Path(__file__).resolve().with_name("run_name_grammar.py")
    )
    assert _grammar_spec and _grammar_spec.loader, "run_name_grammar.py is missing"
    run_name_grammar = importlib.util.module_from_spec(_grammar_spec)
    _grammar_spec.loader.exec_module(run_name_grammar)
    _lane = run_name_grammar.WORKER_LANE
    # An expression with no registered sample is REPORTED here and also renders to a sentinel that
    # matches no grammar, so a new or renamed workflow input reds the seam twice over rather than
    # quietly rendering to nothing.
    _rendering = run_name_grammar.render_lane(_lane)
    _rendered = _rendering.text
    check(
        "[#1130] every worker.yml run-name expression has a known rendering",
        _rendering.unknown,
        (),
    )
    check(
        "[#1130] the render is not vacuous — every sample value reached the title",
        _rendering.reached,
        tuple(sorted(_lane.samples.values())),
    )

    def _matched_claim(title: str) -> str | None:
        # None-safe: a regression here must report a readable FAIL, not abort the whole suite.
        match = WORKER_RUN_NAME.fullmatch(title)
        return match.group("claim") if match else None

    _seam = WORKER_RUN_NAME.fullmatch(_rendered)
    check(
        "[#1130] WORKER_RUN_NAME fullmatches worker.yml's OWN rendered run-name",
        _seam is not None and _seam.group("claim") == _lane.claim,
        True,
    )
    # Second anchor: display_title values measured off the live runs API (#1130). Independent of
    # the render above, so a run-name edit that is mirrored into BOTH still has to face reality.
    for _measured, _claim in (
        ("worker jeswr/agent-account-registry claim=f45ca53d124d4127b9279a7998e3303d",
         "f45ca53d124d4127b9279a7998e3303d"),
        ("worker sparq-org/sparq claim=e84718f205574e3fa4a1724912625e64",
         "e84718f205574e3fa4a1724912625e64"),
    ):
        _m = WORKER_RUN_NAME.fullmatch(_measured)
        check(
            f"[#1130] live worker run title correlates: {_measured}",
            _m is not None and _m.group("claim") == _claim,
            True,
        )
    check(
        "MUTATION: the target-less pattern matches NO live worker title (the #1130 defect)",
        re.compile(r"worker claim=(?P<claim>[0-9a-f]{32}|self)").fullmatch(
            "worker sparq-org/sparq claim=" + "f" * 32),
        None,
    )
    check(
        "[#1130] a pre-change (target-less) history title still correlates",
        _matched_claim("worker claim=" + "a" * 32),
        "a" * 32,
    )
    check(
        "a self-dispatch run is matched but carries no claim",
        _matched_claim("worker sparq-org/sparq claim=self"),
        "self",
    )
    # The widened pattern must still be a PARSE, not a wildcard: a malformed claim id, a trailing
    # suffix, or another lane's run must never correlate to a lease.
    for _reject in (
        "worker sparq-org/sparq claim=not-a-claim-id",
        "worker sparq-org/sparq claim=" + "A" * 32,          # hex is lower-case only
        "worker sparq-org/sparq claim=" + "a" * 31,
        "worker sparq-org/sparq claim=" + "a" * 32 + " [resume]",
        "worker sparq-org/sparq owner/other claim=" + "a" * 32,
        "review-fix review sparq-org/sparq claim=" + "a" * 32,
        "not-worker sparq-org/sparq claim=" + "a" * 32,
    ):
        check(
            f"a non-worker-claim title never correlates: {_reject}",
            WORKER_RUN_NAME.fullmatch(_reject),
            None,
        )

    # ---- _correlate_claim_runs: page the worker-run history, never just newest-100 (issue #173) ----
    # A dispatcher-held live lease whose worker run has aged off page 1 must still be correlated;
    # reading only the newest page would classify it dead on its timeout and reset a live worker.
    def _iso(epoch: int) -> str:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat()

    def _worker_run(claim: str, created: int, status: str = "in_progress") -> dict[str, Any]:
        # The REAL title shape worker.yml renders (#1130) — the target repo sits between the lane
        # name and `claim=`. This fixture carried the target-less shape, which is why every
        # correlation check below stayed green while the live correlation matched nothing.
        return {"status": status, "created_at": _iso(created),
                "display_title": f"worker sparq-org/sparq claim={claim}"}

    # Fillers newer than the live lease's issuance, filling page 1 exactly (100) so the walk must
    # continue; none of them is the target claim.
    live_lease = {**base, "claim_id": "a" * 32, "holder": "owner/repo#7@dispatch-123.1",
                  "issued_at": now - 100}
    page1 = [_worker_run(f"{i:032x}", now + 50) for i in range(100)]
    target_run = _worker_run("a" * 32, now - 40)  # created AFTER the lease was issued
    page2 = [target_run] + [_worker_run(f"{i:032x}", now - 60) for i in range(1000, 1099)]

    class _RunsAPI:
        def __init__(self, pages):
            self.pages, self.registry_repo = pages, "owner/registry"
            self.requested_pages: list[int] = []

        def request(self, method, path, **_kwargs):
            page = int(re.search(r"[?&]page=(\d+)", path).group(1))
            self.requested_pages.append(page)
            runs = self.pages[page - 1] if page - 1 < len(self.pages) else []
            return {"workflow_runs": runs}

    def _newest_page_only(runs):  # models the reverted single-snapshot behaviour
        out: dict[str, Any] = {}
        for run in runs:
            m = WORKER_RUN_NAME.fullmatch(run["display_title"])
            if m and m.group("claim") != "self":
                out[m.group("claim")] = run
        return out

    check(
        "MUTATION: the newest-100 snapshot alone MISSES the aged-off live claim (non-vacuous)",
        ("a" * 32) in _newest_page_only(page1),
        False,
    )
    found_api = _RunsAPI([page1, page2])
    check(
        "paginated correlation finds the aged-off live claim on page 2 (issue #173)",
        _correlate_claim_runs(found_api, [live_lease]).get("a" * 32) is target_run,
        True,
    )
    check(
        "correlation stops as soon as every claim is matched (no needless paging)",
        found_api.requested_pages,
        [1, 2],
    )
    # Time-window stop: a claim with NO run anywhere is not chased to the ceiling — once a page's
    # oldest run predates the oldest live issuance the window is covered and the walk returns.
    windowed = _RunsAPI([
        [_worker_run(f"{i:032x}", now + 50) for i in range(100)],   # all newer than issuance
        [_worker_run(f"{i:032x}", now - 500) for i in range(1000, 1100)],  # oldest < issuance
    ])
    check(
        "an uncorrelated claim yields no run once the time window is covered",
        ("a" * 32) in _correlate_claim_runs(windowed, [live_lease]),
        False,
    )
    check("time-window stop pages only until the window is covered", windowed.requested_pages, [1, 2])

    # Fail-closed on truncation: full pages that never reach the window and never match the claim
    # must raise, never silently return an empty (→ eventually "dead") correlation.
    class _TruncAPI:
        def __init__(self):
            self.registry_repo, self.calls = "owner/registry", 0

        def request(self, method, path, **_kwargs):
            page = int(re.search(r"[?&]page=(\d+)", path).group(1))
            self.calls += 1
            # 100 distinct runs per page, all newer than issuance → never exhausts, never covers.
            return {"workflow_runs": [
                _worker_run(f"{page * 100 + j:032x}", now + 50) for j in range(100)
            ]}

    trunc = _TruncAPI()
    truncated_loud = False
    try:
        _correlate_claim_runs(trunc, [live_lease])
    except GroomError as exc:
        truncated_loud = "truncated" in str(exc)
    check("truncated worker-run history fails closed (never a silent dead lease)", truncated_loud, True)
    check("truncation walks the full page ceiling before failing", trunc.calls, WORKER_RUN_PAGE_CEILING)

    comments = [
        {"user": {"login": "app[bot]"}, "body": ATTEMPT_MARKER + " run=1 -->"},
        {"user": {"login": "APP[bot]"}, "body": ATTEMPT_MARKER + " run=2 -->"},
        {"user": {"login": "human"}, "body": ATTEMPT_MARKER},
    ]
    check("bot-only attempt count", count_attempts(comments, "app[bot]"), 2)

    # ---- [#1303] THE ATTEMPT-BUDGET READ SKIP. -------------------------------------------
    # The sweep's dominant request cost is one `/issues/{n}/comments` GET per commented issue,
    # on the SAME rate-limit partition every other lane's issues/pulls reads draw from. The skip
    # is only legitimate if it is DECISION-EQUIVALENT, so that is what is checked — not merely
    # that the predicate returns what it returns.

    # (a) The bound itself, EXECUTED rather than asserted. `count_attempts` counts a subset of
    #     the comments it is given, so it can never exceed len(comments). Without this row the
    #     whole optimisation rests on a docstring.
    check(
        "the comment count is a real upper bound on count_attempts (the premise of the skip)",
        all(
            count_attempts(comments[:k], "app[bot]") <= k
            for k in range(len(comments) + 1)
        ),
        True,
    )

    # (b) BOUNDARY, and the reason it is `>=` not `>`. An issue with exactly max_attempts
    #     comments can have every one of them be an attempt comment and MUST still be fetched.
    #     Mutating `>=` to `>` in attempts_fetch_needed reds this row.
    _quiet = {"status:ready"}   # a label set on which the orphan repair cannot fire
    check(
        "fetch is needed at exactly the cap, and not below it",
        tuple(attempts_fetch_needed(n, _quiet, False, 3) for n in (0, 1, 2, 3, 4)),
        (False, False, False, True, True),
    )
    # ...and the boundary case is REAL: three comments that are all attempts exhausts a cap of 3.
    _all_attempts = [
        {"user": {"login": "app[bot]"}, "body": ATTEMPT_MARKER + f" run={i} -->"}
        for i in range(3)
    ]
    check(
        "the cap-boundary issue the `>=` protects really does exhaust its budget",
        (count_attempts(_all_attempts, "app[bot]"),
         attempts_fetch_needed(3, _quiet, False, 3)),
        (3, True),
    )

    # (b2) THE ORPHAN-REPAIR GUARD, which a cap-only filter cannot see. `used >= 1` is sensitive
    #      at 0-vs-1, where the comment-count upper bound decides nothing — so a BELOW-CAP issue
    #      on which the repair can still fire MUST be fetched. Deleting the orphan-repair half of
    #      attempts_fetch_needed reds the first row here; deleting its label/staleness conjuncts
    #      reds the rest (each would re-spend the requests this change exists to save).
    check(
        "below the cap, a STALE label-less issue with a comment still needs the real count "
        "(the `used >= 1` orphan repair can fire on it)",
        attempts_fetch_needed(1, set(), True, 3), True,
    )
    check(
        "...but not when the repair's own free conjuncts already refuse it",
        (attempts_fetch_needed(1, set(), False, 3),                     # not stale
         attempts_fetch_needed(1, {"needs:user"}, True, 3),             # human-owned
         attempts_fetch_needed(1, {"status:ready"}, True, 3),           # holds a status
         attempts_fetch_needed(1, {"status:in-progress"}, True, 3),     # earlier branch returns
         attempts_fetch_needed(0, set(), True, 3)),                     # no comments at all
        (False, False, False, False, False),
    )
    check(
        "...and status:in-progress-review is the ONE status the repair still fires on",
        attempts_fetch_needed(1, {"status:in-progress-review"}, True, 3), True,
    )
    # THE CROSS-FILE SEAM. The filter's staleness input must mean what `_plan_actions` means by
    # `stale`, or the two disagree about which issues are exempt. Both are `now - updated_at >=
    # threshold_seconds`; pin the boundary from both sides.
    _seam_limits = Limits(worker_timeout_minutes=10, max_attempts=3)
    check(
        "seam: the filter's staleness boundary is _plan_actions' (>= threshold, not >)",
        (attempts_fetch_needed(1, set(), 600 >= _seam_limits.threshold_seconds, 3),
         attempts_fetch_needed(1, set(), 599 >= _seam_limits.threshold_seconds, 3)),
        (True, False),
    )

    # (c) DECISION EQUIVALENCE, through the real consumer. `_plan_actions` is the ONLY reader of
    #     the attempts map, and it reads it through one comparison. Plan the same fixture twice —
    #     once with the true attempt counts a full fetch would produce, once with the bounds the
    #     skip records — and require byte-identical actions. A skip that changed any decision
    #     reds this row; so does a call site that records 0 instead of the bound while some other
    #     consumer exists.
    _eq_limits = Limits(worker_timeout_minutes=10, max_attempts=3)
    _eq_stale = datetime.fromtimestamp(now - 10_000, timezone.utc).isoformat()
    # #31 is BELOW the cap and carries `status:ready`, so the orphan repair's own conjuncts
    #     refuse it -> SKIPPED, recorded as the bound 2 while the truth is 1. This is the row
    #     that makes the equivalence non-trivial.
    # #32 sits AT the cap (3 comments, 3 attempts) -> fetched, recorded as the true 3 -> defers.
    # #33 sits above the cap in COMMENTS but only 1 is an attempt -> fetched, true 1, no defer
    #     from exhaustion, but the orphan repair DOES fire on it (stale, statusless, 1 attempt).
    _eq_issues = {
        "owner/repo": {
            31: {"labels": [{"name": "status:ready"}], "updated_at": _eq_stale, "comments": 2},
            32: {"labels": [{"name": "area:a"}], "updated_at": _eq_stale, "comments": 3},
            33: {"labels": [{"name": "area:a"}], "updated_at": _eq_stale, "comments": 9},
        }
    }
    _eq_true = {("owner/repo", 31): 1, ("owner/repo", 32): 3, ("owner/repo", 33): 1}
    # Exactly what the new call site records: the true count when fetched, the comment count when
    # the fetch was skipped.
    _eq_recorded = {
        ("owner/repo", n): (
            _eq_true[("owner/repo", n)]
            if attempts_fetch_needed(
                _eq_issues["owner/repo"][n]["comments"],
                {lab["name"] for lab in _eq_issues["owner/repo"][n]["labels"]},
                True,   # every _eq issue carries the stale updated_at above
                3,
            )
            else _eq_issues["owner/repo"][n]["comments"]
        )
        for n in (31, 32, 33)
    }
    check(
        "the recorded map differs from the true map (otherwise the equivalence below is vacuous)",
        _eq_recorded != _eq_true,
        True,
    )

    def _eq_plan(attempt_map):
        acts, prs, dead = _plan_actions(
            {"owner/repo": _eq_limits}, _eq_issues, {"owner/repo": {}},
            {"owner/repo": set()}, attempt_map, {}, [], {}, now, "app[bot]",
        )
        return ([(a.number, a.mode, a.reason) for a in acts], prs, dead)

    check(
        "DECISION EQUIVALENCE: planning on the recorded bounds equals planning on true counts",
        _eq_plan(_eq_recorded), _eq_plan(_eq_true),
    )
    # NON-VACUITY of that equivalence: the fixture must actually exercise the exhaustion park,
    # or two empty plans would compare equal and prove nothing.
    check(
        "...and the fixture really does plan an exhaustion park (the equivalence is not of two "
        "empty plans)",
        [(number, mode) for number, mode, _reason in _eq_plan(_eq_true)[0]],
        [(32, "defer"), (33, "ready")],
    )

    check(
        "ready transition is idempotent",
        label_transition({"status:ready"}, "ready"),
        (set(), set()),
    )
    check(
        "defer transition removes dispatch state",
        label_transition({"status:ready", "status:in-progress"}, "defer"),
        ({"status:parked", "status:deferred"}, {"status:ready", "status:in-progress"}),
    )
    # Park-policy defect 1: the budget-exhaustion defer is MACHINE-owned — it must never write
    # the human-question terminal needs:user (which stripped the issue's PR from the review
    # loop and terminally absorbed it; 2026-07-18 mass-park incident).
    check(
        "defer transition never writes needs:user",
        "needs:user" in label_transition({"status:ready"}, "defer")[0],
        False,
    )
    check(
        "defer transition is idempotent on an already-parked issue",
        label_transition({"status:parked", "status:deferred"}, "defer"),
        (set(), set()),
    )
    check(
        "ready transition clears the review-loop label",
        label_transition({"status:in-progress-review"}, "ready"),
        ({"status:ready"}, {"status:in-progress-review"}),
    )
    check(
        "ready repair clears a leftover machine park",
        label_transition({"status:parked", "status:in-progress-review"}, "ready"),
        ({"status:ready"}, {"status:parked", "status:in-progress-review"}),
    )

    class _StubAPI:
        def __init__(self, responses):
            self.responses = responses
            self.paths: list[str] = []

        def request(self, method, path, **_kwargs):
            self.paths.append(path)
            return self.responses.get(path)

    stub = _StubAPI({"/users/app%5Bbot%5D": {"login": "app[bot]"}})
    check("bot login via app slug", _bot_login(stub, "app"), "app[bot]")
    check(
        "slug path avoids GET /user",
        stub.paths,
        ["/users/app%5Bbot%5D"],
    )
    mismatch_failed = False
    try:
        _bot_login(_StubAPI({"/users/app%5Bbot%5D": {"login": "other[bot]"}}), "app")
    except GroomError:
        mismatch_failed = True
    check("slug/login mismatch fails closed", mismatch_failed, True)
    unsafe_slug_failed = False
    try:
        _bot_login(_StubAPI({}), "bad/slug")
    except GroomError:
        unsafe_slug_failed = True
    check("unsafe slug fails closed", unsafe_slug_failed, True)
    check(
        "no slug falls back to /user (non-App token)",
        _bot_login(_StubAPI({"/user": {"login": "legacy[bot]"}})),
        "legacy[bot]",
    )
    old_pr = {
        "updated_at": datetime.fromtimestamp(now - 601, timezone.utc).isoformat(),
        "head": {"ref": "sparq-agent/issue-7-99-1"},
        "user": {"login": "app[bot]"},
        "body": WORKER_PR_MARKER + "\n\nFixes #7",
        "draft": False,
        "mergeable_state": "blocked",
    }
    check(
        "stale blocked worker PR",
        stale_worker_pr_reason(
            old_pr, "app[bot]", limits.threshold_seconds, now, has_valid_provenance=True
        ),
        BAD_MERGE_STATES["blocked"],
    )
    check(
        "clean worker PR is preserved",
        stale_worker_pr_reason(
            {**old_pr, "mergeable_state": "clean"},
            "app[bot]",
            600,
            now,
            has_valid_provenance=True,
        ),
        None,
    )
    check("worker branch links issue", linked_issue_numbers(old_pr), {7})

    # ---- issue #548: safely defuse stale terminally parked, ready-for-review PRs. ----
    # These fixtures drive the same live predicate twice (collection and mutation boundary) and
    # the real gh/comment executor. Removing any age/hold/draft/latch rule therefore turns a
    # negative fixture into a target mutation and reds its assertion.
    saved_stale_hours = os.environ.pop("STALE_HOURS", None)
    try:
        check(
            "#548 STALE_HOURS defaults to six",
            _configured_stale_hours(argparse.Namespace()),
            6,
        )
    finally:
        if saved_stale_hours is not None:
            os.environ["STALE_HOURS"] = saved_stale_hours

    defuse_now = 100_000
    defuse_stale_seconds = DEFAULT_STALE_HOURS * 3600
    old_activity = datetime.fromtimestamp(
        defuse_now - defuse_stale_seconds - 1, timezone.utc
    ).isoformat()
    recent_activity = datetime.fromtimestamp(defuse_now - 60, timezone.utc).isoformat()

    # The App login these fixtures' PRs are authored by. Ownership is EXACT (a `type == "Bot"`
    # check would admit dependabot and every other third-party App — see _parked_pr_snapshot).
    DEFUSE_BOT_LOGIN = "app[bot]"   # the identity this module's harness resolves throughout

    def _defuse_pull(number: int, **changes: Any) -> dict[str, Any]:
        pull = {
            "number": number,
            "state": "open",
            "draft": False,
            "labels": [{"name": "needs:user"}],
            "updated_at": old_activity,
            "head": {"sha": f"{number:040x}"},
            # Defuse candidates are OUR OWN parked PRs. A human's PR, and a FOREIGN bot's,
            # are both excluded by _parked_pr_snapshot; both are covered separately below.
            "user": {"login": DEFUSE_BOT_LOGIN, "type": "Bot"},
            "auto_merge": None,
        }
        pull.update(changes)
        return pull

    defuse_details = {
        1: _defuse_pull(1),
        2: _defuse_pull(2, updated_at=recent_activity),
        3: _defuse_pull(3, labels=[{"name": "review:changes"}]),
        4: _defuse_pull(4, auto_merge={"enabled_at": old_activity}),
        5: _defuse_pull(5),
        6: _defuse_pull(6, draft=True),
        7: _defuse_pull(7),
        8: _defuse_pull(8),
        9: _defuse_pull(9),
        # #3427: identical to the admitted #1 in EVERY respect except authorship. This is the
        # live shape that made groom permanently red — the maintainer's own `needs:user` PR was
        # selected on every sweep and every redraft came back
        # `Resource not accessible by integration (convertPullRequestToDraft)`.
        10: _defuse_pull(10, user={"login": "jeswr", "type": "User"}),
        # Unknown/malformed authorship must fail toward NOT touching the PR. These carry OUR
        # OWN login on purpose: with a foreign login they would be rejected by the ownership
        # conjunct and would pin nothing about `type` (exactly how the r1 version was vacuous).
        11: _defuse_pull(11, user=None),
        12: _defuse_pull(12, user={"login": DEFUSE_BOT_LOGIN}),          # no `type` at all
        20: _defuse_pull(20, user={"login": DEFUSE_BOT_LOGIN, "type": "User"}),   # contradictory
        21: _defuse_pull(21, user={"login": DEFUSE_BOT_LOGIN, "type": ""}),       # empty type
        # A FOREIGN bot. `type == "Bot"` admitted these; cross-provider review drove
        # dependabot[bot] all the way through live revalidation to a real `gh pr ready --undo`
        # plus an audit comment. Ownership is a single login, not a category.
        13: _defuse_pull(13, user={"login": "dependabot[bot]", "type": "Bot"}),
        14: _defuse_pull(14, user={"login": "copilot[bot]", "type": "Bot"}),
        15: _defuse_pull(15, user={"login": "github-actions[bot]", "type": "Bot"}),
        # Logins that CONTAIN ours but are not ours — the App-name-squatting shape. Found by
        # mutation: with only the fixtures above, relaxing the comparison to a substring test
        # stayed GREEN, because none of them is a superstring of the bot login.
        17: _defuse_pull(17, user={"login": "not-app[bot]", "type": "Bot"}),
        18: _defuse_pull(18, user={"login": "app[bot]-lookalike", "type": "Bot"}),
    }
    del defuse_details[8]["auto_merge"]  # unknown REST latch state must fail closed

    class _DefuseAPI:
        def __init__(self):
            self.comments: list[tuple[str, str]] = []

        def request(self, method, path, body=None, allow_404=False, **_kwargs):
            if method == "GET":
                return defuse_details.get(int(path.rsplit("/", 1)[1]))
            if path == "/graphql":
                number = body["variables"]["number"]
                if number == 9:
                    return {"data": {"repository": {"pullRequest": {
                        "mergeQueueEntry": None,
                        # Missing autoMergeRequest is UNKNOWN, never safely absent.
                    }}}}
                return {"data": {"repository": {"pullRequest": {
                    "mergeQueueEntry": {"id": "queue-5"} if number == 5 else None,
                    "autoMergeRequest": {"enabledAt": old_activity}
                    if number == 7 else None,
                }}}}
            self.comments.append((path, body["body"]))
            return {}

    defuse_api = _DefuseAPI()
    defuse_candidates = _collect_defuse_prs(
        defuse_api,
        "owner/repo",
        defuse_details,
        defuse_now,
        defuse_stale_seconds,
        DEFUSE_BOT_LOGIN,
    )
    check(
        "#548 tripwire (b): a recently-active parked PR is NOT defused",
        ("owner/repo", 2) in defuse_candidates,
        False,
    )
    # #3427: a HUMAN's parked PR is not ours to re-draft. Asserted against the admitted bot PR #1
    # in the same breath — without that contrast this would also pass if the whole defuse phase
    # were deleted, which is the vacuity shape this repo keeps producing.
    check(
        "#3427: a human-authored parked PR is NOT a defuse candidate, while the otherwise "
        "IDENTICAL bot-authored PR still is",
        (
            ("owner/repo", 1) in defuse_candidates,
            ("owner/repo", 10) in defuse_candidates,
        ),
        (True, False),
    )
    check(
        "#3427: unknown or malformed authorship fails toward NOT mutating the PR — asserted "
        "with OUR OWN login, so it pins the `type` conjunct rather than the ownership one "
        "(#659 review r2: the foreign-login version was rejected for the wrong reason)",
        {("owner/repo", number) in defuse_candidates for number in (11, 12, 20, 21)},
        {False},
    )
    # The first cut of this guard tested `user.type == "Bot"`, which admits EVERY GitHub App.
    # Cross-provider review reproduced dependabot[bot] passing live revalidation and reaching a
    # real `gh pr ready --undo` plus an audit comment. The obligation is exact ownership of a
    # single login, so a predicate over the category of bot-authored PRs is the wrong scope.
    check(
        "#659 review: a FOREIGN bot's parked PR is NOT a defuse candidate (type == 'Bot' is "
        "not ownership — dependabot/copilot/github-actions are other people's PRs)",
        {("owner/repo", number) in defuse_candidates for number in (13, 14, 15)},
        {False},
    )
    check(
        "#659 review: a login that merely CONTAINS ours is NOT ours (equality, not substring "
        "— an App-name squatter must not inherit our authority)",
        {("owner/repo", number) in defuse_candidates for number in (17, 18)},
        {False},
    )
    check(
        "#659 review: ownership comparison is case-insensitive, as GitHub logins are",
        _parked_pr_snapshot(
            _defuse_pull(16, user={"login": DEFUSE_BOT_LOGIN.upper(), "type": "Bot"}),
            defuse_now, defuse_stale_seconds, DEFUSE_BOT_LOGIN,
        )
        is not None,
        True,
    )
    # An unresolved App identity must admit NOTHING: with nothing to compare against, every PR
    # belongs to somebody else. Asserted against the SAME fixture that IS admitted with an
    # identity, so this cannot pass merely because the fixture was unusable.
    check(
        "#659 review: an unresolved bot_login admits nothing (fail-closed), while the same "
        "fixture IS admitted once the identity is known",
        (
            _parked_pr_snapshot(defuse_details[1], defuse_now, defuse_stale_seconds, "")
            is None,
            # The case the guard EXISTS for, found by mutation: without it, a degraded payload
            # reporting an empty login would compare equal to an unresolved empty bot_login and
            # be admitted. Two empty strings must not constitute a match.
            _parked_pr_snapshot(
                _defuse_pull(19, user={"login": "", "type": "Bot"}),
                defuse_now, defuse_stale_seconds, "",
            )
            is None,
            _parked_pr_snapshot(
                defuse_details[1], defuse_now, defuse_stale_seconds, DEFUSE_BOT_LOGIN
            )
            is not None,
        ),
        (True, True, True),
    )
    check(
        "#548 tripwire (c): review:changes alone is NOT a terminal defuse hold",
        ("owner/repo", 3) in defuse_candidates,
        False,
    )
    check(
        "#548 tripwire (d): REST-auto-merged or queued PRs are NOT defused",
        {("owner/repo", number) in defuse_candidates for number in (4, 5)},
        {False},
    )
    check(
        "#548 tripwire (d): GraphQL auto-merge and unknown latch states fail closed",
        {("owner/repo", number) in defuse_candidates for number in (7, 8, 9)},
        {False},
    )
    check(
        "#548 tripwire (e): an already-draft parked PR is a no-op",
        ("owner/repo", 6) in defuse_candidates,
        False,
    )

    empty_plan_args = (
        {"owner/repo": limits},
        {"owner/repo": {}},
        {"owner/repo": {}},
        {"owner/repo": set()},
        {},
        {},
        [],
        {},
        defuse_now,
        "app[bot]",
    )
    _empty_issues, safe_defuse_actions, _empty_claims = _plan_actions(
        *empty_plan_args, defuse_prs=defuse_candidates
    )
    check(
        "#548 safe-class planner admits the stale needs:user non-draft PR",
        [(action.number, action.mode) for action in safe_defuse_actions],
        [(1, "defuse")],
    )

    defuse_commands: list[tuple[list[str], str | None]] = []

    class _DefuseResult:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_defuse_run(args, **kwargs):
        defuse_commands.append((list(args), (kwargs.get("env") or {}).get("GH_TOKEN")))
        return _DefuseResult()

    real_subprocess_run = subprocess.run
    subprocess.run = _fake_defuse_run
    try:
        defused = _execute_defuse_actions(
            safe_defuse_actions,
            {"owner/repo": defuse_api},
            {"owner": "owner-target-token"},
            defuse_now,
            defuse_stale_seconds,
            DEFUSE_BOT_LOGIN,
        )
    finally:
        subprocess.run = real_subprocess_run
    check(
        "#548 tripwire (a): stale needs:user non-draft PR is redrafted with its target token",
        (defused.changed, defuse_commands),
        (1, [(["gh", "pr", "ready", "1", "-R", "owner/repo", "--undo"],
              "owner-target-token")]),
    )
    check(
        "#644: an all-clean defuse phase is attempted, completed, and leaves the run green",
        (defused.attempted, defused.deferred, defused.unavailable,
         defuse_exit_failure(defused)),
        (1, (), (), None),
    )
    check(
        "#548 tripwire (a): defuse writes one loud audit comment with resume instructions",
        (
            len(defuse_api.comments),
            defuse_api.comments[0][0] if defuse_api.comments else "",
            defuse_api.comments[0][1].startswith("> 🤖 SPARQ agent")
            if defuse_api.comments else False,
            "Marking it ready for review resumes it" in defuse_api.comments[0][1]
            if defuse_api.comments else False,
        ),
        (1, "/repos/owner/repo/issues/1/comments", True, True),
    )

    over_bound = {
        ("owner/repo", number): (f"{number:040x}", old_activity)
        for number in range(1, MAX_AUTO_DEFUSES_PER_TICK + 3)
    }
    _bound_issues, bound_actions, _bound_claims = _plan_actions(
        *empty_plan_args, defuse_prs=over_bound
    )
    check(
        "#548 tripwire (f): auto-defuses are bounded to ten per sweep",
        (MAX_AUTO_DEFUSES_PER_TICK, len(bound_actions)),
        (10, 10),
    )

    # ---- issue #644: an un-redraftable PR must not abort the sweep, and must say WHY ------------
    # Live incident: sparq-org/sparq#3427 (open, non-draft, needs:user, quiet since 01:41:36Z)
    # became a defuse candidate at 07:41:36Z, and groom then failed on EVERY run — the redraft's
    # GroomError was raised from OUTSIDE the per-PR resilience block, and because candidates are
    # processed lowest-number-first it was a permanent head-of-line block: nothing after the defuse
    # phase ran, dead-lease reclaim included. The failure also discarded `gh`'s stderr, so three
    # hours of identical failures carried zero cause. This fixture drives BOTH defects from the
    # LIVE functions (no fixture text is mutated to make them red).
    redraft_stderr = (
        "GraphQL: refusing to allow a GitHub App to create or update workflow "
        "`.github/workflows/codeql.yml` without `workflows` permission (convertPullRequestToDraft)"
    )

    class _RedraftAPI:
        """A defuse-phase API whose latch reads always succeed, so only the redraft can fail."""

        def __init__(self):
            self.comments: list[str] = []
            self.pulls = {21: _defuse_pull(21), 22: _defuse_pull(22)}
            self.comment_failures: set[int] = set()

        def request(self, method, path, body=None, allow_404=False, **_kwargs):
            if method == "GET":
                return self.pulls.get(int(path.rsplit("/", 1)[1]))
            if path == "/graphql":
                return {"data": {"repository": {"pullRequest": {
                    "mergeQueueEntry": None, "autoMergeRequest": None}}}}
            number = int(path.split("/issues/", 1)[1].split("/", 1)[0])
            if number in self.comment_failures:
                raise GroomError("issue comment write failed")
            self.comments.append(path)
            return {}

    def _redraft_actions(api: _RedraftAPI) -> list[PullAction]:
        return [
            PullAction(
                repo="owner/repo",
                number=number,
                reason="terminally parked and quiet",
                mode="defuse",
                head_sha=api.pulls[number]["head"]["sha"],
                updated_at=api.pulls[number]["updated_at"],
            )
            for number in sorted(api.pulls)
        ]

    def _run_defuse(
        api: _RedraftAPI,
        failing: set[int],
        tokens: dict[str, str] | None = None,
        stderr: str = redraft_stderr,
        gh_missing: bool = False,
    ) -> tuple[DefuseOutcome | None, bool, list[int]]:
        """Run the real defuse phase against `api`; report whether it ABORTED (the #644 defect)."""
        drafted: list[int] = []

        class _Result:
            def __init__(self, number):
                self.returncode = 1 if number in failing else 0
                self.stdout = ""
                self.stderr = stderr if number in failing else ""

        def _fake_run(args, **_kwargs):
            if gh_missing:
                raise FileNotFoundError("gh")
            number = int(args[3])
            if number not in failing:
                drafted.append(number)
            return _Result(number)

        real_run = subprocess.run
        subprocess.run = _fake_run
        try:
            return _execute_defuse_actions(
                _redraft_actions(api),
                {"owner/repo": api},
                {"owner": "owner-target-token"} if tokens is None else tokens,
                defuse_now,
                defuse_stale_seconds,
                DEFUSE_BOT_LOGIN,
            ), False, drafted
        except GroomError:
            # Reached ONLY if a per-PR failure escapes the block — i.e. the defect is back.
            return None, True, drafted
        finally:
            subprocess.run = real_run

    # (1) THE DEFECT: the LOWEST-numbered candidate cannot be redrafted. The sweep must process the
    # remaining candidate anyway. Moving the _redraft_pr call back outside the per-PR
    # `except GroomError -> defuse deferred -> continue` block reds this check.
    head_of_line_api = _RedraftAPI()
    head_of_line, aborted, drafted = _run_defuse(head_of_line_api, failing={21})
    check(
        "#644: an un-redraftable LOWEST-numbered PR must NOT abort the defuse phase (the "
        "_redraft_pr call must sit INSIDE the per-PR `except GroomError -> deferred -> continue`)",
        aborted,
        False,
    )
    check(
        "#644: the later candidate is still redrafted and audited after the head-of-line failure",
        (drafted, head_of_line_api.comments, head_of_line.changed if head_of_line else -1),
        ([22], ["/repos/owner/repo/issues/22/comments"], 1),
    )
    check(
        "#644: the FAILED candidate gets no audit comment and is recorded as one deferral",
        (
            "/repos/owner/repo/issues/21/comments" in head_of_line_api.comments
            if head_of_line else True,
            len(head_of_line.deferred) if head_of_line else -1,
            head_of_line.deferred[0].startswith("owner/repo#21: ") if head_of_line else False,
        ),
        (False, 1, True),
    )
    # (2) THE DISCARDED CAUSE: `gh`'s stderr must reach the reported error, verbatim enough to
    # identify the refusal. Dropping _gh_failure_detail (or its result.stderr read) reds this.
    check(
        "#644: a redraft failure REPORTS gh's stderr (the discarded-cause defect: 'workflows "
        "permission' must be visible in the deferral, not just 'redraft failed')",
        (
            "without `workflows` permission" in head_of_line.deferred[0]
            if head_of_line and head_of_line.deferred else False,
            "gh exited 1" in head_of_line.deferred[0]
            if head_of_line and head_of_line.deferred else False,
        ),
        (True, True),
    )
    masked_api = _RedraftAPI()
    masked, _aborted, _drafted = _run_defuse(
        masked_api,
        failing={21},
        stderr="gh: authentication failed for token owner-target-token (ghs_abcdefgh12345678)",
    )
    check(
        "#644: the reported gh stderr is credential-MASKED (neither the target token nor any "
        "token-shaped string may reach the operator log)",
        (
            "owner-target-token" in masked.deferred[0] if masked and masked.deferred else True,
            "ghs_abcdefgh12345678" in masked.deferred[0] if masked and masked.deferred else True,
            masked.deferred[0].count("***") if masked and masked.deferred else -1,
        ),
        (False, False, 2),
    )
    check(
        "#644: an empty gh stderr still reports the exit code rather than nothing",
        _gh_failure_detail(
            type("_R", (), {"returncode": 3, "stdout": "", "stderr": ""})(), ""
        ),
        "gh exited 3 with no output",
    )
    bounded = _gh_failure_detail(
        type("_R", (), {"returncode": 1, "stdout": "", "stderr": "x" * 5000})(), ""
    )
    check(
        "#644: the reported gh output is bounded (a runaway body must not flood the log)",
        (len(bounded) <= GH_DETAIL_LIMIT + 40, bounded.endswith("…")),
        (True, True),
    )
    # (3) EXIT-STATUS DISCRIMINATION, both directions. This is the exit-zero-swallows-failure
    # guard: per-PR deferral must not make a whole-phase failure silently green.
    check(
        "#644 precedence rule 3: ONE deferred candidate alongside a completed defuse leaves the "
        "run GREEN (a single un-redraftable PR only defers itself)",
        defuse_exit_failure(head_of_line) if head_of_line else "aborted",
        None,
    )
    all_failed_api = _RedraftAPI()
    all_failed, _aborted, all_drafted = _run_defuse(all_failed_api, failing={21, 22})
    all_failed_reason = defuse_exit_failure(all_failed) if all_failed else None
    check(
        "#644 precedence rule 2: EVERY candidate failing is systemic — the run exits NON-zero and "
        "names the deferrals, never a silent green",
        (
            all_drafted,
            all_failed.changed if all_failed else -1,
            all_failed.attempted if all_failed else -1,
            all_failed_reason is not None,
            "every parked PR defuse failed (2 attempted, 0 completed)" in (all_failed_reason or ""),
            "owner/repo#21" in (all_failed_reason or "")
            and "owner/repo#22" in (all_failed_reason or ""),
        ),
        ([], 0, 2, True, True, True),
    )
    no_token_api = _RedraftAPI()
    no_token, _aborted, _no_token_drafted = _run_defuse(no_token_api, failing=set(), tokens={})
    no_token_reason = defuse_exit_failure(no_token) if no_token else None
    check(
        "#644 precedence rule 1: a NON-per-PR failure (no owner token) is systemic even though it "
        "was raised per PR — and it never aborts the phase",
        (
            len(no_token.unavailable) if no_token else -1,
            no_token.deferred if no_token else "aborted",
            no_token_reason is not None,
            "unavailable for the whole run" in (no_token_reason or ""),
        ),
        (2, (), True, True),
    )
    gh_missing_api = _RedraftAPI()
    gh_missing, _aborted, _gh_drafted = _run_defuse(
        gh_missing_api, failing=set(), gh_missing=True
    )
    check(
        "#644 precedence rule 1: a missing `gh` binary is systemic, not one PR's deferral",
        (
            len(gh_missing.unavailable) if gh_missing else -1,
            defuse_exit_failure(gh_missing) is not None if gh_missing else False,
        ),
        (2, True),
    )
    # Rule 1 DOMINATES rule 3: one owner unavailable must red the run even when another candidate
    # completed. (Both candidates share an owner here, so force the split with a mixed outcome.)
    mixed = DefuseOutcome(
        changed=1, attempted=2, deferred=(), unavailable=("owner/repo#21: no token",)
    )
    check(
        "#644 precedence rule 1 DOMINATES rule 3: a completed defuse does not excuse a non-per-PR "
        "failure",
        defuse_exit_failure(mixed) is not None,
        True,
    )
    # A failed AUDIT COMMENT is also per-PR (same head-of-line shape), and because the phase then
    # completed nothing, rule 2 keeps the run loud rather than silently green.
    audit_api = _RedraftAPI()
    audit_api.comment_failures = {21, 22}
    audit, audit_aborted, audit_drafted = _run_defuse(audit_api, failing=set())
    check(
        "#644: a failed audit comment defers that PR instead of aborting the sweep, and an "
        "all-failed phase still exits non-zero",
        (
            audit_aborted,
            audit_drafted,
            audit.changed if audit else -1,
            len(audit.deferred) if audit else -1,
            defuse_exit_failure(audit) is not None if audit else False,
        ),
        (False, [21, 22], 0, 2, True),
    )
    check(
        "#644: a phase with NO attempted candidate is green (an unreadable latch already defers "
        "per PR by design; that unrelated path's status semantics are unchanged)",
        defuse_exit_failure(DefuseOutcome()),
        None,
    )

    # ---- issue #647: ONE precedence rule, applied to EVERY per-object phase --------------------
    # #644 fixed the defuse phase and wrote the precedence rule down. #647 closes the CLASS: the
    # stale-PR hand-off and issue-repair loops now record the same outcome shape and are judged by
    # the SAME function. These checks pin that there is one rule, that it names the phase it is
    # reporting, and that nothing here can buy silence.
    check(
        "#647: #644's names are ALIASES of the shared rule, not a second copy of it (a duplicated "
        "precedence implementation is what this issue forbids)",
        (DefuseOutcome is PhaseOutcome, defuse_exit_failure is phase_exit_failure),
        (True, True),
    )
    check(
        "#647: the systemic report NAMES the phase it came from, so an operator reading a red run "
        "knows which loop failed",
        (
            phase_exit_failure(PhaseOutcome(
                label="stale PR hand-off", attempted=2, deferred=("owner/repo#31: refused",))),
            phase_exit_failure(PhaseOutcome(
                label="issue status repair", attempted=1, deferred=("owner/repo#41: refused",))),
        ),
        (
            "every stale PR hand-off failed (2 attempted, 0 completed): owner/repo#31: refused",
            "every issue status repair failed (1 attempted, 0 completed): owner/repo#41: refused",
        ),
    )
    check(
        "#647 rule 2 fires on a deferral recorded BEFORE the attempt was counted — a phase that "
        "completed nothing while something failed can never report green (the read-stage swallow "
        "is unrepresentable, not merely unlikely)",
        phase_exit_failure(PhaseOutcome(
            label="stale PR hand-off", attempted=0, deferred=("owner/repo#31: GET refused",)
        )) is not None,
        True,
    )
    check(
        "#647: EVERY failing phase is named in the sweep's exit status, not just the first "
        "(a second systemic failure must not hide behind a fixed one)",
        sweep_exit_failure((
            PhaseOutcome(label="issue status repair", attempted=1,
                         deferred=("owner/repo#41: refused",)),
            PhaseOutcome(label="parked PR defuse", changed=1, attempted=1),
            PhaseOutcome(label="stale PR hand-off", attempted=1,
                         deferred=("owner/repo#31: refused",)),
        )),
        "every issue status repair failed (1 attempted, 0 completed): owner/repo#41: refused | "
        "every stale PR hand-off failed (1 attempted, 0 completed): owner/repo#31: refused",
    )
    check(
        "#647: an all-green sweep reports no exit failure at all",
        sweep_exit_failure((
            PhaseOutcome(label="issue status repair", changed=2, attempted=2),
            PhaseOutcome(),
            PhaseOutcome(label="stale PR hand-off", changed=3, attempted=3,
                         deferred=("owner/repo#31: refused",)),
        )),
        None,
    )
    # The HTTP-side cause helper, alongside #644's gh-side one: bounded, masked, and never itself
    # the reason a diagnostic is lost (an HTTPError with no readable body must degrade to its
    # status reason, not to nothing).
    check(
        "#647: a failed call's error envelope is reported, credential-masked and bounded",
        (
            _http_failure_detail(
                HTTPError("https://api.github.com/x", 403, "Forbidden", {},
                          io.BytesIO(b'{"message":"Bad credentials ghs_abcdefgh12345678 tok"}')),
                "tok",
            ),
            len(_http_failure_detail(
                HTTPError("https://api.github.com/x", 422, "Unprocessable", {},
                          io.BytesIO(b"y" * 5000)),
                "",
            )) <= GH_DETAIL_LIMIT + 1,
        ),
        ('{"message":"Bad credentials *** ***"}', True),
    )
    check(
        "#647: an HTTPError carrying NO readable body degrades to its status reason rather than "
        "losing the cause a second time",
        _http_failure_detail(
            HTTPError("https://api.github.com/x", 403, "Forbidden", {}, None), "tok"
        ),
        "Forbidden",
    )

    # [FABLE-5] Deadlock regression (live PRs #3472/#3470): a stale DRAFT worker PR with a VALID
    # registry provenance record (aged past the maintenance threshold purely by WAITING for a
    # backed-up review lane) is REVIEW-LOOP-OWNED and must NOT be age-parked into terminal
    # needs:user by this sweep — that terminal label excludes the PR from
    # dispatch-claim.enumerate_review_items, deadlocking the exact loop that drives it.
    # (a) THE BUG: a stale valid-provenance draft returns None (no needs:user park). Even a draft
    # in an otherwise-bad merge state stays untouched here — review-loop ownership dominates the
    # merge-state escalation.
    stale_draft_pr = {**old_pr, "draft": True}
    check(
        "stale DRAFT worker PR with VALID provenance is NOT age-parked (review-loop-owned)",
        stale_worker_pr_reason(
            stale_draft_pr, "app[bot]", limits.threshold_seconds, now, has_valid_provenance=True
        ),
        None,
    )
    check(
        "stale valid-provenance draft is untouched even in a bad merge state (ownership wins)",
        stale_worker_pr_reason(
            {**old_pr, "draft": True, "mergeable_state": "dirty"},
            "app[bot]",
            limits.threshold_seconds,
            now,
            has_valid_provenance=True,
        ),
        None,
    )
    # (a2) CLOSURE GUARANTEE: a stale DRAFT with NO VALID provenance record (missing, unreadable,
    # or schema-invalid) is a genuine orphan — the review loop fails closed on every one of those
    # cases and groom's issue-side orphan repair skips an open draft — so the age-park (human
    # hand-off) is KEPT for exactly this case. Also dominates the merge state: the orphan reason,
    # not the merge reason, is returned.
    check(
        "stale DRAFT worker PR WITHOUT valid provenance still parks (orphan hand-off)",
        stale_worker_pr_reason(
            stale_draft_pr, "app[bot]", limits.threshold_seconds, now, has_valid_provenance=False
        ),
        ORPHAN_DRAFT_REASON,
    )
    check(
        "no-provenance orphan draft park dominates the merge-state reason",
        stale_worker_pr_reason(
            {**old_pr, "draft": True, "mergeable_state": "dirty"},
            "app[bot]",
            limits.threshold_seconds,
            now,
            has_valid_provenance=False,
        ),
        ORPHAN_DRAFT_REASON,
    )
    # (b) A stale NON-DRAFT worker PR wedged in a bad merge state STILL parks (unchanged; a state no
    # automation recovers — the defensible, in-scope escalation the fix must not remove).
    check(
        "stale NON-DRAFT bad-merge-state worker PR still parks (unchanged)",
        stale_worker_pr_reason(
            {**old_pr, "draft": False, "mergeable_state": "dirty"},
            "app[bot]",
            limits.threshold_seconds,
            now,
            has_valid_provenance=True,
        ),
        BAD_MERGE_STATES["dirty"],
    )
    # (a3) The provenance VALIDITY lookup: mirrors worker-pr.provenance_path — the record for
    # <owner>/<name>#<N> lives at orchestration/provenance/<owner>--<name>--pr<N>.json under the
    # registry root — and validates the record with the review loop's OWN shared predicate
    # (dispatch-claim.is_enumerable_provenance, imported, so the schemas cannot drift). The
    # result flips the draft branch between review-loop-owned (VALID) and orphan-park (missing
    # OR invalid): the review loop fails closed on every invalid case below, so groom-preserving
    # such a draft would silently strand it.
    with tempfile.TemporaryDirectory() as tmp:
        registry_root = Path(tmp)
        check(
            "provenance validity: missing record -> False (park)",
            worker_pr_provenance_enumerable("owner/repo", 99, registry_root),
            False,
        )
        record_dir = registry_root / PROVENANCE_DIR
        record_dir.mkdir(parents=True)
        record_path = record_dir / "owner--repo--pr99.json"
        # COMPLETE by the review path's full requirement set — including impl_alias (safe
        # atom) and issue (positive int), the two fields the round-3 partial predicate missed,
        # and recorded_at_run (issue #657): the record's ATTESTATION BASIS must be a host-side
        # run. This is a worker record, so worker.yml's `<run>.<attempt>` shape.
        valid_record = {
            "pr_number": 99,
            "head_sha_at_open": "1" * 40,
            "impl_provider": "anthropic",
            "impl_alias": "fable",
            "impl_account_h": "ab" * 8,
            "issue": 7,
            "recorded_at_run": "29694084610.1",
        }
        record_path.write_text(json.dumps(valid_record), encoding="utf-8")
        check(
            "provenance validity: schema-valid record -> True (review-loop-owned)",
            worker_pr_provenance_enumerable("owner/repo", 99, registry_root),
            True,
        )
        check(
            "provenance validity: different PR number stays False",
            worker_pr_provenance_enumerable("owner/repo", 100, registry_root),
            False,
        )
        # MUTATION guard against the file-existence-only revert: every case below leaves the
        # record FILE in place, so an existence-only lookup would report True (no park) while
        # the review loop rejects the record — exactly the silent-strand this gate closes.
        # Each must stay False (park).
        record_path.write_text("{not json", encoding="utf-8")
        check(
            "provenance validity: MALFORMED-JSON record -> False (park; existence insufficient)",
            worker_pr_provenance_enumerable("owner/repo", 99, registry_root),
            False,
        )
        record_path.write_text("{}", encoding="utf-8")
        check(
            "provenance validity: empty {} record -> False (park)",
            worker_pr_provenance_enumerable("owner/repo", 99, registry_root),
            False,
        )
        for field, bad_value in (
            ("pr_number", 98),  # points at a different target PR
            # Cross-type equality hazard: Python says 99.0 == 99 and True == 1, so a bare
            # != admits a JSON float/bool pr_number. The strict int-not-bool guard in
            # provenance_admission_error rejects both; reverting it ADMITS 99.0 (reds here).
            ("pr_number", 99.0),  # float is not an int (99.0 == 99 under lax equality)
            ("pr_number", True),  # bool is not an int (True == 1 under lax equality)
            ("impl_provider", "mallory"),  # unregistered provider
            # UNHASHABLE / wrong-type fields must park, never raise: before the predicate's
            # isinstance-before-membership guard, [] / {} here raised TypeError out of the
            # provider set lookup and aborted the whole groom run instead of parking one
            # orphan. Reverting that guard makes these cases RAISE (mutation tripwire).
            ("impl_provider", []),  # unhashable list
            ("impl_provider", {}),  # unhashable object
            ("issue", []),  # wrong-type (list) issue number
            ("head_sha_at_open", {}),  # wrong-type (object) opened-head sha
            ("head_sha_at_open", "not-a-sha"),  # malformed opened-head sha
            ("impl_account_h", "raw-handle@x"),  # not the salted 16-hex hash (decision 22a)
            # Round-3 finding: review-fix.yml's resolve rejects these two, so a draft carrying
            # them is review-REJECTED — groom must park, not preserve. Each keys the matching
            # field check in dispatch-claim.provenance_admission_error (dropping it reds here).
            ("impl_alias", "no spaces allowed"),  # not a safe atom (resolve-step requirement)
            ("impl_alias", 5),  # non-string alias
            ("issue", 0),  # not a positive issue number
            ("issue", -7),  # negative issue number
            ("issue", True),  # bool is not an issue number (str(True) breaks the issues/ read)
            ("issue", "7"),  # string is not an int
        ):
            record_path.write_text(
                json.dumps({**valid_record, field: bad_value}), encoding="utf-8"
            )
            check(
                f"provenance validity: schema-invalid {field}={bad_value!r} -> False (park)",
                worker_pr_provenance_enumerable("owner/repo", 99, registry_root),
                False,
            )
        for missing in ("impl_alias", "issue"):
            record_path.write_text(
                json.dumps({k: v for k, v in valid_record.items() if k != missing}),
                encoding="utf-8",
            )
            check(
                f"provenance validity: missing {missing} -> False (park)",
                worker_pr_provenance_enumerable("owner/repo", 99, registry_root),
                False,
            )
        malformed_repo_failed = False
        try:
            worker_pr_provenance_enumerable("no-slash", 99, registry_root)
        except GroomError:
            malformed_repo_failed = True
        check("provenance validity: malformed repo fails closed", malformed_repo_failed, True)
        # (a4) Ledger-first resolution (issue #96): post-outage records exist ONLY on the
        # `ledger` branch checkout — a groom that reads just the master checkout would orphan-
        # park every ledger-recorded draft (the exact deadlock the outage caused). The legacy
        # master-checkout record stays visible as the fallback (pre-outage PRs <= sparq#2542).
        record_path.unlink()
        ledger_dir = registry_root / "ledger-checkout"
        ledger_record = ledger_dir / PROVENANCE_DIR / "owner--repo--pr99.json"
        ledger_record.parent.mkdir(parents=True)
        ledger_record.write_text(json.dumps(valid_record), encoding="utf-8")
        check(
            "provenance validity: ledger-only record -> True (review-loop-owned)",
            worker_pr_provenance_enumerable(
                "owner/repo", 99, registry_root, ledger_root=ledger_dir),
            True,
        )
        check(
            "provenance validity: ledger-only record invisible without a ledger root",
            worker_pr_provenance_enumerable("owner/repo", 99, registry_root),
            False,
        )
        ledger_record.unlink()
        record_path.write_text(json.dumps(valid_record), encoding="utf-8")
        check(
            "provenance validity: legacy master-checkout record still admits (fallback)",
            worker_pr_provenance_enumerable(
                "owner/repo", 99, registry_root, ledger_root=ledger_dir),
            True,
        )
        # A PRESENT ledger record governs even when invalid — never fall back past it to a
        # stale-but-valid master copy (validity, not just existence, decides ownership).
        ledger_record.write_text("{not json", encoding="utf-8")
        check(
            "provenance validity: present-but-invalid ledger record -> False (no fallback)",
            worker_pr_provenance_enumerable(
                "owner/repo", 99, registry_root, ledger_root=ledger_dir),
            False,
        )
    # (c) Non-vacuity / mutation guards. The two draft tests above are mutually discriminating:
    # reverting the draft branch to master's UNCONDITIONAL park reds test (a) (valid-provenance
    # draft would park), and reverting it to an unconditional Return-None (the earlier revision of
    # this fix) reds test (a2) (the orphan draft would get silence). The modelled revert below
    # additionally proves test (a) discriminates against the exact master behaviour — if the draft
    # branch ever again returns a reason for a valid-provenance draft, run_sweep's pull_actions
    # loop applies needs:user, re-arming the deadlock.
    def _reverted_stale_worker_pr_reason(pull, bot, threshold, at):
        updated = _epoch(pull.get("updated_at"), "pull request")
        if at - updated < threshold:
            return None
        head = pull.get("head", {}).get("ref", "")
        author = pull.get("user", {}).get("login", "")
        pbody = pull.get("body") or ""
        if (
            not isinstance(head, str)
            or WORKER_BRANCH.match(head) is None
            or not isinstance(author, str)
            or author.casefold() != bot.casefold()
            or not isinstance(pbody, str)
            or not pbody.lstrip().startswith(WORKER_PR_MARKER)
        ):
            return None
        if pull.get("draft") is True:
            return "the worker pull request is still a draft"  # the removed terminal-park
        merge_state = pull.get("mergeable_state") or "unknown"
        return BAD_MERGE_STATES.get(merge_state)

    check(
        "MUTATION: reverting the draft-fix re-parks the draft (non-vacuous)",
        _reverted_stale_worker_pr_reason(
            stale_draft_pr, "app[bot]", limits.threshold_seconds, now
        ),
        "the worker pull request is still a draft",
    )
    check(
        "MUTATION guard agrees with the live fix on the non-draft park (only draft changed)",
        _reverted_stale_worker_pr_reason(old_pr, "app[bot]", limits.threshold_seconds, now)
        == stale_worker_pr_reason(
            old_pr, "app[bot]", limits.threshold_seconds, now, has_valid_provenance=True
        ),
        True,
    )

    fixture_issues = {
        "owner/repo": {
            7: {
                "labels": [{"name": "status:in-progress"}],
                "updated_at": datetime.fromtimestamp(
                    now - 700, timezone.utc
                ).isoformat(),
            },
            8: {
                "labels": [{"name": "status:ready"}],
                "updated_at": datetime.fromtimestamp(
                    now - 700, timezone.utc
                ).isoformat(),
            },
            # Issue #9: the attempt budget is exhausted (issue #170), but its FINAL allowed attempt
            # opened a still-open ADMITTED worker PR (#91). Exhaustion must NOT defer it — parking
            # `needs:user` here would strip #91 from dispatch's review loop.
            9: {
                "labels": [{"name": "status:in-progress"}],
                "updated_at": datetime.fromtimestamp(
                    now - 700, timezone.utc
                ).isoformat(),
            },
        }
    }
    # PR #91 carries the FULL worker identity (App author, same-repo head, worker branch, body
    # marker) so `_current_links` legitimately links issue #9 — the genuine admitted worker PR the
    # comment above describes. An identity-incomplete PR would no longer link (issue #172), so this
    # fixture must be faithful to the "admitted worker PR is open" scenario it stands in for.
    fixture_pulls = {
        "owner/repo": {
            91: {
                "updated_at": datetime.fromtimestamp(now - 700, timezone.utc).isoformat(),
                "head": {
                    "ref": "sparq-agent/issue-9-91-1",
                    "repo": {"full_name": "owner/repo"},
                },
                "user": {"login": "app[bot]"},
                "body": WORKER_PR_MARKER + "\n\nFixes #9",
            }
        }
    }
    fixture_attempts = {("owner/repo", 7): 0, ("owner/repo", 8): 2, ("owner/repo", 9): 2}
    fixture_states = {"a" * 32: LeaseDecision("dead", "fixture complete")}
    actions, prs, dead = _plan_actions(
        {"owner/repo": limits},
        fixture_issues,
        fixture_pulls,
        {"owner/repo": {9}},  # PR #91 is a PROVEN admitted worker attempt for issue #9
        fixture_attempts,
        fixture_states,
        [base],
        {},
        now,
        "app[bot]",
    )
    check(
        "fixture plans dead reset and exhaustion",
        [(action.number, action.mode) for action in actions],
        [(7, "ready"), (8, "defer")],
    )
    check(
        "MUTATION: exhaustion does NOT defer an issue whose ADMITTED final-attempt PR is open (#170)",
        any(action.number == 9 for action in actions),
        False,
    )
    check("fixture reclaims dead claim", dead, {"a" * 32})
    check("fixture has no PR writes", prs, [])

    # ---- issue #649 (1): the attempt-budget SKIP-SET, and why a defaulted 0 is unsound ---------
    # The head-of-line abort in the pre-planning comments read cannot take #648's mechanical
    # record-and-continue, because `_plan_actions` needs a VALUE for `attempts[key]`. These three
    # calls are the argument, executed rather than asserted: the same issue, planned from its TRUE
    # exhausted budget, from the 0 the mechanical fix would have written, and from the skip-set.
    def _plan_quietly(**kwargs):
        """`_plan_actions` over the shared fixture; its SKIP lines captured, not printed."""
        buffer = io.StringIO()
        saved = sys.stdout
        sys.stdout = buffer
        try:
            planned = _plan_actions(
                {"owner/repo": limits}, fixture_issues, fixture_pulls,
                {"owner/repo": {9}}, kwargs.pop("attempts", fixture_attempts),
                fixture_states, [base], {}, now, "app[bot]", **kwargs,
            )
        finally:
            sys.stdout = saved
        return planned, buffer.getvalue()

    # Issue #7 is `status:in-progress`, stale, and (here) has SPENT its budget: the truth defers it.
    _649_exhausted = {**fixture_attempts, ("owner/repo", 7): limits.max_attempts}
    (_649_true_actions, _p, _649_true_dead), _log = _plan_quietly(attempts=_649_exhausted)
    # THE UNSOUND FIX, MODELLED. `used = 0` suppresses the exhaustion defer (which reads `used`)
    # while the `status:in-progress` ready repair (which does not) still fires — so the mechanical
    # record-and-continue would RE-READY and re-dispatch an issue whose attempts are spent. If this
    # ever stops differing from the line above, the skip-set has become decoration.
    (_649_zero_actions, _p, _p2), _log = _plan_quietly(
        attempts={**fixture_attempts, ("owner/repo", 7): 0})
    check(
        "#649 (1) NON-VACUITY: defaulting a failed attempt-budget read to 0 turns issue #7's "
        "exhaustion DEFER into a READY — a wrong mutation (re-dispatch), not a deferred one",
        (
            [(action.number, action.mode) for action in _649_true_actions],
            [(action.number, action.mode) for action in _649_zero_actions],
        ),
        ([(7, "defer"), (8, "defer")], [(7, "ready"), (8, "defer")]),
    )
    # THE SOUND FIX. The issue leaves planning entirely, and its `attempts` entry is ABSENT — a
    # skip-set that still needed a value would not have solved anything, so the fixture withholds
    # one. Issue #8 still defers: one unreadable budget is not a head-of-line block.
    _649_missing = {key: used for key, used in _649_exhausted.items() if key[1] != 7}
    (_649_skip_actions, _p, _649_skip_dead), _649_skip_log = _plan_quietly(
        attempts=_649_missing, unplannable_issues={("owner/repo", 7)})
    check(
        "#649 (1): the skip-set excludes the issue from EVERY planning branch, needs no attempts "
        "entry at all, does not block the other issues, and says so in the log",
        (
            [(action.number, action.mode) for action in _649_skip_actions],
            "SKIP issue owner/repo#7: attempt budget unreadable" in _649_skip_log,
        ),
        ([(8, "defer")], True),
    )
    # ...and it is scoped to PLANNING. The lease for the very same issue is classified from the
    # snapshot the sweep already read, so a degraded COMMENTS read must not move it either way.
    check(
        "#649 (1): a skipped issue's LEASE decision is untouched — the claim still reclaims "
        "exactly as it does on the readable path (the skip-set must not become a reap gate)",
        (_649_skip_dead, _649_true_dead),
        ({"a" * 32}, {"a" * 32}),
    )

    # ---- issue #649 (2): the dead-claim computation is scoped PER REPO -------------------------
    # A repo whose snapshot could not be read is dropped from `issues`/`pulls` as a UNIT. Omission
    # alone is not enough: it silently moves a run-dead TERMINAL claim out of the branch #509's
    # fresh-read boundary can still retain, into the one that releases unconditionally. So the
    # repo is named, and it contributes no releases at all this tick.
    _649_unread_log = io.StringIO()
    saved_stdout = sys.stdout
    sys.stdout = _649_unread_log
    try:
        _649_unread_actions, _p, _649_unread_dead = _plan_actions(
            {"owner/repo": limits}, {}, {}, {}, {}, fixture_states, [base], {}, now,
            "app[bot]", unreadable_repos={"owner/repo"},
        )
        # NON-VACUITY: the identical call WITHOUT the scoping releases the claim, so the guard is
        # what retains it — not the empty snapshot, which by itself reads the issue as ORPHANED.
        _p, _p2, _649_dropped_dead = _plan_actions(
            {"owner/repo": limits}, {}, {}, {}, {}, fixture_states, [base], {}, now, "app[bot]",
        )
    finally:
        sys.stdout = saved_stdout
    check(
        "#649 (2): a repo whose snapshot was unreadable releases NOTHING and plans NOTHING, while "
        "the same call without the per-repo scoping releases the claim (non-vacuous)",
        (
            _649_unread_dead,
            _649_unread_actions,
            _649_dropped_dead,
            "SKIP lease release claim=aaaaaaaa: owner/repo's target snapshot was unreadable"
            in _649_unread_log.getvalue(),
        ),
        (set(), [], {"a" * 32}, True),
    )

    # ---- issue #509: non-PR terminal/orphan claims are immediate groom candidates. ----
    terminal_issue = {
        "owner/repo": {
            7: {"labels": [{"name": "area:crate-a"}, {"name": "needs:user"}],
                "updated_at": datetime.fromtimestamp(now - 10, timezone.utc).isoformat()}
        }
    }
    live_state = {
        "a" * 32: classify_lease(base, limits, now, {"a" * 32: active}, {})
    }
    terminal_log = io.StringIO()
    saved_stdout = sys.stdout
    sys.stdout = terminal_log
    try:
        terminal_actions, _terminal_prs, terminal_dead = _plan_actions(
            {"owner/repo": limits}, terminal_issue, {"owner/repo": {}},
            {"owner/repo": set()}, {("owner/repo", 7): 0}, live_state, [base], {}, now,
            "app[bot]",
        )
    finally:
        sys.stdout = saved_stdout
    check("#509 terminal issue-only claim backed by a live run is retained",
          terminal_dead, set())
    check("#509 live-run terminal reap deferral is loud and identifies the backing run",
          "terminal reap deferred: backing run 789 live" in terminal_log.getvalue(), True)
    check("#509 terminal issue-only reap deferral does not relabel the parked issue",
          terminal_actions, [])

    unknown_log = io.StringIO()
    sys.stdout = unknown_log
    try:
        _unknown_actions, _unknown_prs, unknown_dead = _plan_actions(
            {"owner/repo": limits}, terminal_issue, {"owner/repo": {}},
            {"owner/repo": set()}, {("owner/repo", 7): 0},
            {"a" * 32: LeaseDecision("unknown", "fixture liveness unavailable")},
            [base], {}, now, "app[bot]",
        )
    finally:
        sys.stdout = saved_stdout
    check("#509 UNKNOWN terminal-claim liveness fails closed and retains the claim",
          unknown_dead, set())
    check("#509 UNKNOWN terminal-claim liveness deferral is loud",
          "terminal reap deferred: backing run liveness UNKNOWN" in unknown_log.getvalue(),
          True)

    completed_terminal_state = {
        "a" * 32: classify_lease(base, limits, now, {"a" * 32: complete}, {})
    }
    _done_actions, _done_prs, completed_terminal_dead = _plan_actions(
        {"owner/repo": limits}, terminal_issue, {"owner/repo": {}},
        {"owner/repo": set()}, {("owner/repo", 7): 0}, completed_terminal_state,
        [base], {}, now, "app[bot]",
    )
    check("#509 terminal issue-only claim with a completed backing run is reaped",
          completed_terminal_dead, {"a" * 32})

    orphan_issues = {"owner/repo": {}}
    check("#509 orphaned non-PR claim is a terminal-reap candidate",
          _terminal_non_pr_claims(
              orphan_issues, {"owner/repo": {}}, [base], "app[bot]"),
          {"a" * 32})

    backed_pull = {
        92: {
            "number": 92,
            "state": "open",
            "updated_at": datetime.fromtimestamp(now - 10, timezone.utc).isoformat(),
            "head": {"ref": "sparq-agent/issue-7-92-1",
                     "repo": {"full_name": "owner/repo"}},
            "user": {"login": "app[bot]"},
            "body": WORKER_PR_MARKER + "\n\nFixes #7",
        }
    }
    check("#509 PR-backed terminal claim is not label-reaped by groom",
          _terminal_non_pr_claims(
              terminal_issue, {"owner/repo": backed_pull}, [base], "app[bot]"),
          set())
    check("#509 live nonterminal issue-only claim remains",
          _terminal_non_pr_claims(
              {"owner/repo": {7: {
                  "labels": [{"name": "area:crate-a"}, {"name": "status:in-progress"}],
                  "updated_at": datetime.fromtimestamp(now - 10, timezone.utc).isoformat(),
              }}}, {"owner/repo": {}}, [base], "app[bot]"),
          set())
    # NEGATIVE (review round 1): the SAME open PR #91 — which still loose-links issue #9 via its
    # branch and `Fixes #9` body — must NOT suppress the exhaustion defer when it is not in the
    # ADMITTED set (no proven worker identity/provenance). Reverting the exhaustion guard back to
    # the loose `links` map reds this check: an arbitrary or attacker-controlled PR would then
    # hold an exhausted issue out of `needs:user` indefinitely.
    unadmitted_actions, _prs_u, _dead_u = _plan_actions(
        {"owner/repo": limits},
        fixture_issues,
        fixture_pulls,
        {"owner/repo": set()},
        fixture_attempts,
        fixture_states,
        [base],
        {},
        now,
        "app[bot]",
    )
    check(
        "MUTATION: an UNADMITTED linking PR does NOT suppress the exhaustion defer (round 1)",
        [(a.number, a.mode) for a in unadmitted_actions if a.number == 9],
        [(9, "defer")],
    )

    # ---- _admitted_review_prs: the admission that gates exhaustion suppression (round 1) ----
    # Only a PR carrying the review loop's OWN identity + provenance admissions may suppress the
    # exhausted-attempt defer; every weaker linkage (a `Fixes #N` body reference, a fork's
    # worker-shaped head, a bot PR with no registry provenance record) must be refused —
    # otherwise an arbitrary open PR keeps an exhausted issue out of `needs:user` indefinitely.
    with tempfile.TemporaryDirectory() as tmp:
        admit_root = Path(tmp)
        admit_dir = admit_root / PROVENANCE_DIR
        admit_dir.mkdir(parents=True)
        (admit_dir / "owner--repo--pr91.json").write_text(
            json.dumps({
                "pr_number": 91,
                "head_sha_at_open": "1" * 40,
                "impl_provider": "anthropic",
                "impl_alias": "fable",
                "impl_account_h": "ab" * 8,
                "issue": 9,
                # Machine-attested stamp (issue #657): a record whose trust basis is not a
                # host-side run is refused by the shared admission predicate, so a "proven
                # worker attempt" must carry worker.yml's `<run>.<attempt>` stamp to suppress.
                "recorded_at_run": "29694084610.1",
            }),
            encoding="utf-8",
        )
        proven_pull = {
            "updated_at": datetime.fromtimestamp(now - 700, timezone.utc).isoformat(),
            "head": {
                "ref": "sparq-agent/issue-9-91-1",
                "repo": {"full_name": "owner/repo"},
            },
            "user": {"login": "app[bot]"},
            "body": WORKER_PR_MARKER + "\n\nFixes #9",
        }
        check(
            "admission: a proven worker attempt (identity + provenance) suppresses",
            _admitted_review_prs("owner/repo", {91: proven_pull}, "app[bot]", admit_root),
            {9},
        )
        arbitrary_pull = {
            "updated_at": proven_pull["updated_at"],
            "head": {"ref": "feature/anything", "repo": {"full_name": "owner/repo"}},
            "user": {"login": "mallory"},
            "body": "helpful contribution\n\nFixes #9",
        }
        check(
            "NEGATIVE: an arbitrary PR with a `Fixes #9` body reference is NOT admitted",
            _admitted_review_prs("owner/repo", {92: arbitrary_pull}, "app[bot]", admit_root),
            set(),
        )
        # issue #172: `_current_links` (recovery-suppression linkage) now applies the SAME
        # worker-PR identity gate, so an untrusted PR can no longer hold a stale issue out of
        # recovery. Unlike `_admitted_review_prs` it does NOT require a provenance record (see its
        # docstring) — for "is the App working this issue right now" the authoring identity is
        # authoritative. Positive first, so the gate rejecting everything flips these red.
        check(
            "links: a genuine App-authored worker PR IS linked to its source issue",
            _current_links("owner/repo", {91: proven_pull}, "app[bot]").get(9),
            {91},
        )
        check(
            "NEGATIVE: an arbitrary `Fixes #9` PR no longer links it (the closed hole)",
            9 in _current_links("owner/repo", {92: arbitrary_pull}, "app[bot]"),
            False,
        )
        # Round 1: even a FULLY authenticated worker PR links ONLY its branch-encoded issue —
        # a `Fixes #25` body reference on the issue-9 branch must not enter #25 in the map, or
        # the App's own PR would suppress stale/orphan recovery for an unrelated issue.
        cross_ref_pull = {**proven_pull, "body": WORKER_PR_MARKER + "\n\nFixes #25"}
        check(
            "round 1: an authenticated worker PR links only the branch-encoded issue",
            _current_links("owner/repo", {91: cross_ref_pull}, "app[bot]"),
            {9: {91}},
        )
        check(
            "NEGATIVE: a fork PR with a spoofed worker-shaped head does not link",
            _current_links(
                "owner/repo",
                {91: {**proven_pull,
                      "head": {"ref": "sparq-agent/issue-9-91-1",
                               "repo": {"full_name": "mallory/repo"}}}},
                "app[bot]",
            ),
            {},
        )
        check(
            "NEGATIVE: a non-bot author with a worker-shaped head does not link",
            _current_links(
                "owner/repo", {91: {**proven_pull, "user": {"login": "mallory"}}}, "app[bot]"
            ),
            {},
        )
        check(
            "NEGATIVE: a bot worker PR WITHOUT the worker body marker does not link",
            _current_links(
                "owner/repo", {91: {**proven_pull, "body": "Fixes #9"}}, "app[bot]"
            ),
            {},
        )
        check(
            "NEGATIVE: an unresolved (empty) bot login links nothing (fail closed)",
            _current_links("owner/repo", {91: proven_pull}, ""),
            {},
        )
        fork_pull = {
            **proven_pull,
            "head": {
                "ref": "sparq-agent/issue-9-91-1",
                "repo": {"full_name": "mallory/repo"},
            },
        }
        check(
            "NEGATIVE: a fork PR with a spoofed worker-shaped head is NOT admitted",
            _admitted_review_prs("owner/repo", {91: fork_pull}, "app[bot]", admit_root),
            set(),
        )
        check(
            "NEGATIVE: a worker-shaped branch from a NON-BOT author is NOT admitted",
            _admitted_review_prs(
                "owner/repo",
                {91: {**proven_pull, "user": {"login": "mallory"}}},
                "app[bot]",
                admit_root,
            ),
            set(),
        )
        check(
            "NEGATIVE: a bot worker branch WITHOUT the worker PR marker is NOT admitted",
            _admitted_review_prs(
                "owner/repo",
                {91: {**proven_pull, "body": "Fixes #9"}},
                "app[bot]",
                admit_root,
            ),
            set(),
        )
        # PR #93 is worker-shaped, bot-authored, and marked — but NO registry provenance record
        # exists for it, so the review loop will never drive it: it must not suppress (an
        # UNADMITTED worker-shaped branch is exactly the round-1 negative case).
        unrecorded_pull = {
            **proven_pull,
            "head": {
                "ref": "sparq-agent/issue-9-93-1",
                "repo": {"full_name": "owner/repo"},
            },
        }
        check(
            "NEGATIVE: a worker-shaped bot PR with NO provenance record is NOT admitted",
            _admitted_review_prs("owner/repo", {93: unrecorded_pull}, "app[bot]", admit_root),
            set(),
        )
        check(
            "NEGATIVE: a record whose issue disagrees with the branch-encoded issue is refused",
            _admitted_review_prs(
                "owner/repo",
                {91: {**proven_pull,
                      "head": {"ref": "sparq-agent/issue-8-91-1",
                               "repo": {"full_name": "owner/repo"}}}},
                "app[bot]",
                admit_root,
            ),
            set(),
        )
        check(
            "NEGATIVE: an unresolved (empty) bot login admits nothing (fail closed)",
            _admitted_review_prs("owner/repo", {91: proven_pull}, "", admit_root),
            set(),
        )

    # ---- live-ref provenance revalidation at the terminal mutation boundary (issue #174) ----
    # Both planning and the on-disk mutation-boundary re-check read the IMMUTABLE workflow checkout,
    # so a provenance record a delayed job/backfill lands DURING the sweep is invisible and groom
    # would terminally park an already-valid PR. _live_provenance_record re-reads the record from the
    # live `ledger` ref: it can only CANCEL a park (admits), let it proceed on a conclusive read
    # (denies), or force skip+alert on an unusable read (indeterminate) — never park on a bad read.
    def _contents(obj: Any) -> dict[str, str]:
        return {"type": "file",
                "content": base64.b64encode(json.dumps(obj).encode()).decode()}

    live_valid = {
        "pr_number": 91, "head_sha_at_open": "1" * 40, "impl_provider": "anthropic",
        "impl_alias": "fable", "impl_account_h": "ab" * 8, "issue": 9,
        # Machine-attested stamp (issue #657): the shared admission predicate now requires the
        # record's trust basis to be a host-side run. This fixture is a WORKER record, so it
        # carries the worker.yml provenance job's `<run>.<attempt>` stamp.
        "recorded_at_run": "29694084610.1",
    }
    # A Contents 404 only proves file absence once the ledger REF is verified (review round 1),
    # so every conclusive read first resolves the ref and pins the record read to its tip sha.
    # Literal "ledger" here for the same reason as the ledger-branch-targeting checks below.
    live_tip = "a" * 40
    live_ref = {"/repos/owner/registry/git/ref/heads/ledger": {"object": {"sha": live_tip}}}
    live_path = (
        "/repos/owner/registry/contents/orchestration/provenance/"
        f"owner--repo--pr91.json?ref={live_tip}"
    )

    class _RaisingAPI:
        def request(self, method, path, **_kwargs):
            raise GroomError("registry contents read failed")

    check(
        "live provenance: a schema-valid record on the live ref ADMITS (cancel the park)",
        _live_provenance_record(
            _StubAPI({**live_ref, live_path: _contents(live_valid)}),
            "owner/registry", "owner/repo", 91),
        ("admits", live_valid),
    )
    check(
        "live provenance: a clean 404 on the VERIFIED live ref DENIES (park may proceed)",
        _live_provenance_record(_StubAPI(dict(live_ref)), "owner/registry", "owner/repo", 91),
        ("denies", None),
    )
    # The 404 is only conclusive against a PROVEN ref: with the ledger ref itself missing (deleted
    # branch, misconfigured LEDGER_REF, lost registry visibility) the record 404 proves nothing.
    # Reverting the ref verification (trusting a bare Contents 404) turns these red as "denies".
    check(
        "live provenance: a 404 with the ledger REF missing is INDETERMINATE (never park)",
        _live_provenance_record(_StubAPI({}), "owner/registry", "owner/repo", 91),
        ("indeterminate", None),
    )
    check(
        "live provenance: a malformed ref object (no tip sha) is INDETERMINATE",
        _live_provenance_record(
            _StubAPI({"/repos/owner/registry/git/ref/heads/ledger": {"object": {}}}),
            "owner/registry", "owner/repo", 91)[0],
        "indeterminate",
    )
    # A cleanly-read but schema-invalid record is a conclusive 'not admissible' — the same
    # fail-closed orphan-park the on-disk path makes, NOT an indeterminate alert.
    check(
        "live provenance: a cleanly-read schema-invalid record DENIES (orphan park stands)",
        _live_provenance_record(
            _StubAPI({**live_ref, live_path: _contents({**live_valid, "pr_number": 90})}),
            "owner/registry", "owner/repo", 91)[0],
        "denies",
    )
    # Unusable reads must NEVER let the park proceed: a non-file shape, undecodable content, and
    # malformed JSON are all indeterminate (skip + operational alert). Reverting any of these to a
    # park (denies) or a suppress (admits) reds a check here. Each stub carries the ref entry so
    # the indeterminate verdict is attributable to the CONTENT defect, not a missing ref.
    check(
        "live provenance: a non-file contents shape is INDETERMINATE",
        _live_provenance_record(
            _StubAPI({**live_ref, live_path: {"type": "dir"}}),
            "owner/registry", "owner/repo", 91)[0],
        "indeterminate",
    )
    check(
        "live provenance: undecodable base64 content is INDETERMINATE",
        _live_provenance_record(
            _StubAPI({**live_ref, live_path: {"type": "file", "content": "not base64!"}}),
            "owner/registry", "owner/repo", 91)[0],
        "indeterminate",
    )
    check(
        "live provenance: valid base64 wrapping malformed JSON is INDETERMINATE",
        _live_provenance_record(
            _StubAPI({**live_ref, live_path: {
                "type": "file",
                "content": base64.b64encode(b"{not json").decode()}}),
            "owner/registry", "owner/repo", 91)[0],
        "indeterminate",
    )
    check(
        "live provenance: an unavailable (raising) registry read is INDETERMINATE (fail closed)",
        _live_provenance_record(_RaisingAPI(), "owner/registry", "owner/repo", 91)[0],
        "indeterminate",
    )
    live_repo_failed = False
    try:
        _live_provenance_record(_StubAPI({}), "owner/registry", "no-slash", 91)
    except GroomError:
        live_repo_failed = True
    check("live provenance: a malformed target repo fails closed", live_repo_failed, True)

    # _live_issue_admission: the single-issue admission the defer boundary asks — mirrors
    # _admitted_review_prs' identity + issue-binding, only the record SOURCE differs (live ref).
    live_worker_pull = {
        "head": {"ref": "sparq-agent/issue-9-91-1", "repo": {"full_name": "owner/repo"}},
        "user": {"login": "app[bot]"},
        "body": WORKER_PR_MARKER + "\n\nFixes #9",
    }
    check(
        "live admission: a raced-in valid record for the issue's worker PR ADMITS it",
        _live_issue_admission(
            _StubAPI({**live_ref, live_path: _contents(live_valid)}), "owner/registry",
            "owner/repo", 9, {91: live_worker_pull}, "app[bot]"),
        "admitted",
    )
    # NEGATIVE: the live record's issue field disagrees with the branch-encoded issue — admit
    # neither (exactly _admitted_review_prs' cross-check, applied to the live record).
    check(
        "live admission: a record whose issue disagrees with the branch is DENIED",
        _live_issue_admission(
            _StubAPI({**live_ref, live_path: _contents({**live_valid, "issue": 8})}),
            "owner/registry", "owner/repo", 9, {91: live_worker_pull}, "app[bot]"),
        "denied",
    )
    # The finding's mutation-relevant direction: a missing ledger ref must surface as
    # INDETERMINATE through the single-issue admission too, so the caller skips the park.
    check(
        "live admission: a missing ledger REF is INDETERMINATE (skip the park)",
        _live_issue_admission(
            _StubAPI({}), "owner/registry", "owner/repo", 9,
            {91: live_worker_pull}, "app[bot]"),
        "indeterminate",
    )
    check(
        "live admission: an unavailable read on this issue's worker PR is INDETERMINATE",
        _live_issue_admission(
            _RaisingAPI(), "owner/registry", "owner/repo", 9,
            {91: live_worker_pull}, "app[bot]"),
        "indeterminate",
    )
    # A non-worker PR (fails the identity gate) is never read and never suppresses.
    check(
        "live admission: a non-worker PR is skipped without a live read (DENIED)",
        _live_issue_admission(
            _RaisingAPI(), "owner/registry", "owner/repo", 9,
            {92: {"head": {"ref": "feature/x", "repo": {"full_name": "owner/repo"}},
                  "user": {"login": "mallory"}, "body": "Fixes #9"}}, "app[bot]"),
        "denied",
    )
    check(
        "live admission: an unresolved (empty) bot login admits nothing (fail closed)",
        _live_issue_admission(
            _StubAPI({live_path: _contents(live_valid)}), "owner/registry",
            "owner/repo", 9, {91: live_worker_pull}, ""),
        "denied",
    )

    # ---- [registry #835] GROOM IS NO LONGER CLASS-BLIND ---------------------------------------
    # THE DEFECT: every suppression guard here keyed on WORKER identity, so an enrolled #657
    # orchestrator PR under review could not hold its source issue out of the attempt-exhaustion
    # park. Groom then wrote status:parked to that source issue, and
    # dispatch-claim.enumerate_review_items excludes a PR whose source issue carries
    # status:parked (or any needs:*) — SILENTLY, because a PR with no `review:*` label is not
    # `signalled` and `exclude_signalled` prints nothing for it. Groom's run succeeded; the PR
    # was simply absent from the next enumeration. Both directions are asserted, plus a worker
    # regression control and the five shapes that must stay out.
    orch_login = "enrolled-orchestrator"
    orch_enrolled = (orch_login,)
    orch_review = _review_loop_module()
    orch_record = dict(orch_review.orchestrator_probe_record(95), issue=9)
    check(
        "[#835] the fixture really is the ORCHESTRATOR attestation class (else nothing below "
        "tests the class at all)",
        orch_review.provenance_attestation_class(orch_record),
        orch_review.ORCHESTRATOR_CLASS,
    )
    orch_pull = {
        "updated_at": datetime.fromtimestamp(now - 700, timezone.utc).isoformat(),
        # The #657 population's shape: same-repo head on an ORDINARY branch, HUMAN author, and
        # no worker body marker — it fails EVERY predicate _worker_pr_identity applies.
        "head": {"ref": "fix/ordinary-branch", "repo": {"full_name": "owner/repo"}},
        "user": {"login": orch_login},
        "body": "an orchestrator-authored pull request",
    }
    with tempfile.TemporaryDirectory() as tmp:
        orch_root = Path(tmp)
        (orch_root / PROVENANCE_DIR).mkdir(parents=True)

        def _write_record(number: int, record: Any) -> None:
            (orch_root / PROVENANCE_DIR / f"owner--repo--pr{number}.json").write_text(
                json.dumps(record), encoding="utf-8")

        _write_record(95, orch_record)
        _write_record(91, {
            "pr_number": 91, "head_sha_at_open": "1" * 40, "impl_provider": "anthropic",
            "impl_alias": "fable", "impl_account_h": "ab" * 8, "issue": 9,
            "recorded_at_run": "29694084610.1"})

        def admitted_for(pulls: dict[int, dict[str, Any]], authors: Any) -> set[int]:
            return _admitted_review_prs("owner/repo", pulls, "app[bot]", orch_root,
                                        enrolled_authors=authors)

        check(
            "[#835] an ENROLLED orchestrator-class PR suppresses its source issue's exhaustion "
            "park (reverting the admission reds THIS check)",
            admitted_for({95: orch_pull}, orch_enrolled), {9})
        check(
            "[#835] ...and with an EMPTY allowlist the very same PR suppresses NOTHING "
            "(enrolment is the discriminator, not the branch shape)",
            admitted_for({95: orch_pull}, ()), set())
        orch_worker_pull = {
            "updated_at": orch_pull["updated_at"],
            "head": {"ref": "sparq-agent/issue-9-91-1", "repo": {"full_name": "owner/repo"}},
            "user": {"login": "app[bot]"},
            "body": WORKER_PR_MARKER + "\n\nFixes #9",
        }
        check(
            "[#835] REGRESSION CONTROL: a worker-class PR still suppresses, in BOTH allowlist "
            "states (frozen literals, not a re-call of the live predicate)",
            [admitted_for({91: orch_worker_pull}, ()),
             admitted_for({91: orch_worker_pull}, orch_enrolled)], [{9}, {9}])
        for _why, _pull, _record in (
                ("a THIRD-PARTY author is not enrolled",
                 {**orch_pull, "user": {"login": "drive-by-contributor"}}, orch_record),
                ("a FORK head is never admitted, on any path",
                 {**orch_pull,
                  "head": {"ref": "fix/x", "repo": {"full_name": "mallory/repo"}}}, orch_record),
                ("the record must be THIS PR's record",
                 orch_pull, dict(orch_review.orchestrator_probe_record(7), issue=9)),
                ("a MACHINE-attested record is not the orchestrator class",
                 orch_pull, {**orch_record, "recorded_at_run": "29694084610.1"}),
                ("a malformed record fails closed",
                 orch_pull, {**orch_record, "issue": 0})):
            _write_record(95, _record)
            check(f"[#835] NEGATIVE: {_why}", admitted_for({95: _pull}, orch_enrolled), set())
        _write_record(95, orch_record)
        check(
            "[#835] NEGATIVE: no record at all fails closed",
            admitted_for({96: {**orch_pull}}, orch_enrolled), set())

        # END TO END, through the SAME composition run_sweep uses: the exhaustion planner reads
        # the admitted set this allowlist produces. This is the check that expresses the actual
        # harm — a defer action on issue #9 IS the silent de-enumeration of PR #95.
        exhausted_issue = {"owner/repo": {9: {
            "labels": [{"name": "status:in-progress"}],
            "updated_at": datetime.fromtimestamp(now - 700, timezone.utc).isoformat()}}}

        def exhaustion_modes(pulls: dict[int, dict[str, Any]], authors: Any) -> list[Any]:
            acts, _prs, _dead = _plan_actions(
                {"owner/repo": Limits(worker_timeout_minutes=10, max_attempts=2,
                                      enrolled_authors=authors)},
                exhausted_issue, {"owner/repo": pulls},
                {"owner/repo": admitted_for(pulls, authors)},
                {("owner/repo", 9): 2}, {}, [], {}, now, "app[bot]")
            return [(a.number, a.mode) for a in acts]

        check(
            "[#835] END TO END: an exhausted issue whose ENROLLED orchestrator PR is open is "
            "NOT parked — no silent de-enumeration",
            exhaustion_modes({95: orch_pull}, orch_enrolled), [])
        check(
            "[#835] END TO END: the pre-#835 behaviour (empty allowlist) still parks it — this "
            "is the defect, and it is what enrolment removes",
            exhaustion_modes({95: orch_pull}, ()), [(9, "defer")])
        check(
            "[#835] END TO END REGRESSION CONTROL: an open worker PR still suppresses with the "
            "allowlist enabled",
            exhaustion_modes({91: orch_worker_pull}, orch_enrolled), [])
        check(
            "[#835] END TO END: an UNENROLLED third party cannot hold an exhausted issue out of "
            "its park",
            exhaustion_modes({95: {**orch_pull, "user": {"login": "mallory"}}}, orch_enrolled),
            [(9, "defer")])
        # The claim that makes adding `admitted` to the recovery-suppression guard worker-NEUTRAL:
        # for the worker class the admitted set is a SUBSET of the links keys, so the new
        # disjunct can never change a worker outcome. Asserted, not asserted-in-prose.
        for _authors in ((), orch_enrolled):
            check(
                f"[#835] REGRESSION CONTROL: worker admitted ⊆ links keys (authors={_authors})",
                admitted_for({91: orch_worker_pull}, _authors)
                <= set(_current_links("owner/repo", {91: orch_worker_pull}, "app[bot]")),
                True)
        # ...and the recovery path itself: a stale in-progress issue with an ENROLLED
        # orchestrator PR open is NOT re-readied (before #835 it was, and a worker was
        # dispatched onto work already in the review lane).
        stale_open = {"owner/repo": {9: {
            "labels": [{"name": "status:in-progress"}],
            "updated_at": datetime.fromtimestamp(now - 700, timezone.utc).isoformat()}}}

        def recovery_modes(pulls: dict[int, dict[str, Any]], authors: Any) -> list[Any]:
            acts, _prs, _dead = _plan_actions(
                {"owner/repo": Limits(worker_timeout_minutes=10, max_attempts=9,
                                      enrolled_authors=authors)},
                stale_open, {"owner/repo": pulls},
                {"owner/repo": admitted_for(pulls, authors)},
                {("owner/repo", 9): 1}, {}, [], {}, now, "app[bot]")
            return [(a.number, a.mode) for a in acts]

        check(
            "[#835] the stale-in-progress recovery does NOT re-ready an issue whose enrolled "
            "orchestrator PR is open",
            recovery_modes({95: orch_pull}, orch_enrolled), [])
        check(
            "[#835] ...and with an empty allowlist it still re-readies (the pre-#835 behaviour, "
            "so the check above is not vacuous)",
            recovery_modes({95: orch_pull}, ()), [(9, "ready")])
        check(
            "[#835] REGRESSION CONTROL: the recovery path is unchanged for a worker PR and for "
            "an issue with no PR at all",
            [recovery_modes({91: orch_worker_pull}, orch_enrolled), recovery_modes({}, ())],
            [[], [(9, "ready")]])

    # The MUTATION BOUNDARY re-read must admit the class on the same terms, or the on-disk
    # admission suppresses and the live one lets the park through — the exact drift the worker
    # path already forbids (issue #174).
    orch_live_path = (
        "/repos/owner/registry/contents/orchestration/provenance/"
        f"owner--repo--pr95.json?ref={live_tip}")
    orch_live_record = dict(orch_review.orchestrator_probe_record(95), issue=9)
    check(
        "[#835] live admission: an ENROLLED orchestrator PR's raced-in record ADMITS (cancel "
        "the park)",
        _live_issue_admission(
            _StubAPI({**live_ref, orch_live_path: _contents(orch_live_record)}),
            "owner/registry", "owner/repo", 9, {95: orch_pull}, "app[bot]",
            enrolled_authors=orch_enrolled),
        "admitted",
    )
    check(
        "[#835] live admission: the same PR with an EMPTY allowlist is never even read (DENIED)",
        _live_issue_admission(
            _RaisingAPI(), "owner/registry", "owner/repo", 9, {95: orch_pull}, "app[bot]"),
        "denied",
    )
    check(
        "[#835] live admission: an enrolled PR whose live record binds ANOTHER issue is DENIED",
        _live_issue_admission(
            _StubAPI({**live_ref,
                      orch_live_path: _contents({**orch_live_record, "issue": 8})}),
            "owner/registry", "owner/repo", 9, {95: orch_pull}, "app[bot]",
            enrolled_authors=orch_enrolled),
        "denied",
    )
    check(
        "[#835] live admission: an enrolled PR with an UNREADABLE live ledger is INDETERMINATE "
        "(skip the park + alert), never a park on an unusable read",
        _live_issue_admission(
            _RaisingAPI(), "owner/registry", "owner/repo", 9, {95: orch_pull}, "app[bot]",
            enrolled_authors=orch_enrolled),
        "indeterminate",
    )
    check(
        "[#835] live admission: a FORK head is never read and never suppresses, even enrolled",
        _live_issue_admission(
            _RaisingAPI(), "owner/registry", "owner/repo", 9,
            {95: {**orch_pull,
                  "head": {"ref": "fix/x", "repo": {"full_name": "mallory/repo"}}}},
            "app[bot]", enrolled_authors=orch_enrolled),
        "denied",
    )

    # THE POLICY READ. `Limits.enrolled_authors` defaults to `()`, so a load_limits that never
    # populates it would leave every check above passing while production ran enrolment-off.
    with tempfile.TemporaryDirectory() as tmp:
        _pol_dir = Path(tmp)
        (_pol_dir / "repos.toml").write_text(
            '[repos."owner/repo"]\nenabled=true\nrouting="r.toml"\naccount_pool=["acct01"]\n'
            'max_concurrent=1\nworker_timeout_minutes=30\ngate_profile="lint-only"\n'
            'arm_auto_merge=false\nmax_attempts=3\ntrust="collaborators"\n'
            f'review_enrolment_authors=["{orch_login}"]\n', encoding="utf-8")
        _pol_limits = load_limits(_pol_dir / "repos.toml",
                                  Path(__file__).resolve().with_name("policy-resolve.py"))
        check(
            "[#835] load_limits carries the repo's MASTER-protected allowlist onto Limits "
            "(hard-coding `()` there turns groom's class awareness off in production)",
            _pol_limits["owner/repo"].enrolled_authors, (orch_login,))
        (_pol_dir / "repos.toml").write_text(
            (_pol_dir / "repos.toml").read_text(encoding="utf-8").replace(
                f'review_enrolment_authors=["{orch_login}"]\n', ""), encoding="utf-8")
        check(
            "[#835] ...and an unset allowlist is EMPTY, i.e. enrolment off by default",
            load_limits(_pol_dir / "repos.toml",
                        Path(__file__).resolve().with_name("policy-resolve.py")
                        )["owner/repo"].enrolled_authors, ())

    # THE CALL SITES, on the PARSED module. A behavioural test of the admissions cannot see
    # `run_sweep` passing a hard-coded `()`; the guards would stay green while the feature was
    # off in production. Parsed, never regexed — a source regex fails permissive under a reflow.
    _sweep_fn = next(
        node for node in ast.walk(ast.parse(
            Path(__file__).resolve().read_text(encoding="utf-8")))
        if isinstance(node, ast.FunctionDef) and node.name == "run_sweep")
    _sweep_enrol = [
        (getattr(node.func, "id", ""), ast.unparse(keyword.value))
        for node in ast.walk(_sweep_fn) if isinstance(node, ast.Call)
        and getattr(node.func, "id", "") in ("_admitted_review_prs", "_live_issue_admission")
        for keyword in node.keywords if keyword.arg == "enrolled_authors"]
    check(
        "[#835] every class-aware admission in run_sweep is handed the LIVE per-repo allowlist "
        "(not a literal), at all FOUR call sites",
        sorted(_sweep_enrol),
        sorted([("_admitted_review_prs", "limits[repo].enrolled_authors"),          # planning
                # Issue #279: the ready-repair boundary re-derives this PER ACTION from a fresh
                # listing, so it is keyed on `action.repo` like the defer boundary — the pre-loop
                # per-repo snapshot it replaced is gone.
                ("_admitted_review_prs", "limits[action.repo].enrolled_authors"),   # ready boundary
                ("_admitted_review_prs", "limits[action.repo].enrolled_authors"),   # defer boundary
                ("_live_issue_admission", "limits[action.repo].enrolled_authors")]))

    # [#649] THE REPORTING SEAM, on the same parsed module. A phase that records deferrals and is
    # then never handed to `sweep_exit_failure` is exit-zero-swallows-failure with extra steps —
    # and no behavioural test can see it, because the phase's own ALERTs still print. Every
    # PhaseOutcome `run_sweep` binds must appear in the argument tuple, and the tuple is pinned
    # EXACTLY, so adding a ninth phase without reporting it (or dropping an existing one) reds.
    _sweep_outcome_names = sorted(
        target.id
        for node in ast.walk(_sweep_fn) if isinstance(node, ast.Assign)
        if isinstance(node.value, ast.Call)
        and getattr(node.value.func, "id", "") == "PhaseOutcome"
        for target in node.targets if isinstance(target, ast.Name))
    _sweep_reported_names = sorted(
        ast.unparse(element)
        for node in ast.walk(_sweep_fn) if isinstance(node, ast.Call)
        and getattr(node.func, "id", "") == "sweep_exit_failure"
        for argument in node.args
        for element in (argument.elts
                        if isinstance(argument, (ast.Tuple, ast.List)) else [argument]))
    check(
        "[#649] EVERY phase outcome run_sweep builds is reported by sweep_exit_failure, and the "
        "reported set is exactly the eight phases (the three #649 additions included)",
        (
            sorted(set(_sweep_outcome_names) - set(_sweep_reported_names)),
            _sweep_reported_names,
        ),
        ([], sorted([
            "detect_outcome", "repair_outcome", "defuse_outcome", "stale_outcome",
            "unpark_outcome", "snapshot_outcome", "budget_outcome", "reap_outcome",
        ])))

    # Orphan repair: closed-unmerged worker PRs strip every status label ('complete' adds nothing),
    # and a dead review loop leaves status:in-progress-review. Both are recoverable ONLY when the
    # issue carries worker-attempt evidence, is stale, is not needs:user, and has no open PR.
    stale_at = datetime.fromtimestamp(now - 700, timezone.utc).isoformat()
    orphan_issues = {
        "owner/repo": {
            21: {"labels": [{"name": "role:impl"}], "updated_at": stale_at},
            22: {"labels": [{"name": "status:in-progress-review"}], "updated_at": stale_at},
            23: {"labels": [{"name": "role:impl"}], "updated_at": stale_at},  # no attempts
            24: {"labels": [{"name": "role:impl"}, {"name": "needs:user"}],
                 "updated_at": stale_at},
            25: {"labels": [{"name": "status:in-progress-review"}], "updated_at": stale_at},
            26: {"labels": [{"name": "status:deferred"}], "updated_at": stale_at},
            27: {"labels": [{"name": "role:impl"}],
                 "updated_at": datetime.fromtimestamp(now - 10, timezone.utc).isoformat()},
        }
    }
    # A genuine open worker PR for issue #25 (full identity) suppresses its orphan repair — the
    # "has no open PR" recovery precondition. Identity-incomplete linkage no longer counts (issue
    # #172), so this stand-in must carry the App author, same-repo head, worker branch, and marker.
    linked_pull = {
        "updated_at": stale_at,
        "head": {
            "ref": "sparq-agent/issue-25-99-1",
            "repo": {"full_name": "owner/repo"},
        },
        "user": {"login": "app[bot]"},
        "body": WORKER_PR_MARKER + "\n\nFixes #25",
    }
    orphan_attempts = {("owner/repo", n): 1 for n in (21, 22, 24, 25, 26, 27)}
    orphan_attempts[("owner/repo", 23)] = 0
    orphan_actions, _prs2, _dead2 = _plan_actions(
        {"owner/repo": limits},
        orphan_issues,
        {"owner/repo": {99: linked_pull}},
        {"owner/repo": set()},
        orphan_attempts,
        {},
        [],
        {},
        now,
        "app[bot]",
    )
    check(
        "orphan repair readies dead states only",
        sorted((action.number, action.mode) for action in orphan_actions),
        [(21, "ready"), (22, "ready")],
    )
    check(
        "orphan repair reasons are recoverable",
        sorted(action.reason for action in orphan_actions),
        [
            "in review without an open worker PR",
            "no orchestration status after a worker attempt",
        ],
    )
    # issue #172, end-to-end: an UNTRUSTED PR that only loose-links issue #25 (fork head, no bot
    # author, no marker) must NOT suppress its orphan repair — issue #25 is now readied alongside
    # #22. Reverting `_current_links` to loose linkage reds this: an outsider could otherwise hold
    # a stale issue out of recovery indefinitely by opening a fork PR that mentions it.
    untrusted_pull = {
        "updated_at": stale_at,
        "head": {"ref": "sparq-agent/issue-25-99-1", "repo": {"full_name": "mallory/repo"}},
        "user": {"login": "mallory"},
        "body": "helpful contribution\n\nFixes #25",
    }
    untrusted_actions, _prs3, _dead3 = _plan_actions(
        {"owner/repo": limits},
        orphan_issues,
        {"owner/repo": {99: untrusted_pull}},
        {"owner/repo": set()},
        orphan_attempts,
        {},
        [],
        {},
        now,
        "app[bot]",
    )
    check(
        "issue #172: an untrusted linking PR does NOT suppress orphan recovery of issue #25",
        sorted((a.number, a.mode) for a in untrusted_actions),
        [(21, "ready"), (22, "ready"), (25, "ready")],
    )
    # Round 1, end-to-end: a fully AUTHENTICATED worker PR bound to issue #22 by its branch, whose
    # body also says `Fixes #25`, suppresses recovery for #22 ONLY — #25 is readied. Linking body
    # closing references back into `_current_links` reds this: the App's own PR would then hold an
    # unrelated stale issue out of recovery.
    cross_linked_pull = {
        "updated_at": stale_at,
        "head": {
            "ref": "sparq-agent/issue-22-99-1",
            "repo": {"full_name": "owner/repo"},
        },
        "user": {"login": "app[bot]"},
        "body": WORKER_PR_MARKER + "\n\nFixes #25",
    }
    cross_actions, _prs4, _dead4 = _plan_actions(
        {"owner/repo": limits},
        orphan_issues,
        {"owner/repo": {99: cross_linked_pull}},
        {"owner/repo": set()},
        orphan_attempts,
        {},
        [],
        {},
        now,
        "app[bot]",
    )
    check(
        "round 1: a worker PR's body reference does NOT suppress recovery of unrelated issue #25",
        sorted((a.number, a.mode) for a in cross_actions),
        [(21, "ready"), (25, "ready")],
    )

    malformed_failed = False
    try:
        validate_ledger({"leases": [{**base, "claim_id": "unsafe"}]})
    except GroomError:
        malformed_failed = True
    check("malformed ledger fails closed", malformed_failed, True)
    check("raw account handle is dropped during bounded ledger migration",
          validate_ledger({"leases": [{**base, "account": "acct01"}]}), [])
    mixed = validate_ledger({"leases": [{**base, "account": "acct01"}, base]})
    check("canonical lease survives mixed-ledger migration", mixed, [base])
    canonical_shape_failed = False
    try:
        validate_ledger({"leases": [{**base, "claim_id": "unsafe"}]})
    except GroomError:
        canonical_shape_failed = True
    check("canonical lease shape still fails closed", canonical_shape_failed, True)

    # Review/fix repair leases: tolerated by validation, never issue-mapped, and a malformed
    # NON-repair holder still fails closed (the skip must not widen into blanket tolerance).
    check("repair holder detected", is_repair_holder("review:sparq-org/sparq#2445"), True)
    check("fix holder detected", is_repair_holder("fix:sparq-org/sparq#2445"), True)
    check("impl holder is not repair", is_repair_holder(base["holder"]), False)
    repair_lease = {**base, "claim_id": "c" * 32, "holder": "review:owner/repo#9"}
    validated = validate_ledger({"leases": [base, repair_lease]})
    check("repair lease passes ledger validation", len(validated), 2)
    bad_holder_failed = False
    try:
        validate_ledger({"leases": [{**base, "claim_id": "d" * 32, "holder": "not-an-issue-holder"}]})
    except GroomError:
        bad_holder_failed = True
    check("malformed non-repair holder still fails closed", bad_holder_failed, True)

    # ---- per-owner target token routing (issue #168: two enabled owners, one token per owner) ----
    # The sweep reads/writes each target under ITS owner's App token; a single sparq-org-scoped
    # token 404s every jeswr read and fails every jeswr write, aborting the sweep before dead-lease
    # release. Reverting target_api_for to a single shared client (owner-blind) reds the "different
    # api per owner" checks; dropping the wrong-owner defer reds the "unminted owner -> None" check.
    sparq_api, jeswr_api = object(), object()
    routed = {"sparq-org": sparq_api, "jeswr": jeswr_api}
    check(
        "sparq-org repo routes to the sparq-org token client",
        target_api_for("sparq-org/sparq", routed) is sparq_api,
        True,
    )
    check(
        "jeswr repo routes to the DIFFERENT jeswr token client (not the sparq one)",
        target_api_for("jeswr/agent-account-registry", routed) is jeswr_api,
        True,
    )
    check(
        "unminted owner routes to None (defer, never a wrong-owner token)",
        target_api_for("other/repo", {"sparq-org": sparq_api}),
        None,
    )
    check("malformed repo routes to None", target_api_for("no-slash", routed), None)

    saved_token_env = {
        key: os.environ.get(key)
        for key in ("TARGET_GH_TOKENS", "TARGET_GH_TOKEN", "TARGET_GH_TOKEN_OWNER")
    }
    try:
        for key in saved_token_env:
            os.environ.pop(key, None)
        os.environ["TARGET_GH_TOKENS"] = json.dumps(
            {"sparq-org": "tok-sparq", "jeswr": "tok-jeswr", "blank": "", "": "x"}
        )
        check(
            "per-owner token map parses and drops blank owner/token entries",
            target_tokens_map(),
            {"sparq-org": "tok-sparq", "jeswr": "tok-jeswr"},
        )
        os.environ.pop("TARGET_GH_TOKENS", None)
        os.environ["TARGET_GH_TOKEN"] = "legacy-tok"
        os.environ["TARGET_GH_TOKEN_OWNER"] = "sparq-org"
        legacy_map = target_tokens_map()
        check("legacy single token maps to its declared owner", legacy_map, {"sparq-org": "legacy-tok"})
        check("legacy token does NOT cover the other owner (defers)", "jeswr" in legacy_map, False)
        os.environ["TARGET_GH_TOKENS"] = "{not json"
        malformed_tokens = False
        try:
            target_tokens_map()
        except GroomError:
            malformed_tokens = True
        check("malformed TARGET_GH_TOKENS fails closed", malformed_tokens, True)
        os.environ["TARGET_GH_TOKENS"] = json.dumps(["sparq-org", "tok"])
        non_object_tokens = False
        try:
            target_tokens_map()
        except GroomError:
            non_object_tokens = True
        check("non-object TARGET_GH_TOKENS fails closed", non_object_tokens, True)
    finally:
        for key, value in saved_token_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # ---- per-owner mint scoping (issue #168, review round 1) ----
    # Each owner's App token must be scoped to EVERY enabled repo under that owner: reverting
    # enabled_owner_repos to "one representative repo per owner" reds the two-repos check below,
    # and dropping the exact-owner-set assertion reds the drift checks (fail-loud, never a
    # silently dropped or under-scoped owner token).
    two_per_owner = {
        "repos": {
            "sparq-org/sparq": {"enabled": True},
            "sparq-org/second-target": {"enabled": True},
            "jeswr/agent-account-registry": {"enabled": True},
            "jeswr/disabled-target": {"enabled": False},
        }
    }
    check(
        "ALL enabled repos are collected per owner (not one representative)",
        enabled_owner_repos(two_per_owner),
        {"sparq-org": ["sparq", "second-target"], "jeswr": ["agent-account-registry"]},
    )
    check(
        "mint-scope outputs carry every enabled repo, comma-joined per owner",
        sorted(owner_repo_output_lines(two_per_owner)),
        ["jeswr_names=agent-account-registry", "sparq_names=sparq,second-target"],
    )
    for drift_name, drift_doc in (
        (
            "an unexpected third enabled owner fails loud (no silent token drop)",
            {"repos": {**two_per_owner["repos"], "third-org/repo": {"enabled": True}}},
        ),
        (
            "a missing expected owner fails loud (its mint step would be unscoped)",
            {"repos": {"sparq-org/sparq": {"enabled": True}}},
        ),
    ):
        drifted = False
        try:
            owner_repo_output_lines(drift_doc)
        except GroomError:
            drifted = True
        check(drift_name, drifted, True)
    unsafe_owner_repo = False
    try:
        enabled_owner_repos({"repos": {"bad name/repo": {"enabled": True}}})
    except GroomError:
        unsafe_owner_repo = True
    check("unsafe enabled repo name fails closed in mint scoping", unsafe_owner_repo, True)

    # ---- dispatch.yml manifest mint scoping (issue #273) ----
    # dispatch's owners come from the DISPATCH_TARGET_REPOS manifest, not policy, and CLAIM routes
    # the minted token by OWNER. Reverting the manifest aggregation to "one representative repo
    # per owner" (the #273 defect) reds the two-repos check; dropping the exact-owner-set
    # assertion or the safe-name/JSON validation reds the fail-closed checks below.
    check(
        "manifest mint scope carries EVERY repo per owner, comma-joined",
        sorted(manifest_owner_repo_output_lines(
            '["sparq-org/sparq", "jeswr/agent-account-registry", "sparq-org/second-target"]'
        )),
        ["jeswr_names=agent-account-registry", "sparq_names=sparq,second-target"],
    )
    check(
        "a repeated manifest entry is collapsed, not doubled in the mint scope",
        owner_repos_from_names(["sparq-org/sparq", "sparq-org/sparq", "jeswr/registry"]),
        {"sparq-org": ["sparq"], "jeswr": ["registry"]},
    )
    for manifest_name, bad_manifest in (
        ("a third manifest owner fails loud (its mint step is missing)",
         '["sparq-org/sparq", "jeswr/agent-account-registry", "third-org/repo"]'),
        ("a manifest missing an expected owner fails loud", '["sparq-org/sparq"]'),
        ("an unsafe manifest repo name fails closed", '["sparq-org/sparq", "jeswr/bad name"]'),
        ("a non-string manifest entry fails closed", '["sparq-org/sparq", 7]'),
        ("a non-array manifest fails closed", '{"sparq-org": "sparq"}'),
        ("an empty manifest fails closed (never an unscoped mint)", "[]"),
        ("a malformed/absent manifest fails closed", ""),
    ):
        manifest_died = False
        try:
            manifest_owner_repo_output_lines(bad_manifest)
        except GroomError:
            manifest_died = True
        check(manifest_name, manifest_died, True)

    # ---- ledger-branch targeting (issue #28: data plane off the protected code branch) ----
    # Literal "ledger": pointing either helper back at the default branch (or changing the shipped
    # REGISTRY_LEDGER_REF default) must turn these red.
    check(
        "ledger read targets the ledger ref",
        ledger_read_path("o/r"),
        f"/repos/o/r/contents/{LEDGER_PATH}?ref=ledger",
    )
    check("ledger write pins branch=ledger", ledger_put_body("m", "abc", "s")["branch"], "ledger")
    check("ledger write carries the CAS sha", ledger_put_body("m", "abc", "s")["sha"], "s")
    check("ledger write without sha omits it (create-if-absent)",
          "sha" in ledger_put_body("m", "abc", None), False)
    seeded = _StubAPI({
        ledger_read_path("o/r"): {
            "content": base64.b64encode(json.dumps({"leases": []}).encode()).decode(),
            "sha": "s1",
        }
    })
    check("ledger read parses at the ledger ref", _read_ledger(seeded, "o/r"), ([], "s1"))
    mixed_seeded = _StubAPI({
        ledger_read_path("o/r"): {
            "content": base64.b64encode(json.dumps({
                "leases": [{**base, "account": "legacy-handle"}, base],
            }).encode()).decode(),
            "sha": "s2",
        }
    })
    check("ledger read drops legacy identity and retains canonical lease",
          _read_ledger(mixed_seeded, "o/r"), ([base], "s2"))
    missing_ledger_loud = False
    try:
        _read_ledger(_StubAPI({}), "o/r")  # stub 404s every path → branch AND file absent
    except GroomError:
        missing_ledger_loud = True
    check("missing ledger BRANCH fails loud (never silently-empty)", missing_ledger_loud, True)
    check(
        "missing ledger FILE on a present branch seeds empty (first-write path)",
        _read_ledger(
            _StubAPI({f"/repos/o/r/git/ref/heads/{LEDGER_REF}": {"object": {"sha": "tip"}}}),
            "o/r",
        ),
        ([], None),
    )

    # ---- CAS retry backoff schedule + retry/fail-loud behavior (issue #179) ----
    check(
        "backoff ceiling is exponential then capped",
        [_backoff_ceiling(a) for a in (1, 2, 3, 4, 5, 6, 10)],
        [0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 8.0],
    )

    dead = "e" * 32

    class _CasAPI:
        """Drive _release_claims: each GET returns the ledger holding `dead` (fresh sha per read);
        each PUT raises GroomConflict for the first `conflicts` calls, then a success dict — unless
        `put_error` is set, in which case every PUT raises it (a non-conflict GitHubAPI failure)."""

        def __init__(self, conflicts=0, put_error=None):
            self.conflicts, self.put_error = conflicts, put_error
            self.reads = self.puts = 0

        def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
            if method == "GET":
                self.reads += 1
                document = {
                    "leases": [{
                        "account": "aaaaaaaaaaaaaaaa", "claim_id": dead,
                        "holder": "owner/repo#7@run.1",
                        "package": "p", "role": "impl", "model": "m",
                        "issued_at": 1, "expires_at": 9,
                    }]
                }
                return {
                    "content": base64.b64encode(json.dumps(document).encode()).decode(),
                    "sha": f"sha{self.reads}",
                }
            self.puts += 1
            if self.put_error is not None:
                raise self.put_error
            if self.puts <= self.conflicts:
                raise GroomConflict("compare-and-swap conflict")
            return {"content": {"sha": "new"}}

    real_backoff = globals()["_sleep_backoff"]
    backoff_attempts: list[int] = []
    globals()["_sleep_backoff"] = lambda attempt: backoff_attempts.append(attempt)
    try:
        rider = _CasAPI(conflicts=1)
        released = _release_claims(rider, "o/r", {dead})
        check("release rides out one CAS conflict", released, 1)
        check("release re-read after the conflict (CAS retry)", rider.reads, 2)
        check("release backs off once, only between attempts", backoff_attempts, [1])
        # A non-conflict GitHubAPI failure (e.g. 403 auth) is NOT swallowed as a conflict: it
        # propagates out of the retry loop instead of being retried six times.
        backoff_attempts.clear()
        loud = False
        try:
            _release_claims(_CasAPI(put_error=GroomError("auth")), "o/r", {dead})
        except GroomError:
            loud = True
        check("non-conflict PUT error propagates (not collapsed into a conflict retry)", loud, True)
        # Persistent CAS conflict still settles into the loud "did not settle" after retries.
        settled_loud = False
        try:
            _release_claims(_CasAPI(conflicts=99), "o/r", {dead}, retries=3)
        except GroomError as exc:
            settled_loud = "did not settle" in str(exc)
        check("persistent CAS conflict fails loud after retries", settled_loud, True)
    finally:
        globals()["_sleep_backoff"] = real_backoff

    # ---- #494 bounded transient-network retry in GitHubAPI.request ----
    # The live failure was a raw http.client.RemoteDisconnected out of api.paginate -> request()
    # that exited the whole sweep 1. These drive the REAL request() through a swapped urlopen: a
    # transient class that succeeds on the 2nd attempt must complete (delete the retry -> the first
    # RemoteDisconnected propagates and reds "sweep completes"), and a 403 must NEVER be retried
    # (widen the retry to 4xx -> the call count reds "403 is not retried").
    check("RemoteDisconnected classifies transient", _is_transient_network(
        http.client.RemoteDisconnected("Remote end closed connection without response")), True)
    check("URLError-wrapped reset classifies transient",
          _is_transient_network(URLError(ConnectionResetError("reset by peer"))), True)
    check("timeout classifies transient", _is_transient_network(TimeoutError("timed out")), True)
    check("DNS/refused URLError stays fatal",
          _is_transient_network(URLError("Name or service not known")), False)
    check("an HTTPError is not a network-transient (handled by code branch)",
          _is_transient_network(HTTPError("https://x", 503, "u", {}, None)), False)
    # [issue #291] The transient HTTP class is the WHOLE 5xx range, not the {502,503,504} allow-list
    # that let `... GET failed with HTTP 500` kill two sweeps in 4.5h. Both directions are pinned:
    # every 5xx retries, and NOTHING outside 5xx does — restoring the allow-list reds the 500/507
    # legs, and widening to 4xx reds the refusal legs (429 included, deliberately).
    check("#291 the 500 that killed the sweep is transient", _is_transient_status(500), True)
    check("#291 the whole 5xx range is transient (not a three-code allow-list)",
          [code for code in range(500, 600) if not _is_transient_status(code)], [])
    check("#291 the pre-existing gateway codes still retry (no regression)",
          [_is_transient_status(code) for code in (502, 503, 504)], [True, True, True])
    check("#291 no 4xx is transient — a refusal must fail closed, 429 INCLUDED",
          [code for code in range(400, 500) if _is_transient_status(code)], [])
    check("#291 success/redirect statuses are not transient either",
          [_is_transient_status(code) for code in (200, 201, 301, 304, 600)],
          [False, False, False, False, False])
    # [registry #552] ...and the classifier those rows exercise must BE the shared taxonomy's, not a
    # private re-implementation that happens to agree today. Every behavioural row above passes just
    # as happily against an inlined copy, and an inlined copy is precisely the defect: this decision
    # was written out by hand in groom AND in plan-snapshot with nothing comparing the two tables,
    # so a change to one drifted from the other silently — in the fail-CLOSED direction, where each
    # omission costs a whole scheduled sweep. So pin IDENTITY, not behaviour: re-inline
    # `_is_transient_status` or `_is_transient_network` here and this row goes red while everything
    # above stays green.
    check("#552 the transient classifier IS the shared http_transient one, not a local copy",
          (_is_transient_status == _TRANSIENT_STATUS_POLICY.retries,
           _TRANSIENT_STATUS_POLICY is _http_transient.GROOM_SWEEP,
           _is_transient_network is _http_transient.is_transient_network),
          (True, True, True))
    # ...and the shared taxonomy's OWN suite must pass, since groom's retry correctness now rests on
    # it. A classifier that ships broken must not be adopted silently by its consumer.
    check("#552 the shared http_transient taxonomy's own self-test passes",
          _http_transient._self_test(), True)
    check("Retry-After is honoured and capped",
          (_retry_after_seconds({"Retry-After": "2"}),
           _retry_after_seconds({"Retry-After": "9999"}),
           _retry_after_seconds({}),
           _retry_after_seconds({"Retry-After": "soon"})),
          (2.0, _RETRY_AFTER_CAP, None, None))

    class _FakeResp:
        def __init__(self, raw: bytes):
            self._raw = raw

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def read(self) -> bytes:
            return self._raw

    real_urlopen = globals()["urlopen"]
    real_sleep_transient = globals()["_sleep_transient"]
    transient_sleeps: list[Any] = []
    globals()["_sleep_transient"] = (
        lambda attempt, retry_after=None: transient_sleeps.append((attempt, retry_after)))
    calls = {"n": 0}
    try:
        api = GitHubAPI("t", "registry")

        def _flaky(_request, timeout=None):        # RemoteDisconnected once, then a good page
            calls["n"] += 1
            if calls["n"] == 1:
                raise http.client.RemoteDisconnected("Remote end closed connection")
            return _FakeResp(json.dumps({"ok": True}).encode())

        globals()["urlopen"] = _flaky
        result = api.request("GET", "/repos/o/r/issues/7/comments")
        check("transient RemoteDisconnected retried, sweep completes",
              (result, calls["n"], transient_sleeps), ({"ok": True}, 2, [(1, None)]))

        calls["n"] = 0
        transient_sleeps.clear()

        def _forbidden(_request, timeout=None):    # 403 is auth/permission — never retried
            calls["n"] += 1
            raise HTTPError("https://api.github.com/x", 403, "Forbidden", {}, None)

        globals()["urlopen"] = _forbidden
        forbidden_loud = False
        try:
            api.request("GET", "/repos/o/r/issues/7/comments")
        except GroomError as exc:
            forbidden_loud = "403" in str(exc)
        check("403 is not retried (fails closed on the first attempt)",
              (forbidden_loud, calls["n"], transient_sleeps), (True, 1, []))

        calls["n"] = 0
        transient_sleeps.clear()

        def _throttled(_request, timeout=None):    # 503 + Retry-After, then a good page
            calls["n"] += 1
            if calls["n"] == 1:
                raise HTTPError("https://x", 503, "Unavailable", {"Retry-After": "2"}, None)
            return _FakeResp(json.dumps([]).encode())

        globals()["urlopen"] = _throttled
        throttled = api.request("GET", "/repos/o/r/issues?state=open")
        check("503 retried, honouring the Retry-After header",
              (throttled, calls["n"], transient_sleeps), ([], 2, [(1, 2.0)]))

        # [issue #291] THE PRODUCTION LEG, end to end. Asserting only `_is_transient_status(500)`
        # would stay green if the call site still consulted the old allow-list, and "500 is in a
        # set" is not the property that killed two sweeps. This drives the REAL request() through
        # the REAL retry loop with the REAL status those runs emitted, and counts urlopen
        # INVOCATIONS: pre-fix this was 1 call and a GroomError.
        calls["n"] = 0
        transient_sleeps.clear()

        def _internal_error(_request, timeout=None):   # plain 500 once, then the real page
            calls["n"] += 1
            if calls["n"] == 1:
                raise HTTPError("https://api.github.com/x", 500, "Internal Server Error", {}, None)
            return _FakeResp(json.dumps({"number": 7}).encode())

        globals()["urlopen"] = _internal_error
        try:
            recovered: Any = api.request("GET", "/repos/sparq-org/sparq/issues/7")
        except GroomError as exc:
            # The pre-fix behaviour, reported as a FAIL rather than propagating: an abort here
            # would skip the fail-closed legs below, which are the ones that prove the widening
            # did not go too far.
            recovered = f"LOUD-FAILED: {exc}"
        check("#291 a transient HTTP 500 on a target GET is retried and the sweep completes",
              (recovered, calls["n"], transient_sleeps), ({"number": 7}, 2, [(1, None)]))

        # FAIL-CLOSED IS PRESERVED: widening the class must not turn a persistent 500 into a silent
        # success or an unbounded loop. It still dies loud, after the bounded attempts, naming 500.
        calls["n"] = 0
        transient_sleeps.clear()

        def _always_500(_request, timeout=None):
            calls["n"] += 1
            raise HTTPError("https://api.github.com/x", 500, "Internal Server Error", {}, None)

        globals()["urlopen"] = _always_500
        persistent_500 = ""
        try:
            api.request("GET", "/repos/sparq-org/sparq/issues/7")
        except GroomError as exc:
            persistent_500 = str(exc)
        check("#291 a PERSISTENT 500 still fails loud after the bounded attempts",
              ("HTTP 500" in persistent_500, calls["n"]), (True, _TRANSIENT_RETRIES))

        # ...and the newly-widened class does NOT leak past the mutation guard: a 500 on a POST is
        # ambiguous (GitHub may have applied it), so it fails loud on attempt 1 exactly as before.
        calls["n"] = 0
        transient_sleeps.clear()
        globals()["urlopen"] = _internal_error   # a GET recovers on this stub; a POST must not
        post_500_loud = False
        try:
            api.request("POST", "/repos/o/r/issues/7/comments", {"body": "x"})
        except GroomError:
            post_500_loud = True
        check("#291 a 500 on a POST is still never replayed (fails loud, one attempt)",
              (post_500_loud, calls["n"], transient_sleeps), (True, 1, []))

        calls["n"] = 0
        transient_sleeps.clear()

        def _always_reset(_request, timeout=None):  # persistent transient still fails loud
            calls["n"] += 1
            raise ConnectionResetError("connection reset by peer")

        globals()["urlopen"] = _always_reset
        exhausted_loud = False
        try:
            api.request("GET", "/repos/o/r/issues/7/comments")
        except GroomError:
            exhausted_loud = True
        check("persistent transient fails loud after the bounded attempts (no infinite loop)",
              (exhausted_loud, calls["n"]), (True, _TRANSIENT_RETRIES))

        # Mutations are NEVER transparently replayed: an ambiguous transient failure cannot prove
        # the first attempt was not applied (a replayed POST duplicates a comment; a replayed
        # PATCH/PUT repeats a state transition). Widen _IDEMPOTENT_METHODS or drop the retryable
        # guard and the call counts here red at 2.
        check("only GET/HEAD are transparently retried",
              sorted(_IDEMPOTENT_METHODS), ["GET", "HEAD"])

        calls["n"] = 0
        transient_sleeps.clear()
        globals()["urlopen"] = _flaky   # RemoteDisconnected once, then success — GETs recover here
        post_loud = False
        try:
            api.request("POST", "/repos/o/r/issues/7/comments", {"body": "x"})
        except GroomError:
            post_loud = True
        check("ambiguous connection drop on a POST is not replayed (fails loud, one attempt)",
              (post_loud, calls["n"], transient_sleeps), (True, 1, []))

        calls["n"] = 0
        transient_sleeps.clear()

        def _gateway_503(_request, timeout=None):   # transient-class 503 on a mutation
            calls["n"] += 1
            raise HTTPError("https://x", 503, "Unavailable", {"Retry-After": "2"}, None)

        globals()["urlopen"] = _gateway_503
        patch_loud = False
        try:
            api.request("PATCH", "/repos/o/r/issues/7", {"state": "closed"})
        except GroomError as exc:
            patch_loud = "503" in str(exc)
        check("transient 503 on a PATCH is not replayed (fails loud, one attempt)",
              (patch_loud, calls["n"], transient_sleeps), (True, 1, []))

        # ---- #240: a 422 is a CAS conflict ONLY in the create-race shape ----
        # `retry_conflict` used to classify EVERY 422 as contention, so a request-VALIDATION 422
        # was retried until _release_claims exhausted its attempts and reported "did not settle"
        # with GitHub's real cause thrown away. These drive the REAL request(); widen the
        # classifier back to `exc.code in {409, 422}` and the three fail-loud checks red, narrow
        # it further (drop the 422 arm entirely) and the create-race check reds.
        #
        # The envelopes are GitHub's RAW answers — JSON SOURCE, so the message's inner quotes are
        # backslash-escaped, which is precisely what the classifier has to cope with.
        create_race_body = (
            b'{"message":"Invalid request.\\n\\n\\"sha\\" wasn\'t supplied.",'
            b'"documentation_url":"https://docs.github.com/rest/repos/contents"}'
        )
        validation_body = b'{"message":"Invalid request.\\n\\n\\"branch\\" wasn\'t supplied."}'
        ledger_path = f"/repos/o/r/contents/{LEDGER_PATH}"
        create_put = ledger_put_body("m", "e", None)     # sha-less: the create-if-absent form
        update_put = ledger_put_body("m", "e", "sha1")   # sha-bearing: an update
        check("the create/update PUT shapes under test really do differ by `sha`",
              ("sha" in create_put, update_put.get("sha")), (False, "sha1"))

        def _refusing(code, body_bytes):
            def _raise(_request, timeout=None):
                calls["n"] += 1
                raise HTTPError("https://x", code, "Unprocessable Entity", {},
                                io.BytesIO(body_bytes))
            return _raise

        # A distinct client: the shared `api` above holds the one-character token "t", and the
        # credential mask would replace every "t" in the envelope — including the signature's own.
        cas_api = GitHubAPI("CAS-SELFTEST-TOKEN", "registry")

        def _classify(stub, put_body, retry_conflict=True):
            """Run the LIVE request() against `stub` and report how it classified the failure."""
            globals()["urlopen"] = stub
            try:
                cas_api.request("PUT", ledger_path, put_body, retry_conflict=retry_conflict)
            except GroomConflict:
                return "conflict"
            except GroomError as exc:
                return str(exc)
            return "no error at all"

        check(
            "#240: the create-race 422 on a sha-less ledger PUT is still the retryable CAS "
            "conflict the caller's re-read loop owns",
            _classify(_refusing(422, create_race_body), create_put),
            "conflict",
        )
        check(
            "#240: a request-VALIDATION 422 fails LOUD carrying GitHub's own cause — it is not "
            "retried as contention until the caller reports 'did not settle'",
            _classify(_refusing(422, validation_body), create_put),
            'registry GitHub API PUT failed with HTTP 422: {"message":"Invalid request.\\n\\n'
            '\\"branch\\" wasn\'t supplied."}',
        )
        check(
            "#240: even the create-race signature is validation on an UPDATE PUT — a write that "
            "names the revision it expects cannot lose the CREATE race",
            _classify(_refusing(422, create_race_body), update_put),
            'registry GitHub API PUT failed with HTTP 422: {"message":"Invalid request.\\n\\n'
            '\\"sha\\" wasn\'t supplied.","documentation_url":'
            '"https://docs.github.com/rest/repos/contents"}',
        )
        check(
            "#240: HTTP 409 stays a CAS conflict on BOTH ledger PUT shapes (a lost SHA is never "
            "validation)",
            (_classify(_refusing(409, b'{"message":"Conflict"}'), create_put),
             _classify(_refusing(409, b'{"message":"Conflict"}'), update_put)),
            ("conflict", "conflict"),
        )
        check(
            "#240: a caller that owns NO CAS re-read loop never sees a conflict — 409 and the "
            "create-race 422 both fail loud when retry_conflict is off",
            (_classify(_refusing(409, b'{"message":"Conflict"}'), create_put,
                       retry_conflict=False).startswith("registry GitHub API PUT failed"),
             _classify(_refusing(422, create_race_body), create_put,
                       retry_conflict=False).startswith("registry GitHub API PUT failed")),
            (True, True),
        )

        # The reported symptom, end to end through the caller's retry loop: the PUT below goes
        # through the LIVE request(), so this asserts the real classifier rather than a
        # hand-raised exception.
        class _ValidationLedgerAPI(_CasAPI):
            def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
                if method == "GET":
                    return super().request(method, path, body, allow_404, retry_conflict)
                self.puts += 1
                return cas_api.request("PUT", path, body, retry_conflict=retry_conflict)

        globals()["urlopen"] = _refusing(422, validation_body)
        saved_cas_backoff = globals()["_sleep_backoff"]
        globals()["_sleep_backoff"] = lambda attempt: None
        try:
            rider = _ValidationLedgerAPI()
            validation_failure = ""
            try:
                _release_claims(rider, "o/r", {dead})
            except GroomError as exc:
                validation_failure = str(exc)
            check(
                "#240 (the reported symptom): a VALIDATION 422 on the ledger PUT surfaces "
                "GitHub's cause on the FIRST attempt — never six retries collapsed into "
                "'lease ledger CAS conflicts did not settle'",
                ("HTTP 422" in validation_failure and "branch" in validation_failure,
                 "did not settle" in validation_failure,
                 rider.puts),
                (True, False, 1),
            )
        finally:
            globals()["_sleep_backoff"] = saved_cas_backoff
    finally:
        globals()["urlopen"] = real_urlopen
        globals()["_sleep_transient"] = real_sleep_transient

    # ---- #509 release-side mutation boundary + bounded terminal reaping. ----
    # These fixtures drive the REAL run_sweep entry. The first changes a needs:* issue back to
    # status:ready after planning but before release; removing the fresh issue/PR re-confirmation
    # must release the claim and red the test. The second proves the numeric per-tick bound.
    terminal_sweep_env: dict[str, Any] = {}

    class _TerminalSweepAPI:
        def __init__(self, token, purpose):
            self.purpose = purpose

        def request(self, method, path, body=None, allow_404=False, **_kwargs):
            # Issue #647: a per-object operation can be refused by GitHub. The refusal raised here
            # is the EXACT GroomError the LIVE GitHubAPI.request builds for that HTTP failure
            # (_live_http_failure below) — never a hand-written string.
            refusal = terminal_sweep_env.get("http_failures", {}).get((method, path))
            if refusal is not None:
                raise refusal
            if method == "GET" and path.startswith("/repos/owner/repo/issues/"):
                number = int(path.rsplit("/", 1)[1])
                return terminal_sweep_env["fresh_issues"].get(number)
            if method == "GET":
                return terminal_sweep_env.get("gets", {}).get(path)
            if path == "/graphql":
                # Both live merge latches absent, so a defuse candidate stays safe-class and the
                # ONLY thing that can fail in the phase is the redraft itself (issue #644).
                return {"data": {"repository": {"pullRequest": {
                    "mergeQueueEntry": None, "autoMergeRequest": None}}}}
            terminal_sweep_env["writes"].append((method, path))
            # The BODY, recorded separately so the pre-existing (method, path) assertions keep
            # their shape. Asserting only that a POST to .../labels happened is what let the age
            # hand-off's label go untested through every round of this file's history.
            terminal_sweep_env.setdefault("write_bodies", []).append((method, path, body))
            # The RESPONSE a write hands back, opaque `{}` unless a scenario says otherwise
            # (issue #83): GitHub's DELETE-label body is the post-state the un-park verifies
            # against, so a fixture that could not vary it could not test the verification.
            return terminal_sweep_env.get("write_responses", {}).get((method, path), {})

        def paginate(self, path):
            # [#1303] Every paginated READ this fixture serves, recorded. The attempt-budget skip
            # is a claim about which requests are ISSUED, and only the call site can witness it.
            terminal_sweep_env.setdefault("paginated", []).append(path)
            # Issue #649: the three residual aborts are all PAGINATED reads (`_issues`, `_pulls`,
            # `_comments`), so the fixture must be able to refuse one — the write-side refusal map
            # above never reaches them.
            refusal = terminal_sweep_env.get("paginate_failures", {}).get(path)
            if refusal is not None:
                raise refusal
            # [#649, review round 1] CALL-SEQUENCED refusal, keyed by (path, 1-based Nth call to
            # that path). The defect under test is a listing that SUCCEEDS in the snapshot phase and
            # is refused on the LATER fresh read; a path-keyed map cannot express it — refusing
            # `/pulls?state=open` there always fails the FIRST read, so the scenario is
            # unrepresentable and the whole revalidation read goes untested.
            nth = sum(1 for seen in terminal_sweep_env["paginated"] if seen == path)
            sequenced = terminal_sweep_env.get("paginate_seq_failures", {}).get((path, nth))
            if sequenced is not None:
                raise sequenced
            if path == "/repos/owner/repo/issues?state=open":
                return terminal_sweep_env["planned_issues"]
            if path == "/repos/owner/repo/pulls?state=open":
                return terminal_sweep_env.get("pulls", [])
            return terminal_sweep_env.get("pages", {}).get(path, [])

    terminal_sweep_releases: list[set[str]] = []

    def _terminal_sweep_release(_api, _repo, claims, **_kwargs):
        terminal_sweep_releases.append(set(claims))
        return len(claims)

    terminal_sweep_leases: list[dict[str, Any]] = []
    terminal_sweep_patched = {
        "GitHubAPI": _TerminalSweepAPI,
        "load_limits": lambda *_a, **_k: {"owner/repo": limits},
        "target_tokens_map": lambda: {"owner": "sweep-token"},
        "_bot_login": lambda _api, _slug="": "app[bot]",
        "_read_ledger": lambda _api, _repo: (list(terminal_sweep_leases), "s1"),
        "_worker_runs": lambda _api, _leases: ({}, {}),
        "_release_claims": _terminal_sweep_release,
    }
    terminal_sweep_saved = {
        name: globals()[name] for name in terminal_sweep_patched
    }

    def _terminal_sweep() -> tuple[int, int, int, int]:
        return run_sweep(argparse.Namespace(
            registry_repo="owner/registry",
            policy_file="unused-policy",
            policy_resolver="unused-resolver",
            bot_slug="app",
            ledger_root="",
            stale_hours=DEFAULT_STALE_HOURS,
        ))

    # Issue #647: the refusal a per-object write meets, built by the LIVE GitHubAPI.request from a
    # real HTTPError carrying GitHub's own error envelope. The fixture therefore asserts nothing
    # about a string it wrote itself — dropping the envelope from request's raise, dropping
    # _http_failure_detail's body read, or dropping the credential mask each changes THIS value and
    # reds the assertions below.
    def _live_http_failure(
        method: str,
        path: str,
        envelope: str,
        code: int = 403,
        token: str = "sweep-token",
        purpose: str = "target owner",
    ) -> GroomError:
        real_api = terminal_sweep_saved["GitHubAPI"](token, purpose)
        saved_urlopen = globals()["urlopen"]

        def _refuse(_request, timeout=None):
            raise HTTPError(
                "https://api.github.com" + path, code, "Forbidden", {},
                io.BytesIO(envelope.encode()),
            )

        globals()["urlopen"] = _refuse
        try:
            real_api.request(method, path, {"labels": ["needs:user"]})
        except GroomError as exc:
            return exc
        finally:
            globals()["urlopen"] = saved_urlopen
        raise AssertionError("the live GitHubAPI.request must fail on an HTTP error")

    try:
        globals().update(terminal_sweep_patched)
        race_claim = "b" * 32
        terminal_sweep_leases[:] = [{
            **base,
            "claim_id": race_claim,
            "holder": "owner/repo#7@777.1",
            "issued_at": 1,
            "expires_at": 2,
        }]
        parked_issue = {
            "number": 7,
            "state": "open",
            "labels": [{"name": "area:crate-a"}, {"name": "needs:user"}],
            "updated_at": datetime.fromtimestamp(now - 10, timezone.utc).isoformat(),
            "comments": 0,
        }
        unparked_issue = {
            **parked_issue,
            "labels": [{"name": "area:crate-a"}, {"name": "status:ready"}],
        }
        terminal_sweep_env.update(
            planned_issues=[parked_issue], fresh_issues={7: unparked_issue}, writes=[]
        )
        terminal_sweep_releases.clear()
        race_summary = _terminal_sweep()
        check(
            "MUTATION #509 release guard: a freshly UNPARKED issue retains its claim",
            (race_summary[0], terminal_sweep_releases),
            (0, [set()]),
        )

        terminal_sweep_leases[:] = [
            {
                **base,
                "claim_id": f"{index:032x}",
                "holder": f"owner/repo#{index}@{1000 + index}.1",
                "issued_at": 1,
                "expires_at": 2,
            }
            for index in range(1, MAX_TERMINAL_REAPS_PER_TICK + 6)
        ]
        terminal_sweep_env.update(planned_issues=[], fresh_issues={}, writes=[])
        terminal_sweep_releases.clear()
        check("#509 terminal reap cap is explicitly fixed at 20",
              MAX_TERMINAL_REAPS_PER_TICK, 20)
        cap_log = io.StringIO()
        saved_stdout = sys.stdout
        sys.stdout = cap_log
        try:
            cap_summary = _terminal_sweep()
        finally:
            sys.stdout = saved_stdout
        check(
            "MUTATION #509 reap cap: cap+5 orphans release exactly the numeric cap",
            (cap_summary[0], len(terminal_sweep_releases[0])),
            (20, 20),
        )
        check(
            "#509 reap cap logs the exact deferred count",
            f"reap cap reached — 5 deferred" in cap_log.getvalue(),
            True,
        )

        # ---- [#1303] THE ATTEMPT-BUDGET SKIP, AT THE PRODUCTION CALL SITE. ----------------
        # The predicate and the decision-equivalence are checked above as pure functions. Neither
        # can witness whether run_sweep actually CONSULTS the predicate: replacing the call site's
        # condition with a constant leaves both of them green. This drives the real run_sweep and
        # asserts on the requests it ISSUED, which is the only place that claim is observable.
        # `limits` here is max_attempts=2, so 0- and 1-comment issues are decidable for free and
        # 2+ must still be read.
        # run_sweep takes its clock from `time.time()`, NOT this file's fixed `now`, so a
        # "fresh" issue here has to carry a real wall-clock stamp or every fixture issue reads
        # as stale and the staleness half of the filter is never exercised.
        _fresh = datetime.now(timezone.utc).isoformat()
        _old = datetime.fromtimestamp(1_000, timezone.utc).isoformat()

        def _budget_issue(number, comments, updated, labels=("area:crate-a",)):
            return {"number": number, "state": "open", "comments": comments,
                    "labels": [{"name": name} for name in labels], "updated_at": updated}

        _attempt_comment = {"user": {"login": "app[bot]"},
                            "body": ATTEMPT_MARKER + " run=1 -->"}
        # 60: no comments                       -> skip (neither guard can fire)
        # 61: below cap, NOT stale              -> skip (the orphan repair's conjuncts refuse it)
        # 62: at the cap (2)                    -> FETCH; 2 attempts exhausts it -> parks
        # 63: above the cap                     -> FETCH; only 1 attempt -> not exhausted
        # 64: below cap but STALE and statusless -> FETCH; this is the row a cap-only filter got
        #     wrong, and without it the orphan-repair half of the predicate is untested here.
        _budget_issues = [
            _budget_issue(60, 0, _fresh), _budget_issue(61, 1, _fresh),
            _budget_issue(62, 2, _fresh), _budget_issue(63, 5, _fresh),
            _budget_issue(64, 1, _old, labels=()),
        ]
        terminal_sweep_leases[:] = []
        terminal_sweep_env.update(
            planned_issues=_budget_issues,
            fresh_issues={item["number"]: item for item in _budget_issues},
            pulls=[], gets={}, writes=[], paginated=[],
            pages={
                # #62 is EXHAUSTED (2 bot attempts against max_attempts=2) -> must be read.
                "/repos/owner/repo/issues/62/comments": [_attempt_comment] * 2,
                # #63 has plenty of comments but only ONE attempt -> read, and not exhausted.
                "/repos/owner/repo/issues/63/comments": [_attempt_comment],
                # #64's single comment is a HUMAN one: the orphan repair must NOT fire, which is
                # exactly the answer the comment count alone could not have supplied.
                "/repos/owner/repo/issues/64/comments": [
                    {"user": {"login": "human"}, "body": "a question"}
                ],
                # #60 and #61 are deliberately ABSENT: a fetch for either returns [] here, so a
                # regression that reads them would be silent without the assertion below.
            },
        )
        terminal_sweep_releases.clear()
        _budget_log = io.StringIO()
        saved_stdout = sys.stdout
        sys.stdout = _budget_log
        try:
            _terminal_sweep()
        finally:
            sys.stdout = saved_stdout
        _comment_reads = sorted({
            int(p.rsplit("/", 2)[-2])
            for p in terminal_sweep_env["paginated"]
            if p.startswith("/repos/owner/repo/issues/") and p.endswith("/comments")
        })
        check(
            "CALL SITE #1303: run_sweep reads comments ONLY for the issues on which a guard can "
            "still fire (a call site that always fetches, or never fetches, reds this)",
            _comment_reads, [62, 63, 64],
        )
        # NON-VACUITY, both directions. The skipped set must be non-empty (or the optimisation
        # never fires) and the fetched set must still drive the real park (or the call site could
        # skip everything and pass).
        check(
            "...and the tick really did skip some issues AND still park the exhausted one",
            (len(terminal_sweep_env["planned_issues"]) - len(_comment_reads),
             [(m, p) for m, p, _b in terminal_sweep_env.get("write_bodies", [])
              if p == "/repos/owner/repo/issues/62/labels"]),
            (2, [("POST", "/repos/owner/repo/issues/62/labels")]),
        )
        # The #64 row is the one a cap-only filter got wrong. It is fetched, and the fetch buys a
        # real answer: its single comment is human, so the orphan repair does NOT fire. Skipping
        # it and recording the comment-count bound would have re-readied it.
        check(
            "...and the STALE below-cap issue is read, and its human comment correctly does NOT "
            "trigger the orphan repair",
            (64 in _comment_reads,
             [p for _m, p, _b in terminal_sweep_env.get("write_bodies", [])
              if "/issues/64/" in p]),
            (True, []),
        )
        check(
            "...and the per-tick saving is REPORTED, so a quiet hour cannot be mistaken for it",
            "SWEEP attempt-budget reads: 3 of 5 open issues needed a comments fetch, 2 decided "
            "by the comment count already in the list payload (0 requests)"
            in _budget_log.getvalue(),
            True,
        )

        # ---- issue #644 END-TO-END: the sweep must SURVIVE an un-redraftable parked PR ----------
        # The live failure: an uncaught redraft GroomError raised out of run_sweep BEFORE
        # _release_claims, so groom leaked leases on every run for hours while reporting only
        # "parked PR redraft failed for sparq-org/sparq#3427". Here the ONLY defuse candidate
        # cannot be redrafted AND a dead lease is waiting. Reclaim must still happen, the cause
        # must be in the log, and — because NO candidate completed — the run must still end
        # non-zero (precedence rule 2), not silently green.
        terminal_sweep_leases[:] = [{
            **base,
            "claim_id": "f" * 32,
            "holder": "owner/repo#7@777.1",
            "issued_at": 1,
            "expires_at": 2,
        }]
        stuck_pr = {
            "number": 21,
            "state": "open",
            "draft": False,
            "labels": [{"name": "needs:user"}],
            "updated_at": datetime.fromtimestamp(
                now - DEFAULT_STALE_HOURS * 3600 - 600, timezone.utc
            ).isoformat(),
            "head": {"sha": "c" * 40, "ref": "ci/codeql-nonblocking-retroactive"},
            # A BOT-authored PR touching workflow files. It was originally modelled on
            # sparq-org/sparq#3427, which is HUMAN-authored — but human PRs are no longer defuse
            # candidates at all (see _parked_pr_snapshot), so the #3427 shape now belongs to the
            # dedicated check further down. What this block still tests, and must keep testing, is
            # the head-of-line property: one un-redraftable candidate must not abort the phase.
            # A bot PR touching `.github/workflows/**` reaches that same failure legitimately.
            "user": {"login": "app[bot]", "type": "Bot"},
            "body": "a worker PR touching .github/workflows/**",
            "auto_merge": None,
        }
        terminal_sweep_env.update(
            planned_issues=[],
            fresh_issues={},
            pulls=[stuck_pr],
            gets={"/repos/owner/repo/pulls/21": stuck_pr},
            writes=[],
        )
        terminal_sweep_releases.clear()

        class _StuckRedraft:
            returncode = 1
            stdout = ""
            stderr = (
                "GraphQL: refusing to allow a GitHub App to create or update workflow "
                "`.github/workflows/codeql.yml` without `workflows` permission"
            )

        stuck_log = io.StringIO()
        saved_stdout = sys.stdout
        real_run = subprocess.run
        subprocess.run = lambda *_a, **_k: _StuckRedraft()
        sys.stdout = stuck_log
        stuck_error = ""
        try:
            _stuck_summary = _terminal_sweep()
        except GroomError as exc:
            stuck_error = str(exc)
        finally:
            sys.stdout = saved_stdout
            subprocess.run = real_run
        stuck_output = stuck_log.getvalue()
        check(
            "MUTATION #644: dead-lease reclaim STILL RUNS when the only parked PR cannot be "
            "redrafted (move _redraft_pr back outside the per-PR except block and run_sweep "
            "raises before _release_claims, leaking the lease)",
            terminal_sweep_releases,
            [{"f" * 32}],
        )
        check(
            "#644: the sweep reaches its SUMMARY and reports the deferral instead of aborting",
            (
                "ALERT PR owner/repo#21:" in stuck_output,
                "defuse deferred" in stuck_output,
                "SUMMARY reclaimed=1" in stuck_output,
                "defused_prs=0 defuse_deferred=1" in stuck_output,
            ),
            (True, True, True, True),
        )
        check(
            "#644: the un-redraftable PR's gh stderr reaches the log, and the run still exits "
            "NON-zero naming the whole-phase failure (no exit-zero swallowing)",
            (
                "without `workflows` permission" in stuck_output,
                "every parked PR defuse failed (1 attempted, 0 completed)" in stuck_error,
                "owner/repo#21" in stuck_error,
            ),
            (True, True, True),
        )
        terminal_sweep_env.update(pulls=[], gets={})

        # ---- issue #647: the SAME head-of-line abort shape in the two OTHER per-object loops -----
        # #644 fixed the defuse phase. The stale-PR hand-off loop and the issue-repair loop kept the
        # identical structure — unwrapped per-object reads and writes with _release_claims
        # DOWNSTREAM — so one unreachable PR or one un-labellable issue could still abort a sweep
        # whose later phases include reclaim. Both loops are driven END-TO-END through the real
        # run_sweep here, with the LOWEST-numbered object refused (the head-of-line position that
        # made #644 permanent), and each scenario is checked in both precedence directions.
        forbidden_envelope = (
            '{"message":"Resource not accessible by integration","documentation_url":'
            '"https://docs.github.com/rest/issues/labels#add-labels-to-an-issue","status":"403"}'
        )

        def _stale_worker_pr(number: int) -> dict[str, Any]:
            """A non-draft worker PR wedged in a bad merge state: a park (hand-off) candidate."""
            return {
                "number": number,
                "state": "open",
                "draft": False,
                "labels": [],
                "updated_at": datetime.fromtimestamp(1_000, timezone.utc).isoformat(),
                "head": {"sha": f"{number:040x}", "ref": f"sparq-agent/issue-9{number}-fix"},
                "user": {"login": "app[bot]"},
                "body": f"{WORKER_PR_MARKER}\n\nautomated work",
                "mergeable_state": "dirty",
                "auto_merge": None,
            }

        def _repairable_issue(number: int) -> dict[str, Any]:
            """A stale status:in-progress issue with no PR and no lease: a status-repair action."""
            return {
                "number": number,
                "state": "open",
                "labels": [{"name": "area:crate-a"}, {"name": "status:in-progress"}],
                "updated_at": datetime.fromtimestamp(1_000, timezone.utc).isoformat(),
                "comments": 0,
            }

        def _sweep_with_refusals(
            refusals: dict[tuple[str, str], GroomError],
            *,
            pulls: tuple[dict[str, Any], ...] = (),
            issues: tuple[dict[str, Any], ...] = (),
            details: tuple[dict[str, Any], ...] | None = None,
            extra_gets: dict[str, Any] | None = None,
            paginate_refusals: dict[str, GroomError] | None = None,
            paginate_seq_refusals: dict[tuple[str, int], GroomError] | None = None,
            leases: tuple[dict[str, Any], ...] | None = None,
            repos: tuple[str, ...] = ("owner/repo",),
        ) -> tuple[str, str, list[set[str]]]:
            """Run the REAL run_sweep with the given per-object refusals; report (log, error, releases).

            `details` overrides what the per-PR detail GET returns, so a candidate can be
            revalidated AWAY inside the hand-off loop (the deliberate-skip case). `paginate_refusals`
            refuses a LISTING (issue #649's snapshot and comments reads), `paginate_seq_refusals`
            refuses the Nth call to one listing path (the terminal-reap re-read, which is the SECOND
            read of `/pulls?state=open`), `repos`/`leases` widen the fixture to a second target so a
            head-of-line claim about ONE repo can be witnessed.
            """
            terminal_sweep_leases[:] = list(leases) if leases is not None else [{
                **base,
                "claim_id": "e" * 32,
                "holder": "owner/repo#7@777.1",
                "issued_at": 1,
                "expires_at": 2,
            }]
            terminal_sweep_env.setdefault("write_bodies", []).clear()
            terminal_sweep_env.update(
                planned_issues=list(issues),
                fresh_issues={issue["number"]: issue for issue in issues},
                pulls=list(pulls),
                gets={
                    **{
                        f"/repos/owner/repo/pulls/{pull['number']}": pull
                        for pull in (pulls if details is None else details)
                    },
                    **(extra_gets or {}),
                },
                writes=[],
                paginated=[],
                http_failures=dict(refusals),
                paginate_failures=dict(paginate_refusals or {}),
                paginate_seq_failures=dict(paginate_seq_refusals or {}),
            )
            terminal_sweep_releases.clear()
            saved_limits = globals()["load_limits"]
            globals()["load_limits"] = lambda *_a, **_k: {repo: limits for repo in repos}
            log = io.StringIO()
            saved = sys.stdout
            sys.stdout = log
            error = ""
            try:
                _terminal_sweep()
            except GroomError as exc:
                error = str(exc)
            finally:
                sys.stdout = saved
                globals()["load_limits"] = saved_limits
                terminal_sweep_env.update(
                    pulls=[], gets={}, http_failures={}, planned_issues=[], fresh_issues={},
                    paginate_failures={}, paginate_seq_failures={},
                )
            return log.getvalue(), error, [set(claims) for claims in terminal_sweep_releases]

        # (1) STALE-PR HAND-OFF LOOP, head-of-line refusal. The lower-numbered PR's needs:user label
        # POST is refused; the later PR must still be parked and commented, and the dead lease —
        # released by _release_claims, the very next statement after this loop — must still be
        # reclaimed. Move the try/except wrap away and run_sweep raises here instead.
        park_log, park_error, park_releases = _sweep_with_refusals(
            {("POST", "/repos/owner/repo/issues/31/labels"): _live_http_failure(
                "POST", "/repos/owner/repo/issues/31/labels", forbidden_envelope)},
            pulls=(_stale_worker_pr(31), _stale_worker_pr(32)),
        )
        park_writes = terminal_sweep_env["writes"]
        check(
            "MUTATION #647 (stale-PR hand-off): dead-lease reclaim STILL RUNS when the "
            "LOWEST-numbered parked PR's label write is refused (remove the loop's per-PR "
            "try/except and run_sweep raises before _release_claims, releasing NOTHING)",
            park_releases,
            [{"e" * 32}],
        )
        check(
            "#647 (stale-PR hand-off): the refused PR does NOT block the later PR — #32 is still "
            "labelled AND commented, and #31 writes nothing past its refusal",
            (
                ("POST", "/repos/owner/repo/issues/32/labels") in park_writes,
                ("POST", "/repos/owner/repo/issues/32/comments") in park_writes,
                ("POST", "/repos/owner/repo/issues/31/comments") in park_writes,
                "SKIP PR owner/repo#32" in park_log,
            ),
            (True, True, False, False),
        )
        check(
            "#647 (stale-PR hand-off): the refusal's CAUSE reaches the deferral — GitHub's own "
            "'Resource not accessible by integration' envelope, not just 'HTTP 403' (drop the "
            "envelope from GitHubAPI.request's raise, or _http_failure_detail's body read, and "
            "this reds)",
            (
                "ALERT PR owner/repo#31:" in park_log,
                "stale PR hand-off deferred" in park_log,
                "Resource not accessible by integration" in park_log,
                "HTTP 403" in park_log,
            ),
            (True, True, True, True),
        )
        check(
            "#647 precedence rule 3 (stale-PR hand-off): ONE refused PR alongside a completed one "
            "leaves the run GREEN, and the sweep still reports its SUMMARY",
            (
                park_error,
                "SUMMARY reclaimed=1" in park_log,
                "stale_prs=1" in park_log,
                "stale_pr_deferred=1" in park_log,
            ),
            ("", True, True, True),
        )
        # (1b) EVERY candidate refused: per-object leniency must not make a whole-phase failure
        # green. Reclaim still runs FIRST — the exit status is the report, never the control flow.
        park_all_log, park_all_error, park_all_releases = _sweep_with_refusals(
            {
                ("POST", f"/repos/owner/repo/issues/{number}/labels"): _live_http_failure(
                    "POST", f"/repos/owner/repo/issues/{number}/labels", forbidden_envelope)
                for number in (31, 32)
            },
            pulls=(_stale_worker_pr(31), _stale_worker_pr(32)),
        )
        check(
            "#647 precedence rule 2 (stale-PR hand-off): EVERY candidate refused is systemic — the "
            "run exits NON-zero naming both deferrals — while reclaim STILL ran first",
            (
                park_all_releases,
                "every stale PR hand-off failed (2 attempted, 0 completed)" in park_all_error,
                "owner/repo#31" in park_all_error and "owner/repo#32" in park_all_error,
                "SUMMARY reclaimed=1" in park_all_log,
                "stale_pr_deferred=2" in park_all_log,
            ),
            ([{"e" * 32}], True, True, True, True),
        )
        # (1c) The credential mask must hold on the path that now carries a response body into the
        # operator log. Removing the token replacement OR the _TOKEN_SHAPE substitution reds this.
        leaky_envelope = (
            '{"message":"Bad credentials for token sweep-token '
            '(ghs_leakleakleak12345678) while adding labels"}'
        )
        masked_log, _masked_error, _masked_releases = _sweep_with_refusals(
            {("POST", "/repos/owner/repo/issues/31/labels"): _live_http_failure(
                "POST", "/repos/owner/repo/issues/31/labels", leaky_envelope)},
            pulls=(_stale_worker_pr(31), _stale_worker_pr(32)),
        )
        check(
            "#647: an error envelope that echoes a credential is MASKED before it reaches the "
            "operator log (neither the exact target token nor any token-shaped string may appear)",
            (
                "sweep-token" in masked_log,
                "ghs_leakleakleak12345678" in masked_log,
                "Bad credentials for token *** (***) while adding labels" in masked_log,
            ),
            (False, False, True),
        )

        # ---- THE AGE-PARK CLASS SPLIT, driven END-TO-END through the real run_sweep ------------
        # Every check below is on the LEG THIS CHANGE IS NAMED FOR — the label the hand-off
        # actually POSTs — not on a helper. The pre-existing #647 checks above assert only that a
        # POST to `.../labels` HAPPENED, which is exactly why swapping `needs:user` for
        # `review:parked` left this whole file green: the body was never read. `write_bodies` is
        # the seam that closes that.
        def _park_bodies() -> list[Any]:
            # `/issues/<n>/labels` only — `POST /repos/<r>/labels` is _ensure_label CREATING
            # the label definition, which is not a park write.
            return [body for method, path, body in terminal_sweep_env.get("write_bodies", [])
                    if method == "POST" and "/issues/" in path and path.endswith("/labels")]

        def _comment_bodies() -> list[str]:
            return [body["body"] for method, path, body
                    in terminal_sweep_env.get("write_bodies", [])
                    if method == "POST" and path.endswith("/comments")]

        # (A1) A machine-recoverable cause (a wedged merge state) age-parks into the MACHINE class.
        # Invert age_park_label's return and this reds on the very first tuple element.
        machine_log, _e, _r = _sweep_with_refusals({}, pulls=(_stale_worker_pr(31),))
        machine_receipt = (f"{AGE_PARK_MARKER} cause=merge-dirty head={31:040x} gen=1 -->")
        check(
            "an AGE/timeout park lands in the MACHINE class: the hand-off POSTs review:parked, "
            "never the human-owned needs:user, and mints a cause/head/gen receipt",
            (
                _park_bodies(),
                any(machine_receipt in body for body in _comment_bodies()),
                any("No action is required from you." in body for body in _comment_bodies()),
                "labels=review:parked" in machine_log,
            ),
            ([{"labels": ["review:parked"]}], True, True, True),
        )
        check(
            "the age hand-off writes NO human-owned label for a machine-recoverable cause "
            "(the whole defect: needs:user is what park_policy refuses to auto-re-admit)",
            [body for body in _park_bodies()
             if park_policy.HUMAN_PARK_LABEL in body.get("labels", [])],
            [],
        )

        # (A2) FAIL-CLOSED DEFAULT. A cause the taxonomy cannot name has no recovery predicate, so
        # it keeps the HUMAN hand-off — a soft hold with no provable exit would be a SILENT
        # permanent hold. Deleting the `age_park_cause(reason) is None` branch reds this.
        _saved_dirty = AGE_PARK_CAUSES.pop(BAD_MERGE_STATES["dirty"])
        try:
            _unmapped_log, _e, _r = _sweep_with_refusals({}, pulls=(_stale_worker_pr(31),))
            check(
                "a cause with NO machine recovery predicate still lands in needs:user "
                "(fail-closed: an unprovable exit stays a VISIBLE human hold)",
                (
                    _park_bodies(),
                    any(AGE_PARK_MARKER in body for body in _comment_bodies()),
                ),
                ([{"labels": ["needs:user"]}], False),
            )
        finally:
            AGE_PARK_CAUSES[BAD_MERGE_STATES["dirty"]] = _saved_dirty

        # (A3) THE CAP, at the only place it is enforced — and, since [registry #1292], WHAT IT
        # COUNTS. AGE_UNPARK_MAX bounds AUTOMATIC RE-ADMISSIONS, so the generation that spends it
        # is one past every GRANT on record. Two PARK receipts are not two re-admissions; on the
        # live population they were not even one.
        def _park_receipt_comment(gen: int, number: int = 31, cause: str = "merge-dirty") -> dict:
            # Faithful to what the hand-off actually posts — STALE_PR_MARKER INCLUDED. A
            # fixture that omitted it would let a dedupe reverted to the once-ever marker pass.
            return {"user": {"login": "app[bot]"},
                    "body": f"> 🤖 SPARQ agent\n\n{STALE_PR_MARKER}\n{AGE_PARK_MARKER} "
                            f"cause={cause} head={number:040x} gen={gen} -->"}

        def _grant_receipt_comment(gen: int, number: int = 31, cause: str = "merge-dirty") -> dict:
            """An un-park GRANT receipt: the machine PROVED this park's cause recovered and spent
            one of its AGE_UNPARK_MAX automatic re-admissions on it. This — not a park comment —
            is what the cap counts."""
            return {"user": {"login": "app[bot]"},
                    "body": f"{AGE_UNPARK_MARKER} cause={cause} head={number:040x} gen={gen} -->"}

        # (A3a) [#1292] THE ABSORBING PARK, AND THE SELF-WOUND CLOCK THAT DROVE IT. This fixture
        # is the dominant live shape, reproduced exactly: repeated PARK receipts at an UNCHANGED
        # head and ZERO un-park receipts — the machine re-parked its own PR and never once
        # re-admitted it. MEASURED on the live open-PR population 2026-07-29: all 16 standing
        # age-park escalations had precisely this shape (same head across all three generations,
        # zero grants), and they were 15 of the 18 human-terminal holds applied that day.
        #
        # Counting PARKS made the escalation self-driving. The receipt embeds `gen=`, so a
        # park-derived generation minted a receipt string `already_commented` could never match;
        # the comment was re-posted; the post bumped `updated_at`; stale_worker_pr_reason reads
        # `updated_at`, so the sweep guaranteed its own next threshold crossing. Three crossings
        # of a clock the sweep wound itself reached generation 3 and applied `needs:user` — which
        # park_policy.capacity_park_admission refuses to auto-re-admit and
        # dispatch-claim.enumerate_review_items excludes. There is no machine path out of that.
        #
        # BOTH halves are asserted, because both are load-bearing and they fail independently:
        # the CLASS stays MACHINE (so age_park_cause_recovered can still let this PR out), and
        # NOTHING is re-commented (so `updated_at` does not move and the clock stops re-arming).
        # Revert age_park_generation to counting AGE_PARK_MARKER and every element reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/31/comments": [
                _park_receipt_comment(1), _park_receipt_comment(2)]}
        uncredited_log, _e, _r = _sweep_with_refusals({}, pulls=(_stale_worker_pr(31),))
        check(
            "[#1292] a park the machine NEVER re-admitted does not spend the re-admission cap: "
            "repeated parks at an unchanged head keep the MACHINE class, never needs:user, and "
            "re-post NO comment — so the sweep stops bumping updated_at and re-arming its own "
            "staleness clock",
            (
                _park_bodies(),
                _comment_bodies(),
                any("age-park generation" in body for body in _comment_bodies()),
                "labels=needs:user" in uncredited_log,
            ),
            ([{"labels": ["review:parked"]}], [], False, False),
        )
        # (A3b) ...and once the machine label is already live the whole tick is a NO-OP. This is
        # the steady state the fix converges to: the cause has not recovered, nothing was granted,
        # nothing changed — so the sweep writes nothing at all, forever, instead of counting its
        # own silence toward a human question.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/31/comments": [
                _park_receipt_comment(1), _park_receipt_comment(2)]}
        quiet_log, _e, _r = _sweep_with_refusals(
            {}, pulls=({**_stale_worker_pr(31), "labels": [{"name": "review:parked"}]},))
        check(
            "[#1292] an un-recovered, never-re-admitted park is a total NO-OP on every "
            "subsequent tick (no label, no comment) — the ladder cannot advance on its own",
            (terminal_sweep_env["writes"], _comment_bodies(), "stale_prs=0" in quiet_log),
            ([], [], True),
        )
        # (A3c) THE CAP STILL BITES — on the quantity it names. AGE_UNPARK_MAX grants really
        # spent, and the PR back in the same state, IS a flap and IS a human question. Raise
        # AGE_UNPARK_MAX (or drop the generation comparison in age_park_label) and this reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/31/comments": [
                _park_receipt_comment(1), _grant_receipt_comment(1),
                _park_receipt_comment(2), _grant_receipt_comment(2)]}
        capped_log, _e, _r = _sweep_with_refusals({}, pulls=(_stale_worker_pr(31),))
        check(
            "[#1292] re-admission is CAPPED on GRANTS: AGE_UNPARK_MAX automatic re-admissions "
            "actually granted, and the PR back again, escalates to needs:user",
            (
                _park_bodies(),
                any("age-park generation 3" in body for body in _comment_bodies()),
                any("the machine granted 2 automatic re-admission(s)" in body
                    for body in _comment_bodies()),
                any("the machine granted NO automatic re-admission on this PR"
                    in body for body in _comment_bodies()),
            ),
            ([{"labels": ["needs:user"]}], True, True, False),
        )
        # (A3d) THE ESCALATION PROSE CAN NO LONGER LIE. `flap`'s zero-grant branch tells the
        # maintainer "the machine granted NO automatic re-admission on this PR" — true when it was
        # written, and the thing that made #769 stop at the prose instead of the arithmetic. With
        # the cap counting grants, an over-cap generation PROVES AGE_UNPARK_MAX grants are on
        # record, so that branch is unreachable for any mapped cause. Asserted over the real
        # function rather than by reading the source: a generation past the cap and a grant count
        # below it must be an impossible pair.
        _over_cap = [comment for gen in range(1, AGE_UNPARK_MAX + 2)
                     for comment in (_park_receipt_comment(gen), _grant_receipt_comment(gen))]
        check(
            "[#1292] over-cap generation PROVES the grants it is about to claim — the "
            "'granted NO automatic re-admission' escalation is unreachable for a mapped cause",
            [(age_park_generation(comments, "app[bot]"),
              len(age_receipts(comments, AGE_UNPARK_MARKER, "app[bot]")))
             for comments in (_over_cap[:index] for index in range(len(_over_cap) + 1))
             if age_park_generation(comments, "app[bot]") > AGE_UNPARK_MAX
             and len(age_receipts(comments, AGE_UNPARK_MARKER, "app[bot]")) < AGE_UNPARK_MAX],
            [],
        )
        # ... and the SAME escalation with two REAL grants on record states the count it can
        # prove, and names the flap. Swap the two branches and one of these two checks reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/32/comments": [
                _park_receipt_comment(1, 32), _park_receipt_comment(2, 32),
                {"user": {"login": "app[bot]"},
                 "body": f"{AGE_UNPARK_MARKER} cause=merge-dirty head={32:040x} gen=1 -->"},
                {"user": {"login": "app[bot]"},
                 "body": f"{AGE_UNPARK_MARKER} cause=merge-dirty head={32:040x} gen=2 -->"}]}
        granted_log, _e, _r = _sweep_with_refusals({}, pulls=(_stale_worker_pr(32),))
        check(
            "[#769] ...and when the machine DID grant re-admissions, the escalation states the "
            "count the receipts prove and names the flap",
            (
                any("the machine granted 2 automatic re-admission(s)" in body
                    for body in _comment_bodies()),
                any("a repeated failure — not a timeout" in body
                    for body in _comment_bodies()),
                any("granted NO automatic re-admission" in body
                    for body in _comment_bodies()),
            ),
            (True, True, False),
        )
        # ... and the SAME escalation with two REAL grants on record states the count it can
        # prove, and names the flap. Swap the two branches and one of these two checks reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/32/comments": [
                _park_receipt_comment(1, 32), _park_receipt_comment(2, 32),
                {"user": {"login": "app[bot]"},
                 "body": f"{AGE_UNPARK_MARKER} cause=merge-dirty head={32:040x} gen=1 -->"},
                {"user": {"login": "app[bot]"},
                 "body": f"{AGE_UNPARK_MARKER} cause=merge-dirty head={32:040x} gen=2 -->"}]}
        granted_log, _e, _r = _sweep_with_refusals({}, pulls=(_stale_worker_pr(32),))
        check(
            "[#769] ...and when the machine DID grant re-admissions, the escalation states the "
            "count the receipts prove and names the flap",
            (
                any("the machine granted 2 automatic re-admission(s)" in body
                    for body in _comment_bodies()),
                any("a repeated failure — not a timeout" in body
                    for body in _comment_bodies()),
                any("granted NO automatic re-admission" in body
                    for body in _comment_bodies()),
            ),
            (True, True, False),
        )
        # The escalation is itself RECEIPTED, and that receipt is what makes it idempotent. Drop it
        # and `already_commented` can never match the body just written, so every subsequent sweep
        # posts the same escalation again — comment spam on a PR already handed to a human.
        # Replaying the tick with the escalation on record must write NOTHING. Driven from the
        # GRANT-bearing fixture, which is the only shape that can reach the escalation at all.
        _spent_cap = [_park_receipt_comment(1), _grant_receipt_comment(1),
                      _park_receipt_comment(2), _grant_receipt_comment(2)]
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/31/comments": list(_spent_cap)}
        capped_log, _e, _r = _sweep_with_refusals({}, pulls=(_stale_worker_pr(31),))
        escalation_receipt = f"{AGE_PARK_MARKER} cause=merge-dirty head={31:040x} gen=3 -->"
        check(
            "the over-cap ESCALATION is receipted too — both classes consume a generation, so both "
            "must be on record",
            any(escalation_receipt in body for body in _comment_bodies()),
            True,
        )
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/31/comments": [
                *_spent_cap,
                {"user": {"login": "app[bot]"},
                 "body": f"> 🤖 SPARQ agent\n\n{STALE_PR_MARKER}\n{escalation_receipt}"}]}
        replay_escalation_log, _e, _r = _sweep_with_refusals(
            {}, pulls=({**_stale_worker_pr(31), "labels": [{"name": "needs:user"}]},))
        check(
            "an escalation already on record is IDEMPOTENT — the same tick replayed writes NOTHING "
            "(a human hold that re-comments every sweep is the spam this replaces)",
            (terminal_sweep_env["writes"], "stale_prs=0" in replay_escalation_log),
            ([], True),
        )
        terminal_sweep_env["pages"] = {}

        # ---- the MACHINE EXIT: cause-gated, consumed exactly once, never over a human hold ------
        def _machine_parked_pr(number: int, merge_state: str, labels: tuple[str, ...],
                               *, fresh: bool = False) -> dict[str, Any]:
            """An already-age-parked worker PR, as the open-PR listing shows it.

            `fresh` puts it inside the age threshold, which the hand-off skips — so a scenario can
            exercise the EXIT phase in isolation. That it still runs is itself the point: the
            re-admission sweep is deliberately NOT age-gated, because a cause that recovers five
            minutes after the park must be re-admitted five minutes after the park."""
            return {
                "number": number,
                "state": "open",
                "draft": False,
                "labels": [{"name": name} for name in labels],
                "updated_at": datetime.fromtimestamp(
                    int(time.time()) if fresh else 1_000, timezone.utc).isoformat(),
                "head": {"sha": f"{number:040x}", "ref": f"sparq-agent/issue-9{number}-fix"},
                "user": {"login": "app[bot]"},
                "body": f"{WORKER_PR_MARKER}\n\nautomated work",
                "mergeable_state": merge_state,
                "auto_merge": None,
            }

        def _before(writes: list[Any], first: Any, second: Any) -> bool:
            """`first` was written strictly before `second`. Total, never raises: an assertion
            that CRASHES on a mutant reports a crash-kill, which hides WHICH guard failed."""
            return (first in writes and second in writes
                    and writes.index(first) < writes.index(second))

        def _grant_comment(receipt: str, at: str = "2026-07-26T11:00:00Z") -> dict[str, Any]:
            """A bot-authored un-park GRANT receipt, with the `created_at` the recency conjunct
            compares against the newest park application. A grant with no readable stamp cannot be
            proven current and must refuse."""
            return {"user": {"login": "app[bot]"}, "body": receipt, "created_at": at}

        def _labelled(label: str, at: str, actor: str) -> dict[str, Any]:
            return {"event": "labeled", "label": {"name": label},
                    "created_at": at, "actor": {"login": actor}}

        # A BOT `labeled review:parked` event must EXIST for the label to be provably
        # machine-applied. park_policy.label_application_machine_owned refuses on absence —
        # "absence of evidence is NOT proof of machine ownership" — so every happy-path fixture
        # here carries the event the live sweep would have written. The earlier fixtures omitted
        # it and passed only because the predicate then in use (park_applications) read absence
        # as permission: exactly reproduced direction 2 of #690.
        def _bot_park_timeline(number: int) -> dict[str, list[dict[str, Any]]]:
            return {f"/repos/owner/repo/issues/{number}/timeline": [
                _labelled("review:parked", "2026-07-26T10:00:00Z", "app[bot]")]}

        class _RaisingPages(dict):
            """A page store whose TIMELINE read fails. Every consumer of the timeline must fail
            CLOSED on it — the park stands, and no claim is made off evidence nobody could read.
            Defined here rather than at its first use because two call sites now need it."""

            def get(self, key, default=None):
                if key.endswith("/timeline"):
                    raise GroomError("timeline read failed")
                return super().get(key, default)

        recovered_pr = _machine_parked_pr(33, "clean", ("review:parked",))
        unpark_receipt = f"{AGE_UNPARK_MARKER} cause=merge-dirty head={33:040x} gen=1 -->"
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [_park_receipt_comment(1, 33)],
            **_bot_park_timeline(33)}
        unpark_log, _e, _r = _sweep_with_refusals({}, pulls=(recovered_pr,))
        unpark_writes = terminal_sweep_env["writes"]
        _label_delete = ("DELETE", "/repos/owner/repo/issues/33/labels/review%3Aparked")
        check(
            "PROVEN CAUSE-RECOVERY re-admits the machine age park: the receipt is posted FIRST, "
            "then review:parked is deleted — and the un-park is reported",
            (
                any(unpark_receipt in body for body in _comment_bodies()),
                _label_delete in unpark_writes,
                _before(unpark_writes, ("POST", "/repos/owner/repo/issues/33/comments"),
                        _label_delete),
                "age_unparked=1" in unpark_log,
            ),
            (True, True, True, True),
        )

        # ---- issue #83: A 2xx ON THE DELETE IS NOT "THE LABEL IS GONE" --------------------------
        # The receipt is public BEFORE the DELETE runs (receipt-first is what bounds the crash
        # residue), so an unverified removal reported as a removal is precisely how a PR comes to
        # say "re-admitted, back in the review loop" while still wearing the park — the
        # contradiction that held four sparq PRs for ~17h. Same recovered PR, same authorised
        # un-park; the only change is that the live label set still carries `review:parked`
        # afterwards. The phase must DEFER this PR — no "WRITE remove label" claim, no grant
        # counted — and, because it was the only candidate, the run must exit non-zero (the shared
        # precedence rule, rule 2). Delete the _label_gone check and all four of these red.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [_park_receipt_comment(1, 33)],
            "/repos/owner/repo/issues/33/labels": [
                {"name": "review:parked"}, {"name": "area:crate-a"}],
            **_bot_park_timeline(33)}
        survived_log, survived_error, survived_releases = _sweep_with_refusals(
            {}, pulls=(recovered_pr,))
        check(
            "[#83] a DELETE that returns success while the label SURVIVES defers the PR — it is "
            "never reported as a removal, and the sweep still reclaims dead leases",
            (
                "WRITE remove label" in survived_log,
                "age_unparked=0" in survived_log,
                "still live on owner/repo#33" in survived_log,
                "every age park re-admission failed (1 attempted, 0 completed)" in survived_error,
                survived_releases,
            ),
            (False, True, True, True, [{"e" * 32}]),
        )
        # CONTROL: the verification reads back THE PARK LABEL, not "are there any labels". A live
        # label set that simply does not contain `review:parked` is a completed removal, and the
        # grant stands. Without this, `_label_gone` could be any-nonempty and the check above
        # would still pass.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [_park_receipt_comment(1, 33)],
            "/repos/owner/repo/issues/33/labels": [{"name": "area:crate-a"}],
            **_bot_park_timeline(33)}
        cleared_log, cleared_error, _r = _sweep_with_refusals({}, pulls=(recovered_pr,))
        check(
            "[#83] CONTROL: a read-back WITHOUT the park label is a completed removal — the "
            "verification is scoped to the label it deleted, not to label presence in general",
            (
                "WRITE remove label" in cleared_log,
                "age_unparked=1" in cleared_log,
                cleared_error,
            ),
            (True, True, ""),
        )
        # ...and GitHub's own DELETE body — the labels that REMAIN — is authoritative when it
        # is a list, so the verification costs no extra call on the live path. Here the read-back
        # page is EMPTY (it would report success) and only the response says the label survived:
        # a verification that ignored the response would pass this and must not.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [_park_receipt_comment(1, 33)],
            **_bot_park_timeline(33)}
        terminal_sweep_env["write_responses"] = {
            _label_delete: [{"name": "review:parked"}]}
        response_log, _e, _r = _sweep_with_refusals({}, pulls=(recovered_pr,))
        check(
            "[#83] the DELETE's own post-state body is consulted: a response still listing the "
            "park label defers even when a later read-back would not",
            ("age_unparked=0" in response_log, "still live on owner/repo#33" in response_log),
            (True, True),
        )
        # The other direction of the same precedence: a response that PROVES the removal is
        # believed, and the read-back is not consulted at all. It must not be — a later read is a
        # LATER fact, so a re-park landing between the two would otherwise be misreported as this
        # sweep's DELETE having failed.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [_park_receipt_comment(1, 33)],
            "/repos/owner/repo/issues/33/labels": [{"name": "review:parked"}],
            **_bot_park_timeline(33)}
        terminal_sweep_env["write_responses"] = {_label_delete: [{"name": "area:crate-a"}]}
        believed_log, believed_error, _r = _sweep_with_refusals({}, pulls=(recovered_pr,))
        check(
            "[#83] a DELETE response that proves the removal is believed — a LATER read-back "
            "showing the label again is a re-park, not this sweep's failure",
            ("age_unparked=1" in believed_log, believed_error),
            (True, ""),
        )
        # A post-state this code cannot PARSE is not a post-state that proves anything. Skipping
        # unreadable entries would turn "I cannot tell" into "the label is gone" — the same
        # direction the whole verification closes — so a malformed body defers too.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [_park_receipt_comment(1, 33)],
            **_bot_park_timeline(33)}
        terminal_sweep_env["write_responses"] = {_label_delete: ["review:parked", {"name": 7}]}
        malformed_state_log, _e, _r = _sweep_with_refusals({}, pulls=(recovered_pr,))
        check(
            "[#83] an UNREADABLE post-state defers — a shape the verification cannot parse is "
            "never read as a completed removal",
            ("age_unparked=0" in malformed_state_log,
             "still live on owner/repo#33" in malformed_state_log),
            (True, True),
        )
        terminal_sweep_env["write_responses"] = {}

        # Consume-exactly-once: replay the SAME recovery with the un-park receipt already on
        # record. Drop the `consumed` set from age_unpark_owed and this reds — the recovery would
        # be re-earned every tick, i.e. the infinite-retry failure that is worse than a hold.
        # Consumed AND the label is GONE — the normal finished state. Nothing is written, and in
        # particular no SECOND receipt: the recovery cannot be re-earned.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [
                _park_receipt_comment(1, 33),
                _grant_comment(unpark_receipt)],
            **_bot_park_timeline(33)}
        replay_log, _e, _r = _sweep_with_refusals(
            {}, pulls=({**recovered_pr, "labels": []},))
        check(
            "a re-admission is CONSUMED EXACTLY ONCE: the same (cause, head, gen) recovery grants "
            "nothing on a later tick — no receipt, no unlabel",
            (terminal_sweep_env["writes"], "age_unparked=0" in replay_log),
            ([], True),
        )

        # The cause has NOT recovered: the park stands, and it says why. Invert
        # age_park_cause_recovered's merge branch and this reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/34/comments": [_park_receipt_comment(1, 34)],
            **_bot_park_timeline(34)}
        stands_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(34, "dirty", ("review:parked",), fresh=True),))
        check(
            "an UNRECOVERED cause is never re-admitted, and the sweep NAMES the standing park "
            "(a park with no stated reason is the state nothing can audit)",
            (
                terminal_sweep_env["writes"],
                "age park stands owner/repo#34" in stands_log,
                "the merge state is still dirty" in stands_log,
            ),
            ([], True, True),
        )

        # A GENUINE human-question park is never auto-re-admitted — it carries no machine label,
        # so the exit phase never even considers it. Drop the MACHINE_PARK_PR_LABEL membership
        # test at the top of _execute_age_unpark_actions and this reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/35/comments": [_park_receipt_comment(1, 35)]}
        human_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(35, "clean", ("needs:user",), fresh=True),))
        check(
            "a GENUINE needs:user park is NEVER auto-re-admitted, even with a recovered cause and "
            "a receipt on record (park_policy invariant 3, preserved exactly)",
            (terminal_sweep_env["writes"], "age_unparked=0" in human_log),
            ([], True),
        )

        # [#769] THE ONE RULE, on the PAIR the previous check could not reach. The check above
        # carries `needs:user` ALONE, so the MACHINE_PARK_PR_LABEL membership test refuses it and
        # human_owned_holds is never consulted — which is exactly how this went missing. The
        # defect is the PR wearing BOTH labels: it enters the phase (the machine label IS live),
        # its cause HAS recovered, and before this guard it was GRANTED — measured on the real
        # function: `grants=1`, an un-park receipt minted, `review:parked` deleted.
        #
        # No human label was cleared, so invariant 3 held literally, and that is what made it easy
        # to miss. The harm is the BUDGET: the one automatic recovery this park will ever earn was
        # spent on a PR that provably could not re-enter, because the live `needs:user` keeps
        # every downstream admission refusing. Consume-once means it can never be re-earned.
        #
        # BOTH HOLD SPELLINGS are driven, because human_owned_holds covers `review:needs-user` and
        # ANY `needs:*` and a guard scoped to one symptom does not generalise. Delete the
        # `human_owned_holds` call and BOTH of these red.
        for _hold in ("needs:user", "review:needs-user", "needs:external-audit"):
            terminal_sweep_env["pages"] = {
                "/repos/owner/repo/issues/37/comments": [_park_receipt_comment(1, 37)],
                **_bot_park_timeline(37)}
            held_log, _e, _r = _sweep_with_refusals(
                {}, pulls=(_machine_parked_pr(37, "clean", ("review:parked", _hold),
                                              fresh=True),))
            check(
                f"[#769] a PR wearing BOTH review:parked and `{_hold}` spends NO re-admission "
                "budget: no grant receipt, no unlabel, and the park is NAMED as human-held",
                (
                    terminal_sweep_env["writes"],
                    "age_unparked=0" in held_log,
                    f"human-owned hold(s) live ({_hold})" in held_log,
                ),
                ([], True, True),
            )
        # THE CONVERGENCE PATH under the same hold. The three checks above all exercise the GRANT
        # branch, so they pin the guard's POSITION only above that one: a guard moved below the
        # `granted is not None` branch would still pass them while the convergence retry deleted
        # the label off a human-held PR. Same fixture, plus the un-park receipt already on record
        # and the machine label still live — the exact crash residue the convergence branch exists
        # for — and it must refuse too.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/37/comments": [
                _park_receipt_comment(1, 37),
                _grant_comment(f"{AGE_UNPARK_MARKER} cause=merge-dirty head={37:040x} gen=1 -->",
                               at="2026-07-26T11:00:00Z")],
            **_bot_park_timeline(37)}
        held_converge_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(37, "clean", ("review:parked", "needs:user"),
                                          fresh=True),))
        held_converge_writes = list(terminal_sweep_env["writes"])
        check(
            "[#769] the CONVERGENCE retry refuses under a human-owned hold too — the guard is "
            "above BOTH write branches, not just the grant. The write assertion is now stated as "
            "the invariant itself (NO label mutation of any kind) rather than as an empty write "
            "list, because issue #83 adds ONE non-label write to this exact state — the "
            "correction comment below. Every label direction this check ever made still reds.",
            (
                [(method, path) for method, path in held_converge_writes
                 if method == "DELETE" or path.endswith("/labels")],
                "age_converged=0" in held_converge_log,
                "human-owned hold(s) live (needs:user)" in held_converge_log,
            ),
            ([], True, True),
        )
        # ---- issue #83: THAT state is the ~17h contradiction, and it must not pass in silence ----
        # This is the same fixture as the guard above, and the guard is why it is permanent: the
        # PR carries a public un-park receipt saying it re-entered the review loop, `review:parked`
        # is still live, and `needs:user` makes the convergence retry refuse FOREVER (a machine
        # never clears a human hold). Before #83 the whole tick printed one "age park stands" line
        # to a cron log and wrote nothing, so the newest thing on the PR told every reader —
        # including the human who had to act — that it had been re-admitted. Four sparq PRs
        # (#2508/#2505/#2499/#2496) sat exactly here for ~17 hours.
        #
        # Delete the stall branch and the first three of these red; the FOURTH is what keeps the
        # correction from being a label write in disguise.
        check(
            "[#83] a re-admission announced on a PR a human-owned hold still holds out is ALERTed "
            "and CORRECTED ON THE PR — the contradiction can never self-heal, so silence is the "
            "defect",
            (
                "ALERT PR owner/repo#37:" in held_converge_log,
                "record says re-admitted while its labels hold it out" in held_converge_log,
                ("POST", "/repos/owner/repo/issues/37/comments") in held_converge_writes,
                "age_unpark_stalled=1" in held_converge_log,
            ),
            (True, True, True, True),
        )
        # The correction must SAY the two things a human needs and claim nothing it cannot prove:
        # which labels are live, that the machine cannot resolve it, and that the re-admission
        # above is withdrawn. It must NOT assert the DELETE failed — the identical contradiction
        # is reached when the un-park landed and another writer re-parked the PR — and it must NOT
        # carry either receipt marker, or the next tick would read this correction as a park
        # generation or as a second grant.
        stall_body = next(iter(_comment_bodies()), "")
        check(
            "[#83] the correction states the live labels, names the human as the only exit, "
            "withdraws the announcement — and carries NEITHER receipt marker",
            (
                "review:parked" in stall_body and "needs:user" in stall_body,
                "human is the only exit" in stall_body,
                "withdrawn" in stall_body,
                AGE_UNPARK_STALL_MARKER in stall_body,
                AGE_PARK_MARKER in stall_body or AGE_UNPARK_MARKER in stall_body,
                "DELETE" in stall_body or "failed" in stall_body,
            ),
            (True, True, True, True, False, False),
        )
        # The correction is READ BACK by this same file, so its marker must be DISJOINT from both
        # receipt markers — driven through the REAL readers on the REAL rendered body, not
        # asserted about the literals. A correction that parsed as a park would climb
        # age_park_generation toward the escalation cap on its own; one that parsed as a grant
        # would consume a re-admission nothing earned.
        _stall_grant = {"cause": "merge-dirty", "head": f"{37:040x}", "gen": 1}
        _stall_only = [{"user": {"login": "app[bot]"}, "created_at": "2026-07-26T12:00:00Z",
                        "body": unpark_stall_comment(
                            "review:parked", ["needs:user"], _stall_grant)}]
        check(
            "[#83] a correction comment is NEITHER a park generation NOR a grant — and it IS its "
            "own dedupe record",
            (
                age_park_generation(_stall_only, "app[bot]"),
                age_unpark_state(_stall_only, "app[bot]"),
                unpark_stall_pending(_stall_only, "app[bot]", _stall_grant),
                unpark_stall_pending([], "app[bot]", _stall_grant),
            ),
            (1, (None, False), False, True),
        )
        # ...and a correction NO BOT authored is not a record of what this loop did: age_receipts'
        # trust filter applies here exactly as it does to the receipts, so a drive-by comment
        # carrying the marker can never suppress a correction the maintainer needs to see.
        check(
            "[#83] a correction the bot did not author does not dedupe",
            unpark_stall_pending(
                [{**_stall_only[0], "user": {"login": "drive-by"}}], "app[bot]", _stall_grant),
            True,
        )
        # ...and it is posted ONCE per grant fingerprint. A PR held for days must not collect one
        # correction per tick — that is the 37-times-relabelled spam park_policy invariant 3 was
        # written after, wearing a comment instead of a label. Replay the tick with the correction
        # already on record: the ALERT still fires (the state IS still live and the gauge must
        # still see it) and NOTHING is written.
        stall_receipt = (f"{AGE_UNPARK_STALL_MARKER} cause=merge-dirty head={37:040x} gen=1 -->")
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/37/comments": [
                _park_receipt_comment(1, 37),
                _grant_comment(f"{AGE_UNPARK_MARKER} cause=merge-dirty head={37:040x} gen=1 -->",
                               at="2026-07-26T11:00:00Z"),
                {"user": {"login": "app[bot]"}, "body": stall_receipt}],
            **_bot_park_timeline(37)}
        stall_replay_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(37, "clean", ("review:parked", "needs:user"),
                                          fresh=True),))
        check(
            "[#83] the correction is deduped on the GRANT fingerprint: replaying the tick writes "
            "NOTHING, while the gauge and the ALERT still report the live contradiction",
            (
                terminal_sweep_env["writes"],
                "age_unpark_stalled=1" in stall_replay_log,
                "ALERT PR owner/repo#37:" in stall_replay_log,
            ),
            ([], True, True),
        )
        # A stall correction on a DIFFERENT fingerprint is not this grant's correction. Without
        # the triple comparison the dedupe would key on the marker alone, and a PR that parked,
        # was re-admitted, re-parked and stalled AGAIN would be corrected once, ever.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/37/comments": [
                _park_receipt_comment(1, 37),
                _grant_comment(f"{AGE_UNPARK_MARKER} cause=merge-dirty head={37:040x} gen=1 -->",
                               at="2026-07-26T11:00:00Z"),
                {"user": {"login": "app[bot]"},
                 "body": f"{AGE_UNPARK_STALL_MARKER} cause=merge-dirty head={38:040x} gen=1 -->"}],
            **_bot_park_timeline(37)}
        stall_other_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(37, "clean", ("review:parked", "needs:user"),
                                          fresh=True),))
        check(
            "[#83] a correction for ANOTHER fingerprint does not dedupe this one",
            (
                ("POST", "/repos/owner/repo/issues/37/comments")
                in terminal_sweep_env["writes"],
                "age_unpark_stalled=1" in stall_other_log,
            ),
            (True, True),
        )
        # [#83, round-1 finding] A MATCHING GRANT IS NOT PROOF THAT THE LIVE LABEL IS ITS RESIDUE.
        # `review:parked` is a SHARED MULTI-WRITER label, so the grant must be proven STRICTLY
        # NEWER than every park application before the state is called a stall — the same conjunct
        # the convergence branch below already applies, and for the same reason. The reachable
        # shape: groom age-parks, grants, and the un-park LANDS; the account later starves and
        # worker-pr capacity-parks the PR at 12:00; a human then holds it. Every receipt still
        # matches, yet nothing is contradictory — the re-admission completed and the live label is
        # a separate later decision. Correcting there tells a human the completed re-admission is
        # "withdrawn" and invites them to remove a VALID park. Drop the `_grant_is_current`
        # conjunct from the held branch and all three of these red.
        _held_grant = _grant_comment(
            f"{AGE_UNPARK_MARKER} cause=merge-dirty head={37:040x} gen=1 -->",
            at="2026-07-26T11:00:00Z")
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/37/comments": [_park_receipt_comment(1, 37), _held_grant],
            "/repos/owner/repo/issues/37/timeline": [
                _labelled("review:parked", "2026-07-26T10:00:00Z", "app[bot]"),
                _labelled("review:parked", "2026-07-26T12:00:00Z", "app[bot]")],
        }
        later_park_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(37, "clean", ("review:parked", "needs:user"),
                                          fresh=True),))
        check(
            "[#83] a LATER shared-writer park under the SAME hold is NOT this grant's residue — "
            "no ALERT, no correction, gauge at zero, and the log says which fact is missing",
            (
                terminal_sweep_env["writes"],
                "age_unpark_stalled=0" in later_park_log,
                "ALERT PR owner/repo#37:" in later_park_log,
                "is NEWER than the un-park receipt" in later_park_log,
            ),
            ([], True, False, True),
        )
        # The same conjunct's two AMBIGUITY directions, which must fail CLOSED (silent), not open:
        # an unreadable timeline proves nothing about which park is live, and a grant with no
        # readable stamp cannot be ordered against any park at all. Relax either to "assume
        # current" and the correction fires on evidence that does not exist.
        for _label, _pages, _needle in (
            ("an UNREADABLE park timeline",
             _RaisingPages({"/repos/owner/repo/issues/37/comments": [
                 _park_receipt_comment(1, 37), _held_grant]}),
             "could not be read"),
            ("a grant with NO readable timestamp",
             {"/repos/owner/repo/issues/37/comments": [
                 _park_receipt_comment(1, 37),
                 {"user": {"login": "app[bot]"},
                  "body": f"{AGE_UNPARK_MARKER} cause=merge-dirty head={37:040x} gen=1 -->"}],
              **_bot_park_timeline(37)},
             "carries no readable timestamp"),
        ):
            terminal_sweep_env["pages"] = _pages
            ambiguous_log, _e, _r = _sweep_with_refusals(
                {}, pulls=(_machine_parked_pr(37, "clean", ("review:parked", "needs:user"),
                                              fresh=True),))
            check(
                f"[#83] {_label} cannot prove the live park is this grant's residue — the "
                "correction fails CLOSED: no ALERT, no comment, gauge at zero",
                (
                    terminal_sweep_env["writes"],
                    "age_unpark_stalled=0" in ambiguous_log,
                    "ALERT PR owner/repo#37:" in ambiguous_log,
                    _needle in ambiguous_log,
                ),
                ([], True, False, True),
            )

        # CONTROL, the direction that keeps every check above from passing on a stall branch that
        # fires unconditionally: the SAME hold with NO grant on record is an ordinary human-held
        # park. It must stay silent — no ALERT, no comment, gauge at zero. (The `_hold` loop above
        # asserts the empty write list for this fixture; this pins the new signals to it.)
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/37/comments": [_park_receipt_comment(1, 37)],
            **_bot_park_timeline(37)}
        no_grant_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(37, "clean", ("review:parked", "needs:user"),
                                          fresh=True),))
        check(
            "[#83] CONTROL: a human-held park with NO re-admission on record contradicts nothing "
            "— no ALERT, no correction, gauge at zero",
            (
                terminal_sweep_env["writes"],
                "age_unpark_stalled=0" in no_grant_log,
                "ALERT PR owner/repo#37:" in no_grant_log,
            ),
            ([], True, False),
        )
        # ... and the SAME convergence fixture WITHOUT the hold does converge, so the check above
        # cannot pass merely because convergence stopped working.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/37/comments": [
                _park_receipt_comment(1, 37),
                _grant_comment(f"{AGE_UNPARK_MARKER} cause=merge-dirty head={37:040x} gen=1 -->",
                               at="2026-07-26T11:00:00Z")],
            **_bot_park_timeline(37)}
        unheld_converge_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(37, "clean", ("review:parked",), fresh=True),))
        check(
            "[#769] CONTROL: the identical convergence WITHOUT the hold still completes the "
            "interrupted unlabel",
            (
                ("DELETE", "/repos/owner/repo/issues/37/labels/review%3Aparked")
                in terminal_sweep_env["writes"],
                "age_converged=1" in unheld_converge_log,
            ),
            (True, True),
        )

        # THE OTHER DIRECTION, on the SAME fixture minus the hold — otherwise the three checks
        # above would pass just as well if the exit had stopped granting anything at all. This is
        # the same PR, same recovered cause, same receipts: it MUST still be re-admitted.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/37/comments": [_park_receipt_comment(1, 37)],
            **_bot_park_timeline(37)}
        unheld_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(37, "clean", ("review:parked",), fresh=True),))
        check(
            "[#769] CONTROL: the identical PR WITHOUT the hold is still re-admitted — the hold "
            "guard refuses the held case only, it does not disable the exit",
            (
                ("DELETE", "/repos/owner/repo/issues/37/labels/review%3Aparked")
                in terminal_sweep_env["writes"],
                "age_unparked=1" in unheld_log,
            ),
            (True, True),
        )

        # [#769] park_policy INVARIANT 3, pinned STRUCTURALLY rather than by scenario. The
        # behavioural checks above can only speak about the label paths their fixtures reach; the
        # claim that has to hold is about EVERY path — "this phase's only label DELETE is on
        # MACHINE_PARK_PR_LABEL, and no path here auto-clears a human hold". The incident behind
        # that invariant is a label re-applied 37 times, and the live control is sparq-org/sparq
        # #3728, a conflict-resolver escalation carrying `needs:user`: nothing in this phase may
        # ever reach it. Parsed, never regexed — a source regex passes permissively under a
        # reflow, and the failure mode of a permissive guard here is silent.
        _unpark_fn = next(
            node for node in ast.walk(ast.parse(
                Path(__file__).resolve().read_text(encoding="utf-8")))
            if isinstance(node, ast.FunctionDef) and node.name == "_execute_age_unpark_actions")
        _unpark_deletes = [
            ast.unparse(node) for node in ast.walk(_unpark_fn)
            if isinstance(node, ast.Call)
            and any(isinstance(arg, ast.Constant) and arg.value == "DELETE"
                    for arg in node.args)]
        check(
            "[#769] the age exit issues EXACTLY ONE label DELETE and it is on "
            "MACHINE_PARK_PR_LABEL — invariant 3: no path here auto-clears a human hold "
            "(#3728, a conflict-resolver needs:user escalation, is the live control)",
            (
                len(_unpark_deletes),
                all("park_policy.MACHINE_PARK_PR_LABEL" in call for call in _unpark_deletes),
                any(name in call for call in _unpark_deletes
                    for name in ("HUMAN_PARK_LABEL", "HUMAN_PR_PARK_LABEL", "needs:user",
                                 "needs-user")),
            ),
            (1, True, False),
        )

        # A machine label a PROVEN HUMAN applied is likewise never auto-cleared: the actor decides,
        # not the label. Remove the park_applications human_park check and this reds.
        # TWO events, bot FIRST and the human LATER, so "the latest application was human" is
        # genuinely the deciding fact. The previous single-event fixture proved nothing: with only
        # a human event, absence-of-a-bot-event would have refused it anyway, so the branch this
        # names was never exercised. Delete the human event and the sweep DOES clear the label.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/36/comments": [_park_receipt_comment(1, 36)],
            "/repos/owner/repo/issues/36/timeline": [
                _labelled("review:parked", "2026-07-26T10:00:00Z", "app[bot]"),
                _labelled("review:parked", "2026-07-26T12:00:00Z", "jeswr")],
        }
        human_applied_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(36, "clean", ("review:parked",), fresh=True),),
            extra_gets={"/repos/owner/repo/collaborators/jeswr/permission":
                        {"permission": "admin"}},
        )
        check(
            "a machine park whose LATEST application is a PROVEN HUMAN is never auto-cleared, "
            "even though an EARLIER bot application exists",
            (
                terminal_sweep_env["writes"],
                "not provably machine-applied" in human_applied_log,
            ),
            ([], True),
        )

        # ---- #690 direction 1: authorising a DELETE of one label with evidence about THREE ----
        # A human applied `review:parked`; a bot later applied `needs:user`. park_applications
        # reads the newest `labeled` event across READMISSION_LABELS, so it reports "latest park
        # was a machine" and the human's label is deleted. label_application_machine_owned reads
        # ONLY `review:parked` events and refuses. Swap the call back and this reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/38/comments": [_park_receipt_comment(1, 38)],
            "/repos/owner/repo/issues/38/timeline": [
                _labelled("review:parked", "2026-07-26T10:00:00Z", "jeswr"),
                _labelled("needs:user", "2026-07-26T12:00:00Z", "app[bot]")],
        }
        cross_label_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(38, "clean", ("review:parked",), fresh=True),),
            extra_gets={"/repos/owner/repo/collaborators/jeswr/permission":
                        {"permission": "admin"}},
        )
        check(
            "#690 direction 1: a HUMAN-applied review:parked is NOT clearable because a LATER "
            "bot event exists on a DIFFERENT park label — ownership is proven per-label",
            (terminal_sweep_env["writes"], "not provably machine-applied" in cross_label_log),
            ([], True),
        )

        # ---- #690 direction 3: absence of evidence is not permission ---------------------------
        # A live `review:parked` with NO `labeled` event at all (timeline truncated, label applied
        # before the window, or applied by an import). Nothing proves a machine applied it.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/39/comments": [_park_receipt_comment(1, 39)]}
        no_event_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(39, "clean", ("review:parked",), fresh=True),))
        check(
            "#690 direction 3: a live review:parked with NO `labeled` event is NOT clearable — "
            "absence of evidence is not proof of machine ownership",
            (terminal_sweep_env["writes"], "not provably machine-applied" in no_event_log),
            ([], True),
        )

        # ---- the UNREADABLE timeline, which previously had no red test at all ------------------
        # The PR body claims "unreadable timeline -> stay parked"; before this check that claim was
        # unsupported (deleting the branch left the suite green). A raising timeline read must
        # refuse, and must NOT be swallowed into a re-admission.
        terminal_sweep_env["pages"] = _RaisingPages(
            {"/repos/owner/repo/issues/40/comments": [_park_receipt_comment(1, 40)]})
        unreadable_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(40, "clean", ("review:parked",), fresh=True),))
        check(
            "an UNREADABLE park timeline keeps the park (the claim the body makes, now with a "
            "test that reds when the refusal is removed)",
            (terminal_sweep_env["writes"], "not provably machine-applied" in unreadable_log),
            ([], True),
        )
        terminal_sweep_env["pages"] = {}

        # ---- CONVERGENCE: receipt landed, unlabel did not (registry #614 `auto-receipt`) -------
        # Reached by ONE HTTP transient on the DELETE. Without this branch the PR keeps
        # `review:parked` forever: its cause has recovered so the hand-off derives no reason and
        # never re-parks it, and nothing else clears it — the INVISIBLE permanent hold. Delete the
        # `if consumed:` block and this reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [
                _park_receipt_comment(1, 33),
                _grant_comment(unpark_receipt)],
            **_bot_park_timeline(33)}
        converge_log, _e, _r = _sweep_with_refusals({}, pulls=(recovered_pr,))
        check(
            "CONVERGENCE: a consumed receipt with the label STILL LIVE completes the interrupted "
            "unlabel — no second receipt, no new evidence, the generation untouched",
            (
                _label_delete in terminal_sweep_env["writes"],
                _comment_bodies(),
                "CONVERGE PR owner/repo#33" in converge_log,
                # A convergence is a RETRY of an already-authorised write, not a new grant. The
                # two are counted apart so neither can be read as the other — the reviewer's
                # probe C ("5 replays = 5 unparks against a cap of 2") is answered by this line:
                # grants stay at 0 however many times the tick replays.
                ("age_unparked=0" in converge_log, "age_converged=1" in converge_log),
            ),
            (True, [], True, (True, True)),
        )

        # ---- B: a DIFFERENT writer's LATER park must NOT be deleted off a stale grant ----------
        # `review:parked` is written by dispatch-claim (x2) and worker-pr's capacity park as well
        # as by this sweep, so its presence never proves THIS sweep parked the PR. Live shape:
        # age-park -> recover -> unpark -> the account starves -> worker-pr capacity-parks -> every
        # groom tick deletes it. Drop the recency conjunct and this reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [
                _park_receipt_comment(1, 33), _grant_comment(unpark_receipt)],
            "/repos/owner/repo/issues/33/timeline": [
                _labelled("review:parked", "2026-07-26T10:00:00Z", "app[bot]"),
                _labelled("review:parked", "2026-07-26T12:00:00Z", "app[bot]")],
        }
        newer_park_log, _e, _r = _sweep_with_refusals({}, pulls=(recovered_pr,))
        check(
            "a LATER park application refuses convergence — a shared multi-writer label being "
            "present never proves THIS sweep's un-park failed to land",
            (
                terminal_sweep_env["writes"],
                "is NEWER than the un-park receipt" in newer_park_log,
                "age_converged=0" in newer_park_log,
            ),
            ([], True, True),
        )

        # C/D: convergence can never span two parks, so it cannot escape the cap it sits outside
        # of. Replaying the SAME tick grants nothing new each time, and the moment anything
        # re-parks the PR the check above refuses — which is the structural bound, not a counter.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [
                _park_receipt_comment(1, 33), _grant_comment(unpark_receipt)],
            **_bot_park_timeline(33)}
        replay_grants = []
        for _tick in range(3):
            tick_log, _e, _r = _sweep_with_refusals({}, pulls=(recovered_pr,))
            replay_grants.append(("age_unparked=0" in tick_log,
                                  _comment_bodies() == []))
        check(
            "replaying the same tick mints NO new grant and NO second receipt, however many times "
            "it runs — the cap governs grants, and convergence can never become one",
            replay_grants,
            [(True, True)] * 3,
        )

        # A TIE is not "newer". park_policy resolves every instant tie conservatively (its own
        # comment: "an instant tie resolves toward HUMAN-owned"), and capacity_park_admission's
        # recency test is STRICT. Relax `<=` to `<` and a park applied in the same second as the
        # grant is treated as older, re-opening exactly the multi-writer hole above.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [
                _park_receipt_comment(1, 33),
                _grant_comment(unpark_receipt, at="2026-07-26T10:00:00Z")],
            **_bot_park_timeline(33)}
        tie_log, _e, _r = _sweep_with_refusals({}, pulls=(recovered_pr,))
        check(
            "an instant TIE between the grant and a park application refuses convergence — the "
            "comparison is STRICTLY newer, as park_policy's is",
            (terminal_sweep_env["writes"],
             "is NEWER than the un-park receipt" in tie_log),
            ([], True),
        )

        # A malformed grant stamp must DEFER this PR, not abort the sweep: park_policy's timestamp
        # primitives raise ValueError, which the per-PR handler must absorb like any other failure.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [
                _park_receipt_comment(1, 33),
                _grant_comment(unpark_receipt, at="not-a-timestamp")],
            **_bot_park_timeline(33)}
        malformed_log, malformed_error, malformed_releases = _sweep_with_refusals(
            {}, pulls=(recovered_pr,))
        check(
            "a MALFORMED grant stamp refuses convergence and never aborts the sweep — dead-lease "
            "reclaim still runs (narrow the per-PR except to GroomError and this reds)",
            (
                terminal_sweep_env["writes"],
                "carries no readable timestamp" in malformed_log,
                malformed_releases,
            ),
            ([], True, [{"e" * 32}]),
        )

        # EVERY failure class defers ITSELF. The guard above closes the one ValueError path that
        # exists today, so this drives a NON-GroomError out of the per-PR body directly: narrow the
        # handler back to `except GroomError` and this unhandled exception aborts run_sweep before
        # _release_claims — #644/#647's head-of-line abort, from one PR.
        class _ValueErrorPages(dict):
            def get(self, key, default=None):
                if key == "/repos/owner/repo/issues/33/comments":
                    raise ValueError("comment page is a shape park_policy rejects")
                return super().get(key, default)

        terminal_sweep_env["pages"] = _ValueErrorPages(_bot_park_timeline(33))
        ve_log, ve_error, ve_releases = _sweep_with_refusals({}, pulls=(recovered_pr,))
        check(
            "a NON-GroomError from one PR defers THAT PR and never aborts the sweep — dead-lease "
            "reclaim still runs and the phase reports the deferral",
            (
                ve_releases,
                "age un-park deferred" in ve_log,
                "age_unpark_deferred=1" in ve_log,
                "every age park re-admission failed (1 attempted, 0 completed)" in ve_error,
            ),
            ([{"e" * 32}], True, True, True),
        )
        terminal_sweep_env["pages"] = {}

        # A grant with no readable timestamp cannot be proven newer than the park, so it refuses.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [
                _park_receipt_comment(1, 33),
                {"user": {"login": "app[bot]"}, "body": unpark_receipt}],
            **_bot_park_timeline(33)}
        no_stamp_log, _e, _r = _sweep_with_refusals({}, pulls=(recovered_pr,))
        check(
            "an un-park grant with NO readable timestamp refuses convergence (it cannot be proven "
            "current)",
            (terminal_sweep_env["writes"],
             "carries no readable timestamp" in no_stamp_log),
            ([], True),
        )

        # Convergence is NOT a licence to clear a human's label: a human who re-applied
        # `review:parked` AFTER our receipt owns it. Remove the _clearable() gate from the
        # convergence branch and this reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/33/comments": [
                _park_receipt_comment(1, 33),
                _grant_comment(unpark_receipt)],
            # The human application lands BEFORE the grant, so the recency conjunct PASSES and the
            # ownership proof is the only thing that can refuse — isolating _clearable() inside the
            # convergence branch rather than letting recency mask it.
            "/repos/owner/repo/issues/33/timeline": [
                _labelled("review:parked", "2026-07-26T09:00:00Z", "app[bot]"),
                _labelled("review:parked", "2026-07-26T10:30:00Z", "jeswr")],
        }
        converge_human_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(recovered_pr,),
            extra_gets={"/repos/owner/repo/collaborators/jeswr/permission":
                        {"permission": "admin"}},
        )
        check(
            "CONVERGENCE still refuses a human-owned label: a human who re-applied review:parked "
            "after the receipt owns it",
            (terminal_sweep_env["writes"],
             "not provably machine-applied" in converge_human_log),
            ([], True),
        )

        # ---- the OVER-CAP gate, which previously survived deletion ------------------------------
        # A gen-3 park receipt is over AGE_UNPARK_MAX, so age_park_label wrote the HUMAN class and
        # the exit phase must not consider it AT ALL — even with a recovered cause, a live machine
        # label and a clean bot-applied timeline. Delete the `gen > AGE_UNPARK_MAX` branch from
        # age_unpark_state and this reds.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/42/comments": [_park_receipt_comment(3, 42)],
            **_bot_park_timeline(42)}
        over_cap_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_machine_parked_pr(42, "clean", ("review:parked",), fresh=True),))
        check(
            "the OVER-CAP gate holds at the exit too: a gen-3 park is never automatically "
            "re-admitted, however clean everything else looks",
            (terminal_sweep_env["writes"], "age_unparked=0" in over_cap_log),
            ([], True),
        )
        terminal_sweep_env["pages"] = {}

        # (A4) THE STICKY VETO FOLLOWS THE LABEL BEING WRITTEN. A human who removed `review:parked`
        # more recently than any application has explicitly unparked THIS PR, and the machine must
        # not re-apply it. Hard-code the veto's label argument back to "needs:user" — a six-character
        # change that leaves the park class, the receipt and every other check above intact — and
        # the veto silently queries a label with no history, so the suppressed park is written
        # anyway. That is the mutant this check exists for.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/31/timeline": [
                {"event": "labeled", "label": {"name": "review:parked"},
                 "created_at": "2026-07-26T10:00:00Z", "actor": {"login": "app[bot]"}},
                {"event": "unlabeled", "label": {"name": "review:parked"},
                 "created_at": "2026-07-26T11:00:00Z", "actor": {"login": "jeswr"}}],
        }
        veto_log, _e, _r = _sweep_with_refusals(
            {}, pulls=(_stale_worker_pr(31),),
            extra_gets={"/repos/owner/repo/collaborators/jeswr/permission":
                        {"permission": "admin"}},
        )
        check(
            "the sticky human unpark is checked against the label ACTUALLY BEING WRITTEN: a human "
            "who removed review:parked vetoes the MACHINE age park (not just needs:user)",
            (
                _park_bodies(),
                "review:parked park suppressed" in veto_log,
                _comment_bodies(),
            ),
            ([], True, []),
        )
        terminal_sweep_env["pages"] = {}

        # (A5) A SECOND generation must be able to mint. The machine class dedupes on its own
        # receipt fingerprint; revert it to the once-ever STALE_PR_MARKER dedupe and generation 2
        # is never recorded — so the cap in (A3c) can never be reached and the escalation to the
        # human class becomes unreachable. The prior tick's receipt already carries
        # STALE_PR_MARKER, so only the fingerprint dedupe distinguishes the two.
        #
        # [#1292] The fixture now carries the GRANT that makes this a re-park after a genuine
        # re-admission — which is what the check has always been named for. Its old fixture had a
        # park receipt and no grant at all, so it asserted that a generation advances on a
        # re-admission that never happened: the defect, pinned as the requirement.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/31/comments": [
                _park_receipt_comment(1), _grant_receipt_comment(1)]}
        gen2_log, _e, _r = _sweep_with_refusals({}, pulls=(_stale_worker_pr(31),))
        check(
            "a RE-park after a re-admission mints a NEW generation receipt — without it the cap "
            "is unreachable and nothing ever escalates",
            (
                any(f"{AGE_PARK_MARKER} cause=merge-dirty head={31:040x} gen=2 -->" in body
                    for body in _comment_bodies()),
                _park_bodies(),
            ),
            (True, [{"labels": ["review:parked"]}]),
        )
        terminal_sweep_env["pages"] = {}

        # (A6) The exit phase is judged by the SHARED precedence rule, like every other phase.
        # Its ONLY candidate's receipt write is refused: nothing completed, so the run must exit
        # NON-ZERO naming the deferral. Drop unpark_outcome from the sweep_exit_failure tuple and
        # a whole re-admission phase can fail in total while the run reports success — the
        # exit-zero-swallows-failure shape this module already carries three scars from.
        terminal_sweep_env["pages"] = {
            "/repos/owner/repo/issues/37/comments": [_park_receipt_comment(1, 37)],
            **_bot_park_timeline(37)}
        unpark_fail_log, unpark_fail_error, _r = _sweep_with_refusals(
            {("POST", "/repos/owner/repo/issues/37/comments"): _live_http_failure(
                "POST", "/repos/owner/repo/issues/37/comments", forbidden_envelope)},
            pulls=(_machine_parked_pr(37, "clean", ("review:parked",), fresh=True),),
        )
        check(
            "a re-admission phase in which NOTHING completed exits NON-ZERO naming the deferral "
            "(the phase is enrolled in the shared exit precedence, not exempt from it)",
            (
                "every age park re-admission failed (1 attempted, 0 completed)"
                in unpark_fail_error,
                "owner/repo#37" in unpark_fail_error,
                "age_unpark_deferred=1" in unpark_fail_log,
                "age_unparked=0" in unpark_fail_log,
            ),
            (True, True, True, True),
        )
        terminal_sweep_env["pages"] = {}

        # An UNKNOWN cause token can never be proven recovered, so it never re-admits. This is the
        # quantifier direction that matters: "some causes recover" must not become "re-admit unless
        # we can show it did not".
        check(
            "an UNRECOGNISED cause token is NEVER re-admitted (no predicate ⇒ no proof ⇒ parked)",
            age_park_cause_recovered("teleported", {"mergeable_state": "clean"},
                                     lambda: ("admits", {}))[0],
            False,
        )
        check(
            "an INDETERMINATE live provenance read keeps the orphan-draft park (never re-admit on "
            "an unusable read)",
            (age_park_cause_recovered("orphan-draft", {}, lambda: ("indeterminate", None))[0],
             age_park_cause_recovered("orphan-draft", {}, lambda: ("denies", None))[0],
             age_park_cause_recovered("orphan-draft", {}, lambda: ("admits", {}))[0]),
            (False, False, True),
        )
        check(
            "a MALFORMED live merge state keeps the park (fail-closed, never a re-admission)",
            age_park_cause_recovered("merge-blocked", {"mergeable_state": 7},
                                     lambda: ("denies", None))[0],
            False,
        )
        # A malformed receipt still CONSUMES a generation — otherwise a corrupt comment buys an
        # extra automatic re-admission (park_policy's auto_marker_count rule). [#1292] The
        # generation counts GRANTS, so it is the malformed GRANT that must still be counted; and
        # the same malformed body on a PARK receipt must NOT advance it, or a corrupt park comment
        # would spend a re-admission the machine never made.
        check(
            "a MALFORMED un-park GRANT still consumes a re-admission (it cannot buy an extra "
            "one) — and a malformed PARK receipt still buys nothing",
            (
                age_park_generation(
                    [{"user": {"login": "app[bot]"}, "body": f"{AGE_UNPARK_MARKER} garbage -->"}],
                    "app[bot]"),
                age_park_generation(
                    [{"user": {"login": "app[bot]"}, "body": f"{AGE_PARK_MARKER} garbage -->"}],
                    "app[bot]"),
            ),
            (2, 1),
        )
        check(
            "a receipt authored by anyone but the bot proves nothing",
            age_receipts(
                [{"user": {"login": "mallory"},
                  "body": f"{AGE_PARK_MARKER} cause=merge-dirty head={'a' * 40} gen=1 -->"}],
                AGE_PARK_MARKER, "app[bot]"),
            [],
        )
        check(
            "every reason stale_worker_pr_reason can return is CLASSIFIED — a new bad merge state "
            "cannot silently fall through to the human terminal",
            sorted({age_park_cause(reason) for reason in
                    [ORPHAN_DRAFT_REASON, *BAD_MERGE_STATES.values()]} - {None}),
            sorted({"orphan-draft", *(f"merge-{state}" for state in BAD_MERGE_STATES)}),
        )

        # (2) ISSUE-REPAIR LOOP, head-of-line refusal. Same shape: the lower-numbered issue's
        # _apply_labels write is refused, the later issue must still be repaired, reclaim must still
        # run. This loop sits BEFORE the defuse phase and the hand-off loop, so its abort took out
        # strictly more of the sweep than #644's did.
        repair_log, repair_error, repair_releases = _sweep_with_refusals(
            {("POST", "/repos/owner/repo/issues/41/labels"): _live_http_failure(
                "POST", "/repos/owner/repo/issues/41/labels", forbidden_envelope)},
            issues=(_repairable_issue(41), _repairable_issue(42)),
        )
        repair_writes = terminal_sweep_env["writes"]
        check(
            "MUTATION #647 (issue repair): dead-lease reclaim STILL RUNS when the LOWEST-numbered "
            "issue's label write is refused (remove the loop's per-issue try/except and run_sweep "
            "raises before _release_claims, releasing NOTHING)",
            repair_releases,
            [{"e" * 32}],
        )
        check(
            "#647 (issue repair): the refused issue does NOT block the later one — #42 is still "
            "re-readied (status:ready added, status:in-progress removed) while #41's transition "
            "stops at its refusal",
            (
                ("POST", "/repos/owner/repo/issues/42/labels") in repair_writes,
                ("DELETE", "/repos/owner/repo/issues/42/labels/status%3Ain-progress")
                in repair_writes,
                ("DELETE", "/repos/owner/repo/issues/41/labels/status%3Ain-progress")
                in repair_writes,
            ),
            (True, True, False),
        )
        check(
            "#647 (issue repair): the refusal's CAUSE reaches the deferral, credential-masked and "
            "naming the issue",
            (
                "ALERT issue owner/repo#41:" in repair_log,
                "status repair deferred" in repair_log,
                "Resource not accessible by integration" in repair_log,
            ),
            (True, True, True),
        )
        check(
            "#647 precedence rule 3 (issue repair): ONE refused issue alongside a repaired one "
            "leaves the run GREEN, and the SUMMARY counts both the repair and the deferral",
            (
                repair_error,
                "SUMMARY reclaimed=1" in repair_log,
                "reset=1" in repair_log,
                "repair_deferred=1" in repair_log,
            ),
            ("", True, True, True),
        )
        repair_all_log, repair_all_error, repair_all_releases = _sweep_with_refusals(
            {
                ("POST", f"/repos/owner/repo/issues/{number}/labels"): _live_http_failure(
                    "POST", f"/repos/owner/repo/issues/{number}/labels", forbidden_envelope)
                for number in (41, 42)
            },
            issues=(_repairable_issue(41), _repairable_issue(42)),
        )
        check(
            "#647 precedence rule 2 (issue repair): EVERY issue refused is systemic — the run exits "
            "NON-zero naming both deferrals — while reclaim STILL ran first",
            (
                repair_all_releases,
                "every issue status repair failed (2 attempted, 0 completed)" in repair_all_error,
                "owner/repo#41" in repair_all_error and "owner/repo#42" in repair_all_error,
                "SUMMARY reclaimed=1" in repair_all_log,
                "repair_deferred=2" in repair_all_log,
            ),
            ([{"e" * 32}], True, True, True, True),
        )
        # (3) A phase that SKIPPED every object it TOOK UP is a working phase, not a failed one: the
        # sole hand-off candidate is revalidated away inside the loop (it closed after planning),
        # nothing is deferred, and the run must stay GREEN. This is the direction that keeps rule 2
        # honest without red-flagging every quiet sweep — counting the skip as an incomplete attempt
        # instead reds this check.
        skip_log, skip_error, skip_releases = _sweep_with_refusals(
            {},
            pulls=(_stale_worker_pr(31),),
            details=({**_stale_worker_pr(31), "state": "closed"},),
        )
        # (4) THIRD INSTANCE, found while closing the other two: the per-PR DETAIL read in the
        # pre-planning loop. Refusing the lowest-numbered PR's detail GET used to abort the sweep
        # before EVERYTHING — the defuse phase, both mutation loops and reclaim. The later PR must
        # still be detected and handed off, and reclaim must still run.
        detect_log, detect_error, detect_releases = _sweep_with_refusals(
            {("GET", "/repos/owner/repo/pulls/31"): _live_http_failure(
                "GET", "/repos/owner/repo/pulls/31", forbidden_envelope, code=451)},
            pulls=(_stale_worker_pr(31), _stale_worker_pr(32)),
        )
        detect_writes = terminal_sweep_env["writes"]
        check(
            "MUTATION #647 (third instance — stale-PR detection): an unreadable PR DETAIL defers "
            "only that PR; reclaim still runs and the later PR is still handed off (remove the "
            "per-PR try/except in the pre-planning loop and run_sweep raises before every "
            "subsequent phase, releasing NOTHING)",
            (
                detect_releases,
                ("POST", "/repos/owner/repo/issues/32/labels") in detect_writes,
                ("POST", "/repos/owner/repo/issues/32/comments") in detect_writes,
            ),
            ([{"e" * 32}], True, True),
        )
        check(
            "#647 (stale-PR detection): the deferral names the PR and carries the refusal's cause, "
            "and rule 3 leaves the run green because another PR was detected",
            (
                "ALERT PR owner/repo#31:" in detect_log,
                "stale PR detection deferred" in detect_log,
                "Resource not accessible by integration" in detect_log,
                detect_error,
                "detect_deferred=1" in detect_log,
            ),
            (True, True, True, "", True),
        )
        detect_all_log, detect_all_error, detect_all_releases = _sweep_with_refusals(
            {
                ("GET", f"/repos/owner/repo/pulls/{number}"): _live_http_failure(
                    "GET", f"/repos/owner/repo/pulls/{number}", forbidden_envelope, code=451)
                for number in (31, 32)
            },
            pulls=(_stale_worker_pr(31), _stale_worker_pr(32)),
        )
        check(
            "#647 precedence rule 2 (stale-PR detection): EVERY detail read refused is systemic — "
            "non-zero naming both deferrals — while reclaim STILL ran first",
            (
                detect_all_releases,
                "every stale PR detection failed (2 attempted, 0 completed)" in detect_all_error,
                "owner/repo#31" in detect_all_error and "owner/repo#32" in detect_all_error,
                "detect_deferred=2" in detect_all_log,
            ),
            ([{"e" * 32}], True, True, True),
        )

        check(
            "#647: a hand-off candidate revalidated AWAY inside the loop is a COMPLETED decision, "
            "not a failure — the run stays green, and reclaim still runs",
            (
                skip_error,
                skip_releases,
                "SKIP PR owner/repo#31: no longer open" in skip_log,
                "stale_prs=0 " in skip_log and "stale_pr_deferred=0" in skip_log,
            ),
            ("", [{"e" * 32}], True, True),
        )

        # ---- issue #649: the THREE residual head-of-line aborts, END TO END --------------------
        # #648 closed every loop whose fix was #644's mechanical record-and-continue. These three
        # were deliberately left loud because that same change would have been UNSOUND in each, so
        # each is driven through the real run_sweep with the refusal in the head-of-line position
        # and each is checked in BOTH precedence directions — plus, in every case, that the fail
        # direction chosen is the one that cannot mutate or release on a read that never returned.
        def _refused_listing(path: str) -> GroomError:
            return _live_http_failure("GET", path, forbidden_envelope)

        def _commented_issue(number: int) -> dict[str, Any]:
            """A repairable issue with enough comments that the #1303 filter DEMANDS a fetch."""
            return {**_repairable_issue(number), "comments": limits.max_attempts}

        # (1) THE ATTEMPT-BUDGET READ. The refused issue must vanish from PLANNING — not be planned
        # from a defaulted 0, which `_plan_actions`' own fixture above proves would re-ready an
        # exhausted issue. The later issue must still be repaired, and reclaim must still run.
        budget_log, budget_error, budget_releases = _sweep_with_refusals(
            {},
            issues=(_commented_issue(41), _commented_issue(42)),
            paginate_refusals={
                "/repos/owner/repo/issues/41/comments":
                    _refused_listing("/repos/owner/repo/issues/41/comments")},
        )
        budget_writes = terminal_sweep_env["writes"]
        check(
            "MUTATION #649 (1 — attempt-budget read): an unreadable comments listing defers ONLY "
            "that issue; #42 is still re-readied and reclaim still runs (drop the try/except and "
            "run_sweep raises before every later phase, releasing NOTHING)",
            (
                budget_releases,
                ("POST", "/repos/owner/repo/issues/42/labels") in budget_writes,
                ("POST", "/repos/owner/repo/issues/41/labels") in budget_writes,
            ),
            ([{"e" * 32}], True, False),
        )
        check(
            "#649 (1): the refused issue is EXCLUDED FROM PLANNING (never planned from a "
            "defaulted 0), the deferral carries the refusal's cause, and rule 3 leaves the run "
            "green because another issue's budget was read",
            (
                "ALERT issue owner/repo#41:" in budget_log,
                "attempt-budget read deferred" in budget_log,
                "Resource not accessible by integration" in budget_log,
                "SKIP issue owner/repo#41: attempt budget unreadable" in budget_log,
                budget_error,
                "attempt_budget_deferred=1" in budget_log,
                # ...and the exclusion is REAL, not just logged: #41 never becomes an action, so
                # the repair phase takes up exactly one issue and defers none. A defaulted 0 plans
                # #41 as a READY, the phase then attempts it and its own boundary read defers it,
                # and this counter moves — the accounting, not a string, is what discriminates.
                "reset=1 " in budget_log and "repair_deferred=0" in budget_log,
            ),
            (True, True, True, True, "", True, True),
        )
        budget_all_log, budget_all_error, budget_all_releases = _sweep_with_refusals(
            {},
            issues=(_commented_issue(41), _commented_issue(42)),
            paginate_refusals={
                f"/repos/owner/repo/issues/{number}/comments":
                    _refused_listing(f"/repos/owner/repo/issues/{number}/comments")
                for number in (41, 42)},
        )
        check(
            "#649 (1) precedence rule 2: EVERY attempt-budget read refused is systemic — non-zero "
            "naming both deferrals — while reclaim STILL ran first",
            (
                budget_all_releases,
                "every attempt-budget read failed (2 attempted, 0 completed)" in budget_all_error,
                "owner/repo#41" in budget_all_error and "owner/repo#42" in budget_all_error,
                "attempt_budget_deferred=2" in budget_all_log,
            ),
            ([{"e" * 32}], True, True, True),
        )

        # (2) THE PER-REPO SNAPSHOT. Two targets, ONE of them unreadable. The unreadable repo must
        # contribute NO release — its leases cannot be proven terminal, orphaned, or safely
        # dead-reaped from a listing that never returned — while the OTHER repo reclaims normally.
        # That is the head-of-line property, and one repo alone cannot witness it.
        other_lease = {
            **base, "claim_id": "f" * 32, "holder": "owner/other#8@778.1",
            "issued_at": 1, "expires_at": 2,
        }
        repo_lease = {
            **base, "claim_id": "e" * 32, "holder": "owner/repo#7@777.1",
            "issued_at": 1, "expires_at": 2,
        }
        snapshot_log, snapshot_error, snapshot_releases = _sweep_with_refusals(
            {},
            repos=("owner/repo", "owner/other"),
            leases=(repo_lease, other_lease),
            paginate_refusals={
                "/repos/owner/repo/issues?state=open":
                    _refused_listing("/repos/owner/repo/issues?state=open")},
        )
        check(
            "MUTATION #649 (2 — per-repo snapshot): the unreadable repo's lease is RETAINED while "
            "the readable repo's is reclaimed in the SAME tick. Recording an EMPTY snapshot "
            "instead releases owner/repo#7 as an 'orphan' it never read; dropping the try "
            "altogether releases NOTHING at all. Both mutations red this.",
            (
                snapshot_releases,
                "ALERT repo owner/repo:" in snapshot_log,
                "SKIP lease release claim=eeeeeeee: owner/repo's target snapshot was unreadable"
                in snapshot_log,
                snapshot_error,
                "snapshot_deferred=1" in snapshot_log,
            ),
            ([{"f" * 32}], True, True, "", True),
        )
        snap_all_log, snap_all_error, snap_all_releases = _sweep_with_refusals(
            {},
            paginate_refusals={
                "/repos/owner/repo/pulls?state=open":
                    _refused_listing("/repos/owner/repo/pulls?state=open")},
        )
        check(
            "#649 (2) precedence rule 2: the ONLY target's snapshot failing is systemic — non-zero "
            "naming the repo — and the PR half failing drops the repo as a UNIT, so no half-read "
            "target view reaches planning (reclaim still ran, releasing nothing it could not prove)",
            (
                snap_all_releases,
                "every target repo snapshot failed (1 attempted, 0 completed)" in snap_all_error,
                "owner/repo" in snap_all_error,
                "snapshot_deferred=1" in snap_all_log,
            ),
            ([set()], True, True, True),
        )

        # (3) THE TERMINAL-REAP RE-READ (#509's mutation boundary). Here record-and-continue fails
        # OPEN — an unread issue stays ABSENT from `fresh_reap_issues`, which `_terminal_non_pr_claims`
        # reads as ORPHANED, confirming the release on a read that never returned. So the safe
        # degradation is the opposite of `continue`: withdraw the claim and RETAIN the lease.
        reap_lease_8 = {
            **base, "claim_id": "d" * 32, "holder": "owner/repo#8@778.1",
            "issued_at": 1, "expires_at": 2,
        }
        reap_log, reap_error, reap_releases = _sweep_with_refusals(
            {("GET", "/repos/owner/repo/issues/7"): _live_http_failure(
                "GET", "/repos/owner/repo/issues/7", forbidden_envelope)},
            leases=(repo_lease, reap_lease_8),
        )
        check(
            "MUTATION #649 (3 — terminal reap re-read): the claim whose fresh issue read was "
            "REFUSED keeps its lease, while the readable claim in the same batch still reclaims. "
            "Record-and-continue instead leaves #7 absent from the fresh view, which reads as "
            "ORPHANED and RELEASES it on a read that never returned — releasing BOTH reds this.",
            (
                reap_releases,
                "ALERT lease claim=eeeeeeee:" in reap_log,
                "terminal reap revalidation deferred for owner/repo#7" in reap_log,
                "the lease is RETAINED" in reap_log,
                "Resource not accessible by integration" in reap_log,
                reap_error,
                "reap_deferred=1" in reap_log,
            ),
            ([{"d" * 32}], True, True, True, True, "", True),
        )
        reap_all_log, reap_all_error, reap_all_releases = _sweep_with_refusals(
            {
                ("GET", f"/repos/owner/repo/issues/{number}"): _live_http_failure(
                    "GET", f"/repos/owner/repo/issues/{number}", forbidden_envelope)
                for number in (7, 8)
            },
            leases=(repo_lease, reap_lease_8),
        )
        check(
            "#649 (3) precedence rule 2: EVERY reap revalidation refused is systemic — non-zero "
            "naming both — and NOT ONE claim is released, because none of them was proven",
            (
                reap_all_releases,
                "every terminal reap revalidation failed (2 attempted, 0 completed)"
                in reap_all_error,
                "owner/repo#7" in reap_all_error and "owner/repo#8" in reap_all_error,
                "reap_deferred=2" in reap_all_log,
            ),
            ([set()], True, True, True),
        )

        # (3b) [review round 1] The reap block's OTHER fresh read: the pull listing that supplies
        # the "no open worker PR" half of #509's boundary. It is a SECOND read of a path the
        # snapshot phase already read, so the snapshot phase's own try CANNOT cover it — the
        # listing succeeds there and is refused here — and it used to sit outside the block,
        # unwrapped, aborting the whole sweep before `_release_claims`. Expressing that needs a
        # CALL-SEQUENCED refusal; a path-keyed one can only fail the first (snapshot) read.
        pull_reval_log, pull_reval_error, pull_reval_releases = _sweep_with_refusals(
            {},
            repos=("owner/repo", "owner/other"),
            leases=(repo_lease, other_lease),
            paginate_seq_refusals={
                ("/repos/owner/repo/pulls?state=open", 2):
                    _refused_listing("/repos/owner/repo/pulls?state=open")},
        )
        reval_pull_reads = sum(
            1 for path in terminal_sweep_env["paginated"]
            if path == "/repos/owner/repo/pulls?state=open"
        )
        check(
            "MUTATION #649 (3b — fresh PR listing): a listing that SUCCEEDED in the snapshot and "
            "is refused on the reap re-read defers ONLY its own repo's claims — owner/repo#7 keeps "
            "its lease while owner/other#8 reclaims in the SAME tick. Hoisting the read back out "
            "of the reap block raises before _release_claims (releasing NOTHING); leaving the "
            "failed repo merely ABSENT from current_pulls reads as 'no worker PR' and releases "
            "BOTH. Both mutations red this.",
            (
                pull_reval_releases,
                "ALERT repo owner/repo:" in pull_reval_log,
                "fresh PR listing unreadable" in pull_reval_log,
                "cannot prove the ABSENCE of a worker PR" in pull_reval_log,
                "Resource not accessible by integration" in pull_reval_log,
                pull_reval_error,
                "reap_deferred=1" in pull_reval_log,
                # INSTRUMENT VALIDATION: the FIRST read of that same path — the snapshot phase's —
                # must have SUCCEEDED. Without this the scenario silently degenerates into the
                # already-covered snapshot case (2) and proves nothing about the LATER read.
                "snapshot_deferred=0" in pull_reval_log,
            ),
            ([{"f" * 32}], True, True, True, True, "", True, True),
        )
        pull_all_log, pull_all_error, pull_all_releases = _sweep_with_refusals(
            {},
            repos=("owner/repo", "owner/other"),
            leases=(repo_lease, other_lease),
            paginate_seq_refusals={
                (f"/repos/{repo}/pulls?state=open", 2):
                    _refused_listing(f"/repos/{repo}/pulls?state=open")
                for repo in ("owner/repo", "owner/other")},
        )
        check(
            "#649 (3b) precedence rule 2: EVERY fresh PR listing refused is systemic — non-zero "
            "naming both claims BY ISSUE — and the raise happens only AFTER the sweep's work, so "
            "reclaim still ran and released nothing it could not prove",
            (
                pull_all_releases,
                "every terminal reap revalidation failed (2 attempted, 0 completed)"
                in pull_all_error,
                "owner/repo#7" in pull_all_error and "owner/other#8" in pull_all_error,
                "reap_deferred=2" in pull_all_log,
                # Same instrument validation: BOTH snapshots read fine, so the only phase that
                # failed is the revalidation one this scenario is about.
                "snapshot_deferred=0" in pull_all_log,
            ),
            ([set()], True, True, True, True),
        )
        # A tick with NOTHING to revalidate must not spend the second listing at all — the read is
        # inside the reap block, not unconditional. The pair is what makes this non-vacuous: the
        # reaping tick above really did issue a SECOND read of the same path (or the refusal at
        # ordinal 2 could never have fired), and this quiet tick issues only the snapshot's first.
        _sweep_with_refusals({}, leases=())
        quiet_pull_reads = sum(
            1 for path in terminal_sweep_env["paginated"]
            if path == "/repos/owner/repo/pulls?state=open"
        )
        check(
            "#649 (3b) CALL SITE: the reap-revalidation pull listing is read ONCE PER REAPING "
            "TICK and NOT AT ALL when there is no terminal reap candidate (hoisting it back to an "
            "unconditional comprehension makes the quiet tick 2)",
            (reval_pull_reads, quiet_pull_reads),
            (2, 1),
        )
    finally:
        globals().update(terminal_sweep_saved)

    # ---- run_sweep mutation-boundary guard (issue #170, review round 1, finding 3) ----
    # Drive the REAL run_sweep with a stubbed API in which the open-PR listing is SCHEDULED per
    # read: the planning snapshot read (#1) sees NO pulls, and only the defer branch's
    # mutation-boundary re-read (#2) sees the freshly opened admitted worker PR. The
    # discriminating pair: (A) the PR appears at the boundary → NO label mutation may occur
    # (deleting or inverting the run_sweep defer-branch guard, or keying it on the planning
    # snapshot, reds this — the snapshot never saw the PR); (B) no PR ever appears → the defer
    # mutation MUST occur (an inverted guard, or one keyed on anything but the fresh read, reds
    # this instead).
    #
    # [#649, review round 1] The boundary read is the SECOND, not the third: the reap
    # revalidation's own pull listing now runs only when there is a terminal reap candidate, and
    # this fixture's ledger is empty. Leaving these ordinals at 3 would make every
    # PR-appears-at-the-boundary scenario below assert about a PR that never appears at all.
    sweep_env: dict[str, Any] = {}

    class _SweepAPI:
        """Serve run_sweep's reads from fixtures; record every write. Listing reads of the
        target's open PRs are counted so the qualifying PR can 'appear' mid-sweep."""

        def __init__(self, token, purpose):
            self.purpose = purpose

        def request(self, method, path, body=None, allow_404=False, **_kwargs):
            if method == "GET":
                # Issue #174: simulate an UNAVAILABLE live provenance read (registry contents GET
                # raising) so the mutation-boundary live gate must fail closed (skip + alert).
                if sweep_env.get("provenance_error") and "/contents/" in path:
                    raise GroomError("registry contents read failed")
                return sweep_env["gets"].get(path)
            sweep_env["writes"].append((method, path))
            return {}

        def paginate(self, path):
            if path == "/repos/owner/repo/pulls?state=open":
                sweep_env["pull_reads"] += 1
                if sweep_env["pull_reads"] >= sweep_env["pr_visible_from"]:
                    # Which PR "appears" is a scenario knob (issue #279): the default is the
                    # admitted worker PR, and the ready-repair cases below substitute a loose
                    # `Fixes #8` PR and an enrolled orchestrator PR.
                    return [sweep_env.get("appearing_pull") or sweep_env["worker_pull"]]
                return []
            return sweep_env["pages"].get(path, [])

    sweep_now = int(time.time())
    sweep_issue = {
        "number": 8,
        "state": "open",
        "labels": [{"name": "status:in-progress"}],
        "updated_at": datetime.fromtimestamp(sweep_now - 700, timezone.utc).isoformat(),
        "comments": 1,
    }
    sweep_env["gets"] = {
        "/repos/owner/repo/issues/8": sweep_issue,
        # The strict maintainer probe (park-policy hygiene finding): jeswr is a repo admin,
        # so the human-unpark veto honours exactly this actor and nobody unverifiable.
        "/repos/owner/repo/collaborators/jeswr/permission": {"permission": "admin"},
    }
    sweep_env["pages"] = {
        "/repos/owner/repo/issues?state=open": [sweep_issue],
        # Two durable bot attempt comments: the budget (max_attempts=2) is exhausted, so
        # planning emits the defer and the write-loop recount confirms it.
        "/repos/owner/repo/issues/8/comments": [
            {"user": {"login": "app[bot]"}, "body": ATTEMPT_MARKER + " run=1 -->"},
            {"user": {"login": "app[bot]"}, "body": ATTEMPT_MARKER + " run=2 -->"},
        ],
    }
    sweep_env["worker_pull"] = {
        "number": 91,
        "updated_at": datetime.fromtimestamp(sweep_now - 30, timezone.utc).isoformat(),
        "head": {"ref": "sparq-agent/issue-8-91-1", "repo": {"full_name": "owner/repo"}},
        "user": {"login": "app[bot]"},
        "body": WORKER_PR_MARKER + "\n\nFixes #8",
    }

    def _sweep_scenario(
        pr_visible_from: int, appearing_pull: dict[str, Any] | None = None
    ) -> tuple[int, int, int, int]:
        sweep_env.update(pull_reads=0, pr_visible_from=pr_visible_from, writes=[],
                         appearing_pull=appearing_pull)
        return run_sweep(argparse.Namespace(
            registry_repo="owner/registry",
            policy_file="unused-policy",
            policy_resolver="unused-resolver",
            bot_slug="app",
            ledger_root="",
            stale_hours=DEFAULT_STALE_HOURS,
        ))

    sweep_patched = {
        "GitHubAPI": _SweepAPI,
        "load_limits": lambda *_a, **_k: {"owner/repo": limits},
        "target_tokens_map": lambda: {"owner": "sweep-token"},
        "_bot_login": lambda _api, _slug="": "app[bot]",
        "_read_ledger": lambda _api, _repo: ([], "s1"),
    }
    sweep_saved = {name: globals()[name] for name in sweep_patched}
    sweep_prior_cwd = os.getcwd()
    try:
        globals().update(sweep_patched)
        with tempfile.TemporaryDirectory() as tmp:
            # run_sweep resolves provenance from its working directory (the checkout root), so
            # give the admitted worker PR a valid record there.
            sweep_record_dir = Path(tmp) / PROVENANCE_DIR
            sweep_record_dir.mkdir(parents=True)
            (sweep_record_dir / "owner--repo--pr91.json").write_text(
                json.dumps({
                    "pr_number": 91,
                    "head_sha_at_open": "2" * 40,
                    "impl_provider": "anthropic",
                    "impl_alias": "fable",
                    "impl_account_h": "cd" * 8,
                    "issue": 8,
                }),
                encoding="utf-8",
            )
            os.chdir(tmp)
            # (A) The admitted worker PR opens AFTER the planning snapshot (listing read #1) and
            # is first visible to the mutation-boundary re-read (#2): NO label write may land.
            summary_a = _sweep_scenario(pr_visible_from=2)
            check(
                "MUTATION boundary: a post-snapshot admitted worker PR suppresses the defer WRITE",
                (summary_a, sweep_env["writes"]),
                ((0, 0, 0, 0), []),
            )
            check(
                "MUTATION boundary: the guard actually RE-READ open PRs at the boundary",
                sweep_env["pull_reads"] >= 2,
                True,
            )
            # (B) No PR ever appears: the exhausted defer mutation MUST land (discriminates an
            # inverted or over-broad guard that would suppress every defer).
            summary_b = _sweep_scenario(pr_visible_from=10**6)
            check(
                "MUTATION boundary: with no open worker PR the defer mutation still lands",
                (summary_b[2],
                 ("POST", "/repos/owner/repo/issues/8/labels") in sweep_env["writes"],
                 ("DELETE", "/repos/owner/repo/issues/8/labels/status%3Ain-progress")
                 in sweep_env["writes"]),
                (1, True, True),
            )
            # (B2) Sticky human unpark (park_policy.py defect 2): the SAME exhausted defer is
            # SUPPRESSED end-to-end when the issue timeline shows a human removed status:parked
            # more recently than the bot applied it — the machine never overrides a human's
            # explicit unpark. A later bot re-application (most-recent-event wins) re-enables
            # the park, proving the veto reads the timeline rather than latching forever.
            sweep_timeline = "/repos/owner/repo/issues/8/timeline"
            sweep_env["pages"][sweep_timeline] = [
                {"event": "labeled", "label": {"name": "status:parked"},
                 "created_at": "2026-07-18T10:00:00Z", "actor": {"login": "app[bot]"}},
                {"event": "unlabeled", "label": {"name": "status:parked"},
                 "created_at": "2026-07-18T11:00:00Z", "actor": {"login": "jeswr"}},
            ]
            summary_b2 = _sweep_scenario(pr_visible_from=10**6)
            check(
                "sticky human unpark VETOES the exhausted defer write",
                (summary_b2[2], sweep_env["writes"]),
                (0, []),
            )
            sweep_env["pages"][sweep_timeline].append(
                {"event": "labeled", "label": {"name": "status:parked"},
                 "created_at": "2026-07-18T12:00:00Z", "actor": {"login": "app[bot]"}})
            summary_b3 = _sweep_scenario(pr_visible_from=10**6)
            check(
                "a newer application supersedes the human unpark (most-recent-event wins)",
                (summary_b3[2],
                 ("POST", "/repos/owner/repo/issues/8/labels") in sweep_env["writes"]),
                (1, True),
            )
            del sweep_env["pages"][sweep_timeline]
            # ---- issue #174: live-ref revalidation at the terminal defer boundary ----
            # Remove the ON-DISK provenance record so the on-disk mutation-boundary admission no
            # longer suppresses (modelling a record that landed on the live `ledger` ref AFTER the
            # immutable checkout was taken). The live `ledger` ref is served the valid record.
            (sweep_record_dir / "owner--repo--pr91.json").unlink()
            # The live gate first verifies the ledger ref exists and pins the record read to its
            # tip sha (review round 1) — serve the ref, and the record AT that pinned sha.
            sweep_ref_path = "/repos/owner/registry/git/ref/heads/ledger"
            sweep_tip = "b" * 40
            sweep_env["gets"][sweep_ref_path] = {"object": {"sha": sweep_tip}}
            live_prov_path = (
                "/repos/owner/registry/contents/orchestration/provenance/"
                f"owner--repo--pr91.json?ref={sweep_tip}"
            )
            sweep_env["gets"][live_prov_path] = {
                "type": "file",
                "content": base64.b64encode(json.dumps({
                    "pr_number": 91, "head_sha_at_open": "3" * 40,
                    "impl_provider": "anthropic", "impl_alias": "fable",
                    "impl_account_h": "ef" * 8, "issue": 8,
                    # Machine-attested stamp (issue #657) — a WORKER record, so worker.yml's
                    # `<run>.<attempt>`. Without it the shared admission predicate refuses the
                    # record and the live-ref gate can no longer cancel the park.
                    "recorded_at_run": "29694084610.1",
                }).encode()).decode(),
            }
            # (C) The worker PR is visible at the boundary but ABSENT on the immutable checkout;
            # the LIVE ref admits it → the terminal defer park is CANCELLED (no write). Reverting
            # the live gate reds this: the on-disk admission alone would park the already-valid
            # issue (the exact stale-checkout bug).
            summary_c = _sweep_scenario(pr_visible_from=2)
            check(
                "issue #174: a record on the LIVE ref (missing on the checkout) cancels the park",
                (summary_c, sweep_env["writes"]),
                ((0, 0, 0, 0), []),
            )
            # (D) The live read is UNAVAILABLE (registry contents GET raises): the park must be
            # SKIPPED and an operational ALERT raised — never park on an unusable read. Capturing
            # stdout proves the alert is emitted alongside the skipped mutation.
            sweep_env["provenance_error"] = True
            alert_buf = io.StringIO()
            saved_stdout = sys.stdout
            sys.stdout = alert_buf
            try:
                summary_d = _sweep_scenario(pr_visible_from=2)
            finally:
                sys.stdout = saved_stdout
            check(
                "issue #174: an unavailable live read skips the park AND raises an ALERT",
                (summary_d[2], sweep_env["writes"], "ALERT" in alert_buf.getvalue()),
                (0, [], True),
            )
            sweep_env["provenance_error"] = False
            # (E) The ledger REF itself is unresolvable at the boundary (deleted branch or
            # misconfigured LEDGER_REF — review round 1): the record 404 proves nothing, so the
            # terminal park must be SKIPPED with an ALERT, never written. Reverting the ref
            # verification (trusting a bare Contents 404 as "denies") reds this: the record is
            # stubbed only at the verified-sha path, so the un-pinned read would deny and park.
            sweep_env["gets"].pop(sweep_ref_path)
            alert_buf = io.StringIO()
            sys.stdout = alert_buf
            try:
                summary_e = _sweep_scenario(pr_visible_from=2)
            finally:
                sys.stdout = saved_stdout
            check(
                "issue #174: a missing ledger REF skips the terminal park AND raises an ALERT",
                (summary_e[2], sweep_env["writes"], "ALERT" in alert_buf.getvalue()),
                (0, [], True),
            )
            # ---- issue #279: the READY-repair side of the same mutation boundary ----------------
            # The defer branch above re-reads open PRs immediately before its write; the ready
            # branch used to answer the same "is this issue already being worked?" question from
            # the PRE-LOOP snapshot, which is already stale by the time a later action reaches its
            # write. Wrong in the DANGEROUS direction: the missed PR means groom writes
            # status:ready and the dispatcher sends a second worker onto work that already has an
            # open PR. One attempt comment (budget 2) turns the SAME fixture issue into the stale
            # in-progress repair, so these scenarios differ from the defer ones by that alone.
            sweep_env["pages"]["/repos/owner/repo/issues/8/comments"] = [
                {"user": {"login": "app[bot]"}, "body": ATTEMPT_MARKER + " run=1 -->"},
            ]
            ready_writes = (
                ("POST", "/repos/owner/repo/issues/8/labels"),
                ("DELETE", "/repos/owner/repo/issues/8/labels/status%3Ain-progress"),
            )

            def _ready_landed(summary: tuple[int, int, int, int]) -> tuple[Any, ...]:
                return (summary[1],
                        all(write in sweep_env["writes"] for write in ready_writes))

            # (F) No PR ever appears: the repair MUST land. This is what makes (G) non-vacuous —
            # an over-broad guard that suppressed every ready write would red HERE.
            check(
                "#279 ready repair: with no open PR the status:ready repair still lands",
                _ready_landed(_sweep_scenario(pr_visible_from=10**6)),
                (1, True),
            )
            # (G) The worker PR is first visible to the boundary re-read (#2): NO write may land.
            # Reverting the ready branch to the planning snapshot reds this — the snapshot (#1)
            # never saw the PR — and so does deleting the guard.
            summary_g = _sweep_scenario(pr_visible_from=2)
            check(
                "MUTATION #279: a worker PR opening after the planning snapshot suppresses the "
                "status:ready WRITE",
                (summary_g[1], sweep_env["writes"]),
                (0, []),
            )
            check(
                "#279: the ready branch actually RE-READ open PRs at the write boundary",
                sweep_env["pull_reads"] >= 2,
                True,
            )
            # (H) The availability direction #279 asked about: an arbitrary open PR whose body
            # says `Fixes #8` must NOT delay the repair. The boundary check keys on the worker-PR
            # identity gate (#172), not on body references, so the repair lands. Reverting
            # `_current_links` to loose linkage reds this.
            loose_pull = {
                "number": 96,
                "updated_at": datetime.fromtimestamp(
                    sweep_now - 30, timezone.utc).isoformat(),
                "head": {"ref": "feature/anything", "repo": {"full_name": "owner/repo"}},
                "user": {"login": "drive-by-contributor"},
                "body": "a helpful drive-by\n\nFixes #8",
            }
            check(
                "#279: an arbitrary open PR whose body says `Fixes #8` cannot hold the issue out "
                "of ready repair",
                _ready_landed(
                    _sweep_scenario(pr_visible_from=2, appearing_pull=loose_pull)),
                (1, True),
            )
            # (I) The CLASS-AWARE half of the boundary predicate is live too ([registry #835]):
            # an enrolled orchestrator PR is not worker-shaped, so only `_admitted_review_prs`
            # can see it. Enrolment is the discriminator — the identical PR with the default
            # empty allowlist suppresses nothing.
            sweep_orch_pull = {
                **orch_pull,
                "number": 95,
                "updated_at": datetime.fromtimestamp(
                    sweep_now - 30, timezone.utc).isoformat(),
            }
            (sweep_record_dir / "owner--repo--pr95.json").write_text(
                json.dumps(dict(orch_review.orchestrator_probe_record(95), issue=8)),
                encoding="utf-8",
            )
            check(
                "#279 control: with the default EMPTY allowlist an orchestrator PR suppresses "
                "nothing and the repair lands",
                _ready_landed(
                    _sweep_scenario(pr_visible_from=2, appearing_pull=sweep_orch_pull)),
                (1, True),
            )
            globals()["load_limits"] = lambda *_a, **_k: {"owner/repo": Limits(
                worker_timeout_minutes=10, max_attempts=2,
                enrolled_authors=orch_enrolled)}
            try:
                summary_i = _sweep_scenario(
                    pr_visible_from=2, appearing_pull=sweep_orch_pull)
            finally:
                globals()["load_limits"] = sweep_patched["load_limits"]
            check(
                "[#835] MUTATION #279: an ENROLLED orchestrator PR opening after the snapshot "
                "also suppresses the status:ready write (dropping the admitted disjunct, or its "
                "enrolled_authors argument, reds this)",
                (summary_i[1], sweep_env["writes"]),
                (0, []),
            )
    finally:
        os.chdir(sweep_prior_cwd)
        globals().update(sweep_saved)

    # ---- burned account-slot report (issue #245) ------------------------------------------------
    def _orphan_raises(function, *call_args) -> Any:
        try:
            function(*call_args)
        except GroomError:
            return True
        except Exception as exc:                   # noqa: BLE001 - a WRONG exception is not a pass
            return f"{type(exc).__name__}: {exc}"
        return False

    check("orphan-claims: claim refs are keyed by SLOT and keep the ref they were read from",
          claim_ref_slots([{"ref": "refs/acct-claims/acct07"},
                           {"ref": "refs/acct-claims/acct12"}]),
          {7: "refs/acct-claims/acct07", 12: "refs/acct-claims/acct12"})
    check("orphan-claims: only an EXACT refs/acct-claims/acctNN ref is a claimed slot",
          claim_ref_slots([{"ref": "refs/heads/acct07"},
                           {"ref": "refs/acct-claims/acctXX"},
                           {"ref": "refs/acct-claims/acct07/sub"},
                           {"ref": "refs/tags/acct08"}]), {})
    check("orphan-claims: a malformed claim listing REFUSES rather than parsing what it can (a "
          "silently short claim set under-reports burned slots)",
          [_orphan_raises(claim_ref_slots, payload)
           for payload in ("not-a-list", None, [{"ref": 7}], ["refs/acct-claims/acct01"])],
          [True] * 4)
    check("orphan-claims: DISTINCT refs colliding on one slot NUMBER refuse — alternate padding "
          "(`acct1` vs `acct01`) and a repeated ref are two claims and one key, so keying by the "
          "number would silently drop one from claims=/burned= and from the named rows",
          [_orphan_raises(claim_ref_slots, payload)
           for payload in ([{"ref": "refs/acct-claims/acct1"},
                            {"ref": "refs/acct-claims/acct01"}],
                           [{"ref": "refs/acct-claims/acct007"},
                            {"ref": "refs/acct-claims/acct07"}],
                           [{"ref": "refs/acct-claims/acct07"},
                            {"ref": "refs/acct-claims/acct07"}])],
          [True] * 3)
    check("orphan-claims: the collision guard is EXACT — unpadded and padded numbers that DIFFER "
          "are still two ordinary slots, so the refusal cannot swallow a normal inventory",
          claim_ref_slots([{"ref": "refs/acct-claims/acct1"},
                           {"ref": "refs/acct-claims/acct01x"},
                           {"ref": "refs/acct-claims/acct10"}]),
          {1: "refs/acct-claims/acct1", 10: "refs/acct-claims/acct10"})

    check("orphan-claims: acctNN issues in ANY state count, and a PULL REQUEST titled acctNN does "
          "NOT (an /issues page carries both)",
          account_issue_slots([{"title": "acct03", "state": "open"},
                               {"title": "acct04", "state": "closed"},
                               {"title": "acct05", "pull_request": {"url": "x"}},
                               {"title": "acct06-retired"},
                               {"title": "groom: report orphaned acct-claims refs"}]), {3, 4})
    check("orphan-claims: a malformed issue listing REFUSES (a silently short issue set reports "
          "LIVE slots as burned)",
          [_orphan_raises(account_issue_slots, payload)
           for payload in ({"not": "a list"}, [{"title": None}], ["acct01"])], [True] * 3)

    check("orphan-claims: EXACTLY the ACCTNN_TOKEN names map to slots",
          account_secret_slots(["ACCT01_TOKEN", "ACCT12_TOKEN", "acct02_token",
                                "ACCT03_TOKEN_BACKUP", "ACCTLOOKALIKE", "REGISTRY_SECRETS_PAT"]),
          {1, 12})
    check("orphan-claims: a malformed secret inventory REFUSES (same reason as the issue "
          "listing — a short secret set reports LIVE slots as burned)",
          [_orphan_raises(account_secret_slots, payload)
           for payload in ("ACCT01_TOKEN", {"ACCT01_TOKEN": ""}, [7], [None])], [True] * 4)

    check("orphan-claims: an UNPROVEN secret inventory REFUSES — unset, blank, bad JSON, or not an "
          "array of names — because an unproven `no secret` reports live slots as burned",
          [_orphan_raises(parse_acct_secret_names, raw)
           for raw in (None, "", "   ", "{oops", '{"a": 1}', '["ACCT01_TOKEN", 7]', 7)],
          [True] * 7)
    check("orphan-claims: a PROVEN-EMPTY inventory is accepted (it is not the same as unset)",
          parse_acct_secret_names("[]"), [])

    orphan_claims_fixture = {5: "refs/acct-claims/acct05", 6: "refs/acct-claims/acct06",
                             7: "refs/acct-claims/acct07", 8: "refs/acct-claims/acct08"}
    check("orphan-claims: ONLY a claim with NEITHER an issue NOR a secret is burned — claim+secret "
          "is a STORED CREDENTIAL, claim+issue is an account mid-enrolment",
          orphaned_claim_slots(orphan_claims_fixture, {6}, {7}), [5, 8])
    check("orphan-claims: dropping EITHER exclusion changes the answer, so neither is decorative",
          (orphaned_claim_slots(orphan_claims_fixture, set(), {7}),
           orphaned_claim_slots(orphan_claims_fixture, {6}, set())),
          ([5, 6, 8], [5, 7, 8]))
    check("orphan-claims: a legacy slot with an issue/secret but NO claim ref is allocated, not "
          "burned, and is not reported",
          orphaned_claim_slots({}, {2}, {3}), [])

    orphan_burned_report = format_orphan_claim_report(orphan_claims_fixture, {6}, {7})
    check("orphan-claims: the report counts the fleet and NAMES each burned ref",
          (orphan_burned_report[0],
           [line for line in orphan_burned_report if line.startswith("ORPHAN-CLAIM ")]),
          ("ORPHAN-CLAIMS claims=4 account_issues=1 account_secrets=1 burned=2",
           [f"ORPHAN-CLAIM refs/acct-claims/acct0{slot}: slot claimed, but no acct0{slot} issue "
            f"and no ACCT0{slot}_TOKEN secret exist — burned by a failed enrolment"
            for slot in (5, 8)]))
    check("orphan-claims: a burned report carries the NEVER-DELETE instruction (deletion re-opens "
          "the overwrite race the claim closes)",
          orphan_burned_report[-1], ORPHAN_CLAIM_NOTE)
    orphan_clean_report = format_orphan_claim_report({6: "refs/acct-claims/acct06"}, {6}, set())
    check("orphan-claims: a clean fleet reports `none` and names no slot",
          (len(orphan_clean_report), "burned=0" in orphan_clean_report[0],
           [line for line in orphan_clean_report if line.startswith("ORPHAN-CLAIM ")]),
          (2, True, []))

    # The CLI contract, driven through main() exactly as groom.yml drives it: real argument
    # parsing, real environment resolution, the real paginated request sequence. A pure function
    # nothing CALLS is a vacuous guard, so the driver stubs only the HTTP boundary — GitHubAPI's
    # own missing-token refusal and `paginate` stay live.
    orphan_repo = "jeswr/agent-account-registry"
    orphan_pages = {
        f"/repos/{orphan_repo}/git/matching-refs/acct-claims/": [
            {"ref": "refs/acct-claims/acct05"},
            {"ref": "refs/acct-claims/acct06"},
            {"ref": "refs/acct-claims/acct07"},
            {"ref": "refs/acct-claims/acct09"},
        ],
        f"/repos/{orphan_repo}/issues": [
            {"title": "acct06"},
            # A PULL REQUEST titled acct09: not an account record, so slot 9 IS burned. Dropping
            # the pull_request exclusion silently loses that row from the report.
            {"title": "acct09", "pull_request": {"url": "x"}},
            {"title": "groom: report orphaned acct-claims refs"},
        ],
    }
    orphan_saved_api = globals()["GitHubAPI"]

    def _orphan_cli(
        env: dict[str, str | None], pages: dict[str, list[Any]], repo: str = orphan_repo
    ) -> tuple[Any, ...]:
        recorded: list[tuple[str, str, Any]] = []

        class _RecordingAPI(orphan_saved_api):                       # type: ignore[misc, valid-type]
            def request(self, method, path, body=None, **_kw):
                recorded.append((method, path, body))
                base = path.split("?", 1)[0]
                return list(pages.get(base, [])) if "page=1" in path else []

        held = {key: os.environ.get(key)
                for key in ("REGISTRY_GH_TOKEN", ACCT_SECRET_NAMES_ENV)}
        saved_orphan_argv, buffer = sys.argv, io.StringIO()
        saved_out, saved_err = sys.stdout, sys.stderr
        globals()["GitHubAPI"] = _RecordingAPI
        try:
            for key, value in env.items():
                os.environ.pop(key, None) if value is None else os.environ.__setitem__(key, value)
            sys.argv = ["groom.py", "--report-orphan-claims", "--registry-repo", repo]
            # BOTH streams: the groom step's stderr lands in the same log as its stdout.
            sys.stdout = sys.stderr = buffer
            code = main()
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err
            sys.argv = saved_orphan_argv
            globals()["GitHubAPI"] = orphan_saved_api
            for key, value in held.items():
                os.environ.pop(key, None) if value is None else os.environ.__setitem__(key, value)
        return code, buffer.getvalue(), recorded

    orphan_code, orphan_text, orphan_calls = _orphan_cli(
        {"REGISTRY_GH_TOKEN": "registry-token",
         ACCT_SECRET_NAMES_ENV: '["ACCT07_TOKEN", "REGISTRY_SECRETS_PAT"]'},
        orphan_pages,
    )
    check("orphan-claims CLI: reports the burned slots and exits 0 (a hygiene report never takes "
          "the sweep down)",
          (orphan_code,
           sorted(line.split()[1].rstrip(":") for line in orphan_text.splitlines()
                  if line.startswith("ORPHAN-CLAIM "))),
          (0, ["refs/acct-claims/acct05", "refs/acct-claims/acct09"]))
    check("orphan-claims CLI: the summary line counts what the three listings proved",
          [line for line in orphan_text.splitlines() if line.startswith("ORPHAN-CLAIMS ")][0],
          "ORPHAN-CLAIMS claims=4 account_issues=1 account_secrets=1 burned=2")
    check("orphan-claims CLI: REPORT-ONLY — every request is a GET, so no claim ref can be "
          "deleted (deletion re-opens the credential-overwrite race the claim closes)",
          sorted({method for method, _path, _body in orphan_calls}), ["GET"])
    check("orphan-claims CLI: both listings go through the PAGINATED reader (a capped page drops "
          "claim refs or account issues and silently changes the verdict)",
          sorted(path for _method, path, _body in orphan_calls),
          [f"/repos/{orphan_repo}/git/matching-refs/acct-claims/?per_page=100&page=1",
           f"/repos/{orphan_repo}/issues?state=all&per_page=100&page=1"])
    check("orphan-claims CLI: no secret VALUE and no token reaches the report's output",
          [token for token in ("registry-token", "REGISTRY_SECRETS_PAT") if token in orphan_text],
          [])

    orphan_unproven_code, orphan_unproven_text, orphan_unproven_calls = _orphan_cli(
        {"REGISTRY_GH_TOKEN": "registry-token", ACCT_SECRET_NAMES_ENV: None}, orphan_pages)
    check("orphan-claims CLI: an UNPROVEN secret inventory exits NON-ZERO, names NO burned slot, "
          "and reads NOTHING — `could not tell` must never read as `nothing is burned`",
          (orphan_unproven_code, "ORPHAN-CLAIM" in orphan_unproven_text, orphan_unproven_calls),
          (1, False, []))
    orphan_ambiguous_code, orphan_ambiguous_text, _ = _orphan_cli(
        {"REGISTRY_GH_TOKEN": "registry-token", ACCT_SECRET_NAMES_ENV: '["ACCT07_TOKEN"]'},
        {**orphan_pages,
         f"/repos/{orphan_repo}/git/matching-refs/acct-claims/": [
             {"ref": "refs/acct-claims/acct1"},
             {"ref": "refs/acct-claims/acct01"},
             {"ref": "refs/acct-claims/acct09"},
         ]})
    check("orphan-claims CLI: an AMBIGUOUS claim inventory exits NON-ZERO and emits NO report — a "
          "count that quietly dropped a real claim ref must never be published as the fleet's "
          "burned-slot truth",
          (orphan_ambiguous_code, "ORPHAN-CLAIM" in orphan_ambiguous_text), (1, False))
    orphan_untoken_code, orphan_untoken_text, _ = _orphan_cli(
        {"REGISTRY_GH_TOKEN": None, ACCT_SECRET_NAMES_ENV: '["ACCT07_TOKEN"]'}, orphan_pages)
    check("orphan-claims CLI: a missing registry token is a REFUSAL, not an empty report",
          (orphan_untoken_code, "ORPHAN-CLAIM" in orphan_untoken_text), (1, False))
    orphan_unsafe_code, orphan_unsafe_text, orphan_unsafe_calls = _orphan_cli(
        {"REGISTRY_GH_TOKEN": "registry-token", ACCT_SECRET_NAMES_ENV: '["ACCT07_TOKEN"]'},
        orphan_pages, repo="jeswr/agent-account-registry/../../evil")
    check("orphan-claims CLI: an unsafe --registry-repo REFUSES before any request is issued",
          (orphan_unsafe_code, "ORPHAN-CLAIM" in orphan_unsafe_text, orphan_unsafe_calls),
          (1, False, []))
    saved_orphan_argv = sys.argv
    try:
        sys.argv = ["groom.py", "--report-orphan-claims"]
        saved_err = sys.stderr
        sys.stderr = io.StringIO()
        try:
            orphan_usage_code: Any = main()
        except SystemExit as exc:
            orphan_usage_code = exc.code
        finally:
            sys.stderr = saved_err
    finally:
        sys.argv = saved_orphan_argv
    check("orphan-claims CLI: --report-orphan-claims without --registry-repo is a usage error, "
          "not a silent pass", orphan_usage_code, 2)

    # ---- THE YAML SEAM for the burned-slot report ------------------------------------------------
    # The measured lesson of this estate: the uncaught mutants live one level ABOVE the Python — a
    # renamed flag, an `if: false`, a dropped env line, a producer moved after its consumer. So the
    # wiring is asserted STRUCTURALLY against groom.yml, with the same dependency-free line
    # discipline the worker.yml run-name seam above uses: PyYAML is NOT installed in the `groom`
    # job that runs this self-test (only the watchdog jobs install it). Anything that cannot be
    # located fails CLOSED — "zero steps matched" must never read as a pass.
    try:
        orphan_yaml = (
            Path(__file__).resolve().parent.parent / ".github" / "workflows" / "groom.yml"
        ).read_text(encoding="utf-8")
        orphan_yaml_lines = orphan_yaml.splitlines()
        orphan_job_start = orphan_yaml_lines.index("  groom:")
        orphan_job_end = next(
            (index for index in range(orphan_job_start + 1, len(orphan_yaml_lines))
             if re.match(r"^  [A-Za-z]", orphan_yaml_lines[index])),
            len(orphan_yaml_lines),
        )
        orphan_job = orphan_yaml_lines[orphan_job_start:orphan_job_end]
        orphan_step_starts = [index for index, line in enumerate(orphan_job)
                              if re.match(r"^ {6}- name:", line)]
        orphan_steps = [
            orphan_job[start:(orphan_step_starts + [len(orphan_job)])[position + 1]]
            for position, start in enumerate(orphan_step_starts)
        ]

        # COMMENT-BLIND matching (the dispatch-secrets-guard round-19 lesson): comment prose must
        # never stand in for a real call site, a real env line or a real dependency edge — the
        # rationale comments around these steps QUOTE the expressions being asserted, and
        # `true  # python3 scripts/groom.py --report-orphan-claims ...` un-wires the report while
        # leaving every substring intact. Stripping is delegated to the ONE shared quote-aware
        # stripper rather than copied, so both call sites keep the same tokenization rules.
        _orphan_shell = _load_module(
            Path(__file__).resolve().with_name("dispatch-secrets-guard.py"),
            "registry_dispatch_secrets_guard",
        )

        def _orphan_code(step: list[str]) -> str:
            return _orphan_shell.strip_shell_comments("\n".join(step))

        def _orphan_steps_with(needle: str) -> list[list[str]]:
            return [step for step in orphan_steps if needle in _orphan_code(step)]

        def _step_if_disabled(step: list[str]) -> bool:
            # A step-level `if:` key sits at exactly 8 spaces; shell/python bodies are deeper.
            return any(re.match(r"^ {8}if:", line) for line in step)

        check("YAML seam: groom.yml invokes --report-orphan-claims exactly once, inside the "
              "`groom` job", len(_orphan_steps_with("--report-orphan-claims")), 1)
        orphan_report_step = _orphan_steps_with("--report-orphan-claims")[0]
        orphan_filter_step = _orphan_steps_with("ALL_SECRETS: ${{ toJSON(secrets) }}")[0]
        orphan_report_text = _orphan_code(orphan_report_step)
        orphan_filter_text = _orphan_code(orphan_filter_step)
        check("YAML seam: the report step runs THIS script against the registry repo",
              ("python3 scripts/groom.py --report-orphan-claims" in orphan_report_text,
               '--registry-repo "$GITHUB_REPOSITORY"' in orphan_report_text), (True, True))
        check("YAML seam: the report step is fed the derived secret-name inventory from the "
              "filter step's output (drop the env line and the report refuses every tick)",
              "ACCT_SECRET_NAMES: ${{ steps.acct-slots.outputs.names }}" in orphan_report_text,
              True)
        check("YAML seam: LEAST EXPOSURE — the whole secrets context reaches exactly one step, the "
              "FILTER, and never the report process",
              (len(_orphan_steps_with("toJSON(secrets)")),
               "toJSON(secrets)" in orphan_report_text,
               "id: acct-slots" in orphan_filter_text), (1, False, True))
        check("YAML seam: the filter step emits NAMES only — no secret value is written out",
              ('output.write(f"names={json.dumps(names' in orphan_filter_text,
               "ACCT[0-9]+_TOKEN" in orphan_filter_text), (True, True))
        check("YAML seam: the filter runs BEFORE the report (a producer moved after its consumer "
              "leaves the inventory empty and the report refuses)",
              orphan_steps.index(orphan_filter_step) < orphan_steps.index(orphan_report_step),
              True)
        check("YAML seam: neither step is if:-disabled",
              (_step_if_disabled(orphan_report_step), _step_if_disabled(orphan_filter_step)),
              (False, False))
        check("YAML seam: both steps are continue-on-error — a hygiene report must never abort "
              "the dead-lease release that follows it",
              ("continue-on-error: true" in orphan_report_text,
               "continue-on-error: true" in orphan_filter_text), (True, True))
        check("YAML seam: the job reading the secrets context is dispatch-secrets-bound (an "
              "UNBOUND read resolves the provably-empty repo scope, and EVERY claimed slot would "
              "then look burned)",
              "    environment: dispatch-secrets" in orphan_job, True)
        check("YAML seam: REPORT-ONLY at the seam — the report step carries no deletion or gate "
              "flag",
              [flag for flag in ("git/refs", "--delete", "--prune", "--fail-on", "DELETE")
               if flag in orphan_report_text], [])
    except Exception as exc:                       # noqa: BLE001 - fail CLOSED, never skip
        check(f"YAML seam: groom.yml burned-slot wiring is inspectable "
              f"({type(exc).__name__}: {exc})", False, True)

    print("groom self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--print-owner-repos",
        action="store_true",
        help="print the per-owner enabled-repo GITHUB_OUTPUT lines that scope groom.yml's "
             "App-token mints (issue #168), then exit",
    )
    parser.add_argument(
        "--target-repos-env",
        default="",
        help="with --print-owner-repos: read the target set from this environment variable (a "
             "JSON array of owner/name) instead of --policy-file — dispatch.yml's manifest-driven "
             "per-owner mints (issue #273)",
    )
    parser.add_argument(
        "--report-orphan-claims",
        action="store_true",
        help="report `refs/acct-claims/` slots burned by a failed enrolment — claimed, but with "
             "no acctNN issue and no ACCTNN_TOKEN secret (issue #245), then exit. REPORT-ONLY: "
             "claim refs are never deleted",
    )
    parser.add_argument("--registry-repo")
    parser.add_argument("--policy-file", default="policy/repos.toml")
    parser.add_argument("--policy-resolver", default="scripts/policy-resolve.py")
    parser.add_argument(
        "--stale-hours",
        type=int,
        default=None,
        help="quiet hours before safely redrafting a terminally parked PR "
        "(default: STALE_HOURS or 6)",
    )
    parser.add_argument(
        "--bot-slug",
        default="",
        help="GitHub App slug from the token mint step (an installation token cannot GET /user)",
    )
    parser.add_argument(
        "--ledger-root",
        default="",
        help="`ledger` data-plane branch checkout root — the PRIMARY provenance record "
             "location (issue #96); empty falls back to the master checkout only",
    )
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    if args.target_repos_env and not args.print_owner_repos:
        parser.error("--target-repos-env is only valid with --print-owner-repos")
    if args.print_owner_repos:
        try:
            if args.target_repos_env:
                # Absent/empty manifest env => DIE, never an unscoped or single-repo mint.
                lines = manifest_owner_repo_output_lines(
                    os.environ.get(args.target_repos_env) or ""
                )
            else:
                lines = owner_repo_output_lines(_policy_document(Path(args.policy_file)))
            for line in lines:
                print(line)
        except GroomError as exc:
            print(f"groom: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.report_orphan_claims:
        if not args.registry_repo:
            parser.error("--report-orphan-claims requires --registry-repo")
        try:
            return report_orphan_claims(args)
        except GroomError as exc:
            # A refusal is the report. Exiting NON-ZERO on an unprovable inventory is what keeps
            # "could not tell" from reading as "nothing is burned"; groom.yml runs this step
            # continue-on-error so the refusal is loud without ever aborting the repair sweep.
            print(f"groom: {exc}", file=sys.stderr)
            return 1
    if not args.registry_repo:
        parser.error("--registry-repo is required outside --self-test")
    try:
        run_sweep(args)
    except GroomError as exc:
        print(f"groom: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
