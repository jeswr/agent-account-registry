#!/usr/bin/env python3
# [GPT-5.6] REG-5 fail-closed maintenance sweep for the private-registry orchestrator.
"""Reclaim dead worker leases and conservatively repair target orchestration state.

The live path uses deliberately separate credentials: ``REGISTRY_GH_TOKEN`` may only update the
private registry lease ledger and inspect registry Actions runs, while ``TARGET_GH_TOKENS`` is a
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
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import random
import re
import sys
import tempfile
import time
import tomllib
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


LEDGER_PATH = "data/leases.json"
# Mutable data plane lives on a dedicated non-code branch (issue #28): required-status-check
# protection on the default branch rejects the bot's contents-API PUTs, so every ledger read and
# write pins this ref. Keep in sync with select-and-claim.py / model-health.py LEDGER_REF.
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")
ATTEMPT_MARKER = "<!-- sparq-worker-attempt:v1"
STALE_PR_MARKER = "<!-- registry-groom-stale-pr:v1 -->"
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
HOLDER = re.compile(
    r"(?P<repo>[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)"
    r"#(?P<issue>[1-9][0-9]*)@(?P<run>[^\r\n]+)"
)
WORKER_RUN_NAME = re.compile(r"worker claim=(?P<claim>[0-9a-f]{32}|self)")
# Cross-provider review/fix repair leases (dispatch-claim prefixes `review:` / `fix:`) carry no
# target-issue holder; they are TTL-managed by groom-leases. Groom must SKIP them, never
# issue-map them, and never fail the whole sweep on their holder shape (live incident
# 2026-07-17: every scheduled sweep aborted while a review lease existed).
REPAIR_HOLDER_PREFIXES = ("review:", "fix:")


def is_repair_holder(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(REPAIR_HOLDER_PREFIXES)
WORKER_BRANCH = re.compile(r"^sparq-agent/issue-(?P<issue>[1-9][0-9]*)-")
LINKED_ISSUE = re.compile(
    r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#(?P<issue>[1-9][0-9]*)\b"
)
ACTIVE_RUN_STATUSES = {"queued", "in_progress", "requested", "waiting", "pending"}
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
    "needs:user": ("b60205", "Human attention required"),
}


class GroomError(RuntimeError):
    """A concise fail-closed error which never contains credential or response bodies."""


class GroomConflict(GroomError):
    """A retryable contents-API compare-and-swap conflict."""


@dataclass(frozen=True)
class Limits:
    worker_timeout_minutes: int
    max_attempts: int

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
    if not isinstance(document, dict) or set(document) != {"leases"}:
        raise GroomError("lease ledger top level is malformed")
    leases = document["leases"]
    if not isinstance(leases, list):
        raise GroomError("lease ledger leases field is malformed")
    claims: set[str] = set()
    for lease in leases:
        if not isinstance(lease, dict):
            raise GroomError("lease ledger contains a non-object entry")
        claim = lease.get("claim_id")
        if not isinstance(claim, str) or SAFE_CLAIM.fullmatch(claim) is None:
            raise GroomError("lease ledger contains an unsafe claim id")
        if claim in claims:
            raise GroomError("lease ledger contains duplicate claim ids")
        claims.add(claim)
        if not is_repair_holder(lease.get("holder")):
            parse_holder(lease.get("holder"))
        issued = _positive_int(lease.get("issued_at"), "lease issued_at")
        expires = _positive_int(lease.get("expires_at"), "lease expires_at")
        if expires <= issued:
            raise GroomError("lease expiry does not follow issuance")
        for field in ("account", "package", "role", "model"):
            if not isinstance(lease.get(field), str) or not lease[field]:
                raise GroomError(f"lease {field} is malformed")
    return leases


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
        state = _run_status(claim_runs[claim])
        conclusion = claim_runs[claim].get("conclusion") or "active"
        return LeaseDecision(
            state, f"claim-correlated worker is {state} ({conclusion})"
        )

    holder = parse_holder(lease["holder"])
    holder_run = holder_runs.get(holder.run_id) if holder.run_id is not None else None
    if holder_run is not None:
        path = str(holder_run.get("path", "")).split("@", 1)[0]
        if not holder.dispatcher_run and path == ".github/workflows/worker.yml":
            state = _run_status(holder_run)
            conclusion = holder_run.get("conclusion") or "active"
            return LeaseDecision(state, f"holder worker is {state} ({conclusion})")

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


def label_transition(labels: set[str], mode: str) -> tuple[set[str], set[str]]:
    # status:in-progress-review is removed by BOTH modes: the orphan repair (a worker PR that
    # closed without merging) must not leave the review-loop label behind on a re-readied issue.
    if mode == "ready":
        desired = {"status:ready"}
        remove = {"status:in-progress", "status:in-progress-review", "status:deferred"}
    elif mode == "defer":
        desired = {"needs:user", "status:deferred"}
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
    account hash — the COMPLETE field set; see provenance_admission_error, the one function
    every consumer calls).

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
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None  # unreadable/malformed JSON — the review loop fails closed on it too
    if not _review_loop_module().is_enumerable_provenance(record, number):
        return None
    return record


def _worker_pr_identity(
    repo: str, pull: dict[str, Any], bot: str
) -> re.Match[str] | None:
    """The worker-branch match for ``pull`` IFF it clears the worker-PR IDENTITY gate for
    ``repo`` — a worker-pattern head branch, a same-repository head (a fork head is
    attacker-controlled), the App-bot author, and the worker PR body marker — else None.

    This is the identity subset shared by two admissions so they cannot drift: `_admitted_worker_prs`
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


def _admitted_worker_prs(
    repo: str,
    pulls: dict[int, dict[str, Any]],
    bot_login: str,
    registry_root: Path = Path("."),
    ledger_root: Path | None = None,
) -> set[int]:
    """Source-issue numbers among ``pulls`` (open PRs) with a PROVEN admitted worker attempt —
    the ONLY linkage strong enough to suppress the exhausted-attempt defer (issue #170, review
    round 1).

    `_current_links` linkage (a worker-looking branch OR a `Fixes #N` body reference) is
    deliberately NOT trusted for suppression: anyone can open a PR whose body says `Fixes #N`,
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
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as exc:
            if allow_404 and exc.code == 404:
                return None
            if retry_conflict and exc.code in {409, 422}:
                raise GroomConflict("lease ledger compare-and-swap conflict") from exc
            raise GroomError(
                f"{self._purpose} GitHub API {method} failed with HTTP {exc.code}"
            ) from exc
        except (URLError, TimeoutError) as exc:
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
        )
    if not limits:
        raise GroomError("repository policy has no enabled target rows")
    return limits


# Exact owner -> GITHUB_OUTPUT key map for the per-owner App-token mint steps in groom.yml
# (issue #168). The workflow's mint steps are STATIC (one step per known owner), so the
# resolver below fails LOUD when policy's enabled owner set drifts from this map — a silently
# dropped owner would reintroduce the wrong-owner-token bug.
EXPECTED_TARGET_OWNERS = {"sparq-org": "sparq_names", "jeswr": "jeswr_names"}


def enabled_owner_repos(document: Any) -> dict[str, list[str]]:
    """EVERY enabled repo name per owner (issue #168, review round 1). Each per-owner App-token
    mint must be scoped to ALL of that owner's enabled repositories — a single "representative"
    repo would mint a token that 404s the owner's other enabled repos, and groom (which routes
    tokens per OWNER) would then abort mid-sweep on a supported policy shape."""
    repos = document.get("repos") if isinstance(document, dict) else None
    if not isinstance(repos, dict) or not repos:
        raise GroomError("repository policy has no target rows")
    owners: dict[str, list[str]] = {}
    for repo, raw in repos.items():
        if not isinstance(repo, str) or SAFE_REPO.fullmatch(repo) is None:
            raise GroomError("repository policy contains an unsafe target name")
        if not isinstance(raw, dict) or not isinstance(raw.get("enabled"), bool):
            raise GroomError(f"repository policy enablement is malformed for {repo}")
        if not raw["enabled"]:
            continue
        owner, name = repo.split("/", 1)
        owners.setdefault(owner, []).append(name)
    if not owners:
        raise GroomError("repository policy has no enabled target rows")
    return owners


def owner_repo_output_lines(document: Any) -> list[str]:
    """GITHUB_OUTPUT lines (``<key>=name1,name2``) scoping each mint step's ``repositories``
    input to the owner's full enabled-repo list. Fails LOUD unless the enabled owner set is
    exactly ``EXPECTED_TARGET_OWNERS`` — never silently drops an owner's token."""
    owners = enabled_owner_repos(document)
    if set(owners) != set(EXPECTED_TARGET_OWNERS):
        raise GroomError(
            f"unexpected enabled target owners {sorted(owners)}; groom.yml mints tokens for "
            f"exactly {sorted(EXPECTED_TARGET_OWNERS)} — add a mint step before widening policy"
        )
    return [f"{key}={','.join(owners[owner])}" for owner, key in EXPECTED_TARGET_OWNERS.items()]


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


def _worker_runs(
    api: GitHubAPI, leases: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any] | None]]:
    if not leases:
        return {}, {}
    runs_doc = api.request(
        "GET",
        "/repos/"
        + _registry_repo(api)
        + "/actions/workflows/worker.yml/runs?per_page=100",
    )
    if not isinstance(runs_doc, dict) or not isinstance(
        runs_doc.get("workflow_runs"), list
    ):
        raise GroomError("registry worker-run snapshot is malformed")
    claim_runs: dict[str, dict[str, Any]] = {}
    for run in runs_doc["workflow_runs"]:
        if not isinstance(run, dict):
            raise GroomError("registry worker-run entry is malformed")
        _run_status(run)
        display = run.get("display_title")
        if isinstance(display, str):
            match = WORKER_RUN_NAME.fullmatch(display)
            if match and match.group("claim") != "self":
                claim = match.group("claim")
                if claim in claim_runs:
                    raise GroomError("multiple worker runs claim the same lease id")
                claim_runs[claim] = run

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
    encoded = quote(label, safe="")
    existing = api.request("GET", f"/repos/{repo}/labels/{encoded}", allow_404=True)
    if existing is not None:
        return False
    colour, description = LABELS[label]
    api.request(
        "POST",
        f"/repos/{repo}/labels",
        {"name": label, "color": colour, "description": description},
    )
    print(f"WRITE create label repo={repo} label={label}")
    return True


def _apply_labels(
    api: GitHubAPI, repo: str, number: int, current: set[str], mode: str
) -> bool:
    add, remove = label_transition(current, mode)
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

    This is the identity gate WITHOUT the registry-provenance record `_admitted_worker_prs`
    additionally requires: recovery suppression asks 'is the App itself actively working this issue
    right now', for which the authoring identity is authoritative — provenance-record visibility
    (issue #96) is not, and demanding it here would prematurely reset a legitimately in-progress
    issue whose record is not yet on the read branch."""
    links: dict[int, set[int]] = {}
    bot = bot_login.casefold()
    if not bot:
        return links  # no bot identity resolved — trust no linkage, fail closed
    for number, pull in pulls.items():
        if _worker_pr_identity(repo, pull, bot) is None:
            continue
        for issue in linked_issue_numbers(pull):
            links.setdefault(issue, set()).add(number)
    return links


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
) -> tuple[list[IssueAction], list[PullAction], set[str]]:
    live_by_issue: set[tuple[str, int]] = set()
    dead_claims: set[str] = set()
    dead_by_issue: set[tuple[str, int]] = set()
    for lease in leases:
        holder = parse_holder(lease["holder"])
        key = (holder.repo, holder.issue)
        decision = lease_states[lease["claim_id"]]
        if decision.state == "dead":
            dead_claims.add(lease["claim_id"])
            dead_by_issue.add(key)
        else:  # Unknown is deliberately treated as live for issue-state mutation.
            live_by_issue.add(key)

    actions: list[IssueAction] = []
    for repo, repo_issues in issues.items():
        links = _current_links(repo, pulls[repo], bot_login)
        for number, issue in repo_issues.items():
            key = (repo, number)
            labels = _labels(issue, f"target issue {repo}#{number}")
            used = attempts[key]
            # An open PROVEN worker PR for this issue means the final allowed attempt SUCCEEDED —
            # parking the source issue (`needs:user`) would strip that PR from dispatch's review
            # loop (any source `needs:*` is terminal there), so exhaustion never defers while an
            # ADMITTED attempt is open. Admission is `_admitted_worker_prs` — the review loop's
            # own identity + registry-provenance checks — NEVER the loose `links` map below: an
            # arbitrary PR whose body says `Fixes #N` (or a fork with a worker-shaped head) must
            # not hold an exhausted issue out of `needs:user` (review round 1). This guard must
            # run FIRST so a successful last attempt is not mis-parked.
            if (
                used >= limits[repo].max_attempts
                and key not in live_by_issue
                and number not in admitted[repo]
            ):
                actions.append(
                    IssueAction(repo, number, "defer", "attempt budget exhausted")
                )
                continue
            if key in live_by_issue or number in links:
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

    pull_actions = [
        PullAction(repo, number, reason)
        for (repo, number), reason in sorted(stale_prs.items())
    ]
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
    limits = load_limits(Path(args.policy_file), Path(args.policy_resolver))
    registry_api = GitHubAPI(os.environ.get("REGISTRY_GH_TOKEN", ""), "registry")
    registry_api.registry_repo = registry_repo
    # Per-owner target App-token map (issue #168): one client per enabled-policy owner, so each
    # target repo is read/written under ITS owner's token — never a wrong-owner token that 404s
    # and aborts the whole sweep before dead-lease release.
    target_apis = {
        owner: GitHubAPI(token, f"target {owner}")
        for owner, token in target_tokens_map().items()
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
    for repo, api in groomable.items():
        repo_limits = limits[repo]
        issues[repo] = _issues(api, repo)
        pulls[repo] = _pulls(api, repo)
        for number, issue in issues[repo].items():
            comments = _comments(api, repo, number) if issue["comments"] else []
            attempts[(repo, number)] = count_attempts(comments, bot_login)
        for number, pull in pulls[repo].items():
            if (
                now - _epoch(pull["updated_at"], f"target pull request {repo}#{number}")
                < repo_limits.threshold_seconds
            ):
                continue
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
            if reason:
                stale_prs[(repo, number)] = reason

    admitted = {
        repo: _admitted_worker_prs(repo, pulls[repo], bot_login, ledger_root=ledger_root)
        for repo in groomable
    }
    issue_actions, pull_actions, dead_claims = _plan_actions(
        limits, issues, pulls, admitted, attempts, lease_states, leases, stale_prs, now,
        bot_login,
    )

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
    current_pulls = {repo: _pulls(api, repo) for repo, api in groomable.items()}
    current_links = {
        repo: _current_links(repo, repo_pulls, bot_login)
        for repo, repo_pulls in current_pulls.items()
    }

    reset = 0
    deferred = 0
    for action in issue_actions:
        api = groomable[action.repo]
        key = (action.repo, action.number)
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
            elif action.number in current_links[action.repo]:
                print(f"SKIP issue {action.repo}#{action.number}: an open PR appeared")
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
            # GitHub's own read-to-write gap, and since `needs:user` is terminal for the review
            # loop (no automated repair), skipping — the fail-closed side, retried next sweep —
            # wins any tie.
            if action.number in _admitted_worker_prs(
                action.repo, _pulls(api, action.repo), bot_login, ledger_root=ledger_root
            ):
                print(
                    f"SKIP issue {action.repo}#{action.number}: an admitted worker PR is open"
                )
                continue
        changed = _apply_labels(api, action.repo, action.number, labels, mode)
        if changed and mode == "ready":
            reset += 1
        elif changed:
            deferred += 1

    stale_count = 0
    for action in pull_actions:
        api = groomable[action.repo]
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
        labels = _labels(pull, f"target pull request {action.repo}#{action.number}")
        label_changed = False
        if "needs:user" not in labels:
            _ensure_label(api, action.repo, "needs:user")
            api.request(
                "POST",
                f"/repos/{action.repo}/issues/{action.number}/labels",
                {"labels": ["needs:user"]},
            )
            print(
                f"WRITE add labels repo={action.repo} issue={action.number} labels=needs:user"
            )
            label_changed = True
        comments = _comments(api, action.repo, action.number)
        already_commented = any(
            comment["user"]["login"].casefold() == bot_login.casefold()
            and STALE_PR_MARKER in comment["body"]
            for comment in comments
        )
        comment_changed = False
        if not already_commented:
            body = (
                "> 🤖 SPARQ agent\n\n"
                f"This worker PR has been untouched beyond the {limits[action.repo].worker_timeout_minutes}-"
                f"minute maintenance threshold, and {reason}. Grooming will not close, merge, or force-push "
                "it; human review is required.\n\n"
                f"{STALE_PR_MARKER}"
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

    reclaimed = _release_claims(registry_api, registry_repo, dead_claims)
    print(
        f"SUMMARY reclaimed={reclaimed} reset={reset} deferred={deferred} stale_prs={stale_count}"
    )
    return reclaimed, reset, deferred, stale_count


def _self_test() -> int:
    ok = True

    def check(name: str, got: Any, want: Any) -> None:
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    now = 10_000
    limits = Limits(worker_timeout_minutes=10, max_attempts=2)
    base = {
        "account": "acct01",
        "claim_id": "a" * 32,
        "holder": "owner/repo#7@dispatch-123.1",
        "package": "crate-a",
        "role": "impl",
        "model": "terra",
        "issued_at": now - 100,
        "expires_at": now + 600,
    }
    active = {
        "status": "in_progress",
        "conclusion": None,
        "path": ".github/workflows/worker.yml",
    }
    complete = {
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
    comments = [
        {"user": {"login": "app[bot]"}, "body": ATTEMPT_MARKER + " run=1 -->"},
        {"user": {"login": "APP[bot]"}, "body": ATTEMPT_MARKER + " run=2 -->"},
        {"user": {"login": "human"}, "body": ATTEMPT_MARKER},
    ]
    check("bot-only attempt count", count_attempts(comments, "app[bot]"), 2)
    check(
        "ready transition is idempotent",
        label_transition({"status:ready"}, "ready"),
        (set(), set()),
    )
    check(
        "defer transition removes dispatch state",
        label_transition({"status:ready", "status:in-progress"}, "defer"),
        ({"needs:user", "status:deferred"}, {"status:ready", "status:in-progress"}),
    )
    check(
        "ready transition clears the review-loop label",
        label_transition({"status:in-progress-review"}, "ready"),
        ({"status:ready"}, {"status:in-progress-review"}),
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
        # atom) and issue (positive int), the two fields the round-3 partial predicate missed.
        valid_record = {
            "pr_number": 99,
            "head_sha_at_open": "1" * 40,
            "impl_provider": "anthropic",
            "impl_alias": "fable",
            "impl_account_h": "ab" * 8,
            "issue": 7,
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

    # ---- _admitted_worker_prs: the admission that gates exhaustion suppression (round 1) ----
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
            _admitted_worker_prs("owner/repo", {91: proven_pull}, "app[bot]", admit_root),
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
            _admitted_worker_prs("owner/repo", {92: arbitrary_pull}, "app[bot]", admit_root),
            set(),
        )
        # issue #172: `_current_links` (recovery-suppression linkage) now applies the SAME
        # worker-PR identity gate, so an untrusted PR can no longer hold a stale issue out of
        # recovery. Unlike `_admitted_worker_prs` it does NOT require a provenance record (see its
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
            _admitted_worker_prs("owner/repo", {91: fork_pull}, "app[bot]", admit_root),
            set(),
        )
        check(
            "NEGATIVE: a worker-shaped branch from a NON-BOT author is NOT admitted",
            _admitted_worker_prs(
                "owner/repo",
                {91: {**proven_pull, "user": {"login": "mallory"}}},
                "app[bot]",
                admit_root,
            ),
            set(),
        )
        check(
            "NEGATIVE: a bot worker branch WITHOUT the worker PR marker is NOT admitted",
            _admitted_worker_prs(
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
            _admitted_worker_prs("owner/repo", {93: unrecorded_pull}, "app[bot]", admit_root),
            set(),
        )
        check(
            "NEGATIVE: a record whose issue disagrees with the branch-encoded issue is refused",
            _admitted_worker_prs(
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
            _admitted_worker_prs("owner/repo", {91: proven_pull}, "", admit_root),
            set(),
        )

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

    malformed_failed = False
    try:
        validate_ledger({"leases": [{**base, "claim_id": "unsafe"}]})
    except GroomError:
        malformed_failed = True
    check("malformed ledger fails closed", malformed_failed, True)

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
                        "account": "a", "claim_id": dead, "holder": "owner/repo#7@run.1",
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

    # ---- run_sweep mutation-boundary guard (issue #170, review round 1, finding 3) ----
    # Drive the REAL run_sweep with a stubbed API in which the open-PR listing is SCHEDULED per
    # read: the plan read (#1) and pre-loop snapshot read (#2) see NO pulls, and only the defer
    # branch's mutation-boundary re-read (#3) sees the freshly opened admitted worker PR. The
    # discriminating pair: (A) the PR appears at the boundary → NO label mutation may occur
    # (deleting or inverting the run_sweep defer-branch guard, or reverting it to the pre-loop
    # snapshot, reds this — the snapshot never saw the PR); (B) no PR ever appears → the defer
    # mutation MUST occur (an inverted guard, or one keyed on anything but the fresh read, reds
    # this instead).
    sweep_env: dict[str, Any] = {}

    class _SweepAPI:
        """Serve run_sweep's reads from fixtures; record every write. Listing reads of the
        target's open PRs are counted so the qualifying PR can 'appear' mid-sweep."""

        def __init__(self, token, purpose):
            self.purpose = purpose

        def request(self, method, path, body=None, allow_404=False, **_kwargs):
            if method == "GET":
                return sweep_env["gets"].get(path)
            sweep_env["writes"].append((method, path))
            return {}

        def paginate(self, path):
            if path == "/repos/owner/repo/pulls?state=open":
                sweep_env["pull_reads"] += 1
                if sweep_env["pull_reads"] >= sweep_env["pr_visible_from"]:
                    return [sweep_env["worker_pull"]]
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
    sweep_env["gets"] = {"/repos/owner/repo/issues/8": sweep_issue}
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

    def _sweep_scenario(pr_visible_from: int) -> tuple[int, int, int, int]:
        sweep_env.update(pull_reads=0, pr_visible_from=pr_visible_from, writes=[])
        return run_sweep(argparse.Namespace(
            registry_repo="owner/registry",
            policy_file="unused-policy",
            policy_resolver="unused-resolver",
            bot_slug="app",
            ledger_root="",
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
            # (A) The admitted worker PR opens AFTER the pre-loop snapshot (listing read #2) and
            # is first visible to the mutation-boundary re-read (#3): NO label write may land.
            summary_a = _sweep_scenario(pr_visible_from=3)
            check(
                "MUTATION boundary: a post-snapshot admitted worker PR suppresses the defer WRITE",
                (summary_a, sweep_env["writes"]),
                ((0, 0, 0, 0), []),
            )
            check(
                "MUTATION boundary: the guard actually RE-READ open PRs at the boundary",
                sweep_env["pull_reads"] >= 3,
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
    finally:
        os.chdir(sweep_prior_cwd)
        globals().update(sweep_saved)

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
    parser.add_argument("--registry-repo")
    parser.add_argument("--policy-file", default="policy/repos.toml")
    parser.add_argument("--policy-resolver", default="scripts/policy-resolve.py")
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
    if args.print_owner_repos:
        try:
            for line in owner_repo_output_lines(_policy_document(Path(args.policy_file))):
                print(line)
        except GroomError as exc:
            print(f"groom: {exc}", file=sys.stderr)
            return 1
        return 0
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
