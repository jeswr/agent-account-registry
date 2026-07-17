#!/usr/bin/env python3
# [GPT-5.6] REG-5 fail-closed maintenance sweep for the private-registry orchestrator.
"""Reclaim dead worker leases and conservatively repair target orchestration state.

The live path uses two deliberately separate credentials: ``REGISTRY_GH_TOKEN`` may only update
the private registry lease ledger and inspect registry Actions runs, while ``TARGET_GH_TOKEN`` is
a target-scoped GitHub App token used for issue and pull-request reads/writes. Tokens are never
accepted on the command line or included in diagnostics.

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
import re
import sys
import time
import tomllib
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


LEDGER_PATH = "data/leases.json"
ATTEMPT_MARKER = "<!-- sparq-worker-attempt:v1"
STALE_PR_MARKER = "<!-- registry-groom-stale-pr:v1 -->"
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


def stale_worker_pr_reason(
    pull: dict[str, Any], bot_login: str, threshold_seconds: int, now: int
) -> str | None:
    """Return why an old worker PR needs attention, or None when it should remain untouched."""
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
        return "the worker pull request is still a draft"
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


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location("registry_policy_resolve", path)
    if spec is None or spec.loader is None:
        raise GroomError("cannot load policy-resolve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_limits(policy_file: Path, resolver_file: Path) -> dict[str, Limits]:
    try:
        with policy_file.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GroomError("repository policy could not be read") from exc
    repos = document.get("repos") if isinstance(document, dict) else None
    if not isinstance(repos, dict) or not repos:
        raise GroomError("repository policy has no target rows")
    resolver = _load_module(resolver_file)
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


def _read_ledger(
    api: GitHubAPI, registry_repo: str
) -> tuple[list[dict[str, Any]], str]:
    result = api.request("GET", f"/repos/{registry_repo}/contents/{LEDGER_PATH}")
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


def _release_claims(
    api: GitHubAPI, registry_repo: str, claims: set[str], retries: int = 6
) -> int:
    if not claims:
        return 0
    for _ in range(retries):
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
                {
                    "message": f"groom {len(present)} dead lease(s)",
                    "content": encoded,
                    "sha": sha,
                },
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


def _current_links(pulls: dict[int, dict[str, Any]]) -> dict[int, set[int]]:
    links: dict[int, set[int]] = {}
    for number, pull in pulls.items():
        for issue in linked_issue_numbers(pull):
            links.setdefault(issue, set()).add(number)
    return links


def _plan_actions(
    limits: dict[str, Limits],
    issues: dict[str, dict[int, dict[str, Any]]],
    pulls: dict[str, dict[int, dict[str, Any]]],
    attempts: dict[tuple[str, int], int],
    lease_states: dict[str, LeaseDecision],
    leases: list[dict[str, Any]],
    stale_prs: dict[tuple[str, int], str],
    now: int,
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
        links = _current_links(pulls[repo])
        for number, issue in repo_issues.items():
            key = (repo, number)
            labels = _labels(issue, f"target issue {repo}#{number}")
            used = attempts[key]
            if used >= limits[repo].max_attempts and key not in live_by_issue:
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


def run_sweep(args: argparse.Namespace) -> tuple[int, int, int, int]:
    registry_repo = args.registry_repo
    if SAFE_REPO.fullmatch(registry_repo) is None:
        raise GroomError("registry repo must be a safe owner/name")
    limits = load_limits(Path(args.policy_file), Path(args.policy_resolver))
    registry_api = GitHubAPI(os.environ.get("REGISTRY_GH_TOKEN", ""), "registry")
    registry_api.registry_repo = registry_repo
    target_api = GitHubAPI(os.environ.get("TARGET_GH_TOKEN", ""), "target")
    bot_login = _bot_login(target_api, getattr(args, "bot_slug", "") or "")
    now = int(time.time())

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
    for repo, repo_limits in limits.items():
        issues[repo] = _issues(target_api, repo)
        pulls[repo] = _pulls(target_api, repo)
        for number, issue in issues[repo].items():
            comments = _comments(target_api, repo, number) if issue["comments"] else []
            attempts[(repo, number)] = count_attempts(comments, bot_login)
        for number, pull in pulls[repo].items():
            if (
                now - _epoch(pull["updated_at"], f"target pull request {repo}#{number}")
                < repo_limits.threshold_seconds
            ):
                continue
            detail = target_api.request("GET", f"/repos/{repo}/pulls/{number}")
            if not isinstance(detail, dict):
                raise GroomError(
                    f"target pull request detail is malformed for {repo}#{number}"
                )
            reason = stale_worker_pr_reason(
                detail, bot_login, repo_limits.threshold_seconds, now
            )
            if reason:
                stale_prs[(repo, number)] = reason

    issue_actions, pull_actions, dead_claims = _plan_actions(
        limits, issues, pulls, attempts, lease_states, leases, stale_prs, now
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
    current_pulls = {repo: _pulls(target_api, repo) for repo in limits}
    current_links = {
        repo: _current_links(repo_pulls) for repo, repo_pulls in current_pulls.items()
    }

    reset = 0
    deferred = 0
    for action in issue_actions:
        key = (action.repo, action.number)
        if key in fresh_live_issues:
            print(f"SKIP issue {action.repo}#{action.number}: a live lease appeared")
            continue
        issue = _fresh_issue(target_api, action.repo, action.number)
        if issue is None or issue.get("state") != "open":
            print(f"SKIP issue {action.repo}#{action.number}: no longer open")
            continue
        labels = _labels(issue, f"target issue {action.repo}#{action.number}")
        mode = action.mode
        if mode == "ready":
            current_comments = (
                _comments(target_api, action.repo, action.number)
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
                _comments(target_api, action.repo, action.number)
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
        changed = _apply_labels(target_api, action.repo, action.number, labels, mode)
        if changed and mode == "ready":
            reset += 1
        elif changed:
            deferred += 1

    stale_count = 0
    for action in pull_actions:
        pull = target_api.request(
            "GET", f"/repos/{action.repo}/pulls/{action.number}", allow_404=True
        )
        if not isinstance(pull, dict) or pull.get("state") != "open":
            print(f"SKIP PR {action.repo}#{action.number}: no longer open")
            continue
        reason = stale_worker_pr_reason(
            pull, bot_login, limits[action.repo].threshold_seconds, now
        )
        if reason is None:
            print(f"SKIP PR {action.repo}#{action.number}: no longer stale/failing")
            continue
        labels = _labels(pull, f"target pull request {action.repo}#{action.number}")
        label_changed = False
        if "needs:user" not in labels:
            _ensure_label(target_api, action.repo, "needs:user")
            target_api.request(
                "POST",
                f"/repos/{action.repo}/issues/{action.number}/labels",
                {"labels": ["needs:user"]},
            )
            print(
                f"WRITE add labels repo={action.repo} issue={action.number} labels=needs:user"
            )
            label_changed = True
        comments = _comments(target_api, action.repo, action.number)
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
            target_api.request(
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
        stale_worker_pr_reason(old_pr, "app[bot]", limits.threshold_seconds, now),
        BAD_MERGE_STATES["blocked"],
    )
    check(
        "clean worker PR is preserved",
        stale_worker_pr_reason(
            {**old_pr, "mergeable_state": "clean"}, "app[bot]", 600, now
        ),
        None,
    )
    check("worker branch links issue", linked_issue_numbers(old_pr), {7})

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
        }
    }
    fixture_pulls = {"owner/repo": {}}
    fixture_attempts = {("owner/repo", 7): 0, ("owner/repo", 8): 2}
    fixture_states = {"a" * 32: LeaseDecision("dead", "fixture complete")}
    actions, prs, dead = _plan_actions(
        {"owner/repo": limits},
        fixture_issues,
        fixture_pulls,
        fixture_attempts,
        fixture_states,
        [base],
        {},
        now,
    )
    check(
        "fixture plans dead reset and exhaustion",
        [(action.number, action.mode) for action in actions],
        [(7, "ready"), (8, "defer")],
    )
    check("fixture reclaims dead claim", dead, {"a" * 32})
    check("fixture has no PR writes", prs, [])

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
    linked_pull = {
        "updated_at": stale_at,
        "head": {"ref": "sparq-agent/issue-25-99-1"},
        "body": "Fixes #25",
    }
    orphan_attempts = {("owner/repo", n): 1 for n in (21, 22, 24, 25, 26, 27)}
    orphan_attempts[("owner/repo", 23)] = 0
    orphan_actions, _prs2, _dead2 = _plan_actions(
        {"owner/repo": limits},
        orphan_issues,
        {"owner/repo": {99: linked_pull}},
        orphan_attempts,
        {},
        [],
        {},
        now,
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

    print("groom self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--registry-repo")
    parser.add_argument("--policy-file", default="policy/repos.toml")
    parser.add_argument("--policy-resolver", default="scripts/policy-resolve.py")
    parser.add_argument(
        "--bot-slug",
        default="",
        help="GitHub App slug from the token mint step (an installation token cannot GET /user)",
    )
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
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
