#!/usr/bin/env python3
"""Deterministically curate unstaged work into a small, conflict-free ready frontier.

The enabled target list and additional trusted automation identities come from
``policy/repos.toml``.  The default mode is a read-only dry run; ``--apply`` is the only path
that mutates target issues.  No issue labels are ever removed.
"""
import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any


TARGET_READY = 12
MAX_CLOSES = 5
GATE_LABELS = ("needs:", "trust:untrusted")
TRUSTED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
IN_FLIGHT_STATUS = {"status:ready", "status:in-progress"}
TRUST_LABEL_PREFIXES = (
    "area:sparq-zk", "area:sparq-mpc", "area:zk", "area:mpc", "area:trust",
    "area:sparq-trust", "area:e2ee", "area:sparq-e2ee", "zk", "mpc",
)
TRUST_KEYWORDS = (
    "zk", "zkp", "mpc", "noir", "secprop", "nullifier", "e2ee", "crypt",
    "issuer", "credential", "trust anchor",
)
EC2_KEYWORDS = (
    "quiet-box", "ec2", "canonical gather", "same-box", "full-scale",
    "nightly gather", "gather run",
)
WELL_SPECIFIED_LABELS = {"self-improvement", "from:agent", "drift"}
SAFE_REPO = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*"
)
_PATH = re.compile(
    r"(?<![A-Za-z0-9_])(?:\.github|[A-Za-z0-9_.-]+)"
    r"(?:/[A-Za-z0-9_.-]+)+"
)
_FILE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9_.-]+\.)"
    r"(?:rs|py|sh|toml|ya?ml|json|md|ts|tsx|js|jsx|html|css)\b",
    re.IGNORECASE,
)
_FUNCTION = re.compile(
    r"\b(?:def|fn|function|method)\s+[A-Za-z_][A-Za-z0-9_]*\b"
    r"|\b[A-Za-z_][A-Za-z0-9_:.-]*\(\)",
    re.IGNORECASE,
)
_LINE = re.compile(
    r"\bline\s+[1-9][0-9]*\b|(?<![A-Za-z0-9_])L[1-9][0-9]*\b"
    r"|\b[A-Za-z0-9_./-]+\.[A-Za-z0-9]+:[1-9][0-9]*\b",
    re.IGNORECASE,
)
_CODE_ONLY_BENCH = re.compile(
    r"\b(?:fix|wire|repair|refactor|update|change|implement|add|modify)\b"
    r".{0,80}\b(?:scripts?|harness)\b"
    r"|\b(?:scripts?|harness)\b.{0,80}"
    r"\b(?:fix|wire|repair|refactor|update|change|implement|add|modify)\b",
    re.IGNORECASE | re.DOTALL,
)
_P2 = re.compile(
    r"\bci(?:\s+is)?\s+red\b|\bdeadlock(?:ed|s|ing)?\b|\bbricks?\b"
    r"|\bblocks\s+all\b",
    re.IGNORECASE,
)


class CuratorError(RuntimeError):
    """A fail-closed configuration, snapshot, or API error."""


@dataclass(frozen=True)
class Mutation:
    kind: str
    number: int
    issue: dict[str, Any]
    labels: tuple[str, ...] = ()
    canonical: int | None = None
    canonical_issue: dict[str, Any] | None = None


def labels_of(issue: dict[str, Any]) -> set[str]:
    raw = issue.get("labels")
    if not isinstance(raw, list):
        raise CuratorError("issue labels are malformed")
    result = set()
    for label in raw:
        name = label.get("name") if isinstance(label, dict) else label
        if not isinstance(name, str) or not name:
            raise CuratorError("issue carries a malformed label")
        result.add(name)
    return result


def is_open_issue(issue: Any) -> bool:
    return (
        isinstance(issue, dict)
        and "pull_request" not in issue
        and str(issue.get("state", "")).lower() == "open"
        and isinstance(issue.get("number"), int)
    )


def has_gate(labels: set[str]) -> bool:
    """Mirror ready-issues.py: every needs:* label and trust:untrusted are hard gates."""
    return any(label == gate or label.startswith(gate)
               for label in labels for gate in GATE_LABELS)


def has_status(labels: set[str]) -> bool:
    return any(label.startswith("status:") for label in labels)


def author_login(issue: dict[str, Any]) -> str:
    user = issue.get("user")
    login = user.get("login") if isinstance(user, dict) else None
    return login if isinstance(login, str) else ""


def trusted_author(issue: dict[str, Any], automation_logins: set[str]) -> bool:
    """Mirror dispatch CLAIM: collaborator association or exact allowlisted automation login."""
    login = author_login(issue)
    association = str(issue.get("author_association", "")).upper()
    return bool(login) and (
        association in TRUSTED_ASSOCIATIONS or login in automation_logins
    )


def is_automation_author(issue: dict[str, Any], automation_logins: set[str]) -> bool:
    return author_login(issue) in automation_logins


def issue_text(issue: dict[str, Any]) -> str:
    title = issue.get("title")
    body = issue.get("body")
    if not isinstance(title, str) or not isinstance(body, (str, type(None))):
        raise CuratorError("issue title/body are malformed")
    return f"{title}\n{body or ''}"


def is_trust_surface(issue: dict[str, Any], labels: set[str]) -> bool:
    folded_labels = {label.casefold() for label in labels}
    if any(label.startswith(prefix) for label in folded_labels
           for prefix in TRUST_LABEL_PREFIXES):
        return True
    folded = issue_text(issue).casefold()
    return any(keyword in folded for keyword in TRUST_KEYWORDS)


def is_ec2_measurement(issue: dict[str, Any]) -> bool:
    text = issue_text(issue)
    folded = text.casefold()
    title = issue.get("title")
    if not isinstance(title, str):
        raise CuratorError("issue title is malformed")
    return any(keyword in folded for keyword in EC2_KEYWORDS) and not _CODE_ONLY_BENCH.search(title)


def is_well_specified(issue: dict[str, Any], labels: set[str]) -> bool:
    body = issue.get("body") or ""
    if not isinstance(body, str) or len(body) < 200:
        return False
    concrete = any(pattern.search(body) for pattern in (_PATH, _FILE, _FUNCTION, _LINE))
    return concrete or bool(labels & WELL_SPECIFIED_LABELS)


def derive_area(issue: dict[str, Any], labels: set[str], repo_labels: set[str]) -> tuple[str | None, str]:
    existing = sorted(label for label in labels if label.startswith("area:"))
    if len(existing) == 1:
        return existing[0], "existing"
    if len(existing) > 1:
        return None, "multiple existing area labels"

    title = str(issue.get("title", ""))
    crates = {
        f"area:{name.casefold()}"
        for name in re.findall(r"\bsparq-[A-Za-z0-9][A-Za-z0-9-]*\b", title, re.IGNORECASE)
        if f"area:{name.casefold()}" in repo_labels
    }
    if len(crates) == 1:
        return next(iter(crates)), "title crate"
    if len(crates) > 1:
        return None, "multiple crate areas in title"

    text = issue_text(issue)
    hints = set()
    path_hints = (
        (r"(?<![A-Za-z0-9_.-])site/", "area:site"),
        (r"(?<![A-Za-z0-9_.-])gui/", "area:gui"),
        (r"(?<![A-Za-z0-9_.-])bench/", "area:bench"),
        (r"(?<![A-Za-z0-9_.-])(?:\.github(?:/|\b)|scripts/)", "area:ci"),
    )
    for pattern, area in path_hints:
        if area in repo_labels and re.search(pattern, text, re.IGNORECASE):
            hints.add(area)
    if len(hints) == 1:
        return next(iter(hints)), "path hint"
    if len(hints) > 1:
        return None, "multiple path-hint areas"
    return None, "no existing label, crate, or path hint maps to a repository area"


def role_for(labels: set[str], area: str) -> str:
    if "kind:docs" in labels:
        return "role:docs"
    if "kind:perf" in labels:
        return "role:perf"
    if area == "area:ci":
        return "role:ci"
    if area == "area:site":
        return "role:site"
    return "role:impl"


def priority_for(issue: dict[str, Any]) -> str:
    return "priority:P2" if _P2.search(issue_text(issue)) else "priority:P3"


def normalized_title(issue: dict[str, Any]) -> frozenset[str]:
    title = issue.get("title")
    if not isinstance(title, str):
        raise CuratorError("issue title is malformed")
    return frozenset(re.findall(r"[a-z0-9]+", title.casefold()))


def title_jaccard(left: dict[str, Any], right: dict[str, Any]) -> float:
    a, b = normalized_title(left), normalized_title(right)
    return len(a & b) / len(a | b) if a and b else 0.0


def duplicate_components(issues: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Connected components of the >=0.7 title-token Jaccard graph."""
    ordered = sorted(issues, key=lambda issue: issue["number"])
    parent = list(range(len(ordered)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        a, b = find(left), find(right)
        if a != b:
            parent[max(a, b)] = min(a, b)

    for left in range(len(ordered)):
        for right in range(left + 1, len(ordered)):
            if title_jaccard(ordered[left], ordered[right]) >= 0.7:
                union(left, right)

    groups: dict[int, list[dict[str, Any]]] = {}
    for index, issue in enumerate(ordered):
        groups.setdefault(find(index), []).append(issue)
    return [group for group in groups.values() if len(group) > 1]


def _conflicting_label(labels: set[str], prefix: str, desired: str) -> bool:
    return any(label.startswith(prefix) and label != desired for label in labels)


def plan_repository(
    issues: list[dict[str, Any]],
    repo_labels: set[str],
    automation_logins: set[str],
    close_limit: int = MAX_CLOSES,
    target_ready: int = TARGET_READY,
) -> tuple[list[Mutation], list[str]]:
    """Return a deterministic mutation plan and human-readable skip log for one target."""
    if close_limit < 0:
        raise CuratorError("close limit cannot be negative")
    _validated_target_ready(target_ready)
    open_issues = sorted((issue for issue in issues if is_open_issue(issue)),
                         key=lambda issue: issue["number"])
    logs: list[str] = []
    ec2_actions: list[Mutation] = []
    safe_candidates: dict[int, dict[str, Any]] = {}

    for issue in open_issues:
        labels = labels_of(issue)
        number = issue["number"]
        if has_status(labels) or has_gate(labels):
            continue
        if not trusted_author(issue, automation_logins):
            logs.append(f"skip #{number}: untrusted author")
            continue
        if is_trust_surface(issue, labels):
            logs.append(f"skip #{number}: trust-surface content")
            continue
        if is_ec2_measurement(issue):
            if "needs:ec2" not in repo_labels:
                raise CuratorError("target repository is missing required label needs:ec2")
            ec2_actions.append(Mutation("needs-ec2", number, issue, ("needs:ec2",)))
            logs.append(f"gate #{number}: EC2 measurement work -> needs:ec2")
            continue
        safe_candidates[number] = issue

    # Every status:* issue is protected but participates in dedupe, so a new candidate cannot be
    # staged beside work that the pipeline has already admitted.
    staged = {
        issue["number"]: issue for issue in open_issues if has_status(labels_of(issue))
    }
    dedupe_pool = list({**staged, **safe_candidates}.values())
    components = duplicate_components(dedupe_pool)
    canonical_for: dict[int, int] = {}
    component_status: dict[int, list[int]] = {}
    close_options: list[Mutation] = []
    for component in components:
        component = sorted(component, key=lambda issue: issue["number"])
        canonical = component[0]
        canonical_number = canonical["number"]
        status_numbers = [
            issue["number"] for issue in component if has_status(labels_of(issue))
        ]
        for issue in component:
            canonical_for[issue["number"]] = canonical_number
            component_status[issue["number"]] = status_numbers
        for duplicate in component[1:]:
            number = duplicate["number"]
            labels = labels_of(duplicate)
            if (
                number in safe_candidates
                and not has_status(labels)
                and is_automation_author(duplicate, automation_logins)
            ):
                close_options.append(Mutation(
                    "close", number, duplicate, canonical=canonical_number,
                    canonical_issue=canonical,
                ))
            elif number in safe_candidates:
                logs.append(f"keep #{number}: duplicate of #{canonical_number} is human-authored")

    close_options.sort(key=lambda mutation: (mutation.canonical or 0, mutation.number))
    close_actions = close_options[:close_limit]
    for mutation in close_actions:
        logs.append(f"close #{mutation.number}: duplicate of canonical #{mutation.canonical}")
    if len(close_options) > close_limit:
        logs.append(f"defer {len(close_options) - close_limit} duplicate close(s): run cap is {close_limit}")

    current_ready = sum(
        1 for issue in open_issues if "status:ready" in labels_of(issue)
    )
    depth = max(0, target_ready - current_ready)
    in_flight_areas = {
        label
        for issue in open_issues
        if labels_of(issue) & IN_FLIGHT_STATUS
        for label in labels_of(issue)
        if label.startswith("area:")
    }
    stage_options: list[tuple[int, int, str, tuple[str, ...], dict[str, Any]]] = []
    closing_numbers = {mutation.number for mutation in close_actions}

    for number, issue in sorted(safe_candidates.items()):
        if number in closing_numbers:
            continue
        canonical = canonical_for.get(number, number)
        if canonical != number:
            logs.append(f"skip #{number}: duplicate of canonical #{canonical}")
            continue
        staged_duplicates = [n for n in component_status.get(number, []) if n != number]
        if staged_duplicates:
            refs = ", ".join(f"#{n}" for n in staged_duplicates)
            logs.append(f"skip #{number}: duplicate cluster already carries status at {refs}")
            continue
        labels = labels_of(issue)
        if not is_well_specified(issue, labels):
            logs.append(f"skip #{number}: not well-specified")
            continue
        area, area_reason = derive_area(issue, labels, repo_labels)
        if area is None:
            logs.append(f"skip #{number}: no confident area ({area_reason})")
            continue
        role = role_for(labels, area)
        priority = priority_for(issue)
        if _conflicting_label(labels, "priority:", priority):
            logs.append(f"skip #{number}: existing priority conflicts with {priority}")
            continue
        if _conflicting_label(labels, "role:", role):
            logs.append(f"skip #{number}: existing role conflicts with {role}")
            continue
        desired = ("status:ready", priority, role, area)
        missing = sorted(set(desired) - repo_labels)
        if missing:
            raise CuratorError("target repository is missing staging labels: " + ", ".join(missing))
        stage_options.append((int(priority[-1]), number, area, desired, issue))

    stage_options.sort(key=lambda item: (item[0], item[1]))
    selected_areas: set[str] = set()
    stage_actions: list[Mutation] = []
    area_limited = False
    for _priority, number, area, desired, issue in stage_options:
        if len(stage_actions) >= depth:
            break
        if area in in_flight_areas:
            area_limited = True
            logs.append(f"skip #{number}: {area} already has in-flight work")
            continue
        if area in selected_areas:
            area_limited = True
            logs.append(f"skip #{number}: this wave already selected {area}")
            continue
        selected_areas.add(area)
        stage_actions.append(Mutation("stage", number, issue, desired))
        logs.append(f"stage #{number}: {','.join(desired)}")

    if area_limited and len(stage_actions) < depth:
        resulting_ready = current_ready + len(stage_actions)
        busy_areas = len(in_flight_areas | selected_areas)
        logs.append(
            f"frontier: area-limited at {resulting_ready}/{target_ready} "
            f"({busy_areas} areas busy)"
        )

    return ec2_actions + close_actions + stage_actions, logs


def _flatten_pages(document: Any, kind: str) -> list[dict[str, Any]]:
    if not isinstance(document, list):
        raise CuratorError(f"{kind} pagination result is malformed")
    items: list[dict[str, Any]] = []
    for page in document:
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            raise CuratorError(f"{kind} pagination page is malformed")
        items.extend(page)
    return items


def _gh_env(token: str) -> dict[str, str]:
    if not token:
        raise CuratorError("target GitHub token is missing")
    env = dict(os.environ)
    env.pop("TARGET_GH_TOKENS", None)
    env["GH_TOKEN"] = token
    return env


def _gh_json(args: list[str], token: str) -> Any:
    try:
        result = subprocess.run(
            ["gh", *args], capture_output=True, text=True, check=True, env=_gh_env(token)
        )
        return json.loads(result.stdout or "null")
    except FileNotFoundError as exc:
        raise CuratorError("gh is unavailable") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "gh command failed").strip()
        raise CuratorError(detail) from exc
    except json.JSONDecodeError as exc:
        raise CuratorError("gh returned malformed JSON") from exc


def fetch_repository(repo: str, token: str) -> tuple[list[dict[str, Any]], set[str]]:
    issue_pages = _gh_json([
        "api", "--paginate", "--slurp", f"repos/{repo}/issues?state=open&per_page=100"
    ], token)
    raw_issues = _flatten_pages(issue_pages, "issue")
    if len(raw_issues) >= 10000:
        raise CuratorError(f"{repo} issue snapshot reached the 10000-item safety ceiling")
    issues = [issue for issue in raw_issues if "pull_request" not in issue]

    label_pages = _gh_json([
        "api", "--paginate", "--slurp", f"repos/{repo}/labels?per_page=100"
    ], token)
    raw_labels = _flatten_pages(label_pages, "label")
    if len(raw_labels) >= 5000:
        raise CuratorError(f"{repo} label snapshot reached the 5000-item safety ceiling")
    labels = set()
    for label in raw_labels:
        name = label.get("name")
        if not isinstance(name, str) or not name:
            raise CuratorError(f"{repo} returned a malformed label")
        labels.add(name)
    return issues, labels


def _fingerprint(issue: dict[str, Any]) -> tuple[Any, ...]:
    return (
        issue.get("number"), str(issue.get("state", "")).lower(),
        "pull_request" in issue, issue.get("title"), issue.get("body") or "",
        tuple(sorted(labels_of(issue))), author_login(issue),
        str(issue.get("author_association", "")).upper(),
    )


def _live_issue(repo: str, number: int, token: str) -> dict[str, Any]:
    issue = _gh_json(["api", f"repos/{repo}/issues/{number}"], token)
    if not isinstance(issue, dict):
        raise CuratorError(f"{repo}#{number} live issue is malformed")
    return issue


def execute_plan(repo: str, mutations: list[Mutation], token: str, apply: bool) -> int:
    """Apply snapshot-revalidated mutations; return the number of actual duplicate closes."""
    closed = 0
    mode = "apply" if apply else "dry-run"
    for mutation in mutations:
        if mutation.kind == "needs-ec2":
            description = "add needs:ec2"
        elif mutation.kind == "close":
            description = f"close as not planned (duplicate of #{mutation.canonical})"
        else:
            description = "add " + ",".join(mutation.labels)
        print(f"{mode} {repo}#{mutation.number}: {description}")
        if not apply:
            continue

        current = _live_issue(repo, mutation.number, token)
        if _fingerprint(current) != _fingerprint(mutation.issue):
            print(f"skip {repo}#{mutation.number}: issue changed since snapshot")
            continue
        if mutation.kind == "close":
            assert mutation.canonical is not None and mutation.canonical_issue is not None
            canonical = _live_issue(repo, mutation.canonical, token)
            if _fingerprint(canonical) != _fingerprint(mutation.canonical_issue):
                print(f"skip {repo}#{mutation.number}: canonical #{mutation.canonical} changed")
                continue
            comment = (
                f"> 🤖 SPARQ agent — closing this duplicate in favor of canonical "
                f"issue #{mutation.canonical} (the lowest-numbered issue in the cluster)."
            )
            command = [
                "issue", "close", str(mutation.number), "--repo", repo,
                "--reason", "not planned", "--comment", comment,
            ]
        else:
            command = ["issue", "edit", str(mutation.number), "--repo", repo]
            for label in mutation.labels:
                command.extend(["--add-label", label])
        try:
            subprocess.run(["gh", *command], check=True, env=_gh_env(token))
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise CuratorError(f"mutation failed for {repo}#{mutation.number}") from exc
        if mutation.kind == "close":
            closed += 1
    return closed


def _validated_target_ready(value: Any, repo: str | None = None) -> int:
    context = f" for {repo}" if repo else ""
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= 100
    ):
        raise CuratorError(f"target_ready{context} must be an integer in [1, 100]")
    return value


def _target_ready_of(repo: str, row: dict[str, Any]) -> int:
    throughput = row.get("throughput")
    if throughput is None:
        return TARGET_READY
    if not isinstance(throughput, dict):
        raise CuratorError(f"throughput policy for {repo} must be a table")
    return _validated_target_ready(throughput.get("target_ready", TARGET_READY), repo)


def load_targets(policy_file: Path, bot_login: str) -> list[tuple[str, set[str], int]]:
    try:
        with policy_file.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CuratorError("repository policy could not be read") from exc
    rows = document.get("repos") if isinstance(document, dict) else None
    if not isinstance(rows, dict) or not rows:
        raise CuratorError("repository policy has no target rows")
    targets = []
    for repo, row in rows.items():
        if not isinstance(repo, str) or SAFE_REPO.fullmatch(repo) is None:
            raise CuratorError("repository policy contains an unsafe target name")
        if not isinstance(row, dict) or not isinstance(row.get("enabled"), bool):
            raise CuratorError(f"repository policy enablement is malformed for {repo}")
        if not row["enabled"]:
            continue
        bots = row.get("trusted_bots", [])
        if (
            not isinstance(bots, list)
            or any(not isinstance(login, str) or not login or "\n" in login for login in bots)
            or len(set(bots)) != len(bots)
        ):
            raise CuratorError(f"trusted_bots is malformed for {repo}")
        automation = set(bots)
        if bot_login:
            automation.add(bot_login)
        targets.append((repo, automation, _target_ready_of(repo, row)))
    if not targets:
        raise CuratorError("repository policy has no enabled target rows")
    return sorted(targets, key=lambda item: item[0])


def load_tokens() -> tuple[dict[str, str], str]:
    raw = os.environ.get("TARGET_GH_TOKENS", "")
    if raw:
        try:
            tokens = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CuratorError("TARGET_GH_TOKENS is not valid JSON") from exc
        if (
            not isinstance(tokens, dict)
            or any(not isinstance(owner, str) or not isinstance(token, str) or not token
                   for owner, token in tokens.items())
        ):
            raise CuratorError("TARGET_GH_TOKENS must be a non-empty {owner: token} object")
        return tokens, ""
    return {}, os.environ.get("GH_TOKEN", "")


def _self_test() -> int:
    all_labels = {
        "status:ready", "status:in-progress", "needs:ec2",
        "priority:P2", "priority:P3", "role:impl", "role:docs", "role:perf",
        "role:ci", "role:site",
        "area:alpha", "area:beta", "area:gamma", "area:delta", "area:bench",
        "area:ci", "area:site",
    }
    long_body = ("Change scripts/frontier.py and validate compute_ready() at line 42. "
                 + "Detailed acceptance criteria. " * 12)

    def issue(number: int, title: str, labels: tuple[str, ...] = (), *,
              author: str = "registry[bot]", association: str = "NONE",
              body: str = long_body) -> dict[str, Any]:
        return {
            "number": number, "state": "open", "title": title, "body": body,
            "labels": [{"name": label} for label in labels],
            "user": {"login": author}, "author_association": association,
        }

    automation = {"registry[bot]"}
    checks: list[tuple[str, bool]] = []

    # (a) Both needs:ec2 and needs:user are caught solely by the shared prefix gate. Removing the
    # has_gate() candidate filter makes these otherwise stageable fixtures appear in stage actions.
    gated = [
        issue(1, "Improve alpha parser", ("area:alpha", "needs:ec2")),
        issue(2, "Improve beta parser", ("area:beta", "needs:user")),
    ]
    planned, _ = plan_repository(gated, all_labels, automation)
    checks.append(("needs:ec2/needs:user candidates are never staged",
                   not any(m.kind == "stage" for m in planned)))

    # (b) Content-keyword exclusions are independent of labels and specification quality.
    trust_work = [
        issue(10, "Improve MPC executor", ("area:alpha",)),
        issue(11, "Document zkp behavior", ("area:beta", "kind:docs")),
    ]
    planned, _ = plan_repository(trust_work, all_labels, automation)
    checks.append(("zk/mpc keyword candidates are never staged",
                   not any(m.kind == "stage" for m in planned)))

    # (c) Seven bot-authored copies form one cluster: lowest survives and only five close.
    duplicate_fixture = [
        issue(number, "Repair frontier snapshot pagination", ("area:alpha",))
        for number in range(20, 27)
    ]
    planned, _ = plan_repository(duplicate_fixture, all_labels, automation)
    closes = [m for m in planned if m.kind == "close"]
    checks.append(("dedupe keeps lowest number and closes at most five",
                   len(closes) == 5
                   and {m.number for m in closes} == {21, 22, 23, 24, 25}
                   and all(m.canonical == 20 for m in closes)))

    # (d) Ten existing ready issues leave depth two. Alpha is selected once, beta fills slot two,
    # and delta is excluded because an in-progress issue already owns that area.
    depth_fixture = [
        issue(100 + n, f"Existing ready lane unique{n}",
              ("status:ready", f"area:ready{n}"))
        for n in range(10)
    ]
    all_labels.update(f"area:ready{n}" for n in range(10))
    depth_fixture.extend([
        issue(40, "CI red blocks alpha parser", ("area:alpha",)),
        issue(41, "Improve alpha serializer", ("area:alpha",)),
        issue(42, "Improve beta serializer", ("area:beta",)),
        issue(43, "Improve gamma serializer", ("area:gamma",)),
        issue(44, "Existing delta worker", ("status:in-progress", "area:delta")),
        issue(45, "Improve delta serializer", ("area:delta",)),
    ])
    planned, _ = plan_repository(depth_fixture, all_labels, automation)
    stages = [m for m in planned if m.kind == "stage"]
    stage_areas = [next(label for label in m.labels if label.startswith("area:")) for m in stages]
    checks.append(("depth cap and one-per-area/in-flight rules hold",
                   len(stages) == 2 and len(stage_areas) == len(set(stage_areas))
                   and {m.number for m in stages} == {40, 42} and "area:delta" not in stage_areas))

    # (e) A status:* duplicate and a status:* EC2 issue are protected from every mutation kind.
    status_fixture = [
        issue(200, "Repair frontier collision detector", ("area:alpha",)),
        issue(201, "Repair frontier collision detector", ("status:ready", "area:alpha")),
        issue(202, "Run quiet-box EC2 gather", ("status:untriaged", "area:bench")),
    ]
    planned, _ = plan_repository(status_fixture, all_labels, automation)
    touched = {m.number for m in planned}
    checks.append(("already-status issues are never touched", not ({201, 202} & touched)))

    # (f) A non-collaborator, non-allowlisted author cannot be staged or dedupe-closed.
    untrusted = [issue(210, "Improve gamma parser", ("area:gamma",), author="outsider")]
    planned, _ = plan_repository(untrusted, all_labels, automation)
    checks.append(("untrusted-author candidate is skipped", not planned))

    human_duplicates = [
        issue(220, "Repair deterministic wave selector", ("area:alpha",)),
        issue(221, "Repair deterministic wave selector", ("area:alpha",),
              author="maintainer", association="OWNER"),
    ]
    planned, _ = plan_repository(human_duplicates, all_labels, automation)
    checks.append(("human-authored duplicate is never closed",
                   not any(m.kind == "close" and m.number == 221 for m in planned)))

    bench_fixture = [
        issue(230, "Run canonical gather on same-box EC2", ("area:bench",)),
        issue(231, "Fix scripts/gather.py for canonical gather", ("area:bench",)),
    ]
    planned, _ = plan_repository(bench_fixture, all_labels, automation)
    checks.append(("measurement work is gated while code-only bench work remains stageable",
                   any(m.kind == "needs-ec2" and m.number == 230 for m in planned)
                   and any(m.kind == "stage" and m.number == 231 for m in planned)))

    # Policy controls the ready-depth target. Thirty distinct eligible areas prove the policy
    # value reaches the planner instead of leaving the former hard-coded cap of twelve in place.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        policy_file = Path(tmp) / "repos.toml"
        policy_file.write_text(
            '[repos."o/scaled"]\n'
            'enabled = true\n'
            '[repos."o/scaled".throughput]\n'
            'target_ready = 30\n'
            '[repos."o/default"]\n'
            'enabled = true\n'
            '[repos."o/default".throughput]\n'
            'open_pr_alert_threshold = 5\n',
            encoding="utf-8",
        )
        loaded = {
            repo: (bots, target)
            for repo, bots, target in load_targets(policy_file, "registry[bot]")
        }
        scaled_automation, scaled_target = loaded["o/scaled"]
        scaled_fixture = []
        for offset in range(30):
            area = f"area:scaled{offset}"
            all_labels.add(area)
            scaled_fixture.append(issue(
                300 + offset, f"Improve component{offset} frontier behavior", (area,)
            ))
        planned, _ = plan_repository(
            scaled_fixture, all_labels, scaled_automation, target_ready=scaled_target
        )
        checks.append(("policy target_ready=30 stages beyond twelve",
                       len([m for m in planned if m.kind == "stage"]) == 30))
        checks.append(("missing target_ready falls back to twelve",
                       loaded["o/default"][1] == 12))

        for raw, display in (("0", "0"), ('"abc"', '"abc"'), ("250", "250")):
            policy_file.write_text(
                '[repos."o/bad"]\n'
                'enabled = true\n'
                '[repos."o/bad".throughput]\n'
                f'target_ready = {raw}\n',
                encoding="utf-8",
            )
            error = ""
            try:
                load_targets(policy_file, "registry[bot]")
            except CuratorError as exc:
                error = str(exc)
            checks.append((f"target_ready={display} rejected loudly",
                           "target_ready" in error and "[1, 100]" in error))

    area_fixture = [
        issue(400 + offset, f"Improve alpha component{offset} behavior", ("area:alpha",))
        for offset in range(4)
    ]
    planned, logs = plan_repository(
        area_fixture, all_labels, automation, target_ready=4
    )
    checks.append(("area-limited frontier is logged loudly",
                   len([m for m in planned if m.kind == "stage"]) == 1
                   and "frontier: area-limited at 1/4 (1 areas busy)" in logs))

    ok = all(result for _, result in checks)
    for name, result in checks:
        print(f"  {'ok  ' if result else 'FAIL'} {name}")
    print("curate-frontier self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_false", dest="apply",
                      help="print the mutation plan without acting (default)")
    mode.add_argument("--apply", action="store_true",
                      help="snapshot-revalidate and apply the mutation plan")
    parser.set_defaults(apply=False)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--policy-file", default="policy/repos.toml")
    parser.add_argument("--bot-login", default=os.environ.get("BOT_LOGIN", ""))
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    if args.bot_login and not args.bot_login.endswith("[bot]"):
        raise CuratorError("bot login must be an exact GitHub App [bot] login")

    targets = load_targets(Path(args.policy_file), args.bot_login)
    tokens, ambient = load_tokens()
    remaining_closes = MAX_CLOSES
    for repo, automation_logins, target_ready in targets:
        owner = repo.split("/", 1)[0]
        token = tokens.get(owner, ambient)
        if not token:
            raise CuratorError(f"no target token for enabled owner {owner}")
        issues, repo_labels = fetch_repository(repo, token)
        mutations, logs = plan_repository(
            issues, repo_labels, automation_logins, close_limit=remaining_closes,
            target_ready=target_ready,
        )
        print(f"== {repo}: ready={sum('status:ready' in labels_of(i) for i in issues)} "
              f"target={target_ready} ==")
        for line in logs:
            print(line)
        actual_closes = execute_plan(repo, mutations, token, args.apply)
        used = actual_closes if args.apply else sum(m.kind == "close" for m in mutations)
        remaining_closes -= used
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CuratorError as exc:
        print(f"curate-frontier: {exc}", file=sys.stderr)
        sys.exit(1)
