#!/usr/bin/env python3
"""Deterministically curate unstaged work into a small, conflict-free ready frontier.

The enabled target list and additional trusted automation identities come from
``policy/repos.toml``.  The default mode is a read-only dry run; ``--apply`` is the only path
that mutates target issues.  Exactly ONE label is ever removed — ``status:untriaged``, and only
from an issue this run is simultaneously staging (see ``Mutation.remove`` and ``is_staged``);
``execute_plan`` raises on any other strip.
"""
import argparse
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any


def _load_park_policy() -> Any:
    spec = importlib.util.spec_from_file_location(
        "registry_park_policy", Path(__file__).resolve().with_name("park_policy.py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load shared park policy")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Shared park-label policy: every park-label application (the steering-question and
# conditional-evidence fences write needs:user) consults the sticky human-unpark veto first
# (park_policy.py defect 2).
_park_policy = _load_park_policy()


def _load_gh_retry() -> Any:
    spec = importlib.util.spec_from_file_location(
        "registry_gh_retry", Path(__file__).resolve().with_name("gh_retry.py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load shared gh retry policy")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Shared bounded-retry mechanics for IDEMPOTENT gh reads (registry #563 adoption item 4): the
# 16:00 incident redded a whole curate tick on one transient 503. READS ONLY — execute_plan's
# label/close mutations stay fail-loud and are never routed through this wrapper.
_gh_retry = _load_gh_retry()


def _load_measurement_gate() -> Any:
    spec = importlib.util.spec_from_file_location(
        "registry_measurement_gate", Path(__file__).resolve().with_name("measurement_gate.py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the shared measurement gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_ready_issues() -> Any:
    spec = importlib.util.spec_from_file_location(
        "registry_ready_issues", Path(__file__).resolve().with_name("ready-issues.py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the shared readiness engine")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The measurement-RUN classifier (registry #466). This module's EC2 fence and the triage/readiness
# path's `needs:ec2` gate must never drift apart into two keyword lists, so the keywords and the
# code-only exemption now live in ONE place. curate keeps the UNSCOPED, narrow predicate — it runs
# on brand-new, status-less issues that have no `area:*` label yet — while triage.py uses the
# bench-SCOPED one. `measurement_gate`'s self-test pins both and their containment.
_measurement_gate = _load_measurement_gate()

# THE readiness engine (`ready-issues.py`), imported for the SAME reason metrics.py imports it
# (`_ready_count`: "so the label-gate definition can never drift from the dispatcher's"). The
# curator was the last component still keeping a PRIVATE copy of "how much ready work exists" —
# a bare `"status:ready" in labels` count — and that copy is what `depth` was computed from.
_ready = _load_ready_issues()


TARGET_READY = 12
MAX_CLOSES = 5
# How many per-issue readiness refusals the frontier census prints verbatim before summarising.
MAX_REFUSAL_LINES = 20
GATE_LABELS = ("needs:", "trust:untrusted")
TRUSTED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
ACTIONS_BOT_LOGIN = "github-actions[bot]"
IN_FLIGHT_STATUS = {"status:ready", "status:in-progress"}
PARKED_AREA_LABELS = {"needs:user", "review:needs-user", "status:blocked"}
# `status:untriaged` is the ONE status label that is not a staging claim — it is the assertion
# that NOTHING has staged this issue yet. See is_staged() for the measured deadlock this closes.
UNSTAGED_STATUS = "status:untriaged"
TRUST_LABEL_PREFIXES = (
    "area:sparq-zk", "area:sparq-mpc", "area:zk", "area:mpc", "area:trust",
    "area:sparq-trust", "area:e2ee", "area:sparq-e2ee", "zk", "mpc",
)
TRUST_KEYWORDS = (
    "zk", "zkp", "mpc", "noir", "secprop", "nullifier", "e2ee", "crypt",
    "issuer", "credential", "trust anchor", "zero-knowledge", "multi-party", "snark",
    "garbled", "proving key", "witness commitment", "trusted setup",
)
# The unscoped EC2 signal, sourced from the shared classifier so there is ONE list (#466). The
# bare/phrase partition is re-exported rather than re-derived: `ec2` is the ONE entry that is a
# BARE TOKEN rather than a phrase, so it is the only one a label (`needs:ec2`, `blocked:ec2`), a
# path (`research/ci-ec2-design.md`, `.github/workflows/bench-ec2.yml`,
# `scripts/ec2-buildfarm.sh`), a branch name (`chore/sq-uhqah-formalize-codex-ec2`) or an
# identifier (`AWSServiceRoleForEC2Spot`) can swallow — every one of those is the issue TALKING
# ABOUT the fence, not announcing work that has to run on dedicated hardware. It therefore matches
# as a FREE WORD inside `measurement_gate.ec2_signal`, which carries the measured false-positive
# census. Re-exporting keeps this module's self-test able to pin the partition, and pins it to the
# SHARED one, so a future edit cannot restore a plain-substring `ec2` in either place.
EC2_KEYWORDS = _measurement_gate.EC2_KEYWORDS
EC2_BARE_KEYWORD = _measurement_gate.EC2_BARE_KEYWORD
EC2_PHRASE_KEYWORDS = _measurement_gate.EC2_PHRASE_KEYWORDS
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
_CODE_ONLY_BENCH = _measurement_gate.CODE_ONLY_BENCH
_P2 = re.compile(
    r"\bci(?:\s+is)?\s+red\b|\bdeadlock(?:ed|s|ing)?\b|\bbricks?\b"
    r"|\bblocks\s+all\b",
    re.IGNORECASE,
)
_OPEN_ENDED_VERBS = frozenset({
    "consider", "maybe", "investigate", "explore", "evaluate", "decide",
})
_ACCEPTANCE_SECTION = re.compile(
    r"^#+\s*(?:acceptance|deliverable|spec)", re.IGNORECASE | re.MULTILINE
)
_DELIVERABLE_MARKER = re.compile(r"\*\*Deliverable:\*\*", re.IGNORECASE)
_CONDITIONAL_EVIDENCE = re.compile(
    r"\b(?:if\s+profiling|if\s+benchmarks\s+show|if\s+benchmarking\s+shows"
    r"|measure\s+first)\b"
    r"|\bif\s+[^\r\n]*?\bproves?\s+hot\b"
    r"|\bshould\s+[^\r\n]*?\bprove\s+hot\b"
    r"|\bonly\s+if\s+[^\r\n]*?\bshows\b",
    re.IGNORECASE,
)
_STEERING_QUESTION = re.compile(
    r"\bopen\s+question\s+for\s+steering\b"
    r"|\bfor\s+the\s+maintainer\s+to\s+steer\b"
    r"|^##[ \t]+open[ \t]+question[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)


class CuratorError(RuntimeError):
    """A fail-closed configuration, snapshot, or API error."""


@dataclass(frozen=True)
class Mutation:
    kind: str
    number: int
    issue: dict[str, Any]
    labels: tuple[str, ...] = ()
    # The ONLY labels this tool ever strips, and only from the `stage` action: `status:untriaged`
    # on an issue it is simultaneously staging. Without it the add-only edit leaves BOTH
    # `status:ready` and `status:untriaged` on the issue, and `status:untriaged` is in
    # ready-issues.BUSY_STATUS — so the "staged" issue is STILL unenumerable and the repair is
    # vacuous. `gh issue edit` sends one PATCH carrying the resulting label set, so the add and
    # the strip land together or not at all; this is not the two-independent-edits shape #582 is
    # about, and execute_plan still raises on a non-zero return.
    remove: tuple[str, ...] = ()
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


def occupies_area(artifact: dict[str, Any]) -> bool:
    """Whether an otherwise in-flight snapshot artifact may occupy its labelled area.

    This is deliberately a pure label predicate: removing a terminal park label in the next
    snapshot immediately restores occupancy, with no remembered state to reconcile.
    """
    return not bool(labels_of(artifact) & PARKED_AREA_LABELS)


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


def is_staged(labels: set[str]) -> bool:
    """Whether the pipeline has ALREADY staged this issue — the CANDIDATE-ADMISSION predicate.

    NOT the same question as has_status(), and the difference is the whole of registry #799.

    MEASURED DEADLOCK. `triage-issue.yml` fires on `issues: [opened, edited, reopened]` and stamps
    `status:untriaged` within seconds of creation — `triage.triage()` always adds either
    `status:ready` or `status:untriaged`, never neither. The candidate filter used has_status(),
    so from that moment the curator — the ONLY lane in the estate that mints `priority:*`,
    `area:*` and `status:ready` — could never look at the issue again. And `retriage.py` cannot
    rescue it either: its promotion lane fires only when the label set is ALREADY triage-complete,
    which requires exactly the `priority:*`/`area:*` labels only the curator writes. Two lanes,
    each reporting `success` on every run, each structurally unable to produce the other's input:
    on the live board 274 of 339 open issues sat `status:untriaged`, the oldest for two weeks, and
    retriage run 262 visited 80 of them and wrote NOTHING (80/80 `classifier-incomplete`).

    So `status:untriaged` alone is UNSTAGED and admissible. Every other `status:*` still means
    staged, and — deliberately — so does `status:untriaged` in COMBINATION with another status:
    the `status:available` account-inventory records (#1, #2, #14, ...) and any contradictory
    `status:untriaged`+`status:ready` pair stay untouched here, the latter because `retriage.py`
    owns that repair.

    has_status() is intentionally left alone. It also guards the duplicate-CLOSE path, where
    "carries a status label" means "the pipeline has seen it, do not auto-close it" — widening
    THAT would newly expose 274 issues to automated closure, which is the opposite of the repair.
    """
    return any(label.startswith("status:") and label != UNSTAGED_STATUS for label in labels)


def drainable_ready(open_issues: list[dict[str, Any]]) -> tuple[int, list[str]]:
    """How much ready work the READINESS ENGINE can actually enumerate, plus the reason for
    every `status:ready` issue it refuses. Returns `(count, defer_lines)`.

    THE MEASUREMENT THAT DRIVES `depth`. It used to be `sum("status:ready" in labels)` — a raw
    count of the positive ATTESTATION, which is not the same set as the work the dispatcher can
    see. MEASURED on the live registry board 2026-07-27T16:34Z, against the curator's own
    `== jeswr/agent-account-registry: ready=14 target=12 ==` line: 14 issues carried
    `status:ready`, and SIX of them (#32 #33 #34 #35 #36 #43) carried `status:deferred` at the
    same time. `ready-issues.BUSY_STATUS` contains `status:deferred`, so the dispatcher refused
    all six on that same tick and said so — `readiness defer #43: busy: status:deferred`, once per
    issue, in the PLAN log of every run for days. The curator read 14, the engine could see 8, and
    `depth = max(0, 12 - 14)` was therefore 0 while the frontier was starved: a measurement defect
    driving a control decision. Raising `target_ready` would have papered over it and then
    over-stocked the frontier the moment the count became honest.

    The count is delegated to `ready-issues.ready_candidates`, never re-derived here, for the
    reason `metrics._ready_count` gives for delegating the identical question: "so the label-gate
    definition can never drift from the dispatcher's". Delegating to `ready_candidates` rather
    than to `exclusion_reason` is deliberate — `ready_candidates` is THE gate, and a rule composed
    into it later (registry #122's routability refusal) is inherited here for free instead of
    silently leaving this the laxest reader again.

    ADVISORY, and only ever in the fail-safe direction. `dispatch.yml` plans each target with THAT
    TARGET's own copy of the engine, which may lag this one; a disagreement moves `depth` by a row
    or two and self-corrects on the next tick, because nothing here is remembered.
    """
    open_numbers = {issue["number"] for issue in open_issues}
    # `open_blocker_count` unions BOTH blocker channels — the native `issue_dependencies_summary`
    # GitHub already ships in this very list payload, and the legacy `Blocked-by: #NN` body
    # marker. The curator fetches `issues?state=open`, the same endpoint the dispatcher snapshots,
    # so both channels are present here and neither has to be re-derived.
    prepared = [{**issue, "open_blockers": _ready.open_blocker_count(issue, open_numbers)}
                for issue in open_issues]
    defers: list[str] = []
    count = len(_ready.ready_candidates(prepared, log=defers.append))
    # COUNTS SUM TO THE POPULATION. `ready_candidates` emits exactly one defer line per
    # `status:ready` issue it drops and admits only `status:ready` issues, so this identity holds
    # by construction — and its breach means the engine's logging contract moved under us, which
    # is precisely when the curator must stop rather than plan from a number it cannot account
    # for. Fail-loud (main() prints and exits 1); never silently continue on an unexplained count.
    attested = sum(1 for issue in open_issues if "status:ready" in labels_of(issue))
    if count + len(defers) != attested:
        raise CuratorError(
            f"readiness census does not account for the board: {count} drainable + "
            f"{len(defers)} refused != {attested} status:ready issue(s)"
        )
    return count, defers


def frontier_header(repo: str, issues: list[dict[str, Any]], target_ready: int) -> str:
    """The operator-facing `== repo: ready=N target=M ==` line.

    Extracted so the number a human reads is PROVABLY the number `depth` is computed from — one
    call to `drainable_ready`, one definition, testable without a live fetch. The old header
    counted raw `status:ready` over the UNFILTERED fetch (which carries PR rows too, since
    `issues?state=open` returns both), so it could not agree with the control input even in
    principle. `ready=14 target=12` was the only frontier signal an operator got while the
    dispatcher could enumerate eight of those fourteen; a report that disagrees with the decision
    it describes is how the pin stayed invisible.
    """
    ready, _refusals = drainable_ready([issue for issue in issues if is_open_issue(issue)])
    return f"== {repo}: ready={ready} target={target_ready} =="


def author_login(issue: dict[str, Any]) -> str:
    user = issue.get("user")
    login = user.get("login") if isinstance(user, dict) else None
    return login if isinstance(login, str) else ""


def trusted_author(
    issue: dict[str, Any],
    automation_logins: set[str],
    allow_actions_bot_issues: bool = False,
) -> bool:
    """Mirror dispatch CLAIM's collaborator/allowlisted-bot author predicate exactly."""
    login = author_login(issue)
    association = str(issue.get("author_association", "")).upper()
    return bool(login) and (
        association in TRUSTED_ASSOCIATIONS or login in automation_logins
        or (allow_actions_bot_issues and login == ACTIONS_BOT_LOGIN)
    )


def is_automation_author(issue: dict[str, Any], automation_logins: set[str]) -> bool:
    return author_login(issue) in automation_logins


def issue_text(issue: dict[str, Any]) -> str:
    title = issue.get("title")
    body = issue.get("body")
    if not isinstance(title, str) or not isinstance(body, (str, type(None))):
        raise CuratorError("issue title/body are malformed")
    return f"{title}\n{body or ''}"


def open_ended_first_sentence(issue: dict[str, Any]) -> str | None:
    """Return the disallowed opening word when the title's first sentence is open-ended."""
    title = issue.get("title")
    if not isinstance(title, str):
        raise CuratorError("issue title is malformed")
    first_sentence = re.split(r"[.!?](?:\s|$)", title, maxsplit=1)[0]
    match = re.match(r"\s*([A-Za-z]+)", first_sentence)
    verb = match.group(1).casefold() if match else ""
    return verb if verb in _OPEN_ENDED_VERBS else None


def has_explicit_deliverable(issue: dict[str, Any]) -> bool:
    body = issue.get("body") or ""
    if not isinstance(body, str):
        raise CuratorError("issue body is malformed")
    return bool(_ACCEPTANCE_SECTION.search(body) or _DELIVERABLE_MARKER.search(body))


def has_conditional_evidence(issue: dict[str, Any]) -> bool:
    """Whether the body carries one of the narrow measurement-before-work signatures."""
    body = issue.get("body") or ""
    if not isinstance(body, str):
        raise CuratorError("issue body is malformed")
    return bool(_CONDITIONAL_EVIDENCE.search(body))


def is_steering_question(issue: dict[str, Any]) -> bool:
    """Whether the issue has an explicitly question-shaped title or steering body."""
    title = issue.get("title")
    body = issue.get("body") or ""
    if not isinstance(title, str) or not isinstance(body, str):
        raise CuratorError("issue title/body are malformed")
    return title.endswith("?") or bool(_STEERING_QUESTION.search(body))


def is_trust_surface(issue: dict[str, Any], labels: set[str]) -> bool:
    folded_labels = {label.casefold() for label in labels}
    if any(label.startswith(prefix) for label in folded_labels
           for prefix in TRUST_LABEL_PREFIXES):
        return True
    folded = issue_text(issue).casefold()
    return any(keyword in folded for keyword in TRUST_KEYWORDS)


def is_ec2_measurement(issue: dict[str, Any]) -> bool:
    """The UNSCOPED EC2 fence — whether the issue announces work that has to RUN on dedicated
    measurement hardware — delegated to the shared classifier (registry #466).

    The bare `ec2` keyword matches as a FREE WORD, not as a substring; the phrase keywords, the
    title-only `_CODE_ONLY_BENCH` escape and the fail-loud malformed-payload contract are all
    unchanged. The rule and its measured census live in `measurement_gate.ec2_signal`, so the
    triage/readiness path's `needs:ec2` gate cannot drift back onto a substring scan of its own.

    WHY THAT PRECISION IS A BLOCKING CONCERN AND NOT A NICETY, in THIS module's terms. `needs:ec2`
    is a ONE-WAY hold: no lane in this estate removes it, and `triage-stock-alert.census()` — the
    alarm THIS PR adds — excludes every `needs:*` row from `machine_owed`, because a `needs:` gate
    normally means a HUMAN owes the issue its next move. So a false fence written HERE does not
    merely delay an issue, it moves the issue OUT of the population the starvation alarm keys on.
    That is exactly the missing-state-exit defect this PR exists to close, re-created one layer up
    by the fix for it. Admitting `status:untriaged` as a candidate (`is_staged`) is what made it
    reachable at scale — which is why the fixtures for it are pinned in this module's self-test
    THROUGH `plan_repository`, not only in the shared module's.

    `issue_text` is still called first so a malformed title/body raises CuratorError — this
    module's own error type — before the shared module ever sees it; the delegation therefore
    cannot change which exception a malformed issue produces here.
    """
    issue_text(issue)
    title = issue.get("title")
    if not isinstance(title, str):
        raise CuratorError("issue title is malformed")
    return _measurement_gate.is_ec2_measurement(title, issue.get("body"))


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

    # THE TARGET'S OWN AREA TAXONOMY. The crate rule above and the path hints below are both
    # sparq-shaped: `sparq-*` crate names, and `site/`/`gui/`/`bench/`/`scripts/` trees. Against
    # the registry — the estate's SECOND enabled target — that left only `area:ci` reachable, so
    # 8 of its 10 `area:*` labels (dispatch, groom, worker, review-loop, set-up-account, usage,
    # dashboard, docs) were invisible to the curator and every issue it could classify collapsed
    # into the SAME package. Since a wave stages at most one issue per package, the whole target's
    # drain was pinned at 1 per run regardless of the depth budget.
    #
    # Same shape as the crate rule, generalised: a repository's `area:<name>` labels ARE its
    # declared surface vocabulary, so an issue whose TITLE names exactly one of them is
    # classified by it. Title-only (not the body) for the same precision reason the crate rule is
    # title-only, and fail-closed on ambiguity exactly like every other branch here: two named
    # surfaces are an UNRESOLVED area, not a coin flip.
    declared = {
        label for label in repo_labels
        if label.startswith("area:") and len(label) > len("area:")
        and re.search(rf"(?<![A-Za-z0-9_-]){re.escape(label[len('area:'):])}(?![A-Za-z0-9_-])",
                      title, re.IGNORECASE)
    }
    if len(declared) == 1:
        return next(iter(declared)), "title names a declared area"
    if len(declared) > 1:
        return None, "multiple declared areas named in title"

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


# A fence whose label the target repository does not carry. The line is a LOG entry, not an
# exception, and main() turns the run red once the whole plan has been printed and applied.
FENCE_UNAVAILABLE = "FENCE-UNAVAILABLE"


def _fence_unavailable(
    logs: list[str], number: int, fence: str, desired: tuple[str, ...], repo_labels: set[str],
) -> bool:
    """True (and logged) when `fence` cannot be applied because the target lacks its label(s).

    This used to `raise CuratorError`, which aborted the ENTIRE target's plan — every other
    issue's fence and every stage with it — on one unconfigured label. That was invisible while
    the curator's candidate set was tiny; admitting `status:untriaged` issues (registry #799)
    makes it reachable on the first tick, and the registry genuinely lacks `needs:ec2` and
    `status:blocked` today, so the whole-target abort would have replaced a starving lane with a
    red one and STILL drained nothing.

    Availability and fail-closed are not in tension here, because the two failures are on
    different axes: the ISSUE is skipped, so it is never admitted (fail-closed, unchanged), while
    the RUN still curates everything else and then goes red once via main() (loud, unchanged).
    This is retriage.yml's own "record the per-issue failure, continue the sweep, turn the step
    red once after the loop" idiom.
    """
    missing = sorted(set(desired) - repo_labels)
    if not missing:
        return False
    logs.append(
        f"{FENCE_UNAVAILABLE} #{number}: {fence} fence needs {','.join(missing)}, which this "
        f"repository does not have — skipping the issue (never admitted) and failing the run"
    )
    return True


def plan_repository(
    issues: list[dict[str, Any]],
    repo_labels: set[str],
    automation_logins: set[str],
    close_limit: int = MAX_CLOSES,
    target_ready: int = TARGET_READY,
    allow_actions_bot_issues: bool = False,
) -> tuple[list[Mutation], list[str]]:
    """Return a deterministic mutation plan and human-readable skip log for one target."""
    if close_limit < 0:
        raise CuratorError("close limit cannot be negative")
    _validated_target_ready(target_ready)
    open_issues = sorted((issue for issue in issues if is_open_issue(issue)),
                         key=lambda issue: issue["number"])
    logs: list[str] = []
    gate_actions: list[Mutation] = []
    safe_candidates: dict[int, dict[str, Any]] = {}
    # [OPUS-5] issues the curator can never stage because no area can be attributed to them.
    unattributable: list[int] = []

    for issue in open_issues:
        labels = labels_of(issue)
        number = issue["number"]
        if is_staged(labels) or has_gate(labels):
            continue
        if not trusted_author(issue, automation_logins, allow_actions_bot_issues):
            login = author_login(issue) or "<malformed>"
            logs.append(
                f"skip #{number}: undispatchable author {login!r} "
                "(not maintainer/collaborator/allowlisted bot)"
            )
            continue
        if is_trust_surface(issue, labels):
            logs.append(f"skip #{number}: trust-surface content")
            continue
        if has_conditional_evidence(issue):
            needs_label = "needs:ec2" if "needs:ec2" in repo_labels else "needs:user"
            desired = (needs_label, "status:blocked")
            if _fence_unavailable(logs, number, "CONDITIONAL-EVIDENCE", desired, repo_labels):
                continue
            gate_actions.append(Mutation(
                "conditional-evidence", number, issue, desired
            ))
            logs.append(
                f"FENCE #{number}: CONDITIONAL-EVIDENCE -> {','.join(desired)}; never admit"
            )
            continue
        if is_steering_question(issue):
            if _fence_unavailable(logs, number, "QUESTION-SHAPED/steering",
                                  ("needs:user",), repo_labels):
                continue
            gate_actions.append(Mutation(
                "steering-question", number, issue, ("needs:user",)
            ))
            logs.append(
                f"FENCE #{number}: QUESTION-SHAPED/steering -> needs:user; never admit"
            )
            continue
        if is_ec2_measurement(issue):
            if _fence_unavailable(logs, number, "EC2-measurement", ("needs:ec2",), repo_labels):
                continue
            gate_actions.append(Mutation("needs-ec2", number, issue, ("needs:ec2",)))
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

    # `drainable_ready` (PR #799, merged) is the depth MEASUREMENT: what the readiness ENGINE can
    # enumerate, not the raw `status:ready` attestation. This PR is UPSTREAM of it — it decides
    # WHICH ISSUES ARE CANDIDATES AT ALL. Both are required; neither subsumes the other, and
    # neither moves the drain off zero alone (see the PR body's 2x2 matrix).
    current_ready, ready_refusals = drainable_ready(open_issues)
    depth = max(0, target_ready - current_ready)
    # The number `depth` was computed from, ATTRIBUTABLE, and printed on EVERY tick including the
    # healthy one — the #597 idiom: a check that is silent when it passes is a check nobody
    # notices has stopped running. A curator that admits nothing must say, in the log a human
    # already reads, whether that is because the frontier is genuinely stocked or because the
    # number it stocked against counts work the dispatcher has already refused. `ready=14
    # target=12` was true, and told nobody that eight was the real figure.
    logs.append(
        f"frontier: {current_ready} drainable of "
        f"{current_ready + len(ready_refusals)} status:ready attested, "
        f"depth {depth}/{target_ready}"
    )
    # The engine's OWN refusal lines, verbatim (never re-derived, never re-worded here): the same
    # `readiness defer #N: <reason>` text `dispatch.yml` prints, so the two logs grep as one class.
    # Capped like the roleless report in `dispatch.yml` — sparq attests ~470 `status:ready` issues
    # and refuses most of them, and burying the curate log under hundreds of lines it already
    # prints elsewhere is how a signal stops being read. The COUNT above is never truncated.
    for line in sorted(ready_refusals)[:MAX_REFUSAL_LINES]:
        logs.append(f"  {line}")
    if len(ready_refusals) > MAX_REFUSAL_LINES:
        logs.append(f"  (+{len(ready_refusals) - MAX_REFUSAL_LINES} more refused; the full list is "
                    "the PLAN log's `readiness defer` lines)")
    in_flight_blockers: dict[str, list[dict[str, Any]]] = {}
    for issue in open_issues:
        labels = labels_of(issue)
        if not labels & IN_FLIGHT_STATUS or not occupies_area(issue):
            continue
        for area in sorted(label for label in labels if label.startswith("area:")):
            in_flight_blockers.setdefault(area, []).append(issue)
    in_flight_areas = set(in_flight_blockers)
    for area, blockers in sorted(in_flight_blockers.items()):
        blocker = blockers[0]
        kind = "pr" if "pull_request" in blocker else "issue"
        count = f" ({len(blockers)} blockers)" if len(blockers) > 1 else ""
        logs.append(f"busy {area} <- {kind}#{blocker['number']}{count}")
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
            # [OPUS-5] The fail-closed refusal is CORRECT — an area is never guessed. Its
            # SILENCE was not. This skip line scrolls past every 30 minutes and the issue is
            # re-skipped forever with no label, no count, and no route back to a human. It is a
            # LARGE standing class on sparq-org/sparq, not a rounding error — but no figure is
            # written here on purpose: a count pasted into a source comment is stale the day
            # after it is written, and the first draft of this comment carried one (142 of 218)
            # that matched no run anyone could reproduce, including this PR's own evidence. The
            # report emitted below is the number, measured every tick.
            #
            # Recorded here and reported as an always-printed total, with the SEVERITY of the
            # precedent it cites: dispatch.yml's roleless-report emits a `::warning::` on the
            # non-zero branch and a plain line at zero, which is what puts the class on the run
            # page instead of at line ~207 of a 543-line log nothing reads.
            unattributable.append(number)
            logs.append(f"skip #{number}: no confident area ({area_reason})")
            continue
        role = role_for(labels, area)
        opening = open_ended_first_sentence(issue)
        if (
            role in {"role:impl", "role:ci"}
            and opening is not None
            and not has_explicit_deliverable(issue)
        ):
            logs.append(
                f"reroute #{number}: {role} rejected — first sentence starts with "
                f"{opening!r} and has no acceptance/deliverable/spec; use role:research"
            )
            role = "role:research"
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
        # Strip `status:untriaged` in the SAME edit that stages: it is in
        # ready-issues.BUSY_STATUS, so leaving it behind stages an issue the dispatcher still
        # cannot enumerate — a repair that changes labels and drains nothing.
        strip = (UNSTAGED_STATUS,) if UNSTAGED_STATUS in labels_of(issue) else ()
        stage_actions.append(Mutation("stage", number, issue, desired, remove=strip))
        logs.append(f"stage #{number}: {','.join(desired)}"
                    + (f" -{','.join(strip)}" if strip else ""))

    # [OPUS-5] ALWAYS emitted, including the zero case — a report that only appears when the
    # number is non-zero cannot be told apart from a report that stopped running.
    #
    # The non-zero branch is a `::warning::`, the zero branch a plain line. That is not
    # cosmetic and it is the difference two reviews of the first draft both blocked on: a
    # plain `print` puts this class at roughly line 207 of a 543-line log, in a 30-minute cron
    # with no `workflow_run` consumer, no metrics/dashboard reader, and no label — so the class
    # became distinguishable-if-you-open-the-log rather than VISIBLE, which is the same
    # state-with-no-exit shape the report exists to remove, one layer shallower. `::warning::`
    # surfaces it on the run page without opening the log, exactly as the cited precedent
    # (dispatch.yml's roleless-report, `.github/workflows/dispatch.yml`) does. It is an
    # annotation, not a route: draining the class still wants a label or a deduped roll-up
    # issue, which is deliberately NOT in this diff.
    #
    # "no confident area" is not one condition: `derive_area` returns None both for NO signal
    # and for AMBIGUOUS signal (multiple area labels / multiple crate areas in a title /
    # multiple path hints), and those want different remediation. The per-issue skip line still
    # carries `area_reason`, so the split stays recoverable; the roll-up deliberately does not
    # claim otherwise, hence "cannot be staged until an area is attributed" rather than the
    # first draft's "can never stage", which overstated a state that clears the moment an
    # `area:` label lands.
    shown = ", ".join(f"#{n}" for n in unattributable[:20])
    more = f" (+{len(unattributable) - 20} more)" if len(unattributable) > 20 else ""
    if unattributable:
        logs.append(f"::warning::unattributable: {len(unattributable)} issue(s) have NO "
                    f"confident area and cannot be staged until an area is attributed: "
                    f"{shown}{more}")
    else:
        logs.append("unattributable: 0 issue(s) have NO confident area and cannot be staged "
                    "until an area is attributed")

    if area_limited and len(stage_actions) < depth:
        resulting_ready = current_ready + len(stage_actions)
        busy_areas = len(in_flight_areas | selected_areas)
        logs.append(
            f"frontier: area-limited at {resulting_ready}/{target_ready} "
            f"({busy_areas} areas busy)"
        )

    return gate_actions + close_actions + stage_actions, logs


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
    # Every _gh_json call site is an idempotent READ (issue/label/timeline/collaborator lists),
    # so a transient 5xx/secondary-403/connection blip gets gh_retry's bounded backoff instead of
    # redding the whole curate tick (registry #563 item 4). Error classification and the
    # fail-loud CuratorError stay owned here; gh_retry replaces only the loop/sleep mechanics.
    try:
        result = _gh_retry.run_gh(args, env=_gh_env(token))
    except FileNotFoundError as exc:
        raise CuratorError("gh is unavailable") from exc
    if result.returncode != 0:
        raise CuratorError((result.stderr or "gh command failed").strip())
    try:
        return json.loads(result.stdout or "null")
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


def _issue_timeline(repo: str, number: int, token: str) -> list[dict[str, Any]]:
    """The FULL label timeline for the sticky human-unpark veto. Paginated: the newest events
    (the ones the veto decision hinges on) are on the LAST page, so a truncated read must raise
    (park_vetoed then fails toward NOT parking) rather than return a prefix."""
    pages = _gh_json([
        "api", "--paginate", "--slurp",
        f"repos/{repo}/issues/{number}/timeline?per_page=100",
    ], token)
    return _flatten_pages(pages, "timeline event")


def _is_human_maintainer(repo: str, login: str, token: str) -> bool:
    """The strict maintainer probe for the unpark veto (park-policy hygiene finding; the
    worker-issue._is_human_maintainer pattern): repo collaborator permission in
    park_policy.HUMAN_MAINTAINER_PERMISSIONS. Probe-call FAILURE counts as NOT a maintainer
    and emits the shared distinct ::warning:: diagnostic (park_policy.probe_maintainer,
    round-3 Opus finding); a genuine not-a-maintainer permission stays quiet."""
    def read_permission(probe_login: str):
        payload = _gh_json(
            ["api", f"repos/{repo}/collaborators/{probe_login}/permission"], token)
        if not isinstance(payload, dict):
            raise CuratorError("collaborator permission payload is malformed")
        return payload.get("permission")

    return _park_policy.probe_maintainer(repo, login, read_permission)


def execute_plan(repo: str, mutations: list[Mutation], token: str, apply: bool) -> int:
    """Apply snapshot-revalidated mutations; return the number of actual duplicate closes."""
    closed = 0
    mode = "apply" if apply else "dry-run"
    for mutation in mutations:
        # THE STRIP BOUND, checked on the PLAN before any I/O and before the dry-run print, so a
        # malformed plan is refused identically in `--dry-run` and `--apply` and cannot be
        # discovered only after a live fetch. The curator may remove exactly one label,
        # `status:untriaged`, and only from a `stage`.
        for label in mutation.remove:
            if mutation.kind != "stage" or label != UNSTAGED_STATUS:
                raise CuratorError(
                    f"refusing to strip {label!r} from {repo}#{mutation.number}: the curator "
                    f"may only remove {UNSTAGED_STATUS!r}, and only when staging")
        if mutation.kind == "needs-ec2":
            description = "add needs:ec2"
        elif mutation.kind == "close":
            description = f"close as not planned (duplicate of #{mutation.canonical})"
        else:
            description = "add " + ",".join(mutation.labels)
            if mutation.remove:
                description += " / remove " + ",".join(mutation.remove)
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
            # Sticky human unpark (park_policy.py defect 2): a fence that applies a park label
            # (needs:user — steering questions and the conditional-evidence fallback) is
            # SUPPRESSED when a human removed that label more recently than any application;
            # an unreadable timeline never parks.
            if any(
                _park_policy.park_vetoed(
                    repo, mutation.number, label,
                    lambda r, n: _issue_timeline(r, n, token),
                    is_human=lambda login: _is_human_maintainer(repo, login, token))
                for label in mutation.labels if label in _park_policy.PARK_LABELS
            ):
                print(f"skip {repo}#{mutation.number}: park suppressed (sticky human unpark)")
                continue
            command = ["issue", "edit", str(mutation.number), "--repo", repo]
            for label in mutation.labels:
                command.extend(["--add-label", label])
            # Bounded by the plan-shape guard at the top of this loop.
            for label in mutation.remove:
                command.extend(["--remove-label", label])
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


def _allow_actions_bot_issues_of(repo: str, row: dict[str, Any]) -> bool:
    value = row.get("allow_actions_bot_issues", False)
    if not isinstance(value, bool):
        raise CuratorError(f"allow_actions_bot_issues for {repo} must be boolean")
    return value


def load_targets(policy_file: Path, bot_login: str) -> list[tuple[str, set[str], bool, int]]:
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
        targets.append((
            repo,
            automation,
            _allow_actions_bot_issues_of(repo, row),
            _target_ready_of(repo, row),
        ))
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
        "status:ready", "status:in-progress", "status:blocked", "needs:ec2", "needs:user",
        "review:changes", "review:needs-user",
        "priority:P2", "priority:P3", "role:impl", "role:docs", "role:perf",
        "role:ci", "role:site", "role:research",
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

    # Admission fences run before ready-depth selection: the two lower-numbered misses are fenced,
    # then the ordinary imperative candidate tops the frontier up. Removing either fence steals the
    # sole ready slot from #52 and flips these checks red.
    fence_fixture = [
        issue(
            50, "Implement alpha parser", ("area:alpha",),
            body=long_body + "\nMeasure first before changing the parser.",
        ),
        issue(51, "Should we implement gamma parser?", ("area:gamma",)),
        issue(52, "Implement beta parser", ("area:beta",)),
    ]
    planned, logs = plan_repository(
        fence_fixture, all_labels, automation, target_ready=1
    )
    checks.append((
        "measure-first body is loudly fenced as conditional evidence",
        any(
            m.kind == "conditional-evidence"
            and m.number == 50
            and m.labels == ("needs:ec2", "status:blocked")
            for m in planned
        )
        and not any(m.kind == "stage" and m.number == 50 for m in planned)
        and any("FENCE #50: CONDITIONAL-EVIDENCE" in line for line in logs),
    ))
    checks.append((
        "terminal-question title is loudly fenced for user steering",
        any(
            m.kind == "steering-question"
            and m.number == 51
            and m.labels == ("needs:user",)
            for m in planned
        )
        and not any(m.kind == "stage" and m.number == 51 for m in planned)
        and any("FENCE #51: QUESTION-SHAPED/steering" in line for line in logs),
    ))
    checks.append((
        "ordinary imperative fixture is not fenced and tops up ready depth",
        any(m.kind == "stage" and m.number == 52 for m in planned)
        and not any(
            m.number == 52 and m.kind in {"conditional-evidence", "steering-question"}
            for m in planned
        ),
    ))

    conditional_bodies = (
        "If profiling identifies a regression, implement the cache.",
        "If benchmarks show a regression, implement the cache.",
        "If benchmarking shows a regression, implement the cache.",
        "Measure first, then implement the cache.",
        "If the parser proves hot, implement the cache.",
        "If the parser prove hot, implement the cache.",
        "Should the parser prove hot, implement the cache.",
        "Only if the trace shows a regression, implement the cache.",
    )
    checks.append((
        "every conditional-evidence signature is recognized case-insensitively",
        all(has_conditional_evidence(issue(53, "Implement cache", body=body.swapcase()))
            for body in conditional_bodies),
    ))
    checks.append((
        "conditional-evidence matching stays body-only and word-bounded",
        not has_conditional_evidence(issue(54, "Measure first before implementing cache"))
        and not has_conditional_evidence(issue(
            55, "Implement cache", body=long_body + "\nMeasurement firstly guides the change."
        )),
    ))

    steering_bodies = (
        "This is an open question for steering before implementation.",
        "This is for the maintainer to steer before implementation.",
        "## Open question\nWhich implementation should be used?",
    )
    checks.append((
        "every steering-body signature is recognized case-insensitively",
        all(is_steering_question(issue(56, "Implement cache", body=body.swapcase()))
            for body in steering_bodies),
    ))
    checks.append((
        "an internal question mark and a level-three heading do not trip the fence",
        not is_steering_question(issue(57, "Explain why? then implement the cache"))
        and not is_steering_question(issue(
            58, "Implement cache", body=long_body + "\n### Open question\nDocumented context."
        )),
    ))

    fallback_labels = all_labels - {"needs:ec2"}
    fallback_candidate = issue(
        59, "Implement delta parser", ("area:delta",),
        body=long_body + "\nIf profiling identifies a regression, implement the change.",
    )
    planned, _ = plan_repository([fallback_candidate], fallback_labels, automation)
    checks.append((
        "conditional evidence falls back to needs:user when needs:ec2 is unavailable",
        any(
            m.kind == "conditional-evidence"
            and m.labels == ("needs:user", "status:blocked")
            for m in planned
        ),
    ))

    already_fenced = issue(
        60, "Should we implement delta parser?", ("area:delta", "needs:user")
    )
    planned, _ = plan_repository([already_fenced], all_labels, automation)
    label_calls: list[list[str]] = []
    original_run = subprocess.run

    def capture_label_calls(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if command[1:3] == ["issue", "edit"]:
            label_calls.append(command)
        return subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(already_fenced), stderr=""
        )

    try:
        subprocess.run = capture_label_calls
        execute_plan("o/r", planned, "self-test-token", True)
    finally:
        subprocess.run = original_run
    checks.append((
        "already-fenced fixture produces zero label calls",
        not planned and not label_calls,
    ))

    # Sticky human unpark (park_policy.py defect 2): the steering-question needs:user fence is
    # SUPPRESSED end-to-end when the issue timeline shows a human removed needs:user more
    # recently than any application; with no such removal the identical fence lands. The stub
    # serves the live-issue re-read, the paginated timeline, and captures label edits.
    steering = issue(61, "Should we implement epsilon parser?", ("area:delta",))
    veto_state = {"timeline": [
        {"event": "labeled", "label": {"name": "needs:user"},
         "created_at": "2026-07-18T10:00:00Z", "actor": {"login": "app[bot]"}},
        {"event": "unlabeled", "label": {"name": "needs:user"},
         "created_at": "2026-07-18T11:00:00Z", "actor": {"login": "jeswr"}},
    ]}

    def veto_subprocess(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if command[1:3] == ["issue", "edit"]:
            label_calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if "--paginate" in command:
            return subprocess.CompletedProcess(
                command, 0, stdout=json.dumps([veto_state["timeline"]]), stderr="")
        if any("/collaborators/" in part and part.endswith("/permission")
               for part in command):
            # The strict maintainer probe: jeswr is a repo admin; nobody else counts.
            login = next(part for part in command if "/collaborators/" in part
                         ).rsplit("/", 2)[-2]
            return subprocess.CompletedProcess(
                command, 0,
                stdout=json.dumps({"permission": "admin" if login == "jeswr" else "none"}),
                stderr="")
        return subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(steering), stderr="")

    planned, _ = plan_repository([steering], all_labels, automation)
    steering_planned = [m for m in planned if m.kind == "steering-question"]
    label_calls.clear()
    try:
        subprocess.run = veto_subprocess
        execute_plan("o/r", steering_planned, "self-test-token", True)
        vetoed_calls = list(label_calls)
        veto_state["timeline"] = []
        execute_plan("o/r", steering_planned, "self-test-token", True)
        clean_calls = list(label_calls)
    finally:
        subprocess.run = original_run
    checks.append((
        "human unpark vetoes the steering needs:user fence",
        len(steering_planned) == 1 and vetoed_calls == [],
    ))
    checks.append((
        "the same fence lands once no human unpark is on the timeline",
        len(clean_calls) == 1 and "needs:user" in clean_calls[0],
    ))

    # Every open-ended operative word independently forces impl/ci work into research unless the
    # body owns an explicit acceptance shape. Keeping the fixtures separate makes deleting any one
    # word from _OPEN_ENDED_VERBS mutation-visible.
    for offset, verb in enumerate((
        "consider", "maybe", "investigate", "explore", "evaluate", "decide",
    )):
        candidate = issue(12 + offset, f"{verb.title()} alpha parser", ("area:alpha",))
        planned, logs = plan_repository([candidate], all_labels, automation)
        stages = [m for m in planned if m.kind == "stage"]
        checks.append((
            f"{verb} impl candidate is loudly rerouted to research",
            len(stages) == 1
            and "role:research" in stages[0].labels
            and "role:impl" not in stages[0].labels
            and any(f"reroute #{candidate['number']}: role:impl rejected" in line for line in logs),
        ))

    deliverable_body = long_body + "\n\n## Deliverable\nShip the parser change and tests."
    deliverable = issue(
        18, "Consider alpha parser", ("area:alpha",), body=deliverable_body
    )
    planned, _ = plan_repository([deliverable], all_labels, automation)
    checks.append(("consider candidate with Deliverable section remains impl",
                   any(m.kind == "stage" and "role:impl" in m.labels for m in planned)))

    bold_deliverable = issue(
        19, "Explore gamma parser", ("area:gamma",),
        body=long_body + "\n\n**Deliverable:** Ship the parser change and tests.",
    )
    planned, _ = plan_repository([bold_deliverable], all_labels, automation)
    checks.append(("bold Deliverable marker also preserves impl staging",
                   any(m.kind == "stage" and "role:impl" in m.labels for m in planned)))

    ci_candidate = issue(29, "Decide CI cache strategy", ("area:ci",))
    planned, _ = plan_repository([ci_candidate], all_labels, automation)
    checks.append(("open-ended CI candidate is rerouted to research",
                   any(m.kind == "stage" and "role:research" in m.labels
                       and "role:ci" not in m.labels for m in planned)))

    docs_candidate = issue(
        30, "Consider documenting parser behavior", ("area:alpha", "kind:docs")
    )
    planned, _ = plan_repository([docs_candidate], all_labels, automation)
    checks.append(("open-ended filter is limited to impl/ci",
                   any(m.kind == "stage" and "role:docs" in m.labels for m in planned)))

    for offset, keyword in enumerate((
        "zero-knowledge", "multi-party", "snark", "garbled", "proving key",
        "witness commitment", "trusted setup",
    )):
        candidate = issue(
            31 + offset, f"Implement {keyword} protocol cache", ("area:alpha",)
        )
        planned, _ = plan_repository([candidate], all_labels, automation)
        checks.append((f"trust keyword {keyword!r} excludes its fixture",
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
    # Each existing lane carries a COMPLETE ready label set (priority + role), because `depth` is
    # computed from the readiness ENGINE's count and the engine refuses an attested issue that is
    # missing either — ten priority-less rows are ten refusals, i.e. depth twelve, not depth two,
    # and this fixture would then be testing the pin instead of the cap it is named for.
    depth_fixture = [
        issue(100 + n, f"Existing ready lane unique{n}",
              ("status:ready", "priority:P2", "role:impl", f"area:ready{n}"))
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

    # (d2) THE PIN (this PR's leg). `depth` must be computed from the ready work the READINESS
    # ENGINE can enumerate, not from the raw `status:ready` attestation. The fixture is the live
    # 2026-07-27 registry board in miniature: every attested issue is ALSO `status:deferred`, which
    # `ready-issues.BUSY_STATUS` refuses (the dispatcher printed `readiness defer #N: busy:
    # status:deferred` for six real issues on every tick for days). Raw count = 12 = target, so a
    # raw reader computes depth 0 and stages NOTHING while the frontier is empty; the engine's
    # count is 0, so depth is 12 and the one viable candidate is staged.
    #
    # DELIBERATELY end-to-end through `plan_repository`, not a direct `drainable_ready` call:
    # reverting ONLY the call site to `sum(1 for i in open_issues if "status:ready" in ...)`
    # leaves every direct test of the helper green while fully restoring the outage. Each
    # undrainable issue gets its OWN area so area-serialization cannot be what suppresses the
    # stage, and the candidate's area is held by nothing.
    all_labels.update({"status:deferred", "area:pinned"})
    all_labels.update(f"area:pin{n}" for n in range(12))
    # Complete ready label sets APART from `status:deferred`, so the single difference between
    # this fixture and `healthy_fixture` below is the one label under test. A priority-less or
    # role-less row would be refused for that reason instead and the pair would no longer isolate
    # the busy-status rule.
    pin_fixture = [
        issue(200 + n, f"Attested but undrainable lane unique{n}",
              ("status:ready", "priority:P2", "role:impl", "status:deferred", f"area:pin{n}"))
        for n in range(12)
    ]
    pin_candidate = issue(299, "Repair the pinned-area snapshot writer", ("area:pinned",))
    planned, pin_logs = plan_repository(
        pin_fixture + [pin_candidate], all_labels, automation, target_ready=12)
    pin_stages = [m for m in planned if m.kind == "stage"]
    checks.append((
        "depth reads DRAINABLE readiness: 12 attested-but-deferred do not pin the curator",
        len(pin_stages) == 1 and pin_stages[0].number == 299))
    # The count itself, and the fact that the refusal is ATTRIBUTED rather than silent.
    checks.append((
        "the pinned fixture reports 0 drainable of 12 attested at full depth",
        any(line == "frontier: 0 drainable of 12 status:ready attested, depth 12/12"
            for line in pin_logs)
        and sum(1 for line in pin_logs
                if line.strip().startswith("readiness defer #")
                and line.strip().endswith("busy: status:deferred")) == 12))
    # The refusal list is CAPPED but the COUNT is not: sparq attests ~470 ready issues and refuses
    # most of them, so an uncapped census would bury the curate log. 25 refusals -> 20 lines + one
    # summary naming the missing 5, and the header still says 25.
    all_labels.update(f"area:cap{n}" for n in range(25))
    cap_fixture = [
        issue(400 + n, f"Attested but undrainable cap lane unique{n}",
              ("status:ready", "priority:P2", "role:impl", "status:deferred", f"area:cap{n}"))
        for n in range(25)
    ]
    _planned, cap_logs = plan_repository(cap_fixture, all_labels, automation, target_ready=12)
    cap_defers = [line for line in cap_logs if line.strip().startswith("readiness defer #")]
    checks.append((
        "the refusal census is capped at 20 lines but never truncates the count",
        len(cap_defers) == MAX_REFUSAL_LINES
        and any(line == "frontier: 0 drainable of 25 status:ready attested, depth 12/12"
                for line in cap_logs)
        and any(line.strip() == "(+5 more refused; the full list is the PLAN log's "
                                "`readiness defer` lines)" for line in cap_logs)))

    # A HEALTHY frontier must still pin the curator — the fix must not turn `depth` into "always
    # top up". Same twelve issues, same target, `status:deferred` removed: all twelve are now
    # drainable, so depth is 0 and the identical candidate is NOT staged.
    healthy_fixture = [
        issue(200 + n, f"Attested but undrainable lane unique{n}",
              ("status:ready", "priority:P2", "role:impl", f"area:pin{n}"))
        for n in range(12)
    ]
    healthy_planned, _ = plan_repository(
        healthy_fixture + [pin_candidate], all_labels, automation, target_ready=12)
    checks.append((
        "a genuinely stocked frontier still admits nothing (depth stays 0)",
        not any(m.kind == "stage" for m in healthy_planned)))

    # (d3) COUNTS SUM TO THE POPULATION, over every class the engine refuses for a DIFFERENT
    # reason. Each row below carries the `status:ready` attestation and is refused on another
    # ground, so `drainable + refused == attested` is a real partition, not an identity over an
    # empty set. `status:parked` is deliberately in the DRAINABLE column: `ready-issues` does not
    # list it in BUSY_STATUS, the dispatcher therefore does enumerate such an issue, and this
    # function's whole contract is to agree with the engine rather than to hold a private opinion
    # about it. If that is wrong it is now wrong in ONE place.
    all_labels.update({"status:parked", "status:untriaged", "kind:epic", "priority:P1"})
    census_ready = ("status:ready", "priority:P1", "role:impl", "area:alpha")
    census_fixture = [
        issue(300, "Drainable", census_ready),
        issue(301, "Drainable while machine-parked", census_ready + ("status:parked",)),
        issue(302, "Refused deferred", census_ready + ("status:deferred",)),
        issue(303, "Refused blocked", census_ready + ("status:blocked",)),
        issue(304, "Refused untriaged", census_ready + ("status:untriaged",)),
        issue(305, "Refused in-progress", census_ready + ("status:in-progress",)),
        issue(306, "Refused gated", census_ready + ("needs:user",)),
        issue(307, "Refused epic", census_ready + ("kind:epic",)),
        issue(308, "Refused roleless", ("status:ready", "priority:P1", "area:alpha")),
        issue(309, "Refused ambiguous priority",
              census_ready + ("priority:P2",)),
        issue(310, "Not attested at all", ("area:alpha",)),
    ]
    census_count, census_refusals = drainable_ready(census_fixture)
    attested_rows = sum(1 for row in census_fixture if "status:ready" in labels_of(row))
    checks.append((
        "readiness census partitions the attested population exactly",
        (census_count, len(census_refusals), attested_rows) == (2, 8, 10)
        and census_count + len(census_refusals) == attested_rows))
    checks.append((
        "every refusal names the issue it refused",
        {int(line.split("#", 1)[1].split(":", 1)[0]) for line in census_refusals}
        == {302, 303, 304, 305, 306, 307, 308, 309}))
    # A census that does not add up must STOP the tick, not plan from a number it cannot account
    # for. `ready_candidates` is stubbed to admit a row it never logged and never returned.
    _real_candidates = _ready.ready_candidates
    try:
        _ready.ready_candidates = lambda rows, log=None: []
        raised = False
        try:
            drainable_ready([issue(311, "Attested", census_ready)])
        except CuratorError as exc:
            raised = "does not account for the board" in str(exc)
        checks.append(("an unaccounted-for readiness census fails the tick loudly", raised))
    finally:
        _ready.ready_candidates = _real_candidates

    # (d4) The operator-facing header is the SAME measurement as the control input, over the SAME
    # population. A raw reader prints 12 here (and 13 if it also miscounts the PR row the
    # `issues?state=open` fetch carries); the engine's answer is 0.
    header_pr_row = {**issue(320, "A pull request row", ("status:ready", "area:pinned")),
                     "pull_request": {}}
    checks.append((
        "the ready= header reports drainable readiness over open ISSUES only",
        frontier_header("o/t", pin_fixture + [header_pr_row], 12) == "== o/t: ready=0 target=12 =="
        and frontier_header("o/t", healthy_fixture, 12) == "== o/t: ready=12 target=12 =="))

    # Issue #509: the area predicate is snapshot-derived and terminal park labels alone remove an
    # otherwise active artifact. PR-shaped fixtures pin the label boundary even though the
    # curator's production snapshot currently derives occupancy from open status-bearing issues.
    parked_draft = {
        **issue(70, "Worker draft for alpha", ("status:ready", "area:alpha", "needs:user")),
        "pull_request": {}, "draft": True,
    }
    active_changes_draft = {
        **issue(71, "Worker draft cycling changes",
                ("status:ready", "area:beta", "review:changes")),
        "pull_request": {}, "draft": True,
    }
    checks.append(("needs:user-parked draft PR does not occupy its area",
                   not occupies_area(parked_draft)))
    checks.append(("review:changes NON-parked PR still occupies",
                   occupies_area(active_changes_draft)))
    checks.append(("review:needs-user and status:blocked also park artifacts",
                   not occupies_area({
                       **active_changes_draft,
                       "labels": [{"name": "status:ready"}, {"name": "area:beta"},
                                  {"name": "review:needs-user"}],
                   })
                   and not occupies_area(issue(
                       72, "Blocked gamma worker",
                       ("status:in-progress", "area:gamma", "status:blocked"),
                   ))))

    parked_in_progress = issue(
        73, "Existing parked delta worker",
        ("status:in-progress", "area:delta", "needs:user"),
    )
    unparked_in_progress = {
        **parked_in_progress,
        "labels": [
            label for label in parked_in_progress["labels"]
            if label["name"] != "needs:user"
        ],
    }
    waiting_delta = issue(74, "Improve delta snapshot behavior", ("area:delta",))
    parked_plan, _ = plan_repository(
        [parked_in_progress, waiting_delta], all_labels, automation, target_ready=1
    )
    unparked_plan, unparked_logs = plan_repository(
        [unparked_in_progress, waiting_delta], all_labels, automation, target_ready=1
    )
    checks.append(("an in-progress issue still occupies",
                   occupies_area(unparked_in_progress)
                   and not any(m.kind == "stage" and m.number == 74 for m in unparked_plan)))
    checks.append(("busy-area log names the blocking artifact",
                   "busy area:delta <- issue#73" in unparked_logs))
    checks.append(("label removal on the fixture restores occupancy",
                   not occupies_area(parked_in_progress)
                   and occupies_area(unparked_in_progress)
                   and any(m.kind == "stage" and m.number == 74 for m in parked_plan)
                   and not any(m.kind == "stage" and m.number == 74 for m in unparked_plan)))

    # (e) A STAGED duplicate and a STAGED EC2 issue are protected from every mutation kind.
    #
    # registry #799 changed what "staged" means: this fixture previously used `status:untriaged`
    # for #202 as a stand-in for "the pipeline already owns this", which is precisely the
    # conflation that starved the board — `status:untriaged` is the assertion that NOTHING owns
    # it. #202 now carries a real staging status, and the untriaged EC2 case is asserted
    # positively below: it is FENCED (`needs:ec2`), which is a machine exit, rather than left to
    # sit forever with no label and no owner.
    status_fixture = [
        issue(200, "Repair frontier collision detector", ("area:alpha",)),
        issue(201, "Repair frontier collision detector", ("status:ready", "area:alpha")),
        issue(202, "Run quiet-box EC2 gather", ("status:in-progress", "area:bench")),
    ]
    planned, _ = plan_repository(status_fixture, all_labels, automation)
    touched = {m.number for m in planned}
    checks.append(("already-staged issues are never touched", not ({201, 202} & touched)))

    untriaged_ec2 = [issue(203, "Run quiet-box EC2 gather", ("status:untriaged", "area:bench"))]
    planned, _ = plan_repository(untriaged_ec2, all_labels | {"status:untriaged"}, automation)
    checks.append(("an untriaged EC2 measurement is FENCED, not staged and not ignored",
                   [(m.kind, m.labels) for m in planned] == [("needs-ec2", ("needs:ec2",))]))

    # (f) A non-collaborator, non-allowlisted author cannot be staged or dedupe-closed.
    untrusted = [issue(210, "Improve gamma parser", ("area:gamma",), author="outsider")]
    planned, logs = plan_repository(untrusted, all_labels, automation)
    checks.append(("undispatchable-author candidate is skipped loudly",
                   not planned and any(
                       "skip #210: undispatchable author 'outsider'" in line for line in logs
                   )))

    actions_issue = issue(
        211, "Improve actions parser", ("area:alpha",), author=ACTIONS_BOT_LOGIN
    )
    planned, _ = plan_repository([actions_issue], all_labels, set())
    checks.append(("actions bot is denied by default",
                   not any(m.kind == "stage" for m in planned)))

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

    # Registry #466: the fence delegates to measurement_gate but keeps the UNSCOPED, narrow
    # keyword list. This runs THROUGH plan_repository, so it fails if curate is ever re-pointed at
    # the bench-SCOPED list — which would fence every status-less issue whose body says "measured".
    scoped_only = [
        issue(232, "Fix the MEASURED parser regression", ("area:alpha",),
              body=long_body + " A measurement run on the nightly tier would confirm it."),
    ]
    planned, _ = plan_repository(scoped_only, all_labels, automation)
    checks.append(("curate's fence stays UNSCOPED-narrow (a scoped-only keyword never fences)",
                   not any(m.kind == "needs-ec2" for m in planned)
                   and any(m.kind == "stage" and m.number == 232 for m in planned)))
    malformed_raised = False
    try:
        is_ec2_measurement({"title": None, "body": ""})
    except CuratorError:
        malformed_raised = True
    checks.append(("curate's fence still raises CuratorError on a malformed title",
                   malformed_raised))

    # ============================================================================================
    # THE FENCE IS A ONE-WAY HOLD, SO THE PREDICATE THAT WRITES IT MUST BE PRECISE.
    #
    # `needs:ec2` has no machine exit and `triage-stock-alert.census()` excludes every `needs:*`
    # row from `machine_owed`, so a FALSE fence removes the issue from the population the alarm
    # this PR adds is keyed on. The bare `ec2` keyword therefore matches as a FREE WORD, never as
    # a substring of a label / path / branch / identifier. Each check below is bound to
    # `measurement_gate._EC2_FREE_WORD` THROUGH the delegation in `is_ec2_measurement`: reverting
    # the shared rule to the old `"ec2" in text.casefold()` reds the first three; narrowing the
    # scan to the title (the alternative this diff REJECTED on the measurement) reds the fourth
    # and fifth. They run through `plan_repository`, so they also pin that a fenced row leaves the
    # frontier and an unfenced one still stages — which the shared module's own self-test, having
    # no planner, cannot see.
    # ============================================================================================
    # (e1) THE MEASURED LIVE FALSE POSITIVES. All three registry rows (#471, #802, #803) match the
    # old rule only because the literal LABEL `needs:ec2` appears in a body that is discussing
    # this very fence. Verbatim-shaped bodies, long enough to clear the well-specified bar so the
    # fixture proves the FENCE is what changed and not some other gate.
    # Shared filler that clears `is_well_specified` (>=200 chars AND one concrete reference), so
    # every check below turns on the FENCE and never on a different gate. The reference is
    # deliberately ec2-free.
    spec = ("\n\n## Acceptance\nSee `scripts/alpha-writer.py`. "
            + "Detailed acceptance criteria for the change. " * 12)
    label_mention = issue(
        940, "no_change vocabulary has no environment reason", ("area:alpha",),
        body="Layer 2 asks the worker to auto-gate `needs:ec2` when the model reports an "
             "environment blocker, and only #3314 correctly carries `needs:ec2` today." + spec)
    planned, _ = plan_repository([label_mention], all_labels, automation)
    checks.append((
        "a body that merely NAMES the needs:ec2 label is not fenced",
        not is_ec2_measurement(label_mention)
        and any(m.kind == "stage" and m.number == 940 for m in planned)))

    # (e2) A FILENAME containing `ec2` is not a claim about where the work runs. Live shapes:
    # `research/ci-ec2-design.md`, `.github/workflows/bench-ec2.yml`, `scripts/ec2-buildfarm.sh`,
    # the branch `chore/sq-uhqah-formalize-codex-ec2`, and `AWSServiceRoleForEC2Spot`.
    for number, blurb in (
        (941, "The `research/ci-ec2-design.md` OIDC pattern is the one to reuse here."),
        (942, "Wire the HEAVY tiers into `.github/workflows/bench-ec2.yml` and the nightly lane."),
        (943, "Flip `scripts/ec2-buildfarm.sh` fmt from ADVISORY to gating."),
        (944, "Stale branch `chore/sq-uhqah-formalize-codex-ec2` is unreachable by review."),
        (945, "The scoped role cannot create the `AWSServiceRoleForEC2Spot` SLR."),
    ):
        path_mention = issue(number, "Repair the alpha snapshot writer", ("area:alpha",),
                             body=blurb + spec)
        planned, _ = plan_repository([path_mention], all_labels, automation)
        checks.append((
            f"a path/branch/identifier containing ec2 is not fenced (#{number})",
            not is_ec2_measurement(path_mention)
            and any(m.kind == "stage" and m.number == number for m in planned)))

    # (e3) ...and the label mention does not become fence-able just by appearing in the TITLE.
    checks.append((
        "a TITLE that names the needs:ec2 label is not fenced either",
        not is_ec2_measurement(issue(946, "Auto-gate bench issues with needs:ec2", ()))))

    # (e4) THE FIX MUST NOT BECOME A FAIL-OPEN. The precision repair narrows WHICH mentions count,
    # never WHERE they may appear: a body that says the work runs on a box still fences. This is
    # the check that reds the rejected title-scoping variant, which on the live sparq board would
    # have dropped SIXTY rows — including #4040/#4056/#4352/#4370, whose titles say "bench",
    # "microbench" and "canonical host" and never say "ec2" at all.
    for number, blurb in (
        (950, "Gathered on the quiet EC2 reference box with CANONICAL=1."),
        (951, "This needs the DBPSB EC2/nightly tier, not the work box."),
        (952, "Work-box numbers are non-canonical; run it on EC2."),
        (953, "Requires the dedicated quiet-box protocol on the perf host."),
    ):
        body_run = issue(number, "Measure the alpha loader at 100M triples", ("area:bench",),
                         body=blurb + spec)
        planned, _ = plan_repository([body_run], all_labels, automation)
        checks.append((
            f"a body that says the work RUNS on the hardware still fences (#{number})",
            is_ec2_measurement(body_run)
            and any(m.kind == "needs-ec2" and m.number == number for m in planned)))

    # (e5) The free-word rule is LIVE, not shadowed. If a future edit renames or drops the bare
    # `ec2` entry, `EC2_PHRASE_KEYWORDS` silently regains a plain-substring `ec2` and every check
    # above goes green again while the defect is back — the decaying-control shape. Pin the
    # partition itself rather than trusting the derivation, and pin that curate reads the SHARED
    # one (#466) so the two lists cannot drift back apart into a wide copy and a narrow copy.
    checks.append((
        "the bare ec2 keyword is scanned ONLY by the free-word rule",
        EC2_BARE_KEYWORD in EC2_KEYWORDS
        and EC2_BARE_KEYWORD not in EC2_PHRASE_KEYWORDS
        and len(EC2_PHRASE_KEYWORDS) == len(EC2_KEYWORDS) - 1
        and set(EC2_PHRASE_KEYWORDS) | {EC2_BARE_KEYWORD} == set(EC2_KEYWORDS)))
    checks.append((
        "curate's EC2 signal IS the shared classifier's, partition included",
        (EC2_KEYWORDS, EC2_BARE_KEYWORD, EC2_PHRASE_KEYWORDS)
        == (_measurement_gate.EC2_KEYWORDS, _measurement_gate.EC2_BARE_KEYWORD,
            _measurement_gate.EC2_PHRASE_KEYWORDS)))

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
            'open_pr_alert_threshold = 5\n'
            '[repos."o/actions"]\n'
            'enabled = true\n'
            'allow_actions_bot_issues = true\n',
            encoding="utf-8",
        )
        loaded = {
            repo: (bots, allow_actions, target)
            for repo, bots, allow_actions, target
            in load_targets(policy_file, "registry[bot]")
        }
        scaled_automation, _, scaled_target = loaded["o/scaled"]
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
                       loaded["o/default"][2] == 12))

        actions_automation, actions_allowed, _ = loaded["o/actions"]
        planned, _ = plan_repository(
            [actions_issue], all_labels, actions_automation,
            allow_actions_bot_issues=actions_allowed,
        )
        checks.append(("policy-allowed actions bot is staged",
                       any(m.kind == "stage" and m.number == 211 for m in planned)))

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

        policy_file.write_text(
            '[repos."o/bad"]\n'
            'enabled = true\n'
            'allow_actions_bot_issues = "yes"\n',
            encoding="utf-8",
        )
        error = ""
        try:
            load_targets(policy_file, "registry[bot]")
        except CuratorError as exc:
            error = str(exc)
        checks.append(("non-boolean allow_actions_bot_issues is rejected loudly",
                       "allow_actions_bot_issues" in error and "boolean" in error))

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

    # ============================================================================================
    # registry #799 — `status:untriaged` IS AN ADMISSIBLE CANDIDATE STATE.
    #
    # Every check below is bound to a specific guard, and each was confirmed RED by deleting or
    # inverting that guard (see the PR body's mutation table).
    # ============================================================================================
    untriaged_labels = all_labels | {"status:untriaged", "status:available"}

    # (u1) THE HEADLINE GUARD. An issue carrying only `status:untriaged` is unstaged work, and the
    # curator is the ONLY lane that mints priority/area/status:ready. Inverting `is_staged` back
    # to `has_status` turns this stage into zero mutations.
    stuck = [issue(900, "Improve alpha parser behavior", ("status:untriaged", "area:alpha"))]
    planned, _ = plan_repository(stuck, untriaged_labels, automation)
    staged_now = [m for m in planned if m.kind == "stage"]
    checks.append(("a status:untriaged issue IS a staging candidate", len(staged_now) == 1))

    # (u2) ...and the SAME mutation strips it. `status:untriaged` is in
    # `ready-issues.BUSY_STATUS`, so an add-only stage leaves the issue unenumerable and the
    # repair drains nothing. Deleting the `remove=strip` argument makes this red while (u1)
    # stays green — which is exactly the vacuous-fix shape this guards against.
    checks.append(("...and the stage mutation strips status:untriaged",
                   bool(staged_now) and staged_now[0].remove == ("status:untriaged",)
                   and "status:ready" in staged_now[0].labels))

    # (u3) Only `status:untriaged` is unstaged. Any OTHER status — including untriaged ALONGSIDE
    # one (the `status:available` acctNN inventory records, and the contradictory
    # untriaged+ready pair `retriage.py` owns) — is still staged and never touched here.
    for label in ("status:ready", "status:in-progress", "status:blocked"):
        other = [issue(901, "Improve beta parser behavior", ("status:untriaged", label,
                                                            "area:beta"))]
        planned, _ = plan_repository(other, untriaged_labels, automation)
        checks.append((f"status:untriaged + {label} is staged, never re-staged",
                       not any(m.kind == "stage" for m in planned)))
    inventory = [issue(902, "acct09", ("status:untriaged", "status:available", "area:beta"))]
    planned, _ = plan_repository(inventory, untriaged_labels, automation)
    checks.append(("a status:available account record is never staged",
                   not any(m.kind == "stage" for m in planned)))

    # (u4) THE CLOSE PATH IS NOT WIDENED. `has_status` still guards duplicate closure, so
    # admitting 274 untriaged issues as staging candidates must not newly expose any of them to
    # automated closing. Replacing `has_status` with `is_staged` in the close branch makes this
    # red (the untriaged duplicate becomes closable).
    dupes = [
        issue(910, "Improve alpha parser behavior", ("status:untriaged", "area:alpha")),
        issue(911, "Improve alpha parser behavior", ("status:untriaged", "area:alpha")),
    ]
    planned, _ = plan_repository(dupes, untriaged_labels, automation)
    checks.append(("an untriaged duplicate is never auto-closed",
                   not any(m.kind == "close" for m in planned)))

    # (u5) THE STRIP IS BOUNDED AT THE MUTATION BOUNDARY, not by convention. execute_plan refuses
    # any removal that is not `status:untriaged` on a `stage`. Deleting the raise lets a
    # hand-built mutation strip anything.
    for bad in (Mutation("stage", 1, issue(1, "x"), ("status:ready",), remove=("needs:user",)),
                Mutation("needs-ec2", 1, issue(1, "x"), ("needs:ec2",),
                         remove=("status:untriaged",))):
        for apply_mode in (False, True):
            refused = ""
            try:
                execute_plan("o/r", [bad], "tok", apply=apply_mode)
            except CuratorError as exc:
                refused = str(exc)
            checks.append((f"execute_plan(apply={apply_mode}) refuses to strip "
                           f"{bad.remove[0]} on a {bad.kind}", "may only remove" in refused))

    # (u6) THE TARGET'S OWN AREA TAXONOMY. A repository's `area:*` labels are its declared surface
    # vocabulary; before this rule only sparq-shaped hints (`sparq-*` crates, `site/`, `gui/`,
    # `bench/`, `scripts/`) resolved, so every registry issue collapsed into `area:ci` and the
    # one-issue-per-package wave rule pinned the whole target at one stage per run. Deleting the
    # `declared` block makes this red.
    declared_area, reason = derive_area(
        issue(920, "The gamma sweep drops rows", ()), set(), all_labels)
    checks.append(("an issue whose title names a declared area resolves to it",
                   (declared_area, reason) == ("area:gamma", "title names a declared area")))
    # Fail-closed on ambiguity, exactly like every other branch of derive_area.
    ambiguous, reason = derive_area(
        issue(921, "Make gamma and delta agree", ()), set(), all_labels)
    checks.append(("two declared areas in one title is UNRESOLVED, never a coin flip",
                   ambiguous is None and reason == "multiple declared areas named in title"))
    # Word-boundary, not substring: `area:alpha` must not match "alphabetically". The body is
    # neutral on purpose — `long_body` mentions `scripts/`, which the LATER path-hint rule
    # resolves to `area:ci`, and a fixture that lets a different rule answer proves nothing about
    # this one.
    boundary, reason = derive_area(
        issue(922, "Sort the output alphabetically", (), body="No paths here. " * 20),
        set(), all_labels)
    checks.append(("a declared area matches on word boundaries, not substrings",
                   boundary is None and "declared" not in reason))
    # An EXISTING area label still wins — the new rule is a last resort, not an override.
    existing, reason = derive_area(
        issue(923, "The gamma sweep drops rows", ("area:beta",)), {"area:beta"}, all_labels)
    checks.append(("an existing area label still wins over the title",
                   (existing, reason) == ("area:beta", "existing")))

    # (u7) A FENCE WHOSE LABEL THE TARGET LACKS skips the ISSUE (never admits it) and fails the
    # RUN — it no longer aborts the whole target's plan. Deleting the `continue`/log makes the
    # first assertion red; deleting main()'s FENCE_UNAVAILABLE scan makes a silent pass possible,
    # which the second assertion pins by requiring the marker in the log.
    without_ec2 = all_labels - {"needs:ec2"} | {"status:untriaged"}
    mixed = [
        issue(930, "Benchmark the alpha loader on a dedicated EC2 instance and report ns/op",
              ("status:untriaged",),
              body="Run the benchmark on EC2 hardware and record the measured numbers. "
                   + "Detailed acceptance criteria. " * 12),
        issue(931, "Improve gamma parser behavior", ("status:untriaged", "area:gamma")),
    ]
    planned, logs = plan_repository(mixed, without_ec2, automation)
    fence_lines = [line for line in logs if line.startswith(FENCE_UNAVAILABLE)]
    checks.append(("an unavailable fence never admits its issue",
                   not any(m.number == 930 for m in planned)))
    checks.append(("an unavailable fence is logged for main() to fail the run on",
                   len(fence_lines) == 1 and "needs:ec2" in fence_lines[0]))
    checks.append(("...and the REST of the target is still curated",
                   any(m.kind == "stage" and m.number == 931 for m in planned)))

    # [OPUS-5] The unattributable class must be REPORTED, not silently re-skipped forever.
    # "Zebra component" matches no crate, path or area label, so derive_area refuses it.
    # NB: a body with NO path and NO crate token — the shared long_body names scripts/frontier.py,
    # which would itself supply an area:ci path hint and make this fixture attributable.
    # A function+line reference satisfies is_well_specified WITHOUT naming a path, so the
    # fixture reaches derive_area and is refused there (rather than being filtered earlier).
    blind_body = ("Rework zebra_behaviour() at line 42 so the documented outcome holds. "
                  "Acceptance criteria: the described outcome is verified by a test. " * 6)
    blind = [issue(500, "Zebra component needs rework", body=blind_body),
             issue(501, "Quokka component needs rework", body=blind_body)]
    _planned, blind_logs = plan_repository(blind, all_labels, automation)
    # Matched on the payload, so the SEVERITY prefix is a separate, asserted property rather
    # than something the matcher quietly tolerates either way.
    report = [line for line in blind_logs if "unattributable: " in line]
    checks.append((
        "unattributable issues are counted and named, not silently skipped",
        len(report) == 1 and "unattributable: 2 issue(s)" in report[0]
        and "#500" in report[0] and "#501" in report[0]))
    # ...and the non-zero branch is an ANNOTATION. A plain print leaves the class at line ~207
    # of a 543-line log in a cron nothing reads — distinguishable-if-you-open-the-log, not
    # visible. This is the severity channel of the precedent the comment cites
    # (dispatch.yml's roleless-report), and dropping the prefix must red HERE.
    checks.append((
        "a NON-ZERO unattributable count is a ::warning:: annotation, not a buried log line "
        "(the severity channel of the cited dispatch.yml precedent)",
        len(report) == 1 and report[0].startswith("::warning::unattributable: ")))
    # The always-printed half: a report that only appears when non-zero is indistinguishable
    # from a report that stopped running. Deleting the zero case must red THIS check.
    _planned, clean_logs = plan_repository(
        [issue(502, "Improve alpha component behavior", ("area:alpha",))],
        all_labels, automation)
    clean_report = [line for line in clean_logs if "unattributable: " in line]
    checks.append((
        "the unattributable report is emitted even when the count is ZERO",
        clean_report == ["unattributable: 0 issue(s) have NO confident area and cannot be "
                         "staged until an area is attributed"]))
    # ...and at ZERO it is a PLAIN line, exactly as dispatch.yml does it. A `::warning::` every
    # tick on a healthy board is how an annotation stops being read, which would undo the row
    # above by a different route.
    checks.append((
        "a ZERO count is NOT annotated — an every-tick warning trains the reader to skip it",
        len(clean_report) == 1 and not clean_report[0].startswith("::warning::")))
    # THE BRANCH THAT ACTUALLY FIRES. Every fixture above is under the 20-issue display cap, so
    # `len(unattributable) > 20` had ZERO coverage while being true on every live tick — the
    # marquee path, untested. 21 issues: 20 named, one folded into the suffix.
    many = [issue(600 + index, f"Zebra component {index} needs rework", body=blind_body)
            for index in range(21)]
    _planned, many_logs = plan_repository(many, all_labels, automation)
    many_report = [line for line in many_logs if "unattributable: " in line]
    checks.append((
        "the >20 display cap names exactly 20 and folds the REST into an accurate (+N more) "
        "suffix — the only branch that fires on the live board",
        len(many_report) == 1
        and "unattributable: 21 issue(s)" in many_report[0]
        and many_report[0].count("#") == 20
        and many_report[0].endswith("(+1 more)")
        and "#619" in many_report[0] and "#620" not in many_report[0]))

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
    unavailable_fences = 0
    for repo, automation_logins, allow_actions_bot_issues, target_ready in targets:
        owner = repo.split("/", 1)[0]
        token = tokens.get(owner, ambient)
        if not token:
            raise CuratorError(f"no target token for enabled owner {owner}")
        issues, repo_labels = fetch_repository(repo, token)
        mutations, logs = plan_repository(
            issues, repo_labels, automation_logins, close_limit=remaining_closes,
            target_ready=target_ready,
            allow_actions_bot_issues=allow_actions_bot_issues,
        )
        print(frontier_header(repo, issues, target_ready))
        for line in logs:
            print(line)
            if line.startswith(FENCE_UNAVAILABLE):
                unavailable_fences += 1
        actual_closes = execute_plan(repo, mutations, token, args.apply)
        used = actual_closes if args.apply else sum(m.kind == "close" for m in mutations)
        remaining_closes -= used
    if unavailable_fences:
        print(f"::error::{unavailable_fences} issue(s) matched a fence whose label the target "
              f"repository does not carry; they were skipped, never admitted — create the "
              f"missing label(s) named above", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CuratorError as exc:
        print(f"curate-frontier: {exc}", file=sys.stderr)
        sys.exit(1)
