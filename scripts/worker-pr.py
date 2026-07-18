#!/usr/bin/env python3
# Target-PR control plane for the cross-provider review/fix loop: durable review-state labels,
# run-keyed round/no-change/gate-fail markers, registry-recorded provenance + verdicts, and the
# ONLY code path that may arm a pull request. It never reads registry account credentials.
"""GitHub PR helper for the registry review-fix pipeline (mirror of worker-issue.py).

Trust posture (locked decisions, review blueprint):
- Provenance is REGISTRY-recorded at publish time and read back only from the registry; commit
  trailers/PR bodies are audit-only. A PR without a provenance record is never reviewed.
- The reviewer model is read-only; ALL PR mutations happen here, host-side, AFTER the worker's
  byte-identical-tree check. The verdict crosses the trust boundary as a schema-validated JSON
  file, never as parsed model stdout.
- `review:*` labels are a SEPARATE namespace from the issue `status:*` values.
- Arming (`ready-and-arm`) is host-only, one-shot, and gated on: schema-valid approve verdict,
  reviewer provider != implementer provider, reviewer account != implementer account, and the
  live head SHA still being the reviewed SHA (re-read immediately before arm).
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REVIEW_LABELS = ("review:needs", "review:changes", "review:pass", "review:needs-user")
LABEL_COLOURS = {
    "review:needs": "1d76db",
    "review:changes": "e99695",
    "review:pass": "0e8a16",
    "review:needs-user": "b60205",
}
# Run-keyed durable markers (bot comments). Each carries the round + the workflow run key so a
# re-run of the same phase is idempotent (mirror worker-issue record_attempt) and stop conditions
# are computed from ordered, run-keyed markers — never raw comment counts.
ROUND_MARKER = "<!-- sparq-review-round:v1"
MARKER_KINDS = {
    "nochange": "<!-- sparq-fix-nochange:v1",
    "gatefail": "<!-- sparq-fix-gatefail:v1",
    "missed": "<!-- sparq-fix-missed:v1",
}
# Model-escalation accounting (maintainer directive 2026-07-17). Durable, bot-authored markers:
# the fix outcome records WHICH model executed each fix round (the commit [alias] tag is not
# durable enough — squash merges and force-pushes lose it), a budget extension records the pinned
# fix-model FLOOR, and the findings comment records the reviewer's progress grade for its round.
# All are parsed with the same bot-login trust filter as the round markers.
FIX_MODEL_MARKER = "<!-- sparq-fix-model:v1"
MODEL_PIN_MARKER = "<!-- sparq-fix-modelpin:v1"
PROGRESS_MARKER = "<!-- sparq-review-progress:v1"
SAFE_ALIAS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
# Provider escalation ladders in ASCENDING capability order. anthropic: sonnet < fable < opus
# (opus is the terminal fix tier for hard cases); openai is single-tier (terra) — no ladder, so
# only the progress extension applies there. A pin or recorded model outside its provider ladder
# is REJECTED (hostile-input surface: a forged marker must never select an arbitrary
# provider_model — concrete ids are still resolved from protected target routing by alias).
ESCALATION_LADDERS = {"anthropic": ["sonnet", "fable", "opus"], "openai": ["terra"]}
PROGRESS_VALUES = ("improving", "stagnant", "regressing")
HARD_CAP_ROUNDS = 6  # absolute bound on review rounds across BOTH extension mechanisms
REVIEWED_SHA_RE = re.compile(r"<!-- sparq-reviewed-sha:([0-9a-f]{40}|none) -->")
WORKER_HEAD_RE = re.compile(r"sparq-agent/issue-([1-9][0-9]*)-[A-Za-z0-9._-]+")
# Human-owned PR labels: review:needs-user is the loop's own terminal escalation, needs:user is
# groom's parked-PR marker ("Human attention required"). Either stands the loop down.
HUMAN_OWNED_LABELS = ("review:needs-user", "needs:user")
SECURITY_KEYWORDS = ("zk", "mpc", "crypto", "auth", "e2ee")
# [OPUS-4.8] B3 / defect #2,#4: the trust-surface FILE paths. A worker PR whose diff touches ANY
# of these gate-weakening / orchestration-control files must NOT auto-arm regardless of its issue
# labels — the cross-provider review still runs (automated), but the final arm click is a HUMAN's.
# This is the ACTIVE, WIRED FILE-level control (previously the policy-row `security_paths` was
# unwired config). Prefix-matched against every PR-diff path; a trailing `/` marks a directory
# subtree, a bare path is an exact-or-descendant match. review-fix.yml passes the resolved list
# from the target policy row; this constant is the built-in fail-closed default when no list is
# supplied (so the guard is never silently absent).
DEFAULT_TRUST_SURFACE_PATHS = (
    "scripts/dispatch-claim.py",
    "scripts/worker-live.sh",
    "scripts/worker-pr.py",
    "scripts/worker-issue.py",
    "scripts/select-and-claim.py",
    "scripts/groom.py",
    "scripts/policy-resolve.py",
    "scripts/route-resolve.py",
    "scripts/ready-issues.py",
    "scripts/dispatch-plan.py",
    "scripts/triage.py",
    "scripts/broker-refresh.py",
    "scripts/account-usage.py",
    ".github/workflows/",
    "policy/",
    "orchestration/",
    ".claude/agents/",
)
VERDICTS = {"approve", "request_changes"}
SEVERITIES = {"blocker", "major", "minor", "nit"}
MAX_ISSUES = 10
PROVENANCE_DIR = "orchestration/provenance"
VERDICT_DIR = "orchestration/review-verdicts"


class WorkerPrError(RuntimeError):
    """A concise, credential-free operational error."""


# ---- pure helpers (unit-tested by --self-test) ---------------------------------------------------
def account_hash(handle, salt):
    """Privacy-preserving account fingerprint (locked decision 22a): the registry is PUBLIC, so
    provenance records never store the raw acctNN handle — only
    sha256(handle + ':' + PROVENANCE_SALT)[:16]. The reviewer != implementer assertion compares
    these hashes (the reviewer side is hashed the same way at claim time)."""
    if not handle or not salt:
        raise WorkerPrError("account hashing requires both a handle and PROVENANCE_SALT")
    return hashlib.sha256(f"{handle}:{salt}".encode()).hexdigest()[:16]


def _alert_route():
    """Ops-alert destination (locked decision 22c): a maintainer-set ALERT_REPO (+ optional
    ALERT_TOKEN) routes the account-enumerating alert issue to a PRIVATE repo; unset falls back
    to the registry repo + workflow token (current behaviour)."""
    repo = os.environ.get("ALERT_REPO") or os.environ.get("REGISTRY_REPO")
    token = os.environ.get("ALERT_TOKEN") or os.environ.get("REGISTRY_ALERT_TOKEN")
    return repo, token


def _bot_comments(comments, bot_login):
    bot = bot_login.casefold()
    return [c for c in comments
            if str(c.get("user", {}).get("login", "")).casefold() == bot]


def count_rounds(comments, bot_login):
    """Highest review round recorded by the bot (0 when no review has run)."""
    best = 0
    for comment in _bot_comments(comments, bot_login):
        for match in re.finditer(
                re.escape(ROUND_MARKER) + r" n=([1-9][0-9]*) run=\S+ -->",
                str(comment.get("body", ""))):
            best = max(best, int(match.group(1)))
    return best


def marker_runs(comments, bot_login, kind, round_n):
    """Distinct run keys recorded for a marker kind at a given round (ordered-marker counting)."""
    prefix = MARKER_KINDS[kind]
    runs = set()
    for comment in _bot_comments(comments, bot_login):
        for match in re.finditer(
                re.escape(prefix) + r" round=([1-9][0-9]*) run=(\S+) -->",
                str(comment.get("body", ""))):
            if int(match.group(1)) == round_n:
                runs.add(match.group(2))
    return runs


def round_recorded(comments, bot_login, round_n, run_key):
    marker = f"{ROUND_MARKER} n={round_n} run={run_key} -->"
    return any(marker in str(c.get("body", "")) for c in _bot_comments(comments, bot_login))


def fix_round_models(comments, bot_login):
    """{round: sorted model aliases} recorded by the bot's fix-outcome model markers — the
    durable per-round record of WHICH model executed each fix round."""
    result = {}
    pattern = re.compile(
        re.escape(FIX_MODEL_MARKER)
        + r" round=([1-9][0-9]*) model=([A-Za-z0-9][A-Za-z0-9_.-]*) run=\S+ -->")
    for comment in _bot_comments(comments, bot_login):
        for match in pattern.finditer(str(comment.get("body", ""))):
            result.setdefault(int(match.group(1)), set()).add(match.group(2))
    return {round_n: sorted(models) for round_n, models in result.items()}


def round_progress(comments, bot_login):
    """{round: progress} recorded in the bot's findings comments (the durable round-marker copy
    of each verdict's progress grade; the registry verdict record is the primary source)."""
    result = {}
    pattern = re.compile(
        re.escape(PROGRESS_MARKER)
        + r" round=([1-9][0-9]*) progress=(improving|stagnant|regressing) -->")
    for comment in _bot_comments(comments, bot_login):
        for match in pattern.finditer(str(comment.get("body", ""))):
            result[int(match.group(1))] = match.group(2)
    return result


def pinned_fix_floor(comments, bot_login, provider):
    """Highest recorded fix-model floor pin, validated against the provider ladder. A bot marker
    naming a tier OUTSIDE the ladder raises (fail closed): silently ignoring a corrupt pin would
    run the unpinned chain — exactly the fall-back-down the pin exists to prevent — so the
    caller escalates loudly instead."""
    ladder = ESCALATION_LADDERS.get(provider)
    if not ladder:
        raise WorkerPrError("unknown provider for the escalation ladder")
    pattern = re.compile(
        re.escape(MODEL_PIN_MARKER)
        + r" round=([1-9][0-9]*) tier=([A-Za-z0-9][A-Za-z0-9_.-]*) run=\S+ -->")
    floor = None
    for comment in _bot_comments(comments, bot_login):
        for match in pattern.finditer(str(comment.get("body", ""))):
            tier = match.group(2)
            if tier not in ladder:
                raise WorkerPrError("recorded model pin is not a ladder member for this provider")
            if floor is None or ladder.index(tier) > ladder.index(floor):
                floor = tier
    return floor


def pinned_fix_chain(provider, floor):
    """FLOOR semantics for a pinned fix chain: only ladder members AT OR ABOVE the pin, cheapest
    first. Tiers below the floor are never offered to the allocator — see the defer-not-fallback
    rationale on decide_budget."""
    ladder = ESCALATION_LADDERS.get(provider)
    if not ladder or floor not in ladder:
        raise WorkerPrError("model pin must be a ladder member for its provider")
    return ladder[ladder.index(floor):]


def decide_budget(rounds_used, per_round_models, latest_progress, provider,
                  base_rounds=3, hard_cap=HARD_CAP_ROUNDS,
                  pending_fix_models=(), pin_floor=None):
    """PURE combined round-budget policy (maintainer directive 2026-07-17): decide whether the
    review<->fix loop continues, extends, or hands the PR to a human once the base round budget
    is spent. Every input derives from hostile-parsed marker/verdict data and is validated.

    Inputs: rounds_used (recorded review rounds), per_round_models (every model alias that
    executed a fix round, from the durable fix-model markers), latest_progress (the LATEST
    verdict's progress grade — improving/stagnant/regressing, or None for round 1 / unrecorded),
    provider (the implementer's provider, whose ladder governs fix escalation),
    pending_fix_models (model aliases recorded for the LATEST round's fix when that fix is
    PUSHED but not yet re-reviewed — i.e. the caller is asking about a needs-review head that
    carries an ungraded fix; empty everywhere else), pin_floor (the recorded fix-model floor
    pin, if any — validated as a ladder member).

    Returns {"action", "pin"} with action one of:
      continue         — rounds_used is below the base budget; nothing special to do.
      extend-pending-review — budget spent, but a fix executed AT/ABOVE the pinned floor (any
                         ladder member when unpinned) is pushed and not yet re-reviewed:
                         authorize its re-review. Grading an already-granted, already-executed
                         fix round is NOT a new fix-round spend — the tick that granted that fix
                         proved rounds_used < hard cap, so the re-review lands at <= hard cap.
                         Without this, the model-pin extension's terminal grant ORPHANS the
                         top-tier fix: the executed opus fix falsifies the "top tier not yet
                         run" predicate via its own fix-model marker, while the latest recorded
                         progress grade predates that fix (it graded the weaker tier's stagnant
                         output — the very reason escalation fired), so neither mechanism below
                         could authorize the re-review and the scarce top-tier round would be
                         burned unreviewed with a potentially-approving verdict unreachable.
                         Precedes both mechanisms: with an ungraded pushed fix, the next step is
                         grading it — every extend/stop question is answered better by the fresh
                         grade the re-review produces. A pending fix BELOW the pinned floor does
                         NOT qualify (the pin forbade that tier from running; a marker claiming
                         it did is a pin violation or a forgery and must not mint extensions).
      extend-model-pin — budget spent, but some fix round ran BELOW the provider's top tier and
                         the top tier has not yet fixed: extend (hard cap 6 total rounds) and
                         pin the fix-model floor to `pin`, the tier ABOVE the highest that
                         already ran. Takes precedence over the progress extension because a
                         stronger model resets the quality question.
      extend-progress  — budget spent on the top tier (or with no fix-model record), but the
                         latest verdict grades the PR IMPROVING: extend, at most 6 total rounds.
      needs-user       — the hard cap is reached, or the top tier is stagnant/regressing/ungraded.

    DEFER-NOT-FALLBACK (the WHY, for every consumer of `pin`): once a floor is pinned, tiers
    below it must never run another fix round for the PR. The extended budget exists precisely
    because the below-floor model already burned the base budget without converging; if the
    pinned tier has no available account the fix DEFERS to a later tick — falling back down the
    chain would silently spend the extension re-running the model that already failed."""
    ladder = ESCALATION_LADDERS.get(provider)
    if not ladder:
        raise WorkerPrError("unknown provider for the escalation ladder")
    if not isinstance(rounds_used, int) or isinstance(rounds_used, bool) or rounds_used < 0:
        raise WorkerPrError("rounds_used must be a non-negative integer")
    if not isinstance(base_rounds, int) or isinstance(base_rounds, bool) or base_rounds < 1:
        raise WorkerPrError("base_rounds must be a positive integer")
    models = sorted(set(per_round_models))
    for model in models:
        if model not in ladder:
            raise WorkerPrError("a recorded fix-round model is not a ladder member")
    pending = sorted(set(pending_fix_models))
    for model in pending:
        if model not in ladder:
            raise WorkerPrError("a pending fix-round model is not a ladder member")
    if pin_floor is not None and pin_floor not in ladder:
        raise WorkerPrError("pin_floor must be a ladder member for its provider")
    if latest_progress is not None and latest_progress not in PROGRESS_VALUES:
        raise WorkerPrError("latest_progress must be improving, stagnant, regressing, or None")
    if rounds_used < base_rounds:
        return {"action": "continue", "pin": None}
    if rounds_used >= hard_cap:
        return {"action": "needs-user", "pin": None}
    # Re-review authorization — "may we GRADE a fix round already granted and executed" is a
    # different question from "may we SPEND another fix round" (see extend-pending-review in the
    # docstring). The hard-cap check above keeps rounds_used < hard_cap here, so the authorized
    # re-review lands at rounds_used + 1 <= hard_cap.
    floor_index = ladder.index(pin_floor) if pin_floor is not None else 0
    if any(ladder.index(model) >= floor_index for model in pending):
        return {"action": "extend-pending-review", "pin": None}
    # Mechanism 1 — model escalation: the top tier has not yet run a fix round, so this is not
    # yet a top-model failure. (No recorded fix rounds at all = nothing to escalate FROM; the
    # progress mechanism below still applies.)
    if models and ladder[-1] not in models:
        highest = max(models, key=ladder.index)
        return {"action": "extend-model-pin", "pin": ladder[ladder.index(highest) + 1]}
    # Mechanism 2 — progress extension: only an explicitly IMPROVING latest verdict extends.
    if latest_progress == "improving":
        return {"action": "extend-progress", "pin": None}
    return {"action": "needs-user", "pin": None}


def reviewed_sha_of(body):
    match = REVIEWED_SHA_RE.search(body or "")
    return match.group(1) if match else None


def replace_reviewed_sha(body, sha):
    body = body or ""
    marker = f"<!-- sparq-reviewed-sha:{sha} -->"
    if REVIEWED_SHA_RE.search(body):
        return REVIEWED_SHA_RE.sub(marker, body, count=1)
    return body + "\n\n" + marker + "\n"


def security_flagged(labels, extra_keywords=()):
    """Security surfaces never auto-arm: substring keywords mirror routing match_labels; trust:* is
    a prefix namespace. `extra_keywords` (defect #3) lets the caller inject the TARGET routing's
    own `match_labels` keywords so a per-target trust surface (e.g. the registry's area:worker /
    area:dispatch / area:set-up-account) is flagged too — the built-in SECURITY_KEYWORDS alone did
    not cover the registry's trust areas, so its ready issues classified as non-security and would
    auto-arm."""
    keywords = tuple(SECURITY_KEYWORDS) + tuple(extra_keywords)
    return (any(keyword in label for label in labels for keyword in keywords)
            or any(label.startswith("trust:") for label in labels))


def _norm_path(path):
    norm = str(path).strip().replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm.lstrip("/")


def trust_surface_paths_touched(diff_files, surface_paths=DEFAULT_TRUST_SURFACE_PATHS):
    """[OPUS-4.8] B3 / defects #2,#4: the ACTIVE FILE-level trust-surface control. Returns the
    sorted subset of `diff_files` that touch a gate-weakening / orchestration-control path, so the
    ARM path can withhold auto-arm and route to a HUMAN. A path in `surface_paths` ending in `/`
    matches that directory subtree; a bare path matches itself or any descendant. Hostile-tolerant:
    non-string/empty entries are ignored (a poisoned diff-file list can only DEMOTE to human-arm,
    never silently approve). This is what `policy/repos.toml`'s `security_paths` NOW drives —
    review-fix.yml resolves the row's list and passes it here."""
    surfaces = [_norm_path(p) for p in surface_paths if isinstance(p, str) and p.strip()]
    touched = set()
    for raw in diff_files:
        if not isinstance(raw, str) or not raw.strip():
            continue
        path = _norm_path(raw)
        for surface in surfaces:
            if surface.endswith("/"):
                if path == surface.rstrip("/") or path.startswith(surface):
                    touched.add(path)
                    break
            elif path == surface or path.startswith(surface + "/"):
                touched.add(path)
                break
    return sorted(touched)


def human_owned(labels):
    """A PR carrying review:needs-user (loop escalation) or needs:user (groom's parked-PR
    "Human attention required" marker) is human-owned terminal: no autonomous disarm, redraft,
    fix push, or review may touch it until a human clears the label."""
    return any(label in HUMAN_OWNED_LABELS for label in labels)


def validate_verdict(document, diff_files):
    """Schema-validate a reviewer verdict. The reviewer read hostile PR content, so every field is
    enum/length-capped and file paths must be inside the PR diff file set. Raises on any violation
    (the caller treats an invalid verdict as VOID)."""
    if not isinstance(document, dict):
        raise WorkerPrError("verdict must be a JSON object")
    allowed = {"verdict", "injection_detected", "summary", "issues", "confidence", "progress"}
    required = {"verdict", "injection_detected", "summary", "issues"}
    keys = set(document)
    if not required <= keys or not keys <= allowed:
        raise WorkerPrError("verdict fields are invalid")
    if document["verdict"] not in VERDICTS:
        raise WorkerPrError("verdict value must be approve or request_changes")
    if not isinstance(document["injection_detected"], bool):
        raise WorkerPrError("injection_detected must be boolean")
    summary = document["summary"]
    if not isinstance(summary, str) or len(summary) > 2000:
        raise WorkerPrError("summary must be a string of at most 2000 characters")
    if "confidence" in document:
        confidence = document["confidence"]
        if (not isinstance(confidence, (int, float)) or isinstance(confidence, bool)
                or not 0.0 <= float(confidence) <= 1.0):
            raise WorkerPrError("confidence must be a number in [0, 1]")
    if "progress" in document:
        # Round-over-round progress grade (maintainer directive 2026-07-17): improving /
        # stagnant / regressing, or null on round 1 / when no prior findings are available.
        progress = document["progress"]
        if progress is not None and progress not in PROGRESS_VALUES:
            raise WorkerPrError("progress must be improving, stagnant, regressing, or null")
    issues = document["issues"]
    if not isinstance(issues, list) or len(issues) > MAX_ISSUES:
        raise WorkerPrError(f"issues must be a list of at most {MAX_ISSUES} entries")
    files = set(diff_files)
    has_blockers = False
    for index, issue in enumerate(issues, 1):
        where = f"verdict issue #{index}"
        if not isinstance(issue, dict) or set(issue) != {"severity", "file", "title", "body",
                                                         "fix_hint"}:
            raise WorkerPrError(f"{where} fields are invalid")
        if issue["severity"] not in SEVERITIES:
            raise WorkerPrError(f"{where} severity is invalid")
        if issue["file"] not in files:
            raise WorkerPrError(f"{where} file is outside the PR diff file set")
        for field, cap in (("title", 200), ("body", 2000), ("fix_hint", 2000)):
            if not isinstance(issue[field], str) or len(issue[field]) > cap:
                raise WorkerPrError(f"{where} {field} exceeds its length cap")
        has_blockers = has_blockers or issue["severity"] in {"blocker", "major"}
    return has_blockers


def decide_disarm(armed, draft, head_sha, reviewed_sha, when):
    """Pure decision for `disarm` (registry issue #42: a GitHub auto-merge arm LATCHES across
    force-pushes, so a post-arm head mutation could merge a never-reviewed tree on green CI).

    when="mismatch" — the sweep-side safety invariant: act on a PR whose live head differs from
    its recorded reviewed-sha AND that is either ARMED (the latch would merge a never-reviewed
    tree) or READY-but-unarmed (a disarm interrupted between disable-auto and redraft, or an arm
    crashed between ready and merge --auto — completing the redraft is what makes the sweep
    re-entrant across those crash windows). Matching SHAs are never touched: an armed match is a
    valid arm, and a ready-unarmed match is the valid arm=false-policy terminal (human merges).
    A drafted unarmed PR has nothing latched and nothing interrupted — never touched.
    when="always" — the autonomous-fix admission posture: any armed or non-draft worker PR is
    returned to the drafted, unarmed loop state BEFORE a fix push can ride a stale arm latch
    (the CLAIM caller re-derives the live repair trigger before ever requesting this mode).

    Returns the ordered action list (possibly empty = DO-NOTHING): disable-auto first (kill the
    latch), then redraft (back under the sweep's draft-only review enumeration), then relabel
    (review:* -> needs so the re-review/approve path re-arms)."""
    if when not in {"mismatch", "always"}:
        raise WorkerPrError("disarm mode must be mismatch or always")
    if when == "mismatch" and not ((armed or not draft) and head_sha != reviewed_sha):
        return []
    if when == "always" and not armed and draft:
        return []
    actions = []
    if armed:
        actions.append("disable-auto")
    if not draft:
        actions.append("redraft")
    actions.append("relabel")
    return actions


# Issue #69: bound on the first-parent walk from a live head back to its reviewed sha. The
# pr-freshness update-branch automation adds a handful of merge commits between reviews; a
# longer chain is ambiguity and fails closed to the normal mismatch disarm.
CARRY_FORWARD_CHAIN_LIMIT = 20


def merge_only_advance(head_sha, reviewed_sha, commit_parents, limit=CARRY_FORWARD_CHAIN_LIMIT):
    """Issue #69 half 1, SHAPE check (pure): walk the FIRST-parent chain from the live head
    down to the reviewed sha. The advance qualifies for carry-forward only when every
    intervening commit is a two-parent merge — the head moved exclusively by merging
    something in (update-branch), never by new work commits. Returns the ordered
    [(merge_sha, second_parent_sha), ...] pairs (head first) for the caller to verify each
    second parent against the default branch, or None on ANY other shape: a non-merge or
    octopus commit, an unknown/malformed commit, or a chain longer than `limit` (fail
    closed — the normal mismatch disarm proceeds). Shape alone cannot rule out an evil
    merge, so the caller must ALSO hold diff-identity (diff_fingerprint) before rebinding."""
    if head_sha == reviewed_sha:
        return []
    pairs = []
    current = head_sha
    while current != reviewed_sha:
        if len(pairs) >= limit:
            return None
        parents = commit_parents.get(current)
        if (not isinstance(parents, (list, tuple)) or len(parents) != 2
                or not all(isinstance(parent, str) and parent for parent in parents)):
            return None
        pairs.append((current, parents[1]))
        current = parents[0]
    return pairs


def diff_fingerprint(files):
    """Issue #69 half 1, CONTENT check (pure): a canonical fingerprint of a compare-API
    file list (the PR's diff vs its merge base). Equal fingerprints before and after the
    advance mean the reviewed CONTENT is unchanged: a merge that alters what the PR does
    to any file changes that file's patch (context lines included, so a default-branch
    edit to a PR-touched file is caught even when the merge auto-resolved cleanly) or its
    head blob sha. Returns None when the list or any entry is malformed, or an entry
    carries neither a blob sha nor a patch (unfingerprintable => fail closed)."""
    if not isinstance(files, list):
        return None
    rows = []
    for entry in files:
        if not isinstance(entry, dict):
            return None
        name = entry.get("filename")
        sha = entry.get("sha")
        patch = entry.get("patch")
        if not isinstance(name, str) or not name:
            return None
        if not isinstance(sha, str) and not isinstance(patch, str):
            return None
        rows.append((name, str(entry.get("status") or ""),
                     str(entry.get("previous_filename") or ""),
                     sha if isinstance(sha, str) else "",
                     patch if isinstance(patch, str) else ""))
    return tuple(sorted(rows))


def decide_review(verdict, has_blockers, injection, round_n, max_rounds, security,
                  budget_action="needs-user"):
    """The review-verdict state machine. Every path arms once, requests one fix round, or stops
    at a human — never loops unboundedly. On round-budget exhaustion the caller supplies
    decide_budget's action: an extension (model pin or improving progress) keeps the loop in
    `changes`, bounded by decide_budget's own hard cap; anything else (including the fail-closed
    default) stops at a human."""
    if injection:
        return "needs-user"
    if verdict == "approve" and not has_blockers:
        # Decision 7: security surfaces (zk/mpc/crypto/auth/e2ee/trust:*) never auto-arm.
        return "needs-user" if security else "arm"
    # request_changes, or a contradictory approve-with-blockers (fail closed as changes).
    if round_n >= max_rounds and budget_action not in {"extend-model-pin", "extend-progress"}:
        return "needs-user"
    return "changes"


def decide_fix(injection, made_changes, gate_ok, pushed, nochange_runs, gatefail_runs):
    """The fix-outcome state machine. no-change twice for the SAME round (round only advances on a
    review) or gate-fail twice for the same round => a disagreement a human must break."""
    if injection:
        return "needs-user"
    if not made_changes:
        return "needs-user" if nochange_runs >= 2 else "stay-changes"
    if not gate_ok:
        return "needs-user" if gatefail_runs >= 2 else "stay-changes"
    return "re-review" if pushed else "stay-changes"


# ---- GitHub I/O ----------------------------------------------------------------------------------
def _run_gh(args, *, input_text=None, check=True, env=None):
    merged_env = None
    if env:
        merged_env = {**os.environ, **env}
    result = subprocess.run(["gh", *args], input=input_text, capture_output=True, text=True,
                            check=False, env=merged_env)
    if check and result.returncode != 0:
        raise WorkerPrError(f"GitHub API request failed for {args[1] if len(args) > 1 else 'request'}")
    return result


def _gh_json(args, *, input_doc=None, env=None):
    raw = _run_gh(args, input_text=json.dumps(input_doc) if input_doc is not None else None,
                  env=env).stdout
    try:
        return json.loads(raw or "null")
    except json.JSONDecodeError as exc:
        raise WorkerPrError("GitHub API returned malformed JSON") from exc


def _paginated_comments(repo, pr_number):
    pages = _gh_json([
        "api", "--paginate", "--slurp", f"repos/{repo}/issues/{pr_number}/comments?per_page=100",
    ])
    if not isinstance(pages, list):
        raise WorkerPrError("GitHub API returned malformed comments")
    return [item for page in pages if isinstance(page, list) for item in page]


def _pr_changed_files(repo, pr_number):
    """[OPUS-4.8] B3: the LIVE changed-file paths of a PR (paginated). Used by ready_and_arm's
    trust-surface re-derivation so the arm gate keys on the actual diff (renamed paths included),
    not a planning-time snapshot. Malformed entries are dropped (fail closed toward human arm)."""
    pages = _gh_json([
        "api", "--paginate", "--slurp", f"repos/{repo}/pulls/{pr_number}/files?per_page=100",
    ])
    if not isinstance(pages, list):
        raise WorkerPrError("GitHub API returned malformed PR files")
    files = []
    for page in pages:
        if not isinstance(page, list):
            continue
        for entry in page:
            name = entry.get("filename") if isinstance(entry, dict) else None
            if isinstance(name, str) and name.strip():
                files.append(name)
            # A rename also exposes the old path — both sides must be checked.
            prev = entry.get("previous_filename") if isinstance(entry, dict) else None
            if isinstance(prev, str) and prev.strip():
                files.append(prev)
    return files


def _write_outputs(values):
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as output:
        for key, value in values.items():
            text = str(value).lower() if isinstance(value, bool) else str(value)
            if "\n" in text or "\r" in text:
                raise WorkerPrError(f"unsafe multiline output {key}")
            output.write(f"{key}={text}\n")


def _ensure_label(repo, label):
    if _run_gh(["api", f"repos/{repo}/labels/{label}"], check=False).returncode == 0:
        return
    _gh_json(
        ["api", "-X", "POST", f"repos/{repo}/labels", "--input", "-"],
        input_doc={"name": label, "color": LABEL_COLOURS[label],
                   "description": "Registry cross-provider review-loop state"},
    )


def _remove_label(repo, pr_number, label):
    result = _run_gh(
        ["api", "-X", "DELETE", f"repos/{repo}/issues/{pr_number}/labels/{label}"], check=False
    )
    if result.returncode != 0 and "HTTP 404" not in result.stderr:
        raise WorkerPrError(f"GitHub API could not remove PR label {label}")


def _comment(repo, pr_number, body):
    _gh_json(
        ["api", "-X", "POST", f"repos/{repo}/issues/{pr_number}/comments", "--input", "-"],
        input_doc={"body": body},
    )


def _load_worker_issue():
    path = Path(__file__).resolve().parent / "worker-issue.py"
    spec = importlib.util.spec_from_file_location("registry_worker_issue", path)
    if spec is None or spec.loader is None:
        raise WorkerPrError("cannot load worker-issue.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def set_review_state(repo, pr_number, state):
    """Apply the mutually-exclusive review:* label for `state` and drop the others."""
    label = f"review:{state}"
    if label not in REVIEW_LABELS:
        raise WorkerPrError(f"unknown review state {state}")
    _ensure_label(repo, label)
    _gh_json(
        ["api", "-X", "POST", f"repos/{repo}/issues/{pr_number}/labels", "--input", "-"],
        input_doc={"labels": [label]},
    )
    for other in REVIEW_LABELS:
        if other != label:
            _remove_label(repo, pr_number, other)
    print(f"PR review state: {state}")


def get_review_state(repo, pr_number):
    labels = _gh_json(["api", f"repos/{repo}/issues/{pr_number}/labels"])
    names = {label.get("name") for label in labels if isinstance(label, dict)}
    current = sorted(names & set(REVIEW_LABELS))
    state = current[0][7:] if len(current) == 1 else ""
    _write_outputs({"state": state})
    print(f"PR review state: {state or '(none)'}")


def record_round(repo, pr_number, round_n, run_key, bot_login):
    comments = _paginated_comments(repo, pr_number)
    if round_recorded(comments, bot_login, round_n, run_key):
        print(f"review round already recorded: {round_n}")
        return
    body = (f"> 🤖 SPARQ agent — cross-provider review round {round_n} recorded.\n\n"
            f"{ROUND_MARKER} n={round_n} run={run_key} -->")
    _comment(repo, pr_number, body)
    print(f"review round recorded: {round_n}")


def record_marker(repo, pr_number, kind, round_n, run_key, bot_login):
    comments = _paginated_comments(repo, pr_number)
    runs = marker_runs(comments, bot_login, kind, round_n)
    if run_key in runs:
        _write_outputs({"count": len(runs)})
        print(f"{kind} marker already recorded for round {round_n} ({len(runs)} run(s))")
        return
    body = (f"> 🤖 SPARQ agent — recorded `{kind}` for review round {round_n}.\n\n"
            f"{MARKER_KINDS[kind]} round={round_n} run={run_key} -->")
    _comment(repo, pr_number, body)
    _write_outputs({"count": len(runs) + 1})
    print(f"{kind} marker recorded for round {round_n} ({len(runs) + 1} run(s))")


def check_marker(repo, pr_number, kind, round_n, maximum, bot_login):
    comments = _paginated_comments(repo, pr_number)
    runs = marker_runs(comments, bot_login, kind, round_n)
    _write_outputs({"count": len(runs), "exceeded": len(runs) >= maximum})
    print(f"{kind} markers for round {round_n}: {len(runs)}/{maximum}")


def check_round(repo, pr_number, max_rounds, bot_login):
    comments = _paginated_comments(repo, pr_number)
    rounds = count_rounds(comments, bot_login)
    _write_outputs({"rounds": rounds, "exhausted": rounds >= max_rounds})
    print(f"review rounds recorded: {rounds}/{max_rounds}")


def record_fix_model(repo, pr_number, round_n, model, run_key, bot_login):
    """Durably record WHICH model executed a fix round (idempotent per marker content). The
    commit [alias] tag is not durable enough — squash merges and force-pushes lose it — and
    decide_budget's model-escalation mechanism needs the per-round record."""
    if not SAFE_ALIAS_RE.fullmatch(model or ""):
        raise WorkerPrError("fix model alias is unsafe")
    comments = _paginated_comments(repo, pr_number)
    marker = f"{FIX_MODEL_MARKER} round={round_n} model={model} run={run_key} -->"
    if any(marker in str(c.get("body", "")) for c in _bot_comments(comments, bot_login)):
        print(f"fix model already recorded for round {round_n}")
        return
    _comment(repo, pr_number,
             f"> 🤖 SPARQ agent — fix round {round_n} executed by `{model}`.\n\n{marker}")
    print(f"fix model recorded for round {round_n}: {model}")


def record_model_pin(repo, pr_number, round_n, tier, provider, run_key, bot_login):
    """Durably pin the fix-model floor after a budget extension (idempotent: an existing
    equal-or-higher recorded floor wins — the floor only ever moves UP the ladder)."""
    ladder = ESCALATION_LADDERS.get(provider)
    if not ladder or tier not in ladder:
        raise WorkerPrError("model pin tier must be a ladder member for its provider")
    comments = _paginated_comments(repo, pr_number)
    existing = pinned_fix_floor(comments, bot_login, provider)
    if existing is not None and ladder.index(existing) >= ladder.index(tier):
        print(f"model pin already at or above {tier} ({existing})")
        return
    _comment(repo, pr_number,
             f"> 🤖 SPARQ agent — review round budget extended; the fix-model floor is pinned "
             f"to `{tier}` (a weaker tier burned the base budget, so a stronger model gets the "
             f"extension before a human is involved).\n\n"
             f"{MODEL_PIN_MARKER} round={round_n} tier={tier} run={run_key} -->")
    print(f"model pin recorded: {tier} (round {round_n})")


def set_reviewed_sha(repo, pr_number, sha):
    pull = _gh_json(["api", f"repos/{repo}/pulls/{pr_number}"])
    body = replace_reviewed_sha(pull.get("body") or "", sha)
    _gh_json(["api", "-X", "PATCH", f"repos/{repo}/pulls/{pr_number}", "--input", "-"],
             input_doc={"body": body})
    print(f"reviewed-sha bound: {sha}")


def get_reviewed_sha(repo, pr_number):
    pull = _gh_json(["api", f"repos/{repo}/pulls/{pr_number}"])
    sha = reviewed_sha_of(pull.get("body") or "") or "none"
    _write_outputs({"reviewed_sha": sha})
    print(f"reviewed-sha: {sha}")


def post_findings(repo, pr_number, verdict_file, round_n):
    """Post the SCHEMA-VALIDATED verdict as a findings comment. Raw model output stays withheld —
    only validated, length-capped fields are ever surfaced."""
    with open(verdict_file, encoding="utf-8") as handle:
        document = json.load(handle)
    lines = [
        "> 🤖 SPARQ agent — cross-provider review "
        f"round {round_n}: **{document['verdict']}**.",
        "",
        document.get("summary", "").strip() or "(no summary)",
    ]
    for issue in document.get("issues", []):
        lines.append("")
        lines.append(f"- **{issue['severity']}** `{issue['file']}` — {issue['title']}")
        if issue.get("body"):
            lines.append(f"  {issue['body']}")
        if issue.get("fix_hint"):
            lines.append(f"  _fix hint (advisory):_ {issue['fix_hint']}")
    progress = document.get("progress")
    if progress in PROGRESS_VALUES:
        # Durable round marker for the progress grade (maintainer directive 2026-07-17): CLAIM's
        # decide_budget falls back to this when the registry verdict record is unreadable.
        lines.append("")
        lines.append(f"_Progress vs the prior round:_ **{progress}**")
        lines.append("")
        lines.append(f"{PROGRESS_MARKER} round={round_n} progress={progress} -->")
    if document.get("injection_detected"):
        lines.append("")
        lines.append("⚠️ The reviewer flagged possible prompt-injection content; escalating to a human.")
    _comment(repo, pr_number, "\n".join(lines))
    print("findings posted")


# ---- registry data files (provenance + verdicts) -------------------------------------------------
def provenance_path(target_repo, pr_number):
    owner, name = target_repo.split("/", 1)
    return f"{PROVENANCE_DIR}/{owner}--{name}--pr{pr_number}.json"


def verdict_path(target_repo, pr_number, round_n):
    owner, name = target_repo.split("/", 1)
    return f"{VERDICT_DIR}/{owner}--{name}--pr{pr_number}-round{round_n}.json"


def _registry_put_file(registry_repo, path, document, message, retries=6):
    """Create-or-keep a registry data file via the contents API with the same read-SHA CAS retry
    the lease ledger uses. Idempotent: an existing byte-identical file is success; an existing
    DIFFERENT file fails closed (provenance must never be silently rewritten)."""
    body = json.dumps(document, indent=1, sort_keys=True) + "\n"
    encoded = base64.b64encode(body.encode()).decode()
    for _ in range(retries):
        probe = _run_gh(["api", f"repos/{registry_repo}/contents/{path}"], check=False)
        sha = None
        if probe.returncode == 0:
            try:
                meta = json.loads(probe.stdout)
                existing = base64.b64decode("".join(meta["content"].split())).decode()
                sha = meta["sha"]
            except (KeyError, ValueError, json.JSONDecodeError) as exc:
                raise WorkerPrError(f"registry file {path} is unreadable") from exc
            if existing == body:
                return False  # already recorded — idempotent success
            raise WorkerPrError(f"registry file {path} already exists with different content")
        elif "HTTP 404" not in probe.stderr:
            raise WorkerPrError(f"registry file {path} probe failed")
        args = ["api", "-X", "PUT", f"repos/{registry_repo}/contents/{path}",
                "-f", f"message={message}", "-f", f"content={encoded}"]
        if sha:
            args += ["-f", f"sha={sha}"]
        if _run_gh(args, check=False).returncode == 0:
            return True
    raise WorkerPrError(f"registry write for {path} kept conflicting")


def provenance_record(registry_repo, target_repo, pr_number, head_sha, impl_provider, impl_alias,
                      impl_account_h, issue, run_key, verify_bot_login=None):
    """Write the registry provenance record (the review loop's root of trust).

    Privacy (locked decision 22a): the record stores ONLY the salted account hash, never the raw
    handle. Integrity: when `verify_bot_login` is given the PR is re-read from the LIVE API and
    must be an open, bot-authored, same-repo PR whose head branch is bound to `issue` — because
    the calling job receives pr_number from a worker job that executed hostile target code, the
    reported number is verified against trusted inputs before anything is recorded, and the head
    sha is taken from the API (never from the hostile job's outputs)."""
    if impl_provider not in {"anthropic", "openai"}:
        raise WorkerPrError("impl_provider must be anthropic or openai")
    if not re.fullmatch(r"[0-9a-f]{16}", impl_account_h or ""):
        raise WorkerPrError("impl_account_h must be a 16-hex salted account hash")
    if verify_bot_login:
        pull = _gh_json(["api", f"repos/{target_repo}/pulls/{pr_number}"])
        if pull.get("state") != "open":
            raise WorkerPrError("provenance target PR is not open")
        if str((pull.get("user") or {}).get("login", "")) != verify_bot_login:
            raise WorkerPrError("provenance target PR is not authored by the App bot")
        head = pull.get("head") or {}
        if (head.get("repo") or {}).get("full_name") != target_repo:
            raise WorkerPrError("provenance target PR head is a fork")
        if not re.fullmatch(rf"sparq-agent/issue-{issue}-[A-Za-z0-9._-]+",
                            str(head.get("ref", ""))):
            raise WorkerPrError("provenance target PR head is not this run's issue branch")
        head_sha = str(head.get("sha", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha or ""):
        raise WorkerPrError("head_sha must be a 40-hex commit id")
    document = {
        "pr_number": pr_number,
        "head_sha_at_open": head_sha,
        "impl_provider": impl_provider,
        "impl_alias": impl_alias,
        "impl_account_h": impl_account_h,
        "issue": issue,
        "recorded_at_run": run_key,
    }
    created = _registry_put_file(
        registry_repo, provenance_path(target_repo, pr_number), document,
        f"provenance {target_repo}#{pr_number}")
    print(f"provenance {'recorded' if created else 'already recorded'} for {target_repo}#{pr_number}")


def verdict_record(registry_repo, target_repo, pr_number, round_n, verdict_file):
    with open(verdict_file, encoding="utf-8") as handle:
        document = json.load(handle)
    created = _registry_put_file(
        registry_repo, verdict_path(target_repo, pr_number, round_n), document,
        f"review verdict {target_repo}#{pr_number} round {round_n}")
    print(f"verdict {'recorded' if created else 'already recorded'} "
          f"for {target_repo}#{pr_number} round {round_n}")


# ---- terminal escalation + arm --------------------------------------------------------------------
def needs_user(repo, pr_number, reason, issue=None, alert_repo=None, alert_token=None,
               maintainer=None):
    """Terminal, human-owned stop: review:needs-user label, an explanatory comment, the source
    issue routed to needs-user, and an ops-alert-style registry ping. The PR stays DRAFT."""
    set_review_state(repo, pr_number, "needs-user")
    handle = maintainer or os.environ.get("MAINTAINER_HANDLE", "jeswr")
    _comment(repo, pr_number,
             f"> 🤖 SPARQ agent — the autonomous review loop stopped: {reason}\n\n"
             f"@{handle} this pull request needs a human decision. It remains a DRAFT and will "
             "not be auto-armed.")
    if issue:
        _load_worker_issue().set_status(repo, issue, "needs-user")
    if alert_repo and alert_token:
        # Reuse the rolling ops-alert posture (usage-alert.py): one deduped registry issue.
        title = f"⚠️ Review loop needs a human — {repo}#{pr_number}"
        env = {"GH_TOKEN": alert_token}
        _run_gh(["label", "create", "ops-alert", "-R", alert_repo, "--color", "d73a4a",
                 "--description", "Autonomous worker availability alert (maintainer action)"],
                check=False, env=env)
        found = _gh_json(["issue", "list", "-R", alert_repo, "--label", "ops-alert", "--state",
                          "open", "--json", "number,title", "--limit", "50"], env=env) or []
        body = (f"> 🤖 SPARQ agent — {reason}\n\nhttps://github.com/{repo}/pull/{pr_number} "
                f"needs @{handle}.")
        number = next((i["number"] for i in found if i.get("title") == title), None)
        if number:
            _run_gh(["issue", "comment", str(number), "-R", alert_repo, "--body", body],
                    check=False, env=env)
        else:
            _run_gh(["issue", "create", "-R", alert_repo, "--title", title, "--label",
                     "ops-alert", "--body", body], check=False, env=env)
    print(f"needs-user recorded: {reason}")


def _merge_only_carry_forward(repo, head_sha, reviewed_sha, default_branch):
    """Issue #69 half 1, LIVE side: True only when BOTH halves hold — (a) the first-parent
    chain from the live head reaches the reviewed sha through two-parent merges whose
    second parents are each reachable from the default branch (compare status
    identical/behind), and (b) the PR's diff vs its merge base is identical before and
    after the advance (diff_fingerprint). Any API failure, truncated compare file list
    (the API caps at 300), or ambiguity returns False — fail closed, the normal mismatch
    disarm proceeds and the sweep re-reviews the new head instead."""
    try:
        listing = _gh_json(["api", f"repos/{repo}/commits?sha={head_sha}&per_page=100"])
        if not isinstance(listing, list):
            return False
        commit_parents = {}
        for entry in listing:
            if not isinstance(entry, dict) or not isinstance(entry.get("sha"), str):
                continue
            commit_parents[entry["sha"]] = [
                parent.get("sha") for parent in (entry.get("parents") or [])
                if isinstance(parent, dict)]
        pairs = merge_only_advance(head_sha, reviewed_sha, commit_parents)
        if not pairs:
            return False
        for _, second_parent in pairs:
            probe = _gh_json(["api", f"repos/{repo}/compare/{default_branch}...{second_parent}"])
            if not isinstance(probe, dict) or probe.get("status") not in ("identical", "behind"):
                return False
        fingerprints = []
        for sha in (reviewed_sha, head_sha):
            compared = _gh_json(["api", f"repos/{repo}/compare/{default_branch}...{sha}"])
            files = compared.get("files") if isinstance(compared, dict) else None
            if not isinstance(files, list) or len(files) >= 300:
                return False
            fingerprints.append(diff_fingerprint(files))
        return fingerprints[0] is not None and fingerprints[0] == fingerprints[1]
    except WorkerPrError:
        return False


def _merge_queue_state(repo, pr_number):
    """Issue #69 half 2: (node_id, queued) for a pull request. Merge-queue membership is
    GraphQL-only — the REST document disarm otherwise reads never exposes mergeQueueEntry,
    and `gh pr merge --disable-auto` hard-fails on a queued PR (the 2026-07-17 incident).
    Raises WorkerPrError on any API/shape failure (fail closed: the caller surfaces a
    structured per-PR error rather than guessing an unqueued state)."""
    owner, name = repo.split("/", 1)
    query = ("query($owner:String!,$name:String!,$number:Int!){"
             "repository(owner:$owner,name:$name){pullRequest(number:$number){"
             "id mergeQueueEntry{id}}}}")
    doc = _gh_json(["api", "graphql", "-f", f"query={query}", "-f", f"owner={owner}",
                    "-f", f"name={name}", "-F", f"number={pr_number}"])
    pull = None
    if isinstance(doc, dict):
        repository = (doc.get("data") or {}).get("repository") or {}
        pull = repository.get("pullRequest")
    if not isinstance(pull, dict) or not pull.get("id"):
        raise WorkerPrError("merge-queue state query returned a malformed pull request")
    return str(pull["id"]), pull.get("mergeQueueEntry") is not None


def _queue_disarm_mutation(mutation, node_id):
    """One GraphQL disarm mutation for a QUEUED pull request (issue #69 half 2):
    dequeuePullRequest takes the PR node id as `id`, disablePullRequestAutoMerge as
    `pullRequestId`. Raises a concise WorkerPrError on failure — disarm() converts it
    into the structured per-PR error its dispatch caller skips per item."""
    if mutation == "dequeuePullRequest":
        query = "mutation($id:ID!){dequeuePullRequest(input:{id:$id}){clientMutationId}}"
    elif mutation == "disablePullRequestAutoMerge":
        query = ("mutation($id:ID!){disablePullRequestAutoMerge(input:{pullRequestId:$id})"
                 "{clientMutationId}}")
    else:
        raise WorkerPrError("unknown merge-queue disarm mutation")
    result = _run_gh(["api", "graphql", "-f", f"query={query}", "-f", f"id={node_id}"],
                     check=False)
    if result.returncode != 0:
        raise WorkerPrError(f"GraphQL {mutation} failed for the queued pull request")


def disarm(repo, pr_number, when):
    """Defuse a worker PR's GitHub-side arm/ready state, fail-closed on LIVE data only (the plan
    row that requested this is hostile — every precondition is re-derived from the API here).

    Trust surface mirrors the review enumerator: only an open, same-repo, bot-authored
    `sparq-agent/*` PR is ever touched, and a PR labelled review:needs-user OR needs:user is
    human-owned (a human arm/park decision stands). when=always additionally consults the
    head-ref-linked SOURCE issue: a `needs:*`-parked issue is human-owned too, and the defuse
    precedes an autonomous push into that human's territory — mismatch mode deliberately does
    NOT consult the issue, because retracting a latch that would merge a never-reviewed tree is
    the safety invariant and must not be blocked by work-item parking. when=mismatch requires
    (armed OR ready-but-unarmed) AND head != reviewed-sha (registry issue #42 invariant —
    matching SHAs are NEVER disarmed).

    Issue #69: a mismatch is FIRST tested for merge-only carry-forward — the pr-freshness
    update-branch automation advances heads with default-branch merge commits, and a
    content-identical advance REBINDS the reviewed-sha marker instead of disarming (both the
    chain shape and the diff-vs-merge-base identity must verify; anything else falls through
    to the disarm). The armed bit is derived from REST auto-merge OR live merge-queue
    membership (GraphQL — invisible to REST): a queued PR disarms via dequeuePullRequest +
    disablePullRequestAutoMerge, never `gh pr merge --disable-auto` (which fails on queued
    PRs). Any API failure past the guards surfaces as ONE structured per-PR error (a
    disarm_error output row + a per-PR exit message) so the dispatch caller's per-item
    handling skips exactly this PR and sibling enumeration continues."""
    live = _gh_json(["api", f"repos/{repo}/pulls/{pr_number}"])
    if not isinstance(live, dict) or live.get("state") != "open":
        _write_outputs({"disarmed": False})
        print("disarm skipped: pull request is not open")
        return
    head = live.get("head") or {}
    head_sha = str(head.get("sha", ""))
    head_repo = (head.get("repo") or {}).get("full_name")
    login = str((live.get("user") or {}).get("login", ""))
    labels = {label.get("name") for label in (live.get("labels") or [])
              if isinstance(label, dict)}
    head_match = WORKER_HEAD_RE.fullmatch(str(head.get("ref", "")))
    if head_repo != repo or not head_match or not login.endswith("[bot]"):
        _write_outputs({"disarmed": False})
        print("disarm skipped: not a same-repo bot worker PR")
        return
    if human_owned(labels):
        _write_outputs({"disarmed": False})
        print("disarm skipped: the PR is human-owned (review:needs-user / needs:user)")
        return
    if when == "always":
        # The defuse admits an autonomous fix push; a human-parked SOURCE issue parks that too.
        # Best-effort read: CLAIM's admission already fail-closed on the same live check, this
        # is defence in depth — an unreadable issue does not block the defuse itself.
        probe = _run_gh(["api", f"repos/{repo}/issues/{head_match.group(1)}"], check=False)
        if probe.returncode == 0:
            try:
                issue_labels = {label.get("name")
                                for label in (json.loads(probe.stdout).get("labels") or [])
                                if isinstance(label, dict)}
            except (json.JSONDecodeError, AttributeError):
                issue_labels = set()
            if any(isinstance(label, str) and label.startswith("needs:")
                   for label in issue_labels):
                _write_outputs({"disarmed": False})
                print("disarm skipped: the source issue is human-owned (needs:*)")
                return
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise WorkerPrError("live head sha is malformed")
    reviewed = reviewed_sha_of(live.get("body") or "") or "none"
    # Issue #69 half 1: before treating the divergence as a disarmable mismatch, test whether
    # the head advanced ONLY by default-branch merge commits with the PR's diff-vs-merge-base
    # unchanged. The reviewed CONTENT is then intact — rebind the marker to the new head and
    # leave the arm state alone. Every check is live and fail-closed: any real content
    # change, unknown shape, or API failure falls through to the normal disarm below.
    if when == "mismatch" and reviewed != "none" and head_sha != reviewed:
        default_branch = str(((live.get("base") or {}).get("repo") or {})
                             .get("default_branch") or "")
        if default_branch and _merge_only_carry_forward(repo, head_sha, reviewed,
                                                        default_branch):
            set_reviewed_sha(repo, pr_number, head_sha)
            _write_outputs({"disarmed": False, "carried_forward": True})
            print("reviewed-sha carried forward: the head advanced only by verified "
                  "default-branch merge commits and the diff vs the merge base is unchanged")
            return
    try:
        # Issue #69 half 2: queued PRs are never drafts, so a drafted PR skips the GraphQL
        # probe; for the rest, merge-queue membership counts as ARMED (REST auto_merge alone
        # misses a directly-queued PR whose latch would merge a never-reviewed tree).
        node_id, queued = "", False
        if live.get("draft") is not True:
            node_id, queued = _merge_queue_state(repo, pr_number)
        actions = decide_disarm((live.get("auto_merge") is not None) or queued,
                                live.get("draft") is True, head_sha, reviewed, when)
        if not actions:
            _write_outputs({"disarmed": False})
            print(f"disarm no-op ({when}): the live PR state does not require it")
            return
        for action in actions:
            if action == "disable-auto":
                if queued:
                    _queue_disarm_mutation("dequeuePullRequest", node_id)
                    print("merge-queue entry removed (GraphQL dequeue)")
                    if live.get("auto_merge") is not None:
                        _queue_disarm_mutation("disablePullRequestAutoMerge", node_id)
                        print("auto-merge disabled (GraphQL; the PR was queued)")
                else:
                    _run_gh(["pr", "merge", str(pr_number), "-R", repo, "--disable-auto"])
                    print("auto-merge disabled (stale arm latch removed)")
            elif action == "redraft":
                _run_gh(["pr", "ready", str(pr_number), "-R", repo, "--undo"])
                print("pull request returned to draft for the review sweep")
            else:
                set_review_state(repo, pr_number, "needs")
    except WorkerPrError as exc:
        # Issue #69 half 2: the structured per-PR error — one sanitized output row plus a
        # per-PR exit message. The dispatch caller maps the nonzero exit to a per-item
        # DispatchError and skips exactly this PR; siblings keep enumerating.
        reason = " ".join(str(exc).split())[:200] or "disarm failed"
        _write_outputs({"disarmed": False, "disarm_error": reason})
        raise WorkerPrError(f"disarm {repo}#{pr_number}: {reason}") from exc
    _write_outputs({"disarmed": True})
    print(f"disarm applied ({when}): {','.join(actions)}")


def ready_and_arm(repo, pr_number, reviewed_sha, impl_provider, impl_account_h, reviewer_provider,
                  reviewer_account, arm, issue=None, surface_paths=None):
    """The ONLY place a PR can be armed. Fail-closed assertions per locked decision 6; a live-head
    mismatch returns the PR to review:needs (a fixer/other push raced the approval).

    Account disjointness is asserted on SALTED HASHES (locked decision 22a): the registry
    provenance record stores impl_account_h, and the live reviewer handle is hashed here with the
    same PROVENANCE_SALT. Liveness (crash-window hardening): `gh pr ready` un-drafts the PR, so if
    the subsequent `merge --auto` fails the draft state is restored (`gh pr ready --undo`) — the
    PR stays visible to the sweep for a bounded re-review instead of stalling non-draft/unarmed
    forever; if even the undo fails, this escalates to review:needs-user (never silent).

    [OPUS-4.8] B3 / defects #2,#4: DEFENSE-IN-DEPTH trust-surface arm gate re-derived on LIVE
    data. Even if the upstream review-outcome decided `arm`, this — the last mutation before the
    latch — re-reads the PR's changed files from the API at the reviewed head and, if ANY touches
    a gate-weakening / orchestration-control path (renamed paths included, since the check is live
    against the actual diff, not the planning-time list), WITHHOLDS auto-arm and escalates to a
    human (review:needs-user). The PR is NOT undrafted/armed; the automated review already ran, the
    final arm click is a human's for gate-weakening paths regardless of issue labels."""
    if reviewer_provider == impl_provider:
        raise WorkerPrError("refusing to arm: reviewer provider equals implementer provider")
    salt = os.environ.get("PROVENANCE_SALT", "")
    if account_hash(reviewer_account, salt) == impl_account_h:
        raise WorkerPrError("refusing to arm: reviewer account equals implementer account")
    if not re.fullmatch(r"[0-9a-f]{40}", reviewed_sha):
        raise WorkerPrError("reviewed sha is malformed")
    live = _gh_json(["api", f"repos/{repo}/pulls/{pr_number}"])
    if live.get("state") != "open":
        raise WorkerPrError("pull request is no longer open")
    head_sha = str(live.get("head", {}).get("sha", ""))
    if head_sha != reviewed_sha:
        # Not an error: new commits landed between approve and arm; re-review binds to the new head.
        set_review_state(repo, pr_number, "needs")
        _write_outputs({"armed": False, "head_moved": True})
        print("live head advanced past the reviewed sha; returned to review:needs")
        return
    if arm:
        # Live trust-surface re-derivation BEFORE any undraft/latch (renamed-path safe).
        surfaces = tuple(surface_paths) if surface_paths else DEFAULT_TRUST_SURFACE_PATHS
        live_files = _pr_changed_files(repo, pr_number)
        hits = trust_surface_paths_touched(live_files, surfaces)
        if hits:
            alert_repo, alert_token = _alert_route()
            needs_user(repo, pr_number,
                       "trust-surface change approved by cross-provider review; human arm "
                       f"required (diff touches: {', '.join(hits[:8])})",
                       issue=issue, alert_repo=alert_repo, alert_token=alert_token)
            _write_outputs({"armed": False, "head_moved": False, "trust_surface": True})
            print("trust-surface diff: withheld auto-arm; escalated to human (review:needs-user)")
            return
    _run_gh(["pr", "ready", str(pr_number), "-R", repo])
    if arm:
        merge = _run_gh(["pr", "merge", str(pr_number), "-R", repo, "--squash", "--auto"],
                        check=False)
        if merge.returncode != 0:
            undo = _run_gh(["pr", "ready", str(pr_number), "-R", repo, "--undo"], check=False)
            if undo.returncode == 0:
                # Back to draft with review:needs and NO reviewed-sha bind (the bind runs after
                # this step) — the sweep re-reviews next tick, bounded by max_review_rounds.
                raise WorkerPrError(
                    "auto-merge arm failed; draft restored for the sweep to retry")
            alert_repo, alert_token = _alert_route()
            needs_user(repo, pr_number,
                       "arming failed AFTER the PR left draft and the draft state could not be "
                       "restored; a human must re-arm or re-draft this PR",
                       issue=issue, alert_repo=alert_repo, alert_token=alert_token)
            raise WorkerPrError("auto-merge arm failed and the draft undo failed; escalated")
    set_review_state(repo, pr_number, "pass")
    if issue:
        # Deferred issue completion (locked decision 16): complete only on arm, not on publish.
        _load_worker_issue().set_status(repo, issue, "complete")
    _write_outputs({"armed": bool(arm), "head_moved": False})
    print(f"pull request marked ready{' and armed (auto-merge)' if arm else ''}")


# ---- composite outcomes (thin workflow steps, testable decisions) --------------------------------
def review_outcome(args):
    """Apply the review outcome. Deliberate ordering for crash-window liveness (the durable
    registry verdict record is written by the workflow BEFORE this step, the round marker was
    recorded BEFORE the model ran, and the reviewed-sha bind runs AFTER this step and the arm):
    a crash between any two mutations leaves reviewed-sha != head, so the sweep re-derives and
    retries next tick — bounded by max_review_rounds — instead of silently stalling."""
    diff_files = Path(args.files_file).read_text(encoding="utf-8").splitlines()
    with open(args.verdict_file, encoding="utf-8") as handle:
        document = json.load(handle)
    has_blockers = validate_verdict(document, diff_files)  # raises => verdict VOID, step fails
    post_findings(args.repo, args.pr, args.verdict_file, args.round)
    # [OPUS-4.8] B3 / defects #2,#4: the ACTIVE FILE-level trust-surface control. Derive it from
    # the PR's own diff file set (the same list the reviewer just used). ANY gate-weakening /
    # orchestration-control path forces the security posture — the review stays automated, but an
    # approved PR that touches one is HUMAN-armed (needs-user), never auto-armed. The surface list
    # comes from the target policy row's `security_paths` (workflow-supplied via --surface-path);
    # an empty supplied list means "not configured for this target" and falls back to the built-in
    # DEFAULT_TRUST_SURFACE_PATHS so the guard is never silently absent (fail closed).
    surface_paths = tuple(args.surface_path) if args.surface_path else DEFAULT_TRUST_SURFACE_PATHS
    surface_hits = trust_surface_paths_touched(diff_files, surface_paths)
    trust_surface = bool(surface_hits)
    security = args.security or trust_surface
    # Round-budget exhaustion consults the PURE decide_budget (maintainer directive 2026-07-17):
    # a model-tier escalation or an improving-progress grade extends the loop (hard cap 6 total
    # rounds inside decide_budget) instead of the flat needs-user at the base budget.
    budget = {"action": "needs-user", "pin": None}
    if args.round >= args.max_rounds and not document["injection_detected"]:
        comments = _paginated_comments(args.repo, args.pr)
        models = sorted({model
                         for models in fix_round_models(comments, args.bot_login).values()
                         for model in models})
        budget = decide_budget(args.round, models, document.get("progress"),
                               args.impl_provider, base_rounds=args.max_rounds)
    decision = decide_review(document["verdict"], has_blockers,
                             document["injection_detected"], args.round, args.max_rounds,
                             security, budget_action=budget["action"])
    _write_outputs({"decision": decision, "verdict": document["verdict"],
                    "has_blockers": has_blockers,
                    "injection": document["injection_detected"],
                    "trust_surface": trust_surface,
                    "budget": budget["action"]})
    if decision == "changes":
        if budget["action"] == "extend-model-pin" and budget["pin"]:
            record_model_pin(args.repo, args.pr, args.round, budget["pin"],
                             args.impl_provider, args.run_key, args.bot_login)
        set_review_state(args.repo, args.pr, "changes")
    elif decision == "needs-user":
        approved = document["verdict"] == "approve" and not has_blockers
        if document["injection_detected"]:
            reason = "the reviewer flagged possible prompt injection"
        elif approved and trust_surface:
            # B3: the review APPROVED, but the diff touches a gate-weakening / orchestration
            # trust-surface path — the automated cross-provider review is complete, but the arm
            # is a human's regardless of issue labels.
            reason = ("trust-surface change approved by cross-provider review; human arm "
                      f"required (diff touches: {', '.join(surface_hits[:8])})")
        elif approved:
            reason = "a security-labelled surface passed review and needs a HUMAN arm decision"
        else:
            reason = (f"the review round budget is exhausted at {args.round} round(s) (base "
                      f"{args.max_rounds}, hard cap {HARD_CAP_ROUNDS}) with no extension left — "
                      "the top fix tier has run and the latest verdict does not grade the PR "
                      "improving")
        alert_repo, alert_token = _alert_route()
        needs_user(args.repo, args.pr, reason, issue=args.issue,
                   alert_repo=alert_repo, alert_token=alert_token)
    else:
        # decision == "arm": the workflow runs ready-and-arm as a separate step under the
        # narrowly-minted arm token; nothing to mutate here.
        print("verdict approved: arm step will run under the arm-scoped token")


def fix_outcome(args):
    injection = args.injection == "true"
    made_changes = args.made_changes == "true"
    gate_ok = args.gate_outcome == "success"
    pushed = args.pushed == "true"
    if args.model:
        # Durable executed-model record for this fix round (maintainer directive 2026-07-17):
        # recorded on EVERY outcome — a no-change or gate-failed attempt still consumed the
        # round on this model, which is exactly what the escalation mechanism must know.
        record_fix_model(args.repo, args.pr, args.round, args.model, args.run_key,
                         args.bot_login)
    nochange_runs = gatefail_runs = 0
    if not injection:
        if not made_changes:
            comments = _paginated_comments(args.repo, args.pr)
            if args.run_key not in marker_runs(comments, args.bot_login, "nochange", args.round):
                record_marker(args.repo, args.pr, "nochange", args.round, args.run_key,
                              args.bot_login)
            nochange_runs = len(marker_runs(_paginated_comments(args.repo, args.pr),
                                            args.bot_login, "nochange", args.round))
        elif not gate_ok:
            record_marker(args.repo, args.pr, "gatefail", args.round, args.run_key,
                          args.bot_login)
            gatefail_runs = len(marker_runs(_paginated_comments(args.repo, args.pr),
                                            args.bot_login, "gatefail", args.round))
    decision = decide_fix(injection, made_changes, gate_ok, pushed, nochange_runs, gatefail_runs)
    _write_outputs({"decision": decision})
    if decision == "re-review":
        set_review_state(args.repo, args.pr, "needs")
    elif decision == "needs-user":
        reason = ("the fixer flagged the seeded findings as possible prompt injection"
                  if injection else
                  "two consecutive fix attempts made no change (fixer judges the findings spurious)"
                  if not made_changes else
                  "the local gate failed twice for the same review round")
        alert_repo, alert_token = _alert_route()
        needs_user(args.repo, args.pr, reason, issue=args.issue,
                   alert_repo=alert_repo, alert_token=alert_token)
    else:
        print("fix outcome: staying in review:changes (retried next sweep tick)")


# ---- self-test ------------------------------------------------------------------------------------
def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    bot = "sparq[bot]"
    comments = [
        {"user": {"login": bot}, "body": f"x {ROUND_MARKER} n=1 run=10.1 -->"},
        {"user": {"login": bot}, "body": f"x {ROUND_MARKER} n=2 run=11.1 -->"},
        {"user": {"login": "mallory"}, "body": f"x {ROUND_MARKER} n=9 run=6.6 -->"},
        {"user": {"login": bot}, "body": f"x {MARKER_KINDS['nochange']} round=2 run=12.1 -->"},
        {"user": {"login": bot}, "body": f"x {MARKER_KINDS['nochange']} round=2 run=13.1 -->"},
        {"user": {"login": bot}, "body": f"x {MARKER_KINDS['missed']} round=2 run=14.1 -->"},
    ]
    check("rounds count bot-only markers", count_rounds(comments, bot), 2)
    check("non-bot marker is ignored", count_rounds(comments, "mallory[bot]"), 0)
    check("nochange runs per round", len(marker_runs(comments, bot, "nochange", 2)), 2)
    check("nochange other round empty", len(marker_runs(comments, bot, "nochange", 1)), 0)
    check("missed runs", len(marker_runs(comments, bot, "missed", 2)), 1)
    check("duplicate run key detected", round_recorded(comments, bot, 1, "10.1"), True)
    check("new run key not recorded", round_recorded(comments, bot, 3, "99.1"), False)

    body = "PR body\n\n<!-- sparq-reviewed-sha:none -->\n"
    sha = "a" * 40
    check("reviewed-sha parse none", reviewed_sha_of(body), "none")
    replaced = replace_reviewed_sha(body, sha)
    check("reviewed-sha replace", reviewed_sha_of(replaced), sha)
    check("reviewed-sha insert when absent", reviewed_sha_of(replace_reviewed_sha("x", sha)), sha)

    check("security label substring", security_flagged({"area:sparq-zk"}), True)
    check("security trust prefix", security_flagged({"trust:untrusted"}), True)
    check("security plain labels", security_flagged({"area:sparq-core", "role:impl"}), False)
    # [OPUS-4.8] defect #3: per-target keyword injection flags the registry's trust areas that the
    # builtin keyword set missed (area:worker/dispatch/set-up-account/review-loop/groom).
    check("defect#3 registry area unflagged by builtin",
          security_flagged({"area:worker", "role:impl", "status:ready"}), False)
    check("defect#3 registry area flagged with target keywords",
          security_flagged({"area:worker", "role:impl"},
                           extra_keywords=("worker", "dispatch", "set-up-account")), True)
    check("defect#3 non-trust area still unflagged with keywords",
          security_flagged({"area:usage", "role:impl"},
                           extra_keywords=("worker", "dispatch")), False)

    # [OPUS-4.8] B3 / defects #2,#4: the WIRED trust-surface FILE control (both directions +
    # renamed-path + directory-subtree). A benign diff is NOT flagged; ANY gate-weakening path is.
    check("trust-surface benign diff",
          trust_surface_paths_touched(["README.md", "data/leases.json"]), [])
    check("trust-surface flags a worker script",
          trust_surface_paths_touched(["README.md", "scripts/worker-pr.py"]),
          ["scripts/worker-pr.py"])
    check("trust-surface flags a workflow (subtree)",
          trust_surface_paths_touched([".github/workflows/dispatch.yml"]),
          [".github/workflows/dispatch.yml"])
    check("trust-surface flags policy + orchestration subtrees",
          trust_surface_paths_touched(["policy/repos.toml", "orchestration/routing.toml"]),
          ["orchestration/routing.toml", "policy/repos.toml"])
    # renamed-path case: the OLD path is a trust surface even if the new name is benign — the live
    # PR-files read exposes both sides, so either side flags.
    check("trust-surface flags a renamed-from surface path",
          trust_surface_paths_touched(["docs/moved.md", "scripts/groom.py"]),
          ["scripts/groom.py"])
    # a caller-supplied (policy security_paths) list REPLACES the default set.
    check("trust-surface honours a supplied path list",
          trust_surface_paths_touched(["scripts/worker-pr.py", "custom/thing.py"],
                                      surface_paths=("custom/",)),
          ["custom/thing.py"])
    # hostile/malformed diff entries can only DEMOTE to human-arm, never silently approve.
    check("trust-surface tolerates malformed entries",
          trust_surface_paths_touched(["", None, 123, "policy/x.toml"]), ["policy/x.toml"])

    # human_owned: EITHER the loop's own escalation label or groom's parked-PR marker parks the
    # autonomous surface; plain loop states do not.
    check("human_owned loop escalation", human_owned({"review:needs-user"}), True)
    check("human_owned groom park", human_owned({"needs:user", "review:pass"}), True)
    check("human_owned plain loop state", human_owned({"review:needs", "area:x"}), False)

    verdict = {"verdict": "request_changes", "injection_detected": False, "summary": "s",
               "issues": [{"severity": "major", "file": "src/a.rs", "title": "t", "body": "b",
                           "fix_hint": "h"}]}
    check("verdict validates + blockers", validate_verdict(verdict, ["src/a.rs"]), True)
    minor = json.loads(json.dumps(verdict))
    minor["issues"][0]["severity"] = "minor"
    check("minor is not a blocker", validate_verdict(minor, ["src/a.rs"]), False)
    graded = json.loads(json.dumps(verdict))
    graded["progress"] = "improving"
    check("progress grade validates", validate_verdict(graded, ["src/a.rs"]), True)
    graded["progress"] = None
    check("round-1 null progress validates", validate_verdict(graded, ["src/a.rs"]), True)
    for mutate, name in (
            (lambda d: d.update(verdict="ship-it"), "verdict enum"),
            (lambda d: d.update(extra=1), "unknown field"),
            (lambda d: d.update(progress="better"), "unknown progress value"),
            (lambda d: d.update(progress=True), "boolean progress"),
            (lambda d: d["issues"][0].update(file="../etc/passwd"), "file outside diff"),
            (lambda d: d["issues"][0].update(title="t" * 201), "title cap"),
            (lambda d: d.update(issues=[dict(d["issues"][0])] * 11), "issues cap"),
    ):
        bad = json.loads(json.dumps(verdict))
        mutate(bad)
        try:
            validate_verdict(bad, ["src/a.rs"])
        except WorkerPrError:
            check(f"rejects {name}", "rejected", "rejected")
        else:
            check(f"rejects {name}", "accepted", "rejected")

    check("approve arms", decide_review("approve", False, False, 1, 3, False), "arm")
    check("approve+security needs user", decide_review("approve", False, False, 1, 3, True),
          "needs-user")
    check("injection short-circuits", decide_review("approve", False, True, 1, 3, False),
          "needs-user")
    check("changes under budget", decide_review("request_changes", True, False, 2, 3, False),
          "changes")
    check("round exhaustion stops", decide_review("request_changes", False, False, 3, 3, False),
          "needs-user")
    check("approve with blockers is changes", decide_review("approve", True, False, 1, 3, False),
          "changes")
    # Budget-extension plumbing (directive 2026-07-17): an extension action keeps the loop in
    # changes at the cap; a continue/unknown action at the cap fails closed to needs-user; the
    # injection and security paths are untouched by any extension.
    for action in ("extend-model-pin", "extend-progress"):
        check(f"exhaustion + {action} stays changes",
              decide_review("request_changes", False, False, 3, 3, False, budget_action=action),
              "changes")
    check("exhaustion + continue fails closed",
          decide_review("request_changes", False, False, 3, 3, False, budget_action="continue"),
          "needs-user")
    check("extension never overrides injection",
          decide_review("request_changes", False, True, 3, 3, False,
                        budget_action="extend-progress"), "needs-user")
    check("extension never arms security",
          decide_review("approve", False, False, 3, 3, True,
                        budget_action="extend-progress"), "needs-user")

    # ---- decide_budget (directive 2026-07-17): the combined round-budget policy ----
    def budget(rounds, models, progress, provider="anthropic", base=3, pending=(), pin=None):
        return decide_budget(rounds, models, progress, provider, base_rounds=base,
                             pending_fix_models=pending, pin_floor=pin)

    check("budget below base continues", budget(2, ["sonnet"], "regressing"),
          {"action": "continue", "pin": None})
    check("budget zero rounds continues", budget(0, [], None),
          {"action": "continue", "pin": None})
    # Mechanism 1 — model escalation, precedence over progress (it resets the quality question)
    check("exhaustion on sonnet pins fable", budget(3, ["sonnet"], "stagnant"),
          {"action": "extend-model-pin", "pin": "fable"})
    check("model pin outranks improving progress", budget(3, ["sonnet"], "improving"),
          {"action": "extend-model-pin", "pin": "fable"})
    check("exhaustion on fable pins opus", budget(3, ["fable"], None),
          {"action": "extend-model-pin", "pin": "opus"})
    check("mixed sonnet+fable pins opus", budget(4, ["sonnet", "fable"], "regressing"),
          {"action": "extend-model-pin", "pin": "opus"})
    # Mechanism 2 — progress extension once the top tier has run (or nothing is recorded)
    check("opus + improving extends on progress", budget(3, ["opus"], "improving"),
          {"action": "extend-progress", "pin": None})
    check("sonnet+opus + improving is progress-only", budget(4, ["sonnet", "opus"], "improving"),
          {"action": "extend-progress", "pin": None})
    check("no fix record + improving extends", budget(3, [], "improving"),
          {"action": "extend-progress", "pin": None})
    # Re-review authorization: a PUSHED-but-unreviewed fix at/above the pinned floor gets its
    # re-review even at exhaustion (the terminal-grant orphan defect: the executed opus fix
    # falsifies the top-tier predicate while the stagnant grade predates that fix)
    check("pending pinned-floor fix authorizes its re-review",
          budget(3, ["fable", "opus"], "stagnant", pending=["opus"], pin="opus"),
          {"action": "extend-pending-review", "pin": None})
    check("no pending fix in the same posture stops (flip side)",
          budget(3, ["fable", "opus"], "stagnant"),
          {"action": "needs-user", "pin": None})
    check("pending fix BELOW the pinned floor never extends",
          budget(3, ["fable", "opus"], "stagnant", pending=["fable"], pin="opus"),
          {"action": "needs-user", "pin": None})
    check("unpinned pending fix authorizes (floor is the ladder bottom)",
          budget(3, ["sonnet"], None, pending=["sonnet"]),
          {"action": "extend-pending-review", "pin": None})
    check("pending re-review precedes the progress extension",
          budget(3, ["opus"], "improving", pending=["opus"], pin="opus"),
          {"action": "extend-pending-review", "pin": None})
    check("openai pending fix authorizes its re-review",
          budget(3, ["terra"], None, provider="openai", pending=["terra"]),
          {"action": "extend-pending-review", "pin": None})
    check("hard cap still dominates a pending fix",
          budget(6, ["fable", "opus"], "stagnant", pending=["opus"], pin="opus"),
          {"action": "needs-user", "pin": None})
    check("pending fix below base just continues",
          budget(2, ["sonnet"], None, pending=["sonnet"]),
          {"action": "continue", "pin": None})
    # needs-user sides (flip-goes-red on every ACT above)
    check("opus + stagnant stops", budget(3, ["opus"], "stagnant"),
          {"action": "needs-user", "pin": None})
    check("opus + regressing stops", budget(4, ["opus"], "regressing"),
          {"action": "needs-user", "pin": None})
    check("opus + ungraded stops", budget(3, ["opus"], None),
          {"action": "needs-user", "pin": None})
    check("no fix record + stagnant stops", budget(3, [], "stagnant"),
          {"action": "needs-user", "pin": None})
    check("hard cap stops even below-top + improving", budget(6, ["sonnet"], "improving"),
          {"action": "needs-user", "pin": None})
    check("hard cap stops past 6", budget(7, ["sonnet"], "improving"),
          {"action": "needs-user", "pin": None})
    check("round 5 still extends under the cap", budget(5, ["sonnet"], None)["action"],
          "extend-model-pin")
    # openai: single tier — no ladder, mechanism 2 only
    check("openai never model-pins", budget(3, ["terra"], "stagnant", provider="openai"),
          {"action": "needs-user", "pin": None})
    check("openai improving extends", budget(3, ["terra"], "improving", provider="openai"),
          {"action": "extend-progress", "pin": None})
    # an explicit policy base above the hard cap is respected up to the base, never extended
    check("base above cap continues below base", budget(6, ["sonnet"], "improving", base=8),
          {"action": "continue", "pin": None})
    check("base above cap stops at base", budget(8, ["sonnet"], "improving", base=8),
          {"action": "needs-user", "pin": None})
    for bad, name in (
            (lambda: budget(3, ["gpt-omega"], None), "unknown fix model"),
            (lambda: budget(3, ["terra"], None), "cross-provider fix model"),
            (lambda: decide_budget(3, [], None, "mystery"), "unknown provider"),
            (lambda: budget(3, [], "better"), "unknown progress value"),
            (lambda: budget(True, [], None), "boolean rounds"),
            (lambda: decide_budget(3, [], None, "anthropic", base_rounds=0), "zero base"),
            (lambda: budget(3, ["opus"], None, pending=["gpt-omega"]), "unknown pending model"),
            (lambda: budget(3, ["opus"], None, pending=["terra"]),
             "cross-provider pending model"),
            (lambda: budget(3, ["opus"], None, pending=["opus"], pin="terra"),
             "cross-provider pin floor"),
            (lambda: budget(3, ["opus"], None, pin="gpt-omega"), "unknown pin floor"),
    ):
        try:
            bad()
        except WorkerPrError:
            check(f"budget rejects {name}", "rejected", "rejected")
        else:
            check(f"budget rejects {name}", "accepted", "rejected")

    # ---- durable escalation markers: fix-model, progress, and the pinned floor ----
    esc_comments = [
        {"user": {"login": bot}, "body": f"x {FIX_MODEL_MARKER} round=1 model=sonnet run=1.1 -->"},
        {"user": {"login": bot}, "body": f"x {FIX_MODEL_MARKER} round=1 model=sonnet run=1.2 -->"},
        {"user": {"login": bot}, "body": f"x {FIX_MODEL_MARKER} round=2 model=fable run=2.1 -->"},
        {"user": {"login": "mallory"},
         "body": f"x {FIX_MODEL_MARKER} round=3 model=opus run=6.6 -->"},
        {"user": {"login": bot},
         "body": f"y {PROGRESS_MARKER} round=2 progress=improving -->"},
        {"user": {"login": "mallory"},
         "body": f"y {PROGRESS_MARKER} round=3 progress=improving -->"},
    ]
    check("fix models per round (bot-only, deduped)", fix_round_models(esc_comments, bot),
          {1: ["sonnet"], 2: ["fable"]})
    check("progress per round (bot-only)", round_progress(esc_comments, bot),
          {2: "improving"})
    check("no pin markers yields no floor", pinned_fix_floor(esc_comments, bot, "anthropic"),
          None)
    pin_comments = esc_comments + [
        {"user": {"login": bot}, "body": f"z {MODEL_PIN_MARKER} round=3 tier=fable run=3.1 -->"},
        {"user": {"login": "mallory"},
         "body": f"z {MODEL_PIN_MARKER} round=3 tier=opus run=6.6 -->"},
    ]
    check("pinned floor reads the bot marker (forged higher pin ignored)",
          pinned_fix_floor(pin_comments, bot, "anthropic"), "fable")
    check("highest recorded floor wins",
          pinned_fix_floor(pin_comments + [
              {"user": {"login": bot},
               "body": f"z {MODEL_PIN_MARKER} round=4 tier=opus run=4.1 -->"}], bot,
              "anthropic"), "opus")
    try:
        pinned_fix_floor([{"user": {"login": bot},
                           "body": f"z {MODEL_PIN_MARKER} round=1 tier=gpt-omega run=1.1 -->"}],
                         bot, "anthropic")
    except WorkerPrError:
        check("corrupt pin tier fails closed", "rejected", "rejected")
    else:
        check("corrupt pin tier fails closed", "accepted", "rejected")
    check("pinned chain keeps floor-and-above ascending",
          pinned_fix_chain("anthropic", "fable"), ["fable", "opus"])
    check("pinned chain at the terminal tier", pinned_fix_chain("anthropic", "opus"), ["opus"])
    check("pinned chain at the bottom is the whole ladder",
          pinned_fix_chain("anthropic", "sonnet"), ["sonnet", "fable", "opus"])
    check("openai pinned chain is its single tier", pinned_fix_chain("openai", "terra"),
          ["terra"])
    try:
        pinned_fix_chain("anthropic", "terra")
    except WorkerPrError:
        check("cross-provider pin fails closed", "rejected", "rejected")
    else:
        check("cross-provider pin fails closed", "accepted", "rejected")

    # decide_disarm (issue #42): the sweep invariant acts on mismatch when the PR is armed OR
    # ready-but-unarmed (interrupted-disarm crash-window re-entry); matching SHAs are NEVER
    # disarmed; when=always defuses any armed/non-draft PR ahead of an autonomous fix.
    sha_x, sha_y = "a" * 40, "b" * 40
    check("disarm armed+mismatch acts", decide_disarm(True, False, sha_x, sha_y, "mismatch"),
          ["disable-auto", "redraft", "relabel"])
    check("disarm armed+match is a no-op", decide_disarm(True, False, sha_x, sha_x, "mismatch"),
          [])
    check("mismatch completes an interrupted disarm (ready+unarmed)",
          decide_disarm(False, False, sha_x, sha_y, "mismatch"), ["redraft", "relabel"])
    check("ready+unarmed+match is the valid arm=false terminal (no-op)",
          decide_disarm(False, False, sha_x, sha_x, "mismatch"), [])
    check("drafted unarmed mismatch is a no-op",
          decide_disarm(False, True, sha_x, sha_y, "mismatch"), [])
    check("disarm unbound marker counts as mismatch",
          decide_disarm(True, False, sha_x, "none", "mismatch"),
          ["disable-auto", "redraft", "relabel"])
    check("always defuses armed even on match", decide_disarm(True, False, sha_x, sha_x,
                                                              "always"),
          ["disable-auto", "redraft", "relabel"])
    check("always redrafts an unarmed ready PR", decide_disarm(False, False, sha_x, sha_x,
                                                               "always"), ["redraft", "relabel"])
    check("always is a no-op on a drafted unarmed PR",
          decide_disarm(False, True, sha_x, sha_y, "always"), [])
    check("armed draft keeps disable-auto first",
          decide_disarm(True, True, sha_x, sha_y, "mismatch"), ["disable-auto", "relabel"])
    try:
        decide_disarm(True, False, sha_x, sha_y, "sometimes")
    except WorkerPrError:
        check("disarm rejects an unknown mode", "rejected", "rejected")
    else:
        check("disarm rejects an unknown mode", "accepted", "rejected")

    # ---- issue #69 half 1: merge-only carry-forward, pure SHAPE + CONTENT halves ----
    rev_sha, mid_sha, top_sha = "a" * 40, "b" * 40, "c" * 40
    main_1, main_2 = "d" * 40, "e" * 40
    check("merge-only chain yields head-first merge pairs",
          merge_only_advance(top_sha, rev_sha,
                             {top_sha: [mid_sha, main_2], mid_sha: [rev_sha, main_1]}),
          [(top_sha, main_2), (mid_sha, main_1)])
    check("identical head is an empty advance", merge_only_advance(rev_sha, rev_sha, {}), [])
    check("a plain work commit on the chain fails closed",
          merge_only_advance(top_sha, rev_sha,
                             {top_sha: [mid_sha, main_2], mid_sha: [rev_sha]}), None)
    check("an octopus merge fails closed",
          merge_only_advance(top_sha, rev_sha, {top_sha: [rev_sha, main_1, main_2]}), None)
    check("an unknown commit fails closed", merge_only_advance(top_sha, rev_sha, {}), None)
    check("a malformed parent entry fails closed",
          merge_only_advance(top_sha, rev_sha, {top_sha: [None, main_1]}), None)
    check("an over-limit chain fails closed",
          merge_only_advance(top_sha, rev_sha, {top_sha: [top_sha, main_1]}, limit=3), None)

    fp_row = {"filename": "src/a.rs", "status": "modified", "sha": "f" * 40,
              "patch": "@@ -1 +1 @@\n-x\n+y"}
    fp_other = {"filename": "src/b.rs", "status": "added", "sha": "0" * 40, "patch": "+z"}
    check("diff fingerprint is order-insensitive",
          diff_fingerprint([fp_row, fp_other]) == diff_fingerprint([fp_other, dict(fp_row)]),
          True)
    check("a patch change breaks diff identity",
          diff_fingerprint([fp_row])
          == diff_fingerprint([dict(fp_row, patch="@@ -1 +1 @@\n-x\n+CHANGED")]), False)
    check("a status change breaks diff identity",
          diff_fingerprint([fp_row]) == diff_fingerprint([dict(fp_row, status="removed")]),
          False)
    check("a binary file (sha, no patch) fingerprints",
          diff_fingerprint([{"filename": "img.png", "status": "added", "sha": "1" * 40}])
          is not None, True)
    check("a file with neither sha nor patch fails closed",
          diff_fingerprint([{"filename": "x", "status": "modified"}]), None)
    check("a malformed file list fails closed", diff_fingerprint("nope"), None)

    # ---- review_outcome wiring (monkeypatched I/O): exhaustion consults decide_budget — an
    # extension records the pin (model path) or not (progress path) and stays review:changes;
    # the terminal path escalates once with the budget-aware reason ----
    import tempfile

    wiring_calls = []
    fake_state = {}
    wiring_globals = globals()
    real_io = {name: wiring_globals[name]
               for name in ("_paginated_comments", "set_review_state", "needs_user",
                            "post_findings", "record_model_pin", "_alert_route")}
    try:
        wiring_globals["_paginated_comments"] = (
            lambda repo, pr: fake_state.get("comments", []))
        wiring_globals["set_review_state"] = (
            lambda repo, pr, state: wiring_calls.append(("state", state)))
        wiring_globals["needs_user"] = (
            lambda repo, pr, reason, **kwargs: wiring_calls.append(("needs-user", reason)))
        wiring_globals["post_findings"] = (
            lambda repo, pr, vf, rn: wiring_calls.append(("findings", rn)))
        wiring_globals["record_model_pin"] = (
            lambda repo, pr, rn, tier, provider, run_key, bot_login:
            wiring_calls.append(("pin", tier)))
        wiring_globals["_alert_route"] = lambda: (None, None)
        with tempfile.TemporaryDirectory() as tmp:
            verdict_file = Path(tmp) / "verdict.json"
            files_file = Path(tmp) / "files.txt"
            files_file.write_text("src/a.rs\n", encoding="utf-8")

            def outcome(progress, comments):
                wiring_calls.clear()
                fake_state["comments"] = comments
                verdict_file.write_text(json.dumps({
                    "verdict": "request_changes", "injection_detected": False,
                    "summary": "s", "issues": [], "progress": progress}), encoding="utf-8")
                review_outcome(argparse.Namespace(
                    repo="o/r", pr=41, verdict_file=str(verdict_file),
                    files_file=str(files_file), round=3, max_rounds=3, security=False,
                    surface_path=[], issue=None, impl_provider="anthropic", bot_login=bot,
                    run_key="9.1"))
                return list(wiring_calls)

            sonnet_fix = [{"user": {"login": bot},
                           "body": f"x {FIX_MODEL_MARKER} round=1 model=sonnet run=1.1 -->"}]
            opus_fix = [{"user": {"login": bot},
                         "body": f"x {FIX_MODEL_MARKER} round=1 model=opus run=1.1 -->"}]
            check("outcome model extension pins + stays changes",
                  outcome("stagnant", sonnet_fix),
                  [("findings", 3), ("pin", "fable"), ("state", "changes")])
            check("outcome progress extension stays changes without a pin",
                  outcome("improving", opus_fix), [("findings", 3), ("state", "changes")])
            terminal = outcome("stagnant", opus_fix)
            check("outcome terminal escalates once",
                  [entry[0] for entry in terminal], ["findings", "needs-user"])
            check("terminal reason names the exhausted budget",
                  "round budget is exhausted" in terminal[1][1], True)
    finally:
        wiring_globals.update(real_io)

    # ---- disarm wiring (monkeypatched I/O), issue #69: a merge-only advance carries the
    # binding forward with the arm intact; a real content change still disarms; a QUEUED
    # mismatch takes the GraphQL dequeue path (never `gh pr merge`); a queue-API failure
    # surfaces as ONE structured per-PR error the dispatch caller can skip per item ----
    net = {}
    disarm_calls = []
    fake_outputs = {}
    real_disarm_io = {name: wiring_globals[name]
                      for name in ("_gh_json", "_run_gh", "_write_outputs",
                                   "set_review_state", "set_reviewed_sha")}
    head_69, main_tip = "b" * 40, "c" * 40
    base_file = {"filename": "src/a.rs", "status": "modified", "sha": "e" * 40,
                 "patch": "@@ -1 +1 @@\n-x\n+y"}
    merge_advance = [{"sha": head_69, "parents": [{"sha": rev_sha}, {"sha": main_tip}]}]
    plain_advance = [{"sha": head_69, "parents": [{"sha": "9" * 40}]}]
    identical_compares = {f"main...{main_tip}": {"status": "behind", "files": []},
                          f"main...{rev_sha}": {"status": "diverged",
                                                "files": [dict(base_file)]},
                          f"main...{head_69}": {"status": "diverged",
                                                "files": [dict(base_file)]}}

    def fake_gh_json(args, **_kwargs):
        path = args[1] if len(args) > 1 else ""
        if path == "graphql":
            disarm_calls.append("queue-probe")
            return {"data": {"repository": {"pullRequest": {
                "id": "PR_node69",
                "mergeQueueEntry": {"id": "MQE_1"} if net.get("queued") else None}}}}
        if path.startswith("repos/o/r/pulls/"):
            return net["live"]
        if path.startswith("repos/o/r/commits?"):
            return net["commits"]
        if path.startswith("repos/o/r/compare/"):
            return net["compare"][path.split("compare/", 1)[1]]
        raise WorkerPrError(f"unexpected API path {path}")

    def fake_run_gh(args, **_kwargs):
        disarm_calls.append(" ".join(args))
        failing = net.get("fail_mutation", "")
        code = 1 if failing and any(failing in part for part in args) else 0
        return argparse.Namespace(returncode=code, stdout="", stderr="")

    def run_disarm(**overrides):
        disarm_calls.clear()
        fake_outputs.clear()
        net.clear()
        net.update({
            "live": {"state": "open", "draft": False,
                     "auto_merge": {"merge_method": "squash"},
                     "user": {"login": "sparq[bot]"}, "labels": [],
                     "body": f"pr body\n\n<!-- sparq-reviewed-sha:{rev_sha} -->\n",
                     "head": {"sha": head_69, "ref": "sparq-agent/issue-7-fix",
                              "repo": {"full_name": "o/r"}},
                     "base": {"repo": {"default_branch": "main"}}},
            "commits": [dict(row) for row in merge_advance],
            "compare": {key: json.loads(json.dumps(doc))
                        for key, doc in identical_compares.items()},
        }, **overrides)
        disarm("o/r", 41, "mismatch")

    try:
        wiring_globals["_gh_json"] = fake_gh_json
        wiring_globals["_run_gh"] = fake_run_gh
        wiring_globals["_write_outputs"] = fake_outputs.update
        wiring_globals["set_review_state"] = (
            lambda repo, pr, state: disarm_calls.append(f"state:{state}"))
        wiring_globals["set_reviewed_sha"] = (
            lambda repo, pr, sha: disarm_calls.append(f"rebind:{sha}"))

        run_disarm()  # merge-only advance, identical diff => rebind, arm left intact
        check("carry-forward rebinds to the live head",
              f"rebind:{head_69}" in disarm_calls, True)
        check("carry-forward never disarms or probes the queue",
              [call for call in disarm_calls if call != f"rebind:{head_69}"], [])
        check("carry-forward outputs stay un-disarmed",
              (fake_outputs.get("disarmed"), fake_outputs.get("carried_forward")),
              (False, True))

        evil = json.loads(json.dumps(identical_compares))
        evil[f"main...{head_69}"]["files"][0]["patch"] = "@@ -1 +1 @@\n-x\n+EVIL"
        run_disarm(compare=evil)  # same merge shape, DIFFERENT content => normal disarm
        check("content change under a merge still disarms (REST path)",
              ("pr merge 41 -R o/r --disable-auto" in disarm_calls
               and "pr ready 41 -R o/r --undo" in disarm_calls
               and "state:needs" in disarm_calls
               and f"rebind:{head_69}" not in disarm_calls), True)
        check("content change reports disarmed", fake_outputs.get("disarmed"), True)

        run_disarm(queued=True, commits=[dict(row) for row in plain_advance])
        check("queued mismatch dequeues via GraphQL",
              any("dequeuePullRequest" in call for call in disarm_calls), True)
        check("queued mismatch disables auto-merge via GraphQL",
              any("disablePullRequestAutoMerge" in call for call in disarm_calls), True)
        check("queued mismatch never calls gh pr merge",
              any(call.startswith("pr merge") for call in disarm_calls), False)
        check("dequeue precedes the auto-merge disable",
              "dequeuePullRequest" in next(
                  call for call in disarm_calls
                  if "dequeuePullRequest" in call or "disablePullRequestAutoMerge" in call),
              True)
        check("queued mismatch still redrafts",
              "pr ready 41 -R o/r --undo" in disarm_calls, True)

        try:
            run_disarm(queued=True, commits=[dict(row) for row in plain_advance],
                       fail_mutation="dequeuePullRequest")
        except WorkerPrError as exc:
            check("queue API failure raises the structured per-PR error",
                  str(exc).startswith("disarm o/r#41:"), True)
        else:
            check("queue API failure raises the structured per-PR error",
                  "no error", "raised")
        check("queue API failure records a skippable output row",
              (fake_outputs.get("disarmed"), bool(fake_outputs.get("disarm_error"))),
              (False, True))
        check("queue API failure never redrafts past the failure",
              "pr ready 41 -R o/r --undo" in disarm_calls, False)
    finally:
        wiring_globals.update(real_disarm_io)

    check("fix pushed re-reviews", decide_fix(False, True, True, True, 0, 0), "re-review")
    check("first nochange stays", decide_fix(False, False, True, False, 1, 0), "stay-changes")
    check("second nochange stops", decide_fix(False, False, True, False, 2, 0), "needs-user")
    check("first gatefail stays", decide_fix(False, True, False, False, 0, 1), "stay-changes")
    check("second gatefail stops", decide_fix(False, True, False, False, 0, 2), "needs-user")
    check("fix injection stops", decide_fix(True, True, True, True, 0, 0), "needs-user")

    check("provenance path", provenance_path("sparq-org/sparq", 12),
          "orchestration/provenance/sparq-org--sparq--pr12.json")
    check("verdict path", verdict_path("sparq-org/sparq", 12, 2),
          "orchestration/review-verdicts/sparq-org--sparq--pr12-round2.json")
    check("label colours cover review namespace", set(LABEL_COLOURS), set(REVIEW_LABELS))

    # Privacy (locked decision 22a): salted hash is 16-hex, deterministic, salt-sensitive, and
    # never the raw handle; missing salt fails closed.
    h1 = account_hash("acct02", "s3cret")
    check("account hash is 16-hex", bool(re.fullmatch(r"[0-9a-f]{16}", h1)), True)
    check("account hash deterministic", account_hash("acct02", "s3cret"), h1)
    check("account hash salt-sensitive", account_hash("acct02", "other") != h1, True)
    check("account hash never the handle", "acct02" not in h1, True)
    try:
        account_hash("acct02", "")
    except WorkerPrError:
        check("missing salt fails closed", "rejected", "rejected")
    else:
        check("missing salt fails closed", "accepted", "rejected")
    os.environ["REGISTRY_REPO"] = "reg/repo"
    os.environ["REGISTRY_ALERT_TOKEN"] = "t0"
    os.environ.pop("ALERT_REPO", None)
    os.environ.pop("ALERT_TOKEN", None)
    check("alert route defaults to registry", _alert_route(), ("reg/repo", "t0"))
    os.environ["ALERT_REPO"] = "private/alerts"
    os.environ["ALERT_TOKEN"] = "t1"
    check("alert route honours ALERT_REPO", _alert_route(), ("private/alerts", "t1"))
    for key in ("REGISTRY_REPO", "REGISTRY_ALERT_TOKEN", "ALERT_REPO", "ALERT_TOKEN"):
        os.environ.pop(key, None)
    print("worker-pr self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo", required=True)
    common.add_argument("--pr", required=True, type=int)

    state = subparsers.add_parser("review-state", parents=[common])
    state.add_argument("action", choices=("get", "set"))
    state.add_argument("--state", choices=("needs", "changes", "pass", "needs-user"))

    rrec = subparsers.add_parser("round-record", parents=[common])
    rrec.add_argument("--round", required=True, type=int)
    rrec.add_argument("--run-key", required=True)
    rrec.add_argument("--bot-login", required=True)

    rchk = subparsers.add_parser("round-check", parents=[common])
    rchk.add_argument("--max-rounds", required=True, type=int)
    rchk.add_argument("--bot-login", required=True)

    mrec = subparsers.add_parser("record-marker", parents=[common])
    mrec.add_argument("--kind", choices=sorted(MARKER_KINDS), required=True)
    mrec.add_argument("--round", required=True, type=int)
    mrec.add_argument("--run-key", required=True)
    mrec.add_argument("--bot-login", required=True)

    mchk = subparsers.add_parser("check-marker", parents=[common])
    mchk.add_argument("--kind", choices=sorted(MARKER_KINDS), required=True)
    mchk.add_argument("--round", required=True, type=int)
    mchk.add_argument("--max", required=True, type=int)
    mchk.add_argument("--bot-login", required=True)

    shap = subparsers.add_parser("reviewed-sha", parents=[common])
    shap.add_argument("action", choices=("get", "set"))
    shap.add_argument("--sha")

    vval = subparsers.add_parser("validate-verdict")
    vval.add_argument("--verdict-file", required=True)
    vval.add_argument("--files-file", required=True)

    findings = subparsers.add_parser("post-findings", parents=[common])
    findings.add_argument("--verdict-file", required=True)
    findings.add_argument("--round", required=True, type=int)

    # The raw account handle + PROVENANCE_SALT arrive ONLY via env (never argv — argv is echoed
    # into public workflow logs); the record stores just the salted 16-hex hash (decision 22a).
    # --verify-bot-login re-reads the PR from the live API (issue-bound, bot-authored, same-repo)
    # and takes head_sha from the API; without it --head-sha is required (backfill path).
    prov = subparsers.add_parser("provenance-record")
    prov.add_argument("--registry-repo", required=True)
    prov.add_argument("--target-repo", required=True)
    prov.add_argument("--pr", required=True, type=int)
    prov.add_argument("--head-sha", default="")
    prov.add_argument("--impl-provider", required=True)
    prov.add_argument("--impl-alias", required=True)
    prov.add_argument("--impl-account-h", default="",
                      help="pre-computed salted hash (backfill); default hashes env "
                           "WORKER_IMPL_ACCOUNT with env PROVENANCE_SALT")
    prov.add_argument("--issue", required=True, type=int)
    prov.add_argument("--run-key", required=True)
    prov.add_argument("--verify-bot-login", default="")

    vrec = subparsers.add_parser("verdict-record")
    vrec.add_argument("--registry-repo", required=True)
    vrec.add_argument("--target-repo", required=True)
    vrec.add_argument("--pr", required=True, type=int)
    vrec.add_argument("--round", required=True, type=int)
    vrec.add_argument("--verdict-file", required=True)

    nuser = subparsers.add_parser("needs-user", parents=[common])
    nuser.add_argument("--reason", required=True)
    nuser.add_argument("--issue", type=int)

    dis = subparsers.add_parser("disarm", parents=[common])
    dis.add_argument("--when", choices=("mismatch", "always"), required=True)

    # The live reviewer handle arrives via env WORKER_REVIEWER_ACCOUNT (not argv — argv is echoed
    # into public logs) and is compared against the recorded hash under PROVENANCE_SALT.
    arm = subparsers.add_parser("ready-and-arm", parents=[common])
    arm.add_argument("--reviewed-sha", required=True)
    arm.add_argument("--impl-provider", required=True)
    arm.add_argument("--impl-account-h", required=True)
    arm.add_argument("--reviewer-provider", required=True)
    arm.add_argument("--arm", choices=("true", "false"), required=True)
    arm.add_argument("--issue", type=int)
    # [OPUS-4.8] B3: the live trust-surface arm gate's path list (repeatable; from policy
    # security_paths). Empty -> DEFAULT_TRUST_SURFACE_PATHS (fail closed, never silently absent).
    arm.add_argument("--surface-path", action="append", default=[],
                     help="trust-surface path/prefix (repeatable; from policy security_paths)")

    rout = subparsers.add_parser("review-outcome", parents=[common])
    rout.add_argument("--verdict-file", required=True)
    rout.add_argument("--files-file", required=True)
    rout.add_argument("--round", required=True, type=int)
    rout.add_argument("--max-rounds", required=True, type=int)
    rout.add_argument("--security", action="store_true")
    # [OPUS-4.8] B3 / defects #2,#4: the WIRED trust-surface FILE list from the target policy
    # row's `security_paths` (repeatable). Any PR-diff path under one of these forces the human
    # arm even for a benign-labelled PR. Empty -> the built-in DEFAULT_TRUST_SURFACE_PATHS.
    rout.add_argument("--surface-path", action="append", default=[],
                      help="trust-surface path/prefix (repeatable; from policy security_paths)")
    rout.add_argument("--issue", type=int)
    # Budget-extension inputs (maintainer directive 2026-07-17): the implementer provider picks
    # the escalation ladder, the bot login trust-filters the durable fix-model markers, and the
    # run key stamps a recorded model pin.
    rout.add_argument("--impl-provider", required=True)
    rout.add_argument("--bot-login", required=True)
    rout.add_argument("--run-key", required=True)

    fout = subparsers.add_parser("fix-outcome", parents=[common])
    fout.add_argument("--round", required=True, type=int)
    fout.add_argument("--run-key", required=True)
    fout.add_argument("--bot-login", required=True)
    fout.add_argument("--injection", choices=("true", "false"), required=True)
    fout.add_argument("--made-changes", choices=("true", "false"), required=True)
    fout.add_argument("--gate-outcome", required=True)
    fout.add_argument("--pushed", choices=("true", "false"), required=True)
    fout.add_argument("--issue", type=int)
    fout.add_argument("--model", default="",
                      help="executed fix-model alias; recorded as a durable round marker")

    # Records/converges the fix-model floor pin (CLAIM's crashed-outcome convergence path; the
    # review outcome records it in-process). Idempotent — an equal-or-higher floor wins.
    mpin = subparsers.add_parser("record-model-pin", parents=[common])
    mpin.add_argument("--round", required=True, type=int)
    mpin.add_argument("--tier", required=True)
    mpin.add_argument("--provider", required=True)
    mpin.add_argument("--run-key", required=True)
    mpin.add_argument("--bot-login", required=True)

    args = parser.parse_args()
    if args.self_test or args.command is None:
        return _self_test()
    try:
        if args.command == "review-state":
            if args.action == "set":
                if not args.state:
                    parser.error("review-state set requires --state")
                set_review_state(args.repo, args.pr, args.state)
            else:
                get_review_state(args.repo, args.pr)
        elif args.command == "round-record":
            record_round(args.repo, args.pr, args.round, args.run_key, args.bot_login)
        elif args.command == "round-check":
            check_round(args.repo, args.pr, args.max_rounds, args.bot_login)
        elif args.command == "record-marker":
            record_marker(args.repo, args.pr, args.kind, args.round, args.run_key, args.bot_login)
        elif args.command == "check-marker":
            check_marker(args.repo, args.pr, args.kind, args.round, args.max, args.bot_login)
        elif args.command == "reviewed-sha":
            if args.action == "set":
                if not args.sha or not re.fullmatch(r"[0-9a-f]{40}", args.sha):
                    parser.error("reviewed-sha set requires a 40-hex --sha")
                set_reviewed_sha(args.repo, args.pr, args.sha)
            else:
                get_reviewed_sha(args.repo, args.pr)
        elif args.command == "validate-verdict":
            diff_files = Path(args.files_file).read_text(encoding="utf-8").splitlines()
            with open(args.verdict_file, encoding="utf-8") as handle:
                document = json.load(handle)
            has_blockers = validate_verdict(document, diff_files)
            _write_outputs({"verdict": document["verdict"], "has_blockers": has_blockers,
                            "injection": document["injection_detected"]})
            print(f"verdict valid: {document['verdict']} (blockers={has_blockers})")
        elif args.command == "post-findings":
            post_findings(args.repo, args.pr, args.verdict_file, args.round)
        elif args.command == "provenance-record":
            impl_account_h = args.impl_account_h or account_hash(
                os.environ.get("WORKER_IMPL_ACCOUNT", ""),
                os.environ.get("PROVENANCE_SALT", ""))
            provenance_record(args.registry_repo, args.target_repo, args.pr, args.head_sha,
                              args.impl_provider, args.impl_alias, impl_account_h, args.issue,
                              args.run_key, verify_bot_login=args.verify_bot_login)
        elif args.command == "verdict-record":
            verdict_record(args.registry_repo, args.target_repo, args.pr, args.round,
                           args.verdict_file)
        elif args.command == "needs-user":
            alert_repo, alert_token = _alert_route()
            needs_user(args.repo, args.pr, args.reason, issue=args.issue,
                       alert_repo=alert_repo, alert_token=alert_token)
        elif args.command == "disarm":
            disarm(args.repo, args.pr, args.when)
        elif args.command == "ready-and-arm":
            ready_and_arm(args.repo, args.pr, args.reviewed_sha, args.impl_provider,
                          args.impl_account_h, args.reviewer_provider,
                          os.environ.get("WORKER_REVIEWER_ACCOUNT", ""),
                          args.arm == "true", issue=args.issue,
                          surface_paths=args.surface_path or None)
        elif args.command == "review-outcome":
            review_outcome(args)
        elif args.command == "fix-outcome":
            fix_outcome(args)
        elif args.command == "record-model-pin":
            record_model_pin(args.repo, args.pr, args.round, args.tier, args.provider,
                             args.run_key, args.bot_login)
    except (WorkerPrError, OSError, json.JSONDecodeError) as exc:
        print(f"worker-pr: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
