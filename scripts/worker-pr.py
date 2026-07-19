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
import random
import re
import subprocess
import sys
import tempfile
import time

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
# Provider escalation ladders in ESCALATION order — weakest tier FIRST, STRONGEST (terminal)
# tier LAST: ladder index is capability rank, exhaustion escalates UPWARD by pinning the tier
# ABOVE the highest that already ran. Maintainer capability order (2026-07-18):
# opus < luna < fable < sol. anthropic: opus then fable (fable terminal); openai: luna then sol
# (sol, the codex-side frontier model, terminal). Sol r2 finding 2 fixed the previous INVERTED
# declarations (["fable","opus"] / ["sol","luna"]) under which exhaustion on the strong tier
# "escalated" the fix floor DOWN to the weaker one. terra and sonnet are DOCS-ONLY models
# (maintainer directive 2026-07-18) and are structurally excluded from every ladder — a
# recorded terra/sonnet fix round or pin now fails closed. A pin or recorded model outside its
# provider ladder is REJECTED (hostile-input surface: a forged marker must never select an
# arbitrary provider_model — concrete ids are still resolved from protected target routing by
# alias).
ESCALATION_LADDERS = {"anthropic": ["opus", "fable"], "openai": ["luna", "sol"]}
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
    "scripts/trust-gate.py",
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
# Provenance + verdict records are written to the unprotected `ledger` data-plane branch
# (issue #96): master's required `gate` status check rejects EVERY direct contents-API PUT from
# github.token — no retry budget can ever land one — so record writes pin this ref exactly like
# the lease ledger (select-and-claim.py) and model-health CAS append. Keep in sync with
# groom.py / select-and-claim.py / model-health.py LEDGER_REF.
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")


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


def _ops_alert(alert_repo, alert_token, title, body):
    """Post or refresh ONE deduped ops-alert registry issue (rolling posture, usage-alert.py):
    an open issue with the same title is commented on, otherwise a new one is opened. Best-effort
    and credential-scoped — a missing route or a failed alert call never masks the operational
    error that triggered it: every gh call is check=False AND the whole delivery is wrapped, so
    even a raising path (the issue lookup goes through _gh_json → check=True + JSON parsing, and
    an unexpected list shape can KeyError) only logs, never propagates into the caller's raise."""
    if not (alert_repo and alert_token):
        return
    try:
        env = {"GH_TOKEN": alert_token}
        _run_gh(["label", "create", "ops-alert", "-R", alert_repo, "--color", "d73a4a",
                 "--description", "Autonomous worker availability alert (maintainer action)"],
                check=False, env=env)
        found = _gh_json(["issue", "list", "-R", alert_repo, "--label", "ops-alert", "--state",
                          "open", "--json", "number,title", "--limit", "50"], env=env) or []
        number = next((i["number"] for i in found
                       if isinstance(i, dict) and i.get("title") == title), None)
        if number:
            _run_gh(["issue", "comment", str(number), "-R", alert_repo, "--body", body],
                    check=False, env=env)
        else:
            _run_gh(["issue", "create", "-R", alert_repo, "--title", title, "--label",
                     "ops-alert", "--body", body], check=False, env=env)
    except Exception as exc:  # noqa: BLE001 — alert delivery must never mask the caller's error
        print(f"ops-alert delivery failed (non-fatal): {exc}", file=sys.stderr)


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
    "Human attention required" marker) is human-owned terminal: no autonomous fix push, review,
    or when=always defuse may touch it until a human clears the label. The ONE exception is the
    when=mismatch safety-only latch retraction (issue #105): a human hold parks pushes/reviews
    but must never strand an auto-merge latch on an unreviewed head — see disarm()."""
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
    crashed between ready and the arm latch — completing the redraft is what makes the sweep
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
    second parent against the PR's base branch, or None on ANY other shape: a non-merge or
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
        # Decision 7 REVISED (maintainer 2026-07-18: approved PRs were parking needs:user
        # unnecessarily — on the registry nearly EVERY self-management diff touches a trust
        # surface, so approve->park was the default outcome and the queue drowned in human
        # hand-offs): the cross-provider approve IS the arm decision on every surface. Trust
        # surfaces keep POST-merge auditability (the `trust-surface` label + an audit comment
        # listing the touched paths, applied by the outcome step) instead of a pre-merge
        # park; injection/tamper evidence still stops at a human above.
        return "arm"
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

    def _neutralize(text):
        # sol r8 on #257: model-controlled text is republished under the App identity, and
        # the audit-suppression check trusts App-authored markers — a prompt-injected
        # reviewer could smuggle the current SHA marker into its verdict and suppress the
        # real audit comment. Reserved marker prefixes are visibly defanged.
        return str(text).replace("<!-- sparq-", "<!- sparq-")

    document = json.loads(_neutralize(json.dumps(document)))
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


def _probe_registry_file(registry_repo, path, ref=None):
    """(existing_body, sha) for a registry data file, or (None, None) on a clean 404. Any other
    probe failure raises with the REAL API error text (issue #96: a masked error class turned a
    permanent branch-protection rejection into 80 silent 'kept conflicting' losses)."""
    location = f"repos/{registry_repo}/contents/{path}" + (f"?ref={ref}" if ref else "")
    probe = _run_gh(["api", location], check=False)
    if probe.returncode != 0:
        if "HTTP 404" in probe.stderr:
            return None, None
        raise WorkerPrError(
            f"registry file {path} probe failed: {(probe.stderr or '').strip() or 'unknown'}")
    try:
        meta = json.loads(probe.stdout)
        return base64.b64decode("".join(meta["content"].split())).decode(), meta["sha"]
    except (KeyError, ValueError, json.JSONDecodeError) as exc:
        raise WorkerPrError(f"registry file {path} is unreadable") from exc


# Parallel per-file record writers (the provenance record plus every review round's verdict) all
# CAS against the SAME `ledger` branch head, so a fixed un-jittered retry keeps them phase-locked:
# each loser re-reads the same sha, re-collides on the next PUT, and burns the whole budget in
# lock-step. A FULL-JITTER exponential backoff BETWEEN attempts decorrelates them (issue #148; the
# lease ledger hit and fixed the identical thundering-herd in #179). Module-level so --self-test
# patches it instead of sleeping for real.
def _registry_backoff_ceiling(attempt, base=0.5, cap=8.0):
    """Upper bound (seconds) for the sleep before CAS retry `attempt` (1-based): exponential
    base*2**(attempt-1), clamped to `cap`."""
    return min(cap, base * (2 ** (attempt - 1)))


def _registry_sleep_backoff(attempt):
    time.sleep(random.uniform(0, _registry_backoff_ceiling(attempt)))


def _registry_put_file(registry_repo, path, document, message, retries=6):
    """Create-or-keep a registry data file via the contents API with the same read-SHA CAS retry
    the lease ledger uses. Probe AND write pin the unprotected `ledger` data-plane branch
    (issue #96): master's required `gate` status check permanently rejects every direct
    contents-API PUT, so an unpinned write can never land regardless of retries. Idempotent: an
    existing byte-identical file — on the ledger branch OR the legacy pre-outage master copy —
    is success; an existing DIFFERENT file fails closed (provenance must never be silently
    rewritten, and a ledger write must never shadow a divergent legacy record). On final failure
    the REAL last API error is raised, never a generic conflict message."""
    body = json.dumps(document, indent=1, sort_keys=True) + "\n"
    encoded = base64.b64encode(body.encode()).decode()
    # BOTH record locations are probed before any success short-circuit (sol review r1 on
    # #100): readers consume the LEDGER copy first, so a divergent ledger record must fail
    # this write even when the legacy master copy is byte-identical — "already recorded" is
    # only claimable when EVERY existing copy matches. Legacy (<= sparq#2542) checked once —
    # master records are immutable; the ledger probe re-runs inside the CAS retry loop.
    legacy, _legacy_sha = _probe_registry_file(registry_repo, path)
    if legacy is not None and legacy != body:
        raise WorkerPrError(
            f"registry file {path} already exists with different content on the default branch")
    last_error = ""
    for attempt in range(retries):
        if attempt:
            # Full-jitter backoff BETWEEN attempts (never before the first read) so parallel
            # per-file writers stop re-colliding in lock-step on the same branch head (#148).
            _registry_sleep_backoff(attempt)
        existing, sha = _probe_registry_file(registry_repo, path, ref=LEDGER_REF)
        if existing is not None:
            if existing == body:
                return False  # already recorded — idempotent success
            raise WorkerPrError(f"registry file {path} already exists with different content "
                                f"on the '{LEDGER_REF}' branch")
        if legacy is not None:
            return False  # identical pre-migration record, no ledger copy — idempotent success
        args = ["api", "-X", "PUT", f"repos/{registry_repo}/contents/{path}",
                "-f", f"message={message}", "-f", f"content={encoded}",
                "-f", f"branch={LEDGER_REF}"]
        if sha:
            args += ["-f", f"sha={sha}"]
        put = _run_gh(args, check=False)
        if put.returncode == 0:
            return True
        last_error = (put.stderr or put.stdout or "").strip()
    # Terminal: the record never landed. A silently-lost provenance record makes the PR
    # permanently invisible to enumeration; a lost verdict burns a round without applying the
    # outcome. Page a human with the REAL API error before failing (best-effort — the alert can
    # never mask the raise below).
    _ops_alert(*_alert_route(),
               f"⚠️ Registry record write failing — {registry_repo}",
               f"> 🤖 SPARQ agent — `{path}` could not be written to the `{LEDGER_REF}` "
               f"data-plane branch after {retries} attempts. Last API error: "
               f"{last_error or 'unknown'}. Records are not landing (protection/ref/availability) "
               f"— a maintainer should check branch protection and the `{LEDGER_REF}` ref.")
    raise WorkerPrError(
        f"registry write for {path} on branch '{LEDGER_REF}' failed after {retries} attempts; "
        f"last API error: {last_error or 'unknown'}")


def provenance_record(registry_repo, target_repo, pr_number, head_sha, impl_provider, impl_alias,
                      impl_account_h, issue, run_key, verify_bot_login=None,
                      verify_head_branch=None):
    """Write the registry provenance record (the review loop's root of trust).

    Privacy (locked decision 22a): the record stores ONLY the salted account hash, never the raw
    handle. Integrity: when `verify_bot_login` is given the PR is re-read from the LIVE API and
    must be an open, bot-authored, same-repo PR whose head branch is bound to `issue` — because
    the calling job receives pr_number from a worker job that executed hostile target code, the
    reported number is verified against trusted inputs before anything is recorded, and the head
    sha is taken from the API (never from the hostile job's outputs). When the caller also knows
    this run's exact head branch (`verify_head_branch`, the reconcile path), the live head ref
    must EQUAL it — the issue prefix alone would accept a sibling run's PR for the same issue and
    record it under this run's implementer identity and run_key."""
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
        if verify_head_branch is not None and str(head.get("ref", "")) != verify_head_branch:
            raise WorkerPrError("provenance target PR head is not this run's exact head branch")
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


def select_reconcilable_pr(pulls, target_repo, bot_login, issue, head_branch):
    """PURE: from the target API's PR list for the DETERMINISTIC head branch, choose the single
    open, bot-authored, non-fork, issue-bound PR whose provenance must be reconciled (issue #128).
    Returns its number, or None when there is nothing to reconcile — the publisher never created a
    PR, OR the candidate set is ambiguous/malformed. Fails CLOSED to None rather than guessing a PR
    to anoint as trusted: the returned number is still RE-VERIFIED against the live API by
    provenance_record before anything is written, so this is only the first, fail-closed filter.
    The candidate's head ref must EQUAL this run's `head_branch` exactly — the API query already
    filters by head, but the query parameter is untrusted-in-effect (a filter silently ignored or
    loosened would return SIBLING runs' PRs for the same issue), so the response is re-asserted
    here rather than trusted. An empty bot_login (worker killed before target-identity was
    verified) yields None: no PR can be authored by nobody, and publish runs long after identity,
    so there is genuinely nothing to record."""
    if not bot_login or not head_branch or not isinstance(pulls, list):
        return None
    ref = re.compile(rf"^sparq-agent/issue-{int(issue)}-[A-Za-z0-9._-]+$")
    found = set()
    for pull in pulls:
        if not isinstance(pull, dict) or pull.get("state") != "open":
            continue
        if str((pull.get("user") or {}).get("login", "")) != bot_login:
            continue
        head = pull.get("head") or {}
        if (head.get("repo") or {}).get("full_name") != target_repo:
            continue
        if str(head.get("ref", "")) != head_branch or not ref.fullmatch(head_branch):
            continue
        number = pull.get("number")
        if isinstance(number, int) and number > 0:
            found.add(number)
    return next(iter(found)) if len(found) == 1 else None


def reconcile_provenance(registry_repo, target_repo, head_branch, impl_provider, impl_alias,
                         impl_account_h, issue, run_key, verify_bot_login):
    """Recover-and-record provenance independently of the publisher's output (issue #128).

    `gh pr create` mutates GitHub BEFORE pr_number reaches $GITHUB_OUTPUT, so a lost response,
    cancellation, or local failure AFTER server-side creation leaves an open worker PR that the
    publish job never reported. With provenance keyed off that empty output the record is skipped,
    the review sweep (which fails closed on a missing record) never enumerates the PR, and the open
    PR blocks the next implementation attempt. This reconciler runs on a fresh runner for EVERY
    acquired attempt: it resolves the PR from the deterministic head branch — built from trusted run
    identity (issue + run id/attempt), NEVER from the hostile worker output — verifies it, and
    records provenance. Idempotent with any publish-path record: pr_number is re-read from the head
    branch, head_sha from the live API, and run_key is the shared run identity, so the document is
    byte-identical. A missing PR records nothing (the legitimate no-publish case)."""
    if not re.fullmatch(r"sparq-agent/issue-[1-9][0-9]*-[A-Za-z0-9._-]+", head_branch or ""):
        raise WorkerPrError("reconcile head branch is unsafe")
    owner = target_repo.split("/", 1)[0]
    pulls = _gh_json([
        "api", f"repos/{target_repo}/pulls?head={owner}:{head_branch}&state=open&per_page=100"])
    pr_number = select_reconcilable_pr(pulls, target_repo, verify_bot_login, issue, head_branch)
    if pr_number is None:
        print(f"reconcile: no open bot PR on {head_branch}; nothing to record")
        return
    # head_sha is left empty on purpose: provenance_record's verify path re-reads it from the live
    # API (never from any worker output) exactly as the publish path does. verify_head_branch
    # binds that final live read to this run's EXACT branch, not merely the issue prefix.
    provenance_record(registry_repo, target_repo, pr_number, "", impl_provider, impl_alias,
                      impl_account_h, issue, run_key, verify_bot_login=verify_bot_login,
                      verify_head_branch=head_branch)
    _write_outputs({"pr_number": pr_number})


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
    # Reuse the rolling ops-alert posture (usage-alert.py): one deduped registry issue.
    _ops_alert(alert_repo, alert_token,
               f"⚠️ Review loop needs a human — {repo}#{pr_number}",
               f"> 🤖 SPARQ agent — {reason}\n\nhttps://github.com/{repo}/pull/{pr_number} "
               f"needs @{handle}.")
    print(f"needs-user recorded: {reason}")


def live_human_holds(repo, pr_number, issue=None, live=None):
    """[round-5 P1] LIVE hold-surface probe shared by EVERY outcome mutation path — the
    review/fix outcome label transitions AND the ready+arm — not just the arm (round 4 covered
    only ready_and_arm): a human/groom park that lands while a run is in flight must WIN over
    the run's stale outcome. A stale request_changes that reaches set_review_state(..,"changes")
    strips review:needs-user (the review:* labels are mutually exclusive) and silently unparks
    a PR whose crate the PLAN busy partition already freed for a sibling.

    Returns the sorted list of live hold labels: the PR's own HUMAN_OWNED_LABELS if any, else
    the source issue's needs:* set (the issue is the explicit `issue` when supplied, else
    derived from the worker head ref). `live` may carry an already-fetched pulls/N document to
    avoid a duplicate read (ready_and_arm reuses its CAS read).

    FAIL CLOSED on ambiguity [round-5 P2]: a malformed PR read, a malformed/hostile label
    payload (a non-list, or any non-dict entry / non-string name), or an unreadable
    source-issue probe RAISES WorkerPrError — the caller mutates nothing and the sweep simply
    retries. The old shape-tolerant read collapsed malformed label data to "no hold" and
    ready_and_arm still issued `pr ready` + the arm latch (fail OPEN on the dangerous act).

    DEFENSE-IN-DEPTH ONLY — RESIDUAL TOCTOU WINDOW (descoped from PR #286, tracked in
    issue #294): this probe is an unbound PREFLIGHT read; a hold that lands in the
    probe-to-mutation gap is still overwritten, because set_review_state deletes the
    mutually-exclusive review:* labels unconditionally and the arm path has the same gap
    before `pr ready`/the arm latch. The concrete worst case is a transiently-removed hold
    label (or, via the freed crate, a duplicate same-crate worker PR) — humanly recoverable
    churn, never credential exposure or data corruption. Closing the window needs a
    monotonic hold/disarm handshake: label transitions that can never delete a
    concurrently-added terminal hold (ETag/If-Match or a label compare-and-swap, or a
    tombstone marker automated paths cannot remove) — see issue #294 for the design
    constraints."""
    if live is None:
        live = _gh_json(["api", f"repos/{repo}/pulls/{pr_number}"])
    if not isinstance(live, dict):
        raise WorkerPrError("live PR hold state is unreadable; refusing to mutate (fail closed)")
    raw_labels = live.get("labels")
    if not isinstance(raw_labels, list) or any(
            not isinstance(label, dict) or not isinstance(label.get("name"), str)
            for label in raw_labels):
        raise WorkerPrError(
            "live PR label payload is malformed; refusing to mutate (fail closed)")
    holds = sorted({label["name"] for label in raw_labels} & set(HUMAN_OWNED_LABELS))
    if holds:
        return holds
    source_issue = issue
    if not source_issue:
        ref_match = WORKER_HEAD_RE.fullmatch(str((live.get("head") or {}).get("ref", "")))
        source_issue = int(ref_match.group(1)) if ref_match else None
    if not source_issue:
        return []
    probe = _gh_json(["api", f"repos/{repo}/issues/{source_issue}"])
    if not isinstance(probe, dict) or not isinstance(probe.get("labels"), list) or any(
            not isinstance(label, dict) or not isinstance(label.get("name"), str)
            for label in probe["labels"]):
        raise WorkerPrError(
            "source issue hold state is unreadable; refusing to mutate (fail closed)")
    return sorted({label["name"] for label in probe["labels"]
                   if label["name"].startswith("needs:")})


# Issue #153: a synthetic audit hit for the LIVE label-derived security posture. The path-based
# trust hits are file names; this stands in for a posture that came from a label rather than a
# touched path so the arm-time audit trail (Decision 7) still names WHY the surface armed.
SECURITY_LABEL_AUDIT_HIT = (
    "(live security label: routing match_labels / trust:* posture recomputed at arm time)")


def live_security_flagged(repo, pr_number, keywords, issue=None, live=None):
    """Issue #153: recompute the LABEL-derived security posture from LIVE data immediately before
    the arm — the union of the PR's OWN labels and its SOURCE issue's labels, classified against
    the builtin SECURITY_KEYWORDS + the TARGET routing's own `match_labels` keywords + the
    `trust:*` prefix (the SAME classifier the resolve step ran, only up to a full review round —
    25min+, or much longer queued — staler). resolve computes this posture ONCE, before the
    review; a `trust:*` / security-keyword label added to the PR or its source issue DURING the
    review window is otherwise invisible to the path-only arm recheck.

    Per Decision 7 (maintainer 2026-07-18) a stricter posture does NOT withhold the arm (approve
    IS the arm decision on every surface); a True return instead forces the SHA-bound POST-arm
    audit trail, so an auto-armed trust-plane change is durably recorded whether it was flagged by
    a touched PATH or only by a LABEL. FAIL CLOSED on ambiguity: an unreadable/malformed PR or
    source-issue label payload RAISES (the arm stands down rather than assume a permissive
    posture) — the same fail-closed shape as live_human_holds."""
    if live is None:
        live = _gh_json(["api", f"repos/{repo}/pulls/{pr_number}"])
    raw_labels = live.get("labels") if isinstance(live, dict) else None
    if not isinstance(raw_labels, list) or any(
            not isinstance(label, dict) or not isinstance(label.get("name"), str)
            for label in raw_labels):
        raise WorkerPrError(
            "live PR label payload is malformed; refusing to arm (fail closed)")
    labels = {label["name"] for label in raw_labels}
    source_issue = issue
    if not source_issue:
        ref_match = WORKER_HEAD_RE.fullmatch(str((live.get("head") or {}).get("ref", "")))
        source_issue = int(ref_match.group(1)) if ref_match else None
    if source_issue:
        probe = _gh_json(["api", f"repos/{repo}/issues/{source_issue}"])
        if not isinstance(probe, dict) or not isinstance(probe.get("labels"), list) or any(
                not isinstance(label, dict) or not isinstance(label.get("name"), str)
                for label in probe["labels"]):
            raise WorkerPrError(
                "source issue label state is unreadable; refusing to arm (fail closed)")
        labels |= {label["name"] for label in probe["labels"]}
    return security_flagged(labels, extra_keywords=tuple(keywords or ()))


def _merge_only_carry_forward(repo, head_sha, reviewed_sha, base_ref):
    """Issue #69 half 1, LIVE side: True only when BOTH halves hold — (a) the first-parent
    chain from the live head reaches the reviewed sha through two-parent merges whose
    second parents are each reachable from the PR's BASE branch (compare status
    identical/behind), and (b) the PR's diff vs its merge base is identical before and
    after the advance (diff_fingerprint). Issue #81: base_ref is the PR's ACTUAL base ref
    (live base.ref), never the repo default branch — for a PR targeting a non-default
    base, both compares against the default branch can fingerprint identical while the
    real diff vs the base changed, which would advance the marker across an unreviewed
    change. Any API failure, truncated compare file list (the API caps at 300), or
    ambiguity returns False — fail closed, the normal mismatch disarm proceeds and the
    sweep re-reviews the new head instead."""
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
            probe = _gh_json(["api", f"repos/{repo}/compare/{base_ref}...{second_parent}"])
            if not isinstance(probe, dict) or probe.get("status") not in ("identical", "behind"):
                return False
        fingerprints = []
        for sha in (reviewed_sha, head_sha):
            compared = _gh_json(["api", f"repos/{repo}/compare/{base_ref}...{sha}"])
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
    `sparq-agent/*` PR is ever touched. A PR labelled review:needs-user OR needs:user is
    human-owned, and when=always (the autonomous-fix defuse) stands down on it entirely — as it
    does on a `needs:*`-parked head-ref-linked SOURCE issue, which it additionally consults so a
    fix push never rides into that human's territory. But when=mismatch — the issue #42 safety
    invariant, retracting a latch that would merge a never-reviewed tree — must NOT be blocked by
    a human hold (issue #105): it retracts the latch (disable-auto/dequeue + redraft) while
    PRESERVING the hold label, dropping only the relabel that would re-admit the PR to the loop
    and never rebinding a held arm forward. mismatch also does NOT consult the source issue,
    for the same reason work-item parking must not strand a live latch. when=mismatch requires
    (armed OR ready-but-unarmed) AND head != reviewed-sha (registry issue #42 invariant —
    matching SHAs are NEVER disarmed).

    Issue #69 (as re-ordered by issue #81): the armed bit is derived FIRST — REST auto-merge
    OR live merge-queue membership (GraphQL — invisible to REST) — and decide_disarm gates
    everything after it; only a mismatch decide_disarm would act on is then tested for
    merge-only carry-forward. The pr-freshness update-branch automation advances heads with
    base-branch merge commits, and a content-identical advance REBINDS the reviewed-sha
    marker instead of disarming (both the chain shape and the diff-vs-merge-base identity
    must verify against the PR's ACTUAL base ref, never the repo default branch; anything
    else falls through to the disarm). A queued PR disarms via dequeuePullRequest +
    disablePullRequestAutoMerge, never `gh pr merge --disable-auto` (which fails on queued
    PRs); issue #81: a failed disarm action never skips the safety actions after it (the
    redraft fallback still runs), and all failures surface as ONE structured per-PR error (a
    disarm_error output row + a per-PR exit message) so the dispatch caller's per-item
    handling skips exactly this PR and sibling enumeration continues — the reviewed-sha
    marker is never advanced on a failed disarm."""
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
    held = human_owned(labels)
    if when == "always" and held:
        # A human hold (review:needs-user / needs:user) parks autonomous PUSHES and reviews, so
        # the when=always fix-admission defuse stands down entirely on a held PR. But it must
        # NEVER suppress when=mismatch, the registry issue #42 safety invariant: retracting an
        # auto-merge latch that would otherwise merge a never-reviewed tree on green CI. Issue
        # #105: a stale armed head escalated to review:needs-user after a failed disarm — or a
        # human label applied while the auto-merge latch survives — must still have that latch
        # retracted. mismatch falls through here; the `held` carve-out below keeps it to the
        # SAFETY actions only (disable-auto / dequeue + redraft), dropping the relabel that would
        # strip a review:needs-user hold and re-admit the PR to the autonomous loop.
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
        # Issue #69 half 1 / issue #81: the carry-forward rebind REPLACES a disarm, so it is
        # tested only AFTER decide_disarm confirms this mismatch is one the #42 invariant
        # would act on — a drafted/unarmed mismatch has nothing latched and its marker is
        # never advanced. The advance must be merge-only against the PR's ACTUAL base ref
        # (live base.ref, never the repo default branch): both the chain shape and the
        # diff-vs-merge-base identity are verified live and fail closed — any real content
        # change, unknown shape, or API failure falls through to the disarm below.
        # Issue #105: a HELD PR never carries the arm forward. Carry-forward rebinds the marker
        # and KEEPS the latch (a content-identical base-merge advance is a valid arm) — but a
        # human hold applied to an armed PR is an explicit "hand control back to me", so the
        # latch is retracted instead of preserved. The safety actions below run unconditionally.
        if when == "mismatch" and not held and reviewed != "none" and head_sha != reviewed:
            base_ref = str((live.get("base") or {}).get("ref") or "")
            if base_ref and _merge_only_carry_forward(repo, head_sha, reviewed, base_ref):
                set_reviewed_sha(repo, pr_number, head_sha)
                _write_outputs({"disarmed": False, "carried_forward": True})
                print("reviewed-sha carried forward: the head advanced only by verified "
                      "base-branch merge commits and the diff vs the merge base is unchanged")
                return
        # Issue #105: on a HELD PR keep ONLY the safety-only latch retraction (disable-auto /
        # dequeue + redraft — a draft cannot merge). The relabel (review:* -> needs) is dropped:
        # it would strip a review:needs-user hold and re-admit the PR to the autonomous review
        # loop. The human's park stands; the unreviewed head simply can no longer auto-merge.
        if held:
            actions = [action for action in actions if action != "relabel"]
        # Issue #81: per-action isolation — a failed action never skips the SAFETY actions
        # after it. Dequeue can succeed while the auto-merge disable fails; the redraft must
        # still run (converting to draft cancels a surviving auto-merge latch and a draft
        # cannot merge), so the PR lands in a verified-safe state even on partial failure.
        # Every failure is collected and re-raised as ONE loud structured error below — the
        # reviewed-sha marker is never advanced on any failure.
        failures = []
        for action in actions:
            try:
                if action == "disable-auto":
                    if queued:
                        _queue_disarm_mutation("dequeuePullRequest", node_id)
                        print("merge-queue entry removed (GraphQL dequeue)")
                        if live.get("auto_merge") is not None:
                            _queue_disarm_mutation("disablePullRequestAutoMerge", node_id)
                            print("auto-merge disabled (GraphQL; the PR was queued)")
                    else:
                        # Idempotent convergence on READ STALENESS (2026-07-18 defer-loop,
                        # sol r1 on #234): the planning read can be stale/raced — auto-merge
                        # may already be off by the time the mutation runs, and
                        # `gh pr merge --disable-auto` then errors ("Can't disable
                        # auto-merge"). On failure, RE-QUERY authoritative state: success is
                        # accepted ONLY when a fresh read confirms auto-merge absent and the
                        # PR not queued; anything else retains the structured failure.
                        try:
                            _run_gh(["pr", "merge", str(pr_number), "-R", repo,
                                     "--disable-auto"])
                            print("auto-merge disabled (stale arm latch removed)")
                        except WorkerPrError:
                            fresh = _gh_json(["api", f"repos/{repo}/pulls/{pr_number}"])
                            _, fresh_queued = _merge_queue_state(repo, pr_number)
                            if (isinstance(fresh, dict)
                                    and fresh.get("auto_merge") is None
                                    and not fresh_queued):
                                print("auto-merge freshly confirmed off "
                                      "(idempotent disarm convergence)")
                            else:
                                raise
                elif action == "redraft":
                    _run_gh(["pr", "ready", str(pr_number), "-R", repo, "--undo"])
                    print("pull request returned to draft for the review sweep")
                else:
                    set_review_state(repo, pr_number, "needs")
            except WorkerPrError as action_exc:
                failures.append(f"{action}: {' '.join(str(action_exc).split())}")
        if failures:
            raise WorkerPrError("partial disarm — " + "; ".join(failures))
    except WorkerPrError as exc:
        # Issue #69 half 2: the structured per-PR error — one sanitized output row plus a
        # per-PR exit message. The dispatch caller maps the nonzero exit to a per-item
        # DispatchError and skips exactly this PR; siblings keep enumerating.
        reason = " ".join(str(exc).split())[:200] or "disarm failed"
        _write_outputs({"disarmed": False, "disarm_error": reason})
        raise WorkerPrError(f"disarm {repo}#{pr_number}: {reason}") from exc
    _write_outputs({"disarmed": True})
    print(f"disarm applied ({when}): {','.join(actions)}")


# [P1 arm regression — review-fix runs 29674274380 (#326) / 29674657458 (#332)] GitHub
# REFUSES the auto-merge latch while the PR reads ALREADY fully mergeable ("clean"/"unstable"
# status): pr-gate.yml re-runs `gate` on ready_for_review, but GitHub takes 1-14s (observed)
# to REGISTER that queued run after `pr ready`, so an immediate enable sees every requirement
# satisfied and errors "Pull request is in clean status". (sol r3 on #334) that refusal is
# RETRYABLE like any other transient — NEVER a direct merge. The round-2 direct-merge
# fallback was REMOVED because it (a) merged while the fresh ready_for_review `gate` run was
# queued-but-unregistered — bypassing a required gate that might fail — and (b) closed the PR
# before the post-arm metadata (review:pass / source-issue completion / reviewed-sha bind)
# landed, an unrecoverable crash window (sweep + groom enumerate OPEN PRs only). The latch,
# once accepted, natively waits for the fresh gate; if every attempt loses the registration
# race, the caller's fail-closed draft-restore path runs and the sweep retries next tick —
# convergent, never gate-bypassing.
#
# (sol r4 on #334) THE LATCH PRIMITIVE IS THE EXPLICIT GraphQL enablePullRequestAutoMerge
# MUTATION (`gh api graphql`), NEVER `gh pr merge --auto`: current gh CLI semantics (sol
# cites the v2.96 source) make `pr merge --auto` fall through to a DIRECT merge when the PR
# reads CLEAN/HAS_HOOKS/UNSTABLE — exactly the already-mergeable registration-lag window this
# retry loop exists for — so with the CLI verb the "latch-only" invariant above was FALSE.
# The raw mutation can only ever latch; GitHub rejects it outright on a clean-status PR
# ("Pull request is in clean status"), which remains the retryable signal. The head CAS moves
# from `--match-head-commit` into the mutation's expectedHeadOid input.
ARM_AUTO_MERGE_MUTATION = (
    "mutation($pr:ID!,$oid:GitObjectID!){"
    "enablePullRequestAutoMerge(input:{pullRequestId:$pr,expectedHeadOid:$oid,"
    "mergeMethod:SQUASH}){clientMutationId}}")
ARM_ATTEMPTS = 6
# Per-retry backoff bounds (seconds) for the 5 sleeps between the 6 attempts.
# (sol r4 on #334) FLOORS are a deterministic MINIMUM cumulative schedule: each sleep is
# max(floor, jitter), so the delay before the FINAL attempt is >= sum(floors) = 20s
# regardless of jitter draws — the old uniform(1s, ceiling) lower bound admitted a ~5s
# cumulative total that never covered the evidenced 14s registration tail. CEILINGS keep the
# Fibonacci-ish full-jitter decorrelation with a bounded ~31s worst case.
ARM_BACKOFF_FLOORS = (2.0, 3.0, 4.0, 5.0, 6.0)
ARM_BACKOFF_CEILINGS = (2.0, 3.0, 5.0, 8.0, 13.0)


def _arm_backoff_ceiling(attempt):
    """Upper bound (seconds) for the sleep before arm retry `attempt` (1-based)."""
    return ARM_BACKOFF_CEILINGS[min(attempt, len(ARM_BACKOFF_CEILINGS)) - 1]


def _arm_backoff_floor(attempt):
    """Deterministic MINIMUM sleep (seconds) before arm retry `attempt` (1-based)."""
    return ARM_BACKOFF_FLOORS[min(attempt, len(ARM_BACKOFF_FLOORS)) - 1]


def _arm_sleep_backoff(attempt):
    # (sol r4 on #334) max(floor, jitter): the retry exists to give Actions time to register
    # the ready_for_review-triggered gate run, and the floors alone guarantee >= 20s
    # cumulative before the final attempt (evidenced tail: 14s) with NO reliance on jitter
    # luck; the jittered ceiling keeps parallel arms decorrelated. Module-level so
    # --self-test patches it instead of sleeping.
    time.sleep(max(_arm_backoff_floor(attempt),
                   random.uniform(0.0, _arm_backoff_ceiling(attempt))))


def _arm_error_text(result):
    """One sanitized single-line string from a failed gh call (stderr wins, stdout appended)."""
    return " ".join(f"{result.stderr or ''} {result.stdout or ''}".split())[:300]


def _arm_hold_recheck(repo, pr_number, issue):
    """(sol r2 on #334) LIVE hold revalidation INSIDE the arm retry window — the SAME
    live_human_holds probe the pre-arm recheck runs, re-read fresh. Returns
    ('hold', labels) when a human/groom park is live, ('unreadable', error) when the hold
    surface cannot be read (fail CLOSED — the caller treats it as a failed attempt so the
    draft-restore liveness path still runs, instead of raising past the undo), and
    (None, '') when clear."""
    try:
        holds = live_human_holds(repo, pr_number, issue=issue)
    except WorkerPrError as exc:
        return "unreadable", str(exc)
    if holds:
        return "hold", ", ".join(holds)
    return None, ""


def _arm_auto_merge(repo, pr_number, reviewed_sha, attempts=ARM_ATTEMPTS, issue=None):
    """Latch the sha-bound auto-merge, surviving the post-`pr ready` CLEAN-STATUS race
    (P1, runs 29674274380/29674657458: every failed arm's ready_for_review `gate` run
    STARTED 1-14s AFTER the enable call failed — the arm raced GitHub's check-run
    registration and lost, and GitHub refuses enablePullRequestAutoMerge on a PR whose
    requirements are all satisfied). Strategy: the LATCH IS THE ONLY MERGE PRIMITIVE
    (sol r3 on #334 — the round-2 direct-merge fallback is gone; see the
    ARM_BACKOFF_CEILINGS block comment for why it was structurally unsafe), and (sol r4
    on #334) the latch is issued as the EXPLICIT enablePullRequestAutoMerge GraphQL
    mutation, never `gh pr merge --auto` — the CLI verb direct-merges a
    CLEAN/HAS_HOOKS/UNSTABLE PR (gh v2.96 source), which falsified the latch-only
    invariant exactly inside the registration-lag window. The PR node id is fetched and
    the live head oid verified against the reviewed sha up front (fail closed on
    mismatch/unreadable — the reviewed tree can never come back under a moved head), and
    the head CAS rides in the mutation's expectedHeadOid input so GitHub itself refuses
    a latch on any later head move. EVERY refusal — the clean/unstable already-mergeable
    family included — backs off with floored, capped jitter and retries the mutation;
    once GitHub registers the queued ready_for_review `gate` run the latch is accepted
    and natively waits for that fresh gate, so a required check can never be bypassed.
    Exhausting every attempt returns failure and the caller's fail-closed draft-restore
    path runs (the sweep retries next tick — convergent). Every gh failure is PRINTED —
    the pre-fix path swallowed stderr, leaving runs with only the generic 'arm failed'
    line.

    (sol r2 on #334) HOLD REVALIDATION PER ATTEMPT: this retry/backoff loop (~31s worst
    case) runs AFTER ready_and_arm's single pre-arm hold probe, and a park that lands
    during backoff (review:needs-user / needs:user on the PR, needs:* on the source
    issue) does NOT move the head — --match-head-commit cannot refuse it, so without a
    re-probe the retry would arm straight past the park. The live hold probe re-runs
    immediately BEFORE every retry attempt; any hold aborts with mode 'human_hold' (the
    caller restores the draft and exits with the valid human_hold shape); an unreadable
    hold surface aborts as a plain failure (fail closed, draft restored, the sweep
    retries). Returns (ok, mode, last_error) with mode in {'auto', 'human_hold'}."""
    # (sol r4 on #334) node id + head pre-verify, ONCE before the loop: the mutation needs
    # the GraphQL node id, and a head already moved past the reviewed sha can never latch
    # (expectedHeadOid would refuse every attempt) — fail closed immediately instead of
    # burning the full backoff schedule. Per-attempt races stay covered by expectedHeadOid,
    # GitHub's own atomic CAS at mutation time.
    try:
        live = _gh_json(["api", f"repos/{repo}/pulls/{pr_number}"])
    except WorkerPrError as exc:
        return False, "", f"PR node lookup failed before the latch (fail closed): {exc}"
    node_id = str(live.get("node_id") or "") if isinstance(live, dict) else ""
    live_head = (str((live.get("head") or {}).get("sha", ""))
                 if isinstance(live, dict) else "")
    if not node_id:
        return False, "", "PR node id unavailable; refusing to latch (fail closed)"
    if live_head != reviewed_sha:
        return False, "", (f"live head {live_head[:12] or '(unreadable)'} != reviewed sha "
                           f"{reviewed_sha[:12]}; refusing to latch (fail closed)")
    last_error = ""
    for attempt in range(1, attempts + 1):
        if attempt > 1:
            _arm_sleep_backoff(attempt - 1)
            # (sol r2 on #334) re-probe immediately before the retry: the backoff window
            # is exactly where a mid-arm park lands without moving the head.
            verdict, detail = _arm_hold_recheck(repo, pr_number, issue)
            if verdict == "hold":
                print(f"arm attempt {attempt}/{attempts}: ABORTED — human hold live "
                      f"({detail}); the park wins over the retry", file=sys.stderr)
                return False, "human_hold", f"human hold live mid-arm: {detail}"
            if verdict == "unreadable":
                print(f"arm attempt {attempt}/{attempts}: hold revalidation unreadable; "
                      f"refusing to retry (fail closed): {detail}", file=sys.stderr)
                return False, "", f"hold revalidation unreadable (fail closed): {detail}"
        # (sol r4 on #334) the explicit mutation: latch-or-refuse, structurally incapable
        # of a direct merge. The reviewed sha rides in expectedHeadOid (the CAS).
        merge = _run_gh(["api", "graphql",
                         "-f", f"query={ARM_AUTO_MERGE_MUTATION}",
                         "-f", f"pr={node_id}",
                         "-f", f"oid={reviewed_sha}"], check=False)
        if merge.returncode == 0:
            return True, "auto", ""
        last_error = _arm_error_text(merge) or "unknown gh error"
        print(f"arm attempt {attempt}/{attempts}: enable auto-merge failed: {last_error}",
              file=sys.stderr)
    return False, "", last_error


def ready_and_arm(repo, pr_number, reviewed_sha, impl_provider, impl_account_h, reviewer_provider,
                  reviewer_account, arm, issue=None, surface_paths=None, bot_login="",
                  reviewed_base="", security_keywords=None):
    """The ONLY place a PR can be armed. Fail-closed assertions per locked decision 6; a live-head
    mismatch returns the PR to review:needs (a fixer/other push raced the approval). [round-4 P1]
    the hold surfaces (HUMAN_OWNED_LABELS on the PR, needs:* on the source issue) are re-read
    live immediately before the first mutation: a park that landed mid-review-run aborts the
    ready+arm untouched (arm_complete=false), so an in-flight run can never arm past a
    human/groom park the busy-partition carve-out relies on. (sol r2 on #334) the same probe
    re-runs INSIDE the arm retry window — before every retry attempt (see _arm_auto_merge) —
    because a park landing during backoff does not move the head and the expectedHeadOid
    CAS alone cannot refuse it; a mid-arm hold exits with the same human_hold shape after the
    draft restore. (sol r3 on #334) the auto-merge LATCH is the only merge primitive — the
    direct-merge fallback was removed, so the fresh ready_for_review `gate` run is always
    waited on and the post-arm metadata (review:pass / issue completion / reviewed-sha bind)
    always lands while the PR is still open. (sol r4 on #334) the latch is the explicit
    enablePullRequestAutoMerge GraphQL mutation, never `gh pr merge --auto` (the CLI verb
    direct-merges a CLEAN/HAS_HOOKS/UNSTABLE PR — see _arm_auto_merge).

    Account disjointness is asserted on SALTED HASHES (locked decision 22a): the registry
    provenance record stores impl_account_h, and the live reviewer handle is hashed here with the
    same PROVENANCE_SALT. Liveness (crash-window hardening): `gh pr ready` un-drafts the PR, so if
    the subsequent latch mutation fails the draft state is restored (`gh pr ready --undo`) — the
    PR stays visible to the sweep for a bounded re-review instead of stalling non-draft/unarmed
    forever; if even the undo fails, this escalates to review:needs-user (never silent).

    [OPUS-4.8] B3, REVISED per Decision 7 (maintainer 2026-07-18): the trust-surface set is
    still re-derived on LIVE changed files (renamed-path safe), but a hit no longer withholds
    the arm — approve IS the arm decision on every surface. The hits feed the POST-arm audit
    trail (_apply_trust_surface_audit: trust-surface label + one idempotent marker comment),
    applied only after a successful live arm, with loud failures.

    [issue #153] the LABEL-derived security posture is re-derived LIVE here too (PR + source
    issue labels vs the routing keywords), not just at resolve: a security label added mid
    review folds into the same audit trail (a True posture appends SECURITY_LABEL_AUDIT_HIT),
    so an auto-armed trust-plane change is audited whether it was flagged by path or by label."""
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
    # [round-4 P1, shared helper since round 5] PARKED-BUT-ARMING RACE: a human/groom park
    # that landed WHILE this review run was in flight must WIN over the run's stale
    # mark-ready+arm decision — the busy-partition carve-out (dispatch-claim.py
    # busy_packages_of_pulls) frees a parked draft's crate on the premise that a parked PR
    # cannot reach main on its own, and an arm that ignores a mid-run park breaks exactly
    # that premise (the enumerator excluded holds at PLAN time, but this run launched BEFORE
    # the park landed). Re-read the hold surfaces HERE, before ANY mutation
    # (ready/arm/audit-comment/review-state) via live_human_holds — the SAME probe every
    # outcome mutation runs (round-5 P1: the round-4 recheck covered only this arm path
    # while a stale `changes` outcome could still strip review:needs-user) — over the live
    # PR labels from the same fresh read the head CAS uses, plus the source issue's needs:*
    # state. Unreadable/malformed hold surfaces RAISE (fail closed, round-5 P2: malformed
    # label payloads previously read as no-hold and the arm still issued ready+merge).
    # Any hold aborts with the valid-exit shape (arm_complete=false — review-fix.yml then
    # never binds reviewed-sha) and NO comment/label churn: the PR is human-owned, and the
    # sweep's enumerator already excludes it for as long as the park stands.
    holds = live_human_holds(repo, pr_number, issue=issue, live=live)
    if holds:
        _write_outputs({"armed": False, "head_moved": False, "human_hold": True,
                        "arm_complete": False})
        print(f"ready+arm ABORTED pre-arm: human hold detected ({', '.join(holds)}) — "
              "the park stands; no ready/arm/review-state mutation was applied")
        return
    head_sha = str(live.get("head", {}).get("sha", ""))
    if head_sha != reviewed_sha:
        # Not an error: new commits landed between approve and arm; re-review binds to the new head.
        set_review_state(repo, pr_number, "needs")
        _write_outputs({"armed": False, "head_moved": True,
                        "arm_complete": False})
        print("live head advanced past the reviewed sha; returned to review:needs")
        return
    live_base = str((live.get("base") or {}).get("ref", ""))
    if reviewed_base and live_base != reviewed_base:
        # Base retarget changes the EFFECTIVE diff without moving the head, and
        # --match-head-commit cannot see it (sol r5 on #257) — the approval bound a
        # different comparison; re-review against the new base. RESIDUAL RISK, DOCUMENTED
        # (sol r7): GitHub exposes no base-CAS primitive, so a retarget in the window
        # between this check and the merge latch cannot be excluded mechanically; the
        # actor able to retarget is a write+ collaborator (already inside the trust
        # boundary), resolution REJECTS non-default-base PRs outright, and this pre-arm
        # check plus the head CAS bound everything GitHub's API allows us to bind.
        set_review_state(repo, pr_number, "needs")
        _write_outputs({"armed": False, "head_moved": True, "base_moved": True,
                        "arm_complete": False})
        print("live base ref differs from the reviewed base; returned to review:needs")
        return
    trust_hits = ()
    if arm:
        # Live trust-surface re-derivation BEFORE any undraft/latch (renamed-path safe).
        # Decision 7 REVISED (maintainer 2026-07-18): a hit no longer parks — it feeds the
        # POST-arm audit trail below (label + comment applied only after a SUCCESSFUL arm,
        # with checked failures — sol r1 on #257).
        surfaces = tuple(surface_paths) if surface_paths else DEFAULT_TRUST_SURFACE_PATHS
        # SHA-BOUND snapshot (sol r3): the mutable PR files endpoint is ABA-racable
        # (A -> benign B -> A force-push between the head check and this read would hide
        # the hits while the CAS still accepts A). The compare at the immutable
        # reviewed_sha cannot change under us.
        base_ref = str((live.get("base") or {}).get("ref", "")) or "main"
        sha_files = _files_at_sha(repo, base_ref, reviewed_sha)
        if FILES_TRUNCATED_SENTINEL in sha_files:
            # Fail closed toward MORE audit: an unverifiable inventory is treated as a hit.
            trust_hits = (FILES_TRUNCATED_SENTINEL,)
        else:
            trust_hits = trust_surface_paths_touched(sha_files, surfaces)
        # Issue #153: the LABEL-derived security posture is recomputed LIVE here too. resolve
        # classified it ONCE, before a review that may have taken 25min+ (or queued far
        # longer); a trust:* / routing-keyword label added to the PR or its SOURCE issue mid
        # review is invisible to the path-only recheck above. Per Decision 7 a stricter
        # posture does NOT withhold the arm — it is folded into the SHA-bound audit trail so
        # the auto-armed trust-plane change is durably recorded whether flagged by path or by
        # label. Malformed live label surfaces RAISE (fail closed, same shape as the hold
        # recheck); the arm never proceeds on an unreadable posture.
        if live_security_flagged(repo, pr_number, security_keywords, issue=issue, live=live):
            trust_hits = tuple(trust_hits) + (SECURITY_LABEL_AUDIT_HIT,)
    if arm and trust_hits:
        # Durable audit BEFORE the merge latch can fire (sol r2 on #257): auto-merge can
        # complete immediately, and a post-merge crash would leave an armed trust diff with
        # no audit trail (reconciliation only walks open PRs). The comment/label are
        # SHA-bound and idempotent, so an arm failure + re-review re-audits the new head.
        _apply_trust_surface_audit(repo, pr_number, trust_hits, reviewed_sha,
                                   bot_login=bot_login)
    _run_gh(["pr", "ready", str(pr_number), "-R", repo])
    arm_mode = ""
    if arm:
        # Atomic SHA-bound arm (sol r2): GitHub's own CAS — the mutation's expectedHeadOid
        # only latches if the head still equals the reviewed sha at mutation time, closing
        # the read-to-arm race.
        # [P1 arm regression] the latch is retried through the post-ready clean-status race
        # (see _arm_auto_merge), and the REAL gh error rides every failure message — the
        # pre-fix single-shot attempt swallowed stderr and lost to the race deterministically
        # on any PR whose draft-time `gate` was already green (#326 lost 3 rounds -> parked).
        # (sol r2 on #334) _arm_auto_merge re-runs the live hold probe before every retry
        # attempt — a park landing during the backoff window (~31s worst case) does not move
        # the head, so the head CAS alone cannot refuse it; a mid-arm hold comes back as
        # mode 'human_hold'. (sol r3 on #334) latch-only: exhaustion falls into the
        # draft-restore path below, never a direct merge. (sol r4 on #334) the latch is the
        # explicit enablePullRequestAutoMerge mutation — `gh pr merge --auto` is banned from
        # this path outright (the CLI verb direct-merges an already-mergeable PR).
        armed_ok, arm_mode, arm_error = _arm_auto_merge(repo, pr_number, reviewed_sha,
                                                        issue=issue)
        if not armed_ok:
            undo = _run_gh(["pr", "ready", str(pr_number), "-R", repo, "--undo"], check=False)
            if undo.returncode == 0:
                if arm_mode == "human_hold":
                    # (sol r2 on #334) a park landed MID-ARM (during the retry backoff
                    # window): same valid-exit shape as the pre-arm hold
                    # abort (arm_complete=false — review-fix.yml never binds reviewed-sha)
                    # with the draft restored (undo above — semantics unchanged) and NO
                    # review-state/comment churn: the PR is human-owned, the sweep's
                    # enumerator excludes it while the park stands.
                    _write_outputs({"armed": False, "head_moved": False,
                                    "human_hold": True, "arm_complete": False})
                    print(f"ready+arm ABORTED mid-arm: {arm_error} — the park stands; "
                          "draft restored, no review-state mutation was applied")
                    return
                # Back to draft with review:needs and NO reviewed-sha bind (the bind runs after
                # this step) — the sweep re-reviews next tick, bounded by max_review_rounds.
                raise WorkerPrError(
                    "auto-merge arm failed; draft restored for the sweep to retry "
                    f"(last gh error: {arm_error})")
            alert_repo, alert_token = _alert_route()
            needs_user(repo, pr_number,
                       "arming failed AFTER the PR left draft and the draft state could not be "
                       "restored; a human must re-arm or re-draft this PR",
                       issue=issue, alert_repo=alert_repo, alert_token=alert_token)
            raise WorkerPrError("auto-merge arm failed and the draft undo failed; escalated "
                                f"(last gh error: {arm_error})")
    set_review_state(repo, pr_number, "pass")
    if issue:
        # Deferred issue completion (locked decision 16): complete only on arm, not on publish.
        _load_worker_issue().set_status(repo, issue, "complete")
    _write_outputs({"armed": bool(arm), "head_moved": False,
                    "trust_surface": bool(trust_hits), "arm_complete": True,
                    "arm_mode": arm_mode})
    print(f"pull request marked ready{' and armed (auto-merge)' if arm else ''}")


TRUST_AUDIT_MARKER_PREFIX = "<!-- sparq-trust-audit:v1 sha="
TRUST_AUDIT_MARKER = TRUST_AUDIT_MARKER_PREFIX  # back-compat alias for tests/greps


COMPARE_FILES_CAP = 300  # GitHub returns up to 300 changed files on compare page 1 (hard cap)
FILES_TRUNCATED_SENTINEL = "(compare file inventory truncated/unavailable - assumed trust-surface)"


def _files_at_sha(repo, base_ref, sha):
    """Changed-file names (current AND previous names — rename-safe) from the IMMUTABLE
    base...sha compare, the SHA-bound counterpart of the mutable PR files endpoint (sol
    r3/r4 on #257). GitHub exposes files only on the FIRST compare page, capped at 300;
    at/over the cap or on a malformed/missing files array this FAILS CLOSED by returning
    the sentinel — the caller treats it as a trust hit and audits MORE, never less."""
    doc = _gh_json(["api", f"repos/{repo}/compare/{base_ref}...{sha}"])
    rows = doc.get("files") if isinstance(doc, dict) else None
    if not isinstance(rows, list) or len(rows) >= COMPARE_FILES_CAP:
        return [FILES_TRUNCATED_SENTINEL]
    files = []
    for r in rows:
        if not isinstance(r, dict):
            return [FILES_TRUNCATED_SENTINEL]
        files.append(str(r.get("filename", "")))
        prev = r.get("previous_filename")
        if isinstance(prev, str) and prev:
            files.append(prev)
    return files


def _apply_trust_surface_audit(repo, pr_number, hits, reviewed_sha, bot_login=""):
    """Durable PRE-arm audit trail for an arming trust-plane diff (Decision 7 revision,
    hardened per sol r2 on #257): the label + ONE idempotent comment listing the touched
    security paths, SHA-BOUND — the idempotency marker carries the reviewed sha and only a
    [bot]-authored marker for THIS sha suppresses a re-post (a stale audit from an earlier
    head never masks the current one; collaborator pre-seeding is within the existing
    write+ trust boundary and documented). Failures are LOUD (raise)."""
    marker = f"{TRUST_AUDIT_MARKER_PREFIX}{reviewed_sha} -->"
    label = _run_gh(["pr", "edit", str(pr_number), "-R", repo,
                     "--add-label", "trust-surface"], check=False)
    if label.returncode != 0:
        _run_gh(["label", "create", "trust-surface", "-R", repo,
                 "--description", "Armed trust-plane diff - post-merge audit trail",
                 "--color", "D93F0B"], check=False)
        _run_gh(["pr", "edit", str(pr_number), "-R", repo, "--add-label", "trust-surface"])
    existing = _paginated_comments(repo, pr_number)
    # Only the EXACT App identity may suppress a re-post (sol r3: any-[bot] let a foreign
    # issues-write bot pre-seed the marker); with no bot_login supplied, nothing suppresses
    # (fail toward a duplicate audit, never toward a missing one).
    if not (bot_login and any(
            marker in str(c.get("body", ""))
            and str(c.get("user", {}).get("login", "")) == bot_login
            for c in existing)):
        body = ("> 🤖 SPARQ agent\n\nArming on cross-provider approve. "
                "Trust-surface audit trail (complete): " + ", ".join(hits) + " @ "
                + reviewed_sha[:12] + ". Post-merge review welcome; revert-and-reopen is "
                "the escalation path.\n\n" + marker)
        _run_gh(["pr", "comment", str(pr_number), "-R", repo, "--body", body])


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
    # [round-5 P1] HOLD WINS on EVERY outcome, not just the arm (the round-4 recheck lived
    # only in ready_and_arm): re-read the live hold surfaces BEFORE any comment/label/state
    # mutation. A terminal human/groom park that landed after this review resolved makes the
    # whole outcome STALE — applying `changes` would call set_review_state(.., "changes"),
    # which REMOVES review:needs-user (the review:* labels are mutually exclusive) and
    # silently unparks a PR whose crate the PLAN busy partition already freed for a sibling;
    # `needs-user` would comment on and relabel a human-owned PR. The outcome is DROPPED
    # with a log line and NOTHING mutated — findings unposted, reviewed-sha left unbound
    # (review-fix.yml keys the bind step off decision != 'hold'), arm_complete=false — so
    # the sweep re-derives this head after a human clears the park. Unreadable/malformed
    # hold surfaces raise (fail closed; the step fails and the sweep retries).
    holds = live_human_holds(args.repo, args.pr, issue=args.issue)
    if holds:
        _write_outputs({"decision": "hold", "human_hold": True, "arm_complete": False})
        print(f"review outcome DROPPED: human hold detected ({', '.join(holds)}) — the hold "
              "wins; no findings/label/state mutation was applied and reviewed-sha stays "
              "unbound")
        return
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
        # narrowly-minted arm token; the post-arm trust-surface audit trail is applied
        # THERE, after a successful live arm with checked failures (sol r1 on #257).
        print("verdict approved: arm step will run under the arm-scoped token")


def fix_outcome(args):
    injection = args.injection == "true"
    made_changes = args.made_changes == "true"
    gate_ok = args.gate_outcome == "success"
    pushed = args.pushed == "true"
    # [round-5 P1] HOLD WINS on every outcome mutation (see review_outcome): a human/groom
    # park that landed while this fix ran makes the outcome stale — `re-review` would call
    # set_review_state(.., "needs") and strip review:needs-user (a silent unpark), and
    # `needs-user` would churn a human-owned PR. Drop the whole outcome BEFORE any
    # marker/label/state mutation; the sweep re-derives once a human clears the park.
    # Unreadable/malformed hold surfaces raise (fail closed; the step fails, the sweep
    # retries).
    holds = live_human_holds(args.repo, args.pr, issue=args.issue)
    if holds:
        _write_outputs({"decision": "hold", "human_hold": True})
        print(f"fix outcome DROPPED: human hold detected ({', '.join(holds)}) — the hold "
              "wins; no marker/label/state mutation was applied")
        return
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

    # select_reconcilable_pr (issue #128): the fail-closed filter that recovers a PR from the
    # deterministic head branch when the publisher's pr_number output was lost. Each assertion
    # flips the result on a WRONG answer, so the test is non-vacuous.
    repo = "acme/widget"
    branch = "sparq-agent/issue-7-9-1"
    good_pr = {"number": 42, "state": "open", "user": {"login": bot},
               "head": {"ref": branch, "repo": {"full_name": repo}}}
    check("reconcile recovers the open bot issue PR",
          select_reconcilable_pr([good_pr], repo, bot, 7, branch), 42)
    check("reconcile: empty list (publisher never opened a PR) records nothing",
          select_reconcilable_pr([], repo, bot, 7, branch), None)
    # A closed/merged PR on the branch is not a live provenance target.
    closed = json.loads(json.dumps(good_pr)); closed["state"] = "closed"
    check("reconcile ignores a non-open PR",
          select_reconcilable_pr([closed], repo, bot, 7, branch), None)
    # Fork with the same branch name must never be trusted as the bot's PR.
    fork = json.loads(json.dumps(good_pr)); fork["head"]["repo"]["full_name"] = "mallory/widget"
    check("reconcile rejects a fork head",
          select_reconcilable_pr([fork], repo, bot, 7, branch), None)
    # Wrong author (branch spoofed by a non-bot) is rejected.
    spoof = json.loads(json.dumps(good_pr)); spoof["user"]["login"] = "mallory"
    check("reconcile rejects a non-bot author",
          select_reconcilable_pr([spoof], repo, bot, 7, branch), None)
    # Issue-binding: a PR for a DIFFERENT issue's branch is not this run's PR.
    check("reconcile rejects a different issue's branch",
          select_reconcilable_pr([good_pr], repo, bot, 8, branch), None)
    # Exact-branch binding (review round 1): a bot-authored, same-repo, open PR for the SAME
    # issue but a DIFFERENT run's branch must be refused even if the API's head filter leaked
    # it into the response — the issue prefix alone is not this run's identity.
    sibling = json.loads(json.dumps(good_pr))
    sibling["head"]["ref"] = "sparq-agent/issue-7-8-1"
    check("reconcile rejects a sibling run's branch for the same issue",
          select_reconcilable_pr([sibling], repo, bot, 7, branch), None)
    # Empty bot_login (worker killed before target identity) fails closed.
    check("reconcile fails closed on empty bot login",
          select_reconcilable_pr([good_pr], repo, "", 7, branch), None)
    # Empty head_branch can never bind a PR to a run — fail closed, never match everything.
    check("reconcile fails closed on empty head branch",
          select_reconcilable_pr([good_pr], repo, bot, 7, ""), None)
    # Ambiguity (should be impossible per one-open-PR-per-branch) records nothing, never a guess.
    other = json.loads(json.dumps(good_pr)); other["number"] = 43
    check("reconcile fails closed on ambiguous candidates",
          select_reconcilable_pr([good_pr, other], repo, bot, 7, branch), None)
    # Malformed/hostile entries can only DROP a candidate, never fabricate one.
    check("reconcile tolerates malformed entries",
          select_reconcilable_pr([None, 123, {}, good_pr], repo, bot, 7, branch), 42)

    # provenance_record's FINAL live-API verification carries the same exact-branch binding
    # (review round 1): with verify_head_branch given, a live PR on a sibling run's branch for
    # the same issue must RAISE, and the exact branch must still record. Monkeypatched I/O —
    # no network, no registry writes.
    prov_docs = []
    real_prov = {name: globals()[name] for name in ("_gh_json", "_registry_put_file")}
    prov_pull = {"state": "open", "user": {"login": bot},
                 "head": {"ref": branch, "sha": "a" * 40, "repo": {"full_name": repo}}}
    try:
        globals()["_gh_json"] = lambda a, **k: json.loads(json.dumps(prov_pull))
        globals()["_registry_put_file"] = (
            lambda _repo, _path, document, _msg: prov_docs.append(document) or True)
        provenance_record("o/registry", repo, 42, "", "anthropic", "opus", "ab" * 8, 7,
                          "10.1", verify_bot_login=bot, verify_head_branch=branch)
        check("provenance verify records the exact run branch",
              [d["pr_number"] for d in prov_docs], [42])
        try:
            provenance_record("o/registry", repo, 42, "", "anthropic", "opus", "ab" * 8, 7,
                              "10.1", verify_bot_login=bot,
                              verify_head_branch="sparq-agent/issue-7-8-1")
        except WorkerPrError:
            check("provenance verify rejects a sibling run's branch", "rejected", "rejected")
        else:
            check("provenance verify rejects a sibling run's branch", "accepted", "rejected")
    finally:
        for name, real in real_prov.items():
            globals()[name] = real

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
    check("approve+security ARMS (Decision 7 revision 2026-07-18)",
          decide_review("approve", False, False, 1, 3, True), "arm")
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
    check("approve at exhaustion still arms on any surface (Decision 7 revision)",
          decide_review("approve", False, False, 3, 3, True,
                        budget_action="extend-progress"), "arm")

    # ---- decide_budget (directive 2026-07-17): the combined round-budget policy ----
    def budget(rounds, models, progress, provider="anthropic", base=3, pending=(), pin=None):
        return decide_budget(rounds, models, progress, provider, base_rounds=base,
                             pending_fix_models=pending, pin_floor=pin)

    check("budget below base continues", budget(2, ["fable"], "regressing"),
          {"action": "continue", "pin": None})
    check("budget zero rounds continues", budget(0, [], None),
          {"action": "continue", "pin": None})
    # Mechanism 1 — model escalation, precedence over progress (it resets the quality question).
    # Direction (sol r2 f2): the ladder escalates UPWARD per opus < luna < fable < sol —
    # exhaustion on the WEAK tier pins the STRONG tier, never the reverse.
    check("exhaustion on opus pins fable (escalates UP)", budget(3, ["opus"], "stagnant"),
          {"action": "extend-model-pin", "pin": "fable"})
    check("model pin outranks improving progress", budget(3, ["opus"], "improving"),
          {"action": "extend-model-pin", "pin": "fable"})
    check("exhaustion on luna pins sol (escalates UP)",
          budget(3, ["luna"], None, provider="openai"),
          {"action": "extend-model-pin", "pin": "sol"})
    # Mechanism 2 — progress extension once the top tier has run (or nothing is recorded)
    check("fable + improving extends on progress (terminal tier)",
          budget(3, ["fable"], "improving"),
          {"action": "extend-progress", "pin": None})
    check("opus+fable + improving is progress-only", budget(4, ["opus", "fable"], "improving"),
          {"action": "extend-progress", "pin": None})
    check("no fix record + improving extends", budget(3, [], "improving"),
          {"action": "extend-progress", "pin": None})
    # Re-review authorization: a PUSHED-but-unreviewed fix at/above the pinned floor gets its
    # re-review even at exhaustion (the terminal-grant orphan defect: the executed fable fix
    # falsifies the top-tier predicate while the stagnant grade predates that fix)
    check("pending pinned-floor fix authorizes its re-review",
          budget(3, ["opus", "fable"], "stagnant", pending=["fable"], pin="fable"),
          {"action": "extend-pending-review", "pin": None})
    check("no pending fix in the same posture stops (flip side)",
          budget(3, ["opus", "fable"], "stagnant"),
          {"action": "needs-user", "pin": None})
    check("pending fix BELOW the pinned floor never extends",
          budget(3, ["opus", "fable"], "stagnant", pending=["opus"], pin="fable"),
          {"action": "needs-user", "pin": None})
    check("unpinned pending fix authorizes (floor is the ladder bottom)",
          budget(3, ["opus"], None, pending=["opus"]),
          {"action": "extend-pending-review", "pin": None})
    check("pending re-review precedes the progress extension",
          budget(3, ["fable"], "improving", pending=["fable"], pin="fable"),
          {"action": "extend-pending-review", "pin": None})
    check("openai pending fix authorizes its re-review",
          budget(3, ["sol"], None, provider="openai", pending=["sol"]),
          {"action": "extend-pending-review", "pin": None})
    check("hard cap still dominates a pending fix",
          budget(6, ["opus", "fable"], "stagnant", pending=["fable"], pin="fable"),
          {"action": "needs-user", "pin": None})
    check("pending fix below base just continues",
          budget(2, ["opus"], None, pending=["opus"]),
          {"action": "continue", "pin": None})
    # needs-user sides (flip-goes-red on every ACT above). fable/sol are the TERMINAL tiers:
    # exhaustion there never pins DOWN the ladder — it stops (or extends only on progress).
    check("fable + stagnant stops (never pins DOWN to opus)", budget(3, ["fable"], "stagnant"),
          {"action": "needs-user", "pin": None})
    check("fable + regressing stops", budget(4, ["fable"], "regressing"),
          {"action": "needs-user", "pin": None})
    check("fable + ungraded stops", budget(3, ["fable"], None),
          {"action": "needs-user", "pin": None})
    check("no fix record + stagnant stops", budget(3, [], "stagnant"),
          {"action": "needs-user", "pin": None})
    check("hard cap stops even below-top + improving", budget(6, ["opus"], "improving"),
          {"action": "needs-user", "pin": None})
    check("hard cap stops past 6", budget(7, ["fable"], "improving"),
          {"action": "needs-user", "pin": None})
    check("round 5 still extends under the cap", budget(5, ["opus"], None)["action"],
          "extend-model-pin")
    # openai two-tier ladder: SOL is terminal — mechanism 2 only once sol has run
    check("openai sol + stagnant stops (never pins DOWN to luna)",
          budget(3, ["sol"], "stagnant", provider="openai"),
          {"action": "needs-user", "pin": None})
    check("openai improving extends", budget(3, ["sol"], "improving", provider="openai"),
          {"action": "extend-progress", "pin": None})
    # an explicit policy base above the hard cap is respected up to the base, never extended
    check("base above cap continues below base", budget(6, ["fable"], "improving", base=8),
          {"action": "continue", "pin": None})
    check("base above cap stops at base", budget(8, ["fable"], "improving", base=8),
          {"action": "needs-user", "pin": None})
    for bad, name in (
            (lambda: budget(3, ["gpt-omega"], None), "unknown fix model"),
            (lambda: budget(3, ["sol"], None), "cross-provider fix model"),
            (lambda: budget(3, ["sonnet"], None), "docs-only fix model (sonnet)"),
            (lambda: budget(3, ["terra"], None, provider="openai"),
             "docs-only fix model (terra)"),
            (lambda: decide_budget(3, [], None, "mystery"), "unknown provider"),
            (lambda: budget(3, [], "better"), "unknown progress value"),
            (lambda: budget(True, [], None), "boolean rounds"),
            (lambda: decide_budget(3, [], None, "anthropic", base_rounds=0), "zero base"),
            (lambda: budget(3, ["opus"], None, pending=["gpt-omega"]), "unknown pending model"),
            (lambda: budget(3, ["opus"], None, pending=["sol"]),
             "cross-provider pending model"),
            (lambda: budget(3, ["opus"], None, pending=["opus"], pin="sol"),
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
        {"user": {"login": bot}, "body": f"x {FIX_MODEL_MARKER} round=1 model=fable run=1.1 -->"},
        {"user": {"login": bot}, "body": f"x {FIX_MODEL_MARKER} round=1 model=fable run=1.2 -->"},
        {"user": {"login": bot}, "body": f"x {FIX_MODEL_MARKER} round=2 model=opus run=2.1 -->"},
        {"user": {"login": "mallory"},
         "body": f"x {FIX_MODEL_MARKER} round=3 model=opus run=6.6 -->"},
        {"user": {"login": bot},
         "body": f"y {PROGRESS_MARKER} round=2 progress=improving -->"},
        {"user": {"login": "mallory"},
         "body": f"y {PROGRESS_MARKER} round=3 progress=improving -->"},
    ]
    check("fix models per round (bot-only, deduped)", fix_round_models(esc_comments, bot),
          {1: ["fable"], 2: ["opus"]})
    check("progress per round (bot-only)", round_progress(esc_comments, bot),
          {2: "improving"})
    check("no pin markers yields no floor", pinned_fix_floor(esc_comments, bot, "anthropic"),
          None)
    pin_comments = esc_comments + [
        {"user": {"login": bot}, "body": f"z {MODEL_PIN_MARKER} round=3 tier=opus run=3.1 -->"},
        {"user": {"login": "mallory"},
         "body": f"z {MODEL_PIN_MARKER} round=3 tier=fable run=6.6 -->"},
    ]
    check("pinned floor reads the bot marker (forged higher pin ignored)",
          pinned_fix_floor(pin_comments, bot, "anthropic"), "opus")
    check("highest recorded floor wins",
          pinned_fix_floor(pin_comments + [
              {"user": {"login": bot},
               "body": f"z {MODEL_PIN_MARKER} round=4 tier=fable run=4.1 -->"}], bot,
              "anthropic"), "fable")
    try:
        pinned_fix_floor([{"user": {"login": bot},
                           "body": f"z {MODEL_PIN_MARKER} round=1 tier=gpt-omega run=1.1 -->"}],
                         bot, "anthropic")
    except WorkerPrError:
        check("corrupt pin tier fails closed", "rejected", "rejected")
    else:
        check("corrupt pin tier fails closed", "accepted", "rejected")
    check("pinned chain keeps floor-and-above ascending",
          pinned_fix_chain("openai", "luna"), ["luna", "sol"])
    check("pinned chain at the terminal tier", pinned_fix_chain("anthropic", "fable"),
          ["fable"])
    check("pinned chain at the bottom is the whole ladder",
          pinned_fix_chain("anthropic", "opus"), ["opus", "fable"])
    check("openai pinned chain at its terminal tier", pinned_fix_chain("openai", "sol"),
          ["sol"])
    try:
        pinned_fix_chain("anthropic", "sol")
    except WorkerPrError:
        check("cross-provider pin fails closed", "rejected", "rejected")
    else:
        check("cross-provider pin fails closed", "accepted", "rejected")
    try:
        pinned_fix_chain("anthropic", "sonnet")
    except WorkerPrError:
        check("docs-only pin fails closed", "rejected", "rejected")
    else:
        check("docs-only pin fails closed", "accepted", "rejected")
    # STRUCTURAL ENFORCEMENT (maintainer directive 2026-07-18): terra + sonnet are DOCS-ONLY —
    # never a ladder member for any provider. review-fix.yml asserts the same over its
    # review/fix chain tables; dispatch-claim.py over REVIEW_CHAIN/FIX_CHAIN.
    check("docs-only models are excluded from every escalation ladder",
          sorted({"terra", "sonnet"} & {alias for ladder in ESCALATION_LADDERS.values()
                                        for alias in ladder}), [])

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
                            "post_findings", "record_model_pin", "_alert_route", "_gh_json")}
    try:
        # [round-5 P1] the outcome now probes the live hold surfaces before mutating; this
        # block exercises the budget machinery, so its fake serves an UNHELD PR + source issue.
        wiring_globals["_gh_json"] = lambda args, **_kw: (
            {"labels": []} if "/issues/" in (args[1] if len(args) > 1 else "")
            else {"state": "open", "labels": [],
                  "head": {"ref": "sparq-agent/issue-7-1-1", "sha": "b" * 40}})
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

            # Ladder direction (sol r2 f2): an exhausted OPUS fix pins UP to fable; a fable
            # (terminal-tier) fix can only progress-extend or stop.
            opus_fix = [{"user": {"login": bot},
                         "body": f"x {FIX_MODEL_MARKER} round=1 model=opus run=1.1 -->"}]
            fable_fix = [{"user": {"login": bot},
                          "body": f"x {FIX_MODEL_MARKER} round=1 model=fable run=1.1 -->"}]
            check("outcome model extension pins + stays changes",
                  outcome("stagnant", opus_fix),
                  [("findings", 3), ("pin", "fable"), ("state", "changes")])
            check("outcome progress extension stays changes without a pin",
                  outcome("improving", fable_fix), [("findings", 3), ("state", "changes")])
            terminal = outcome("stagnant", fable_fix)
            check("outcome terminal escalates once",
                  [entry[0] for entry in terminal], ["findings", "needs-user"])
            check("terminal reason names the exhausted budget",
                  "round budget is exhausted" in terminal[1][1], True)
    finally:
        wiring_globals.update(real_io)

    # ---- registry record writes pin the `ledger` data-plane branch (issue #96): master's
    # required `gate` status check permanently rejects every direct contents-API PUT from
    # github.token, so the probe must carry ?ref= and the PUT an explicit branch param, and a
    # final failure must surface the REAL API error (the masked generic 'kept conflicting'
    # is what silently lost every provenance/verdict record for 14h) ----
    put_calls = []
    put_state = {"files": {}, "put_rc": 0, "put_stderr": ""}

    def fake_put_run_gh(args, **_kwargs):
        put_calls.append(list(args))
        if "-X" in args:  # the PUT
            return argparse.Namespace(returncode=put_state["put_rc"], stdout="",
                                      stderr=put_state["put_stderr"])
        meta = put_state["files"].get(args[1])
        if meta is None:
            return argparse.Namespace(returncode=1, stdout="", stderr="HTTP 404: Not Found")
        return argparse.Namespace(returncode=0, stdout=json.dumps(meta), stderr="")

    def record_meta(document):
        body = json.dumps(document, indent=1, sort_keys=True) + "\n"
        return {"content": base64.b64encode(body.encode()).decode(), "sha": "f" * 40}

    # Full-jitter backoff between CAS attempts + a terminal ops-alert (issue #148): stub both
    # module hooks so the test asserts WHEN each fires without sleeping or hitting the API.
    backoff_attempts = []
    alert_calls = []
    real_backoff = wiring_globals["_registry_sleep_backoff"]
    real_ops_alert = wiring_globals["_ops_alert"]
    real_alert_json = wiring_globals["_gh_json"]
    real_alert_route = wiring_globals["_alert_route"]

    real_put_io = wiring_globals["_run_gh"]
    doc = {"pr_number": 7}
    legacy_loc = "repos/reg/repo/contents/orchestration/provenance/o--r--pr7.json"
    ledger_loc = f"{legacy_loc}?ref={LEDGER_REF}"
    try:
        wiring_globals["_run_gh"] = fake_put_run_gh
        wiring_globals["_registry_sleep_backoff"] = (
            lambda attempt: backoff_attempts.append(attempt))
        wiring_globals["_ops_alert"] = lambda *a: alert_calls.append(a)
        created = _registry_put_file("reg/repo", "orchestration/provenance/o--r--pr7.json",
                                     doc, "m")
        check("fresh record write creates", created, True)
        check("probe order: legacy master copy, then the pinned ledger ref",
              [call[1] for call in put_calls if "-X" not in call],
              [legacy_loc, ledger_loc])
        put_args = next(call for call in put_calls if "-X" in call)
        check("the PUT pins the ledger branch (never the protected default)",
              f"branch={LEDGER_REF}" in put_args, True)
        check("a first-attempt success never backs off and never alerts",
              (backoff_attempts, alert_calls), ([], []))

        put_calls.clear()
        put_state["files"] = {ledger_loc: record_meta(doc)}
        check("byte-identical ledger record is idempotent success",
              _registry_put_file("reg/repo", "orchestration/provenance/o--r--pr7.json",
                                 doc, "m"), False)
        check("idempotent hit performs no PUT",
              any("-X" in call for call in put_calls), False)
        put_state["files"] = {legacy_loc: record_meta(doc)}
        check("byte-identical legacy master record is idempotent success (pre-outage records)",
              _registry_put_file("reg/repo", "orchestration/provenance/o--r--pr7.json",
                                 doc, "m"), False)
        put_state["files"] = {ledger_loc: record_meta({"pr_number": 8})}
        try:
            _registry_put_file("reg/repo", "orchestration/provenance/o--r--pr7.json", doc, "m")
            check("divergent existing ledger record fails closed", "no error", "error")
        except WorkerPrError as exc:
            check("divergent existing ledger record fails closed",
                  "different content" in str(exc), True)
        put_state["files"] = {legacy_loc: record_meta({"pr_number": 8})}
        try:
            _registry_put_file("reg/repo", "orchestration/provenance/o--r--pr7.json", doc, "m")
            check("divergent legacy master record fails closed", "no error", "error")
        except WorkerPrError as exc:
            check("divergent legacy master record fails closed",
                  "different content" in str(exc) and "default branch" in str(exc), True)
        # sol review r1: an identical LEGACY copy must never mask a divergent LEDGER copy —
        # readers consume the ledger first, so this exact combination silently served the
        # divergent record while the writer reported "already recorded".
        put_state["files"] = {legacy_loc: record_meta(doc),
                              ledger_loc: record_meta({"pr_number": 8})}
        try:
            _registry_put_file("reg/repo", "orchestration/provenance/o--r--pr7.json", doc, "m")
            check("identical legacy never masks a divergent ledger copy", "no error", "error")
        except WorkerPrError as exc:
            check("identical legacy never masks a divergent ledger copy",
                  "different content" in str(exc) and LEDGER_REF in str(exc), True)
        put_calls.clear()
        put_state["files"] = {legacy_loc: record_meta(doc)}
        check("identical legacy + no ledger copy stays idempotent (no PUT)",
              (_registry_put_file("reg/repo", "orchestration/provenance/o--r--pr7.json",
                                  doc, "m"),
               any("-X" in call for call in put_calls)), (False, False))

        put_calls.clear()
        backoff_attempts.clear()
        alert_calls.clear()
        put_state.update(files={}, put_rc=1,
                         put_stderr="HTTP 409: Required status check \"gate\" is expected.")
        try:
            _registry_put_file("reg/repo", "orchestration/provenance/o--r--pr7.json", doc, "m")
            check("exhausted write raises", "no error", "error")
        except WorkerPrError as exc:
            check("exhausted write surfaces the REAL API error text",
                  "Required status check \"gate\" is expected" in str(exc), True)
            check("exhausted write never masks as a generic conflict",
                  "kept conflicting" in str(exc), False)
        check("write failure retries the full budget",
              sum(1 for call in put_calls if "-X" in call), 6)
        # #148: jittered backoff fires BETWEEN the 6 attempts (never before the first probe),
        # so exactly attempts 1..5 sleep — decorrelating parallel writers off the shared head.
        check("exhausted write backs off between every retry (never before the first)",
              backoff_attempts, [1, 2, 3, 4, 5])
        # #148: a terminal write failure is not silent — it pages a human once, naming the
        # unwritten record and the real API error (a lost provenance record is invisible).
        check("exhausted write raises ONE ops-alert", len(alert_calls), 1)
        check("the ops-alert names the unwritten record and the real API error",
              alert_calls and "o--r--pr7.json" in alert_calls[0][3]
              and "gate" in alert_calls[0][3], True)

        # sol review r1 on #295: the terminal alert must be best-effort END TO END, so this
        # runs the REAL _ops_alert (not a stub) with its one raising path — the issue lookup
        # via _gh_json (check=True + JSON parsing) — blowing up, and asserts the registry-write
        # error still surfaces carrying the final PUT stderr, never the alert's own failure.
        def raising_alert_gh_json(args, **_kwargs):
            raise WorkerPrError("alert issue lookup failed")

        put_state.update(files={}, put_rc=1,
                         put_stderr="HTTP 409: Required status check \"gate\" is expected.")
        wiring_globals["_ops_alert"] = real_ops_alert
        wiring_globals["_alert_route"] = lambda: ("alerts/private", "alert-token")
        wiring_globals["_gh_json"] = raising_alert_gh_json
        try:
            _registry_put_file("reg/repo", "orchestration/provenance/o--r--pr7.json", doc, "m")
            check("a raising alert lookup never masks the terminal registry-write error",
                  "no error", "error")
        except WorkerPrError as exc:
            check("a raising alert lookup never masks the terminal registry-write error",
                  "Required status check \"gate\" is expected" in str(exc)
                  and "alert issue lookup" not in str(exc), True)
    finally:
        wiring_globals["_run_gh"] = real_put_io
        wiring_globals["_registry_sleep_backoff"] = real_backoff
        wiring_globals["_ops_alert"] = real_ops_alert
        wiring_globals["_gh_json"] = real_alert_json
        wiring_globals["_alert_route"] = real_alert_route

    # #148: the backoff ceiling is a bounded, non-decreasing full-jitter envelope — exponential
    # growth from the base, clamped so a long contention run never sleeps unboundedly.
    check("backoff ceiling starts at the base and grows exponentially",
          [_registry_backoff_ceiling(a) for a in (1, 2, 3)], [0.5, 1.0, 2.0])
    check("backoff ceiling is clamped at the cap",
          _registry_backoff_ceiling(99), 8.0)
    check("backoff ceiling is non-decreasing",
          all(_registry_backoff_ceiling(a) <= _registry_backoff_ceiling(a + 1)
              for a in range(1, 12)), True)

    # ---- disarm wiring (monkeypatched I/O), issue #69: a merge-only advance carries the
    # binding forward with the arm intact; a real content change still disarms; a QUEUED
    # mismatch takes the GraphQL dequeue path (never `gh pr merge`); a queue-API failure
    # surfaces as ONE structured per-PR error the dispatch caller can skip per item ----
    net = {}
    disarm_calls = []
    compare_paths = []
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
            if net.get("live_seq"):
                return net["live_seq"].pop(0)
            return net["live"]
        if path.startswith("repos/o/r/commits?"):
            return net["commits"]
        if path.startswith("repos/o/r/compare/"):
            compare_paths.append(path.split("compare/", 1)[1])
            return net["compare"][path.split("compare/", 1)[1]]
        raise WorkerPrError(f"unexpected API path {path}")

    def fake_run_gh(args, **_kwargs):
        disarm_calls.append(" ".join(args))
        failing = net.get("fail_mutation", "")
        code = 1 if failing and any(failing in part for part in args) else 0
        # Mirror production _run_gh: check=True (the default the REST disarm path uses)
        # RAISES on failure — only the GraphQL wrappers inspect returncode themselves.
        if code and _kwargs.get("check", True) and args[0] != "api":
            raise WorkerPrError(
                f"GitHub API request failed for {args[1] if len(args) > 1 else 'request'}")
        return argparse.Namespace(returncode=code, stdout="", stderr="")

    def run_disarm(base_ref="main", draft=False, armed=True, labels=(), when="mismatch",
                   **overrides):
        disarm_calls.clear()
        compare_paths.clear()
        fake_outputs.clear()
        net.clear()
        net.update({
            "live": {"state": "open", "draft": draft,
                     "auto_merge": {"merge_method": "squash"} if armed else None,
                     "user": {"login": "sparq[bot]"},
                     "labels": [{"name": name} for name in labels],
                     "body": f"pr body\n\n<!-- sparq-reviewed-sha:{rev_sha} -->\n",
                     "head": {"sha": head_69, "ref": "sparq-agent/issue-7-fix",
                              "repo": {"full_name": "o/r"}},
                     "base": {"ref": base_ref, "repo": {"default_branch": "main"}}},
            "commits": [dict(row) for row in merge_advance],
            "compare": {key: json.loads(json.dumps(doc))
                        for key, doc in identical_compares.items()},
        }, **overrides)
        disarm("o/r", 41, when)

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
        # Issue #81 finding 2: the disarm preconditions (queue probe -> decide_disarm) are
        # derived BEFORE the rebind, and the carry-forward still mutates nothing else.
        check("carry-forward derives disarm preconditions first, mutates nothing else",
              disarm_calls, ["queue-probe", f"rebind:{head_69}"])
        check("carry-forward outputs stay un-disarmed",
              (fake_outputs.get("disarmed"), fake_outputs.get("carried_forward")),
              (False, True))

        # Issue #81 finding 2 (red if the rebind is hoisted above decide_disarm again): a
        # drafted, unarmed mismatch is one the #42 invariant never touches — its marker must
        # NOT advance even though the advance is merge-only and content-identical.
        run_disarm(draft=True, armed=False)
        check("drafted/unarmed mismatch never advances the marker (#81)",
              (disarm_calls, fake_outputs.get("disarmed"),
               fake_outputs.get("carried_forward")),
              ([], False, None))

        # Ordering must not start EXECUTING disarm actions before the carry-forward test:
        # a queued content-identical advance keeps its arm (queue membership) intact.
        run_disarm(queued=True)
        check("queued carry-forward rebinds without dequeueing",
              (f"rebind:{head_69}" in disarm_calls,
               any("dequeuePullRequest" in call for call in disarm_calls)),
              (True, False))

        evil = json.loads(json.dumps(identical_compares))
        evil[f"main...{head_69}"]["files"][0]["patch"] = "@@ -1 +1 @@\n-x\n+EVIL"
        run_disarm(compare=evil)  # same merge shape, DIFFERENT content => normal disarm
        check("content change under a merge still disarms (REST path)",
              ("pr merge 41 -R o/r --disable-auto" in disarm_calls
               and "pr ready 41 -R o/r --undo" in disarm_calls
               and "state:needs" in disarm_calls
               and f"rebind:{head_69}" not in disarm_calls), True)
        check("content change reports disarmed", fake_outputs.get("disarmed"), True)

        # #234 sol r1: idempotent convergence must come from a FRESH re-read, not the stale
        # planning dict. (a) mutation fails but the re-read confirms auto-merge off and not
        # queued -> the disarm CONVERGES (safety actions run, no structured failure);
        armed_live = None  # captured below from the standard fixture
        run_disarm(compare=json.loads(json.dumps(evil)))
        armed_live = json.loads(json.dumps(net["live"]))
        unarmed_fresh = json.loads(json.dumps(armed_live)); unarmed_fresh["auto_merge"] = None
        run_disarm(compare=json.loads(json.dumps(evil)), fail_mutation="--disable-auto",
                   live_seq=[json.loads(json.dumps(armed_live)),
                             json.loads(json.dumps(unarmed_fresh))])
        check("stale-read disable-auto failure converges on a fresh confirmed-off read",
              ("pr ready 41 -R o/r --undo" in disarm_calls,
               fake_outputs.get("disarmed"), "disarm_error" in fake_outputs),
              (True, True, False))
        # (b) mutation fails and the fresh read STILL shows armed -> the structured failure
        # is retained (never a silent success on unverified state).
        try:
            run_disarm(compare=json.loads(json.dumps(evil)),
                       fail_mutation="--disable-auto",
                       live_seq=[json.loads(json.dumps(armed_live)),
                                 json.loads(json.dumps(armed_live))])
        except WorkerPrError as exc:
            check("genuine disable-auto failure retains the structured error",
                  str(exc).startswith("disarm o/r#41:") and "disable-auto" in str(exc), True)
        else:
            check("genuine disable-auto failure retains the structured error",
                  "no error", "raised")
        check("genuine failure records the skippable output row",
              (fake_outputs.get("disarmed"), bool(fake_outputs.get("disarm_error"))),
              (False, True))

        # Issue #81 finding 1 (red if the compare base reverts to the repo default branch):
        # the PR targets a non-default base. The default-branch compares fingerprint
        # identical (the trap) while the diff vs the ACTUAL base changed — the marker must
        # not advance across that unreviewed change.
        both_bases = {}
        for branch in ("main", "release"):
            both_bases.update({
                f"{branch}...{main_tip}": {"status": "behind", "files": []},
                f"{branch}...{rev_sha}": {"status": "diverged",
                                          "files": [dict(base_file)]},
                f"{branch}...{head_69}": {"status": "diverged",
                                          "files": [dict(base_file)]}})
        trap = json.loads(json.dumps(both_bases))
        trap[f"release...{head_69}"]["files"][0]["patch"] = "@@ -1 +1 @@\n-x\n+SMUGGLED"
        run_disarm(base_ref="release", compare=trap)
        check("non-default base: change hidden by the default-branch compare still disarms",
              ("pr merge 41 -R o/r --disable-auto" in disarm_calls,
               f"rebind:{head_69}" in disarm_calls, fake_outputs.get("disarmed")),
              (True, False, True))
        genuine = json.loads(json.dumps(both_bases))
        genuine[f"main...{head_69}"]["files"][0]["patch"] = "@@ -1 +1 @@\n-x\n+NOISE"
        run_disarm(base_ref="release", compare=genuine)
        check("non-default base: genuine merge-only advance carries forward on base.ref",
              (f"rebind:{head_69}" in disarm_calls, fake_outputs.get("carried_forward")),
              (True, True))
        # Issue #84 (red if the second-parent PROBE reverts to the default branch): the
        # fixture answers "behind" for BOTH main...tip and release...tip, so the trap and
        # genuine cases above cannot see which base the probe used — pin the exact compare
        # paths instead: every live compare targets base.ref, never the default branch.
        check("non-default base: every compare targets base.ref, never the default branch",
              (sorted(set(compare_paths)),
               any(path.startswith("main...") for path in compare_paths)),
              (sorted({f"release...{main_tip}", f"release...{rev_sha}",
                       f"release...{head_69}"}), False))
        # Issue #84, behavioural half: the merge's second parent is reachable from the
        # DEFAULT branch ("behind") but foreign to the PR's actual base ("diverged"),
        # while the fingerprints vs the base agree — only a base.ref probe rejects this
        # advance; a default-branch probe would carry an unreviewed merge forward.
        foreign = json.loads(json.dumps(both_bases))
        foreign[f"release...{main_tip}"]["status"] = "diverged"
        run_disarm(base_ref="release", compare=foreign)
        check("non-default base: second parent foreign to base.ref still disarms",
              ("pr merge 41 -R o/r --disable-auto" in disarm_calls,
               f"rebind:{head_69}" in disarm_calls, fake_outputs.get("disarmed")),
              (True, False, True))

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
        # Issue #81 finding 3: a failed disable-auto no longer aborts the sequence — the
        # redraft and relabel SAFETY actions still run (converting to draft cancels a
        # surviving latch and a draft cannot merge), then the error is still loud.
        check("dequeue failure still reaches the redraft + relabel fallback (#81)",
              ("pr ready 41 -R o/r --undo" in disarm_calls, "state:needs" in disarm_calls),
              (True, True))

        # Issue #81 finding 3 (red if a mid-sequence exception skips the remaining actions
        # again): the dequeue SUCCEEDS and the auto-merge disable fails — the PR must still
        # land verified-safe (redrafted + relabelled), the marker must not advance, and the
        # partial failure surfaces as the structured per-PR error.
        try:
            run_disarm(queued=True, commits=[dict(row) for row in plain_advance],
                       fail_mutation="disablePullRequestAutoMerge")
        except WorkerPrError as exc:
            check("partial disarm raises the structured per-PR error",
                  str(exc).startswith("disarm o/r#41:") and "disable-auto" in str(exc), True)
        else:
            check("partial disarm raises the structured per-PR error", "no error", "raised")
        check("partial disarm still dequeued first",
              any("dequeuePullRequest" in call for call in disarm_calls), True)
        check("partial disarm still redrafts and relabels (verified-safe fallback)",
              ("pr ready 41 -R o/r --undo" in disarm_calls, "state:needs" in disarm_calls),
              (True, True))
        check("partial disarm never advances the marker",
              (f"rebind:{head_69}" in disarm_calls, fake_outputs.get("disarmed"),
               bool(fake_outputs.get("disarm_error"))), (False, False, True))

        # ---- Issue #105: a human hold must never suppress the safety-only latch retraction ----
        held_evil = json.loads(json.dumps(evil))  # content-changed => a real mismatch to retract
        for hold in ("review:needs-user", "needs:user"):
            # when=mismatch on a HELD armed PR: the latch IS retracted (disable-auto + redraft),
            # but the relabel is DROPPED so the hold survives — the PR stays human-parked and can
            # no longer auto-merge an unreviewed head. Red if the pre-#105 human_owned skip
            # returns before any mutation, or if relabel is not filtered for held PRs.
            run_disarm(compare=json.loads(json.dumps(held_evil)), labels=(hold,))
            check(f"held mismatch ({hold}) retracts the latch (disable-auto + redraft)",
                  ("pr merge 41 -R o/r --disable-auto" in disarm_calls
                   and "pr ready 41 -R o/r --undo" in disarm_calls,
                   "state:needs" in disarm_calls, fake_outputs.get("disarmed")),
                  (True, False, True))
            # a HELD content-identical base-merge advance is retracted too, never carried
            # forward: a human label on an armed PR hands control back, so the arm is not kept.
            run_disarm(labels=(hold,))
            check(f"held content-identical advance ({hold}) retracts, never rebinds/keeps arm",
                  (f"rebind:{head_69}" in disarm_calls,
                   "pr merge 41 -R o/r --disable-auto" in disarm_calls,
                   "state:needs" in disarm_calls, fake_outputs.get("disarmed")),
                  (False, True, False, True))
            # when=always STILL stands down entirely on a human hold (the autonomous-fix defuse
            # must never touch a human-parked PR): no mutation at all.
            run_disarm(labels=(hold,), when="always")
            check(f"held always-defuse ({hold}) stands down untouched",
                  (disarm_calls, fake_outputs.get("disarmed")), ([], False))
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
    # ---- ready_and_arm wiring (Decision 7 revision, sol r1 on #257): approved trust-surface
    # diffs ARM with a post-arm audit; head races and arm failures never audit ----
    os.environ.setdefault("PROVENANCE_SALT", "selftest-salt")
    raa_calls = []
    raa_outputs = {}
    raa_state = {}
    real_raa = {name: globals()[name] for name in (
        "_gh_json", "_run_gh", "_pr_changed_files", "set_review_state",
        "_paginated_comments", "needs_user", "_write_outputs", "_arm_sleep_backoff")}

    def raa_gh_json(args, **_kw):
        path = args[1] if len(args) > 1 else ""
        if "/compare/" in path:
            # the SHA-bound snapshot (sol r3): only the reviewed sha's compare carries hits
            sha_in_path = path.split("...", 1)[1].split("?", 1)[0]
            path_hit = sha_in_path == "b" * 40 and not raa_state.get("benign_diff")
            files = [{"filename": "scripts/worker-pr.py"}] if path_hit else []
            return {"files": files}
        if "/issues/" in path:
            # the [round-4 P1] pre-arm SOURCE-issue hold probe
            if raa_state.get("issue_probe_garbage"):
                return "garbage"
            return {"labels": [{"name": name}
                               for name in raa_state.get("issue_labels", ())]}
        labels_payload = raa_state.get("labels_payload")
        return {"state": "open", "node_id": "PR_kwTESTNODE",
                "labels": (labels_payload if labels_payload is not None
                           else [{"name": name} for name in raa_state.get("labels", ())]),
                "head": {"ref": "sparq-agent/issue-7-1-1", "sha": raa_state["head"]},
                "base": {"ref": "main"}}

    def raa_run_gh(args, **kw):
        joined = " ".join(args)
        raa_calls.append(joined)
        if "enablePullRequestAutoMerge" in joined or list(args[:2]) == ["pr", "merge"]:
            # Merge-CAPABLE argv (the enablePullRequestAutoMerge mutation — or a regressed
            # `pr merge` of any form, which the structural anchor below turns red on).
            # [P1 arm regression] scripted per-merge-call results: a list of (rc, stderr)
            # rows consumed in order, so the retry/fallback shape is pinned exactly.
            script = raa_state.get("merge_script")
            if script is not None:
                rc, err = script.pop(0) if script else (0, "")
                if rc != 0 and raa_state.get("hold_after_fail"):
                    # (sol r2 on #334) mid-arm park injection: the hold labels land on the
                    # live PR only AFTER a failed merge attempt — simulating a human/groom
                    # park arriving during the retry backoff window, with the head unmoved.
                    raa_state["labels"] = raa_state.pop("hold_after_fail")
                return argparse.Namespace(returncode=rc, stdout="", stderr=err)
            if raa_state.get("merge_fails"):
                if kw.get("check", True):
                    raise WorkerPrError("GitHub API request failed for merge")
                return argparse.Namespace(returncode=1, stdout="", stderr="")
        return argparse.Namespace(returncode=0, stdout="", stderr="")

    def run_raa(head_ok=True, merge_fails=False, comments=(), labels=(),
                issue_labels=(), issue=None, probe_garbage=False, labels_payload=None,
                benign_diff=False, security_keywords=(), merge_script=None,
                hold_after_fail=None):
        raa_calls.clear(); raa_outputs.clear()
        sha = "b" * 40
        raa_state.update(head=(sha if head_ok else "c" * 40), merge_fails=merge_fails,
                         labels=labels, issue_labels=issue_labels,
                         issue_probe_garbage=probe_garbage, labels_payload=labels_payload,
                         benign_diff=benign_diff, merge_script=merge_script,
                         hold_after_fail=hold_after_fail)
        globals()["_gh_json"] = raa_gh_json
        globals()["_run_gh"] = raa_run_gh
        globals()["_pr_changed_files"] = lambda repo, pr: ["scripts/worker-pr.py"]
        globals()["set_review_state"] = lambda repo, pr, s: raa_calls.append(f"state:{s}")
        globals()["_paginated_comments"] = lambda repo, pr: list(comments)
        globals()["needs_user"] = lambda repo, pr, reason, **kw: raa_calls.append("needs-user")
        globals()["_arm_sleep_backoff"] = lambda attempt: raa_calls.append(f"sleep:{attempt}")
        globals()["_write_outputs"] = raa_outputs.update
        ready_and_arm("o/r", 41, sha, "anthropic", "ab" * 8, "openai", "acctX", True,
                      issue=issue, bot_login="sparq[bot]",
                      reviewed_base=raa_state.get("reviewed_base", "main"),
                      security_keywords=security_keywords or None)

    # (sol r4 on #334) mutation-NAME matching, not flag matching: the latch argv is
    # recognised by the literal GraphQL mutation name, and "merge-capable" argv is the
    # mutation OR any `gh pr merge` invocation (with or without --auto — the CLI verb
    # direct-merges an already-mergeable PR, so EVERY form is banned from the arm path and
    # turned red by the structural anchor below).
    LATCH_MUTATION = "enablePullRequestAutoMerge"

    def raa_latches():
        """Every recorded merge-CAPABLE gh argv (latch mutation or any `pr merge` form)."""
        return [c for c in raa_calls
                if LATCH_MUTATION in c or c.startswith("pr merge")]

    try:
        sha = "b" * 40
        run_raa()
        check("approved trust-surface diff ARMS (Decision 7 revision)",
              (any(LATCH_MUTATION in c for c in raa_calls), raa_outputs.get("armed"),
               raa_outputs.get("trust_surface")), (True, True, True))
        audit_i = next(i for i, c in enumerate(raa_calls) if "trust-surface" in c)
        # default -1: a MISSING latch mutation FAILS this check (red, not a crash) — that is
        # what a `pr merge` regression looks like to the mutation-name matchers.
        merge_i = next((i for i, c in enumerate(raa_calls) if LATCH_MUTATION in c), -1)
        check("audit trail is DURABLE BEFORE the merge latch (sol r2)",
              audit_i < merge_i, True)
        check("the arm is SHA-bound (expectedHeadOid CAS in the mutation variables)",
              any(LATCH_MUTATION in c and f"oid={sha}" in c for c in raa_calls), True)
        check("the mutation targets the fetched PR node id",
              any(LATCH_MUTATION in c and "pr=PR_kwTESTNODE" in c for c in raa_calls), True)
        check("audit comment carries the SHA-bound idempotency marker",
              any(TRUST_AUDIT_MARKER_PREFIX + sha in c for c in raa_calls), True)
        bot_marker = {"body": f"x {TRUST_AUDIT_MARKER_PREFIX}{sha} -->",
                      "user": {"login": "sparq[bot]"}}
        run_raa(comments=(bot_marker,))
        check("bot marker for THIS sha suppresses a re-post",
              any(TRUST_AUDIT_MARKER_PREFIX in c and "comment" in c for c in raa_calls),
              False)
        stale = {"body": f"x {TRUST_AUDIT_MARKER_PREFIX}{'d' * 40} -->",
                 "user": {"login": "sparq[bot]"}}
        run_raa(comments=(stale,))
        check("a stale-head marker does NOT suppress the fresh audit",
              any(TRUST_AUDIT_MARKER_PREFIX + sha in c for c in raa_calls), True)
        human_marker = {"body": f"x {TRUST_AUDIT_MARKER_PREFIX}{sha} -->",
                        "user": {"login": "mallory"}}
        run_raa(comments=(human_marker,))
        check("a non-bot marker does NOT suppress the audit",
              any(TRUST_AUDIT_MARKER_PREFIX + sha in c for c in raa_calls), True)
        foreign_bot = {"body": f"x {TRUST_AUDIT_MARKER_PREFIX}{sha} -->",
                       "user": {"login": "other-ci[bot]"}}
        run_raa(comments=(foreign_bot,))
        check("a FOREIGN bot marker does NOT suppress the audit (exact App pin, sol r3)",
              any(TRUST_AUDIT_MARKER_PREFIX + sha in c for c in raa_calls), True)
        check("the audit snapshot is SHA-bound (compare at reviewed sha, not the PR endpoint)",
              raa_outputs.get("trust_surface"), True)
        # _files_at_sha unit facets (sol r4): renames carry both names; the 300-cap and
        # malformed rows fail closed to the assumed-trust sentinel.
        real_files_gh = globals()["_gh_json"]
        try:
            globals()["_gh_json"] = lambda a, **k: {"files": [
                {"filename": "scripts/renamed-away.py",
                 "previous_filename": "scripts/worker-pr.py"}]}
            check("renamed trust file still hits (previous_filename tracked)",
                  bool(trust_surface_paths_touched(_files_at_sha("o/r", "main", "b" * 40))),
                  True)
            globals()["_gh_json"] = lambda a, **k: {"files": [
                {"filename": f"f{i}.txt"} for i in range(COMPARE_FILES_CAP)]}
            check("at the compare cap the inventory fails closed to the sentinel",
                  _files_at_sha("o/r", "main", "b" * 40), [FILES_TRUNCATED_SENTINEL])
            globals()["_gh_json"] = lambda a, **k: {"files": "garbage"}
            check("malformed files array fails closed to the sentinel",
                  _files_at_sha("o/r", "main", "b" * 40), [FILES_TRUNCATED_SENTINEL])
        finally:
            globals()["_gh_json"] = real_files_gh
        raa_state["reviewed_base"] = "release"  # live fake serves base ref "main"
        run_raa()
        check("base retarget returns to review:needs with NO arm and NO audit (sol r5)",
              ("state:needs" in raa_calls,
               bool(raa_latches()),
               any("trust-surface" in c for c in raa_calls)), (True, False, False))
        raa_state["reviewed_base"] = "main"
        run_raa(head_ok=False)
        check("head race returns to review:needs with NO arm and NO audit",
              ("state:needs" in raa_calls,
               bool(raa_latches()),
               any("trust-surface" in c for c in raa_calls)), (True, False, False))
        try:
            run_raa(merge_fails=True)
            check("arm failure raises (draft restored path)", "no error", "raised")
        except WorkerPrError:
            check("arm failure raises (draft restored path)", "raised", "raised")
        check("the pre-arm audit survives an arm failure (re-review re-audits per sha)",
              any(TRUST_AUDIT_MARKER_PREFIX in c for c in raa_calls), True)
        # ---- [P1 arm regression — review-fix runs 29674274380 (#326) / 29674657458 (#332)]
        # the post-`pr ready` CLEAN-STATUS race: pr-gate re-runs `gate` on ready_for_review,
        # but until GitHub registers that queued run the PR reads CLEAN and the auto-merge
        # latch is REFUSED ("Pull request is in clean status"). (sol r3+r4 on #334) the arm
        # must (a) mark ready STRICTLY before any latch call, (b) RETRY the latch with
        # backoff on EVERY refusal — the already-mergeable clean/unstable family included,
        # NEVER a direct merge (a direct merge bypasses the queued-but-unregistered fresh
        # gate run and closes the PR before the post-arm metadata lands), (c) issue the
        # latch ONLY as the enablePullRequestAutoMerge mutation — `gh pr merge --auto`
        # direct-merges a CLEAN/HAS_HOOKS/UNSTABLE PR (gh v2.96), so every `pr merge` form
        # is banned — and (d) surface the REAL gh error on terminal failure (the pre-fix
        # path swallowed stderr). ----
        run_raa()
        ready_i = next(i for i, c in enumerate(raa_calls) if c.startswith("pr ready"))
        merge_i = next((i for i, c in enumerate(raa_calls) if LATCH_MUTATION in c), -1)
        check("mark-ready STRICTLY precedes the arm (ready->arm ordering pinned)",
              0 <= merge_i and ready_i < merge_i, True)
        check("arm backoff ceilings cover the observed 1-14s registration tail with margin",
              (tuple(_arm_backoff_ceiling(a) for a in range(1, ARM_ATTEMPTS)),
               _arm_backoff_ceiling(99)),
              (ARM_BACKOFF_CEILINGS, ARM_BACKOFF_CEILINGS[-1]))
        # (sol r4 on #334) deterministic MINIMUM cumulative schedule: the floors sum to
        # >= 20s across the 5 sleeps before the FINAL attempt, covering the evidenced 14s
        # registration tail with NO reliance on jitter draws (the old 1s uniform lower
        # bound admitted a ~5s cumulative total).
        check("arm backoff floors are a >=20s cumulative minimum before the final attempt",
              (tuple(_arm_backoff_floor(a) for a in range(1, ARM_ATTEMPTS)),
               sum(_arm_backoff_floor(a) for a in range(1, ARM_ATTEMPTS)) >= 20.0,
               _arm_backoff_floor(99)),
              (ARM_BACKOFF_FLOORS, True, ARM_BACKOFF_FLOORS[-1]))
        check("every arm backoff sleep has a floor admitted by its ceiling (5 sleeps)",
              (len(ARM_BACKOFF_FLOORS), len(ARM_BACKOFF_CEILINGS),
               all(f <= c for f, c in zip(ARM_BACKOFF_FLOORS, ARM_BACKOFF_CEILINGS))),
              (ARM_ATTEMPTS - 1, ARM_ATTEMPTS - 1, True))
        # The REAL sleep respects the floors under ADVERSARIAL jitter: pin random.uniform
        # to its lower bound (worst draw) and sum what time.sleep is actually asked for —
        # no mocked-jitter luck. Dropping the max(floor, ...) makes this red (~0s total).
        slept = []
        real_uniform, real_time_sleep = random.uniform, time.sleep
        try:
            random.uniform = lambda low, high: low
            time.sleep = slept.append
            for a in range(1, ARM_ATTEMPTS):
                real_raa["_arm_sleep_backoff"](a)
        finally:
            random.uniform, time.sleep = real_uniform, real_time_sleep
        check("MINIMUM cumulative delay before the final attempt is >= 20s (floors, not luck)",
              (sum(slept) >= 20.0,
               [s >= f for s, f in zip(slept, ARM_BACKOFF_FLOORS)], len(slept)),
              (True, [True] * (ARM_ATTEMPTS - 1), ARM_ATTEMPTS - 1))
        clean_err = "GraphQL: Pull request is in clean status (enablePullRequestAutoMerge)"
        run_raa(merge_script=[(1, clean_err), (1, clean_err), (0, "")])
        latches = raa_latches()
        check("clean-status refusal RETRIES the latch; it latches once the fresh run registers",
              (len(latches), all(LATCH_MUTATION in c for c in latches),
               all(f"oid={sha}" in c and "pr=PR_kwTESTNODE" in c for c in latches),
               sum(1 for c in raa_calls if c.startswith("sleep:"))),
              (3, True, True, 2))
        check("the retried latch ARMS mode=auto: no draft undo, no needs-user, arm_complete",
              (raa_outputs.get("armed"), raa_outputs.get("arm_complete"),
               raa_outputs.get("arm_mode"),
               any("--undo" in c for c in raa_calls), "needs-user" in raa_calls),
              (True, True, "auto", False, False))
        try:
            run_raa(merge_script=[(1, clean_err)] * (ARM_ATTEMPTS + 1))
            check("clean-status exhaustion restores the draft with ZERO merges",
                  "no error", "raised")
        except WorkerPrError as exc:
            # MUTATION-CHECK anchor (sol r3+r4 on #334): re-adding ANY `gh pr merge` form
            # on the clean-status refusal — a direct merge OR the --auto verb (which
            # direct-merges an already-mergeable PR) — makes a `pr merge` argv appear and
            # drops the mutation count below ARM_ATTEMPTS -> red.
            check("clean-status exhaustion restores the draft with ZERO merges",
                  ("draft restored for the sweep to retry" in str(exc),
                   "clean status" in str(exc),
                   sum(1 for c in raa_calls if LATCH_MUTATION in c),
                   any(c.startswith("pr merge") for c in raa_calls),
                   any("--undo" in c for c in raa_calls), "state:pass" in raa_calls),
                  (True, True, ARM_ATTEMPTS, False, True, False))
        # STRUCTURAL ANCHOR (sol r4 on #334): the arm path's ONLY merge-capable argv is the
        # enablePullRequestAutoMerge mutation — matched by MUTATION NAME, with zero
        # `gh pr merge` invocations of ANY form (no flag-matching: --auto itself is the
        # direct-merge hazard).
        check("the ONLY merge-capable argv is the enablePullRequestAutoMerge mutation",
              (bool(raa_latches()),
               all(LATCH_MUTATION in c and not c.startswith("pr merge")
                   for c in raa_latches()),
               any(c.startswith("pr merge") for c in raa_calls)),
              (True, True, False))
        lag_err = "GraphQL: Draft pull requests cannot be merged (enablePullRequestAutoMerge)"
        run_raa(merge_script=[(1, lag_err), (0, "")])
        latches = raa_latches()
        check("a transient non-clean refusal RETRIES the latch with backoff (never `pr merge`)",
              (len(latches), all(LATCH_MUTATION in c for c in latches),
               any(c.startswith("sleep:") for c in raa_calls),
               raa_outputs.get("armed"), raa_outputs.get("arm_mode")),
              (2, True, True, True, "auto"))
        try:
            run_raa(merge_script=[(1, "boom: base branch was modified")] * (ARM_ATTEMPTS + 1))
            check("persistent arm failure raises with the REAL gh error surfaced",
                  "no error", "raised")
        except WorkerPrError as exc:
            check("persistent arm failure raises with the REAL gh error surfaced",
                  ("draft restored for the sweep to retry" in str(exc),
                   "boom: base branch was modified" in str(exc),
                   sum(1 for c in raa_calls if LATCH_MUTATION in c),
                   any(c.startswith("pr merge") for c in raa_calls),
                   any("--undo" in c for c in raa_calls)),
                  (True, True, ARM_ATTEMPTS, False, True))
        # ---- (sol r2 on #334) HOLD REVALIDATION INSIDE THE ARM RETRY WINDOW: the
        # retry/backoff (~31s worst case) runs AFTER the single pre-arm hold probe, and a
        # park landing during backoff does NOT move the head — the expectedHeadOid CAS
        # cannot refuse it. The live hold probe must re-run before EVERY retry attempt; any
        # hold refuses with the valid-exit human_hold shape and the draft restored (no
        # needs-user, no review-state churn). ----
        run_raa(merge_script=[(1, lag_err)], hold_after_fail=("needs:user",))
        latches = raa_latches()
        check("a hold injected during backoff REFUSES the retry (zero further latch argv)",
              (len(latches), raa_outputs.get("human_hold"), raa_outputs.get("arm_complete"),
               raa_outputs.get("armed"), any("--undo" in c for c in raa_calls),
               "needs-user" in raa_calls, "state:pass" in raa_calls),
              (1, True, False, False, True, False, False))
        run_raa(merge_script=[(1, clean_err)], hold_after_fail=("review:needs-user",))
        latches = raa_latches()
        check("a hold injected during the clean-status backoff REFUSES the retry (no merge)",
              (len(latches), any(c.startswith("pr merge") for c in raa_calls),
               raa_outputs.get("human_hold"), raa_outputs.get("arm_complete"),
               raa_outputs.get("armed"), any("--undo" in c for c in raa_calls),
               "needs-user" in raa_calls, "state:pass" in raa_calls),
              (1, False, True, False, False, True, False, False))
        # ---- [round-4 P1] PARKED-BUT-ARMING RACE: a human/groom park that landed while
        # this review run was in flight WINS — the pre-arm hold recheck aborts with the
        # valid-exit shape and NO ready/arm/audit/review-state mutation at all ----
        for park in ("needs:user", "review:needs-user"):
            run_raa(labels=(park,))
            check(f"parked-mid-review PR label {park} aborts pre-arm (no ready/arm argv)",
                  (any(c.startswith("pr ready") for c in raa_calls) or bool(raa_latches()),
                   any("trust-surface" in c or c.startswith("state:") for c in raa_calls),
                   raa_outputs.get("arm_complete"), raa_outputs.get("human_hold"),
                   raa_outputs.get("armed")),
                  (False, False, False, True, False))
        run_raa(issue_labels=("needs:maintainer",), issue=7)
        check("parked-mid-review SOURCE issue needs:* aborts pre-arm the same way",
              (any(c.startswith("pr ready") for c in raa_calls) or bool(raa_latches()),
               raa_outputs.get("arm_complete"), raa_outputs.get("human_hold")),
              (False, False, True))
        # the --issue arg may be absent: the source issue is derived from the worker head
        run_raa(issue_labels=("needs:user",))
        check("head-ref-derived source hold aborts pre-arm too",
              (bool(raa_latches()), raa_outputs.get("arm_complete")),
              (False, False))
        run_raa(issue_labels=("area:crate-a", "role:impl"))
        check("unparked run is UNCHANGED (the hold recheck admits the ready+arm)",
              (any(c.startswith("pr ready") for c in raa_calls),
               any(LATCH_MUTATION in c and f"oid={sha}" in c for c in raa_calls),
               raa_outputs.get("arm_complete")), (True, True, True))
        try:
            run_raa(probe_garbage=True)
            check("unreadable source-issue hold state fails closed (no arm)",
                  "no error", "raised")
        except WorkerPrError:
            check("unreadable source-issue hold state fails closed (no arm)",
                  ("raised", any(c.startswith("pr ready") for c in raa_calls)
                   or bool(raa_latches())), ("raised", False))
        # ---- [round-5 P2] malformed live LABEL data must never read as "no hold": the old
        # shape-tolerant read collapsed a garbage payload to an empty label set and STILL
        # issued `pr ready` + the arm latch (fail open on the dangerous act). Unknown
        # shapes now refuse with WorkerPrError and no ready/arm argv. ----
        for payload in ("junk", ["junk"], [{"name": 7}], [{"no_name": "x"}]):
            try:
                run_raa(labels_payload=payload)
                check(f"malformed label payload {payload!r} refuses ready/arm",
                      "no error", "raised")
            except WorkerPrError:
                check(f"malformed label payload {payload!r} refuses ready/arm",
                      ("raised", any(c.startswith("pr ready") for c in raa_calls)
                       or bool(raa_latches())), ("raised", False))
        # ---- Issue #153: the arm recomputes the LIVE label-derived security posture (PR +
        # SOURCE issue, routing keywords) so a security label added DURING the review still
        # lands in the SHA-bound audit trail. Per Decision 7 it AUDITS, never withholds. A
        # BENIGN-path diff isolates the LABEL signal from the path signal. ----
        run_raa(benign_diff=True, labels=("trust:review",))
        check("live trust:* PR label on a benign-path diff ARMS with an audit trail (#153)",
              (any(LATCH_MUTATION in c for c in raa_calls),
               any("trust-surface" in c for c in raa_calls),
               raa_outputs.get("armed"), raa_outputs.get("arm_complete")),
              (True, True, True, True))
        check("the label-driven audit comment names the live-security-label hit (#153)",
              any(SECURITY_LABEL_AUDIT_HIT in c for c in raa_calls), True)
        run_raa(benign_diff=True)
        check("benign-path diff with NO security posture ARMS with NO audit (#153 control)",
              (any(LATCH_MUTATION in c for c in raa_calls),
               any("trust-surface" in c for c in raa_calls),
               raa_outputs.get("armed")), (True, False, True))
        run_raa(benign_diff=True, issue_labels=("area:worker",),
                security_keywords=("worker", "dispatch"))
        check("live routing-keyword SOURCE-issue label audits ONLY when the keyword is threaded",
              any("trust-surface" in c for c in raa_calls), True)
        run_raa(benign_diff=True, issue_labels=("area:worker",))
        check("the same routing-keyword label does NOT audit without the keyword (#153 control)",
              any("trust-surface" in c for c in raa_calls), False)
        # live_security_flagged unit facets: PR + source-issue union, keyword threading, and the
        # fail-closed refusal on an unreadable source-issue label payload.
        real_lsf_gh = globals()["_gh_json"]
        try:
            def lsf(labels=(), issue_labels=(), keywords=(), issue=7):
                globals()["_gh_json"] = lambda a, **k: (
                    {"labels": [{"name": n} for n in issue_labels]}
                    if "/issues/" in (a[1] if len(a) > 1 else "") else {})
                live = {"labels": [{"name": n} for n in labels],
                        "head": {"ref": "sparq-agent/issue-7-1-1"}}
                return live_security_flagged("o/r", 41, keywords, issue=issue, live=live)
            check("live trust:* PR label flags", lsf(labels=("trust:review",)), True)
            check("live builtin-keyword PR label flags without routing keywords",
                  lsf(labels=("area:sparq-zk",)), True)
            check("live routing-keyword label flags ONLY when the keyword is threaded",
                  (lsf(labels=("area:worker",)),
                   lsf(labels=("area:worker",), keywords=("worker",))), (False, True))
            check("live SOURCE-issue security label flags at arm time",
                  lsf(issue_labels=("trust:untrusted",)), True)
            check("a plain live posture is not flagged",
                  lsf(labels=("area:core",), issue_labels=("role:impl",)), False)
            try:
                globals()["_gh_json"] = lambda a, **k: (
                    "garbage" if "/issues/" in (a[1] if len(a) > 1 else "") else {})
                live_security_flagged(
                    "o/r", 41, (), issue=7,
                    live={"labels": [], "head": {"ref": "sparq-agent/issue-7-1-1"}})
                check("unreadable live security posture fails closed", "no error", "raised")
            except WorkerPrError:
                check("unreadable live security posture fails closed", "raised", "raised")
        finally:
            globals()["_gh_json"] = real_lsf_gh
    finally:
        globals().update(real_raa)

    # ---- [round-5 P1] HOLD WINS on EVERY outcome mutation: a human/groom park that lands
    # AFTER the review/fix resolved DROPS the outcome — zero comment/label/state mutations
    # on every outcome path (changes / approve->arm / needs-user park, re-review), not just
    # the round-4 ready_and_arm recheck. ----
    oc_calls = []
    oc_outputs = {}
    oc_state = {}
    real_oc = {name: globals()[name] for name in (
        "_gh_json", "_paginated_comments", "set_review_state", "needs_user",
        "post_findings", "record_model_pin", "_write_outputs", "_alert_route")}

    def oc_gh_json(args, **_kw):
        path = args[1] if len(args) > 1 else ""
        if "/issues/" in path:
            return {"labels": [{"name": name} for name in oc_state.get("issue_labels", ())]}
        return {"state": "open",
                "labels": [{"name": name} for name in oc_state.get("labels", ())],
                "head": {"ref": "sparq-agent/issue-7-1-1", "sha": "b" * 40}}

    def run_review_outcome(verdict, labels=(), issue_labels=(), injection=False):
        oc_calls.clear(); oc_outputs.clear()
        oc_state.update(labels=labels, issue_labels=issue_labels)
        with tempfile.TemporaryDirectory() as tmp:
            verdict_file = Path(tmp) / "verdict.json"
            files_file = Path(tmp) / "files.txt"
            issues = ([{"severity": "major", "file": "src/a.rs", "title": "t", "body": "b",
                        "fix_hint": "h"}] if verdict == "request_changes" else [])
            verdict_file.write_text(json.dumps({
                "verdict": verdict, "injection_detected": injection, "summary": "s",
                "issues": issues}), encoding="utf-8")
            files_file.write_text("src/a.rs\n", encoding="utf-8")
            review_outcome(argparse.Namespace(
                repo="o/r", pr=41, verdict_file=str(verdict_file),
                files_file=str(files_file), round=1, max_rounds=3, security=False,
                surface_path=[], issue=7, impl_provider="anthropic",
                bot_login="sparq[bot]", run_key="9.1"))

    def run_fix_outcome(labels=(), issue_labels=(), injection="false"):
        oc_calls.clear(); oc_outputs.clear()
        oc_state.update(labels=labels, issue_labels=issue_labels)
        fix_outcome(argparse.Namespace(
            repo="o/r", pr=41, round=1, run_key="9.1", bot_login="sparq[bot]",
            injection=injection, made_changes="true", gate_outcome="success",
            pushed="true", issue=7, model=""))

    try:
        globals()["_gh_json"] = oc_gh_json
        globals()["_paginated_comments"] = lambda repo, pr: []
        globals()["set_review_state"] = lambda repo, pr, s: oc_calls.append(f"state:{s}")
        globals()["needs_user"] = lambda repo, pr, reason, **kw: oc_calls.append("needs-user")
        globals()["post_findings"] = lambda *a, **kw: oc_calls.append("post-findings")
        globals()["record_model_pin"] = lambda *a, **kw: oc_calls.append("model-pin")
        globals()["_alert_route"] = lambda: (None, None)
        globals()["_write_outputs"] = oc_outputs.update

        # hold arrives after resolution: EVERY review outcome path drops with zero mutations
        for verdict, injection, park_name in (
                ("request_changes", False, "changes"),
                ("approve", False, "approve->arm"),
                ("request_changes", True, "injection->needs-user")):
            for hold in ({"labels": ("needs:user",)},
                         {"labels": ("review:needs-user",)},
                         {"issue_labels": ("needs:maintainer",)}):
                run_review_outcome(verdict, injection=injection, **hold)
                check(f"held review outcome ({park_name}, {hold}) drops with no mutation",
                      (oc_calls, oc_outputs.get("decision"), oc_outputs.get("human_hold")),
                      ([], "hold", True))
        # unheld control: the same outcomes still apply
        run_review_outcome("request_changes")
        check("unheld request_changes outcome still applies",
              (oc_calls, oc_outputs.get("decision")),
              (["post-findings", "state:changes"], "changes"))
        run_review_outcome("approve")
        check("unheld approve outcome still routes to the arm step",
              (oc_calls, oc_outputs.get("decision")), (["post-findings"], "arm"))
        run_review_outcome("request_changes", injection=True)
        check("unheld injection outcome still parks needs-user",
              (oc_calls, oc_outputs.get("decision")),
              (["post-findings", "needs-user"], "needs-user"))

        # the fix outcome paths drop the same way (re-review + injection->needs-user)
        for injection, park_name in (("false", "re-review"), ("true", "needs-user")):
            run_fix_outcome(labels=("needs:user",), injection=injection)
            check(f"held fix outcome ({park_name}) drops with no mutation",
                  (oc_calls, oc_outputs.get("decision"), oc_outputs.get("human_hold")),
                  ([], "hold", True))
        run_fix_outcome(issue_labels=("needs:maintainer",))
        check("source-issue hold drops the fix outcome too",
              (oc_calls, oc_outputs.get("decision")), ([], "hold"))
        run_fix_outcome()
        check("unheld fix outcome still applies re-review",
              (oc_calls, oc_outputs.get("decision")), (["state:needs"], "re-review"))
        run_fix_outcome(injection="true")
        check("unheld injection fix outcome still parks needs-user",
              (oc_calls, oc_outputs.get("decision")), (["needs-user"], "needs-user"))
    finally:
        globals().update(real_oc)

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

    # Publisher-independent recovery (issue #128): resolve the PR from the deterministic head branch
    # and record provenance even when the publish job's pr_number output was lost after `gh pr
    # create` mutated GitHub. Head_sha/pr_number come from the live API, never a worker output.
    recon = subparsers.add_parser("reconcile-provenance")
    recon.add_argument("--registry-repo", required=True)
    recon.add_argument("--target-repo", required=True)
    recon.add_argument("--head-branch", required=True)
    recon.add_argument("--impl-provider", required=True)
    recon.add_argument("--impl-alias", required=True)
    recon.add_argument("--impl-account-h", default="",
                       help="pre-computed salted hash; default hashes env WORKER_IMPL_ACCOUNT "
                            "with env PROVENANCE_SALT")
    recon.add_argument("--issue", required=True, type=int)
    recon.add_argument("--run-key", required=True)
    recon.add_argument("--verify-bot-login", required=True)

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
    arm.add_argument("--bot-login", default="",
                     help="the App bot login (exact audit-marker suppression identity)")
    arm.add_argument("--reviewed-base", default="",
                     help="the base ref the review compared against (arm re-validates it)")
    # Issue #153: the target routing's own security match_labels keywords (repeatable; resolve
    # unions the builtin set with the routing's). The arm re-reads LIVE PR + source-issue labels
    # against these so a security label added DURING review still lands in the audit trail.
    arm.add_argument("--security-keyword", action="append", default=[],
                     help="security label keyword (repeatable; from the target routing match_labels)")

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
        elif args.command == "reconcile-provenance":
            impl_account_h = args.impl_account_h or account_hash(
                os.environ.get("WORKER_IMPL_ACCOUNT", ""),
                os.environ.get("PROVENANCE_SALT", ""))
            reconcile_provenance(args.registry_repo, args.target_repo, args.head_branch,
                                 args.impl_provider, args.impl_alias, impl_account_h,
                                 args.issue, args.run_key, args.verify_bot_login)
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
                          surface_paths=args.surface_path or None,
                          bot_login=args.bot_login, reviewed_base=args.reviewed_base,
                          security_keywords=args.security_keyword or None)
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
