#!/usr/bin/env python3
# [GPT-5.6] REG-4 privileged dispatcher half. Target code never executes in this process: the
# unprivileged PLAN artifact is treated as hostile data, revalidated against registry policy and
# protected target routing, then fed to the CAS allocator before a workflow_dispatch is emitted.
"""Validate an unprivileged dispatch plan, claim leases, and launch live workers fail-closed."""

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
import time
import tomllib


# v2 adds top-level `review_items` (the cross-provider review/fix loop) and a per-item `deferred`
# flag (the deferred-retry path). Both validators — this one and the dispatch.yml PLAN inline
# check — are bumped in the same commit; the TARGET repo's dispatch-plan.py is untouched.
SCHEMA = "registry-dispatch-plan/v2"
PLAN_FIELDS = {"schema", "generated_at", "repositories", "review_items"}
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
}
REVIEW_STATES = {"needs-review", "needs-fix"}
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
        if item["state"] not in REVIEW_STATES:
            raise DispatchError(f"{where} state is invalid")
        if item["impl_provider"] not in IMPL_PROVIDERS:
            raise DispatchError(f"{where} impl_provider is invalid")
        repo = _safe_string(item["repo"], SAFE_REPO, f"{where} repo")
        if repo not in seen_repositories:
            raise DispatchError(f"{where} repo is not a planned repository")
        _safe_string(item["package"], SAFE_PACKAGE, f"{where} package")
        if not isinstance(item["security"], bool):
            raise DispatchError(f"{where} security must be boolean")
        review_key = (repo, number)
        if review_key in seen_reviews:
            raise DispatchError(f"plan repeats review item {repo}#{number}")
        seen_reviews.add(review_key)
        if prior_review is not None and review_key < prior_review:
            raise DispatchError("plan review items are not in deterministic order")
        prior_review = review_key
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


def enumerate_review_items(repo, pulls, provenance, leases, issue_labels, now, bot_login=""):
    """PURE review_items enumerator (called by the dispatch.yml PLAN step against its own data;
    unit-tested by --self-test). Fail-closed trust posture (locked decisions 1/3/11/13/19):
    - only open DRAFT PRs whose head branch matches the worker pattern,
    - head.repo MUST be the target repo (a fork PR with a spoofed head ref is never enumerated),
    - the author must be a [bot] (and the App bot when `bot_login` is known),
    - a REGISTRY provenance record must exist for the PR (the root of trust — the target model
      cannot write the registry), carrying a valid impl provider,
    - LABEL-terminal states (review:needs-user / review:pass) never re-enter. Round-budget
      exhaustion is deliberately NOT excluded here: CLAIM re-derives the live round count and
      applies the terminal needs-user transition itself, so a PR whose final outcome mutation
      crashed (label never landed) converges to a loud human hand-off instead of silently
      stalling under an exhausted budget (liveness over a redundant plan-side filter),
    - a PR with a LIVE review/fix lease is not re-emitted (the reconciler re-emits a
      review:changes PR with NO live fix lease, so a crashed fix converges),
    - a needs-review PR whose head equals its reviewed-sha marker is skipped (no re-review
      without a head advance; the non-empty-diff gate runs at CLAIM time)."""
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
        if pull.get("state") != "open" or pull.get("draft") is not True:
            continue
        if not HEAD_REF_RE.match(ref):
            continue
        if head_repo != repo:
            continue                      # fork head — attacker-controlled, never reviewed
        if not login.endswith("[bot]") or (bot_login and login != bot_login):
            continue
        record = provenance.get(number)
        if not isinstance(record, dict) or record.get("pr_number") != number:
            continue                      # no registry provenance record — fail closed
        impl_provider = record.get("impl_provider")
        if impl_provider not in IMPL_PROVIDERS:
            continue
        labels = sorted({
            label.get("name") if isinstance(label, dict) else label
            for label in (pull.get("labels") or [])
            if isinstance(label, (dict, str))
        } - {None})
        if "review:needs-user" in labels or "review:pass" in labels:
            continue                      # terminal / nothing to do
        if not SAFE_SHA.fullmatch(sha):
            continue
        if "review:changes" in labels:
            state = "needs-fix"
            if f"fix:{repo}#{number}" in live_keys:
                continue                  # a fix run is live; the reconciler re-emits if it dies
        else:
            # review:needs, or a provenance-backfilled pre-migration PR with no review:* label yet.
            state = "needs-review"
            if f"review:{repo}#{number}" in live_keys:
                continue
            reviewed = REVIEWED_SHA_RE.search(pull.get("body") or "")
            if reviewed and reviewed.group(1) == sha:
                continue                  # head has not advanced past the last review
        issue_number = record.get("issue")
        source_labels = issue_labels.get(issue_number, []) if isinstance(issue_number, int) else []
        areas = sorted(label[5:] for label in source_labels if label.startswith("area:"))
        items.append({
            "pr_number": number,
            "head_sha": sha,
            "state": state,
            "impl_provider": impl_provider,
            "repo": repo,
            "package": areas[0] if areas else "__global__",
            "security": _security_flagged(set(labels) | set(source_labels)),
        })
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


def _target_token():
    return os.environ.get("TARGET_GH_TOKEN", "")


def _run_target_helper(script_dir, script, args):
    """Run a registry helper (worker-issue.py / worker-pr.py) against the TARGET repo under the
    target-scoped App token. The ambient GH_TOKEN stays the registry workflow token."""
    token = _target_token()
    if not token:
        raise DispatchError("target-scoped App token is unavailable")
    result = subprocess.run(
        [sys.executable, str(script_dir / script), *args],
        capture_output=True, text=True, check=False,
        env={**os.environ, "GH_TOKEN": token},
    )
    if result.returncode != 0:
        raise DispatchError(f"target helper {script} {args[0] if args else ''} failed")
    return result


def _pr_needs_user(script_dir, repo, pr_number, issue, reason):
    args = ["needs-user", "--repo", repo, "--pr", str(pr_number), "--reason", reason]
    if isinstance(issue, int) and issue > 0:
        args += ["--issue", str(issue)]
    _run_target_helper(script_dir, "worker-pr.py", args)


def _run_gh_target_comment(repo, issue_or_pr, body):
    token = _target_token()
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
                           registry_repo, registry_root, workflow_ref, bot_login, usage, margin):
    """Hostile re-validation + claim + launch for the review/fix loop. Every item failure SKIPS
    that item (per-item resilience, like the issue loop)."""
    launched = 0
    script_dir = Path(__file__).resolve().parent
    max_rounds = int(policy.get("max_review_rounds", 3))
    for item in review_items:
        number = item["pr_number"]
        try:
            if not bot_login:
                print(f"defer review {repo}#{number}: bot login unavailable (no App token)")
                continue
            pull = _gh_json(["api", f"repos/{repo}/pulls/{number}"])
            if not isinstance(pull, dict) or pull.get("state") != "open" \
                    or pull.get("draft") is not True:
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
            if "review:needs-user" in labels:
                print(f"defer review {repo}#{number}: terminal review:needs-user")
                continue
            record_path = Path(registry_root) / worker_pr.provenance_path(repo, number)
            if not record_path.is_file():
                print(f"defer review {repo}#{number}: no registry provenance record (fail closed)")
                continue
            record = json.loads(record_path.read_text(encoding="utf-8"))
            if (record.get("pr_number") != number
                    or record.get("impl_provider") != item["impl_provider"]
                    or record.get("impl_provider") not in IMPL_PROVIDERS):
                print(f"defer review {repo}#{number}: provenance disagrees with the plan")
                continue
            opened_sha = str(record.get("head_sha_at_open", ""))
            if not SAFE_SHA.fullmatch(opened_sha):
                print(f"defer review {repo}#{number}: provenance head sha is malformed")
                continue
            issue_number = record.get("issue") if isinstance(record.get("issue"), int) else None
            if opened_sha != head_sha:
                compare = _gh_json(["api", f"repos/{repo}/compare/{opened_sha}...{head_sha}"])
                if compare.get("status") not in {"identical", "ahead"}:
                    # Rewritten history — the worker-opened commit is no longer an ancestor.
                    _pr_needs_user(script_dir, repo, number, issue_number,
                                   "the PR head no longer descends from the worker-opened commit "
                                   "(history was rewritten); refusing autonomous review")
                    continue
            comments = _pr_comments(repo, number)
            rounds = worker_pr.count_rounds(comments, bot_login)
            if rounds >= max_rounds:
                # Terminal transition applied HERE (not just skipped): if the final review
                # outcome crashed before its needs-user label landed, the PR would otherwise sit
                # under an exhausted budget forever, invisible and silent. Idempotent — once the
                # label lands, PLAN stops enumerating the PR.
                _pr_needs_user(script_dir, repo, number, issue_number,
                               f"the review round budget ({rounds}/{max_rounds}) is exhausted "
                               "without a recorded terminal outcome; a human must decide")
                continue
            impl_provider = record["impl_provider"]
            # Privacy (locked decision 22a): provenance stores ONLY the salted account hash; a
            # record still carrying a raw handle (or nothing) fails closed — re-run the backfill.
            impl_account_h = str(record.get("impl_account_h", ""))
            if not re.fullmatch(r"[0-9a-f]{16}", impl_account_h):
                print(f"defer review {repo}#{number}: provenance lacks a salted account hash "
                      "(re-record it via backfill-provenance.py)")
                continue
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
                verdict_file = Path(registry_root) / worker_pr.verdict_path(repo, number, rounds)
                if not verdict_file.is_file():
                    _run_target_helper(script_dir, "worker-pr.py", [
                        "record-marker", "--repo", repo, "--pr", str(number), "--kind", "missed",
                        "--round", str(rounds), "--run-key",
                        f"{os.environ.get('GITHUB_RUN_ID', 'local')}."
                        f"{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}",
                        "--bot-login", bot_login])
                    print(f"defer review {repo}#{number}: round {rounds} verdict record missing")
                    continue
                mode, role = "fix", "fix"
                chain = _resolvable_chain(FIX_CHAIN[impl_provider], routing)
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
            print(f"defer review {repo}#{number}: lease allocation errored ({exc}); skipped")
            continue
        if claim is None:
            if mode == "fix":
                try:
                    _run_target_helper(script_dir, "worker-pr.py", [
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
        print(f"dispatched {mode} {repo}#{number}: round={round_number}, claim={claim_id[:8]}")
    return launched


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
             registry_root=".", bot_login=""):
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

        for item in repository["items"]:
            number = item["number"]
            if number in linked_open_prs:
                print(f"defer {repo}#{number}: an open worker/closing PR already exists")
                continue
            # [OPUS-4.8] Per-item resilience: a single item's trust/route/policy resolution failure
            # must SKIP that item, not abort the whole dispatch (which would strand the other ready
            # issues and mark the run failed). Global setup errors above still abort as before.
            try:
                current, reason = _current_issue_matches(repo, item)
                if not current:
                    print(f"defer {repo}#{number}: {reason}")
                    continue
                resolved = _route_matches(repo, item, policy_doc, routing, policy_module)
                if item["deferred"]:
                    # Deferred-retry budget (locked decision 20): re-dispatch is bounded by the
                    # SAME durable attempt markers the worker records; exhausted -> needs-user +
                    # a maintainer-visible comment, never another silent attempt.
                    if not bot_login or not _target_token():
                        print(f"defer {repo}#{number}: deferred retry needs the target App token")
                        continue
                    comments = _pr_comments(repo, number)
                    used = worker_issue.count_attempts(comments, bot_login)
                    if used >= resolved["max_attempts"]:
                        _run_target_helper(script_dir, "worker-issue.py", [
                            "status", "--repo", repo, "--issue", str(number),
                            "--status", "needs-user"])
                        _run_gh_target_comment(repo, number,
                                               f"> 🤖 SPARQ agent — deferred-retry budget "
                                               f"exhausted ({used}/{resolved['max_attempts']} "
                                               "attempts). "
                                               f"@{os.environ.get('MAINTAINER_HANDLE', 'jeswr')} "
                                               "this issue needs a human.")
                        print(f"escalated {repo}#{number}: deferred-retry budget exhausted")
                        continue
            except DispatchError as exc:
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
                        _run_target_helper(script_dir, "worker-issue.py", [
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
                        print(f"escalated {repo}#{number}: escalate-tier has no eligible account")
                    except DispatchError as exc:
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
                print(f"defer {repo}#{number}: lease allocation errored ({exc}); skipped")
                continue
            if claim is None:
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
                print(f"defer {repo}#{number}: allocator returned an unsafe/out-of-policy claim; released + skipped")
                continue

            if item["deferred"]:
                # Strip status:deferred + restore status:ready ON DISPATCH so the worker's
                # reverify (which requires status:ready) passes. If the workflow launch below
                # fails, the issue is simply a ready issue again next tick — it converges.
                try:
                    _run_target_helper(script_dir, "worker-issue.py", [
                        "status", "--repo", repo, "--issue", str(number), "--status", "retry"])
                except DispatchError as exc:
                    _release_failed_dispatch(allocator, registry_repo, claim_id)
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
                float(policy.get("usage_safety_margin", 0.10)))
    print(f"dispatcher complete: {dispatched} worker/review/fix run(s) launched")


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
        }],
    }
    assert validate_plan(fixture) is fixture
    assert _issue_is_trusted({"user": {"login": "maintainer"}, "author_association": "MEMBER"})
    assert _issue_is_trusted({"user": {"login": "worker[bot]"}, "author_association": "NONE"})
    assert not _issue_is_trusted({"user": {"login": "external"}, "author_association": "CONTRIBUTOR"})
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
            (lambda d: d["review_items"][0].update(impl_provider="other"), "bad impl provider"),
            (lambda d: d["review_items"][0].update(repo="not/planned"), "unplanned review repo"),
            (lambda d: d["review_items"][0].update(head_sha="zz"), "bad review head sha"),
            (lambda d: d.pop("review_items"), "missing review_items"),
            (lambda d: d.update(schema="registry-dispatch-plan/v1"), "stale schema version"),
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
                        help="registry checkout root (provenance + verdict records)")
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
        )
    except DispatchError as exc:
        print(f"dispatch-claim: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
