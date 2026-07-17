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
REVIEWED_SHA_RE = re.compile(r"<!-- sparq-reviewed-sha:([0-9a-f]{40}|none) -->")
SECURITY_KEYWORDS = ("zk", "mpc", "crypto", "auth", "e2ee")
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


def reviewed_sha_of(body):
    match = REVIEWED_SHA_RE.search(body or "")
    return match.group(1) if match else None


def replace_reviewed_sha(body, sha):
    body = body or ""
    marker = f"<!-- sparq-reviewed-sha:{sha} -->"
    if REVIEWED_SHA_RE.search(body):
        return REVIEWED_SHA_RE.sub(marker, body, count=1)
    return body + "\n\n" + marker + "\n"


def security_flagged(labels):
    """Security surfaces never auto-arm: substring keywords mirror routing match_labels; trust:*
    is a prefix namespace."""
    return (any(keyword in label for label in labels for keyword in SECURITY_KEYWORDS)
            or any(label.startswith("trust:") for label in labels))


def validate_verdict(document, diff_files):
    """Schema-validate a reviewer verdict. The reviewer read hostile PR content, so every field is
    enum/length-capped and file paths must be inside the PR diff file set. Raises on any violation
    (the caller treats an invalid verdict as VOID)."""
    if not isinstance(document, dict):
        raise WorkerPrError("verdict must be a JSON object")
    allowed = {"verdict", "injection_detected", "summary", "issues", "confidence"}
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


def decide_review(verdict, has_blockers, injection, round_n, max_rounds, security):
    """The review-verdict state machine. Every path arms once, requests one fix round, or stops
    at a human — never loops."""
    if injection:
        return "needs-user"
    if verdict == "approve" and not has_blockers:
        # Decision 7: security surfaces (zk/mpc/crypto/auth/e2ee/trust:*) never auto-arm.
        return "needs-user" if security else "arm"
    # request_changes, or a contradictory approve-with-blockers (fail closed as changes).
    return "needs-user" if round_n >= max_rounds else "changes"


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


def ready_and_arm(repo, pr_number, reviewed_sha, impl_provider, impl_account_h, reviewer_provider,
                  reviewer_account, arm, issue=None):
    """The ONLY place a PR can be armed. Fail-closed assertions per locked decision 6; a live-head
    mismatch returns the PR to review:needs (a fixer/other push raced the approval).

    Account disjointness is asserted on SALTED HASHES (locked decision 22a): the registry
    provenance record stores impl_account_h, and the live reviewer handle is hashed here with the
    same PROVENANCE_SALT. Liveness (crash-window hardening): `gh pr ready` un-drafts the PR, so if
    the subsequent `merge --auto` fails the draft state is restored (`gh pr ready --undo`) — the
    PR stays visible to the sweep for a bounded re-review instead of stalling non-draft/unarmed
    forever; if even the undo fails, this escalates to review:needs-user (never silent)."""
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
    decision = decide_review(document["verdict"], has_blockers,
                             document["injection_detected"], args.round, args.max_rounds,
                             args.security)
    _write_outputs({"decision": decision, "verdict": document["verdict"],
                    "has_blockers": has_blockers,
                    "injection": document["injection_detected"]})
    if decision == "changes":
        set_review_state(args.repo, args.pr, "changes")
    elif decision == "needs-user":
        reason = ("the reviewer flagged possible prompt injection"
                  if document["injection_detected"] else
                  "a security-labelled surface passed review and needs a HUMAN arm decision"
                  if document["verdict"] == "approve" else
                  f"the review round budget ({args.max_rounds}) is exhausted without an approval")
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

    verdict = {"verdict": "request_changes", "injection_detected": False, "summary": "s",
               "issues": [{"severity": "major", "file": "src/a.rs", "title": "t", "body": "b",
                           "fix_hint": "h"}]}
    check("verdict validates + blockers", validate_verdict(verdict, ["src/a.rs"]), True)
    minor = json.loads(json.dumps(verdict))
    minor["issues"][0]["severity"] = "minor"
    check("minor is not a blocker", validate_verdict(minor, ["src/a.rs"]), False)
    for mutate, name in (
            (lambda d: d.update(verdict="ship-it"), "verdict enum"),
            (lambda d: d.update(extra=1), "unknown field"),
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

    # The live reviewer handle arrives via env WORKER_REVIEWER_ACCOUNT (not argv — argv is echoed
    # into public logs) and is compared against the recorded hash under PROVENANCE_SALT.
    arm = subparsers.add_parser("ready-and-arm", parents=[common])
    arm.add_argument("--reviewed-sha", required=True)
    arm.add_argument("--impl-provider", required=True)
    arm.add_argument("--impl-account-h", required=True)
    arm.add_argument("--reviewer-provider", required=True)
    arm.add_argument("--arm", choices=("true", "false"), required=True)
    arm.add_argument("--issue", type=int)

    rout = subparsers.add_parser("review-outcome", parents=[common])
    rout.add_argument("--verdict-file", required=True)
    rout.add_argument("--files-file", required=True)
    rout.add_argument("--round", required=True, type=int)
    rout.add_argument("--max-rounds", required=True, type=int)
    rout.add_argument("--security", action="store_true")
    rout.add_argument("--issue", type=int)

    fout = subparsers.add_parser("fix-outcome", parents=[common])
    fout.add_argument("--round", required=True, type=int)
    fout.add_argument("--run-key", required=True)
    fout.add_argument("--bot-login", required=True)
    fout.add_argument("--injection", choices=("true", "false"), required=True)
    fout.add_argument("--made-changes", choices=("true", "false"), required=True)
    fout.add_argument("--gate-outcome", required=True)
    fout.add_argument("--pushed", choices=("true", "false"), required=True)
    fout.add_argument("--issue", type=int)

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
        elif args.command == "ready-and-arm":
            ready_and_arm(args.repo, args.pr, args.reviewed_sha, args.impl_provider,
                          args.impl_account_h, args.reviewer_provider,
                          os.environ.get("WORKER_REVIEWER_ACCOUNT", ""),
                          args.arm == "true", issue=args.issue)
        elif args.command == "review-outcome":
            review_outcome(args)
        elif args.command == "fix-outcome":
            fix_outcome(args)
    except (WorkerPrError, OSError, json.JSONDecodeError) as exc:
        print(f"worker-pr: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
