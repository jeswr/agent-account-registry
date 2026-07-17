#!/usr/bin/env python3
# [GPT-5.6] REG-3 target-issue control plane: revision-bound trust revalidation, durable attempt
# accounting, and fail-closed status transitions. It never reads registry account credentials.
"""Small GitHub API helper for the live private-registry worker."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ATTEMPT_MARKER = "<!-- sparq-worker-attempt:v1"
# Maintainer-approval convention (issue #31): a HUMAN maintainer approves a retry by commenting
# the word "approved" on the issue AFTER the worker's most recent attempt receipt. The trusted
# human set is derived the same way the triage trust-gate derives it — repo collaborator
# permission in {admin, maintain, write} — and bot/App logins NEVER count.
APPROVAL_RE = re.compile(r"\bapproved\b", re.IGNORECASE)
HUMAN_MAINTAINER_PERMISSIONS = {"admin", "maintain", "write"}
BUSY_OR_GATED = {
    "status:blocked",
    "status:deferred",
    "status:in-progress",
    "status:in-progress-review",
    "status:untriaged",
    "trust:untrusted",
}
LABEL_COLOURS = {
    "status:in-progress": "fbca04",
    "status:in-progress-review": "c5def5",
    "status:deferred": "d4c5f9",
    "status:ready": "0e8a16",
    "needs:user": "b60205",
}


class WorkerIssueError(RuntimeError):
    """A concise, credential-free operational error."""


def body_sha(body):
    return hashlib.sha256((body or "").encode("utf-8")).hexdigest()


def count_attempts(comments, bot_login):
    bot = bot_login.casefold()
    return sum(
        1
        for comment in comments
        if str(comment.get("user", {}).get("login", "")).casefold() == bot
        and ATTEMPT_MARKER in str(comment.get("body", ""))
    )


def find_maintainer_approval(comments, bot_login, is_human_maintainer):
    """Return the approving comment, or None when the retry must fail closed.

    Evidence of maintainer approval (issue #31) is a comment by a HUMAN maintainer whose body
    matches APPROVAL_RE, created strictly after the bot's most recent attempt receipt (the
    failure being retried). `status:ready` is written by the automation itself (triage/groom/
    the deferred-retry transition below) and is therefore NEVER approval evidence. Bot and App
    logins never count as human, whatever they comment. `is_human_maintainer(login)` supplies
    the trusted-set probe so this stays pure and self-testable.
    """
    bot = bot_login.casefold()
    last_failure = max(
        (str(comment.get("created_at", ""))
         for comment in comments
         if str(comment.get("user", {}).get("login", "")).casefold() == bot
         and ATTEMPT_MARKER in str(comment.get("body", ""))),
        default="",
    )
    for comment in comments:
        user = comment.get("user", {}) or {}
        login = str(user.get("login", ""))
        if (not login
                or str(user.get("type", "")).casefold() == "bot"
                or login.casefold().endswith("[bot]")
                or login.casefold() == bot):
            continue
        if not APPROVAL_RE.search(str(comment.get("body", ""))):
            continue
        # ISO-8601 UTC timestamps compare lexicographically; an approval at-or-before the last
        # attempt receipt is stale — it blessed a run that has since failed.
        if str(comment.get("created_at", "")) <= last_failure:
            continue
        if is_human_maintainer(login):
            return comment
    return None


def _is_human_maintainer(repo, login):
    # Same derivation as the triage-issue trust-gate: collaborator permission probe. The
    # trust-gate's extra exact-match entry is the registry App bot, which is excluded here by
    # design — approval must come from a human. Probe failure counts as "not a maintainer".
    result = _run_gh(
        ["api", f"repos/{repo}/collaborators/{login}/permission", "--jq", ".permission"],
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() in HUMAN_MAINTAINER_PERMISSIONS


def _run_gh(args, *, input_text=None, check=True):
    result = subprocess.run(
        ["gh", *args],
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise WorkerIssueError(f"GitHub API request failed for {args[1] if len(args) > 1 else 'request'}")
    return result


def _gh_json(args, *, input_doc=None):
    raw = _run_gh(args, input_text=json.dumps(input_doc) if input_doc is not None else None).stdout
    try:
        return json.loads(raw or "null")
    except json.JSONDecodeError as exc:
        raise WorkerIssueError("GitHub API returned malformed JSON") from exc


def _paginated(repo, issue, resource):
    pages = _gh_json([
        "api",
        "--paginate",
        "--slurp",
        f"repos/{repo}/issues/{issue}/{resource}?per_page=100",
    ])
    if not isinstance(pages, list):
        raise WorkerIssueError(f"GitHub API returned malformed {resource}")
    return [item for page in pages if isinstance(page, list) for item in page]


def _write_outputs(values):
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as output:
        for key, value in values.items():
            text = str(value).lower() if isinstance(value, bool) else str(value)
            if "\n" in text or "\r" in text:
                raise WorkerIssueError(f"unsafe multiline output {key}")
            output.write(f"{key}={text}\n")


def attempt_check(repo, issue, max_attempts, bot_login):
    comments = _paginated(repo, issue, "comments")
    used = count_attempts(comments, bot_login)
    values = {"used": used, "exhausted": used >= max_attempts}
    _write_outputs(values)
    print(f"worker attempts used: {used}/{max_attempts}")


def record_attempt(repo, issue, max_attempts, bot_login, run_key):
    comments = _paginated(repo, issue, "comments")
    used = count_attempts(comments, bot_login)
    exact_marker = f"{ATTEMPT_MARKER} run={run_key} -->"
    for comment in comments:
        if (str(comment.get("user", {}).get("login", "")).casefold() == bot_login.casefold()
                and exact_marker in str(comment.get("body", ""))):
            number = min(used, max_attempts)
            _write_outputs({"number": number})
            print(f"worker attempt already recorded: {number}/{max_attempts}")
            return
    if used >= max_attempts:
        raise WorkerIssueError("attempt budget was exhausted before model launch")
    number = used + 1
    body = (
        f"> 🤖 SPARQ agent — starting live worker attempt {number}/{max_attempts}.\n\n"
        f"{exact_marker}"
    )
    _gh_json(
        ["api", "-X", "POST", f"repos/{repo}/issues/{issue}/comments", "--input", "-"],
        input_doc={"body": body},
    )
    _write_outputs({"number": number})
    print(f"worker attempt recorded: {number}/{max_attempts}")


def reverify(repo, issue, expected_author, expected_body_sha, trust_gate, bot_login, issue_file):
    item = _gh_json(["api", f"repos/{repo}/issues/{issue}"])
    if not isinstance(item, dict) or "pull_request" in item:
        raise WorkerIssueError("target number is not an issue")
    if str(item.get("state", "")).lower() != "open":
        raise WorkerIssueError("target issue is no longer open")
    author = str(item.get("user", {}).get("login", ""))
    if author != expected_author:
        raise WorkerIssueError("target issue author changed since policy resolution")
    if body_sha(item.get("body")) != expected_body_sha:
        raise WorkerIssueError("target issue body changed since policy resolution")
    labels = {
        label.get("name")
        for label in item.get("labels", [])
        if isinstance(label, dict) and isinstance(label.get("name"), str)
    }
    if "status:ready" not in labels:
        raise WorkerIssueError("target issue lost its positive status:ready attestation")
    blockers = sorted(label for label in labels if label in BUSY_OR_GATED or label.startswith("needs:"))
    if blockers:
        raise WorkerIssueError(f"target issue became gated or busy: {', '.join(blockers)}")

    command = [
        sys.executable,
        trust_gate,
        "--author",
        author,
        "--repo",
        repo,
        "--fetch",
        "--bot",
        bot_login,
    ]
    verdict = subprocess.run(command, capture_output=True, text=True, check=False)
    if verdict.returncode == 3:
        # A third-party issue may re-enter the run path only on explicit HUMAN evidence. The
        # status:ready label checked above is NOT that evidence — the automation writes it
        # itself, so honouring it here would let the worker self-approve its own retry.
        approval = find_maintainer_approval(
            _paginated(repo, issue, "comments"),
            bot_login,
            lambda login: _is_human_maintainer(repo, login),
        )
        if approval is None:
            raise WorkerIssueError(
                "third-party issue has no fresh maintainer approval — a human maintainer must "
                "comment 'approved' after the last worker attempt; deferring instead of retrying"
            )
        verdict = subprocess.run(
            [*command, "--maintainer-approved"], capture_output=True, text=True, check=False
        )
    if verdict.returncode != 0 or verdict.stdout.strip() not in {"trusted", "promoted"}:
        raise WorkerIssueError("target issue failed the last-step trust gate")

    destination = Path(issue_file)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(item), encoding="utf-8")
    destination.chmod(0o600)
    print(f"trust reverified: {verdict.stdout.strip()}")


def _ensure_label(repo, label):
    get_result = _run_gh(["api", f"repos/{repo}/labels/{label}"], check=False)
    if get_result.returncode == 0:
        return
    _gh_json(
        ["api", "-X", "POST", f"repos/{repo}/labels", "--input", "-"],
        input_doc={
            "name": label,
            "color": LABEL_COLOURS[label],
            "description": "Private-registry worker orchestration state",
        },
    )


def _remove_label(repo, issue, label):
    result = _run_gh(
        ["api", "-X", "DELETE", f"repos/{repo}/issues/{issue}/labels/{label}"], check=False
    )
    if result.returncode != 0 and "HTTP 404" not in result.stderr:
        raise WorkerIssueError(f"GitHub API could not remove issue label {label}")


def set_status(repo, issue, status):
    # `in-progress-review`: the worker published a DRAFT PR that is cycling through the
    # cross-provider review loop — the issue completes only when the review-fix ARM path fires.
    # `retry`: the dispatcher re-enumerates a deferred issue (deferred-retry, locked decision 20)
    # — status:deferred is stripped and status:ready restored so the worker's reverify passes.
    # NOTE (issue #31): status:ready written here is dispatchability only, never maintainer
    # approval — the reverify third-party path demands separate human evidence.
    transitions = {
        "in-progress": ({"status:in-progress"}, {"status:ready", "status:deferred"}),
        "in-progress-review": ({"status:in-progress-review"},
                               {"status:ready", "status:in-progress", "status:deferred"}),
        "retry": ({"status:ready"}, {"status:deferred"}),
        "deferred": ({"status:deferred"},
                     {"status:ready", "status:in-progress", "status:in-progress-review"}),
        "needs-user": ({"needs:user", "status:deferred"},
                       {"status:ready", "status:in-progress", "status:in-progress-review"}),
        "complete": (set(), {"status:in-progress", "status:in-progress-review", "status:deferred"}),
    }
    add, remove = transitions[status]
    for label in sorted(add):
        _ensure_label(repo, label)
    if add:
        _gh_json(
            ["api", "-X", "POST", f"repos/{repo}/issues/{issue}/labels", "--input", "-"],
            input_doc={"labels": sorted(add)},
        )
    for label in sorted(remove - add):
        _remove_label(repo, issue, label)
    print(f"target issue state: {status}")


def claim_receipt(repo, issue, model, run_url):
    """Post a visible 'the orchestrator is actively working this' receipt. A GitHub App bot user CANNOT
    be an issue assignee, so this receipt + the `status:in-progress` label ARE the assignment: they show
    WHO is working the issue, on WHAT model, and link the LIVE run — filterable via the label."""
    body = (
        "> 🤖 **SPARQ orchestrator** has claimed this issue and is actively working it.\n\n"
        f"- Model: `{model}`\n"
        f"- Live worker run: {run_url}\n\n"
        "Active autonomous work is filterable with `is:issue label:status:in-progress`. A pull request "
        "will link back here when it opens. (A GitHub App cannot be a literal assignee — this receipt + "
        "the `status:in-progress` label are the equivalent.)"
    )
    _gh_json(
        ["api", "-X", "POST", f"repos/{repo}/issues/{issue}/comments", "--input", "-"],
        input_doc={"body": body},
    )
    print("claim receipt posted")


def create_followups(repo, source_issue, spec_file):
    """Create de-duplicated follow-up issues from a JSONL file the model wrote (one {title, body, labels}
    per line) while implementing `source_issue`. Each is linked back + labelled from:agent +
    self-improvement so the issue-sweeper actions them. Best-effort: NEVER raises (a follow-up failure
    must not fail the worker). This is the procedure for the orchestrator to capture discovered work."""
    path = Path(spec_file)
    if not path.exists():
        print("no follow-ups declared")
        return
    existing = {str(i.get("title", "")) for i in (_gh_json(
        ["issue", "list", "-R", repo, "--state", "open", "--limit", "300", "--json", "title"]) or [])}
    created = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            spec = json.loads(line)
        except json.JSONDecodeError:
            continue
        title = " ".join(str(spec.get("title", "")).split())[:200]
        if not title or title in existing:
            continue
        body = str(spec.get("body", "")).strip()
        body += (f"\n\n> 🤖 Discovered by the SPARQ worker while implementing #{source_issue}. "
                 "Out-of-scope for that PR; captured as follow-up.\n<!-- sparq-followup:v1 -->")
        labels = sorted({label for label in (spec.get("labels") or [])
                         if isinstance(label, str) and label}
                        | {"from:agent", "self-improvement"})
        args = ["issue", "create", "-R", repo, "--title", title, "--body", body]
        for label in labels:
            args += ["--label", label]
        result = _run_gh(args, check=False)
        if result.returncode != 0:            # an unknown label fails the create → retry label-free
            result = _run_gh(["issue", "create", "-R", repo, "--title", title, "--body", body], check=False)
        if result.returncode == 0:
            created += 1
            existing.add(title)
    print(f"follow-up issues created: {created}")


def _self_test():
    fake = [
        {"user": {"login": "sparq[bot]"}, "body": f"x {ATTEMPT_MARKER} run=1 -->"},
        {"user": {"login": "SPARQ[bot]"}, "body": f"x {ATTEMPT_MARKER} run=2 -->"},
        {"user": {"login": "someone"}, "body": ATTEMPT_MARKER},
    ]
    assert count_attempts(fake, "sparq[bot]") == 2
    assert body_sha("task") == hashlib.sha256(b"task").hexdigest()
    assert set(LABEL_COLOURS) == {"status:in-progress", "status:in-progress-review",
                                  "status:deferred", "status:ready", "needs:user"}
    assert "status:in-progress-review" in BUSY_OR_GATED

    # Maintainer-approval evidence for the reverify third-party retry (issue #31).
    maintainers = lambda login: login == "jeswr"  # noqa: E731 — trivial trusted-set stub
    failure = {"user": {"login": "sparq[bot]", "type": "Bot"},
               "body": f"x {ATTEMPT_MARKER} run=9 -->", "created_at": "2026-07-10T00:00:00Z"}
    human_after = {"user": {"login": "jeswr", "type": "User"},
                   "body": "Reviewed the re-attested body — approved.",
                   "created_at": "2026-07-11T00:00:00Z"}
    bot_marker = {"user": {"login": "sparq[bot]", "type": "Bot"},
                  "body": "approved", "created_at": "2026-07-12T00:00:00Z"}
    stale_human = {"user": {"login": "jeswr", "type": "User"},
                   "body": "approved", "created_at": "2026-07-09T00:00:00Z"}
    # (i) the regression this issue demands stays dead: a status:ready issue with NO human
    # comment (only the bot's own attempt receipt) is NOT approved.
    assert find_maintainer_approval([failure], "sparq[bot]", maintainers) is None
    # (ii) a human maintainer's marker comment after the last failure IS approval.
    assert find_maintainer_approval([failure, human_after], "sparq[bot]", maintainers) is human_after
    # (iii) a bot comment carrying the marker is NOT approval.
    assert find_maintainer_approval([failure, bot_marker], "sparq[bot]", maintainers) is None
    # (iv) a marker predating the last failure is stale, NOT approval.
    assert find_maintainer_approval([failure, stale_human], "sparq[bot]", maintainers) is None
    # A human without maintainer permission never approves; App-typed users never count even
    # without a [bot] suffix.
    outsider = {**human_after, "user": {"login": "drive-by", "type": "User"}}
    app_user = {**human_after, "user": {"login": "some-app", "type": "Bot"}}
    assert find_maintainer_approval([failure, outsider], "sparq[bot]", maintainers) is None
    assert find_maintainer_approval([failure, app_user], "sparq[bot]", maintainers) is None
    # With no prior attempt receipt there is nothing to be stale against: approval stands.
    assert find_maintainer_approval([human_after], "sparq[bot]", maintainers) is human_after
    print("worker-issue self-test PASSED")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo", required=True)
    common.add_argument("--issue", required=True, type=int)

    budget = subparsers.add_parser("attempt-check", parents=[common])
    budget.add_argument("--max-attempts", required=True, type=int)
    budget.add_argument("--bot-login", required=True)

    record = subparsers.add_parser("record-attempt", parents=[common])
    record.add_argument("--max-attempts", required=True, type=int)
    record.add_argument("--bot-login", required=True)
    record.add_argument("--run-key", required=True)

    trust = subparsers.add_parser("reverify", parents=[common])
    trust.add_argument("--expected-author", required=True)
    trust.add_argument("--expected-body-sha", required=True)
    trust.add_argument("--trust-gate", required=True)
    trust.add_argument("--bot-login", required=True)
    trust.add_argument("--issue-file", required=True)

    status = subparsers.add_parser("status", parents=[common])
    status.add_argument("--status", choices=("in-progress", "in-progress-review", "retry",
                                             "deferred", "needs-user", "complete"),
                        required=True)

    receipt = subparsers.add_parser("claim-receipt", parents=[common])
    receipt.add_argument("--model", required=True)
    receipt.add_argument("--run-url", required=True)

    followup = subparsers.add_parser("followup", parents=[common])
    followup.add_argument("--spec-file", required=True, help="JSONL of {title, body, labels} the model wrote")

    subparsers.add_parser("self-test")
    # --self-test flag alias: every OTHER registry suite script exposes the flag form, and the
    # pr-gate `gate` check + worker-live.sh registry-selftest gate invoke suites uniformly with
    # --self-test; without this alias the required gate fails red on every registry PR.
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        sys.argv[1] = "self-test"
    args = parser.parse_args()

    try:
        if args.command == "attempt-check":
            attempt_check(args.repo, args.issue, args.max_attempts, args.bot_login)
        elif args.command == "record-attempt":
            record_attempt(args.repo, args.issue, args.max_attempts, args.bot_login, args.run_key)
        elif args.command == "reverify":
            reverify(args.repo, args.issue, args.expected_author, args.expected_body_sha,
                     args.trust_gate, args.bot_login, args.issue_file)
        elif args.command == "status":
            set_status(args.repo, args.issue, args.status)
        elif args.command == "claim-receipt":
            claim_receipt(args.repo, args.issue, args.model, args.run_url)
        elif args.command == "followup":
            create_followups(args.repo, args.issue, args.spec_file)
        else:
            _self_test()
    except WorkerIssueError as exc:
        print(f"worker-issue: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
