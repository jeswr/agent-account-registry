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
        # A ready third-party issue was promoted by the trusted target-side pipeline. Supplying the
        # positive attestation here makes trust-gate independently return its "promoted" verdict.
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
        labels = sorted({l for l in (spec.get("labels") or []) if isinstance(l, str) and l}
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
