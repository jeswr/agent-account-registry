#!/usr/bin/env python3
"""Bounded, non-semantic repair for merge-conflicting fleet pull requests.

The default mode is dry-run: repositories are read and candidate rebases are performed
locally, but GitHub is never mutated.  ``--apply`` enables force-with-lease pushes,
comments, and the terminal ``needs:user`` label.

PR content is untrusted.  This program never imports target code, runs tests, invokes
hooks, or executes a repository command.  A clean rebase receives syntax-only parsing
of changed Python and YAML blobs before the push; semantic validation belongs to CI.
"""

import argparse
import ast
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


API_ROOT = "https://api.github.com"
HARD_EXCLUDE_LABELS = {
    "needs:user",
    "review:needs-user",
    "needs:design",
    "trust-surface",
    "trust:untrusted",
}
DEPENDABOT_LOGIN = "dependabot[bot]"
DEPENDABOT_MARKER = "<!-- conflict-resolver head={head} -->"
ATTEMPT_RE = re.compile(
    r"<!-- conflict-resolver attempt=([1-9][0-9]*) head=([0-9a-f]{40}) -->"
)
ESCALATION_MARKER = "<!-- conflict-resolver escalated -->"
SAFE_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
SAFE_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
SAFE_SHA = re.compile(r"[0-9a-f]{40}")
MAX_API_PAGES = 50
DEFAULT_REBASE_CAP = 5


class ResolverError(RuntimeError):
    """A credential-free operational failure suitable for an Actions log."""


def _load_helper(name, filename):
    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ResolverError(f"cannot load registry helper {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_target_repositories(policy_file, registry_repo):
    """Return enabled policy targets plus the registry itself, in policy order."""
    with open(policy_file, "rb") as handle:
        document = tomllib.load(handle)
    rows = document.get("repos") if isinstance(document, dict) else None
    if not isinstance(rows, dict) or not rows:
        raise ResolverError("repository policy has no target rows")
    targets = []
    for repo, row in rows.items():
        if not isinstance(repo, str) or SAFE_REPO.fullmatch(repo) is None:
            raise ResolverError("repository policy contains an unsafe target name")
        if not isinstance(row, dict) or not isinstance(row.get("enabled"), bool):
            raise ResolverError(f"repository policy enablement is malformed for {repo}")
        if row["enabled"]:
            targets.append(repo)
    if SAFE_REPO.fullmatch(registry_repo or "") is None:
        raise ResolverError("registry repository name is unsafe or missing")
    if registry_repo not in targets:
        targets.append(registry_repo)
    return targets


class GitHubAPI:
    """Small per-owner-token GitHub REST client with bounded retries and pagination."""

    def __init__(self, tokens):
        self.tokens = {owner: token for owner, token in tokens.items() if token}

    def has_token(self, repo):
        return repo.split("/", 1)[0] in self.tokens

    def _token_for_url(self, url):
        parts = urlparse(url).path.strip("/").split("/")
        if len(parts) >= 3 and parts[0] == "repos":
            return self.tokens.get(parts[1], "")
        return next(iter(self.tokens.values()), "")

    def request(self, method, url, body=None):
        if url.startswith("/"):
            url = API_ROOT + url
        token = self._token_for_url(url)
        if not token:
            raise ResolverError(f"no target App token for {urlparse(url).path}")
        payload = None if body is None else json.dumps(body).encode("utf-8")
        for attempt in range(3):
            request = Request(
                url,
                data=payload,
                method=method,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "User-Agent": "registry-conflict-resolver",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            try:
                with urlopen(request, timeout=30) as response:
                    raw = response.read()
                    return json.loads(raw) if raw else {}
            except HTTPError as exc:
                if exc.code in {403, 429, 500, 502, 503, 504} and attempt < 2:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise ResolverError(
                    f"GitHub {method} failed (HTTP {exc.code}) for {urlparse(url).path}"
                ) from exc
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                if attempt < 2:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise ResolverError(
                    f"GitHub {method} failed for {urlparse(url).path}"
                ) from exc
        raise AssertionError("unreachable retry loop")

    def fetch(self, url):
        return self.request("GET", url)

    def paginated(self, path):
        items = []
        for page in range(1, MAX_API_PAGES + 1):
            separator = "&" if "?" in path else "?"
            result = self.request(
                "GET", f"{path}{separator}per_page=100&page={page}"
            )
            if not isinstance(result, list):
                raise ResolverError("GitHub API returned a non-list page")
            items.extend(result)
            if len(result) < 100:
                return items
        raise ResolverError("refusing a GitHub listing at or above 5000 entries")

    def repository(self, repo):
        return self.request("GET", f"/repos/{repo}")

    def pulls(self, repo):
        return self.paginated(f"/repos/{repo}/pulls?state=open")

    def comments(self, repo, number):
        return self.paginated(f"/repos/{repo}/issues/{number}/comments")

    def comment(self, repo, number, body):
        return self.request("POST", f"/repos/{repo}/issues/{number}/comments", {"body": body})

    def add_label(self, repo, number, label):
        return self.request(
            "POST", f"/repos/{repo}/issues/{number}/labels", {"labels": [label]}
        )

    def app_identity(self, bot_slug):
        login = f"{bot_slug}[bot]"
        user = self.request("GET", f"/users/{quote(login, safe='[]')}")
        user_id = str(user.get("id", "")) if isinstance(user, dict) else ""
        if user.get("login") != login or not user_id.isdigit():
            raise ResolverError("target token did not resolve the expected GitHub App bot")
        return login, user_id


def _label_names(pr):
    return {
        value
        for label in pr.get("labels") or []
        for value in [label.get("name") if isinstance(label, dict) else label]
        if isinstance(value, str) and value
    }


def _valid_branch(branch):
    return bool(
        SAFE_BRANCH.fullmatch(branch or "")
        and ".." not in branch
        and "//" not in branch
        and not branch.endswith(("/", ".", ".lock"))
        and "/." not in branch
        and "@{" not in branch
    )


def _comment_bodies(comments):
    return [
        comment.get("body", "")
        for comment in comments
        if isinstance(comment, dict) and isinstance(comment.get("body"), str)
    ]


def _self_authored_comments(comments, bot_login):
    return [
        comment
        for comment in comments
        if isinstance(comment, dict)
        and ((comment.get("user") or {}).get("login") == bot_login)
    ]


def attempt_heads(comments, bot_login):
    """Distinct heads attempted by this App; user-spoofed markers never consume budget."""
    heads = []
    for body in _comment_bodies(_self_authored_comments(comments, bot_login)):
        for match in ATTEMPT_RE.finditer(body):
            if match.group(2) not in heads:
                heads.append(match.group(2))
    return heads


def prior_conflicting_files(comments, bot_login):
    """Recover conflict paths from durable App-authored attempt comments."""
    files = []
    for body in _comment_bodies(_self_authored_comments(comments, bot_login)):
        for line in body.splitlines():
            if not line.startswith("- conflict-file: "):
                continue
            try:
                path = json.loads(line.removeprefix("- conflict-file: "))
            except json.JSONDecodeError:
                continue
            if isinstance(path, str) and path not in files:
                files.append(path)
    return tuple(files)


def owned_by_review_rebase_lane(pr, repo, claim):
    """Conservatively identify worker PRs dispatch owns as needs-rebase/rebase repairs."""
    head = pr.get("head") or {}
    login = str((pr.get("user") or {}).get("login", ""))
    return bool(
        claim.FIX_KIND_OF_STATE.get("needs-rebase") == "rebase"
        and claim.HEAD_REF_RE.match(str(head.get("ref", "")))
        and (head.get("repo") or {}).get("full_name") == repo
        and login.endswith("[bot]")
    )


def validate_syntax_blob(path, content):
    """Parse a changed source blob without importing or executing it."""
    if path.endswith(".py"):
        try:
            ast.parse(content, filename=path)
        except SyntaxError as exc:
            raise ResolverError(f"changed Python does not parse: {path}: {exc}") from exc
    elif path.endswith((".yml", ".yaml")):
        try:
            import yaml
        except ImportError as exc:
            raise ResolverError("PyYAML is required for YAML syntax validation") from exc
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ResolverError(f"changed YAML is not UTF-8: {path}") from exc
        try:
            yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ResolverError(f"changed YAML does not parse: {path}: {exc}") from exc


@dataclass(frozen=True)
class RebaseResult:
    outcome: str
    old_head: str
    new_head: str = ""
    conflicting_files: tuple = ()


class MechanicalRebaser:
    """Fresh-clone rebaser; the only credential-bearing subprocess is the final push."""

    def __init__(self, api, workspace, bot_login, bot_id, apply):
        self.api = api
        self.workspace = Path(workspace)
        self.bot_login = bot_login
        self.bot_id = bot_id
        self.apply = apply

    @staticmethod
    def _safe_git_env():
        env = {
            key: os.environ[key]
            for key in ("PATH", "LANG", "LC_ALL", "TMPDIR")
            if key in os.environ
        }
        env.update({
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_TERMINAL_PROMPT": "0",
        })
        return env

    @staticmethod
    def _git(cwd, args, env, check=True):
        command = [
            "git", "-c", f"core.hooksPath={os.devnull}",
            "-c", "commit.gpgSign=false", *args,
        ]
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if check and result.returncode:
            message = result.stderr.decode("utf-8", "replace").strip().splitlines()
            detail = message[-1] if message else "unknown git failure"
            raise ResolverError(f"git {' '.join(args[:2])} failed: {detail}")
        return result

    def __call__(self, repo, pr, default_branch):
        head = pr.get("head") or {}
        branch = str(head.get("ref", ""))
        old_head = str(head.get("sha", ""))
        if not _valid_branch(branch) or not _valid_branch(default_branch):
            raise ResolverError(f"unsafe branch name on {repo}#{pr.get('number')}")
        if SAFE_SHA.fullmatch(old_head) is None:
            raise ResolverError(f"unsafe head SHA on {repo}#{pr.get('number')}")
        self.workspace.mkdir(parents=True, exist_ok=True)
        env = self._safe_git_env()
        with tempfile.TemporaryDirectory(prefix="conflict-resolver-", dir=self.workspace) as tmp:
            checkout = Path(tmp, "target")
            self._git(
                tmp,
                ["clone", "--quiet", f"https://github.com/{repo}.git", str(checkout)],
                env,
            )
            remote_head = self._git(
                checkout, ["rev-parse", f"refs/remotes/origin/{branch}"], env
            ).stdout.decode().strip()
            if remote_head != old_head:
                raise ResolverError(
                    f"head raced before rebase for {repo}#{pr.get('number')}"
                )
            self._git(
                checkout,
                ["switch", "--create", branch, f"refs/remotes/origin/{branch}"],
                env,
            )
            self._git(checkout, ["config", "user.name", self.bot_login], env)
            self._git(
                checkout,
                ["config", "user.email", f"{self.bot_id}+{self.bot_login}@users.noreply.github.com"],
                env,
            )
            rebase = self._git(
                checkout, ["rebase", f"origin/{default_branch}"], env, check=False
            )
            if rebase.returncode:
                conflicts_raw = self._git(
                    checkout,
                    ["diff", "--name-only", "--diff-filter=U", "-z"],
                    env,
                ).stdout
                conflicts = tuple(sorted(
                    path.decode("utf-8", "backslashreplace")
                    for path in conflicts_raw.split(b"\0") if path
                ))
                self._git(checkout, ["rebase", "--abort"], env, check=False)
                if not conflicts:
                    message = rebase.stderr.decode("utf-8", "replace").strip().splitlines()
                    detail = message[-1] if message else "unknown rebase failure"
                    raise ResolverError(f"rebase failed without file conflicts: {detail}")
                return RebaseResult("conflict", old_head, conflicting_files=conflicts)

            changed_raw = self._git(
                checkout,
                ["diff", "--name-only", "--diff-filter=ACMR", "-z",
                 f"origin/{default_branch}...HEAD"],
                env,
            ).stdout
            changed = [
                path.decode("utf-8", "surrogateescape")
                for path in changed_raw.split(b"\0") if path
            ]
            for path in changed:
                if path.endswith((".py", ".yml", ".yaml")):
                    blob = self._git(checkout, ["cat-file", "blob", f"HEAD:{path}"], env).stdout
                    validate_syntax_blob(path, blob)
            new_head = self._git(checkout, ["rev-parse", "HEAD"], env).stdout.decode().strip()
            if new_head == old_head:
                return RebaseResult("unchanged", old_head, new_head)
            if self.apply:
                token = self.api.tokens.get(repo.split("/", 1)[0], "")
                if not token:
                    raise ResolverError(f"target App token disappeared before push for {repo}")
                askpass = Path(tmp, "git-askpass.sh")
                askpass.write_text(
                    "#!/usr/bin/env bash\n"
                    "case \"$1\" in\n"
                    "  *Username*) printf '%s\\n' 'x-access-token' ;;\n"
                    "  *) printf '%s\\n' \"$GH_TOKEN\" ;;\n"
                    "esac\n",
                    encoding="utf-8",
                )
                askpass.chmod(0o700)
                push_env = dict(env)
                push_env.update({"GH_TOKEN": token, "GIT_ASKPASS": str(askpass)})
                self._git(
                    checkout,
                    ["push", f"--force-with-lease=refs/heads/{branch}:{old_head}",
                     "origin", f"HEAD:refs/heads/{branch}"],
                    push_env,
                )
            return RebaseResult("clean", old_head, new_head)


class ConflictResolver:
    def __init__(self, api, snapshot, claim, repos, bot_login, apply=False,
                 max_rebases=DEFAULT_REBASE_CAP, rebaser=None):
        self.api = api
        self.snapshot = snapshot
        self.claim = claim
        self.repos = repos
        self.bot_login = bot_login
        self.apply = apply
        self.max_rebases = max_rebases
        self.rebaser = rebaser
        self.actions = []
        self.errors = []
        self.rebases = 0
        self.budget_used = 0

    def _record(self, kind, repo, number, detail=""):
        self.actions.append((kind, repo, number, detail))
        mode = "APPLY" if self.apply else "DRY-RUN"
        print(f"{mode} {repo}#{number}: {kind}{(': ' + detail) if detail else ''}")

    @staticmethod
    def _skip(repo, number, reason):
        print(f"SKIP {repo}#{number}: {reason}")

    def _post(self, repo, number, body):
        if self.apply:
            self.api.comment(repo, number, body)

    def _escalate(self, repo, pr, comments, conflicts):
        number = pr["number"]
        bodies = _comment_bodies(_self_authored_comments(comments, self.bot_login))
        if not any(ESCALATION_MARKER in body for body in bodies):
            listed = "\n".join(f"- `{json.dumps(path)}`" for path in conflicts)
            body = (
                "> 🤖 SPARQ agent — automatic rebase stopped after two distinct-head "
                "conflict attempts. Human resolution is required; no semantic resolution "
                "was guessed.\n\nConflicting files:\n"
                f"{listed or '- `(Git did not report a path)`'}\n\n{ESCALATION_MARKER}"
            )
            self._post(repo, number, body)
        # Label last: if either mutation is interrupted, the next tick still sees an
        # unheld PR and converges the missing mutation without duplicating the loud marker.
        if self.apply:
            self.api.add_label(repo, number, "needs:user")
        self._record("needs:user", repo, number, ", ".join(conflicts))

    def _handle_conflict(self, repo, pr, conflicts, comments):
        number = pr["number"]
        head = (pr.get("head") or {}).get("sha", "")
        heads = attempt_heads(comments, self.bot_login)
        if head in heads:
            if len(heads) >= 2:
                self._escalate(repo, pr, comments, conflicts)
            else:
                self._skip(repo, number, "this head already has a recorded conflict attempt")
            return
        attempt = len(heads) + 1
        marker = f"<!-- conflict-resolver attempt={attempt} head={head} -->"
        self._post(
            repo,
            number,
            f"{marker}\n> 🤖 SPARQ agent — automatic rebase found file conflicts; "
            "no semantic resolution was attempted.\n\nConflicting files:\n"
            + "\n".join(f"- conflict-file: {json.dumps(path)}" for path in conflicts),
        )
        self._record("conflict-attempt", repo, number, f"attempt={attempt} head={head}")
        heads.append(head)
        if len(heads) >= 2:
            # Include the just-posted marker for exact-once convergence within this run.
            synthetic = comments + [{"body": marker, "user": {"login": self.bot_login}}]
            self._escalate(repo, pr, synthetic, conflicts)

    def _process_pr(self, repo, default_branch, listed_pr):
        number = listed_pr.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            self._skip(repo, "unknown", "invalid PR number in listing")
            return
        detail_url = f"{API_ROOT}/repos/{repo}/pulls/{number}"
        detail = self.snapshot.resolve_mergeable_detail(self.api.fetch, detail_url)
        if not isinstance(detail, dict):
            raise ResolverError(f"PR detail is malformed for {repo}#{number}")
        mergeable = detail.get("mergeable")
        if mergeable is not False:
            reason = "mergeability is still computing" if mergeable is None else "base is not conflicting"
            self._skip(repo, number, reason)
            return
        labels = _label_names(detail)
        holds = sorted(labels & HARD_EXCLUDE_LABELS)
        if holds:
            self._skip(repo, number, f"hard exclusion label(s): {', '.join(holds)}")
            return
        head = detail.get("head") or {}
        base = detail.get("base") or {}
        head_repo = (head.get("repo") or {}).get("full_name")
        base_repo = (base.get("repo") or {}).get("full_name")
        if head_repo != repo or base_repo != repo:
            self._skip(repo, number, "fork PR (head/base repository differs)")
            return
        if base.get("ref") != default_branch:
            self._skip(repo, number, "base branch is not the repository default branch")
            return
        head_sha = str(head.get("sha", ""))
        if SAFE_SHA.fullmatch(head_sha) is None:
            raise ResolverError(f"PR head SHA is malformed for {repo}#{number}")
        login = str((detail.get("user") or {}).get("login", ""))
        if login == DEPENDABOT_LOGIN:
            comments = self.api.comments(repo, number)
            marker = DEPENDABOT_MARKER.format(head=head_sha)
            if any(marker in body for body in _comment_bodies(comments)):
                self._skip(repo, number, "dependabot rebase already requested for this head")
                return
            if self.budget_used >= self.max_rebases:
                self._skip(repo, number, f"per-run rebase request cap ({self.max_rebases}) reached")
                return
            self.budget_used += 1
            self._post(repo, number, f"@dependabot rebase\n\n{marker}")
            self._record("dependabot-comment", repo, number, head_sha)
            return
        if owned_by_review_rebase_lane(detail, repo, self.claim):
            self._skip(
                repo,
                number,
                "review-lane worker PR belongs to the needs-rebase/rebase fix lane",
            )
            return
        comments = self.api.comments(repo, number)
        heads = attempt_heads(comments, self.bot_login)
        if head_sha in heads:
            if len(heads) >= 2:
                self._escalate(
                    repo, detail, comments, prior_conflicting_files(comments, self.bot_login)
                )
            else:
                self._skip(repo, number, "this head already has a recorded conflict attempt")
            return
        if len(heads) >= 2:
            self._escalate(
                repo, detail, comments, prior_conflicting_files(comments, self.bot_login)
            )
            return
        if self.budget_used >= self.max_rebases:
            self._skip(repo, number, f"per-run mechanical rebase cap ({self.max_rebases}) reached")
            return
        self.budget_used += 1
        self.rebases += 1
        result = self.rebaser(repo, detail, default_branch)
        if result.outcome == "conflict":
            self._handle_conflict(repo, detail, result.conflicting_files, comments)
        elif result.outcome == "unchanged":
            self._skip(repo, number, "local rebase was a no-op; nothing to push")
        elif result.outcome == "clean":
            body = (
                "> 🤖 SPARQ agent — this conflicting PR was mechanically auto-rebased "
                f"onto `{default_branch}`. CI, not this privileged job, validates semantics.\n\n"
                f"<!-- conflict-resolver rebased head={result.old_head} -->"
            )
            self._post(repo, number, body)
            self._record("mechanical-rebase", repo, number, f"{result.old_head} -> {result.new_head}")
        else:
            raise ResolverError(f"unknown rebase outcome for {repo}#{number}")

    def run(self):
        for repo in self.repos:
            if not self.api.has_token(repo):
                print(f"SKIP {repo}: no target App token was minted for owner")
                continue
            try:
                metadata = self.api.repository(repo)
                default_branch = metadata.get("default_branch") if isinstance(metadata, dict) else None
                if not _valid_branch(str(default_branch or "")):
                    raise ResolverError(f"repository default branch is unsafe for {repo}")
                pulls = self.api.pulls(repo)
                print(f"SCAN {repo}: {len(pulls)} open PR(s), default={default_branch}")
                for pr in pulls:
                    try:
                        self._process_pr(repo, default_branch, pr)
                    except ResolverError as exc:
                        number = pr.get("number", "unknown") if isinstance(pr, dict) else "unknown"
                        self.errors.append(f"{repo}#{number}: {exc}")
                        print(f"ERROR {repo}#{number}: {exc}", file=sys.stderr)
            except ResolverError as exc:
                self.errors.append(f"{repo}: {exc}")
                print(f"ERROR {repo}: {exc}", file=sys.stderr)
        print(
            f"SUMMARY mode={'apply' if self.apply else 'dry-run'} actions={len(self.actions)} "
            f"rebase-requests={self.budget_used}/{self.max_rebases} "
            f"mechanical-rebases={self.rebases} errors={len(self.errors)}"
        )
        return 1 if self.errors else 0


def _self_test():
    from copy import deepcopy
    from unittest.mock import patch

    snapshot = _load_helper("registry_plan_snapshot_conflict_test", "plan-snapshot.py")
    claim = _load_helper("registry_dispatch_claim_conflict_test", "dispatch-claim.py")
    bot_login = "sparq-agent[bot]"
    repo = "example/repo"
    base_sha = "b" * 40
    ok = True

    def check(name, actual, expected):
        nonlocal ok
        passed = actual == expected
        ok = ok and passed
        print(f"{'PASS' if passed else 'FAIL'}: {name}")
        if not passed:
            print(f"  expected: {expected!r}\n  actual:   {actual!r}")

    def pull(number, head, *, labels=(), author="alice", head_repo=repo, ref=None):
        return {
            "number": number,
            "state": "open",
            "mergeable": False,
            "labels": [{"name": label} for label in labels],
            "user": {"login": author},
            "head": {
                "sha": head,
                "ref": ref or f"topic-{number}",
                "repo": {"full_name": head_repo},
            },
            "base": {
                "sha": base_sha,
                "ref": "main",
                "repo": {"full_name": repo},
            },
        }

    class FakeAPI:
        def __init__(self, pulls, sequences=None):
            self.tokens = {"example": "test-token"}
            self.prs = {pr["number"]: deepcopy(pr) for pr in pulls}
            self.sequences = {number: [deepcopy(value) for value in values]
                              for number, values in (sequences or {}).items()}
            self.comment_rows = {pr["number"]: [] for pr in pulls}
            self.labels_added = []

        def has_token(self, _repo):
            return True

        def repository(self, _repo):
            return {"full_name": repo, "default_branch": "main"}

        def pulls(self, _repo):
            return [deepcopy(self.prs[number]) for number in sorted(self.prs)]

        def fetch(self, url):
            number = int(urlparse(url).path.rsplit("/", 1)[1])
            sequence = self.sequences.get(number)
            if sequence:
                value = sequence.pop(0)
                if not sequence:
                    self.prs[number] = deepcopy(value)
                return deepcopy(value)
            return deepcopy(self.prs[number])

        def comments(self, _repo, number):
            return deepcopy(self.comment_rows[number])

        def comment(self, _repo, number, body):
            self.comment_rows[number].append({"body": body, "user": {"login": bot_login}})

        def add_label(self, _repo, number, label):
            self.labels_added.append((number, label))
            names = _label_names(self.prs[number])
            if label not in names:
                self.prs[number].setdefault("labels", []).append({"name": label})

        def set_head(self, number, head):
            self.prs[number]["head"]["sha"] = head

    class FakeRebaser:
        def __init__(self, outcome="clean"):
            self.outcome = outcome
            self.calls = []

        def __call__(self, repo_name, pr, _base):
            self.calls.append((repo_name, pr["number"], pr["head"]["sha"]))
            if self.outcome == "conflict":
                return RebaseResult(
                    "conflict", pr["head"]["sha"], conflicting_files=("src/value.py",)
                )
            return RebaseResult("clean", pr["head"]["sha"], "f" * 40)

    # (a) Every hard hold and a fork are rejected before the rebaser. Removing any
    # exclusion makes this call list non-empty.
    excluded = [
        pull(1, "1" * 40, labels=("needs:user",)),
        pull(2, "2" * 40, labels=("trust-surface",)),
        pull(3, "3" * 40, head_repo="fork/repo"),
        pull(4, "4" * 40, labels=("review:needs-user",)),
        pull(5, "5" * 40, labels=("needs:design",)),
        pull(6, "6" * 40, labels=("trust:untrusted",)),
    ]
    api = FakeAPI(excluded)
    rebaser = FakeRebaser()
    resolver = ConflictResolver(api, snapshot, claim, [repo], bot_login, True, 5, rebaser)
    resolver.run()
    check("hard labels and fork are never rebased", rebaser.calls, [])

    worker = pull(
        7, "7" * 40, author=bot_login, ref="sparq-agent/issue-7-1-1"
    )
    api_worker = FakeAPI([worker])
    worker_rebaser = FakeRebaser()
    ConflictResolver(
        api_worker, snapshot, claim, [repo], bot_login, True, 5, worker_rebaser
    ).run()
    check("needs-rebase worker lane is never double-owned", worker_rebaser.calls, [])

    # (b) Conflict attempts count distinct heads. The second head escalates once;
    # the resulting hard label makes every later sweep inert.
    api = FakeAPI([pull(10, "a" * 40)])
    rebaser = FakeRebaser("conflict")
    first = ConflictResolver(api, snapshot, claim, [repo], bot_login, True, 5, rebaser)
    first.run()
    api.set_head(10, "c" * 40)
    second = ConflictResolver(api, snapshot, claim, [repo], bot_login, True, 5, rebaser)
    second.run()
    third = ConflictResolver(api, snapshot, claim, [repo], bot_login, True, 5, rebaser)
    third.run()
    bodies = _comment_bodies(api.comment_rows[10])
    check("two distinct attempts add needs:user exactly once", api.labels_added, [(10, "needs:user")])
    check("two attempt markers are durable", sum(bool(ATTEMPT_RE.search(body)) for body in bodies), 2)
    check("loud escalation comment is exactly once", sum(ESCALATION_MARKER in body for body in bodies), 1)

    # (c) Dependabot receives a command, never a host rebase, once per head SHA.
    api = FakeAPI([pull(20, "d" * 40, author=DEPENDABOT_LOGIN)])
    rebaser = FakeRebaser()
    one = ConflictResolver(api, snapshot, claim, [repo], bot_login, True, 5, rebaser)
    one.run()
    two = ConflictResolver(api, snapshot, claim, [repo], bot_login, True, 5, rebaser)
    two.run()
    api.set_head(20, "e" * 40)
    three = ConflictResolver(api, snapshot, claim, [repo], bot_login, True, 5, rebaser)
    three.run()
    dep_bodies = _comment_bodies(api.comment_rows[20])
    check("dependabot path never rebases", rebaser.calls, [])
    check("dependabot command is idempotent per head", sum("@dependabot rebase" in body for body in dep_bodies), 2)
    check("dependabot markers bind both heads", sorted(
        head for head in ("d" * 40, "e" * 40)
        if any(DEPENDABOT_MARKER.format(head=head) in body for body in dep_bodies)
    ), ["d" * 40, "e" * 40])

    # (d) The shared plan-snapshot helper re-polls null before classification.
    unresolved = pull(30, "8" * 40)
    unresolved["mergeable"] = None
    resolved = deepcopy(unresolved)
    resolved["mergeable"] = False
    api = FakeAPI([unresolved], {30: [unresolved, resolved]})
    rebaser = FakeRebaser()
    with patch.object(snapshot.time, "sleep") as sleep:
        ConflictResolver(
            api, snapshot, claim, [repo], bot_login, False, 5, rebaser
        ).run()
    check("null mergeable re-polls before DIRTY classification", len(rebaser.calls), 1)
    check("null mergeable uses the shared bounded interval", sleep.call_args_list,
          [((snapshot.MERGEABLE_POLL_INTERVAL_SECONDS,), {})])

    # (e) Six eligible conflicts yield only the configured five local rebases.
    api = FakeAPI([pull(40 + index, str(index) * 40) for index in range(1, 7)])
    rebaser = FakeRebaser()
    capped = ConflictResolver(api, snapshot, claim, [repo], bot_login, False, 5, rebaser)
    capped.run()
    check("per-run mechanical rebase cap holds", len(rebaser.calls), 5)
    check("cap accounting holds", capped.rebases, 5)

    # Syntax-only validators are direct and non-executing.
    validate_syntax_blob("ok.py", b"value = 1\n")
    validate_syntax_blob("ok.yml", b"key: value\n")
    syntax_rejected = 0
    for path, blob in (("bad.py", b"if:\n"), ("bad.yml", b"key: [\n")):
        try:
            validate_syntax_blob(path, blob)
        except ResolverError:
            syntax_rejected += 1
    check("invalid Python and YAML are rejected without execution", syntax_rejected, 2)

    print(f"conflict-resolver self-test {'PASSED' if ok else 'FAILED'}")
    return 0 if ok else 1


def _tokens_from_environment():
    raw = os.environ.get("TARGET_GH_TOKENS", "")
    if raw:
        try:
            tokens = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ResolverError("TARGET_GH_TOKENS is malformed JSON") from exc
        if not isinstance(tokens, dict) or any(
            not isinstance(owner, str) or not isinstance(token, str)
            for owner, token in tokens.items()
        ):
            raise ResolverError("TARGET_GH_TOKENS must be an owner-to-token object")
        return tokens
    token = os.environ.get("GH_TOKEN", "")
    owner = os.environ.get("GITHUB_REPOSITORY", "").split("/", 1)[0]
    return {owner: token} if owner and token else {}


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", dest="apply", action="store_false",
                      help="read and locally rebase only; this is the default")
    mode.add_argument("--apply", dest="apply", action="store_true",
                      help="push clean rebases and write comments/labels")
    parser.set_defaults(apply=False)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--policy-file", default="policy/repos.toml")
    parser.add_argument("--registry-repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--bot-slug", default="")
    parser.add_argument("--max-rebases", type=int, default=DEFAULT_REBASE_CAP)
    parser.add_argument(
        "--workspace", default=os.environ.get("RUNNER_TEMP", tempfile.gettempdir()),
        help="runner-local parent directory for full-history temporary clones",
    )
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    if args.max_rebases <= 0:
        parser.error("--max-rebases must be positive")
    if not args.bot_slug or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.bot_slug):
        parser.error("--bot-slug is required and must be a safe GitHub App slug")
    try:
        tokens = _tokens_from_environment()
        if not tokens:
            raise ResolverError("no target App tokens were provided")
        api = GitHubAPI(tokens)
        bot_login, bot_id = api.app_identity(args.bot_slug)
        snapshot = _load_helper("registry_plan_snapshot_conflict", "plan-snapshot.py")
        claim = _load_helper("registry_dispatch_claim_conflict", "dispatch-claim.py")
        repos = load_target_repositories(Path(args.policy_file), args.registry_repo)
        rebaser = MechanicalRebaser(
            api, args.workspace, bot_login, bot_id, args.apply
        )
        return ConflictResolver(
            api,
            snapshot,
            claim,
            repos,
            bot_login,
            args.apply,
            args.max_rebases,
            rebaser,
        ).run()
    except (OSError, ResolverError, tomllib.TOMLDecodeError) as exc:
        print(f"conflict-resolver: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
