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
from dataclasses import dataclass, field
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


API_ROOT = "https://api.github.com"
# THE HOLDS THIS PROGRAM STANDS OFF FROM — but only when a HUMAN applied them (registry #1191).
#
# `needs:user` appears on BOTH edges of this program: `_escalate_two_head` WRITES it, and this set
# EXCLUDES it. Read as a bare label set that is a closed loop — the resolver fails to converge on a
# PR, applies the human terminal, and thereby permanently removes that PR from its own candidate
# population. MEASURED on the live registry 2026-07-29: 17 of 17 conflicting open PRs were dropped
# at that one predicate, 14 of them holding a hold whose newest application was made by
# `sparq-orchestrator[bot]`, i.e. by this estate rather than by a person; production ran
# `attempted:0` with `no_exit:0` and exit code 0 in 100 of 100 sampled runs.
#
# The exclusion is NOT the defect and is not deleted: a person who applies one of these is
# mid-decision, and a machine that rebases under them is fighting them. What is deleted is the
# assumption that the LABEL identifies the actor. Ownership is now READ from the timeline, per
# label, across the PR and its source issue (`_hold_ownership`), and only a proven human holds.
HARD_EXCLUDE_LABELS = {
    "needs:user",
    "review:needs-user",
    "needs:design",
    "trust-surface",
    "trust:untrusted",
}
# --- WHO OWNS THE FORWARD EDGE OF A SKIPPED PR ------------------------------------------------
#
# The second, deeper half of #1191: 114 consecutive runs reported `success` while attempting zero
# work, because a run that EXCLUDED EVERY CANDIDATE is byte-identical, in both exit code and
# summary line, to a run that had NOTHING TO DO. A lane that cannot tell those apart re-grows this
# defect wherever the next exclusion is added.
#
# So every skip key is classified by WHO advances that PR next, and the classification is total —
# `_skip` treats an unclassified key as UNOWNED and says so. That default direction is the whole
# point: under a blacklist a newly added skip reason is silently benign, under this whitelist it is
# loud until somebody names its owner.
OWNER_OUT_OF_POPULATION = "out-of-population"   # not a conflicting PR; nothing to own
OWNER_ELSEWHERE = "owned"                       # a person, another lane, or a bounded timer owns it
OWNER_NONE = "unowned"                          # nothing will advance this PR; the run did nothing
SKIP_OWNERSHIP = {
    # Never entered the conflicting population.
    "invalid-pr-number": OWNER_OUT_OF_POPULATION,
    "mergeability-computing": OWNER_OUT_OF_POPULATION,
    "not-conflicting": OWNER_OUT_OF_POPULATION,
    "no-owner-token": OWNER_OUT_OF_POPULATION,
    # Conflicting, and somebody else's move.
    "hard-exclusion-label": OWNER_ELSEWHERE,        # a PROVEN human — checked, no longer assumed
    "two-head-exhausted-stands": OWNER_ELSEWHERE,   # the human the escalation already asked
    "stuck-park-already-delivered": OWNER_ELSEWHERE,  # our own live park, cause-gated
    "park-suppressed-human-unpark": OWNER_ELSEWHERE,  # the human who un-parked it
    "park-already-live": OWNER_ELSEWHERE,             # whoever the live hold already asked
    "residual-human-class-hold": OWNER_ELSEWHERE,     # the `needs:*` hold this program cannot own
    "stuck-park-stands": OWNER_ELSEWHERE,           # a cause-gated machine park
    "awaiting-author-grace": OWNER_ELSEWHERE,       # the author, bounded by --stuck-grace-hours
    "dependabot-already-requested": OWNER_ELSEWHERE,
    "review-lane-owned": OWNER_ELSEWHERE,
    "fork-pr": OWNER_ELSEWHERE,                     # out of scope by construction
    "non-default-base": OWNER_ELSEWHERE,            # out of scope by construction
    "rebase-cap-reached": OWNER_ELSEWHERE,          # the next run, and the cap is in the census
    # Conflicting, and nobody's move.
    "hold-ownership-unreadable": OWNER_NONE,
    "attempt-timestamp-unusable": OWNER_NONE,
    "rebase-no-op": OWNER_NONE,
    # `_handle_conflict`'s pre-existing dead arm (documented at its site). Unreachable by
    # construction today, and classified UNOWNED precisely so that if some future change makes it
    # reachable the run says so instead of absorbing it.
    "duplicate-attempt-this-run": OWNER_NONE,
}
DEPENDABOT_LOGIN = "dependabot[bot]"
DEPENDABOT_MARKER = "<!-- conflict-resolver head={head} -->"
ATTEMPT_RE = re.compile(
    r"<!-- conflict-resolver attempt=([1-9][0-9]*) head=([0-9a-f]{40}) -->"
)
ESCALATION_MARKER = "<!-- conflict-resolver escalated -->"
# --- THE TWO ESCALATION EXITS, named ------------------------------------------------------------
# `_escalate` used to post ONE hard-coded body for BOTH of them, so a grace-window TIMEOUT was
# reported to the reader as "two distinct-head conflict attempts". MEASURED on the live registry
# 2026-07-28: of the 10 conflicting PRs holding a machine-applied `needs:user` from this program,
# exactly ONE (#685) had two attempt markers; the other NINE had one and came through the
# grace-window branch. The body asserted a specific fact that was false in 9 of 10 cases.
#
# The exits differ in KIND, not merely in wording, which is why they are constants and not a
# boolean: two distinct heads failing to converge is a genuine human question, while a window
# elapsing is a TIMEOUT — and a timeout is not a human question (registry #769).
EXIT_TWO_HEAD = "two-distinct-heads"
EXIT_STUCK_GRACE = "stuck-grace"
SAFE_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
SAFE_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
SAFE_SHA = re.compile(r"[0-9a-f]{40}")
MAX_API_PAGES = 50
DEFAULT_REBASE_CAP = 5
# Issue #753. The two-distinct-head escalation is the ONLY exit from a recorded conflict attempt,
# and a second distinct head exists only if somebody PUSHES to the branch. An abandoned worker PR
# therefore parks in `head already has a recorded conflict attempt` FOREVER: no label, no
# escalation, no error, so a run that skipped it is byte-identical to a run that had nothing to do.
# This window is the MACHINE exit: after it elapses with the head unmoved, the single attempt
# escalates exactly as a second failed attempt would. It is a grace period for the author to push
# a fix, not a hold.
DEFAULT_STUCK_GRACE_HOURS = 6.0
# The CLOSED cause taxonomy of the grace-window park, and the automatic re-admission cap.
#
# One cause today, spelled out rather than implied, because `stuck_park_cause_recovered` refuses
# any token it does not recognise: a cause we cannot check is a cause we cannot prove recovered,
# and guessing there turns a bounded exit into an unbounded retry (groom's rule, same words).
STUCK_PARK_CAUSE = "head-unmoved"
# At most this many AUTOMATIC re-admissions may ever be granted to one PR by the grace-window
# exit, and the cap is enforced ONCE, at park time (stuck_park_label): a park in generation
# N > STUCK_UNPARK_MAX is written in the HUMAN class outright, so the exit phase can never see an
# over-cap park. A PR that keeps re-entering the same stuck state is not a timeout, it is a flap,
# and "this recurred N times" is a genuinely different question to put to a human.
STUCK_UNPARK_MAX = 2
# A conflicting PR that is neither parked by a hard label nor repairable nor escalatable is in a
# state with NO exit. That is a defect in this program, not a property of the fleet, so the run
# FAILS on it. It is self-clearing: the grace-window escalation drains the population into the
# human `needs:user` queue, which the hard-exclusion filter then owns.
DEFAULT_NO_EXIT_ALERT_THRESHOLD = 0


class ResolverError(RuntimeError):
    """A credential-free operational failure suitable for an Actions log."""


def _cleanup_tempdir(path):
    """Best-effort removal for runner-local clones; cleanup cannot change the outcome."""
    path = Path(path)
    cleanup_error = None

    def retry_remove(function, failed_path, exc):
        nonlocal cleanup_error
        cleanup_error = exc
        try:
            if not os.path.islink(failed_path):
                os.chmod(failed_path, 0o700)
            function(failed_path)
        except FileNotFoundError:
            pass
        except Exception as retry_exc:
            cleanup_error = retry_exc

    try:
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=retry_remove)
        else:
            shutil.rmtree(
                path,
                onerror=lambda function, failed_path, exc_info: retry_remove(
                    function, failed_path, exc_info[1]
                ),
            )
    except Exception as exc:
        cleanup_error = exc

    if path.exists():
        time.sleep(0.1)
        try:
            shutil.rmtree(path, ignore_errors=True)
        except Exception as exc:
            cleanup_error = exc
    if path.exists():
        detail = str(cleanup_error) if cleanup_error else "directory still exists after retries"
        print(
            f"::warning::conflict-resolver cleanup left temporary directory debris "
            f"at {path}: {detail}",
            file=sys.stderr,
        )


def _load_helper(name, filename):
    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ResolverError(f"cannot load registry helper {filename}")
    module = importlib.util.module_from_spec(spec)
    # Registered BEFORE execution: `@dataclass` resolves its own module through `sys.modules` at
    # class-creation time, so a helper defining one raises AttributeError under a loader that
    # only registers afterwards (groom.py does; measured).
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_GROOM_MODULE = None


def _groom():
    """Cached groom.py — IMPORTED for `linked_issue_numbers`, never re-implemented here.

    The hold-ownership decision spans a PR *and its source issue*, so this program has to answer
    "which issue?" — the same question groom answers for its own park hand-off. Two spellings of
    PR→issue linkage drift silently in the anti-conservative direction: a resolver that fails to
    find the issue reads only the PR, misses a human hold living on the issue, and rebases under
    the person it was written to stand off from. One regex pair, one owner."""
    global _GROOM_MODULE
    if _GROOM_MODULE is None:
        _GROOM_MODULE = _load_helper("registry_groom_conflict_resolver", "groom.py")
    return _GROOM_MODULE


# Shared park-label policy: the terminal needs:user write consults the sticky human-unpark
# veto before every application (park_policy.py).
_park_policy = _load_helper("registry_park_policy", "park_policy.py")

# The two park LABELS and the two durable receipt markers of the grace-window exit. All four
# spellings are park_policy's, never literals here: dispatch-claim's automatic re-admission sweep
# READS the park receipt in order to leave this episode alone (park_policy.
# CAUSE_GATED_PARK_OWNERS), and a hand-copied literal in either entry point is a spelling that can
# drift silently from the other's — the failure being not a crash but a sweep that quietly stops
# recognising the class it was written to skip.
MACHINE_PARK_LABEL = _park_policy.MACHINE_PARK_PR_LABEL
HUMAN_PARK_LABEL = _park_policy.HUMAN_PARK_LABEL
STUCK_PARK_MARKER = _park_policy.CONFLICT_STUCK_PARK_MARKER
STUCK_UNPARK_MARKER = _park_policy.CONFLICT_STUCK_UNPARK_MARKER
STUCK_RECEIPT_RE = re.compile(
    r"cause=(?P<cause>[a-z-]{1,40}) head=(?P<head>[0-9a-f]{40}) gen=(?P<gen>[1-9][0-9]{0,3}) -->"
)


def _is_human_maintainer(api, repo, login, on_failure=None):
    """The strict maintainer probe for the unpark veto (park-policy hygiene finding; the
    worker-issue._is_human_maintainer pattern): repo collaborator permission in
    park_policy.HUMAN_MAINTAINER_PERMISSIONS. Probe-call FAILURE counts as NOT a maintainer
    and emits the shared distinct ::warning:: diagnostic (park_policy.probe_maintainer,
    round-3 Opus finding); a genuine not-a-maintainer permission stays quiet.

    `on_failure` is called once per failed probe. `probe_maintainer` deliberately collapses
    "probe broke" into the same False as "genuinely not a maintainer", which is the right fail
    direction for a VETO — an unverifiable actor mints nothing. It is the WRONG direction for an
    ADMISSION: a 403 on the collaborator endpoint would report a maintainer's own hold as
    machine-applied and rebase under them. Callers that admit on the answer pass this and
    downgrade the result to UNKNOWN (registry #1191 review, secondary finding 2)."""
    def read_permission(probe_login):
        payload = api.request("GET", f"/repos/{repo}/collaborators/{probe_login}/permission")
        if not isinstance(payload, dict):
            raise ResolverError("collaborator permission payload is malformed")
        return payload.get("permission")

    def probe(probe_login):
        try:
            return read_permission(probe_login)
        except Exception:
            if on_failure is not None:
                on_failure(probe_login)
            raise

    return _park_policy.probe_maintainer(repo, login, probe)


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

    def issue(self, repo, number):
        """The source ISSUE, for its live label set only. Read on the hold-ownership path so the
        issue can be checked across every hard-exclusion label rather than only the PR's own."""
        return self.request("GET", f"/repos/{repo}/issues/{number}")

    def timeline(self, repo, number):
        return self.paginated(f"/repos/{repo}/issues/{number}/timeline")

    def comment(self, repo, number, body):
        return self.request("POST", f"/repos/{repo}/issues/{number}/comments", {"body": body})

    def add_label(self, repo, number, label):
        return self.request(
            "POST", f"/repos/{repo}/issues/{number}/labels", {"labels": [label]}
        )

    def remove_label(self, repo, number, label):
        """DELETE one label. 404 means it is already gone, which is the state this call wants."""
        try:
            return self.request(
                "DELETE",
                f"/repos/{repo}/issues/{number}/labels/{quote(label, safe='')}",
            )
        except ResolverError as exc:
            if "HTTP 404" in str(exc):
                return {}
            raise

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


def _comment_epoch(value):
    """POSIX seconds for a GitHub ``created_at``; None when it is absent or unparseable."""
    if not isinstance(value, str) or not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.timestamp()


def attempt_records(comments, bot_login):
    """Distinct attempted heads with the EARLIEST marker timestamp for each.

    Ordered oldest-marker-first, exactly as ``attempt_heads`` was. The timestamp is what makes
    the single-attempt state exitable: without it the only escalation trigger is a second
    distinct head, which an abandoned PR never produces.
    """
    stamps = {}
    order = []
    for comment in _self_authored_comments(comments, bot_login):
        body = comment.get("body")
        if not isinstance(body, str):
            continue
        epoch = _comment_epoch(comment.get("created_at"))
        for match in ATTEMPT_RE.finditer(body):
            head = match.group(2)
            if head not in stamps:
                order.append(head)
                stamps[head] = epoch
            elif epoch is not None and (stamps[head] is None or epoch < stamps[head]):
                stamps[head] = epoch
    return [(head, stamps[head]) for head in order]


def attempt_heads(comments, bot_login):
    """Distinct heads attempted by this App; user-spoofed markers never consume budget."""
    return [head for head, _ in attempt_records(comments, bot_login)]


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


# --- the grace-window park: class, receipts, and the CAUSE-GATED exit -------------------------
#
# registry #769 in one sentence: a clock must not decide an outcome. The grace window may decide
# WHEN to stop waiting — that is what a grace period is — but it may not decide WHAT the stop
# means, and it may certainly not be the evidence that ENDS the resulting hold. Everything below
# is shaped after groom's age-park primitives (age_park_label / age_receipts /
# age_park_generation / age_unpark_state / age_park_cause_recovered) for exactly that reason.


def stuck_park_label(generation):
    """The park label the grace-window exit must write — the ONE place its class is decided.

    MACHINE (`review:parked`) while the PR is within its automatic re-admission cap; HUMAN
    (`needs:user`) past it, which is a flap rather than a timeout. There is no unmapped-cause
    branch here as there is in groom's `age_park_label`: this exit derives exactly one cause and
    that cause has a recovery predicate, so the cap is the only way out of the machine class."""
    return HUMAN_PARK_LABEL if generation > STUCK_UNPARK_MAX else MACHINE_PARK_LABEL


def stuck_receipts(comments, bot_login, marker):
    """Well-formed BOT-AUTHORED grace-window receipts of one kind, oldest-first.

    Trust filter first, as everywhere else in this file: a receipt any other actor could author is
    not a durable record of what THIS program did. A malformed receipt is dropped here but still
    counted by ``stuck_park_generation``, so a corrupt receipt can never buy an extra automatic
    re-admission."""
    found = []
    if not bot_login:
        return found
    for comment in _self_authored_comments(comments, bot_login):
        body = comment.get("body")
        if not isinstance(body, str):
            continue
        index = body.find(marker)
        if index < 0:
            continue
        match = STUCK_RECEIPT_RE.match(body[index + len(marker):].lstrip())
        if match is None:
            continue
        found.append({"cause": match.group("cause"), "head": match.group("head"),
                      "gen": int(match.group("gen"))})
    return found


def stuck_park_generation(comments, bot_login):
    """The generation a NEW grace-window park would occupy: one past every park receipt already on
    record, CLAMPED at STUCK_UNPARK_MAX + 1.

    Counts MARKERS, not well-formed records. The clamp is what makes the terminal terminal: without
    it every later sweep of an already-escalated PR mints a higher generation whose receipt no
    earlier one matches, so the escalation comment is re-posted forever on a PR already handed to a
    human."""
    if not bot_login:
        return 1
    return min(
        STUCK_UNPARK_MAX + 1,
        1 + sum(STUCK_PARK_MARKER in body
                for body in _comment_bodies(_self_authored_comments(comments, bot_login))),
    )


def stuck_unpark_state(comments, bot_login):
    """``(park_receipt, grant_receipt)`` for the newest grace-window park on record.

    ``park_receipt`` is None when this is not a park of ours, or when the park is OVER THE CAP
    (generation > STUCK_UNPARK_MAX) — an over-cap park was written in the HUMAN class by
    ``stuck_park_label`` and must never be automatically re-admitted, so the exit phase must not
    even consider it.

    ``grant_receipt`` is the un-park receipt carrying the SAME (cause, head, gen) triple, or None
    when the recovery is still unconsumed. That triple is the CONSUME-EXACTLY-ONCE key: one
    recovery can never be re-earned, and a further re-admission requires a NEW park at a new
    fingerprint.

    The two are returned separately rather than collapsed into "owed or not" because granted +
    label-still-live is a distinct state from granted + label-gone. Receipt-first ordering makes
    the former the only crash residue possible, and collapsing it strands the PR under
    `review:parked` forever — one HTTP transient on the DELETE is enough to reach it."""
    parks = stuck_receipts(comments, bot_login, STUCK_PARK_MARKER)
    if not parks:
        return None, None
    latest = parks[-1]
    if latest["gen"] > STUCK_UNPARK_MAX:
        return None, None
    key = (latest["cause"], latest["head"], latest["gen"])
    for grant in stuck_receipts(comments, bot_login, STUCK_UNPARK_MARKER):
        if (grant["cause"], grant["head"], grant["gen"]) == key:
            return latest, grant
    return latest, None


def stuck_park_cause_recovered(cause, detail, parked_head):
    """Has THIS park's OWN cause provably recovered? Returns ``(recovered, why)``.

    THE EXIT IS GATED ON THE CAUSE, NEVER ON ELAPSED TIME. Re-introducing a timer here would
    rebuild precisely what registry #769 removed: an age park whose only clearing evidence is more
    age is its own recovery proof, which is not a proof at all.

    The cause is `head-unmoved` — one recorded conflict attempt, on a head nobody has pushed to,
    against a base this program could not mechanically rebase onto. Two facts refute it, and each
    is independently sufficient:

      * THE HEAD MOVED. `detail`'s live head SHA differs from the one the receipt was minted
        against, i.e. the author did the thing the grace window was waiting for. The attempt
        markers are keyed by head, so the very next sweep performs a FRESH mechanical rebase.
      * THE CONFLICT RESOLVED. The PR is no longer `mergeable is False` (somebody merged, rebased
        or retargeted it). There is nothing left to park for.

    DELIBERATELY NOT ACCEPTED: "the base advanced". It is a real change in the world and it is
    machine-checkable, but it grants this program NO NEW ACTION — the attempt marker for the
    unmoved head still short-circuits every later sweep before any rebase is attempted, so a
    base-advance exit would clear the label, re-derive the identical stuck state on the next tick,
    and burn a generation each time. On a fast-moving default branch that spends the whole
    re-admission cap within a few ticks and lands the PR in the human terminal SOONER than doing
    nothing. An exit that grants no new attempt is a churn generator, not an exit.

    THE CONTINGENCY THAT EXCLUSION STANDS ON, written down rather than left implicit: it is sound
    ONLY BECAUSE the attempt marker is keyed by HEAD, so an unmoved head short-circuits every
    later sweep before any rebase is attempted. A base advance can genuinely turn a conflict
    clean, so if this program ever learns to retry a mechanical rebase when the BASE moves — key
    the marker by (head, base), say — then a base advance WOULD grant a new action and this
    exclusion becomes wrong and must be revisited here. That is a property of the marker's key,
    not of this predicate, which is exactly why it is recorded at the predicate that depends on
    it.

    Every ambiguity fails toward STAYING PARKED: a malformed live head, a missing mergeability
    field, and an unrecognised cause token all return False."""
    if cause != STUCK_PARK_CAUSE:
        return False, f"cause {cause!r} has no recovery predicate — never auto-re-admitted"
    live_head = str(((detail or {}).get("head") or {}).get("sha", ""))
    if SAFE_SHA.fullmatch(live_head) is None:
        return False, "the live head SHA is malformed, so the head cannot be proven to have moved"
    if live_head != parked_head:
        return True, (f"the head moved from {parked_head[:12]} to {live_head[:12]} — the author "
                      "pushed, and the next sweep rebases the new head")
    if (detail or {}).get("mergeable") is not False:
        return True, "the PR is no longer conflicting with its base"
    return False, (f"the head is still {parked_head[:12]} and the base is still conflicting — "
                   "nothing this program can act on has changed")


def stuck_receipt(marker, head, generation):
    """One durable grace-window receipt. The (cause, head, gen) triple is the consume-once key."""
    return f"{marker} cause={STUCK_PARK_CAUSE} head={head} gen={generation} -->"


def escalation_body(exit_kind, conflicts, attempts, park_label, receipt="", generation=None,
                    grants=0):
    """The comment body for ONE exit — the single place the escalation wording is decided.

    THE DEFECT THIS CLOSES. One hard-coded body served both exits, so a grace-window timeout told
    its reader "automatic rebase stopped after two distinct-head conflict attempts". That is not
    vague, it is FALSE: nine of the ten live cases had exactly one attempt marker. Whoever reads
    it — a maintainer, or a machine keying on the prose (park_policy.LEGACY_PARK_PROSE reads
    exactly these sentences) — is told the resolver tried twice on different heads when it tried
    once and then waited.

    So the body is DERIVED from the exit and the counts actually observed, and an unknown exit
    kind raises rather than falling through to a default sentence — an unrepresentable body must
    fail LOUD at the writer, exactly as `park_policy.park_reason_marker` refuses an unknown cause.

    `grants` is READ from the un-park receipts, never inferred from the generation (registry #769,
    same finding): a generation is consumed by every re-park however the label was cleared, so
    "generation 3" does not imply "the machine granted 2 re-admissions", and telling a maintainer
    it did sends them hunting a flap that never happened."""
    if exit_kind == EXIT_TWO_HEAD:
        lead = (
            f"automatic rebase stopped after {attempts} distinct-head conflict attempts "
            "(the two-distinct-head exhaustion exit). The machine tried on more than one head "
            "and cannot converge, so human resolution is required; no semantic resolution was "
            "guessed."
        )
    elif exit_kind != EXIT_STUCK_GRACE:
        raise ResolverError(f"unknown conflict-resolver escalation exit {exit_kind!r}")
    elif park_label == MACHINE_PARK_LABEL:
        lead = (
            f"automatic rebase is holding after {attempts} conflict attempt(s) on an UNMOVED "
            "head: the author grace window elapsed with no new push (the stuck-attempt "
            "grace-window exit). A timeout is not a human question, so this is the MACHINE-owned "
            f"`{MACHINE_PARK_LABEL}` soft hold and NOT a request for human resolution. It clears "
            "itself, with no action from you, as soon as the head moves or the conflict resolves."
        )
    else:
        lead = (
            f"automatic rebase escalated at grace-window park generation {generation} "
            f"(cap {STUCK_UNPARK_MAX}), with {attempts} conflict attempt(s) recorded and "
            f"{grants} automatic re-admission(s) on record (the stuck-attempt grace-window exit, "
            "past its automatic re-admission cap). This PR keeps re-entering the same stuck "
            "state, so a repeated failure — not a timeout, and not two distinct heads — is what "
            "is being escalated."
        )
    listed = "\n".join(f"- `{json.dumps(path)}`" for path in conflicts)
    return (
        f"> 🤖 SPARQ agent — {lead}\n\nConflicting files:\n"
        f"{listed or '- `(Git did not report a path)`'}\n\n{receipt}"
    )


def owned_by_review_rebase_lane(pr, repo, claim):
    """Conservatively identify worker PRs dispatch owns as needs-rebase/rebase repairs.

    True here means this resolver CEDES the PR — it posts nothing, rebases nothing, and lets the
    review/fix lane repair it. So the predicate is only sound while it selects PRs that lane will
    actually TAKE; ceding one it refuses is not conservatism, it is a silent no-exit for a
    CONFLICTING PR, and a conflicting PR is exactly the population that gets no `pr-gate` run at
    all.

    [registry #657, design record §7.4 step 2b] THE ORCHESTRATOR CLASS IS NEVER CEDED, and the
    reason is a property of the review lane, not of this shape test. `review_fix_pr_admission`
    waives the head-ref/author/draft shape gates for ``mode == "review"`` ALONE: a `fix` run
    PUSHES COMMITS to the PR head, and a self-attested record must never buy write access to its
    own branch (design record §3). A rebase repair IS a fix dispatch, so the class is refused
    there at the same four predicates it always was — and handing it over would strand it.

    Today the two populations are DISJOINT BY CONSTRUCTION rather than by any test written here:
    `admits_orchestrator_pr` requires the author's login in `review_enrolment_authors`, and
    policy-resolve refuses a `[bot]` login in that list (GITHUB_LOGIN_RE has no brackets), while
    this predicate requires a `[bot]` author. Adding `and not admits_orchestrator_pr(...)` would
    therefore be a conjunct that can never fire — a dead guard dressed as a control. What is
    asserted instead, executably, is the JUSTIFICATION: --self-test runs the LIVE
    `review_fix_pr_admission` in fix mode over a fully-admissible enrolled orchestrator PR and
    requires it to REFUSE. Widen that waiver to fix mode and the control reds, pointing here.

    FORK GATE FIRST. It is hoisted out of the middle of the `and` chain — order inside a boolean
    chain is irrelevant, so the point is not sequencing but that the one predicate no waiver may
    ever reach is not fused with the two that #657 waives elsewhere.

    THE HOLD GATES ARE THE LANE'S, NOT COPIES (PR #1294). The three predicates above test the
    PRODUCER shape — "did the worker lane make this PR?" — and the paragraph at the top says the
    cede is sound only while the lane will TAKE it. Those are different questions, and for the
    whole live population they gave different answers. MEASURED 2026-07-29 against the live fleet:
    conflict-resolver run 30479952962 ceded 20 CONFLICTING PRs as `review-lane-owned`, and
    dispatch run 30480407955 — seven minutes later, same board — printed a `review-enumeration:
    exclude` line for ALL TWENTY, plus `::warning:: 17 worker PR(s) have a conflicting base but
    ZERO needs-rebase repair item(s) were enumerated` for sparq-org/sparq and the same at 5 for
    this repository. Every one of the 20 carried `needs:user`, `review:needs-user` or
    `review:parked`; `review_items` drops the first two at `HUMAN_HOLD_PR_LABELS` and the third at
    `MACHINE_PARK_PR_LABEL`, both BEFORE any state is emitted. So the hand-over had no receiver,
    and a CONFLICTING PR gets no `pr-gate` run at all — 20 PRs with no machine exit on either
    side, which is the mutual-deferral shape, not conservatism.

    The three labels are READ FROM `claim`, never re-spelled here. A local copy is how the two
    halves drift back apart: the lane adding a fourth hold would silently re-open the hole, and
    with the sets shared it cannot. `--self-test` iterates `claim.HUMAN_HOLD_PR_LABELS |
    {claim.MACHINE_PARK_PR_LABEL}` rather than a literal list for the same reason.

    NOT A WEAKENING OF ANY HUMAN HOLD. `_process_pr` reaches this predicate only AFTER
    `_classify_holds` has proven every live `HARD_EXCLUDE_LABELS` member MACHINE-applied — a
    human-applied one returns at `hard-exclusion-label` and never arrives here. Refusing to cede
    therefore hands the PR to this program's OWN bounded path (one attempt marker, one mechanical
    rebase, then the two-head/grace escalations), which is the strongest thing reachable past this
    gate: never a merge, never an arm.

    WHAT IS DELIBERATELY *NOT* MIRRORED. `review_items` also refuses on registry provenance, on a
    `needs:*` label on the SOURCE issue, and on a live sibling package lease. Those need the
    registry ledger and the lease store, which this program does not read, so the predicate stays
    a NECESSARY-condition test: everything it still cedes may yet be refused downstream for one of
    those reasons. That residual is real and is tracked, not papered over — but on the live
    population it is empty, because the label gates alone account for all 20."""
    head = pr.get("head") or {}
    if (head.get("repo") or {}).get("full_name") != repo:
        return False
    login = str((pr.get("user") or {}).get("login", ""))
    if not (
        claim.FIX_KIND_OF_STATE.get("needs-rebase") == "rebase"
        and claim.HEAD_REF_RE.match(str(head.get("ref", "")))
        and login.endswith("[bot]")
    ):
        return False
    return not (_label_names(pr) & review_lane_refusing_labels(claim))


def review_lane_refusing_labels(claim):
    """The hold labels on which `review_items` refuses a PR outright, read from the LANE.

    One accessor so the cede predicate and its self-test consume the same set — a test that
    re-spells the labels would keep passing on the day the lane grows a fourth one. Fail-closed on
    a malformed export: anything that is not a non-empty string is dropped, and a set that ends up
    EMPTY raises rather than silently ceding everything, because "the lane refuses nothing" is not
    a state this program may infer from a broken import."""
    labels = {
        value
        for value in set(getattr(claim, "HUMAN_HOLD_PR_LABELS", ()) or ())
        | {getattr(claim, "MACHINE_PARK_PR_LABEL", None)}
        if isinstance(value, str) and value
    }
    if not labels:
        raise ResolverError(
            "dispatch-claim exports no review-lane hold labels, so which PRs that lane will "
            "refuse cannot be determined and none may be ceded to it"
        )
    return labels


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
        tmp = tempfile.mkdtemp(prefix="conflict-resolver-", dir=self.workspace)
        try:
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
        finally:
            _cleanup_tempdir(tmp)


@dataclass
class RepoCensus:
    """Per-repository population counts for ONE sweep.

    The point of this object is that ``actions=0 errors=0`` is ambiguous: it is what a run that
    repaired the whole fleet and a run that silently skipped a growing backlog both print. These
    counts separate the two, and every PR the sweep sees lands in exactly one ``skipped`` bucket
    or one outcome counter, so the buckets must sum to ``considered``.
    """

    repo: str
    considered: int = 0
    conflicting: int = 0
    conflicting_draft: int = 0
    selected: int = 0
    attempted: int = 0
    resolved: int = 0
    escalated: int = 0
    # --- PER-EXIT ACCOUNTING ------------------------------------------------------------------
    # `escalated` alone cannot say WHICH exit an escalation took, and the two exits being
    # indistinguishable in the output is why a timeout was reported as exhausted iteration for as
    # long as it was: every run said "escalated=N" and nothing said "N of them were timeouts".
    # These four split it two ways — by EXIT (which branch fired) and by CLASS (which label was
    # written) — because the cap makes them independent: a grace-window exit past
    # STUCK_UNPARK_MAX writes the human terminal, so exit alone no longer implies class.
    # `exit_two_head + exit_stuck_grace == parked_machine + parked_human == escalated` in every
    # run, which is the arithmetic that makes a silently-added third exit visible.
    exit_two_head: int = 0
    exit_stuck_grace: int = 0
    parked_machine: int = 0
    parked_human: int = 0
    # The machine exit actually firing, and the population still waiting on it.
    stuck_readmitted: int = 0
    stuck_park_stands: int = 0
    awaiting_author: int = 0
    # --- THE HOLD-OWNERSHIP SPLIT (#1191) -----------------------------------------------------
    # `held_human` is the population this program is CORRECT to leave alone; `held_released` is
    # the population it used to leave alone by mistake. Reporting only their sum is what made an
    # entirely self-inflicted exclusion indistinguishable from an entirely human one.
    held_human: int = 0
    held_released: int = 0
    # Conflicting PRs skipped into a state whose forward edge belongs to NOBODY (SKIP_OWNERSHIP).
    # The term that turns "attempted nothing" from a fact into a verdict.
    unowned: int = 0
    no_exit: int = 0
    errors: int = 0
    skipped: dict = field(default_factory=dict)

    def skip(self, key):
        self.skipped[key] = self.skipped.get(key, 0) + 1

    def as_dict(self):
        return {
            "repo": self.repo,
            "considered": self.considered,
            "conflicting": self.conflicting,
            "conflicting_draft": self.conflicting_draft,
            "conflicting_ready": self.conflicting - self.conflicting_draft,
            "selected": self.selected,
            "attempted": self.attempted,
            "resolved": self.resolved,
            "escalated": self.escalated,
            "exit_two_head": self.exit_two_head,
            "exit_stuck_grace": self.exit_stuck_grace,
            "parked_machine": self.parked_machine,
            "parked_human": self.parked_human,
            "stuck_readmitted": self.stuck_readmitted,
            "stuck_park_stands": self.stuck_park_stands,
            "awaiting_author": self.awaiting_author,
            "held_human": self.held_human,
            "held_released": self.held_released,
            "unowned": self.unowned,
            "no_exit": self.no_exit,
            "errors": self.errors,
            "skipped": dict(sorted(self.skipped.items())),
        }


def _aggregate_census(rows):
    total = {
        key: sum(row[key] for row in rows)
        for key in ("considered", "conflicting", "conflicting_draft", "conflicting_ready",
                    "selected", "attempted", "resolved", "escalated", "exit_two_head",
                    "exit_stuck_grace", "parked_machine", "parked_human", "stuck_readmitted",
                    "stuck_park_stands", "awaiting_author", "held_human", "held_released",
                    "unowned", "no_exit", "errors")
    }
    skipped = {}
    for row in rows:
        for key, count in row["skipped"].items():
            skipped[key] = skipped.get(key, 0) + count
    total["repos"] = len(rows)
    total["skipped"] = dict(sorted(skipped.items()))
    total["verdict"] = run_verdict(total)
    return total


# --- THE THREE-WAY RUN VERDICT (registry #1191) -----------------------------------------------
VERDICT_ACTED = "acted"
VERDICT_IDLE = "correctly-idle"
VERDICT_INERT = "INERT"
# The dimensions that constitute DOING SOMETHING. `selected` is included because the dependabot
# path consumes budget and posts without ever touching `attempted`; `stuck_readmitted` because
# clearing a park is forward motion even when no rebase followed it in the same run.
WORK_DIMENSIONS = ("attempted", "resolved", "escalated", "selected", "stuck_readmitted")


def run_verdict(total):
    """PURE. ``acted`` / ``correctly-idle`` / ``INERT`` from an aggregated census.

    This is the assertion #1191 is actually about. `attempted:0` is not by itself a fault — a
    sweep with no conflicting PRs, or one where every conflicting PR is genuinely held by a named
    owner, is doing exactly its job and must stay green, or the alarm gets muted and stops being
    read. The fault is `attempted:0` reached by EXCLUDING EVERYTHING: work done is zero AND at
    least one conflicting PR was dropped into a state whose forward edge belongs to nobody.

    The two terms are independent on purpose. Work alone cannot express it (a run that escalated
    one PR and silently swallowed thirty scores as work). Unowned alone cannot express it either
    (a run that repaired five PRs and left one unowned is a partial success, and the existing
    per-PR `no_exit` alarm already owns that case). Only the conjunction says "this run's entire
    output was exclusion", which is the state that ran 114 times reporting success."""
    if any(total.get(key, 0) for key in WORK_DIMENSIONS):
        return VERDICT_ACTED
    return VERDICT_INERT if total.get("unowned", 0) > 0 else VERDICT_IDLE


def render_census_summary(rows, total):
    """Markdown for ``$GITHUB_STEP_SUMMARY`` — the operator-facing form of the census."""
    lines = [
        "### conflict-resolver census",
        "",
        f"**verdict: `{total.get('verdict', run_verdict(total))}`** — "
        f"{total['conflicting']} conflicting PR(s) seen, "
        f"{total['attempted']} attempted, {total['unowned']} left with no owner.",
        "",
        "| repo | considered | conflicting (ready/draft) | attempted | resolved | escalated "
        "| exit: 2-head | exit: stuck-grace | park: machine | park: human | re-admitted "
        "| park stands | awaiting author | held: human | held: released | unowned | no exit "
        "| errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: "
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in [*rows, {**total, "repo": f"**all {total['repos']} repo(s)**"}]:
        lines.append(
            f"| {row['repo']} | {row['considered']} | "
            f"{row['conflicting']} ({row['conflicting_ready']}/{row['conflicting_draft']}) | "
            f"{row['attempted']} | {row['resolved']} | {row['escalated']} | "
            f"{row['exit_two_head']} | {row['exit_stuck_grace']} | "
            f"{row['parked_machine']} | {row['parked_human']} | "
            f"{row['stuck_readmitted']} | {row['stuck_park_stands']} | "
            f"{row['awaiting_author']} | {row['held_human']} | {row['held_released']} | "
            f"{row['unowned']} | {row['no_exit']} | {row['errors']} |"
        )
    if total["skipped"]:
        lines += ["", "Skip reasons:", ""]
        lines += [f"- `{key}`: {count}" for key, count in total["skipped"].items()]
    return "\n".join(lines) + "\n"


class ConflictResolver:
    def __init__(self, api, snapshot, claim, repos, bot_login, apply=False,
                 max_rebases=DEFAULT_REBASE_CAP, rebaser=None,
                 stuck_grace_hours=DEFAULT_STUCK_GRACE_HOURS,
                 no_exit_threshold=DEFAULT_NO_EXIT_ALERT_THRESHOLD,
                 clock=time.time, summary_path=None):
        self.api = api
        self.snapshot = snapshot
        self.claim = claim
        self.repos = repos
        self.bot_login = bot_login
        self.apply = apply
        self.max_rebases = max_rebases
        self.rebaser = rebaser
        self.stuck_grace_hours = stuck_grace_hours
        self.no_exit_threshold = no_exit_threshold
        self.clock = clock
        self.summary_path = summary_path
        self.actions = []
        self.errors = []
        self.rebases = 0
        self.budget_used = 0
        self.census = []
        self.current = RepoCensus("")
        # Whether the PR being processed right now has already been counted into the CONFLICTING
        # population. Read by `_skip` so ownership accounting cannot drift from the population it
        # describes: a skip before this flag is set is out-of-population by construction, and no
        # call site has to remember to say so.
        self._in_population = False
        # The machine-applied hard-exclusion holds released for the PR being processed. Read by
        # the grace-window exit, which must COMPLETE the class conversion it starts.
        self._released_holds = []

    def _record(self, kind, repo, number, detail=""):
        self.actions.append((kind, repo, number, detail))
        mode = "APPLY" if self.apply else "DRY-RUN"
        print(f"{mode} {repo}#{number}: {kind}{(': ' + detail) if detail else ''}")

    def _skip(self, repo, number, reason, key=None):
        key = key or reason
        self.current.skip(key)
        print(f"SKIP {repo}#{number}: {reason}")
        if not self._in_population:
            return
        owner = SKIP_OWNERSHIP.get(key)
        if owner is None:
            # A skip reason nobody classified. It is counted as UNOWNED and announced, because the
            # alternative default — assume somebody owns it — is exactly how 35 excluded PRs a
            # tick stayed invisible to an alarm written to catch them.
            print(f"::warning::conflict-resolver skip reason {key!r} has no entry in "
                  "SKIP_OWNERSHIP; counting it as unowned", file=sys.stderr)
            owner = OWNER_NONE
        if owner == OWNER_NONE:
            self.current.unowned += 1

    def _error(self, target, exc):
        cause = str(exc) or type(exc).__name__
        self.errors.append(f"{target}: {cause}")
        self.current.errors += 1
        print(f"::error::conflict-resolver {target}: {cause}", file=sys.stderr)

    def _no_exit(self, repo, number, reason):
        """A conflicting, unparked PR this sweep can neither repair nor escalate.

        Counted, annotated, and STICKY: nothing later in the sweep can retract it, so a
        clean repository scanned afterwards cannot launder the run back to green.
        """
        self.current.no_exit += 1
        print(
            f"::warning::conflict-resolver {repo}#{number} is conflicting with no automated "
            f"exit: {reason}",
            file=sys.stderr,
        )

    def _attempt_age_hours(self, records, head_sha):
        """Hours since the earliest attempt marker for ``head_sha``; None when unusable.

        A clock skew that puts the marker in the future yields 0.0, never a negative age, so a
        bad timestamp can never *shorten* the grace window into an instant escalation.
        """
        for attempted, epoch in records:
            if attempted != head_sha:
                continue
            if epoch is None:
                return None
            return max(0.0, (self.clock() - epoch) / 3600.0)
        return None

    def _post(self, repo, number, body):
        """THE ONE PLACE this program speaks under the App installation — and therefore the one
        place the reserved-marker sanitiser has to be (registry #1096).

        Every body posted here interpolates REPOSITORY-CONTROLLED text: `_handle_conflict` and
        `escalation_body` echo raw `git diff` pathnames (git does not C-quote under `-z`, so a
        pathname is arbitrary bytes), and those pathnames are chosen by whoever can push to the
        branch. Unsanitised, a crafted pathname carrying `<!-- sparq-park-reason:v1 class=capacity
        cause=partition -->` survived intact into a comment authored by the App — and
        park_policy.park_reason_records reads EVERY App-authored comment, not only park receipts.
        Authorship is not forgeable (a `[bot]` login is unregistrable); CONTENT was.

        The neutralisation is applied to the WHOLE BODY rather than field by field, because a
        per-field call is a defence the NEXT writer added to this file can silently skip — which is
        exactly how this program came to lack it while its sibling worker-pr.py had it. That is
        only sound because this program is not a `sparq-` writer at all: every durable marker it
        mints lives in the `conflict-resolver` namespace and passes through untouched. --self-test
        pins that (`the resolver's OWN markers survive the sanitiser`), so adding a `sparq-` marker
        here reds rather than being silently defanged on the way out."""
        if self.apply:
            self.api.comment(repo, number, _park_policy.neutralize_reserved_markers(body))

    def _count_exit(self, exit_kind, park_label):
        """Record ONE escalation against both of its axes — which exit fired, and which class it
        wrote. An unknown exit kind raises rather than defaulting into a bucket: a silently added
        third exit that quietly counted as one of these two is precisely the invisibility this
        census exists to remove."""
        if exit_kind == EXIT_TWO_HEAD:
            self.current.exit_two_head += 1
        elif exit_kind == EXIT_STUCK_GRACE:
            self.current.exit_stuck_grace += 1
        else:
            raise ResolverError(f"unknown conflict-resolver escalation exit {exit_kind!r}")
        if park_label == MACHINE_PARK_LABEL:
            self.current.parked_machine += 1
        else:
            self.current.parked_human += 1
        self.current.escalated += 1

    def _apply_park_label(self, repo, number, pr, park_label, exit_kind, conflicts):
        """Write the park label, honouring the sticky human-unpark veto (park_policy.py defect 2):
        a human who removed THIS label more recently than any application is never overridden, and
        an unreadable timeline never parks. The veto is checked against the label ACTUALLY being
        written, so the machine class is veto-gated exactly as the human class always was.

        ⚠️ THIS IS THE ONLY PLACE `_count_exit` MAY BE REACHED FROM, and it is reached only after
        a label the PR did not already carry has actually been added (registry #1191, review
        round 3). That is a STRUCTURAL answer to a defect that appeared THREE separate times in
        this one change — the grace-window exit, the veto-suppressed branch, and the over-cap
        branch each scored `escalated` on every tick while changing nothing, and `escalated` is a
        WORK dimension, so any one of them permanently mutes the INERT verdict this PR exists to
        add. Guarding them one at a time was losing: the third instance was reachable through
        `stuck_unpark_state` returning `(None, None)` over the cap, which the second guard
        structurally could not see.

        So the counter no longer depends on any caller remembering to guard. Both no-op shapes —
        the label is already live, or the veto refuses the write — return False WITHOUT counting,
        and each is a named skip so the PR is still accounted for. `_self_test` block (n5) asserts
        by AST that no other call site exists."""
        if park_label in _label_names(pr):
            # ALREADY HELD. The escalation has nothing to add, so it is not an escalation.
            self._skip(repo, number,
                       f"the {park_label} hold this escalation would write is already live",
                       "park-already-live")
            return False
        if self.apply:
            if _park_policy.park_vetoed(
                    repo, number, park_label,
                    lambda r, n: self.api.timeline(r, n),
                    is_human=lambda login: _is_human_maintainer(self.api, repo, login)):
                self._record(f"{park_label}-suppressed", repo, number,
                             "sticky human unpark (or unreadable timeline)")
                # A human who un-parked this PR OWNS it: the exit is theirs, not a missing one —
                # but it is THEIR exit, not a unit of work by this program.
                self._skip(repo, number,
                           "park suppressed by a sticky human unpark",
                           "park-suppressed-human-unpark")
                return False
            self.api.add_label(repo, number, park_label)
        self._count_exit(exit_kind, park_label)
        self._record(park_label, repo, number, ", ".join(conflicts))
        return True

    def _escalate_two_head(self, repo, pr, comments, conflicts):
        """THE TWO-DISTINCT-HEAD EXHAUSTION EXIT — and the ONLY exit that keeps `needs:user`.

        The machine attempted a mechanical rebase on more than one head and could not converge.
        That is a genuine human question, so the human terminal is the right class and nothing
        about it changes here."""
        number = pr["number"]
        bodies = _comment_bodies(_self_authored_comments(comments, self.bot_login))
        escalated_already = any(ESCALATION_MARKER in body for body in bodies)
        if escalated_already and HUMAN_PARK_LABEL in _label_names(pr):
            # ALREADY DELIVERED — not work, and it must not read as work (registry #1191).
            #
            # The hold-ownership split re-admits a PR this program itself parked, so a genuinely
            # exhausted one arrives here on EVERY tick. Re-posting is deduped and re-labelling is
            # a no-op, so the writes were already harmless; what is not harmless is counting an
            # unchanged PR as an escalation, because `escalated` is a WORK dimension and two such
            # PRs would score every future run as `acted` and permanently mute the INERT verdict.
            # A run whose entire output is re-asserting yesterday's escalations did nothing.
            #
            # The conjunction is load-bearing in the other direction too: marker-without-label is
            # the interrupted-mutation state the ordering below exists to converge, so it is NOT
            # caught here and still falls through to re-apply the label.
            self._skip(repo, number,
                       "two-distinct-head exhaustion already escalated and held",
                       "two-head-exhausted-stands")
            return
        if not escalated_already:
            self._post(repo, number, escalation_body(
                EXIT_TWO_HEAD, conflicts, len(attempt_heads(comments, self.bot_login)),
                HUMAN_PARK_LABEL, receipt=ESCALATION_MARKER))
        # Label last: if either mutation is interrupted, the next tick still sees an
        # unheld PR and converges the missing mutation without duplicating the loud marker.
        self._apply_park_label(repo, number, pr, HUMAN_PARK_LABEL, EXIT_TWO_HEAD, conflicts)

    def _escalate_stuck(self, repo, pr, comments, conflicts):
        """THE GRACE-WINDOW EXIT — a TIMEOUT, which takes the MACHINE class (registry #769).

        One recorded attempt, a head nobody pushed to, and a window that elapsed. Nothing here is
        a question anyone can answer: the machine tried ONCE and then waited. So this writes
        park_policy's machine-owned soft hold and mints the durable receipt whose (cause, head,
        gen) triple `_stuck_park_phase` clears on PROVEN CAUSE RECOVERY. The human terminal is
        reached only past STUCK_UNPARK_MAX — a flap, which is a different question.

        THE VETO IS CHECKED BEFORE THE COMMENT here, unlike the two-head exit above, and the
        asymmetry is deliberate rather than an oversight: that exit's comment is deduped
        once-ever on ESCALATION_MARKER and so can never repeat, while this one is deduped per
        GENERATION (it must be, or generation 2 is invisible and the cap is unreachable). Posting
        first would therefore mint a receipt for a park the veto then refuses to apply, spend a
        generation on it, and re-comment on the next tick — spamming a PR a human explicitly
        un-parked. groom's age hand-off checks the veto first for the same reason."""
        number = pr["number"]
        head = str((pr.get("head") or {}).get("sha", ""))
        if SAFE_SHA.fullmatch(head) is None:
            raise ResolverError(f"PR head SHA is malformed for {repo}#{number}")
        # ALREADY DELIVERED (registry #1191 review, blocking 1). The two-distinct-head exit got
        # this guard and this one did not, and the asymmetry rebuilt #1191 inside a new counter:
        # `_apply_park_label` -> `_count_exit` ran unconditionally, so a PR whose park was already
        # written scored `escalated` on EVERY tick forever. MEASURED over 8 simulated ticks on the
        # live stranded shape: from tick 4 the only write was a no-op label add GitHub discards,
        # and the run still returned `acted` / green — i.e. VERDICT_INERT could never fire on this
        # repository again. The alarm this PR exists to add would have muted itself permanently.
        #
        # The CONVERSION CLAUSE is the other half. A delivered park whose released human-class
        # holds are still live is the interrupted state of the demotion below, not a finished one,
        # so it falls through and converges rather than skipping — the same marker-without-label
        # reasoning the two-head exit uses, applied to a label PAIR.
        park_state, grant_state = stuck_unpark_state(comments, self.bot_login)
        if (park_state is not None and grant_state is None
                and stuck_park_label(park_state["gen"]) in _label_names(pr)):
            # Converge the demotion FIRST — never re-mint. Falling through to the write path
            # instead would recompute `generation` from the receipts already on record and burn a
            # fresh generation for what is pure convergence, which is the runaway this guard
            # exists to stop.
            self._demote_holds(repo, number, pr, stuck_park_label(park_state["gen"]))
            self._skip(repo, number,
                       f"grace-window park already delivered at generation {park_state['gen']}",
                       "stuck-park-already-delivered")
            return
        generation = stuck_park_generation(comments, self.bot_login)
        park_label = stuck_park_label(generation)
        receipt = stuck_receipt(STUCK_PARK_MARKER, head, generation)
        # A MACHINE PARK MUST NOT BE WRITTEN UNDER A HOLD IT CANNOT LIFT (review round 3, item 3).
        #
        # `_demotable_holds` can only drop HARD_EXCLUDE_LABELS this sweep proved machine-applied,
        # but `_stuck_park_phase` stands down on `human_owned_holds(EVERY live label)` — and those
        # sets are not nested: `human_owned_holds` matches ANY `needs:*`, while the exclusion set
        # is five specific labels. A PR carrying machine `needs:user` PLUS `needs:ec2` therefore
        # demotes out of reconcile's LIST population (it is fetched by label, so a demoted PR is
        # never read at all) while KEEPING a hold that kills this program's own exit — invisible
        # to both mechanisms at once, with `review:parked` left permanently orphaned once its
        # cause recovers. Population is 0 today; the shape is one `needs:*` label away.
        #
        # The refusal is deliberately narrower than widening what this program DELETES. Deleting
        # more labels to make its own park work is the resolver overriding holds it never proved
        # anything about; refusing to park is the resolver staying inside its remit.
        if park_label == MACHINE_PARK_LABEL:
            residual = _park_policy.human_owned_holds(
                set(_label_names(pr)) - set(self._demotable_holds(pr)))
            if residual:
                self._skip(repo, number,
                           f"machine park refused: human-class hold(s) {', '.join(residual)} "
                           "would survive the demotion and kill its exit",
                           "residual-human-class-hold")
                return
        if self.apply and _park_policy.park_vetoed(
                repo, number, park_label,
                lambda r, n: self.api.timeline(r, n),
                is_human=lambda login: _is_human_maintainer(self.api, repo, login)):
            # NOT an exit, and no longer counted as one. A human un-parked this PR, so they own
            # it — which is a SKIP with a named owner, exactly like the two-head stand-down. The
            # previous `_count_exit` here was the second unguarded mute path: it scored work every
            # tick while writing nothing at all.
            self._record(f"{park_label}-suppressed", repo, number,
                         "sticky human unpark (or unreadable timeline)")
            self._skip(repo, number,
                       "grace-window park suppressed by a sticky human unpark",
                       "park-suppressed-human-unpark")
            return
        bodies = _comment_bodies(_self_authored_comments(comments, self.bot_login))
        # A MACHINE park dedupes on its own receipt FINGERPRINT, not on "any escalation comment
        # ever": a PR that machine-parked, provably recovered, was re-admitted and then parked
        # AGAIN must mint a NEW receipt — otherwise generation 2 is invisible, the cap is never
        # reached, and the escalation to the human class never happens.
        if not any(receipt in body for body in bodies):
            self._post(repo, number, escalation_body(
                EXIT_STUCK_GRACE, conflicts, len(attempt_heads(comments, self.bot_login)),
                park_label,
                receipt=(receipt if park_label == MACHINE_PARK_LABEL
                         else f"{ESCALATION_MARKER}\n{receipt}"),
                generation=generation,
                # READ, never inferred from the generation: a generation is consumed by every
                # re-park however the label was cleared, so telling a maintainer the machine
                # already granted N re-admissions when the record shows none sends them hunting a
                # flap that never happened (registry #769, same finding).
                grants=len(stuck_receipts(comments, self.bot_login, STUCK_UNPARK_MARKER))))
        if self._apply_park_label(repo, number, pr, park_label, EXIT_STUCK_GRACE, conflicts):
            # PARK FIRST, THEN DEMOTE — the interruption residue must be BOTH labels, never
            # neither. Both-labels is a PR still held that the next tick converges; neither is a
            # PR this program silently un-held.
            self._demote_holds(repo, number, pr, park_label)

    def _demote_holds(self, repo, number, pr, park_label):
        """COMPLETE the class conversion: drop the machine-applied human-class holds this sweep
        released, now that a machine-owned park is live in their place.

        THE SECOND BLOCKING FINDING (registry #1191 review). Writing `review:parked` while leaving
        the machine-applied `needs:user` in place is not a conversion, it is an ADDITION — and
        `_stuck_park_phase` stands down entirely whenever `park_policy.human_owned_holds` matches,
        so the machine exit was dead from tick 1. Every subsequent tick then re-escalated, the
        receipts reached generation 3 inside ~40 minutes on the `1,21,41` cron, and
        reconcile-conflict-park reads generation > STUCK_UNPARK_MAX as `budget-exhausted` — a
        HUMAN TERMINAL that outranks even a fully recovered cause. Seven PRs the live census calls
        exit-reachable today would have become permanently human-terminal. A change that moves
        work from "refused early" to "refused forever" is a net loss against master.

        SCOPED TO THE LABELS THAT ACTUALLY BLOCK THE EXIT. Only holds this sweep proved
        machine-applied AND that `human_owned_holds` matches are dropped — so `trust-surface` and
        `trust:untrusted` survive untouched. They do not block the machine exit, and removing a
        trust classification is a different decision than un-doing a machine's own mis-park.

        Never fires for the human class: past STUCK_UNPARK_MAX the park label IS `needs:user`, and
        demoting there would delete the hold just written.

        ⚠️ THIS IS A POLICY WIDENING, AND IT IS NOT NEUTRAL (registry #1191 review round 3).
        Moving a PR from `needs:user` into `review:parked` moves it from reconcile-conflict-park's
        jurisdiction into this program's, and the two do NOT apply the same residual-hold rule.
        reconcile documents its own as "strictly WIDER than the shared one, never narrower" and
        refuses under `review:changes` deliberately; `_stuck_park_phase` gates on
        `park_policy.human_owned_holds`, which does not match `review:changes` at all. So on a PR
        carrying it the label survives the move but STOPS BEING CONSULTED. Live case: #781 — its
        exit is genuinely gained, and partly gained this way.

        The blast radius is bounded — the strongest thing reachable past this gate is ONE
        mechanical rebase, never a merge, never an arm — and the alternative (leaving the PR in a
        terminal nothing can clear) is worse. But it is a widening, not a free win, and it is
        recorded here rather than relied on quietly."""
        if park_label != MACHINE_PARK_LABEL:
            return []
        pending = self._demotable_holds(pr)
        for label in pending:
            if self.apply:
                self.api.remove_label(repo, number, label)
            self._record("hold-demoted", repo, number,
                         f"{label} was machine-applied and is replaced by {MACHINE_PARK_LABEL}")
        return pending

    def _demotable_holds(self, pr):
        """The released machine-applied holds still live on `pr` that would veto the machine
        exit — i.e. the intersection of what this sweep released with `human_owned_holds`."""
        live = _label_names(pr)
        return [label for label in _park_policy.human_owned_holds(self._released_holds)
                if label in live]

    def _clear_stuck_park(self, repo, number):
        if self.apply:
            self.api.remove_label(repo, number, MACHINE_PARK_LABEL)

    def _stuck_park_phase(self, repo, number, detail):
        """THE MACHINE EXIT of the grace-window park. Returns ``(status, detail)`` where status is
        ``"none"`` (no live park of ours), ``"cleared"`` or ``"stands"``.

        CAUSE-GATED, NEVER TIMED. `stuck_park_cause_recovered` reads the live PR: the head moving
        or the conflict resolving clears the park, and nothing else does. No branch here consults
        a clock, and that is the whole point of the class split — a hold whose only exit is more
        elapsed time is the human terminal wearing a machine label.

        RECEIPT-FIRST (#610's ordering): the un-park receipt is posted BEFORE the label is
        removed, so a crash between them leaves receipt-with-label — which the `grant is not None`
        branch converges on the next tick — never label-without-receipt, which would erase the
        re-admission from the durable record and let the same recovery be earned twice.

        EPISODE BINDING. `review:parked` is a shared multi-writer label, so its presence proves
        only that SOMEONE parked this PR. `stuck_unpark_state` answers None unless one of THIS
        program's own bot-authored park receipts is on record, so another mechanism's park is
        never cleared here — and, symmetrically, park_policy.CAUSE_GATED_PARK_OWNERS makes this
        park ineligible for dispatch-claim's sustained-fleet-health heuristic, whose only
        condition this class could ever satisfy is being old enough.

        A HUMAN-OWNED HOLD OUTRANKS THIS PHASE ENTIRELY (park_policy.human_owned_holds — the ONE
        rule, shared with capacity_park_admission's own refusal rather than re-derived). A PR
        wearing `needs:user` or `review:needs-user` alongside our machine park is a PR a human has
        taken, and no automatic path may act on it: this program's remit is its OWN park, not the
        maintainer's queue. It is also what keeps this change strictly forward-looking — the ten
        live PRs holding a machine-applied `needs:user` are untouched by construction, because
        they carry no receipt of ours AND they carry a human-owned hold."""
        labels = _label_names(detail)
        if MACHINE_PARK_LABEL not in labels:
            return "none", ""
        holds = _park_policy.human_owned_holds(labels)
        if holds:
            return "none", ""
        comments = self.api.comments(repo, number)
        park, grant = stuck_unpark_state(comments, self.bot_login)
        if park is None:
            # Not our episode, or a park already past the cap (which was written in the HUMAN
            # class and must never be automatically re-admitted). Either way: leave it alone.
            return "none", ""
        if grant is not None:
            self._clear_stuck_park(repo, number)
            self._record("stuck-park-converged", repo, number,
                         f"gen={park['gen']} head={park['head']}")
            self.current.stuck_readmitted += 1
            return "cleared", "converging an already-receipted re-admission"
        recovered, why = stuck_park_cause_recovered(park["cause"], detail, park["head"])
        if not recovered:
            self.current.stuck_park_stands += 1
            return "stands", why
        self._post(repo, number, (
            "> 🤖 SPARQ agent — the machine-owned grace-window park on this PR is cleared: "
            f"{why}. This is the CAUSE-GATED exit, not a timer — no amount of further waiting "
            "would have cleared it.\n\n"
            f"{stuck_receipt(STUCK_UNPARK_MARKER, park['head'], park['gen'])}"))
        self._clear_stuck_park(repo, number)
        self._record("stuck-park-readmitted", repo, number, why)
        self.current.stuck_readmitted += 1
        return "cleared", why

    def _handle_conflict(self, repo, pr, conflicts, comments):
        number = pr["number"]
        head = (pr.get("head") or {}).get("sha", "")
        heads = attempt_heads(comments, self.bot_login)
        if head in heads:
            # PRE-EXISTING DEAD BRANCH, and stated here so the next mutation sweep does not
            # re-flag it as an uncovered call site. `_handle_conflict` is reached ONLY from
            # `_process_pr`'s rebase leg, which every `head_sha in heads` branch returns before —
            # so by construction `head` is never already in `heads` here, and a `raise` in this
            # arm leaves the whole self-test suite green. It is defensive residue that predates
            # this change; deleting it is a separate, behaviour-touching decision and is not
            # folded into a PR whose remit is the class split.
            if len(heads) >= 2:
                self._escalate_two_head(repo, pr, comments, conflicts)
            else:
                self._skip(repo, number, "this head already has a recorded conflict attempt",
                           "duplicate-attempt-this-run")
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
            self._escalate_two_head(repo, pr, synthetic, conflicts)

    def _hold_ownership(self, repo, number, detail, label):
        """Who owns `label` on this PR: ``"human"``, ``"machine"`` or ``"unknown"``.

        THE EDGE THAT WAS CUT (registry #1191). The old predicate read the label NAME and inferred
        an actor from it. `_escalate_two_head` writes `needs:user`, so this program's own failures
        became indistinguishable from a person's decision, and every one of them permanently
        removed a PR from the population this program exists to drain. Measured on the live
        registry: 14 of 17 excluded conflicting PRs were held by a label the estate's own bot had
        applied, three by a person.

        TWO SURFACES, ASYMMETRIC AUTHORITY. The PR's own timeline must positively prove MACHINE
        ownership — human, absent, or unreadable all keep the hold. The source issue can only
        ESCALATE that answer to human, never rescue it to machine: a question a person asked on
        the issue is not answered by a bot re-labelling the PR a second later, and an issue with
        no such label proves nothing about the PR's. So the issue is consulted only when the PR
        already said machine, and any human application on any surface wins.

        ⚠️ WHAT "PROVEN HUMAN" ACTUALLY PROVES, stated plainly because the answer is weaker than
        the name (registry #1191 review). The probe is repo collaborator permission, and the
        maintainer account it resolves to is ALSO used by the fleet as a PAT. Measured on the
        live registry: all three holds this predicate calls human are, in fact, agent-applied
        through that account. So this separates "acted through the maintainer account" from
        "acted through a bot App identity" — NOT person from machine. The direction is
        conservative (it over-preserves, and every unprovable case also over-preserves), so it is
        safe; it is not, however, the distinction the words suggest, and `correctly-idle` staying
        green rests on it. Weakening the predicate to "fix" this would trade a safe imprecision
        for an unsafe one.

        THE ISSUE IS READ ACROSS ALL HARD-EXCLUSION LABELS, not just this one. Live case: #601
        carries a bot-applied `review:needs-user` while its source issue #583 carries a
        maintainer-applied `trust-surface` — a same-label-only check reads that as unheld and
        rebases under it.

        The tie/fail directions live in park_policy.label_application_ownership and are shared
        with groom, dispatch-claim and both reconcilers rather than restated here."""
        probe_broke = []

        def probe(_repo, target):
            return self.api.timeline(_repo, target)

        def is_human(login):
            return _is_human_maintainer(self.api, repo, login,
                                        on_failure=lambda who: probe_broke.append(who))

        def settle(state):
            # A FAILED MAINTAINER PROBE CANNOT ANSWER "machine". `probe_maintainer` collapses a
            # broken probe into not-human, which would turn a maintainer's own hold into an
            # admission. Anything unproven downgrades to UNKNOWN — which keeps the hold AND is
            # loud, rather than keeping it silently.
            if state == _park_policy.LABEL_OWNER_MACHINE and probe_broke:
                print(f"::warning::conflict-resolver could not verify the actor(s) who applied "
                      f"holds on {repo}#{number}; the hold stands", file=sys.stderr)
                return _park_policy.LABEL_OWNER_UNKNOWN
            return state

        state = _park_policy.label_application_ownership(
            repo, number, label, probe, is_human=is_human)
        if state != _park_policy.LABEL_OWNER_MACHINE:
            return settle(state)
        try:
            issues = sorted(self._groom_linked_issues(detail))
        except Exception as exc:  # noqa: BLE001 — an unreadable linkage proves nothing
            print(f"::warning::conflict-resolver could not read the source-issue linkage for "
                  f"{repo}#{number} ({exc}); the hold stands", file=sys.stderr)
            return _park_policy.LABEL_OWNER_UNKNOWN
        for issue in issues:
            if issue == number:
                continue
            try:
                issue_labels = _label_names(self.api.issue(repo, issue))
            except Exception as exc:  # noqa: BLE001 — an unreadable issue proves nothing
                # NOT "machine". The issue is the surface that can only ever ESCALATE the answer,
                # so failing to read it is failing to check the one place a human hold could be
                # hiding — the exact shape of a silent release (review finding, secondary 1).
                print(f"::warning::conflict-resolver could not read source issue "
                      f"{repo}#{issue} for {repo}#{number} ({exc}); the hold stands",
                      file=sys.stderr)
                return _park_policy.LABEL_OWNER_UNKNOWN
            for candidate in sorted(issue_labels & HARD_EXCLUDE_LABELS):
                issue_state = _park_policy.label_application_ownership(
                    repo, issue, candidate, probe, is_human=is_human)
                if issue_state == _park_policy.LABEL_OWNER_HUMAN:
                    print(f"HOLD {repo}#{number}: {candidate!r} is human-owned via source "
                          f"issue #{issue}")
                    return _park_policy.LABEL_OWNER_HUMAN
                if issue_state != _park_policy.LABEL_OWNER_MACHINE:
                    # THE SECOND SITE OF THE SAME RULE (review round 3). Fixing the issue's LABEL
                    # read left its TIMELINE read still turning a failed read into a `machine`
                    # answer. This candidate is LIVE on the issue and nothing can say who applied
                    # it, on the one surface that exists here to catch a human hold.
                    print(f"::warning::conflict-resolver cannot attribute {candidate!r} on source "
                          f"issue {repo}#{issue} for {repo}#{number}; the hold stands",
                          file=sys.stderr)
                    return _park_policy.LABEL_OWNER_UNKNOWN
        return settle(_park_policy.LABEL_OWNER_MACHINE)

    def _groom_linked_issues(self, detail):
        return _groom().linked_issue_numbers(detail)

    def _classify_holds(self, repo, number, detail, holds):
        """``(human_holds, unreadable_holds)`` for the live hard-exclusion labels on this PR."""
        human, unreadable = [], []
        for label in holds:
            state = self._hold_ownership(repo, number, detail, label)
            if state == _park_policy.LABEL_OWNER_HUMAN:
                human.append(label)
            elif state != _park_policy.LABEL_OWNER_MACHINE:
                unreadable.append(label)
        return human, unreadable

    def _process_pr(self, repo, default_branch, listed_pr):
        self._in_population = False
        self._released_holds = []
        number = listed_pr.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            self._skip(repo, "unknown", "invalid PR number in listing", "invalid-pr-number")
            return
        detail_url = f"{API_ROOT}/repos/{repo}/pulls/{number}"
        detail = self.snapshot.resolve_mergeable_detail(self.api.fetch, detail_url)
        if not isinstance(detail, dict):
            raise ResolverError(f"PR detail is malformed for {repo}#{number}")
        # THE MACHINE EXIT runs FIRST, before the mergeability classification, because one of the
        # two recovery facts is "the PR is no longer conflicting" — evaluating it after the
        # `not-conflicting` return would leave the park live on a PR with nothing left to park
        # for. It performs its own writes and returns a verdict; the SHORT-CIRCUIT is applied
        # below, after the conflicting/draft counting, so a standing park is still counted in the
        # population it belongs to.
        stuck_status, stuck_detail = self._stuck_park_phase(repo, number, detail)
        mergeable = detail.get("mergeable")
        if mergeable is not False:
            if mergeable is None:
                self._skip(repo, number, "mergeability is still computing",
                           "mergeability-computing")
            else:
                self._skip(repo, number, "base is not conflicting", "not-conflicting")
            return
        self.current.conflicting += 1
        self._in_population = True
        if detail.get("draft") is True:
            self.current.conflicting_draft += 1
        if stuck_status == "stands":
            # NOT a no-exit: this PR is held by a park whose exit is proven cause recovery, and
            # the census says so by name every tick (`stuck_park_stands`).
            self._skip(repo, number,
                       f"grace-window machine park stands: {stuck_detail}", "stuck-park-stands")
            return
        labels = _label_names(detail)
        holds = sorted(labels & HARD_EXCLUDE_LABELS)
        if holds:
            human, unreadable = self._classify_holds(repo, number, detail, holds)
            if human:
                self.current.held_human += 1
                self._skip(repo, number,
                           f"human-applied hold(s): {', '.join(human)}", "hard-exclusion-label")
                return
            if unreadable:
                # FAIL CLOSED, AND LOUD. Not proving a machine applied the hold is not permission
                # to rebase under it — but it is also not an exit, so it is counted as one of the
                # states this run could neither repair nor escalate. That combination is exactly
                # what was missing: the old code took the safe action and reported it as success.
                self.current.held_human += 1
                self._skip(repo, number,
                           f"hold ownership unreadable: {', '.join(unreadable)}",
                           "hold-ownership-unreadable")
                self._no_exit(repo, number,
                              f"the hold(s) {', '.join(unreadable)} cannot be attributed to a "
                              "human or a machine, so the exclusion stands with no owner")
                return
            self.current.held_released += 1
            self._released_holds = list(holds)
            self._record("hold-released", repo, number,
                         f"machine-applied hold(s) {', '.join(holds)} do not exclude")
        head = detail.get("head") or {}
        base = detail.get("base") or {}
        head_repo = (head.get("repo") or {}).get("full_name")
        base_repo = (base.get("repo") or {}).get("full_name")
        if head_repo != repo or base_repo != repo:
            # Out of scope by construction, not a broken edge: counted in the census, never a
            # run failure. Only states this program is SUPPOSED to drain can be no-exit.
            self._skip(repo, number, "fork PR (head/base repository differs)", "fork-pr")
            return
        if base.get("ref") != default_branch:
            self._skip(repo, number, "base branch is not the repository default branch",
                       "non-default-base")
            return
        head_sha = str(head.get("sha", ""))
        if SAFE_SHA.fullmatch(head_sha) is None:
            raise ResolverError(f"PR head SHA is malformed for {repo}#{number}")
        login = str((detail.get("user") or {}).get("login", ""))
        if login == DEPENDABOT_LOGIN:
            comments = self.api.comments(repo, number)
            marker = DEPENDABOT_MARKER.format(head=head_sha)
            if any(marker in body for body in _comment_bodies(comments)):
                self._skip(repo, number, "dependabot rebase already requested for this head",
                           "dependabot-already-requested")
                return
            if self.budget_used >= self.max_rebases:
                self._skip(repo, number,
                           f"per-run rebase request cap ({self.max_rebases}) reached",
                           "rebase-cap-reached")
                return
            self.budget_used += 1
            self.current.selected += 1
            self._post(repo, number, f"@dependabot rebase\n\n{marker}")
            self._record("dependabot-comment", repo, number, head_sha)
            return
        if owned_by_review_rebase_lane(detail, repo, self.claim):
            self._skip(
                repo,
                number,
                "review-lane worker PR belongs to the needs-rebase/rebase fix lane",
                "review-lane-owned",
            )
            return
        comments = self.api.comments(repo, number)
        records = attempt_records(comments, self.bot_login)
        heads = [attempted for attempted, _ in records]
        if head_sha in heads:
            if len(heads) >= 2:
                self._escalate_two_head(
                    repo, detail, comments, prior_conflicting_files(comments, self.bot_login)
                )
                return
            # THE GRACE WINDOW (issue #753). One attempt, head unmoved. The two-distinct-head rule
            # can never fire here on its own, so the WAIT is bounded on the clock: inside the
            # window the author may still push; past it, waiting longer has stopped being the
            # plan. What the clock decides is WHEN TO STOP WAITING — and nothing else. It does not
            # decide the CLASS (that is stuck_park_label, on the re-admission cap) and it is not
            # the evidence that ENDS the resulting hold (that is stuck_park_cause_recovered, on
            # the head or the conflict). A window elapsing is a TIMEOUT, and registry #769's
            # finding is that a timeout is not a human question.
            age_hours = self._attempt_age_hours(records, head_sha)
            if age_hours is None:
                self._skip(repo, number,
                           "recorded conflict attempt has no usable timestamp",
                           "attempt-timestamp-unusable")
                self._no_exit(repo, number,
                              "the recorded attempt marker carries no parseable created_at, so "
                              "the grace window cannot be evaluated")
                return
            if age_hours >= self.stuck_grace_hours:
                self._record("stuck-attempt-escalation", repo, number,
                             f"single attempt {age_hours:.1f}h old "
                             f"(grace {self.stuck_grace_hours}h)")
                self._escalate_stuck(
                    repo, detail, comments, prior_conflicting_files(comments, self.bot_login)
                )
                return
            self.current.awaiting_author += 1
            self._skip(repo, number,
                       f"single conflict attempt is {age_hours:.1f}h old; author grace window "
                       f"is {self.stuck_grace_hours}h",
                       "awaiting-author-grace")
            return
        # NO ESCALATION ON A HEAD THIS PROGRAM HAS NEVER TRIED (registry #1191).
        #
        # Reaching here means `head_sha not in heads` — the author has PUSHED SINCE the last
        # recorded attempt. The removed branch escalated anyway whenever two historical heads
        # existed, so "two distinct heads once failed to converge" became a permanent refusal to
        # try a third, however fresh, and the exhaustion the escalation asserts was never
        # re-tested. It also made the resulting hold unreleasable in principle:
        # reconcile-conflict-park refuses `two-head-exhaustion` precisely because a released PR
        # would return straight here and be re-parked without an attempt.
        #
        # The escalation is not deleted — `_handle_conflict` still fires it, one line later,
        # AFTER this head has actually been rebased and actually conflicted. The exit now
        # asserts something that was measured in this run rather than inherited from an old one.
        if self.budget_used >= self.max_rebases:
            self._skip(repo, number,
                       f"per-run mechanical rebase cap ({self.max_rebases}) reached",
                       "rebase-cap-reached")
            return
        self.budget_used += 1
        self.current.selected += 1
        self.rebases += 1
        self.current.attempted += 1
        result = self.rebaser(repo, detail, default_branch)
        if result.outcome == "conflict":
            self._handle_conflict(repo, detail, result.conflicting_files, comments)
        elif result.outcome == "unchanged":
            self._skip(repo, number, "local rebase was a no-op; nothing to push",
                       "rebase-no-op")
        elif result.outcome == "clean":
            self.current.resolved += 1
            body = (
                "> 🤖 SPARQ agent — this conflicting PR was mechanically auto-rebased "
                f"onto `{default_branch}`. CI, not this privileged job, validates semantics.\n\n"
                f"<!-- conflict-resolver rebased head={result.old_head} -->"
            )
            self._post(repo, number, body)
            self._record("mechanical-rebase", repo, number, f"{result.old_head} -> {result.new_head}")
        else:
            raise ResolverError(f"unknown rebase outcome for {repo}#{number}")

    def _publish_census(self, rows, total):
        print(f"CENSUS-TOTAL {json.dumps(total, separators=(',', ':'), sort_keys=True)}")
        if not self.summary_path:
            return
        try:
            with open(self.summary_path, "a", encoding="utf-8") as handle:
                handle.write(render_census_summary(rows, total))
        except OSError as exc:
            # The census is already on stdout; a summary-file failure must not change the verdict.
            print(f"::warning::conflict-resolver could not write the step summary: {exc}",
                  file=sys.stderr)

    def run(self):
        for repo in self.repos:
            action_start = len(self.actions)
            budget_start = self.budget_used
            rebase_start = self.rebases
            error_start = len(self.errors)
            self.current = RepoCensus(repo)
            try:
                if not self.api.has_token(repo):
                    print(f"SKIP {repo}: no target App token was minted for owner")
                    self.current.skip("no-owner-token")
                    continue
                metadata = self.api.repository(repo)
                default_branch = metadata.get("default_branch") if isinstance(metadata, dict) else None
                if not _valid_branch(str(default_branch or "")):
                    raise ResolverError(f"repository default branch is unsafe for {repo}")
                pulls = self.api.pulls(repo)
                self.current.considered = len(pulls)
                print(f"SCAN {repo}: {len(pulls)} open PR(s), default={default_branch}")
                for pr in pulls:
                    try:
                        self._process_pr(repo, default_branch, pr)
                    except ResolverError as exc:
                        number = pr.get("number", "unknown") if isinstance(pr, dict) else "unknown"
                        self._error(f"{repo}#{number}", exc)
            # Repository isolation is deliberately broad: an unexpected client/data error in
            # one target must be loud and make the final status fail, but must not starve later
            # policy targets. Process-control exceptions still propagate normally.
            except Exception as exc:
                self._error(repo, exc)
            finally:
                # Appended UNCONDITIONALLY, including on the failure and no-token paths: a
                # repository missing from the census would be a state exit with no record.
                self.census.append(self.current.as_dict())
                print(
                    f"SUMMARY repo={repo} mode={'apply' if self.apply else 'dry-run'} "
                    f"actions={len(self.actions) - action_start} "
                    f"rebase-requests={self.budget_used - budget_start} "
                    f"mechanical-rebases={self.rebases - rebase_start} "
                    f"errors={len(self.errors) - error_start}"
                )
                print(
                    "CENSUS "
                    + json.dumps(self.census[-1], separators=(",", ":"), sort_keys=True)
                )
        total = _aggregate_census(self.census)
        print(
            f"SUMMARY mode={'apply' if self.apply else 'dry-run'} actions={len(self.actions)} "
            f"rebase-requests={self.budget_used}/{self.max_rebases} "
            f"mechanical-rebases={self.rebases} errors={len(self.errors)}"
        )
        self._publish_census(self.census, total)
        # The population alarm. A per-run exit code cannot express "the backlog is growing", so
        # it expresses the thing this program is actually accountable for instead: how many
        # conflicting PRs it left in a state with no forward edge. Both terms are sticky — a
        # later clean repository adds zero and can never subtract an earned failure.
        if total["no_exit"] > self.no_exit_threshold:
            print(
                f"::error::conflict-resolver left {total['no_exit']} conflicting pull "
                f"request(s) with no automated exit (threshold {self.no_exit_threshold}); "
                f"{total['conflicting_ready']} ready + {total['conflicting_draft']} draft "
                f"conflicting PR(s) were seen across {total['repos']} repository/ies",
                file=sys.stderr,
            )
        # THE INERTNESS ALARM (registry #1191). Distinct from the per-PR no-exit alarm above, and
        # necessarily so: this one is about the RUN. It is the assertion that 114 consecutive
        # green runs could not make, and its whole value is that `attempted:0` no longer has one
        # rendering — the verdict says which of the three things a zero-attempt run was.
        verdict = total["verdict"]
        print(f"VERDICT {verdict}")
        if verdict == VERDICT_INERT:
            print(
                f"::error::conflict-resolver is INERT: it attempted, escalated and repaired "
                f"NOTHING while {total['conflicting']} conflicting pull request(s) were seen "
                f"({total['conflicting_ready']} ready + {total['conflicting_draft']} draft) and "
                f"{total['unowned']} of them were skipped into a state no person, lane or timer "
                f"owns. Skip reasons: {json.dumps(total['skipped'], sort_keys=True)}",
                file=sys.stderr,
            )
        return 1 if (self.errors
                     or total["no_exit"] > self.no_exit_threshold
                     or verdict == VERDICT_INERT) else 0


def _self_test():
    from contextlib import redirect_stderr, redirect_stdout
    from copy import deepcopy
    from io import StringIO
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

    # A fixed wall clock so every age assertion below is exact rather than flaky.
    base_now = 1_800_000_000.0
    grace = 6.0

    def iso(epoch):
        return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def pull(number, head, *, labels=(), author="alice", head_repo=None, ref=None,
             owner_repo=repo, draft=False):
        return {
            "number": number,
            "state": "open",
            "draft": draft,
            "mergeable": False,
            "labels": [{"name": label} for label in labels],
            "user": {"login": author},
            "head": {
                "sha": head,
                "ref": ref or f"topic-{number}",
                "repo": {"full_name": head_repo or owner_repo},
            },
            "base": {
                "sha": base_sha,
                "ref": "main",
                "repo": {"full_name": owner_repo},
            },
        }

    def attempt_comment(head, created_at):
        """A durable attempt marker exactly as _handle_conflict writes one."""
        return {
            "body": f"<!-- conflict-resolver attempt=1 head={head} -->\n"
                    "- conflict-file: \"src/value.py\"",
            "user": {"login": bot_login},
            **({} if created_at is None else {"created_at": created_at}),
        }

    class FakeAPI:
        def __init__(self, pulls, sequences=None, timelines=None, now=base_now, issues=None):
            self.tokens = {"example": "test-token"}
            self.now = now
            # Source ISSUES, by number, for their live label set. `issue_labels=None` means the
            # issue read RAISES — the unreadable-source-issue path, which must never read as
            # machine-owned (review finding, secondary 1).
            self.issue_rows = dict(issues or {})
            self.prs = {pr["number"]: deepcopy(pr) for pr in pulls}
            self.sequences = {number: [deepcopy(value) for value in values]
                              for number, values in (sequences or {}).items()}
            self.comment_rows = {pr["number"]: [] for pr in pulls}
            self.labels_added = []
            self.labels_removed = []
            # THE ORDERED MUTATION LOG. Without it this fixture cannot express an ORDERING
            # property at all: `comment_rows` and `labels_removed` are separate lists, so
            # "the receipt was posted BEFORE the label was deleted" and "…after" produce
            # byte-identical state and no assertion over them can tell the two apart.
            # MEASURED (review round 1): inverting `_stuck_park_phase`'s receipt-first ordering
            # left the WHOLE 44-script suite green, and the two checks credited with killing it
            # were in fact killed by a DIFFERENT mutant — deleting the `_post` outright, i.e. a
            # receipt never minted rather than a receipt minted late. That is #594's stale-SHA
            # stub again: a fixture that cannot express the property it is credited with testing.
            # One interleaved log, appended by every mutating entry point, closes it.
            self.events = []
            self.timelines = {number: [deepcopy(event) for event in events]
                              for number, events in (timelines or {}).items()}

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

        def issue(self, _repo, number):
            if number in self.issue_rows and self.issue_rows[number] is None:
                raise ResolverError(f"issue {number} is unreadable")
            return {"number": number,
                    "labels": [{"name": name}
                               for name in self.issue_rows.get(number, ())]}

        def timeline(self, _repo, number):
            return deepcopy(self.timelines.get(number, []))

        def request(self, method, url, body=None):
            # The strict maintainer probe (park-policy hygiene finding): jeswr is a repo
            # admin; everyone else — bots, outsiders, unverifiable actors — is not.
            if method == "GET" and "/collaborators/" in url and url.endswith("/permission"):
                login = url.rsplit("/", 2)[-2]
                return {"permission": "admin" if login == "jeswr" else "none"}
            raise AssertionError(f"unexpected FakeAPI request: {method} {url}")

        def comment(self, _repo, number, body):
            # The event carries a COARSE KIND, not the whole body: an ordering assertion that
            # pinned prose would go red on any wording change and would then be "fixed" by
            # loosening it, which is how an ordering guard quietly stops guarding ordering.
            kind = ("unpark-receipt" if STUCK_UNPARK_MARKER in body
                    else "park-receipt" if STUCK_PARK_MARKER in body
                    else "escalation" if ESCALATION_MARKER in body
                    else "comment")
            self.events.append((number, "comment", kind))
            self.comment_rows[number].append(
                {"body": body, "user": {"login": bot_login}, "created_at": iso(self.now)}
            )

        def add_label(self, _repo, number, label):
            self.events.append((number, "add-label", label))
            self.labels_added.append((number, label))
            names = _label_names(self.prs[number])
            if label not in names:
                self.prs[number].setdefault("labels", []).append({"name": label})
                # A REAL label add MINTS A TIMELINE EVENT, and this fake must too now that hold
                # OWNERSHIP is read from the timeline (#1191). Without it a label this program
                # wrote reads back as unattributable on the very next tick, so a multi-tick
                # fixture measures the fake's omission instead of the program's behaviour.
                self.timelines.setdefault(number, []).append(
                    {"event": "labeled", "label": {"name": label},
                     "actor": {"login": bot_login}, "created_at": iso(self.now)})

        def remove_label(self, _repo, number, label):
            self.events.append((number, "remove-label", label))
            self.labels_removed.append((number, label))
            self.prs[number]["labels"] = [
                row for row in self.prs[number].get("labels") or []
                if (row.get("name") if isinstance(row, dict) else row) != label
            ]

        def set_head(self, number, head):
            self.prs[number]["head"]["sha"] = head

        def set_mergeable(self, number, value):
            self.prs[number]["mergeable"] = value

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
    #
    # #1191 SPLIT THIS ROW IN THREE, and the reason is the reason this block existed at all: the
    # old fixture gave these PRs NO timeline, so it proved "a label named `needs:user` excludes"
    # and was silent on WHO applied it. That silence is the defect — the estate's own bot applied
    # 14 of the 17 live holds. The label events below are therefore load-bearing fixture data, not
    # decoration: `jeswr` is the fixture's only repo admin, so a human application is exactly one
    # that names him, and (a2)/(a3) drive the other two ownership classes.
    def labelled_by(login, label, at=None):
        return [{"event": "labeled", "label": {"name": label},
                 "actor": {"login": login}, "created_at": iso(at if at is not None else base_now)}]

    excluded = [
        pull(1, "1" * 40, labels=("needs:user",)),
        pull(2, "2" * 40, labels=("trust-surface",)),
        pull(3, "3" * 40, head_repo="fork/repo"),
        pull(4, "4" * 40, labels=("review:needs-user",)),
        pull(5, "5" * 40, labels=("needs:design",)),
        pull(6, "6" * 40, labels=("trust:untrusted",)),
    ]
    api = FakeAPI(excluded, timelines={
        1: labelled_by("jeswr", "needs:user"),
        2: labelled_by("jeswr", "trust-surface"),
        4: labelled_by("jeswr", "review:needs-user"),
        5: labelled_by("jeswr", "needs:design"),
        6: labelled_by("jeswr", "trust:untrusted"),
    })
    rebaser = FakeRebaser()
    resolver = ConflictResolver(api, snapshot, claim, [repo], bot_login, True, 5, rebaser)
    excluded_rc = resolver.run()
    excluded_row = resolver.census[0]
    check(
        "HUMAN-applied hard labels and a fork are never rebased — and the run stays GREEN, "
        "because every one of them has a named owner",
        (rebaser.calls, excluded_rc, excluded_row["held_human"], excluded_row["held_released"],
         excluded_row["unowned"], excluded_row["no_exit"],
         _aggregate_census(resolver.census)["verdict"]),
        ([], 0, 5, 0, 0, 0, VERDICT_IDLE),
    )

    # (a2) THE EDGE THAT WAS CUT (#1191). The SAME six PRs, with the SAME labels, applied by the
    # SAME bot this program runs as — and now every one of them is a candidate. This is the
    # marquee claim of the change, so it is asserted on the rebaser call list (what the program
    # actually DID), not on a census counter. Restore the label-name-only predicate in
    # `_process_pr` — `if holds: skip` — and this row goes red with an empty call list.
    machine_api = FakeAPI(excluded, timelines={
        1: labelled_by(bot_login, "needs:user"),
        2: labelled_by(bot_login, "trust-surface"),
        4: labelled_by(bot_login, "review:needs-user"),
        5: labelled_by(bot_login, "needs:design"),
        6: labelled_by(bot_login, "trust:untrusted"),
    })
    machine_rebaser = FakeRebaser()
    machine_resolver = ConflictResolver(
        machine_api, snapshot, claim, [repo], bot_login, True, 5, machine_rebaser)
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        machine_rc = machine_resolver.run()
    machine_row = machine_resolver.census[0]
    check(
        "[#1191] the SAME hard labels applied by THIS PROGRAM'S OWN BOT do not exclude: all five "
        "are rebased, and the fork — which no timeline can re-classify — still is not",
        (sorted(number for _r, number, _h in machine_rebaser.calls), machine_rc,
         machine_row["held_human"], machine_row["held_released"],
         machine_row["skipped"].get("hard-exclusion-label"),
         machine_row["skipped"].get("fork-pr"),
         _aggregate_census(machine_resolver.census)["verdict"]),
        ([1, 2, 4, 5, 6], 0, 0, 5, None, 1, VERDICT_ACTED),
    )

    # (a3) THE THIRD STATE, and the one the boolean `label_application_machine_owned` cannot
    # express. A hold NOBODY can attribute — no `labeled` event, or an unreadable timeline — keeps
    # the PR excluded (the safe action, unchanged) but is NOT silent: it has no proven owner, so
    # it is a no-exit and the run goes RED. This is the exact combination that was missing for 114
    # runs — the safe action reported as success. Make `_classify_holds` treat UNKNOWN as human
    # (drop the `unreadable` arm) and this row goes red on rc, `unowned` and `no_exit` together.
    unknown_api = FakeAPI([pull(11, "1" * 40, labels=("needs:user",))])   # no timeline at all
    unknown_rebaser = FakeRebaser()
    unknown_resolver = ConflictResolver(
        unknown_api, snapshot, claim, [repo], bot_login, True, 5, unknown_rebaser)
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        unknown_rc = unknown_resolver.run()
    unknown_row = unknown_resolver.census[0]
    check(
        "[#1191] a hold that can be attributed to NEITHER a human NOR a machine keeps the PR "
        "excluded AND reds the run: fail-closed, but never silent",
        (unknown_rebaser.calls, unknown_rc, unknown_api.labels_added,
         unknown_row["skipped"].get("hold-ownership-unreadable"),
         unknown_row["unowned"], unknown_row["no_exit"],
         _aggregate_census(unknown_resolver.census)["verdict"]),
        ([], 1, [], 1, 1, 1, VERDICT_INERT),
    )

    # (a3b) [#1849] THE SAME THIRD STATE, reached by the shape that used to read as PERMISSION.
    # The hold here HAS a `labeled` event; its actor is simply nobody this program can classify —
    # not this bot, and not a maintainer (the collaborator probe answers `none` for them). Until
    # park_policy owned the attributability quantifier that combination answered MACHINE, and (a2)
    # says machine alone is admission: this PR was REBASED under a hold nobody can attribute, at
    # rc=0 and in silence. It is now the same fail-closed, loud no-exit as (a3).
    stranger_api = FakeAPI([pull(19, "1" * 40, labels=("needs:user",))],
                           timelines={19: labelled_by("some-service", "needs:user")})
    stranger_rebaser = FakeRebaser()
    stranger_resolver = ConflictResolver(
        stranger_api, snapshot, claim, [repo], bot_login, True, 5, stranger_rebaser)
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        stranger_rc = stranger_resolver.run()
    stranger_row = stranger_resolver.census[0]
    check(
        "[#1849] a hold applied by an actor who is NEITHER this bot NOR a maintainer is not "
        "permission either: the PR is not rebased, and the run reds as a no-exit instead of "
        "passing quietly",
        (stranger_rebaser.calls, stranger_rc, stranger_api.labels_added,
         stranger_row["skipped"].get("hold-ownership-unreadable"),
         stranger_row["unowned"], stranger_row["no_exit"],
         _aggregate_census(stranger_resolver.census)["verdict"]),
        ([], 1, [], 1, 1, 1, VERDICT_INERT),
    )

    # (a4) THE OTHER SURFACE. The PR's own `needs:user` is bot-applied — machine-owned, and (a2)
    # says that alone is admission — but a PROVEN HUMAN applied the same label to the SOURCE ISSUE
    # the PR body closes. A question a person asked on the issue is not answered by a bot
    # re-labelling the PR, so the hold stands. Drop the source-issue leg of `_hold_ownership` and
    # this row goes red: the PR is rebased under the person holding it.
    issue_held = pull(12, "1" * 40, labels=("needs:user",))
    issue_held["body"] = "> 🤖 SPARQ agent\n\nCloses #4242"
    # #1191 review, secondary finding: the issue is read across EVERY hard-exclusion label, not
    # only the PR's own. The live miss this closes is #601 — a bot-applied `review:needs-user` on
    # the PR whose source issue #583 carries a maintainer-applied `trust-surface`. So the issue
    # here holds a DIFFERENT label from the PR's, and a same-label-only check rebases under it.
    issue_api = FakeAPI([issue_held], timelines={
        12: labelled_by(bot_login, "needs:user"),
        4242: labelled_by("jeswr", "trust-surface"),
    }, issues={4242: ("trust-surface",)})
    issue_rebaser = FakeRebaser()
    issue_resolver = ConflictResolver(
        issue_api, snapshot, claim, [repo], bot_login, True, 5, issue_rebaser)
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        issue_rc = issue_resolver.run()
    issue_row = issue_resolver.census[0]
    check(
        "[#1191] a bot-applied hold on the PR is still HUMAN-owned when a person applied a "
        "DIFFERENT hard-exclusion label to the SOURCE ISSUE — the issue may escalate the answer, "
        "never rescue it",
        (issue_rebaser.calls, issue_rc, issue_row["held_human"], issue_row["held_released"],
         issue_row["skipped"].get("hard-exclusion-label")),
        ([], 0, 1, 0, 1),
    )
    # ...and the CONTROL, which is what stops (a4) passing for the trivial reason that any linked
    # issue blocks: same PR, same linkage, the issue's label applied by the BOT. Now it rebases.
    issue_bot_api = FakeAPI([issue_held], timelines={
        12: labelled_by(bot_login, "needs:user"),
        4242: labelled_by(bot_login, "trust-surface"),
    }, issues={4242: ("trust-surface",)})
    issue_bot_rebaser = FakeRebaser()
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        ConflictResolver(issue_bot_api, snapshot, claim, [repo], bot_login, True, 5,
                         issue_bot_rebaser).run()
    check(
        "[#1191] ...control: the same linked issue held by the BOT does not block the rebase, so "
        "(a4) is about the ACTOR and not merely about having a linked issue",
        [number for _r, number, _h in issue_bot_rebaser.calls],
        [12],
    )

    # (a5) THE INSTANT TIE, newly load-bearing. `park_policy.label_application_ownership` resolves
    # a same-second human/machine tie toward HUMAN-owned, and until #1191 nothing in this repo
    # exercised that arm — MEASURED: deleting it left BOTH this suite and park_policy's own suite
    # fully green. It stopped being a nicety when this program began ADMITTING on the answer:
    # timestamps here are whole seconds, the live escalation pattern writes a label within one
    # second of an attempt, and a tie that resolved toward machine would rebase under a person who
    # labelled in that same second. Re-point the human event's actor at `bot_login` to see the row
    # move; delete the tie rule in park_policy and it goes red.
    tie_api = FakeAPI([pull(14, "1" * 40, labels=("needs:user",))], timelines={
        14: labelled_by(bot_login, "needs:user") + labelled_by("jeswr", "needs:user"),
    })
    tie_rebaser = FakeRebaser()
    tie_resolver = ConflictResolver(
        tie_api, snapshot, claim, [repo], bot_login, True, 5, tie_rebaser)
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        tie_resolver.run()
    check(
        "[#1191] a human and the bot applying the hold in the SAME SECOND resolves to "
        "HUMAN-owned — the tie never rebases under the person",
        (tie_rebaser.calls, tie_resolver.census[0]["held_human"],
         tie_resolver.census[0]["held_released"]),
        ([], 1, 0),
    )

    # (a6) THE INERT VERDICT REDS THE RUN ON ITS OWN. MEASURED, and it is the survivor that made
    # this row exist: removing `or verdict == VERDICT_INERT` from `run()`'s return expression left
    # the whole suite green, because every reachable unowned skip today ALSO fires the per-PR
    # `_no_exit` alarm and that alarm was carrying the exit code. The two alarms answer different
    # questions and the run-level one has to stand up unassisted — a skip reason added later with
    # no owner does NOT fire `_no_exit`. So this drives exactly that: a conflicting PR whose skip
    # key is absent from the taxonomy, `no_exit == 0`, and the run red anyway.
    lonely = ConflictResolver(FakeAPI([pull(15, "1" * 40, head_repo="fork/repo")]),
                              snapshot, claim, [repo], bot_login, True, 5, FakeRebaser())
    with patch.dict(SKIP_OWNERSHIP,
                    {key: value for key, value in SKIP_OWNERSHIP.items() if key != "fork-pr"},
                    clear=True):
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            lonely_rc = lonely.run()
    check(
        "[#1191] the INERT verdict reds the run BY ITSELF, with no per-PR no-exit alarm firing",
        (lonely_rc, lonely.census[0]["no_exit"], lonely.census[0]["unowned"],
         _aggregate_census(lonely.census)["verdict"]),
        (1, 0, 1, VERDICT_INERT),
    )

    worker = pull(
        7, "7" * 40, author=bot_login, ref="sparq-agent/issue-7-1-1"
    )
    api_worker = FakeAPI([worker])
    worker_rebaser = FakeRebaser()
    ConflictResolver(
        api_worker, snapshot, claim, [repo], bot_login, True, 5, worker_rebaser
    ).run()
    check("needs-rebase worker lane is never double-owned", worker_rebaser.calls, [])

    # --- [registry #1294] THE CEDE IS ONLY SOUND WHERE THE LANE ADMITS ------------------------
    # The row directly above proves the hand-over HAPPENS. Nothing proved it happened only to PRs
    # the lane takes, and on the live fleet it did not: 20 of 20 ceded PRs carried a label
    # `review_items` refuses outright, so `--max-rebases 5` was being spent on nobody while the
    # dispatcher warned "ZERO needs-rebase repair item(s) were enumerated" on the same board.
    #
    # DRIVEN FROM THE LANE'S OWN SET, not a literal list. A test that re-spelled the three labels
    # would keep passing on the day `review_items` grows a fourth hold — the exact drift that
    # produced this defect. Every label the lane refuses is asserted in BOTH directions: carrying
    # it must reach the rebaser (this program owns the PR), and the identical PR without it must
    # be ceded (the hand-over still works). A one-directional row passes for a predicate that
    # simply stopped ceding anything.
    refusing = review_lane_refusing_labels(claim)
    check("[#1294] the refusing set is the lane's own three hold labels",
          sorted(refusing), sorted({"needs:user", "review:needs-user", "review:parked"}))
    ceded, owned = [], []
    for index, hold in enumerate(sorted(refusing)):
        held_pull = pull(700 + index, f"{index}" * 40, author=bot_login,
                         ref=f"sparq-agent/issue-{700 + index}-1-1", labels=(hold,))
        clean_pull = pull(750 + index, f"{index}" * 40, author=bot_login,
                          ref=f"sparq-agent/issue-{750 + index}-1-1")
        if owned_by_review_rebase_lane(held_pull, repo, claim):
            ceded.append(hold)
        if not owned_by_review_rebase_lane(clean_pull, repo, claim):
            owned.append(hold)
    check("[#1294] NO label the review lane refuses is ceded to it", ceded, [])
    check("[#1294] ...and removing that label restores the hand-over", owned, [])
    # END TO END, because the predicate is not the behaviour. A worker-shaped PR carrying a
    # MACHINE-applied `needs:user` — the live shape of 11 of the 20 — must now reach the rebaser
    # through the whole `run()` path (hold classification, ownership attribution, cede decision),
    # and its skip must NOT be `review-lane-owned`. `labelled_by(bot_login, ...)` is what makes
    # the hold machine-applied; a human-applied one still returns at `hard-exclusion-label`, which
    # the (a) block above pins.
    held_worker = pull(8, "8" * 40, author=bot_login, ref="sparq-agent/issue-8-1-1",
                       labels=("needs:user",))
    held_api = FakeAPI([held_worker], timelines={8: labelled_by(bot_login, "needs:user")})
    held_rebaser = FakeRebaser()
    held_resolver = ConflictResolver(
        held_api, snapshot, claim, [repo], bot_login, True, 5, held_rebaser
    )
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        held_resolver.run()
    check("[#1294] a machine-held worker PR the lane refuses is REBASED here, not ceded",
          (held_rebaser.calls,
           held_resolver.census[0]["skipped"].get("review-lane-owned"),
           held_resolver.census[0]["held_released"]),
          ([(repo, 8, "8" * 40)], None, 1))
    # FAIL-CLOSED ON A BROKEN IMPORT. An empty refusing set would silently cede everything again —
    # the failure mode is indistinguishable from "the lane refuses nothing", so it raises.
    class _NoLabels:
        HUMAN_HOLD_PR_LABELS = frozenset()
        MACHINE_PARK_PR_LABEL = None

    try:
        review_lane_refusing_labels(_NoLabels)
        empty_export = "returned"
    except ResolverError:
        empty_export = "raised"
    check("[#1294] a lane exporting no hold labels raises rather than ceding everything",
          empty_export, "raised")

    # --- [registry #657 §7.4 step 2b] THE CEDE PREDICATE AND THE ORCHESTRATOR CLASS -----------
    # `owned_by_review_rebase_lane` is a HAND-OVER: True means this resolver walks away. That is
    # only sound while the lane it hands to will TAKE the PR. The #657 orchestrator class is
    # admitted for `mode == "review"` ALONE — a rebase repair is a FIX dispatch, which pushes
    # commits to the PR head — so ceding one would strand a CONFLICTING PR in a lane that
    # structurally refuses it, and a conflicting PR gets no `pr-gate` run at all.
    ORCH_LOGIN = "jeswr"
    orch_conflict_pull = {
        "number": 41, "state": "open", "draft": False,
        "user": {"login": ORCH_LOGIN},
        "head": {"ref": "fix/readiness-visibility-opus5", "sha": "e" * 40,
                 "repo": {"full_name": repo}},
        "base": {"ref": "main", "repo": {"full_name": repo}},
    }
    check("[#657] an orchestrator-class PR is NOT ceded to the review-rebase lane",
          owned_by_review_rebase_lane(orch_conflict_pull, repo, claim), False)
    # THE JUSTIFICATION, executable rather than asserted in prose. A record and an allowlist that
    # make this PR fully admissible in REVIEW mode must still be REFUSED in fix mode; the day
    # that stops being true, the cede decision above has to be revisited and this reds first.
    orch_record = claim.orchestrator_probe_record(41)
    check("[#657] ...the same PR IS admitted by the review lane in review mode (so the fixture "
          "is not vacuously inadmissible)",
          claim.review_fix_pr_admission(repo, orch_conflict_pull, orch_record,
                                        (ORCH_LOGIN,), "review"), (True, None))
    fix_admitted, fix_error = claim.review_fix_pr_admission(
        repo, orch_conflict_pull, orch_record, (ORCH_LOGIN,), "fix")
    check("[#657] ...and REFUSED in fix mode — which is why ceding it would strand it",
          (fix_admitted, bool(fix_error)), (False, True))
    # The FORK GATE, hoisted out of the `and` chain: a fork head is never ceded either, whatever
    # else it satisfies. (A ceded fork PR would be skipped by this resolver AND refused by the
    # review lane's own unconditional fork gate — invisible to both.)
    check("[#657] a fork head is never ceded, even with the worker producer shape",
          owned_by_review_rebase_lane(
              {"user": {"login": bot_login},
               "head": {"ref": "sparq-agent/issue-7-1-1",
                        "repo": {"full_name": "mallory/repo"}}}, repo, claim), False)
    check("[#657] control: the same-repo worker shape IS still ceded (the gate above is not "
          "refusing everything)",
          owned_by_review_rebase_lane(
              {"user": {"login": bot_login},
               "head": {"ref": "sparq-agent/issue-7-1-1",
                        "repo": {"full_name": repo}}}, repo, claim), True)
    # Each remaining conjunct gets a case that reaches IT alone — measured: without these two,
    # deleting the author gate, and neutering the head-ref gate, both survived the whole suite
    # because the other conjunct still refused the orchestrator fixture.
    check("[#657] the AUTHOR gate: a HUMAN author on a worker-shaped branch is not ceded",
          owned_by_review_rebase_lane(
              {"user": {"login": ORCH_LOGIN},
               "head": {"ref": "sparq-agent/issue-7-1-1",
                        "repo": {"full_name": repo}}}, repo, claim), False)
    check("[#657] the HEAD-REF gate: the App bot on an ORDINARY branch is not ceded",
          owned_by_review_rebase_lane(
              {"user": {"login": bot_login},
               "head": {"ref": "fix/readiness-visibility-opus5",
                        "repo": {"full_name": repo}}}, repo, claim), False)

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

    # (b2) Sticky human unpark (park_policy.py defect 2): the SAME two-attempt escalation is
    # label-SUPPRESSED when the PR timeline shows a human removed needs:user more recently than
    # any application — the resolver never overrides an explicit human unpark.
    veto_timeline = [
        {"event": "labeled", "label": {"name": "needs:user"},
         "created_at": "2026-07-18T10:00:00Z", "actor": {"login": bot_login}},
        {"event": "unlabeled", "label": {"name": "needs:user"},
         "created_at": "2026-07-18T11:00:00Z", "actor": {"login": "jeswr"}},
    ]
    api = FakeAPI([pull(10, "a" * 40)], timelines={10: veto_timeline})
    rebaser = FakeRebaser("conflict")
    ConflictResolver(api, snapshot, claim, [repo], bot_login, True, 5, rebaser).run()
    api.set_head(10, "c" * 40)
    ConflictResolver(api, snapshot, claim, [repo], bot_login, True, 5, rebaser).run()
    check("human unpark vetoes the needs:user re-park", api.labels_added, [])

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

    # (f) Enumeration failures are isolated per repository, annotated loudly, and retained in
    # the final status. RuntimeError ensures this tests the broad repository boundary rather than
    # merely the expected ResolverError path.
    class EnumerationAPI:
        def __init__(self, failing_repo=None):
            self.failing_repo = failing_repo
            self.scanned = []

        def has_token(self, _repo):
            return True

        def repository(self, repo_name):
            return {"full_name": repo_name, "default_branch": "main"}

        def pulls(self, repo_name):
            self.scanned.append(repo_name)
            if repo_name == self.failing_repo:
                raise RuntimeError("enumeration exploded")
            return []

    repo_a = "alpha/one"
    repo_b = "beta/two"
    api = EnumerationAPI(repo_a)
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        isolated_rc = ConflictResolver(
            api, snapshot, claim, [repo_a, repo_b], bot_login, False, 5, FakeRebaser()
        ).run()
    check("enumeration failure does not starve the next repository", api.scanned,
          [repo_a, repo_b])
    check("enumeration failure makes the run fail", isolated_rc, 1)
    check("enumeration failure is a loud repository-scoped annotation",
          f"::error::conflict-resolver {repo_a}: enumeration exploded" in stderr.getvalue(),
          True)
    check("failed zero-action repository always has a summary",
          f"SUMMARY repo={repo_a} mode=dry-run actions=0 rebase-requests=0 "
          "mechanical-rebases=0 errors=1" in stdout.getvalue(), True)
    check("continued zero-action repository always has a summary",
          f"SUMMARY repo={repo_b} mode=dry-run actions=0 rebase-requests=0 "
          "mechanical-rebases=0 errors=0" in stdout.getvalue(), True)

    # (g) A clean multi-repository sweep is successful; no aggregate status other than recorded
    # errors is allowed to turn a clean scan red.
    api = EnumerationAPI()
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        clean_rc = ConflictResolver(
            api, snapshot, claim, [repo_a, repo_b], bot_login, False, 5, FakeRebaser()
        ).run()
    check("clean two-repository scan reaches both repositories", api.scanned, [repo_a, repo_b])
    check("clean two-repository scan exits zero", clean_rc, 0)
    check("clean two-repository scan emits no error annotation", stderr.getvalue(), "")

    # (h) An ENOTEMPTY raised only by teardown cannot replace a completed rebase+push result.
    # The real rebaser is used with Git stubbed so this pins the cleanup/work accounting boundary.
    def mechanical_git(old_head, new_head, fail_rebase=False):
        calls = []

        def run(_cwd, args, _env, check=True):
            calls.append(tuple(args))
            stdout = b""
            stderr = b""
            returncode = 0
            if args[0] == "rev-parse":
                stdout = (new_head if args[1] == "HEAD" else old_head).encode("ascii") + b"\n"
            elif args[:2] == ["rebase", "origin/main"] and fail_rebase:
                returncode = 1
                stderr = b"fatal: simulated rebase failure\n"
            return subprocess.CompletedProcess(args, returncode, stdout, stderr)

        return run, calls

    cleanup_api = FakeAPI([pull(70, "7" * 40)])
    cleanup_workspace = Path(tempfile.mkdtemp(prefix="conflict-resolver-self-test-"))
    cleanup_rebaser = MechanicalRebaser(
        cleanup_api, cleanup_workspace, bot_login, "123", True
    )
    fake_git, git_calls = mechanical_git("7" * 40, "8" * 40)
    real_rmtree = shutil.rmtree
    cleanup_calls = []

    def errno39_once(path, *args, **kwargs):
        cleanup_calls.append((os.fspath(path), kwargs.get("ignore_errors", False)))
        if len(cleanup_calls) == 1:
            raise OSError(39, "Directory not empty", os.fspath(path))
        return real_rmtree(path, *args, **kwargs)

    cleanup_resolver = ConflictResolver(
        cleanup_api, snapshot, claim, [repo], bot_login, True, 5, cleanup_rebaser
    )
    stdout = StringIO()
    stderr = StringIO()
    with (
        patch.object(cleanup_rebaser, "_git", side_effect=fake_git),
        patch.object(shutil, "rmtree", side_effect=errno39_once),
        patch.object(time, "sleep"),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        cleanup_rc = cleanup_resolver.run()
    real_rmtree(cleanup_workspace, ignore_errors=True)
    check(
        "cleanup ENOTEMPTY after push preserves the successful rebase outcome",
        (
            cleanup_rc,
            cleanup_resolver.rebases,
            cleanup_resolver.budget_used,
            len(cleanup_resolver.errors),
            [action[0] for action in cleanup_resolver.actions],
            any(call and call[0] == "push" for call in git_calls),
        ),
        (0, 1, 1, 0, ["mechanical-rebase"], True),
    )
    check("cleanup ENOTEMPTY uses the delayed final pass", len(cleanup_calls), 2)
    check("recovered cleanup emits no error annotation", "::error::" in stderr.getvalue(), False)

    # (i) The exception boundary remains narrow: a failure from the rebase itself is loud,
    # counted, and fatal even though teardown is best-effort.
    failure_api = FakeAPI([pull(71, "9" * 40)])
    failure_workspace = Path(tempfile.mkdtemp(prefix="conflict-resolver-self-test-"))
    failure_rebaser = MechanicalRebaser(
        failure_api, failure_workspace, bot_login, "123", True
    )
    fake_git, git_calls = mechanical_git("9" * 40, "a" * 40, fail_rebase=True)
    failure_resolver = ConflictResolver(
        failure_api, snapshot, claim, [repo], bot_login, True, 5, failure_rebaser
    )
    stdout = StringIO()
    stderr = StringIO()
    with (
        patch.object(failure_rebaser, "_git", side_effect=fake_git),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        failure_rc = failure_resolver.run()
    real_rmtree(failure_workspace, ignore_errors=True)
    check(
        "rebase-phase failure remains counted, loud, and fatal",
        (
            failure_rc,
            len(failure_resolver.errors),
            "::error::conflict-resolver example/repo#71: rebase failed" in stderr.getvalue(),
            any(call and call[0] == "push" for call in git_calls),
        ),
        (1, 1, True, False),
    )

    # (j) Persistent debris exercises the callback's chmod+single retry, delayed final pass,
    # and operator-visible warning. Removing any part makes this assertion fail.
    debris_workspace = Path(tempfile.mkdtemp(prefix="conflict-resolver-self-test-"))
    debris = debris_workspace / "debris"
    debris.mkdir()
    cleanup_steps = []

    def leave_debris(path, *args, **kwargs):
        if kwargs.get("ignore_errors"):
            cleanup_steps.append("final-pass")
            return
        cleanup_steps.append("callback")

        def still_busy(_failed_path):
            cleanup_steps.append("retry")
            raise OSError(39, "Directory not empty", os.fspath(path))

        exc = OSError(39, "Directory not empty", os.fspath(path))
        if kwargs.get("onexc"):
            kwargs["onexc"](still_busy, os.fspath(path), exc)
        else:
            kwargs["onerror"](still_busy, os.fspath(path), (OSError, exc, None))

    stderr = StringIO()
    with (
        patch.object(shutil, "rmtree", side_effect=leave_debris),
        patch.object(os, "chmod") as chmod,
        patch.object(time, "sleep") as cleanup_sleep,
        redirect_stderr(stderr),
    ):
        _cleanup_tempdir(debris)
    debris_warning = stderr.getvalue()
    real_rmtree(debris_workspace, ignore_errors=True)
    check(
        "persistent cleanup debris retries once then emits a warning",
        (
            cleanup_steps,
            chmod.call_count,
            cleanup_sleep.call_args_list,
            "::warning::conflict-resolver cleanup left temporary directory debris" in debris_warning,
        ),
        (["callback", "retry", "final-pass"], 1, [((0.1,), {})], True),
    )

    # (k) THE TWO EXITS ARE DIFFERENT EXITS, and this block is written as PAIRS so that neither
    # can pass by collapsing into the other.
    #
    # (k0) THE GRACE WINDOW itself (issue #753) is unchanged: ONE recorded attempt on a head
    # nobody ever pushes to was a hold with NO exit, because the two-distinct-head escalation
    # cannot fire without a second head. Inside the window the wait is correct (the author may
    # still push); past it, waiting has stopped being the plan.
    #
    # WHAT CHANGED (this PR). Past the window is a TIMEOUT, and a timeout is not a human question
    # (registry #769) — so it takes park_policy's MACHINE class with a cause-gated exit, while the
    # two-distinct-head exhaustion keeps `needs:user`. MEASURED on the live registry 2026-07-28:
    # 10 conflicting PRs held a machine-applied `needs:user` from this program and exactly ONE had
    # two attempt markers, so nine of ten were this branch wearing the other one's label AND
    # quoting the other one's sentence.
    def stuck_sweep(elapsed_hours):
        stuck_api = FakeAPI([pull(80, "b" * 40)], now=base_now)
        stuck_rebaser = FakeRebaser("conflict")
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            ConflictResolver(
                stuck_api, snapshot, claim, [repo], bot_login, True, 5, stuck_rebaser,
                stuck_grace_hours=grace, clock=lambda: base_now,
            ).run()
        later = base_now + elapsed_hours * 3600.0
        sweep = ConflictResolver(
            stuck_api, snapshot, claim, [repo], bot_login, True, 5, stuck_rebaser,
            stuck_grace_hours=grace, clock=lambda: later,
        )
        sweep_stdout, sweep_stderr = StringIO(), StringIO()
        with redirect_stdout(sweep_stdout), redirect_stderr(sweep_stderr):
            sweep_rc = sweep.run()
        sweep_bodies = _comment_bodies(stuck_api.comment_rows[80])
        return {
            "rc": sweep_rc,
            "api": stuck_api,
            "labels": list(stuck_api.labels_added),
            "escalations": sum(ESCALATION_MARKER in body for body in sweep_bodies),
            "attempts": sum(bool(ATTEMPT_RE.search(body)) for body in sweep_bodies),
            "park_receipts": sum(STUCK_PARK_MARKER in body for body in sweep_bodies),
            "bodies": sweep_bodies,
            "row": sweep.census[0],
            "rebase_calls": len(stuck_rebaser.calls),
        }

    within = stuck_sweep(grace - 0.5)
    past = stuck_sweep(grace + 0.5)
    check(
        "inside the grace window a lone attempt is left to its author, and is COUNTED",
        (within["rc"], within["labels"], within["escalations"], within["rebase_calls"],
         within["row"]["awaiting_author"], within["row"]["escalated"], within["row"]["no_exit"],
         within["row"]["skipped"].get("awaiting-author-grace")),
        (0, [], 0, 1, 1, 0, 0, 1),
    )
    # (k1) THE GRACE-WINDOW EXIT TAKES THE MACHINE CLASS. This is the named check for the
    # `_escalate_stuck` CALL SITE: point that one line at `_escalate_two_head` and this reds
    # alone, while every two-head check below stays green.
    check(
        "[EXIT stuck-grace] past the window the lone attempt takes the MACHINE class, mints its "
        "park receipt, and is NOT a human escalation",
        (past["rc"], past["labels"], past["escalations"], past["park_receipts"],
         past["attempts"], past["rebase_calls"], past["row"]["escalated"],
         past["row"]["awaiting_author"], past["row"]["no_exit"]),
        (0, [(80, MACHINE_PARK_LABEL)], 0, 1, 1, 1, 1, 0, 0),
    )
    check(
        "[EXIT stuck-grace] ...and the CENSUS attributes it to the grace-window exit and the "
        "machine class, with the two-distinct-head buckets left at zero",
        (past["row"]["exit_stuck_grace"], past["row"]["parked_machine"],
         past["row"]["exit_two_head"], past["row"]["parked_human"]),
        (1, 1, 0, 0),
    )

    # (k2) THE TWO-DISTINCT-HEAD EXIT KEEPS `needs:user`. The PAIRED CONTROL for (k1): the same
    # program, the same PR, one extra pushed head — and the opposite class. This is the named
    # check for the `_escalate_two_head` CALL SITES: point them at `_escalate_stuck` and this
    # reds alone, while (k1) stays green.
    two_head_api = FakeAPI([pull(82, "a" * 40)], now=base_now)
    two_head_rebaser = FakeRebaser("conflict")

    def two_head_sweep():
        sweep = ConflictResolver(
            two_head_api, snapshot, claim, [repo], bot_login, True, 5, two_head_rebaser,
            stuck_grace_hours=grace, clock=lambda: base_now)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            sweep.run()
        return sweep

    two_head_sweep()
    two_head_api.set_head(82, "c" * 40)
    two_head_final = two_head_sweep()
    two_head_bodies = _comment_bodies(two_head_api.comment_rows[82])
    two_head_row = two_head_final.census[0]
    check(
        "[EXIT two-distinct-heads] two heads that both conflict take the HUMAN terminal, and "
        "mint NO machine park receipt",
        (two_head_api.labels_added,
         sum(ESCALATION_MARKER in body for body in two_head_bodies),
         sum(STUCK_PARK_MARKER in body for body in two_head_bodies),
         two_head_api.labels_removed),
        ([(82, HUMAN_PARK_LABEL)], 1, 0, []),
    )
    check(
        "[EXIT two-distinct-heads] ...and the CENSUS attributes it to the exhaustion exit and "
        "the human class, with the grace-window buckets left at zero",
        (two_head_row["exit_two_head"], two_head_row["parked_human"],
         two_head_row["exit_stuck_grace"], two_head_row["parked_machine"]),
        (1, 1, 0, 0),
    )

    # (k2b) THE OTHER TWO-HEAD CALL SITES. MEASURED while writing this block, and it is the
    # finding that matters most here: re-pointing EITHER of the two `_escalate_two_head` call
    # sites in `_process_pr` at `_escalate_stuck` left the WHOLE 44-script suite green. (k2)
    # above drives the rebaser, so it only ever reaches the `_handle_conflict` tail — the
    # exhaustion exit had 1/3 site coverage at 3/3 confidence, which is the exact shape that hid
    # this defect class in #594 and #886. Each site now gets a case that reaches IT alone, off
    # pre-seeded durable markers rather than through a rebase.
    def seeded_attempt(attempt, head):
        return {"body": f"<!-- conflict-resolver attempt={attempt} head={head} -->\n"
                        "- conflict-file: \"src/value.py\"",
                "user": {"login": bot_login}, "created_at": iso(base_now)}

    def seeded_two_head_sweep(number, live_head):
        """A PR with TWO recorded attempt heads already on record, swept 1000 h past the grace
        window — so if the exhaustion exit ever routed through the grace-window exit, it would
        park machine-class here instead of escalating."""
        seeded_api = FakeAPI([pull(number, live_head)], now=base_now)
        seeded_api.comment_rows[number] = [seeded_attempt(1, "1" * 40),
                                           seeded_attempt(2, "2" * 40)]
        seeded_rebaser = FakeRebaser("conflict")
        sweep = ConflictResolver(
            seeded_api, snapshot, claim, [repo], bot_login, True, 5, seeded_rebaser,
            stuck_grace_hours=grace, clock=lambda: base_now + 1000 * 3600.0)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            sweep.run()
        seeded_bodies = _comment_bodies(seeded_api.comment_rows[number])
        return (seeded_api.labels_added,
                sum(ESCALATION_MARKER in body for body in seeded_bodies),
                sum(STUCK_PARK_MARKER in body for body in seeded_bodies),
                len(seeded_rebaser.calls),
                (sweep.census[0]["exit_two_head"], sweep.census[0]["exit_stuck_grace"],
                 sweep.census[0]["parked_machine"], sweep.census[0]["parked_human"]))

    check(
        "[EXIT two-distinct-heads] CALL SITE `head in heads`: a head that ALREADY has an attempt "
        "marker, with a second head on record, takes the HUMAN terminal — not the grace-window "
        "park, even 1000 h past the window",
        seeded_two_head_sweep(84, "2" * 40),
        ([(84, HUMAN_PARK_LABEL)], 1, 0, 0, (1, 0, 0, 1)),
    )
    # THE MARQUEE ROW OF #1191's SECOND EDGE, and it is an INVERSION: this same call previously
    # asserted `0` rebaser calls — a NEW head escalating on two OLD heads' evidence. A push the
    # program never tried is not exhaustion, and asserting it made the resulting `needs:user`
    # unreleasable in principle (reconcile-conflict-park refuses `two-head-exhaustion` because a
    # released PR came straight back here). The escalation still fires — one line later, from
    # `_handle_conflict`, on evidence this run measured. Restore the deleted `if len(heads) >= 2`
    # block in `_process_pr` and this row goes red on the rebase count.
    check(
        "[#1191 EXIT two-distinct-heads] CALL SITE `head not in heads`: a NEW head is REBASED "
        "first even with two failed heads on record, and escalates only on ITS OWN conflict",
        seeded_two_head_sweep(85, "3" * 40),
        ([(85, HUMAN_PARK_LABEL)], 1, 0, 1, (1, 0, 0, 1)),
    )
    # ...and the same PR one tick later: the escalation is ALREADY delivered and the human
    # terminal is live, so re-asserting it is not work. Delete the `escalated_already and
    # HUMAN_PARK_LABEL in _label_names(pr)` guard in `_escalate_two_head` and this row goes red
    # on both the exit counters and the verdict — an unchanged PR would score the run as `acted`
    # and mute the INERT alarm forever.
    def two_head_stands_sweep():
        api2 = FakeAPI([pull(185, "2" * 40, labels=(HUMAN_PARK_LABEL,))], now=base_now)
        api2.comment_rows[185] = [
            seeded_attempt(1, "1" * 40), seeded_attempt(2, "2" * 40),
            {"body": f"{ESCALATION_MARKER}\nalready asked", "user": {"login": bot_login},
             "created_at": iso(base_now)},
        ]
        api2.timelines[185] = [{"event": "labeled", "label": {"name": HUMAN_PARK_LABEL},
                                "actor": {"login": bot_login}, "created_at": iso(base_now)}]
        reb2 = FakeRebaser("conflict")
        sweep = ConflictResolver(api2, snapshot, claim, [repo], bot_login, True, 5, reb2,
                                 stuck_grace_hours=grace,
                                 clock=lambda: base_now + 1000 * 3600.0)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            rc = sweep.run()
        row = sweep.census[0]
        return (rc, api2.labels_added, len(reb2.calls), row["escalated"],
                row["skipped"].get("two-head-exhausted-stands"),
                _aggregate_census(sweep.census)["verdict"])

    check(
        "[#1191] a two-head exhaustion ALREADY escalated and ALREADY held is re-affirmed as "
        "NOTHING: no write, no `escalated`, and the run scores `correctly-idle`, NEVER `acted`",
        two_head_stands_sweep(),
        (0, [], 0, 0, 1, VERDICT_IDLE),
    )

    # (k3) THE BODY MATCHES THE EXIT — both directions (Fix 2). ONE hard-coded body served both
    # exits, so a timeout was reported as "two distinct-head conflict attempts": a specific,
    # checkable, FALSE claim in 9 of the 10 live cases. Asserting only that "a comment was posted"
    # is what let that stand, so each direction asserts BOTH that its own exit's sentence is
    # present AND that the other exit's sentence is absent.
    two_head_text = "\n".join(body for body in two_head_bodies if ESCALATION_MARKER in body)
    stuck_text = "\n".join(body for body in past["bodies"] if STUCK_PARK_MARKER in body)
    check(
        "[BODY] the two-distinct-head body states ITS OWN exit and the attempt count it "
        "observed, and never claims a grace window",
        ("2 distinct-head conflict attempts" in two_head_text,
         "two-distinct-head exhaustion exit" in two_head_text,
         "grace window" in two_head_text, "UNMOVED" in two_head_text),
        (True, True, False, False),
    )
    check(
        "[BODY] the grace-window body states ITS OWN exit and the ONE attempt it observed, and "
        "never claims two distinct-head attempts",
        ("1 conflict attempt(s) on an UNMOVED head" in stuck_text,
         "stuck-attempt grace-window exit" in stuck_text,
         "distinct-head conflict attempts" in stuck_text,
         "Human resolution is required" in stuck_text),
        (True, True, False, False),
    )
    check(
        "[BODY] ...and the machine-class body says so in as many words, so a reader is not told "
        "to act on a hold that clears itself",
        (f"MACHINE-owned `{MACHINE_PARK_LABEL}` soft hold" in stuck_text,
         "as soon as the head moves or the conflict resolves" in stuck_text),
        (True, True),
    )
    # The wording is DERIVED from the exit, not chosen at the call site: an unrepresentable body
    # fails LOUD at the writer rather than falling through to whichever sentence came first.
    unknown_exit_rejected = False
    try:
        escalation_body("some-third-exit", ("a.py",), 1, HUMAN_PARK_LABEL)
    except ResolverError:
        unknown_exit_rejected = True
    check("[BODY] an unknown exit kind is refused, never given a default sentence",
          unknown_exit_rejected, True)
    # The attempt count is READ, not baked in: three heads must say three.
    check("[BODY] the attempt count in the body is the count observed, not a literal",
          ("3 distinct-head conflict attempts"
           in escalation_body(EXIT_TWO_HEAD, ("a.py",), 3, HUMAN_PARK_LABEL)),
          True)
    # THE OVER-CAP BODY, AND ITS GRANT COUNT — the third exit-body shape, and the one that had NO
    # assertion at all in round 1. MEASURED then: replacing `grants=len(stuck_receipts(...))` with
    # `generation - 1` SURVIVED the whole suite. Under that mutant a generation-3 escalation tells
    # a maintainer "2 automatic re-admission(s) on record" when the durable record shows NONE —
    # which is verbatim the registry #769 finding this PR cites as the reason the count must be
    # read. It sends the reader hunting a flapping cause instead of whatever kept clearing the
    # label. So the count is pinned at TWO values: a generation whose grants are 0, and the SAME
    # generation whose grants are 1. `generation - 1` disagrees with at least one of them for
    # every generation, so no arithmetic on the generation can satisfy both rows.
    over_cap_gen = STUCK_UNPARK_MAX + 1
    over_cap_zero = escalation_body(EXIT_STUCK_GRACE, ("a.py",), 1, HUMAN_PARK_LABEL,
                                    generation=over_cap_gen, grants=0)
    over_cap_one = escalation_body(EXIT_STUCK_GRACE, ("a.py",), 1, HUMAN_PARK_LABEL,
                                   generation=over_cap_gen, grants=1)
    check(
        "[BODY] the over-cap body names ITS OWN exit, states the generation, and reports the "
        "grants READ FROM THE RECEIPTS — 0 grants says 0, not `generation - 1`",
        (f"park generation {over_cap_gen}" in over_cap_zero,
         "0 automatic re-admission(s) on record" in over_cap_zero,
         "stuck-attempt grace-window exit" in over_cap_zero,
         "distinct-head conflict attempts" in over_cap_zero,
         f"MACHINE-owned `{MACHINE_PARK_LABEL}` soft hold" in over_cap_zero),
        (True, True, True, False, False),
    )
    check(
        "[BODY] ...and the SAME generation with one grant on record says 1 — the count tracks "
        "the receipts, not the generation",
        ("1 automatic re-admission(s) on record" in over_cap_one,
         "0 automatic re-admission(s) on record" in over_cap_one,
         over_cap_zero == over_cap_one),
        (True, False, False),
    )

    # ...AND THE SAME PROPERTY AT THE CALL SITE, which is a separate assertion and not a
    # restatement. MEASURED (review round 2, on the two checks immediately above): pinning only
    # `escalation_body` left `grants=len(stuck_receipts(...))` -> `grants=generation - 1` ALIVE,
    # because the pure function was never the thing that read the receipts. A guard on the
    # function and a guard on the argument the call site computes are different guards; this is
    # the same 1/N shape that hid the two `_escalate_two_head` sites in round 1, one layer in.
    def over_cap_escalation(grants_on_record):
        """A PR already carrying STUCK_UNPARK_MAX park receipts, so its NEXT grace-window exit is
        generation STUCK_UNPARK_MAX + 1 — the human class — driven end to end through `run()`."""
        over_head = "b" * 40
        rows = [attempt_comment(over_head, iso(base_now))]
        rows += [{"body": stuck_receipt(STUCK_PARK_MARKER, over_head, gen),
                  "user": {"login": bot_login}, "created_at": iso(base_now)}
                 for gen in range(1, STUCK_UNPARK_MAX + 1)]
        rows += [{"body": stuck_receipt(STUCK_UNPARK_MARKER, over_head, gen),
                  "user": {"login": bot_login}, "created_at": iso(base_now)}
                 for gen in range(1, grants_on_record + 1)]
        over_api = FakeAPI([pull(87, over_head)], now=base_now)
        over_api.comment_rows[87] = rows
        sweep = ConflictResolver(
            over_api, snapshot, claim, [repo], bot_login, True, 5, FakeRebaser("conflict"),
            stuck_grace_hours=grace, clock=lambda: base_now + 1000 * 3600.0)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            sweep.run()
        return (over_api.labels_added,
                "\n".join(body for body in _comment_bodies(over_api.comment_rows[87])
                          if ESCALATION_MARKER in body),
                sweep.census[0])

    over_zero_labels, over_zero_body, over_zero_row = over_cap_escalation(0)
    over_one_labels, over_one_body, _over_one_row = over_cap_escalation(1)
    check(
        "[BODY] CALL SITE: an over-cap escalation POSTS the grant count on record — a "
        f"generation-{STUCK_UNPARK_MAX + 1} flap with zero grants says zero, and takes the "
        "human class",
        (over_zero_labels,
         f"park generation {STUCK_UNPARK_MAX + 1}" in over_zero_body,
         "0 automatic re-admission(s) on record" in over_zero_body,
         (over_zero_row["exit_stuck_grace"], over_zero_row["parked_human"],
          over_zero_row["parked_machine"])),
        ([(87, HUMAN_PARK_LABEL)], True, True, (1, 1, 0)),
    )
    check(
        "[BODY] CALL SITE: ...and ONE grant on record says one at the SAME generation, so no "
        "function of the generation alone can satisfy both rows",
        ("1 automatic re-admission(s) on record" in over_one_body,
         "0 automatic re-admission(s) on record" in over_one_body,
         over_one_labels),
        (True, False, [(87, HUMAN_PARK_LABEL)]),
    )

    # (k3b) THE VETO ASYMMETRY. `_escalate_stuck` checks the sticky human-unpark veto BEFORE it
    # comments; the two-head exit checks it after, because that comment is once-ever
    # marker-deduped and cannot repeat. MEASURED (review round 1): deleting the `_escalate_stuck`
    # veto SURVIVED the whole suite — `_apply_park_label`'s veto still suppressed the LABEL, so
    # the end state looked identical while the behaviour the docstring warns about was fully
    # restored: a receipt minted for a park that is never applied, a generation spent on it, and
    # a fresh comment on every tick of a 20-minute cron, on a PR a human explicitly un-parked.
    stuck_veto_timeline = [
        {"event": "labeled", "label": {"name": MACHINE_PARK_LABEL},
         "created_at": "2026-07-18T10:00:00Z", "actor": {"login": bot_login}},
        {"event": "unlabeled", "label": {"name": MACHINE_PARK_LABEL},
         "created_at": "2026-07-18T11:00:00Z", "actor": {"login": "jeswr"}},
    ]

    def stuck_veto_ticks(timelines):
        """One attempt recorded, then TWO further ticks past the grace window. Two, not one:
        the defect this pins is per-TICK repetition, which a single tick cannot express."""
        veto_api = FakeAPI([pull(86, "b" * 40)], timelines=timelines, now=base_now)
        veto_rebaser = FakeRebaser("conflict")
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            ConflictResolver(veto_api, snapshot, claim, [repo], bot_login, True, 5, veto_rebaser,
                             stuck_grace_hours=grace, clock=lambda: base_now).run()
        rows = []
        for _tick in range(2):
            sweep = ConflictResolver(
                veto_api, snapshot, claim, [repo], bot_login, True, 5, veto_rebaser,
                stuck_grace_hours=grace, clock=lambda: base_now + 1000 * 3600.0)
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                sweep.run()
            rows.append(sweep.census[0])
        veto_bodies = _comment_bodies(veto_api.comment_rows[86])
        return (sum(STUCK_PARK_MARKER in body for body in veto_bodies),
                veto_api.labels_added,
                (rows[0]["exit_stuck_grace"], rows[0]["parked_machine"]),
                # The SECOND tick is what the verdict has to survive: a sweep that wrote nothing
                # must not score as work on it (#1191 review, blocking 1).
                _aggregate_census([rows[1]])["verdict"],
                rows[1]["skipped"])

    check(
        "[EXIT stuck-grace] a human un-park VETOES the machine park BEFORE the comment: no "
        "receipt is minted, no generation is spent, and the suppressed tick is a NAMED SKIP that "
        "scores no exit and no work",
        stuck_veto_ticks({86: stuck_veto_timeline}),
        (0, [], (0, 0), VERDICT_IDLE, {"park-suppressed-human-unpark": 1}),
    )
    check(
        "[EXIT stuck-grace] ...PAIRED CONTROL: with no human un-park the SAME two ticks mint "
        "EXACTLY ONE receipt, and tick two stands down on the CAUSE-GATED machine exit rather "
        "than re-escalating — so the check above is not passing because nothing ever posts",
        stuck_veto_ticks({}),
        (1, [(86, MACHINE_PARK_LABEL)], (1, 1), VERDICT_IDLE, {"stuck-park-stands": 1}),
    )

    # (k5) THE LIVE STRANDED SHAPE, OVER MANY TICKS (#1191 review, both blocking findings).
    #
    # A single tick cannot express either defect, and that is exactly how they got in: the first
    # cut of this PR passed 89 single-tick rows while (a) scoring `escalated` on EVERY tick forever
    # — muting its own INERT verdict permanently — and (b) writing `review:parked` while leaving
    # the machine-applied `needs:user` live, which stands `_stuck_park_phase` down via
    # `human_owned_holds` and drives the receipts to generation 3 (past STUCK_UNPARK_MAX) within
    # three ticks, where reconcile-conflict-park reads them as `budget-exhausted` — a HUMAN
    # TERMINAL that outranks a fully recovered cause. Measured on the live census, that would have
    # stranded the 7 PRs it calls exit-reachable today.
    #
    # So this drives EIGHT consecutive sweeps against ONE persistent state, with the author
    # pushing at tick 4, and asserts the whole trajectory rather than any single tick.
    def stranded_ticks(ticks=8, push_at=4, labels=("needs:user",), issue_rows=None):
        pr_row = pull(90, "a" * 40, labels=labels)
        api9 = FakeAPI([pr_row], timelines={90: [
            {"event": "labeled", "label": {"name": name}, "actor": {"login": bot_login},
             "created_at": iso(base_now)} for name in labels]}, issues=issue_rows)
        api9.comment_rows[90] = [attempt_comment("a" * 40, iso(base_now))]
        reb9 = FakeRebaser("conflict")
        trace = []
        for tick in range(1, ticks + 1):
            if tick == push_at:
                api9.set_head(90, "c" * 40)
            sweep = ConflictResolver(api9, snapshot, claim, [repo], bot_login, True, 5, reb9,
                                     stuck_grace_hours=grace,
                                     clock=lambda: base_now + 1000 * 3600.0)
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                sweep.run()
            row = _aggregate_census(sweep.census)
            trace.append((row["escalated"], row["verdict"]))
        return (trace, sorted(_label_names(api9.prs[90])),
                stuck_park_generation(api9.comment_rows[90], bot_login), len(reb9.calls),
                [event for event in api9.events if event[1] in ("add-label", "remove-label")])

    trace, final_labels, final_gen, rebases, _events = stranded_ticks()
    check(
        "[#1191] EIGHT TICKS on the live stranded shape: escalation happens on the tick it is "
        "EARNED and never again — a sweep that re-asserts a delivered park scores "
        "`correctly-idle`, so the INERT verdict can still fire",
        [trace[index] for index in (0, 1, 2, 4, 7)],
        [(1, VERDICT_ACTED), (0, VERDICT_IDLE), (0, VERDICT_IDLE),
         (0, VERDICT_IDLE), (0, VERDICT_IDLE)],
    )
    check(
        "[#1191] ...and the CLASS CONVERSION completes: `needs:user` is gone, the generation "
        "never runs past STUCK_UNPARK_MAX into reconcile's `budget-exhausted` terminal, and the "
        "recovered cause bought a REAL rebase of the pushed head",
        (final_gen <= STUCK_UNPARK_MAX, rebases, trace[3]),
        (True, 1, (1, VERDICT_ACTED)),
    )
    # The demotion's own row, asserted on the LABEL SET a downstream consumer actually reads:
    # `human_owned_holds` must be EMPTY, because that predicate — not the label name — is what
    # stands `_stuck_park_phase` down and what reconcile keys its refusal on. Delete the
    # `_demote_holds` call after `_apply_park_label` and this goes red.
    _t, mid_labels, _g, _r, mid_events = stranded_ticks(ticks=2, push_at=99)
    check(
        "[#1191] parking in the MACHINE class DEMOTES the machine-applied human-class hold it "
        "replaces — the exit-blocking predicate, not merely the label, is cleared",
        (mid_labels, _park_policy.human_owned_holds(mid_labels), mid_events),
        ([MACHINE_PARK_LABEL], [],
         # PARK FIRST, THEN DEMOTE. The residue of an interruption must be BOTH labels — a PR
         # still held, which the next tick converges — never NEITHER, which is this program
         # silently un-holding a PR. Swap the two writes and this row goes red on the order.
         [(90, "add-label", MACHINE_PARK_LABEL), (90, "remove-label", HUMAN_PARK_LABEL)]),
    )
    # ...SCOPED. `trust-surface` is machine-applied and released, but it does not block the
    # machine exit and dropping a trust classification is a different decision. Widen
    # `_demotable_holds` past `human_owned_holds` and this row goes red.
    _t2, trust_labels, _g2, _r2, _e2 = stranded_ticks(
        ticks=2, push_at=99, labels=("needs:user", "trust-surface"))
    check(
        "[#1191] ...and ONLY those: a released `trust-surface` survives the demotion untouched",
        trust_labels,
        sorted([MACHINE_PARK_LABEL, "trust-surface"]),
    )

    # (k5b) THE INTERRUPTED DEMOTION — the one reachable state where `_escalate_stuck` sees its own
    # park already delivered. MEASURED: with the demotion working, `_stuck_park_phase` answers
    # "stands" on tick two and the already-delivered guard is never reached, so deleting that
    # guard left the whole suite green — the headline fix of the review round with no red row.
    #
    # Both labels live is precisely the residue of a crash between the park write and the demote
    # write, so this is the state the ordering above is CHOSEN to produce. The guard must converge
    # it — finish the demotion, spend no generation, mint no second park — because falling through
    # instead recomputes `generation` from the receipts on record and burns one for what is pure
    # convergence. That is the runaway to generation 3 that reconcile reads as `budget-exhausted`.
    def interrupted_demotion():
        pr_row = pull(91, "a" * 40, labels=("needs:user", MACHINE_PARK_LABEL))
        api10 = FakeAPI([pr_row], timelines={91: [
            {"event": "labeled", "label": {"name": name}, "actor": {"login": bot_login},
             "created_at": iso(base_now)} for name in ("needs:user", MACHINE_PARK_LABEL)]})
        api10.comment_rows[91] = [
            attempt_comment("a" * 40, iso(base_now)),
            {"body": f"park\n{stuck_receipt(STUCK_PARK_MARKER, 'a' * 40, 1)}",
             "user": {"login": bot_login}, "created_at": iso(base_now)},
        ]
        sweep = ConflictResolver(api10, snapshot, claim, [repo], bot_login, True, 5,
                                 FakeRebaser("conflict"), stuck_grace_hours=grace,
                                 clock=lambda: base_now + 1000 * 3600.0)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            sweep.run()
        row = sweep.census[0]
        return (sorted(_label_names(api10.prs[91])), row["escalated"],
                stuck_park_generation(api10.comment_rows[91], bot_login),
                row["skipped"].get("stuck-park-already-delivered"),
                _aggregate_census(sweep.census)["verdict"])

    check(
        "[#1191] a park interrupted BETWEEN its two writes converges on the next tick: the "
        "demotion finishes, no generation is spent, no second park is minted, and the tick "
        "scores `correctly-idle`",
        interrupted_demotion(),
        ([MACHINE_PARK_LABEL], 0, 2, 1, VERDICT_IDLE),
    )

    # (k5c) THE HUMAN CLASS IS NEVER DEMOTED. Past STUCK_UNPARK_MAX the park label IS `needs:user`
    # — the same label the release identified as machine-applied — so an unscoped demotion would
    # delete the hold it had just written and leave the PR held by nothing at all. Drop the
    # `park_label != MACHINE_PARK_LABEL` guard in `_demote_holds` and this row goes red.
    # THE THIRD INSTANCE of the self-muting class (review round 3, item 1). Over the cap
    # `stuck_park_label` writes `needs:user` — the very label the release identified as
    # machine-applied and left live — so the write is a no-op, AND `stuck_unpark_state` answers
    # `(None, None)` above the cap, which is why the already-delivered guard structurally CANNOT
    # see this branch. Guarding branch-by-branch was losing; `_apply_park_label` now refuses to
    # reach `_count_exit` at all unless a label the PR lacked was actually added.
    #
    # MULTI-TICK on purpose: a single tick cannot express "scores work forever", which is the
    # only thing that matters here.
    def over_cap_ticks(ticks=5, hold=("needs:user",)):
        pr_row = pull(92, "a" * 40, labels=hold)
        api11 = FakeAPI([pr_row], timelines={
            92: [event for name in hold for event in labelled_by(bot_login, name)]})
        api11.comment_rows[92] = [attempt_comment("a" * 40, iso(base_now))] + [
            {"body": f"park gen {gen}\n{stuck_receipt(STUCK_PARK_MARKER, 'z' * 40, gen)}",
             "user": {"login": bot_login}, "created_at": iso(base_now)}
            for gen in range(1, STUCK_UNPARK_MAX + 1)
        ]
        trace = []
        for _tick in range(ticks):
            sweep = ConflictResolver(api11, snapshot, claim, [repo], bot_login, True, 5,
                                     FakeRebaser("conflict"), stuck_grace_hours=grace,
                                     clock=lambda: base_now + 1000 * 3600.0)
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                sweep.run()
            total = _aggregate_census(sweep.census)
            trace.append((total["escalated"], total["parked_human"], total["verdict"]))
        return (trace, sorted(_label_names(api11.prs[92])), api11.labels_removed,
                sweep.census[0]["skipped"].get("park-already-live"),
                sweep.census[0]["skipped"])

    over_trace, over_labels, over_removed, over_skip, _osk = over_cap_ticks()
    check(
        "[#1191] an OVER-CAP park scores NO work on any tick — the human terminal it would write "
        "is already live, so re-asserting it is not an escalation — and it demotes NOTHING, so "
        "the PR is never left holding no hold at all",
        (over_trace, over_labels, over_removed, over_skip),
        ([(0, 0, VERDICT_IDLE)] * 5, [HUMAN_PARK_LABEL], [], 1),
    )
    # ...PAIRED CONTROL, so the row above is not passing merely because nothing ever escalates
    # over the cap: with the hold ABSENT the same over-cap branch DOES write the human terminal
    # and DOES score exactly one escalation — on the first tick only.
    ctl_trace, ctl_labels, ctl_removed, _ctl_skip, _ctl_sk = over_cap_ticks(hold=())
    check(
        "[#1191] ...CONTROL: with no live hold the over-cap branch writes the human terminal and "
        "scores exactly ONE escalation, on the tick that earned it",
        (ctl_trace[0], ctl_trace[1], ctl_labels, ctl_removed),
        ((1, 1, VERDICT_ACTED), (0, 0, VERDICT_IDLE), [HUMAN_PARK_LABEL], []),
    )

    # (k5d) THE OVER-CAP DEMOTION EXEMPTION, on a fixture that actually REACHES it. MEASURED: the
    # `_apply_park_label` choke point made the previous over-cap row stop reaching `_demote_holds`
    # at all, so the human-class exemption silently lost its guard — a fix creating a hole in a
    # neighbouring test is exactly why mutants get re-run after every change. Here the over-cap
    # park label (`needs:user`) is NOT live, so it is really written, while a machine-applied
    # `review:needs-user` IS live and demotable. Drop the `park_label != MACHINE_PARK_LABEL` guard
    # and this program deletes ANOTHER LANE'S review hold while writing its own terminal.
    def over_cap_demotion():
        pr_row = pull(93, "a" * 40, labels=("review:needs-user",))
        api12 = FakeAPI([pr_row], timelines={93: labelled_by(bot_login, "review:needs-user")})
        api12.comment_rows[93] = [attempt_comment("a" * 40, iso(base_now))] + [
            {"body": f"park gen {gen}\n{stuck_receipt(STUCK_PARK_MARKER, 'z' * 40, gen)}",
             "user": {"login": bot_login}, "created_at": iso(base_now)}
            for gen in range(1, STUCK_UNPARK_MAX + 1)
        ]
        sweep = ConflictResolver(api12, snapshot, claim, [repo], bot_login, True, 5,
                                 FakeRebaser("conflict"), stuck_grace_hours=grace,
                                 clock=lambda: base_now + 1000 * 3600.0)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            sweep.run()
        return (sorted(_label_names(api12.prs[93])), api12.labels_removed,
                sweep.census[0]["parked_human"])

    check(
        "[#1191] writing the HUMAN terminal demotes NOTHING: another lane's `review:needs-user` "
        "survives, and this program never converts a hold it does not own",
        over_cap_demotion(),
        (sorted([HUMAN_PARK_LABEL, "review:needs-user"]), [], 1),
    )

    # (k5e) THE VETO, THROUGH THE TWO-HEAD EXIT — the one caller that reaches
    # `_apply_park_label`'s veto branch (the grace-window exit checks the veto itself, earlier).
    # MEASURED: restoring `_count_exit` there survived the whole suite, so the second of the three
    # mute paths had no red row of its own. A human un-parked this PR; re-parking is refused, and
    # a refused write is not work.
    def two_head_veto():
        pr_row = pull(94, "2" * 40)
        api13 = FakeAPI([pr_row], timelines={94: [
            {"event": "labeled", "label": {"name": HUMAN_PARK_LABEL},
             "actor": {"login": bot_login}, "created_at": "2026-07-18T10:00:00Z"},
            {"event": "unlabeled", "label": {"name": HUMAN_PARK_LABEL},
             "actor": {"login": "jeswr"}, "created_at": "2026-07-18T11:00:00Z"},
        ]})
        api13.comment_rows[94] = [seeded_attempt(1, "1" * 40), seeded_attempt(2, "2" * 40)]
        sweep = ConflictResolver(api13, snapshot, claim, [repo], bot_login, True, 5,
                                 FakeRebaser("conflict"), stuck_grace_hours=grace,
                                 clock=lambda: base_now + 1000 * 3600.0)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            sweep.run()
        total = _aggregate_census(sweep.census)
        return (api13.labels_added, total["escalated"], total["verdict"],
                sweep.census[0]["skipped"].get("park-suppressed-human-unpark"))

    check(
        "[#1191] a two-head escalation VETOED by a sticky human un-park writes nothing, scores "
        "NO escalation, and leaves the run `correctly-idle` — the refusal is the human's exit, "
        "not this program's work",
        two_head_veto(),
        ([], 0, VERDICT_IDLE, 1),
    )

    # (k5f) THE NON-NESTED SETS (review round 3, item 3). `needs:ec2` is matched by
    # `human_owned_holds` — which is what stands `_stuck_park_phase` down — but is NOT in
    # `HARD_EXCLUDE_LABELS`, so it is neither checked for ownership nor demotable. Parking here
    # would demote `needs:user` out of reconcile's label-filtered LIST population while keeping a
    # hold that kills this program's own exit: invisible to both mechanisms at once. Refuse.
    def non_nested_hold():
        pr_row = pull(95, "a" * 40, labels=("needs:user", "needs:ec2"))
        api14 = FakeAPI([pr_row], timelines={95: labelled_by(bot_login, "needs:user")})
        api14.comment_rows[95] = [attempt_comment("a" * 40, iso(base_now))]
        sweep = ConflictResolver(api14, snapshot, claim, [repo], bot_login, True, 5,
                                 FakeRebaser("conflict"), stuck_grace_hours=grace,
                                 clock=lambda: base_now + 1000 * 3600.0)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            rc = sweep.run()
        return (sorted(_label_names(api14.prs[95])), api14.labels_added, api14.labels_removed,
                sweep.census[0]["skipped"].get("residual-human-class-hold"), rc)

    check(
        "[#1191] the machine park is REFUSED when a human-class hold outside this program's "
        "exclusion set would survive the demotion — no park, no demotion, nothing orphaned",
        non_nested_hold(),
        (sorted(["needs:user", "needs:ec2"]), [], [], 1, 0),
    )

    # (k6) THE TWO SILENT-RELEASE PATHS the first cut left open (#1191 review, secondary 1 and 2).
    # Both ended in a rebase under a hold, at rc=0. The fail-closed rule was right; these two
    # paths escaped it because each produced a MACHINE answer out of a FAILED read.
    # ...and the SECOND site of the same rule: the issue READS fine, but nothing on it can say who
    # applied the hard-exclusion label it carries. Round 2 fixed the issue read and left the issue
    # TIMELINE read still answering `machine` on a failed read.
    opaque_issue = pull(18, "1" * 40, labels=("needs:user",))
    opaque_issue["body"] = "Closes #4444"
    oi_api = FakeAPI([opaque_issue], timelines={18: labelled_by(bot_login, "needs:user")},
                     issues={4444: ("needs:design",)})      # live label, NO timeline event
    oi_reb = FakeRebaser()
    oi_res = ConflictResolver(oi_api, snapshot, claim, [repo], bot_login, True, 5, oi_reb)
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        oi_rc = oi_res.run()
    check(
        "[#1191] an UNATTRIBUTABLE hold ON THE SOURCE ISSUE is not permission either: the issue "
        "reads fine, its timeline cannot say who applied the hold it carries, so the hold stands",
        (oi_reb.calls, oi_rc, oi_res.census[0]["skipped"].get("hold-ownership-unreadable")),
        ([], 1, 1),
    )

    unreadable_issue = pull(16, "1" * 40, labels=("needs:user",))
    unreadable_issue["body"] = "Closes #4343"
    ui_api = FakeAPI([unreadable_issue], timelines={16: labelled_by(bot_login, "needs:user")},
                     issues={4343: None})       # the issue read RAISES
    ui_reb = FakeRebaser()
    ui_res = ConflictResolver(ui_api, snapshot, claim, [repo], bot_login, True, 5, ui_reb)
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        ui_rc = ui_res.run()
    check(
        "[#1191] an UNREADABLE source issue is not permission: the PR reads machine-applied, the "
        "one surface that could still hold it cannot be read, so the hold stands and reds the run",
        (ui_reb.calls, ui_rc, ui_res.census[0]["skipped"].get("hold-ownership-unreadable"),
         ui_res.census[0]["no_exit"]),
        ([], 1, 1, 1),
    )

    class BrokenProbeAPI(FakeAPI):
        def request(self, method, url, body=None):
            if method == "GET" and "/collaborators/" in url:
                raise ResolverError("collaborator probe unavailable (403)")
            return super().request(method, url, body)

    bp_api = BrokenProbeAPI([pull(17, "1" * 40, labels=("needs:user",))],
                            timelines={17: labelled_by("jeswr", "needs:user")})
    bp_reb = FakeRebaser()
    bp_res = ConflictResolver(bp_api, snapshot, claim, [repo], bot_login, True, 5, bp_reb)
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        bp_rc = bp_res.run()
    check(
        "[#1191] a FAILED maintainer probe cannot answer `machine`: the hold here IS the "
        "maintainer's, and a 403 on the collaborator endpoint must not rebase under them",
        (bp_reb.calls, bp_rc, bp_res.census[0]["skipped"].get("hold-ownership-unreadable")),
        ([], 1, 1),
    )

    # (k4) THE MACHINE EXIT IS REAL, AND IT IS CAUSE-GATED. A relabelled hold with no exit is
    # worse than the visible one it replaced, so the class split is only honest if the park
    # actually clears — on the CAUSE, never on the clock.
    def parked_pr_api(head="b" * 40, generation=1, granted=False, now=base_now):
        """A PR sitting in exactly the state _escalate_stuck leaves behind."""
        parked = pull(83, head, labels=(MACHINE_PARK_LABEL,))
        rows = [attempt_comment(head, iso(now))]
        rows.append({"body": stuck_receipt(STUCK_PARK_MARKER, head, generation),
                     "user": {"login": bot_login}, "created_at": iso(now)})
        if granted:
            rows.append({"body": stuck_receipt(STUCK_UNPARK_MARKER, head, generation),
                         "user": {"login": bot_login}, "created_at": iso(now)})
        parked_api = FakeAPI([parked], now=now)
        parked_api.comment_rows[83] = rows
        return parked_api

    def exit_sweep(parked_api, elapsed_hours=0.0):
        sweep = ConflictResolver(
            parked_api, snapshot, claim, [repo], bot_login, True, 5, FakeRebaser("clean"),
            stuck_grace_hours=grace, clock=lambda: base_now + elapsed_hours * 3600.0)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            rc = sweep.run()
        return rc, sweep, parked_api

    # THE ANTI-TIMER CONTROL. The identical park, evaluated 1000 h later, is the identical
    # answer. Registry #769's whole finding was that "the evidence clearing an age park was, in
    # substance, MORE AGE"; wire any clock into stuck_park_cause_recovered and this reds.
    held_rc, held, held_api = exit_sweep(parked_pr_api(), elapsed_hours=1000.0)
    check(
        "[EXIT MACHINE] the park STANDS while its cause has not recovered — 1000 h of further "
        "waiting is not evidence, and a standing park is not a no-exit",
        (held_rc, held_api.labels_removed, held.census[0]["stuck_park_stands"],
         held.census[0]["stuck_readmitted"], held.census[0]["no_exit"],
         held.census[0]["escalated"],
         held.census[0]["skipped"].get("stuck-park-stands")),
        (0, [], 1, 0, 0, 0, 1),
    )
    # RECOVERY 1: the head moved — the author did the thing the window was waiting for.
    moved_api = parked_pr_api()
    moved_api.set_head(83, "e" * 40)
    moved_rc, moved, moved_api = exit_sweep(moved_api)
    moved_bodies = _comment_bodies(moved_api.comment_rows[83])
    check(
        "[EXIT MACHINE] a MOVED HEAD clears the park, receipt-first, and the PR re-enters the "
        "ordinary mechanical-rebase path in the same tick",
        (moved_rc, moved_api.labels_removed,
         sum(STUCK_UNPARK_MARKER in body for body in moved_bodies),
         moved.census[0]["stuck_readmitted"], moved.census[0]["stuck_park_stands"],
         moved.census[0]["resolved"]),
        (0, [(83, MACHINE_PARK_LABEL)], 1, 1, 0, 1),
    )
    # RECEIPT-FIRST IS AN ORDERING PROPERTY, so it is asserted over the ORDERED event log and
    # not over end-state. MEASURED (review round 1): the check above was credited with killing
    # the inverted-ordering mutant and does not — it cannot, because `comment_rows` and
    # `labels_removed` are separate lists in which "receipt then unlabel" and "unlabel then
    # receipt" are byte-identical. What it actually kills is `_post` DELETED, which is the other
    # defect (a receipt never minted, rather than minted late).
    #
    # WHY THE ORDER IS LOAD-BEARING (#610): dying between the two writes must leave
    # receipt-with-label, which the `grant is not None` branch converges on the next tick.
    # Inverted, the crash leaves label-gone-with-no-receipt: nothing records that the recovery
    # was consumed, the PR re-enters the stuck state, and the SAME recovery is earned a second
    # time — the consume-exactly-once invariant broken by an ordering alone.
    moved_events = [event for event in moved_api.events if event[0] == 83]
    check(
        "[EXIT MACHINE] RECEIPT-FIRST: the un-park receipt is durable BEFORE the label is "
        "deleted, so the only crash residue is the one the convergence branch can complete",
        (moved_events.index((83, "comment", "unpark-receipt"))
         < moved_events.index((83, "remove-label", MACHINE_PARK_LABEL)),
         [event for event in moved_events
          if event[2] in ("unpark-receipt", MACHINE_PARK_LABEL)]),
        (True, [(83, "comment", "unpark-receipt"), (83, "remove-label", MACHINE_PARK_LABEL)]),
    )
    # RECOVERY 2: the conflict resolved. This is why the exit phase runs BEFORE the mergeability
    # classification — after it, the `not-conflicting` return strands the label forever.
    merged_api = parked_pr_api()
    merged_api.set_mergeable(83, True)
    merged_rc, merged, merged_api = exit_sweep(merged_api)
    check(
        "[EXIT MACHINE] a RESOLVED CONFLICT clears the park even though the PR is no longer in "
        "the conflicting population",
        (merged_rc, merged_api.labels_removed, merged.census[0]["stuck_readmitted"],
         merged.census[0]["conflicting"]),
        (0, [(83, MACHINE_PARK_LABEL)], 1, 0),
    )
    # CONSUME-EXACTLY-ONCE + CONVERGENCE. A grant already on record with the label still live is
    # the only crash residue receipt-first ordering can produce: converge the unlabel, mint
    # NOTHING, consume no new evidence.
    granted_api = parked_pr_api(granted=True)
    granted_rc, granted, granted_api = exit_sweep(granted_api, elapsed_hours=1000.0)
    granted_bodies = _comment_bodies(granted_api.comment_rows[83])
    check(
        "[EXIT MACHINE] an already-granted recovery CONVERGES the unlabel and mints no second "
        "receipt — the same recovery can never be re-earned",
        (granted_rc, granted_api.labels_removed,
         sum(STUCK_UNPARK_MARKER in body for body in granted_bodies),
         granted.census[0]["stuck_readmitted"]),
        (0, [(83, MACHINE_PARK_LABEL)], 1, 1),
    )

    # (k4b) THE RECEIPT KEY IS ROUND-TRIPPED — the WRITE side, which had no guard at all.
    #
    # MEASURED (review round 3): both arguments of the minted un-park key
    # `stuck_receipt(STUCK_UNPARK_MARKER, park["head"], park["gen"])` were unpinned, INCLUDING by
    # the check immediately above whose name carries the property. That check drives
    # `parked_pr_api(granted=True)`, and the fixture builds the grant from the SAME head and
    # generation as the park — so the read side matches by construction and the row cannot
    # disagree however wrong the written key is.
    #
    # THIS IS A DIFFERENT FAILURE FROM M23, and worth naming separately because the question that
    # catches it is different. M23 was "a value pinned through a pure helper while the call site
    # recomputes it" — ask *which layer computes this?*. This one is "the fixture derives its
    # expected value from the same source as the code under test" — ask *does my expected value
    # come from the same place the code gets it?*. When both sides read `park[...]`, the
    # assertion is a tautology and no amount of naming it makes it a guard.
    #
    # Three assertions, none of which can read its expectation out of `park[...]`, and each
    # pinning a different consequence:
    roundtrip_api = parked_pr_api()                    # parked at head "b"*40, generation 1
    roundtrip_api.set_head(83, "e" * 40)               # the author pushed: the cause recovers
    _roundtrip_rc, _roundtrip, roundtrip_api = exit_sweep(roundtrip_api)
    minted = [body for body in _comment_bodies(roundtrip_api.comment_rows[83])
              if STUCK_UNPARK_MARKER in body]
    check(
        "[EXIT MACHINE] ROUND TRIP: the minted un-park key names the PARKED head and the PARKED "
        "generation — matched against a LITERAL, not against `park[...]`",
        (len(minted),
         ("<!-- conflict-resolver stuck-unpark:v1 cause=head-unmoved "
          f"head={'b' * 40} gen=1 -->") in (minted[0] if minted else "")),
        (1, True),
    )
    # CONSEQUENCE 1 — a WRONG HEAD breaks convergence. The receipt landed and the DELETE did not
    # (the only crash residue receipt-first ordering can produce); the next tick must recognise
    # the grant it minted itself, which it can only do if the key it WROTE is the key it READS.
    # Point the key at the live head and this tick mints a SECOND receipt instead.
    roundtrip_api.prs[83].setdefault("labels", []).append({"name": MACHINE_PARK_LABEL})
    residue_rc, residue, roundtrip_api = exit_sweep(roundtrip_api, elapsed_hours=1000.0)
    check(
        "[EXIT MACHINE] ROUND TRIP: the crash-residue tick CONVERGES on the receipt it minted "
        "itself — still exactly ONE, because the key written is the key read",
        (residue_rc,
         sum(STUCK_UNPARK_MARKER in body
             for body in _comment_bodies(roundtrip_api.comment_rows[83])),
         residue.census[0]["stuck_readmitted"], len(roundtrip_api.labels_removed)),
        (0, 1, 1, 2),
    )
    # CONSEQUENCE 2 — a WRONG GENERATION PRE-GRANTS a park that has not happened yet, and this is
    # the serious one: a machine hold that clears itself with NO cause proof, i.e. the exact
    # fail-open this whole PR exists to prevent. Generation 1 recovers by the conflict resolving
    # (so the head is unchanged and only the GENERATION can be wrong), the PR conflicts again on
    # the same head and is parked at generation 2 — whose cause has NOT recovered. It must STAND.
    pregrant_api = parked_pr_api()                     # parked at head "b"*40, generation 1
    pregrant_api.set_mergeable(83, True)               # the conflict resolved: the cause recovers
    exit_sweep(pregrant_api)
    pregrant_api.set_mergeable(83, False)              # ...and it conflicts again, same head
    pregrant_api.comment_rows[83].append(
        {"body": stuck_receipt(STUCK_PARK_MARKER, "b" * 40, 2),
         "user": {"login": bot_login}, "created_at": iso(base_now)})
    pregrant_api.prs[83].setdefault("labels", []).append({"name": MACHINE_PARK_LABEL})
    pregrant_rc, pregrant, pregrant_api = exit_sweep(pregrant_api, elapsed_hours=1000.0)
    check(
        "[EXIT MACHINE] ROUND TRIP: a LATER park is NOT pre-granted by the previous grant — "
        "generation 2 with an unmoved head STANDS, and 1000 h does not change that",
        (pregrant_rc, pregrant.census[0]["stuck_park_stands"],
         pregrant.census[0]["stuck_readmitted"], pregrant_api.labels_removed[1:]),
        (0, 1, 0, []),
    )

    # THE CAP. An over-cap park was written in the HUMAN class at park time, so the exit phase
    # must not even consider it — `stuck_unpark_state` refuses to answer.
    check(
        "[EXIT MACHINE] the cap is enforced at PARK time: over-cap parks are the human class and "
        "the exit phase never sees them",
        (stuck_park_label(1), stuck_park_label(STUCK_UNPARK_MAX),
         stuck_park_label(STUCK_UNPARK_MAX + 1),
         stuck_unpark_state(
             [{"body": stuck_receipt(STUCK_PARK_MARKER, "b" * 40, STUCK_UNPARK_MAX + 1),
               "user": {"login": bot_login}}], bot_login)),
        (MACHINE_PARK_LABEL, MACHINE_PARK_LABEL, HUMAN_PARK_LABEL, (None, None)),
    )
    over_cap_api = parked_pr_api(generation=STUCK_UNPARK_MAX + 1)
    over_cap_rc, over_cap, over_cap_api = exit_sweep(over_cap_api, elapsed_hours=1000.0)
    check(
        "[EXIT MACHINE] ...so an over-cap park is neither cleared nor counted as one of ours",
        (over_cap_rc, over_cap_api.labels_removed,
         over_cap.census[0]["stuck_readmitted"], over_cap.census[0]["stuck_park_stands"]),
        (0, [], 0, 0),
    )
    # NOTHING THIS PROGRAM DOES CLEARS A HUMAN HOLD. The ten live PRs this change exists to stop
    # producing keep their machine-applied `needs:user`: the fix is the SOURCE fix, applied
    # forward, and the triage deliberately cleared none of them. Two independent reasons make that
    # true here — they carry no receipt of ours, and a human-owned hold outranks the exit phase —
    # so this asserts the SECOND one, which is the only one a later PR could accidentally remove.
    held_by_human = parked_pr_api()
    held_by_human.prs[83].setdefault("labels", []).append({"name": HUMAN_PARK_LABEL})
    # #1191: the hold is now HUMAN-owned by EVIDENCE, not by spelling. `jeswr` is the fixture's
    # only repo admin, so this is the one actor whose application the strict maintainer probe
    # confirms. Re-point this event at `bot_login` and the hold is released instead.
    held_by_human.timelines[83] = [
        {"event": "labeled", "label": {"name": HUMAN_PARK_LABEL},
         "actor": {"login": "jeswr"}, "created_at": iso(base_now)},
    ]
    held_by_human.set_head(83, "e" * 40)             # its cause HAS recovered — and it stays put
    human_rc, human_sweep, held_by_human = exit_sweep(held_by_human, elapsed_hours=1000.0)
    check(
        "[EXIT MACHINE] a human-owned hold outranks the exit: a PROVEN recovery clears NOTHING "
        "while `needs:user` is live, and the machine park is left exactly as it was",
        (human_rc, held_by_human.labels_removed, held_by_human.labels_added,
         human_sweep.census[0]["stuck_readmitted"],
         human_sweep.census[0]["skipped"].get("hard-exclusion-label")),
        (0, [], [], 0, 1),
    )
    # THE TRUST FILTER. A third party cannot forge a park receipt and talk this program into
    # clearing a `review:parked` it never applied, nor into skipping a PR it owns.
    forged = parked_pr_api()
    forged.comment_rows[83] = [
        dict(row, user={"login": "drive-by"}) for row in forged.comment_rows[83]
    ]
    check(
        "[EXIT MACHINE] a FORGED park receipt is not ours: nothing is cleared and no park is "
        "attributed to this program",
        (stuck_unpark_state(forged.comment_rows[83], bot_login),
         stuck_receipts(forged.comment_rows[83], bot_login, STUCK_PARK_MARKER)),
        ((None, None), []),
    )
    # THE SHARED-LABEL GUARD, in the direction that matters for the OTHER sweeps: a park receipt
    # of ours makes dispatch-claim's capacity sweep leave the park alone, so the machine exit
    # cannot be pre-empted by the sustained-fleet-health heuristic — whose only condition this
    # class could ever satisfy is being old enough. That is the same "more age is not evidence"
    # defect registry #769 closed for groom, and the spelling is shared, not hand-copied.
    check(
        "[EXIT MACHINE] park_policy binds this episode so the capacity sweep cannot clear it on "
        "age, and the two marker spellings are WIRE FORMAT shared with the reader",
        (_park_policy.cause_gated_park_episode(
            {MACHINE_PARK_LABEL},
            [{"user": {"login": bot_login},
              "body": stuck_receipt(STUCK_PARK_MARKER, "b" * 40, 1),
              "created_at": "2026-07-28T10:00:00Z"}],
            bot_login)[0],
         _park_policy.age_park_episode is _park_policy.cause_gated_park_episode,
         (STUCK_PARK_MARKER, STUCK_UNPARK_MARKER)),
        (True, True,
         ("<!-- conflict-resolver stuck-park:v1", "<!-- conflict-resolver stuck-unpark:v1")),
    )
    # ...and the LABELS themselves, against literals. Found by re-asking the round-3 question of
    # every row in this block: every class assertion above compares what the resolver wrote
    # against `MACHINE_PARK_LABEL` / `HUMAN_PARK_LABEL`, which is the SAME constant the resolver
    # writes from — so repoint either one and every class check still passes while this program
    # writes a hold no other lane honours. (`needs:user` was already literal-pinned, by the
    # pre-existing `two distinct attempts add needs:user exactly once`; `review:parked` was not
    # pinned anywhere.) The cause token is the third value on that wire and is pinned the same
    # way, since a durable receipt already on a live PR stops parsing if it changes.
    check(
        "[EXIT MACHINE] the park LABELS and the cause token are WIRE FORMAT too — pinned to "
        "literals, because every other class check reads them from the same constant the "
        "resolver writes from",
        (MACHINE_PARK_LABEL, HUMAN_PARK_LABEL, STUCK_PARK_CAUSE),
        ("review:parked", "needs:user", "head-unmoved"),
    )
    check(
        "[EXIT MACHINE] ...control: a `review:parked` with NO receipt of ours is NOT bound, so "
        "no existing capacity park loses its own exit",
        _park_policy.cause_gated_park_episode(
            {MACHINE_PARK_LABEL},
            [{"user": {"login": bot_login}, "body": "an ordinary capacity park",
              "created_at": "2026-07-28T10:00:00Z"}],
            bot_login),
        (False, ""),
    )

    # (l) A marker we cannot date is NOT silently treated as forever-young: the grace window is
    # unevaluable, so the PR is a loud no-exit and the run reds. Fail-LOUD, never fail-open.
    undated_api = FakeAPI([pull(81, "c" * 40)], now=base_now)
    undated_api.comment_rows[81] = [attempt_comment("c" * 40, None)]
    undated = ConflictResolver(
        undated_api, snapshot, claim, [repo], bot_login, True, 5, FakeRebaser("conflict"),
        stuck_grace_hours=grace, clock=lambda: base_now + 100 * 3600.0)
    stderr = StringIO()
    with redirect_stdout(StringIO()), redirect_stderr(stderr):
        undated_rc = undated.run()
    check(
        "an undatable attempt marker is a loud no-exit failure, never a silent skip",
        (undated_rc, undated.census[0]["no_exit"], undated_api.labels_added,
         "no automated exit" in stderr.getvalue(),
         "::error::conflict-resolver left 1 conflicting pull request(s)" in stderr.getvalue()),
        (1, 1, [], True, True),
    )

    # (m) STICKINESS. `exit 0` swallowing an already-earned failure has bitten this repo
    # repeatedly, always as a later clean pass discarding an earlier hard one — so assert the
    # INTERLEAVING in both orders, not just the single-repository case.
    class MultiRepoAPI(FakeAPI):
        def __init__(self, pulls_by_repo, now=base_now):
            super().__init__(
                [row for rows in pulls_by_repo.values() for row in rows], now=now
            )
            self.pulls_by_repo = pulls_by_repo

        def repository(self, repo_name):
            return {"full_name": repo_name, "default_branch": "main"}

        def pulls(self, repo_name):
            return [deepcopy(row) for row in self.pulls_by_repo.get(repo_name, [])]

    no_exit_pr = pull(90, "d" * 40, owner_repo=repo_a)
    clean_pr = pull(91, "e" * 40, owner_repo=repo_b)
    clean_pr["mergeable"] = True

    def sticky_sweep(order):
        multi = MultiRepoAPI({repo_a: [no_exit_pr], repo_b: [clean_pr]})
        multi.comment_rows[90] = [attempt_comment("d" * 40, None)]
        sweep = ConflictResolver(
            multi, snapshot, claim, list(order), bot_login, True, 5, FakeRebaser("conflict"),
            stuck_grace_hours=grace, clock=lambda: base_now + 100 * 3600.0)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            return sweep.run(), sweep.census

    rc_failure_first, census_failure_first = sticky_sweep((repo_a, repo_b))
    rc_failure_last, census_failure_last = sticky_sweep((repo_b, repo_a))
    check(
        "a clean repository scanned after a no-exit one cannot launder the failure",
        (rc_failure_first, rc_failure_last,
         sum(row["no_exit"] for row in census_failure_first),
         sum(row["no_exit"] for row in census_failure_last),
         [row["repo"] for row in census_failure_last]),
        (1, 1, 1, 1, [repo_b, repo_a]),
    )

    # (n) A run that resolved nothing must be distinguishable from a run that had nothing to
    # resolve. Every considered PR lands in exactly ONE bucket, so the buckets sum to considered,
    # and the whole census is emitted machine-readably plus into the job step summary.
    mixed = [
        pull(100, "1" * 40),                            # eligible -> attempted -> resolved
        pull(101, "2" * 40, labels=("needs:user",)),    # conflicting, parked for a human
        pull(102, "3" * 40, head_repo="fork/repo"),     # conflicting, out of scope
        pull(103, "4" * 40, draft=True),                # conflicting draft, capped out below
        pull(104, "5" * 40),                            # not conflicting at all
    ]
    mixed[4]["mergeable"] = True
    mixed_api = FakeAPI(mixed, now=base_now)
    # #1191: PR 101 is held because a PROVEN HUMAN applied the label, which is the only shape that
    # still excludes. Without this event the same PR is `hold-ownership-unreadable` — counted,
    # no-exit, and red — so this is also the row that pins which of the two the fixture means.
    mixed_api.timelines[101] = [
        {"event": "labeled", "label": {"name": "needs:user"},
         "actor": {"login": "jeswr"}, "created_at": iso(base_now)},
    ]
    summary_dir = Path(tempfile.mkdtemp(prefix="conflict-resolver-self-test-"))
    summary_file = summary_dir / "step-summary.md"
    mixed_resolver = ConflictResolver(
        mixed_api, snapshot, claim, [repo], bot_login, True, 1, FakeRebaser("clean"),
        stuck_grace_hours=grace, clock=lambda: base_now, summary_path=str(summary_file))
    stdout = StringIO()
    with redirect_stdout(stdout), redirect_stderr(StringIO()):
        mixed_rc = mixed_resolver.run()
    mixed_row = mixed_resolver.census[0]
    mixed_total = _aggregate_census(mixed_resolver.census)
    summary_text = summary_file.read_text(encoding="utf-8")
    real_rmtree(summary_dir, ignore_errors=True)
    check(
        "the census accounts for every considered PR exactly once",
        (mixed_rc, mixed_row["considered"], mixed_row["conflicting"],
         mixed_row["conflicting_draft"], mixed_row["conflicting_ready"],
         mixed_row["attempted"], mixed_row["resolved"],
         sum(mixed_row["skipped"].values()) + mixed_row["resolved"],
         mixed_row["held_human"], mixed_row["held_released"], mixed_row["unowned"]),
        (0, 5, 4, 1, 3, 1, 1, 5, 1, 0, 0),
    )
    check(
        "a no-op sweep is machine-distinguishable from an effective one",
        "CENSUS-TOTAL " + json.dumps(mixed_total, separators=(",", ":"), sort_keys=True)
        in stdout.getvalue(), True,
    )
    check(
        "the census reaches the job step summary",
        ("### conflict-resolver census" in summary_text
         and "| held: human | held: released | unowned | no exit |" in summary_text
         and "rebase-cap-reached" in summary_text), True,
    )
    check(
        "[#1191] the operator-facing summary leads with the VERDICT, not with a bare count",
        (f"**verdict: `{VERDICT_ACTED}`**" in summary_text,
         "left with no owner." in summary_text),
        (True, True),
    )
    # (n2) THE PER-EXIT CENSUS ROW. The two exits being indistinguishable in the output is why a
    # timeout was reported as exhausted iteration for as long as it was: every run printed
    # `escalated=N` and nothing printed how many of the N were which. Assert BOTH that the
    # operator-facing table names each exit and each class, and that the machine-readable row
    # balances — `two_head + stuck_grace == machine + human == escalated` — because that identity
    # is what makes a silently added third exit visible instead of absorbed.
    exits_seen = [
        _aggregate_census([past["row"]]), _aggregate_census([two_head_row]),
    ]
    check(
        "the census names BOTH exits and BOTH classes, per repo and in aggregate",
        ([column for column in ("| exit: 2-head |", "| exit: stuck-grace |", "| park: machine |",
                                "| park: human |", "| re-admitted |", "| park stands |")
          if column not in summary_text],
         [(row["exit_two_head"], row["exit_stuck_grace"], row["parked_machine"],
           row["parked_human"]) for row in exits_seen]),
        ([], [(0, 1, 1, 0), (1, 0, 0, 1)]),
    )
    check(
        "every escalation is attributed to exactly one exit AND one class",
        [(row["exit_two_head"] + row["exit_stuck_grace"] == row["escalated"],
          row["parked_machine"] + row["parked_human"] == row["escalated"])
         for row in exits_seen + [mixed_row, _aggregate_census(mixed_resolver.census)]],
        [(True, True)] * 4,
    )

    # (n3) [registry #1096] THE FORGED PARK-REASON RECEIPT.
    #
    # This program echoes RAW `git diff` pathnames into a comment authored by the App installation
    # (`git diff -z` does not C-quote, so a pathname is arbitrary attacker-chosen bytes), and
    # park_policy.park_reason_records reads EVERY App-authored comment — not only park receipts —
    # to decide whether a `review:parked` label is machine-owned. Its sibling writer worker-pr.py
    # had the reserved-marker sanitiser; this one did not. Authorship was never forgeable (a
    # `[bot]` login is unregistrable); CONTENT was, and the consumer trusts content it did not
    # itself write.
    #
    # THE MUTATION THIS MUST KILL: delete the `neutralize_reserved_markers` call in `_post` and the
    # first two checks go red. The path is deliberately asserted to REACH the body in defanged form
    # (`<!- sparq-`), so a sanitiser that "worked" by dropping the paths outright would red too.
    forged_marker = _park_policy.park_reason_marker("partition")
    hostile_path = f"src/{forged_marker}/value.py"
    forging_api = FakeAPI([pull(90, "9" * 40)])

    class ForgingRebaser:
        """A conflict whose PATHNAME is the attack — everything else is an ordinary conflict."""

        def __call__(self, _repo_name, pr, _base):
            return RebaseResult("conflict", pr["head"]["sha"],
                                conflicting_files=(hostile_path,))

    ConflictResolver(forging_api, snapshot, claim, [repo], bot_login, True, 5,
                     ForgingRebaser()).run()
    forged_bodies = [row["body"] for row in forging_api.comment_rows[90]]
    check(
        "[#1096] a git pathname carrying a park-reason marker is NEUTRALISED in the App-authored "
        "conflict comment — and still reaches the reader, defanged, so the guard is not the paths "
        "being silently dropped",
        (len(forged_bodies),
         any(_park_policy.contains_reserved_marker(body) for body in forged_bodies),
         any("<!- sparq-park-reason:v1" in body for body in forged_bodies)),
        (1, False, True),
    )
    check(
        "[#1096] ...so the crafted pathname classifies NO park: the consumer that reads every "
        "App-authored comment finds no receipt",
        _park_policy.park_reason_records(forging_api.comment_rows[90], bot_login),
        [],
    )
    # THE SECOND SINK, pinned separately because it is a different call site with a different
    # body-builder: `escalation_body` re-echoes the same paths recovered from the durable attempt
    # comments. Both reach GitHub through `_post`, which is the whole point of putting the
    # sanitiser there rather than at each field.
    escalation_api = FakeAPI([pull(91, "9" * 40)])
    ConflictResolver(escalation_api, snapshot, claim, [repo], bot_login, True, 5,
                     FakeRebaser())._post(
        repo, 91, escalation_body(EXIT_TWO_HEAD, (hostile_path,), 2, HUMAN_PARK_LABEL))
    escalation_body_text = escalation_api.comment_rows[91][0]["body"]
    check(
        "[#1096] the ESCALATION body goes out through the same choke point and is neutralised too",
        (_park_policy.contains_reserved_marker(escalation_body_text),
         "<!- sparq-park-reason:v1" in escalation_body_text,
         _park_policy.park_reason_records(escalation_api.comment_rows[91], bot_login)),
        (False, True, []),
    )
    # WHY WHOLE-BODY NEUTRALISATION IS SOUND HERE, asserted rather than asserted-in-prose. `_post`
    # defangs the entire body, which is only safe while this program mints nothing in the reserved
    # `sparq-` namespace — every durable marker it writes lives in the `conflict-resolver` one and
    # must survive byte-for-byte. The constant NAMES are pinned as well as their transparency, so
    # adding a marker reds here (pointing at this reasoning) instead of being silently defanged on
    # the way out, which is the failure mode that let the sanitiser be skipped in the first place.
    resolver_markers = {name: value for name, value in globals().items()
                        if name.endswith("_MARKER") and isinstance(value, str)}
    check(
        "[#1096] EVERY durable marker this program mints survives the sanitiser byte-for-byte — a "
        "NEW writer in the reserved namespace cannot silently skip the choke point",
        (sorted(resolver_markers),
         sorted(name for name, value in resolver_markers.items()
                if _park_policy.neutralize_reserved_markers(value) != value)),
        (["DEPENDABOT_MARKER", "ESCALATION_MARKER", "STUCK_PARK_MARKER", "STUCK_UNPARK_MARKER"],
         []),
    )
    check(
        "[#1096] ...including the RENDERED grace-window receipts, not just the marker openers",
        [receipt for receipt in (stuck_receipt(STUCK_PARK_MARKER, "a" * 40, 1),
                                 stuck_receipt(STUCK_UNPARK_MARKER, "a" * 40, 1))
         if _park_policy.neutralize_reserved_markers(receipt) != receipt],
        [],
    )

    # (n4) THE VERDICT ITSELF (#1191), as a truth table over the pure function — because the thing
    # that ran 114 times was not a wrong number, it was a run with no verdict at all. Each row
    # pins one boundary, and the two IDLE rows are the ones that keep this alarm READABLE: an
    # alarm that fires on every quiet sweep gets muted, and a muted alarm is the state we started
    # in wearing a different name.
    def total(**kw):
        row = {"considered": 0, "conflicting": 0, "conflicting_draft": 0, "conflicting_ready": 0,
               "selected": 0, "attempted": 0, "resolved": 0, "escalated": 0, "exit_two_head": 0,
               "exit_stuck_grace": 0, "parked_machine": 0, "parked_human": 0,
               "stuck_readmitted": 0, "stuck_park_stands": 0, "awaiting_author": 0,
               "held_human": 0, "held_released": 0, "unowned": 0, "no_exit": 0, "errors": 0}
        row.update(kw)
        return row

    check(
        "[#1191] the run verdict: work is `acted`, an owned population is `correctly-idle`, and "
        "ONLY zero-work-with-an-unowned-population is INERT",
        [run_verdict(total()),                                       # nothing open at all
         run_verdict(total(conflicting=39, held_human=39)),          # all 39 owned by people
         run_verdict(total(conflicting=39, unowned=39)),             # THE 07-29 PRODUCTION SHAPE
         run_verdict(total(conflicting=39, unowned=38, attempted=1)),
         run_verdict(total(conflicting=39, unowned=38, escalated=1)),
         run_verdict(total(conflicting=39, unowned=38, resolved=1)),
         run_verdict(total(conflicting=39, unowned=38, selected=1)),
         run_verdict(total(conflicting=39, unowned=38, stuck_readmitted=1))],
        [VERDICT_IDLE, VERDICT_IDLE, VERDICT_INERT] + [VERDICT_ACTED] * 5,
    )
    # ...and the aggregate carries it, so the machine-readable CENSUS-TOTAL line an operator or a
    # later script greps is the same answer the exit code was computed from.
    check(
        "[#1191] the verdict travels in CENSUS-TOTAL, not only in the exit code",
        (_aggregate_census([{**total(conflicting=1, unowned=1), "repo": "x", "skipped": {}}]
                           )["verdict"],
         "VERDICT " + VERDICT_INERT in
         "\n".join(line for line in stdout.getvalue().splitlines()) or
         "VERDICT " + VERDICT_ACTED in stdout.getvalue()),
        (VERDICT_INERT, True),
    )

    # (n5) THE TAXONOMY IS TOTAL, checked against the SOURCE rather than against a hand-list.
    #
    # The whole mechanism rests on `SKIP_OWNERSHIP` naming an owner for every skip this program
    # can emit; a key missing from it is a conflicting PR whose disposal nobody classified. A
    # hand-maintained list of expected keys would rot in exactly the direction that hurts, so the
    # call sites are read out of this file's own AST — `self._skip(..., key)` and
    # `self.current.skip(key)` — and every literal must be classified. Add a `_skip` with a new
    # key and this row goes red naming it.
    def skip_keys_in_source():
        tree = ast.parse(Path(__file__).resolve().read_text(encoding="utf-8"))
        # PRUNED, not filtered by name. `_self_test` is full of deliberately bogus keys and
        # `_skip` itself contains the forwarding `self.current.skip(key)` whose argument is a
        # variable by construction — scanning either turns this guard into noise it would then be
        # "fixed" by loosening. Everything else in the file is in scope.
        pruned = {id(node) for parent in ast.walk(tree)
                  if isinstance(parent, ast.FunctionDef) and parent.name in ("_self_test", "_skip")
                  for node in ast.walk(parent)}
        keys, unpinned = set(), []
        for node in ast.walk(tree):
            if id(node) in pruned:
                continue
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr == "_skip":
                arg = next((kw.value for kw in node.keywords if kw.arg == "key"), None)
                if arg is None and len(node.args) >= 4:
                    arg = node.args[3]
                if arg is None and len(node.args) == 3:
                    arg = node.args[2]        # reason doubles as the key
            elif node.func.attr == "skip" and isinstance(node.func.value, ast.Attribute) \
                    and node.func.value.attr == "current":
                arg = node.args[0] if node.args else None
            else:
                continue
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                keys.add(arg.value)
            else:
                unpinned.append(ast.unparse(node)[:80])
        return keys, unpinned

    # (n6) THE COUNTER CANNOT BE REACHED WITHOUT A WRITE — asserted over the SOURCE, because the
    # property is about the SET of call sites and no behavioural row can see a site that does not
    # exist yet. Three separate branches of this one change scored `escalated` while mutating
    # nothing; the answer is not a fourth guard but a single choke point, and this row is what
    # keeps it single. Add a `self._count_exit(...)` anywhere else and it goes red naming the
    # function it appeared in.
    def count_exit_call_sites():
        tree = ast.parse(Path(__file__).resolve().read_text(encoding="utf-8"))
        sites = []
        for parent in ast.walk(tree):
            if not isinstance(parent, ast.FunctionDef) or parent.name == "_self_test":
                continue
            for node in ast.walk(parent):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "_count_exit"):
                    sites.append(parent.name)
        return sorted(set(sites))

    check(
        "[#1191] `_count_exit` — the WORK counter — is reachable from exactly ONE function, the "
        "one that has just added a label the PR did not carry",
        count_exit_call_sites(),
        ["_apply_park_label"],
    )

    source_keys, unpinned_keys = skip_keys_in_source()
    check(
        "[#1191] every skip key this program can emit has a named owner in SKIP_OWNERSHIP, and "
        "none is computed rather than literal",
        (sorted(source_keys - set(SKIP_OWNERSHIP)), unpinned_keys,
         sorted(set(SKIP_OWNERSHIP) - source_keys)),
        ([], [], []),
    )
    # ...and the DEFAULT DIRECTION for one that slips through anyway. An unclassified key is
    # counted as UNOWNED and announced, never quietly assumed benign — that assumption is the
    # whole shape of this defect. Flip the `owner = OWNER_NONE` default to OWNER_ELSEWHERE and
    # this row goes red on both the counter and the warning.
    rogue = ConflictResolver(FakeAPI([]), snapshot, claim, [repo], bot_login, False, 5,
                             FakeRebaser())
    rogue._in_population = True
    rogue_err = StringIO()
    with redirect_stdout(StringIO()), redirect_stderr(rogue_err):
        rogue._skip(repo, 1, "a reason nobody classified", "not-in-the-taxonomy")
    check(
        "[#1191] an UNCLASSIFIED skip reason counts as unowned and says so",
        (rogue.current.unowned, "has no entry in SKIP_OWNERSHIP" in rogue_err.getvalue()),
        (1, True),
    )
    # ...and the population gate: the same key OUTSIDE the conflicting population is silent, so
    # `not-conflicting` on 99 healthy PRs a tick cannot manufacture an alarm.
    quiet = ConflictResolver(FakeAPI([]), snapshot, claim, [repo], bot_login, False, 5,
                             FakeRebaser())
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        quiet._skip(repo, 1, "not conflicting", "not-in-the-taxonomy")
    check(
        "[#1191] ...but only inside the conflicting population",
        quiet.current.unowned, 0,
    )

    # (o) THE YAML SEAM. Every uncaught mutant in this repo's measured mutation runs lived in a
    # workflow `if:`/step/call-site, not the Python — so pin the CALL SITE itself. Deleting the
    # invocation, dropping --apply or either machine-exit flag, adding continue-on-error, or
    # appending `|| true` reds one of these two checks.
    import yaml as workflow_yaml

    workflow_path = (
        Path(__file__).resolve().parent.parent / ".github/workflows/conflict-resolver.yml"
    )
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow_steps = workflow_yaml.safe_load(workflow_text)["jobs"]["resolve"]["steps"]
    resolver_steps = [
        step for step in workflow_steps if "resolve-conflicts.py" in str(step.get("run", ""))
    ]
    # Shell COMMENTS are stripped before the assertion. Measured while writing this check: the
    # first draft matched the flag names in the rationale comment above the invocation, so
    # deleting the actual `--stuck-grace-hours 6 \` line left the test green. A guard that a
    # comment can satisfy is not a guard.
    resolver_body = "\n".join(
        line for line in str(resolver_steps[0].get("run", "")).splitlines()
        if not line.strip().startswith("#")
    ) if resolver_steps else ""
    resolver_run = " ".join(resolver_body.replace("\\\n", " ").split())
    check(
        "the workflow call site wires the resolver and its machine-exit flags",
        (len(resolver_steps),
         [flag for flag in ("python3 scripts/resolve-conflicts.py --self-test",
                            "python3 scripts/resolve-conflicts.py --apply",
                            "--stuck-grace-hours", "--no-exit-threshold",
                            "--registry-repo", "--bot-slug")
          if flag not in resolver_run]),
        (1, []),
    )
    check(
        "the resolver step can neither continue-on-error nor swallow its exit code",
        (resolver_steps[0].get("continue-on-error") if resolver_steps else "no step",
         "|| true" in resolver_run, "set +e" in resolver_run,
         "set -euo pipefail" in resolver_run),
        (None, False, False, True),
    )

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
        "--stuck-grace-hours", type=float, default=DEFAULT_STUCK_GRACE_HOURS,
        help="hours a single recorded conflict attempt may sit on an unmoved head before it "
             "escalates to needs:user (the machine exit from the single-attempt state)",
    )
    parser.add_argument(
        "--no-exit-threshold", type=int, default=DEFAULT_NO_EXIT_ALERT_THRESHOLD,
        help="fail the run when more than this many conflicting PRs are left in a state the "
             "resolver can neither repair nor escalate",
    )
    parser.add_argument(
        "--workspace", default=os.environ.get("RUNNER_TEMP", tempfile.gettempdir()),
        help="runner-local parent directory for full-history temporary clones",
    )
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    if args.max_rebases <= 0:
        parser.error("--max-rebases must be positive")
    if not args.stuck_grace_hours > 0:
        parser.error("--stuck-grace-hours must be positive")
    if args.no_exit_threshold < 0:
        parser.error("--no-exit-threshold must not be negative")
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
            stuck_grace_hours=args.stuck_grace_hours,
            no_exit_threshold=args.no_exit_threshold,
            summary_path=os.environ.get("GITHUB_STEP_SUMMARY") or None,
        ).run()
    except (OSError, ResolverError, tomllib.TOMLDecodeError) as exc:
        print(f"conflict-resolver: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
