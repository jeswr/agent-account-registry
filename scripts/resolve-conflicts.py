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
    spec.loader.exec_module(module)
    return module


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


def _is_human_maintainer(api, repo, login):
    """The strict maintainer probe for the unpark veto (park-policy hygiene finding; the
    worker-issue._is_human_maintainer pattern): repo collaborator permission in
    park_policy.HUMAN_MAINTAINER_PERMISSIONS. Probe-call FAILURE counts as NOT a maintainer
    and emits the shared distinct ::warning:: diagnostic (park_policy.probe_maintainer,
    round-3 Opus finding); a genuine not-a-maintainer permission stays quiet."""
    def read_permission(probe_login):
        payload = api.request("GET", f"/repos/{repo}/collaborators/{probe_login}/permission")
        if not isinstance(payload, dict):
            raise ResolverError("collaborator permission payload is malformed")
        return payload.get("permission")

    return _park_policy.probe_maintainer(repo, login, read_permission)


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
    ever reach is not fused with the two that #657 waives elsewhere."""
    head = pr.get("head") or {}
    if (head.get("repo") or {}).get("full_name") != repo:
        return False
    login = str((pr.get("user") or {}).get("login", ""))
    return bool(
        claim.FIX_KIND_OF_STATE.get("needs-rebase") == "rebase"
        and claim.HEAD_REF_RE.match(str(head.get("ref", "")))
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
                    "stuck_park_stands", "awaiting_author", "no_exit", "errors")
    }
    skipped = {}
    for row in rows:
        for key, count in row["skipped"].items():
            skipped[key] = skipped.get(key, 0) + count
    total["repos"] = len(rows)
    total["skipped"] = dict(sorted(skipped.items()))
    return total


def render_census_summary(rows, total):
    """Markdown for ``$GITHUB_STEP_SUMMARY`` — the operator-facing form of the census."""
    lines = [
        "### conflict-resolver census",
        "",
        "| repo | considered | conflicting (ready/draft) | attempted | resolved | escalated "
        "| exit: 2-head | exit: stuck-grace | park: machine | park: human | re-admitted "
        "| park stands | awaiting author | no exit | errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: "
        "| ---: | ---: | ---: |",
    ]
    for row in [*rows, {**total, "repo": f"**all {total['repos']} repo(s)**"}]:
        lines.append(
            f"| {row['repo']} | {row['considered']} | "
            f"{row['conflicting']} ({row['conflicting_ready']}/{row['conflicting_draft']}) | "
            f"{row['attempted']} | {row['resolved']} | {row['escalated']} | "
            f"{row['exit_two_head']} | {row['exit_stuck_grace']} | "
            f"{row['parked_machine']} | {row['parked_human']} | "
            f"{row['stuck_readmitted']} | {row['stuck_park_stands']} | "
            f"{row['awaiting_author']} | {row['no_exit']} | {row['errors']} |"
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

    def _record(self, kind, repo, number, detail=""):
        self.actions.append((kind, repo, number, detail))
        mode = "APPLY" if self.apply else "DRY-RUN"
        print(f"{mode} {repo}#{number}: {kind}{(': ' + detail) if detail else ''}")

    def _skip(self, repo, number, reason, key=None):
        self.current.skip(key or reason)
        print(f"SKIP {repo}#{number}: {reason}")

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
        if self.apply:
            self.api.comment(repo, number, body)

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

    def _apply_park_label(self, repo, number, park_label, exit_kind, conflicts):
        """Write the park label, honouring the sticky human-unpark veto (park_policy.py defect 2):
        a human who removed THIS label more recently than any application is never overridden, and
        an unreadable timeline never parks. The veto is checked against the label ACTUALLY being
        written, so the machine class is veto-gated exactly as the human class always was."""
        if self.apply:
            if _park_policy.park_vetoed(
                    repo, number, park_label,
                    lambda r, n: self.api.timeline(r, n),
                    is_human=lambda login: _is_human_maintainer(self.api, repo, login)):
                self._record(f"{park_label}-suppressed", repo, number,
                             "sticky human unpark (or unreadable timeline)")
                # A human who un-parked this PR OWNS it: the exit is theirs, not a missing one.
                self._count_exit(exit_kind, park_label)
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
        if not any(ESCALATION_MARKER in body for body in bodies):
            self._post(repo, number, escalation_body(
                EXIT_TWO_HEAD, conflicts, len(attempt_heads(comments, self.bot_login)),
                HUMAN_PARK_LABEL, receipt=ESCALATION_MARKER))
        # Label last: if either mutation is interrupted, the next tick still sees an
        # unheld PR and converges the missing mutation without duplicating the loud marker.
        self._apply_park_label(repo, number, HUMAN_PARK_LABEL, EXIT_TWO_HEAD, conflicts)

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
        generation = stuck_park_generation(comments, self.bot_login)
        park_label = stuck_park_label(generation)
        receipt = stuck_receipt(STUCK_PARK_MARKER, head, generation)
        if self.apply and _park_policy.park_vetoed(
                repo, number, park_label,
                lambda r, n: self.api.timeline(r, n),
                is_human=lambda login: _is_human_maintainer(self.api, repo, login)):
            self._record(f"{park_label}-suppressed", repo, number,
                         "sticky human unpark (or unreadable timeline)")
            self._count_exit(EXIT_STUCK_GRACE, park_label)
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
        self._apply_park_label(repo, number, park_label, EXIT_STUCK_GRACE, conflicts)

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

    def _process_pr(self, repo, default_branch, listed_pr):
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
            self._skip(repo, number, f"hard exclusion label(s): {', '.join(holds)}",
                       "hard-exclusion-label")
            return
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
        if len(heads) >= 2:
            self._escalate_two_head(
                repo, detail, comments, prior_conflicting_files(comments, self.bot_login)
            )
            return
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
        return 1 if (self.errors or total["no_exit"] > self.no_exit_threshold) else 0


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
        def __init__(self, pulls, sequences=None, timelines=None, now=base_now):
            self.tokens = {"example": "test-token"}
            self.now = now
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
    check(
        "[EXIT two-distinct-heads] CALL SITE `head not in heads`: a NEW head with two failed "
        "heads on record escalates to the HUMAN terminal without spending another rebase",
        seeded_two_head_sweep(85, "3" * 40),
        ([(85, HUMAN_PARK_LABEL)], 1, 0, 0, (1, 0, 0, 1)),
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
                (rows[0]["exit_stuck_grace"], rows[0]["parked_machine"]))

    check(
        "[EXIT stuck-grace] a human un-park VETOES the machine park BEFORE the comment: no "
        "receipt is minted, no generation is spent, and a second tick adds nothing",
        stuck_veto_ticks({86: stuck_veto_timeline}),
        (0, [], (1, 1)),
    )
    check(
        "[EXIT stuck-grace] ...PAIRED CONTROL: with no human un-park the SAME two ticks mint "
        "EXACTLY ONE receipt — so the check above is not passing because nothing ever posts",
        stuck_veto_ticks({}),
        (1, [(86, MACHINE_PARK_LABEL)], (1, 1)),
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
         sum(mixed_row["skipped"].values()) + mixed_row["resolved"]),
        (0, 5, 4, 1, 3, 1, 1, 5),
    )
    check(
        "a no-op sweep is machine-distinguishable from an effective one",
        "CENSUS-TOTAL " + json.dumps(mixed_total, separators=(",", ":"), sort_keys=True)
        in stdout.getvalue(), True,
    )
    check(
        "the census reaches the job step summary",
        ("### conflict-resolver census" in summary_text
         and "| awaiting author | no exit |" in summary_text
         and "rebase-cap-reached" in summary_text), True,
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
