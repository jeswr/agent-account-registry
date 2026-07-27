#!/usr/bin/env python3
# [GPT-5.6] REG-3 target-issue control plane: revision-bound trust revalidation, durable attempt
# accounting, and fail-closed status transitions. It never reads registry account credentials.
"""Small GitHub API helper for the live private-registry worker."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def _park_policy():
    """The shared park-label policy module (machine/human ownership + the sticky human-unpark
    veto). Loaded lazily so only the park transitions pay the import."""
    spec = importlib.util.spec_from_file_location(
        "registry_park_policy", Path(__file__).resolve().with_name("park_policy.py"))
    if spec is None or spec.loader is None:
        raise WorkerIssueError("cannot load shared park policy")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _worker_pr():
    """The sibling PR-control module, loaded lazily (same pattern as _park_policy). Used ONLY for
    is_credential_outage — the single shared definition of "this exit class is a credential/capacity
    outage, so no round or attempt was spent" (registry #596). Keeping ONE definition is the point:
    a second copy here would drift from the review-round path it must agree with."""
    spec = importlib.util.spec_from_file_location(
        "registry_worker_pr", Path(__file__).resolve().with_name("worker-pr.py"))
    if spec is None or spec.loader is None:
        raise WorkerIssueError("cannot load the sibling worker-pr module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ATTEMPT_MARKER = "<!-- sparq-worker-attempt:v1"
# [registry #596] CREDENTIAL-OUTAGE attempt void — the task-side mirror of
# worker-pr.ROUND_VOID_MARKER. The attempt receipt is posted BEFORE the model launches (it is the
# last budget gate), so a launch that dies on the worker ACCOUNT's credential — acct01's codex
# OAuth access token expires hourly and the fleet stores a static snapshot of it — used to burn a
# full attempt from the bounded deferred-retry budget without the model ever running. Enough of
# those and the issue reaches status:parked as if the model had declined the task, which inverts the
# park policy: a credential outage is not a decline. worker.yml records this marker for the SAME run
# key the receipt used once the exit class is known, and count_attempts subtracts it.
#
# Bot-authored only, like every other durable marker: a third party cannot forge one to mint budget.
ATTEMPT_VOID_MARKER = "<!-- sparq-worker-attempt-void:v1"
# [issue #568] OWNERSHIP receipt — the compare-and-swap half of the shared `status:in-progress`
# label. The label alone proves only that SOME run claimed the issue; this run-key-bound receipt
# proves WHICH. It is posted BEFORE the label flip (see worker.yml's claim step) so a run's
# ownership is durable from the very first mutation it makes: an older run reaching the
# pre-publish re-check therefore sees a newer run's ownership receipt even during the long
# pre-attempt interval (claim -> worker-prep -> record-attempt), where the ATTEMPT receipt alone
# left a window in which the older run still looked authorized.
#
# DELIBERATELY a distinct marker from ATTEMPT_MARKER: the attempt receipt is the BUDGET unit
# (count_attempts) and the maintainer-approval staleness anchor. Reusing it here would charge a
# second attempt per run and move the approval anchor — so ownership gets its own marker, and the
# budget/approval surfaces are untouched. Bot-authored only, like every other durable marker.
CLAIM_MARKER = "<!-- sparq-worker-claim:v1"
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
    "status:parked",
    "status:untriaged",
    "trust:untrusted",
}
LABEL_COLOURS = {
    "status:in-progress": "fbca04",
    "status:in-progress-review": "c5def5",
    "status:deferred": "d4c5f9",
    "status:parked": "1d76db",
    "status:ready": "0e8a16",
    "needs:user": "b60205",
}
# The park transitions and the label each one applies. `needs:user` is HUMAN-owned (genuine
# human questions only); `status:parked` is the MACHINE-owned capacity/decline/budget soft hold
# (see park_policy.py). Both are gated by the sticky human-unpark veto in set_status.
PARK_STATUS_LABELS = {"needs-user": "needs:user", "parked": "status:parked"}


class WorkerIssueError(RuntimeError):
    """A concise, credential-free operational error."""


def body_sha(body):
    return hashlib.sha256((body or "").encode("utf-8")).hexdigest()


def _attempt_run_keys(body):
    """The run keys carried by the attempt receipts in one comment body."""
    return set(re.findall(re.escape(ATTEMPT_MARKER) + r" run=(\S+) -->", body))


def _ownership_receipt(body):
    """(is_receipt, run_keys) for one comment body (issue #568).

    Ownership evidence is EITHER marker: the CLAIM receipt (posted before the label flip) or the
    ATTEMPT receipt (posted before the model). Taking the union is the conservative direction —
    it can only ever add FOREIGN claims to out-rank, never drop one — and it keeps a run launched
    from an older workflow revision, which posts only an attempt receipt, visible as a claimant.
    A receipt whose run key is unreadable stays a receipt with NO key, so it is attributable to
    nobody and is treated as foreign below."""
    keys = set(re.findall(re.escape(CLAIM_MARKER) + r" run=(\S+) -->", body))
    keys |= _attempt_run_keys(body)
    return (bool(keys) or CLAIM_MARKER in body or ATTEMPT_MARKER in body), keys


def holds_live_claim(comments, bot_login, current_run_key, log=print):
    """True iff the NEWEST worker ownership receipt on the issue is THIS run's own (issue #568).

    The pre-publish re-check cannot demand `status:ready` — the workflow itself moved the issue to
    `status:in-progress` at claim time — so the accepted in-progress state is instead bound to an
    immutable per-run receipt. `status:in-progress` is a SHARED label: it proves only that some run
    claimed the issue, so on its own it is not a compare-and-swap. The newest ownership receipt is:
    a newer receipt from any other run means this run's claim was superseded (redispatch after a
    deferral, a concurrent worker) and this run must not publish over it.

    Ordering is over PARSED aware instants (park_policy.parse_ts), never raw strings — the
    round-5 lesson: an equally-valid space-separator spelling sorts lexicographically before every
    'T'-form stamp of the same day, so a string compare could read a NEWER foreign receipt as
    older and authorize the superseded run.

    Every fail direction is CLOSED: no run key supplied, no receipt of our own, an unparseable
    stamp on ANY receipt (ownership becomes unprovable), and an exact instant tie with a foreign
    receipt all return False. Only bot-authored comments count, so a human quoting the marker text
    can neither steal nor forge a claim.

    Known residues, stated honestly rather than papered over — both are LIVENESS costs or
    seconds-wide, never a silent grant:
      * GitHub comment timestamps are second-granular, so two runs whose receipts land in the SAME
        second both refuse. Safe (nobody publishes), rare (the upstream lease CAS already
        serialises dispatch), and the next tick re-dispatches.
      * This is a check, not a server-side compare-and-swap on the push itself: a foreign receipt
        landing between this read and `git push` is not seen. That window is seconds wide instead
        of the tens of minutes the pre-model-only check left, and closing it entirely needs the
        publish to be transactional with the claim.
    """
    if not current_run_key:
        return False
    parse_ts = _park_policy().parse_ts
    bot = bot_login.casefold()
    ours, foreign = [], []
    for comment in comments:
        if str(comment.get("user", {}).get("login", "")).casefold() != bot:
            continue
        is_receipt, keys = _ownership_receipt(str(comment.get("body", "")))
        if not is_receipt:
            continue
        try:
            stamp = parse_ts(comment.get("created_at"))
        except ValueError:
            log(f"::warning::worker ownership receipt carries an unparseable created_at "
                f"{comment.get('created_at')!r} — this run cannot prove it still holds the "
                "claim; the pre-publish check fails closed")
            return False
        # Ours ONLY when the receipt names this run and nothing else: a body carrying a foreign
        # key too is attributable to that run as well, so it can never establish our ownership.
        (ours if keys == {current_run_key} else foreign).append(stamp)
    if not ours:
        return False
    newest_own = max(ours)
    return all(stamp < newest_own for stamp in foreign)


def attempt_voids(comments, bot_login):
    """The set of run keys whose attempt was VOIDED as a credential outage (registry #596) and so
    must NOT be charged against the deferred-retry budget. Bot-authored only, like every marker
    parser here — a third party's comment can never un-charge an attempt."""
    bot = bot_login.casefold()
    voided = set()
    pattern = re.escape(ATTEMPT_VOID_MARKER) + r" run=(\S+) -->"
    for comment in comments:
        if str(comment.get("user", {}).get("login", "")).casefold() != bot:
            continue
        voided.update(re.findall(pattern, str(comment.get("body", ""))))
    return voided


def count_attempts(comments, bot_login):
    """Durable worker attempts CHARGED to the budget. A receipt whose run was voided as a
    credential outage (registry #596 — the model never launched, so no attempt was spent) is
    subtracted; a receipt with no run key at all is a legacy/degenerate form and stays charged
    (the fail direction is always toward CHARGING)."""
    bot = bot_login.casefold()
    voided = attempt_voids(comments, bot_login)
    charged = 0
    for comment in comments:
        if str(comment.get("user", {}).get("login", "")).casefold() != bot:
            continue
        body = str(comment.get("body", ""))
        if ATTEMPT_MARKER not in body:
            continue
        keys = _attempt_run_keys(body)
        if keys and keys <= voided:
            continue
        charged += 1
    return charged


def count_attempts_since(comments, bot_login, since, log=print):
    """Durable worker attempts charged to the DEFERRED-RETRY budget after a human readmission.

    Mirrors worker-pr.count_rounds_since: `since` is the readmission cutoff
    (park_policy.readmission_cutoff — the latest proven-human unlabel of a park label), and
    only attempt receipts recorded at or after it are charged, so a human's explicit
    re-admission gesture actually re-enables allocation instead of the full historical count
    exiting the tick forever. Fail direction (toward the OLD conservative full count, never a
    fresh budget on unproven data): a falsy `since` charges everything (plain count_attempts),
    and so does an UNPARSEABLE `since`, loudly; a receipt without a created_at is CHARGED; a
    receipt whose created_at cannot be parsed is CHARGED with a loud log (round-4 finding 3 +
    round-5 finding 2: the window compare is over PARSED aware datetimes —
    park_policy.parse_ts — never raw strings, because an equally-valid spelling like the
    space-separator "2026-07-23 10:30:00Z" VALIDATES yet sorts lexicographically before
    "2026-07-23T09:00:00Z", so the old string compare read a post-cutoff receipt as
    pre-cutoff and silently un-charged it; unprovable time always counts AGAINST the budget,
    exactly like the missing-timestamp case); an instant tie with the cutoff is CHARGED."""
    if not since:
        return count_attempts(comments, bot_login)
    parse_ts = _park_policy().parse_ts
    try:
        since_instant = parse_ts(since)
    except ValueError:
        log(f"::warning::readmission cutoff {since!r} is not a parseable timestamp — the "
            "attempt budget keeps the FULL historical count (never a fresh budget on "
            "unproven data)")
        return count_attempts(comments, bot_login)
    bot = bot_login.casefold()
    # Void subtraction is GLOBAL, exactly as in worker-pr.count_rounds_since (registry #596): a
    # credential-outage attempt is uncharged whichever side of the readmission cutoff it landed on.
    voided = attempt_voids(comments, bot_login)
    charged = 0
    for comment in comments:
        if (str(comment.get("user", {}).get("login", "")).casefold() != bot
                or ATTEMPT_MARKER not in str(comment.get("body", ""))):
            continue
        keys = _attempt_run_keys(str(comment.get("body", "")))
        if keys and keys <= voided:
            continue
        created = comment.get("created_at")
        if isinstance(created, str) and created:
            try:
                created_instant = parse_ts(created)
            except ValueError:
                log(f"::warning::attempt receipt carries a malformed created_at {created!r} "
                    "— CHARGED against the attempt budget (unprovable time can never "
                    "authorize exhausted work)")
            else:
                if created_instant < since_instant:
                    continue
        charged += 1
    return charged


def find_maintainer_approval(comments, bot_login, is_human_maintainer, log=print,
                             current_run_key=None):
    """Return the approving comment, or None when the retry must fail closed.

    Evidence of maintainer approval (issue #31) is a comment by a HUMAN maintainer whose body
    matches APPROVAL_RE, created strictly after the bot's most recent attempt receipt (the
    failure being retried). `status:ready` is written by the automation itself (triage/groom/
    the deferred-retry transition below) and is therefore NEVER approval evidence. Bot and App
    logins never count as human, whatever they comment — and neither does a comment whose
    `performed_via_github_app` is non-null: an App driving a maintainer's user token posts as
    user.type=User under the maintainer's own login, so the user-shaped filters and the
    collaborator probe all pass; only the App attribution field betrays that no human typed it.
    `is_human_maintainer(login)` supplies the trusted-set probe so this stays pure and
    self-testable.

    Staleness ordering is over PARSED aware datetimes (park_policy.parse_ts — round-5
    finding 2), never raw strings: a space-separator receipt stamp sorts lexicographically
    before every 'T'-form stamp of the same day, so the old string compare could read a
    PRE-failure approval as post-failure (blessing a run the maintainer never saw fail). Fail
    directions, both closed: an attempt receipt whose created_at cannot be parsed makes
    "strictly after the last failure" unprovable for EVERY candidate — no approval stands
    (loud log); an approval whose created_at cannot be parsed can never prove it postdates
    the failure — that comment never approves.

    `current_run_key` (issue #568) excludes THIS run's own attempt receipt from the staleness
    anchor. record-attempt posts that receipt at the START of a run, long before the pre-publish
    re-check runs — so without the exclusion the re-check would read this run's own start marker
    as "the last failure" and reject the very approval that authorised the run, making publication
    impossible for every third-party issue. The receipt marks a start, not a failure; the
    staleness rule (an approval must postdate the last FAILED attempt) governs FUTURE retries, so
    dropping ONLY the current run's marker cannot mask a real failure from a different run. It is
    passed exclusively on the pre-publish path; dispatch-mode admission still anchors on every
    receipt, this run's included.
    """
    bot = bot_login.casefold()
    parse_ts = _park_policy().parse_ts
    last_failure = None
    for comment in comments:
        if (str(comment.get("user", {}).get("login", "")).casefold() != bot
                or ATTEMPT_MARKER not in str(comment.get("body", ""))):
            continue
        if (current_run_key
                and _attempt_run_keys(str(comment.get("body", ""))) == {current_run_key}):
            continue
        try:
            stamp = parse_ts(comment.get("created_at"))
        except ValueError:
            log(f"::warning::attempt receipt carries an unparseable created_at "
                f"{comment.get('created_at')!r} — approval evidence cannot be proven to "
                "postdate the last failure; the retry fails closed")
            return None
        if last_failure is None or stamp > last_failure:
            last_failure = stamp
    for comment in comments:
        user = comment.get("user", {}) or {}
        login = str(user.get("login", ""))
        if (not login
                or str(user.get("type", "")).casefold() == "bot"
                or login.casefold().endswith("[bot]")
                or login.casefold() == bot
                or comment.get("performed_via_github_app") is not None):
            continue
        if not APPROVAL_RE.search(str(comment.get("body", ""))):
            continue
        # An approval at-or-before the last attempt receipt is stale — it blessed a run that
        # has since failed. Unprovable approval time never blesses anything.
        try:
            approved_at = parse_ts(comment.get("created_at"))
        except ValueError:
            continue
        if last_failure is not None and approved_at <= last_failure:
            continue
        if is_human_maintainer(login):
            return comment
    return None


def _is_human_maintainer(repo, login):
    # Same derivation as the triage-issue trust-gate: collaborator permission probe. The
    # trust-gate's extra exact-match entry is the registry App bot, which is excluded here by
    # design — approval must come from a human. Probe-call FAILURE counts as "not a
    # maintainer" and emits the shared distinct ::warning:: diagnostic
    # (park_policy.probe_maintainer, round-3 Opus finding); a genuine not-a-maintainer
    # permission stays quiet.
    def read_permission(probe_login):
        result = _run_gh(
            ["api", f"repos/{repo}/collaborators/{probe_login}/permission",
             "--jq", ".permission"],
            check=False,
        )
        if result.returncode != 0:
            raise WorkerIssueError(f"permission probe exited {result.returncode}")
        return result.stdout.strip()

    return _park_policy().probe_maintainer(repo, login, read_permission)


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
    for page in pages:
        # A malformed PAGE must RAISE, never be silently dropped: for the timeline it could
        # hold the newest human unlabel (the exact event the park veto and the readmission
        # window hinge on), so the caller's documented fail direction must apply instead
        # (veto => suppress the park; budget/readmission => the full historical count).
        if not isinstance(page, list):
            raise WorkerIssueError(f"GitHub API returned a malformed {resource} page")
        for entry in page:
            # Round-4 finding 4: ENTRIES are validated at read time too — a [[null]] payload
            # passed the page-only check and crashed the first consumer mid-decision. A
            # non-dict entry (any resource), or a comment without the user(dict)/body(str)/
            # created_at(str) shape every counter relies on, raises exactly like a malformed
            # page: the caller's documented conservative fail direction applies (the budget
            # keeps its full count, the veto suppresses the park, the workflow step fails
            # loud) instead of an unhandled crash past the validation boundary. Timeline
            # entries keep the dict-only check here; park_policy._event_rows enforces the
            # per-event shape downstream with the same raise-not-drop rule.
            if not isinstance(entry, dict):
                raise WorkerIssueError(f"GitHub API returned a malformed {resource} entry")
            if resource == "comments" and (
                    not isinstance(entry.get("user"), dict)
                    or not isinstance(entry.get("body"), str)
                    or not isinstance(entry.get("created_at"), str)):
                raise WorkerIssueError("GitHub API returned a malformed comments entry")
    return [item for page in pages for item in page]


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


def _readmission_cutoff(repo, issue):
    """The deferred-retry budget's human-readmission cutoff, derived WORKER-SIDE from the
    live label timeline via the SAME park_policy.readmission_cutoff helper (strict maintainer
    probe, most-recent-event-wins, latest proven-human unlabel of any READMISSION_LABELS)
    that CLAIM used to grant the readmission (round-4 finding 1).

    DELIBERATELY re-derived here, never threaded through the dispatch payload / claim record:
    every other worker admission guard re-derives its evidence live at the last step
    (reverify re-checks author/body/labels/trust, the selected-model step re-checks routing
    equality against the protected catalog) — a caller-supplied cutoff would be the ONE
    budget input the worker takes on faith, letting any workflow_dispatch caller mint fresh
    budget, and it would freeze the evidence at CLAIM time. The durable evidence (the label
    timeline) is readable under the same target App token this budget check already holds.
    Skew between CLAIM and this check is safe in both directions: a human gesture landing
    after CLAIM only widens the window on proven evidence, and an unreadable timeline yields
    None = the FULL historical count (the conservative side — CLAIM freezes its ladder on
    the same unreadable view)."""
    policy = _park_policy()
    return policy.readmission_cutoff(
        repo, issue, None, lambda fetch_repo, number: _paginated(fetch_repo, number, "timeline"),
        is_human=lambda login: _is_human_maintainer(repo, login))


def _windowed_attempts(repo, issue, comments, bot_login, max_attempts):
    """The attempt count CHARGED to the budget: the plain lifetime count below the budget
    line, the readmission-windowed count at/above it (round-4 finding 1 — the windowed-vs-
    lifetime split brain). CLAIM grants a readmission on the WINDOWED count
    (dispatch-claim's deferred lane); the old worker-side re-check used the UNWINDOWED
    lifetime count, so the launched retry declared itself exhausted, ran no model, the final
    re-park was vetoed by the very unlabel that granted the readmission, status:ready
    persisted, and every tick relaunched a no-op workflow forever. The cutoff is probed only
    once the lifetime count is exhausted, exactly like CLAIM."""
    used = count_attempts(comments, bot_login)
    if used < max_attempts:
        return used
    cutoff = _readmission_cutoff(repo, issue)
    if not cutoff:
        return used
    charged = count_attempts_since(comments, bot_login, cutoff)
    if charged < used:
        print(f"readmission window open: a human unlabeled a park label at {cutoff}; the "
              f"attempt budget charges {charged} of {used} recorded attempt(s)")
    return charged


def attempt_check(repo, issue, max_attempts, bot_login):
    comments = _paginated(repo, issue, "comments")
    used = _windowed_attempts(repo, issue, comments, bot_login, max_attempts)
    values = {"used": used, "exhausted": used >= max_attempts}
    _write_outputs(values)
    print(f"worker attempts used: {used}/{max_attempts}")


def record_attempt(repo, issue, max_attempts, bot_login, run_key):
    comments = _paginated(repo, issue, "comments")
    # The recorder is the LAST budget gate before the model launches; it must apply the same
    # readmission window as attempt_check (round-4 finding 1) or a readmitted retry admitted
    # by the check dies here with "exhausted before model launch". Attempt numbering restarts
    # inside a readmission window by design: the budget is windowed, and the receipt's
    # identity is the run key, not the number.
    used = _windowed_attempts(repo, issue, comments, bot_login, max_attempts)
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


def void_attempt_on_outage(repo, issue, bot_login, run_key, exit_class):
    """[registry #596] Un-charge THIS run's attempt receipt when the model launch died on the
    worker account's credential/capacity (auth / rate-limit / session-limit / billing). The class
    gate is worker-pr.is_credential_outage — ONE definition shared by both the review-round and the
    task-attempt path, so the two can never drift.

    Called from worker.yml right after the exit class is captured (the model step's own job): the
    later `final_state` job cannot do it because the attempt budget is re-read by the NEXT tick's
    dispatch, and by then the receipt is already charged.

    A non-outage class is a NO-OP: the attempt stays charged, so the bounded-crash accounting for
    `setup`/`unknown`/timeouts is untouched. Idempotent per run key.

    DELIBERATELY NOT applied to find_maintainer_approval's staleness anchor: that is a human-CONSENT
    surface ("did the maintainer see the failure being retried?"), not a budget. Leaving a voided
    attempt as the anchor fails CLOSED — it can only require a fresh human approval, never admit a
    run the maintainer did not bless."""
    outage = _worker_pr().is_credential_outage(exit_class)
    _write_outputs({"voided": "true" if outage else "false"})
    if not outage:
        print(f"exit class {str(exit_class or '')!r} is not a credential outage — this worker "
              "attempt stays CHARGED against the deferred-retry budget")
        return False
    comments = _paginated(repo, issue, "comments")
    marker = f"{ATTEMPT_VOID_MARKER} run={run_key} -->"
    for comment in comments:
        if (str(comment.get("user", {}).get("login", "")).casefold() == bot_login.casefold()
                and marker in str(comment.get("body", ""))):
            print(f"worker attempt already voided (run {run_key})")
            return True
    cls = str(exit_class).strip().lower()
    body = (
        f"> 🤖 SPARQ agent — this worker attempt was VOIDED: the model launch failed on the "
        f"worker account's credential/capacity (`exit-class={cls}`) before the model ran, so it "
        "is NOT charged against the deferred-retry budget and is NOT a model decline "
        f"(registry #596).\n\n{marker}"
    )
    _gh_json(
        ["api", "-X", "POST", f"repos/{repo}/issues/{issue}/comments", "--input", "-"],
        input_doc={"body": body},
    )
    print(f"worker attempt voided (run {run_key}, exit-class={cls})")
    return True


def _assert_verifier_immutable(trust_gate, forbid_gate_root):
    """The pre-publish verifier must NOT resolve into the CANDIDATE-CONTROLLED tree (issue #568).

    Executing a trust gate the candidate change supplied would let that change control the very
    program authorizing its own publication — and a trust-surface issue legitimately edits
    `scripts/trust-gate.py`, so this is a live shape, not a hypothetical. The caller names the tree
    to exclude, because which tree that is depends on where the re-check runs:

      * in the isolated `publish` job (issue #575, the current call site) it is the extracted
        publish BUNDLE — the only candidate-controlled bytes on that runner — and the gate itself
        comes from the target checkout pinned to the pre-gate base, digest-bound to the pre-model
        record;
      * when the re-check lived in the worker job it was the post-model `target` working tree, and
        the gate came from a pre-model RUNNER_TEMP snapshot.

    Either way this is the runtime proof of the property, not merely a convention. Resolution is
    over REAL paths (Path.resolve follows symlinks and collapses `..`), so a symlink or a
    `dir/../dir` spelling cannot smuggle the excluded tree back in. Fail-closed in every direction:
    a missing forbidden root, an unresolvable path, or a gate at/under the root all raise."""
    if not forbid_gate_root:
        raise WorkerIssueError("pre-publish reverify requires the model-mutable root to exclude")
    try:
        root = Path(forbid_gate_root).resolve()
        gate = Path(trust_gate).resolve()
    except OSError as exc:                      # unresolvable path — never assume it is outside
        raise WorkerIssueError(f"cannot resolve the pre-publish trust-gate path: {exc}") from exc
    if gate == root or root in gate.parents:
        raise WorkerIssueError(
            "pre-publish trust gate resolves inside the model-mutable tree — the candidate "
            "change would authorize its own publication; refusing")


def reverify(repo, issue, expected_author, expected_body_sha, trust_gate, bot_login, issue_file,
             current_run_key=None, mode="dispatch", forbid_gate_root=None):
    """Re-prove the issue's live trust, revision, and status against the LIVE API.

    `mode="dispatch"` is the pre-model admission check: the issue must still carry its positive
    `status:ready` attestation and no busy/gated label.

    `mode="pre-publish"` (issue #568) is the SAME check re-run in the fresh publisher, seconds
    before push/PR creation, so a maintainer who closed, rewrote, or human-parked the issue during
    the (tens-of-minutes) model + gate span is not published over from a stale snapshot. It cannot
    demand `status:ready`: the workflow ITSELF moved the issue ready -> in-progress at claim time,
    so dispatch mode would refuse every real run and publication would be non-functional. It
    accepts exactly one extra state — THIS run's own still-live claim, proven by the ownership
    receipt CAS (holds_live_claim), never a blanket `status:in-progress` — and additionally proves
    the verifier is immutable. Everything else (another run's claim, human parking, deferral, a
    re-opened pool state, a closed or rewritten issue) fails closed exactly as in dispatch mode.

    It MUTATES no issue state: it only reads the issue + comments and runs the read-only trust
    gate, so an aborted publish leaves a maintainer's intervention exactly as they left it and the
    separate final_state job converges the issue back into the redispatch pool.
    """
    if mode not in {"dispatch", "pre-publish"}:
        raise WorkerIssueError(f"unknown reverify mode {mode!r}")
    if mode == "pre-publish":
        # Both bindings are mandatory here: without the run key there is no claim CAS, and
        # without the forbidden root there is no proof the verifier is out of the model's reach.
        if not current_run_key:
            raise WorkerIssueError("pre-publish reverify requires the current run key")
        _assert_verifier_immutable(trust_gate, forbid_gate_root)
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
    gating = sorted(label for label in labels
                    if label in BUSY_OR_GATED or label.startswith("needs:"))
    if mode == "pre-publish":
        # status:ready RE-appearing means the issue re-entered the dispatch pool (a deferral +
        # retry flip): this run's claim is no longer exclusive, so it must not publish.
        if "status:ready" in labels:
            raise WorkerIssueError(
                "target issue returned to the dispatch pool (status:ready) — this run's claim is "
                "no longer exclusive")
        if "status:in-progress" not in labels:
            raise WorkerIssueError("target issue lost this run's status:in-progress claim")
        blockers = [label for label in gating if label != "status:in-progress"]
        if blockers:
            raise WorkerIssueError(f"target issue became gated or busy: {', '.join(blockers)}")
        # The shared label is NOT the claim; the ownership receipt CAS is (issue #568).
        if not holds_live_claim(_paginated(repo, issue, "comments"), bot_login, current_run_key):
            raise WorkerIssueError(
                "the newest worker ownership receipt is not this run's own — another run holds "
                "or has superseded the claim")
    else:
        if "status:ready" not in labels:
            raise WorkerIssueError("target issue lost its positive status:ready attestation")
        if gating:
            raise WorkerIssueError(f"target issue became gated or busy: {', '.join(gating)}")

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
            current_run_key=current_run_key if mode == "pre-publish" else None,
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


# The status -> (labels to add, labels to remove) table set_status applies. Module-level (issue
# #568) so the self-test can model the REAL workflow lifecycle — ready -> this run's in-progress
# claim -> the pre-publish re-check — from the very table production uses, instead of a
# hand-written label set that could silently drift from it and make the test vacuous.
#
# `in-progress-review`: the worker published a DRAFT PR that is cycling through the
# cross-provider review loop — the issue completes only when the review-fix ARM path fires.
# `retry`: the dispatcher re-enumerates a deferred issue (deferred-retry, locked decision 20)
# — status:deferred is stripped and status:ready restored so the worker's reverify passes.
# `retry` also clears `status:parked`: the deferred-retry dispatch IS the machine park's
# readmission — reaching it proves capacity exists (the allocator granted a claim), so the
# soft hold lifts exactly then.
# `parked`: the MACHINE-owned capacity/decline/budget park (park_policy.py). Unlike
# `needs-user` it is a SOFT hold cleared by a human readmission gesture (or the `retry`
# flip) rather than a terminal question — but it DOES park the whole PR surface while it
# stands (round-3 finding 2, the one-predicate rule): a PR is capacity-parked iff EITHER
# machine label is live (review:parked on the PR OR status:parked on the source), so
# enumerate_review_items excludes on it and CLAIM re-proves any readmission from the
# durable receipts + label timelines.
# `needs-user` stays reserved for genuine human questions and supersedes a machine park.
# NOTE (issue #31): status:ready written here is dispatchability only, never maintainer
# approval — the reverify third-party path demands separate human evidence.
STATUS_TRANSITIONS = {
    "in-progress": ({"status:in-progress"}, {"status:ready", "status:deferred"}),
    "in-progress-review": ({"status:in-progress-review"},
                           {"status:ready", "status:in-progress", "status:deferred"}),
    "retry": ({"status:ready"}, {"status:deferred", "status:parked"}),
    "deferred": ({"status:deferred"},
                 {"status:ready", "status:in-progress", "status:in-progress-review"}),
    "needs-user": ({"needs:user", "status:deferred"},
                   {"status:ready", "status:in-progress", "status:in-progress-review",
                    "status:parked"}),
    "parked": ({"status:parked", "status:deferred"},
               {"status:ready", "status:in-progress", "status:in-progress-review"}),
    # `readmitted`: the SOURCE-ISSUE half of re-admitting a MACHINE capacity park on a
    # PR-backed issue (registry #614 — the automatic cause-recovery path writes exactly what a
    # human's unlabel gesture leads CLAIM to write). It CLEARS status:parked/status:deferred
    # and restores the in-progress-review posture the open worker PR is actually in. It applies
    # NO park label, so it is not veto-gated: the sticky human-unpark veto guards park
    # APPLICATION, and clearing a machine park points the same way a human unpark does.
    # Deliberately NOT `retry`, whose status:ready is the IMPLEMENTATION-dispatch posture —
    # wrong for an issue whose worker PR is already open and cycling through review.
    "readmitted": ({"status:in-progress-review"},
                   {"status:parked", "status:deferred", "status:ready",
                    "status:in-progress"}),
    # `handback` [registry #797]: the SOURCE-ISSUE half of a MACHINE-TERMINAL retirement
    # (worker-pr._retire_worker_pr). Its worker PR consumed two full budgets and has just been
    # CLOSED, so — unlike `readmitted`, which restores the in-progress-review posture of a PR
    # that is still open — the issue goes back to the implementable frontier for a FRESH attempt,
    # normally on a decomposed `role:research` route the caller swapped in first. It clears the
    # machine park and every in-flight posture and restores `status:ready`. It applies NO park
    # label, so it is not veto-gated: like `readmitted`, clearing a machine park points the same
    # way a human unpark does. `status:ready` here is dispatchability, never approval (issue #31).
    "handback": ({"status:ready"},
                 {"status:parked", "status:deferred", "status:in-progress",
                  "status:in-progress-review"}),
    "complete": (set(), {"status:in-progress", "status:in-progress-review",
                         "status:deferred", "status:parked"}),
}


def set_status(repo, issue, status):
    # `in-progress-review`: the worker published a DRAFT PR that is cycling through the
    # cross-provider review loop — the issue completes only when the review-fix ARM path fires.
    # `retry`: the dispatcher re-enumerates a deferred issue (deferred-retry, locked decision 20)
    # — status:deferred is stripped and status:ready restored so the worker's reverify passes.
    # `retry` also clears `status:parked`: the deferred-retry dispatch IS the machine park's
    # readmission — reaching it proves capacity exists (the allocator granted a claim), so the
    # soft hold lifts exactly then.
    # `parked`: the MACHINE-owned capacity/decline/budget park (park_policy.py). Unlike
    # `needs-user` it is a SOFT hold cleared by a human readmission gesture (or the `retry`
    # flip) rather than a terminal question — but it DOES park the whole PR surface while it
    # stands (round-3 finding 2, the one-predicate rule): a PR is capacity-parked iff EITHER
    # machine label is live (review:parked on the PR OR status:parked on the source), so
    # enumerate_review_items excludes on it and CLAIM re-proves any readmission from the
    # durable receipts + label timelines.
    # `needs-user` stays reserved for genuine human questions and supersedes a machine park.
    # NOTE (issue #31): status:ready written here is dispatchability only, never maintainer
    # approval — the reverify third-party path demands separate human evidence.
    # The table itself is STATUS_TRANSITIONS above (module-level so the pre-publish lifecycle
    # self-test derives its label state from the same source production writes from).
    add, remove = STATUS_TRANSITIONS[status]
    park_label = PARK_STATUS_LABELS.get(status)
    if park_label and _park_policy().park_vetoed(
            repo, issue, park_label, lambda r, n: _paginated(r, n, "timeline"),
            is_human=lambda login: _is_human_maintainer(repo, login)):
        # Sticky human unpark (park_policy.py): a PROVEN human (the same strict
        # _is_human_maintainer probe as retry approval — an unverifiable actor never counts)
        # removed this park label more recently than any application (or the timeline could
        # not be read, which must never park). The veto helper already logged the loud
        # "park suppressed:" line; mutate NOTHING.
        print(f"target issue state UNCHANGED: {status} park suppressed for {repo}#{issue}")
        return
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


def claim_receipt(repo, issue, model, run_url, run_key, bot_login):
    """Post the run's OWNERSHIP receipt. A GitHub App bot user CANNOT be an issue assignee, so this
    receipt + the `status:in-progress` label ARE the assignment: they show WHO is working the
    issue, on WHAT model, and link the LIVE run — filterable via the label.

    [issue #568] It is also the compare-and-swap half of that shared label, and worker.yml posts it
    BEFORE the ready -> in-progress flip. The label is shared, so it cannot say WHICH run owns the
    claim; this run-key-bound marker can, and holds_live_claim reads it at pre-publish time. Posting
    it FIRST is the ordering property that closes the supersession race: a newer run's ownership is
    durable from its first mutation, so an older run reaching pre-publish refuses even inside the
    long pre-attempt interval (claim -> worker-prep -> record-attempt). The failure ordering points
    the same way — a receipt that cannot be posted RAISES here, before the label flip, so a run that
    fails to record ownership never takes the label and never becomes authorized to publish.

    Idempotent per run key, like record_attempt: a re-entered step re-uses its existing receipt
    instead of stacking a second one."""
    marker = f"{CLAIM_MARKER} run={run_key} -->"
    for comment in _paginated(repo, issue, "comments"):
        if (str(comment.get("user", {}).get("login", "")).casefold() == bot_login.casefold()
                and marker in str(comment.get("body", ""))):
            print(f"claim ownership receipt already posted (run {run_key})")
            return
    body = (
        "> 🤖 **SPARQ orchestrator** has claimed this issue and is actively working it.\n\n"
        f"- Model: `{model}`\n"
        f"- Live worker run: {run_url}\n\n"
        "Active autonomous work is filterable with `is:issue label:status:in-progress`. A pull request "
        "will link back here when it opens. (A GitHub App cannot be a literal assignee — this receipt + "
        "the `status:in-progress` label are the equivalent.)\n\n"
        f"{marker}"
    )
    _gh_json(
        ["api", "-X", "POST", f"repos/{repo}/issues/{issue}/comments", "--input", "-"],
        input_doc={"body": body},
    )
    print(f"claim ownership receipt posted (run {run_key})")


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

    # count_attempts_since (deferred-retry readmission window): only receipts at/after the
    # cutoff are charged; missing timestamps and exact ties stay CHARGED (fail toward the full
    # count, never a fresh budget on unproven data); no cutoff = the plain full count.
    stamped = [
        {"user": {"login": "sparq[bot]"}, "created_at": "2026-07-20T00:00:00Z",
         "body": f"x {ATTEMPT_MARKER} run=1 -->"},
        {"user": {"login": "sparq[bot]"}, "created_at": "2026-07-23T10:00:00Z",
         "body": f"x {ATTEMPT_MARKER} run=2 -->"},
        {"user": {"login": "someone"}, "created_at": "2026-07-23T10:00:00Z",
         "body": f"x {ATTEMPT_MARKER} run=3 -->"},
    ]
    assert count_attempts_since(stamped, "sparq[bot]", "2026-07-23T09:00:00Z") == 1
    assert count_attempts_since(stamped, "sparq[bot]", None) == 2
    assert count_attempts_since(stamped, "sparq[bot]", "2026-07-23T10:00:00Z") == 1  # tie charged
    unstamped = [{"user": {"login": "sparq[bot]"}, "body": f"x {ATTEMPT_MARKER} run=4 -->"}]
    assert count_attempts_since(stamped + unstamped, "sparq[bot]",
                                "2026-07-24T00:00:00Z") == 1  # no created_at stays charged
    # Round-4 finding 3: a NON-ISO created_at sorting lexicographically BEFORE any real
    # cutoff ("0000-..." < "2026-...") must be CHARGED with a loud log, never silently
    # omitted — the old bare `created < since` skip let a malformed stamp drop a receipt
    # from the charged budget and authorize exhausted work.
    ts_logs = []
    garbage_stamped = [{"user": {"login": "sparq[bot]"}, "created_at": "0000-not-a-timestamp",
                        "body": f"x {ATTEMPT_MARKER} run=5 -->"}]
    assert count_attempts_since(garbage_stamped, "sparq[bot]", "2026-07-23T09:00:00Z",
                                log=ts_logs.append) == 1
    assert any("malformed created_at" in line and "CHARGED" in line for line in ts_logs)
    quiet_logs = []
    assert count_attempts_since(stamped, "sparq[bot]", "2026-07-23T09:00:00Z",
                                log=quiet_logs.append) == 1
    assert quiet_logs == []  # well-formed stamps never warn
    # Round-5 finding 2: the window compare is over PARSED instants, never raw strings. A
    # space-separator stamp VALIDATES yet sorts lexicographically before every 'T'-form stamp
    # of the same day — the old string compare read this post-cutoff attempt as pre-cutoff
    # and silently un-charged it (budget minting, no warning).
    space_receipt = [{"user": {"login": "sparq[bot]"}, "created_at": "2026-07-23 10:30:00Z",
                      "body": f"x {ATTEMPT_MARKER} run=6 -->"}]
    quiet_logs = []
    assert count_attempts_since(space_receipt, "sparq[bot]", "2026-07-23T09:00:00Z",
                                log=quiet_logs.append) == 1
    assert quiet_logs == []  # a well-formed spelling variant charges quietly
    offset_receipt = [{"user": {"login": "sparq[bot]"},
                       "created_at": "2026-07-20T00:00:00+00:00",
                       "body": f"x {ATTEMPT_MARKER} run=7 -->"}]
    assert count_attempts_since(offset_receipt, "sparq[bot]", "2026-07-23T09:00:00Z") == 0
    tie_receipt = [{"user": {"login": "sparq[bot]"},
                    "created_at": "2026-07-23T09:00:00+00:00",
                    "body": f"x {ATTEMPT_MARKER} run=8 -->"}]
    assert count_attempts_since(tie_receipt, "sparq[bot]", "2026-07-23T09:00:00Z") == 1
    naive_receipt = [{"user": {"login": "sparq[bot]"}, "created_at": "2026-07-20T00:00:00",
                      "body": f"x {ATTEMPT_MARKER} run=9 -->"}]
    ts_logs = []
    assert count_attempts_since(naive_receipt, "sparq[bot]", "2026-07-23T09:00:00Z",
                                log=ts_logs.append) == 1  # naive = unorderable = charged
    assert any("malformed created_at" in line and "CHARGED" in line for line in ts_logs)
    ts_logs = []
    assert count_attempts_since(stamped, "sparq[bot]", "not-a-timestamp",
                                log=ts_logs.append) == 2  # unparseable cutoff => full count
    assert any("not a parseable timestamp" in line and "FULL historical count" in line
               for line in ts_logs)
    # ---- [registry #596] a CREDENTIAL-OUTAGE attempt is NOT charged to the retry budget ---------
    # The attempt receipt is posted BEFORE the model launches, so a launch that died on acct01's
    # hourly-expiring codex access token (`worker-live: model-exit-class=auth`) used to burn a full
    # attempt and walk the issue to status:parked as if the model had declined the task.
    bot = "sparq[bot]"
    voided_pair = [
        {"user": {"login": bot}, "body": f"x {ATTEMPT_MARKER} run=1 -->"},
        {"user": {"login": bot}, "body": f"x {ATTEMPT_MARKER} run=2 -->"},
        {"user": {"login": bot}, "body": f"y {ATTEMPT_VOID_MARKER} run=2 -->"},
    ]
    assert attempt_voids(voided_pair, bot) == {"2"}
    assert count_attempts(voided_pair, bot) == 1        # run=2 subtracted
    assert count_attempts_since(voided_pair, bot, None) == 1
    # A void only cancels its EXACT run key, and only a BOT-authored one counts.
    assert count_attempts(voided_pair + [
        {"user": {"login": bot}, "body": f"y {ATTEMPT_VOID_MARKER} run=99 -->"}], bot) == 1
    assert count_attempts([
        {"user": {"login": bot}, "body": f"x {ATTEMPT_MARKER} run=1 -->"},
        {"user": {"login": "mallory"}, "body": f"y {ATTEMPT_VOID_MARKER} run=1 -->"}], bot) == 1
    # Void subtraction also applies inside the readmission window (global, like worker-pr).
    windowed_void = [
        {"user": {"login": bot}, "created_at": "2026-07-23T10:00:00Z",
         "body": f"x {ATTEMPT_MARKER} run=w1 -->"},
        {"user": {"login": bot}, "created_at": "2026-07-23T10:05:00Z",
         "body": f"y {ATTEMPT_VOID_MARKER} run=w1 -->"},
    ]
    assert count_attempts_since(windowed_void, bot, "2026-07-23T09:00:00Z") == 0

    def simulate_attempts(exit_classes, max_attempts=3):
        """Replay one worker run per exit class on ONE issue through the REAL control path:
        record_attempt (pre-model, the last budget gate) then void_attempt_on_outage (post-model,
        class-gated). Returns (charged_attempts, voided_outputs, posted_bodies)."""
        store, outputs, posted = [], [], []
        saved = (globals()["_paginated"], globals()["_gh_json"], globals()["_write_outputs"],
                 globals()["_readmission_cutoff"])
        globals()["_paginated"] = lambda repo, issue, resource: list(store)
        globals()["_readmission_cutoff"] = lambda repo, issue: None

        def fake_gh_json(args, input_doc=None):
            body = (input_doc or {}).get("body", "")
            posted.append(body)
            store.append({"user": {"login": bot}, "body": body})
            return {}

        globals()["_gh_json"] = fake_gh_json
        globals()["_write_outputs"] = lambda values: (
            outputs.append(values["voided"]) if "voided" in values else None)
        try:
            for index, cls in enumerate(exit_classes, start=1):
                run_key = f"{7000 + index}.1"
                record_attempt("o/r", 5, max_attempts, bot, run_key)
                void_attempt_on_outage("o/r", 5, bot, run_key, cls)
        finally:
            (globals()["_paginated"], globals()["_gh_json"], globals()["_write_outputs"],
             globals()["_readmission_cutoff"]) = saved
        return count_attempts(list(store), bot), outputs, posted

    charged, outs, bodies = simulate_attempts(["auth"])
    assert charged == 0, charged                       # the outage attempt is not charged
    assert outs == ["true"], outs
    assert any("exit-class=auth" in b and "registry #596" in b for b in bodies), bodies
    # A genuine no-change/failed-but-ran attempt STILL charges — the budget/park ladder is intact.
    assert simulate_attempts(["no_change"])[0] == 1
    assert simulate_attempts(["success"])[0] == 1
    # DOCUMENTED #596 DECISION: rate-limit is non-chargeable, exactly like auth.
    assert simulate_attempts(["rate-limit"])[0] == 0
    # #614's HOST-SIDE credential pre-flight classes. This is the task-side half of the #604/#614
    # allow-list gap the retro-review found: `void-attempt` reads the RAW class, and model-health's
    # fold onto auth/transient happens LATER in the model_health job — so until the drift lock in
    # worker-pr.CREDENTIAL_OUTAGE_EXIT_CLASSES these CHARGED an attempt (and, on a final attempt,
    # parked the issue) for a failure that happened before the model container existed.
    for preflight_class in ("credential-remint-required", "credential-refresh-transient"):
        pf_charged, pf_outs, pf_bodies = simulate_attempts([preflight_class])
        assert pf_charged == 0, (preflight_class, pf_charged)
        assert pf_outs == ["true"], (preflight_class, pf_outs)
        assert any(f"exit-class={preflight_class}" in b for b in pf_bodies), pf_bodies
    # The budget consequence, end to end: three host-side pre-flight failures against
    # max_attempts=3 leave the attempt budget UNSPENT instead of exhausting it.
    assert simulate_attempts(["credential-remint-required"] * 3)[0] == 0
    assert simulate_attempts(["credential-refresh-transient"] * 3)[0] == 0
    # ...but an UNATTRIBUTABLE failure still charges, so the bounded-crash accounting survives.
    assert simulate_attempts(["unknown"])[0] == 1
    assert simulate_attempts(["setup"])[0] == 1
    # The live mixed window: two credential outages around one real attempt charge EXACTLY one.
    mixed_charged, mixed_outs, _ = simulate_attempts(["auth", "no_change", "auth"])
    assert mixed_charged == 1, mixed_charged
    assert mixed_outs == ["true", "false", "true"], mixed_outs
    # Budget consequence: three auth-class runs against max_attempts=3 leave the budget UNSPENT,
    # where charging them exhausted it and parked the issue.
    assert simulate_attempts(["auth", "auth", "auth"])[0] == 0
    assert simulate_attempts(["no_change", "no_change", "no_change"])[0] == 3
    # Idempotent: voiding the same run twice posts ONE void comment (not one per re-run).
    once_store, once_posted = [], []
    saved_pag, saved_json, saved_out = (globals()["_paginated"], globals()["_gh_json"],
                                        globals()["_write_outputs"])
    try:
        globals()["_paginated"] = lambda repo, issue, resource: list(once_store)
        globals()["_write_outputs"] = lambda values: None

        def once_gh_json(args, input_doc=None):
            body = (input_doc or {}).get("body", "")
            once_posted.append(body)
            once_store.append({"user": {"login": bot}, "body": body})
            return {}

        globals()["_gh_json"] = once_gh_json
        assert void_attempt_on_outage("o/r", 5, bot, "8001.1", "auth") is True
        assert void_attempt_on_outage("o/r", 5, bot, "8001.1", "auth") is True
        assert len(once_posted) == 1, once_posted
        assert void_attempt_on_outage("o/r", 5, bot, "8002.1", "unknown") is False
        assert len(once_posted) == 1, once_posted   # a non-outage class posts nothing at all
    finally:
        (globals()["_paginated"], globals()["_gh_json"],
         globals()["_write_outputs"]) = saved_pag, saved_json, saved_out

    assert body_sha("task") == hashlib.sha256(b"task").hexdigest()
    assert set(LABEL_COLOURS) == {"status:in-progress", "status:in-progress-review",
                                  "status:deferred", "status:parked", "status:ready",
                                  "needs:user"}
    assert "status:in-progress-review" in BUSY_OR_GATED
    # The machine park gates worker admission exactly like every other busy status: reverify
    # fails closed on a parked issue, so no NEW implementation dispatch survives a park.
    assert "status:parked" in BUSY_OR_GATED

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

    # (v) each identity filter is load-bearing on its own (review r1). A trust-everyone stub
    # removes the trusted-set probe as a confounding rejector, so ONLY the bot/App filters can
    # be doing the rejecting here — deleting any one of them turns a case green.
    trust_all = lambda login: True  # noqa: E731 — trivial trusted-set stub
    app_typed = {"user": {"login": "registry-app", "type": "Bot"},
                 "body": "approved", "created_at": "2026-07-11T00:00:00Z"}
    suffixed = {"user": {"login": "helper[bot]", "type": "User"},
                "body": "approved", "created_at": "2026-07-11T00:00:00Z"}
    assert find_maintainer_approval([failure, app_typed], "sparq[bot]", trust_all) is None
    assert find_maintainer_approval([failure, suffixed], "sparq[bot]", trust_all) is None
    # An App wielding a maintainer's user token (review r2): the comment is user.type=User under
    # the maintainer's own login — every user-shaped filter passes and the collaborator probe
    # would confirm it — but performed_via_github_app is non-null. Must be rejected, and ONLY
    # the App-attribution check can be doing the rejecting under trust_all.
    app_on_behalf = {**human_after,
                     "performed_via_github_app": {"id": 7, "slug": "registry-app"}}
    assert find_maintainer_approval([failure, app_on_behalf], "sparq[bot]", trust_all) is None
    # The check is non-null attribution, not key presence: the JSON-null the API returns for a
    # genuinely human comment must still pass.
    explicit_null = {**human_after, "performed_via_github_app": None}
    assert find_maintainer_approval(
        [failure, explicit_null], "sparq[bot]", trust_all) is explicit_null
    # The worker's own login never self-approves, even typed User with no [bot] suffix.
    own_receipt = {"user": {"login": "sparq-svc", "type": "User"},
                   "body": f"x {ATTEMPT_MARKER} run=9 -->", "created_at": "2026-07-10T00:00:00Z"}
    own_approval = {"user": {"login": "sparq-svc", "type": "User"},
                    "body": "approved", "created_at": "2026-07-11T00:00:00Z"}
    assert find_maintainer_approval([own_receipt, own_approval], "sparq-svc", trust_all) is None
    # trust_all admits a genuine human, proving the rejections above came from the identity
    # filters and not from the stub being secretly restrictive.
    assert find_maintainer_approval([failure, human_after], "sparq[bot]", trust_all) is human_after

    # (vi) the approval predicate is load-bearing: a trusted human comment after the receipt
    # that never says "approved" is NOT approval.
    unmarked = {"user": {"login": "jeswr", "type": "User"},
                "body": "looks good to me", "created_at": "2026-07-11T00:00:00Z"}
    assert find_maintainer_approval([failure, unmarked], "sparq[bot]", maintainers) is None

    # (vii) staleness is strict at-or-before: an approval stamped EXACTLY at the receipt time
    # is stale (it cannot postdate the failure it must bless).
    equal_ts = {**human_after, "created_at": failure["created_at"]}
    assert find_maintainer_approval([failure, equal_ts], "sparq[bot]", maintainers) is None

    # (viii) with multiple receipts the NEWEST governs, independent of list order: an approval
    # between two receipts blessed the older failure and is stale; one after both stands.
    failure2 = {**failure, "body": f"x {ATTEMPT_MARKER} run=10 -->",
                "created_at": "2026-07-12T00:00:00Z"}
    after_both = {**human_after, "created_at": "2026-07-13T00:00:00Z"}
    assert find_maintainer_approval([failure, human_after, failure2], "sparq[bot]", maintainers) is None
    assert find_maintainer_approval([failure2, human_after, failure], "sparq[bot]", maintainers) is None

    # (ix) Round-5 finding 2: staleness ordering is over PARSED instants, never raw strings.
    # A space-separator approval stamp AFTER the failure by instant sorts lexicographically
    # BEFORE the failure's 'T'-form stamp — it must still approve.
    space_approval = {**human_after, "created_at": "2026-07-10 12:00:00Z"}
    assert find_maintainer_approval(
        [failure, space_approval], "sparq[bot]", maintainers) is space_approval
    # A space-separator RECEIPT stamp sorts before a 'T'-form approval of an EARLIER instant:
    # the old string compare accepted that PRE-failure approval (blessing a run the
    # maintainer never saw fail); the instant compare rejects it as stale.
    space_failure = {**failure, "created_at": "2026-07-11 08:00:00Z"}
    pre_failure_approval = {**human_after, "created_at": "2026-07-11T07:00:00Z"}
    assert find_maintainer_approval(
        [space_failure, pre_failure_approval], "sparq[bot]", maintainers) is None
    # A +00:00 approval tying the Z-spelled receipt INSTANT is stale (strict at-or-before,
    # across spellings).
    offset_tie = {**human_after, "created_at": "2026-07-10T00:00:00+00:00"}
    assert find_maintainer_approval([failure, offset_tie], "sparq[bot]", maintainers) is None
    # An attempt receipt with an unparseable stamp makes "strictly after the last failure"
    # unprovable for every candidate: the retry fails closed, loudly.
    approval_logs = []
    bad_failure = {**failure, "created_at": "not-a-timestamp"}
    assert find_maintainer_approval([bad_failure, human_after], "sparq[bot]", maintainers,
                                    log=approval_logs.append) is None
    assert any("unparseable created_at" in line and "fails closed" in line
               for line in approval_logs)
    # An approval with an unparseable (or naive) stamp can never prove it postdates the
    # failure — that comment never approves.
    bad_approval = {**human_after, "created_at": "2026-07-11T00:00:00"}
    assert find_maintainer_approval([failure, bad_approval], "sparq[bot]", maintainers) is None
    assert find_maintainer_approval(
        [failure, human_after, failure2, after_both], "sparq[bot]", maintainers) is after_both

    # (ix-b) issue #568: the PRE-PUBLISH re-check must not read THIS run's own start receipt as
    # the failure being retried. record-attempt posts it before the long model+gate span, so at
    # publish time it is the newest receipt and the approval that authorised this very run looks
    # stale — third-party publication would be impossible. Excluding only the current run key
    # restores it, and a DIFFERENT run's later receipt still bounds staleness (no masking).
    own_start = {"user": {"login": "sparq[bot]", "type": "Bot"},
                 "body": f"starting {ATTEMPT_MARKER} run=77.1 -->",
                 "created_at": "2026-07-12T00:00:00Z"}
    other_start = {**own_start, "body": f"starting {ATTEMPT_MARKER} run=88.1 -->"}
    assert find_maintainer_approval([failure, human_after, own_start],
                                    "sparq[bot]", maintainers) is None
    assert find_maintainer_approval([failure, human_after, own_start], "sparq[bot]", maintainers,
                                    current_run_key="77.1") is human_after
    assert find_maintainer_approval([failure, human_after, other_start], "sparq[bot]", maintainers,
                                    current_run_key="77.1") is None
    # The exclusion is exact-key: a receipt naming this run AND another still anchors staleness.
    shared_start = {**own_start,
                    "body": f"{ATTEMPT_MARKER} run=77.1 --> {ATTEMPT_MARKER} run=88.1 -->"}
    assert find_maintainer_approval([failure, human_after, shared_start], "sparq[bot]",
                                    maintainers, current_run_key="77.1") is None

    # (ix) reverify exit-3 wiring (review r1): the fail-closed guard itself, not just the pure
    # helper. A stub trust-gate exits 3 (third-party author); real subprocess wiring, with only
    # the GitHub API seams patched. Without fresh approval reverify must raise the approval
    # error (NOT the generic gate error) and write no issue snapshot; with fresh approval it
    # must rerun the gate --maintainer-approved and accept its "promoted" verdict.
    with tempfile.TemporaryDirectory() as tmp:
        gate = Path(tmp) / "gate.py"
        gate.write_text(
            "import sys\n"
            "if '--maintainer-approved' in sys.argv:\n"
            "    print('promoted')\n"
            "    sys.exit(0)\n"
            "sys.exit(3)\n",
            encoding="utf-8",
        )
        issue_file = Path(tmp) / "issue.json"
        item = {"state": "open", "user": {"login": "third-party"}, "body": "task",
                "labels": [{"name": "status:ready"}]}
        comments = [failure]
        seams = {"_gh_json": lambda args, *, input_doc=None: dict(item),
                 "_paginated": lambda repo, issue, resource: list(comments),
                 "_is_human_maintainer": lambda repo, login: login == "jeswr"}
        saved = {name: globals()[name] for name in seams}
        globals().update(seams)
        try:
            refused = False
            try:
                reverify("o/r", 1, "third-party", body_sha("task"), str(gate),
                         "sparq[bot]", str(issue_file))
            except WorkerIssueError as exc:
                refused = "no fresh maintainer approval" in str(exc)
            assert refused
            assert not issue_file.exists()
            comments.append(human_after)
            reverify("o/r", 1, "third-party", body_sha("task"), str(gate),
                     "sparq[bot]", str(issue_file))
            assert json.loads(issue_file.read_text(encoding="utf-8")) == item
        finally:
            globals().update(saved)

    # (xiii) issue #568 — the OWNERSHIP compare-and-swap behind the shared status:in-progress
    # label. holds_live_claim answers "is the newest worker ownership receipt on this issue mine?"
    def _rcpt(key, stamp, marker=CLAIM_MARKER, login="sparq[bot]"):
        return {"user": {"login": login, "type": "Bot"},
                "body": f"claimed {marker} run={key} -->", "created_at": stamp}

    own_claim = _rcpt("77.1", "2026-07-19T01:00:00Z")
    own_attempt = _rcpt("77.1", "2026-07-19T02:00:00Z", ATTEMPT_MARKER)
    newer_foreign = _rcpt("88.1", "2026-07-19T03:00:00Z")
    older_foreign = _rcpt("88.1", "2026-07-19T00:00:00Z")
    assert holds_live_claim([own_claim], "sparq[bot]", "77.1")
    # Marker INDEPENDENCE is load-bearing: ownership gets its OWN marker precisely so it is not a
    # budget unit. If CLAIM_MARKER ever contained ATTEMPT_MARKER (or vice versa) every run would
    # charge two attempts and the approval staleness anchor would move onto the claim receipt.
    assert ATTEMPT_MARKER not in CLAIM_MARKER and CLAIM_MARKER not in ATTEMPT_MARKER
    assert count_attempts([own_claim], "sparq[bot]") == 0
    assert count_attempts([own_attempt], "sparq[bot]") == 1
    # ...and the credential-outage VOID receipt is not ownership evidence either (its marker is
    # adjacent enough to ATTEMPT_MARKER that a careless rename would make a void look like a claim).
    void_rcpt = {"user": {"login": "sparq[bot]", "type": "Bot"},
                 "body": f"voided {ATTEMPT_VOID_MARKER} run=88.1 -->",
                 "created_at": "2026-07-19T08:00:00Z"}
    assert _ownership_receipt(void_rcpt["body"]) == (False, set())
    assert holds_live_claim([own_claim, void_rcpt], "sparq[bot]", "77.1")
    assert find_maintainer_approval(
        [own_claim, human_after], "sparq[bot]", maintainers) is human_after
    # Either marker is ownership evidence: a run launched from an older workflow revision posts
    # only the ATTEMPT receipt and must still register as a claimant.
    assert holds_live_claim([own_attempt], "sparq[bot]", "77.1")
    assert holds_live_claim([older_foreign, own_claim, own_attempt], "sparq[bot]", "77.1")
    # A NEWER foreign receipt means the claim was superseded — refuse.
    assert not holds_live_claim([own_claim, own_attempt, newer_foreign], "sparq[bot]", "77.1")
    # Instant ties fail closed; an unbound in-progress state (no receipt of ours) refuses; so does
    # an absent run key and an empty issue.
    assert not holds_live_claim([own_claim, _rcpt("88.1", own_claim["created_at"])],
                                "sparq[bot]", "77.1")
    assert not holds_live_claim([newer_foreign], "sparq[bot]", "77.1")
    assert not holds_live_claim([], "sparq[bot]", "77.1")
    assert not holds_live_claim([own_claim], "sparq[bot]", "")
    # Only BOT-authored comments count: a human pasting the marker text can neither steal a claim
    # (their newer "receipt" is ignored) nor forge one.
    human_paste = _rcpt("88.1", "2026-07-19T09:00:00Z", login="jeswr")
    assert holds_live_claim([own_claim, human_paste], "sparq[bot]", "77.1")
    assert not holds_live_claim([_rcpt("77.1", "2026-07-19T09:00:00Z", login="jeswr")],
                                "sparq[bot]", "77.1")
    # A receipt naming BOTH this run and another is attributable to that other run too — it can
    # never establish our exclusive ownership, so it counts as foreign.
    shared_body = {"user": {"login": "sparq[bot]", "type": "Bot"},
                   "created_at": "2026-07-19T04:00:00Z",
                   "body": f"{CLAIM_MARKER} run=77.1 --> {CLAIM_MARKER} run=88.1 -->"}
    assert not holds_live_claim([own_claim, shared_body], "sparq[bot]", "77.1")
    # Ordering is over PARSED instants, never raw strings (round-5 finding 2): this foreign
    # receipt is LATER by instant but its space-separator spelling sorts lexicographically BEFORE
    # our 'T'-form stamp — a string compare would authorize the superseded run.
    space_foreign = _rcpt("88.1", "2026-07-19 05:00:00Z")
    assert space_foreign["created_at"] < own_claim["created_at"]      # the trap, spelled out
    assert not holds_live_claim([own_claim, space_foreign], "sparq[bot]", "77.1")
    # An unparseable stamp on ANY receipt makes "mine is newest" unprovable — refuse, loudly.
    claim_logs = []
    assert not holds_live_claim([own_claim, _rcpt("88.1", "not-a-timestamp")],
                                "sparq[bot]", "77.1", log=claim_logs.append)
    assert any("fails closed" in line for line in claim_logs)
    # An unkeyed receipt is attributable to nobody: it is foreign, and a newer one refuses.
    unkeyed = {"user": {"login": "sparq[bot]", "type": "Bot"}, "body": CLAIM_MARKER,
               "created_at": "2026-07-19T06:00:00Z"}
    assert not holds_live_claim([own_claim, unkeyed], "sparq[bot]", "77.1")

    # (xiii-a) THE SUPERSESSION ORDERING PROPERTY the ownership receipt exists for (issue #568,
    # PR #442 option 1). worker.yml posts the CLAIM receipt BEFORE flipping the shared
    # status:in-progress label, so a newer run owns the issue from its very first mutation —
    # including the whole pre-attempt interval (claim -> worker-prep -> record-attempt) during
    # which it has posted NO attempt receipt yet. The old run must refuse in exactly that window.
    old_claim = _rcpt("77.1", "2026-07-19T01:00:00Z")
    old_attempt = _rcpt("77.1", "2026-07-19T02:00:00Z", ATTEMPT_MARKER)
    new_claim = _rcpt("88.1", "2026-07-19T03:00:00Z")           # newer run, pre-attempt interval
    mid_flight = [old_claim, old_attempt, new_claim]
    assert not holds_live_claim(mid_flight, "sparq[bot]", "77.1")
    # ...and it is the CLAIM receipt doing that work: with the claim receipts stripped (the
    # attempt-receipt-only world this issue's carried-over race describes) the old run's own
    # attempt receipt is the newest evidence and it would have published over the newer claim.
    assert holds_live_claim([c for c in mid_flight if CLAIM_MARKER not in c["body"]],
                            "sparq[bot]", "77.1")
    # The newer run itself holds the claim throughout that interval.
    assert holds_live_claim(mid_flight, "sparq[bot]", "88.1")

    # (xiii-b) the receipt POSTER is the other end of that binding: claim_receipt must embed the
    # run key in a form holds_live_claim actually recognizes (a receipt the CAS cannot read is a
    # silently unowned claim), and it must be idempotent per run so a re-entered step does not
    # stack duplicates.
    posted = []
    receipt_seams = {
        "_gh_json": lambda args, *, input_doc=None: posted.append(str(input_doc["body"])),
        "_paginated": lambda repo, issue, resource: [
            {"user": {"login": "sparq[bot]"}, "body": body, "created_at": "2026-07-19T01:00:00Z"}
            for body in posted],
    }
    saved_receipt = {name: globals()[name] for name in receipt_seams}
    globals().update(receipt_seams)
    try:
        claim_receipt("o/r", 1, "opus", "https://example/run/1", "77.1", "sparq[bot]")
        assert len(posted) == 1 and f"{CLAIM_MARKER} run=77.1 -->" in posted[0]
        assert holds_live_claim(
            [{"user": {"login": "sparq[bot]"}, "body": posted[0],
              "created_at": "2026-07-19T01:00:00Z"}], "sparq[bot]", "77.1")
        claim_receipt("o/r", 1, "opus", "https://example/run/1", "77.1", "sparq[bot]")
        assert len(posted) == 1                     # idempotent per run key
        claim_receipt("o/r", 1, "opus", "https://example/run/2", "88.1", "sparq[bot]")
        assert len(posted) == 2                     # a different run posts its own
    finally:
        globals().update(saved_receipt)

    # (xiv) issue #568 — the WIRED pre-publish re-check over the REAL label lifecycle. The claim
    # step moves the issue ready -> in-progress before the model runs, so a dispatch-mode reverify
    # (which demands status:ready) would deterministically refuse every legitimate publish. Label
    # state is derived from STATUS_TRANSITIONS — the table set_status itself applies — so this
    # tracks the real lifecycle instead of a hand-written set that could drift. Real trust-gate
    # subprocess; only the GitHub API seams are stubbed, and those stubs RAISE on any mutating
    # call so "aborts without mutating human-owned issue state" is proven, not asserted in prose.
    with tempfile.TemporaryDirectory() as tmp:
        model_tree = Path(tmp) / "target"
        (model_tree / "scripts").mkdir(parents=True)
        model_gate = model_tree / "scripts" / "trust-gate.py"
        model_gate.write_text("print('trusted')\n", encoding="utf-8")
        pinned = Path(tmp) / "pinned"
        pinned.mkdir()
        gate_ok = pinned / "trust-gate.py"
        gate_ok.write_text("print('trusted')\n", encoding="utf-8")
        gate_dead = pinned / "gate-dead.py"
        gate_dead.write_text("import sys\nsys.exit(1)\n", encoding="utf-8")
        symlinked = pinned / "looks-pinned.py"
        symlinked.symlink_to(model_gate)

        add, remove = STATUS_TRANSITIONS["in-progress"]
        live_labels = ({"status:ready", "role:impl"} | add) - (remove - add)
        assert live_labels == {"status:in-progress", "role:impl"}   # the claim step's real output
        item = {"state": "open", "user": {"login": "jeswr"}, "body": "task",
                "labels": [{"name": name} for name in sorted(live_labels)]}
        comments = [own_claim, own_attempt]
        issue_file = Path(tmp) / "issue.json"

        def read_only_gh_json(args, *, input_doc=None):
            # Any mutating verb here would be a state change on the maintainer's issue.
            assert "-X" not in args, f"pre-publish reverify mutated issue state: {args}"
            return json.loads(json.dumps(item))

        def read_only_run_gh(args, *, input_text=None, check=True):
            raise AssertionError(f"pre-publish reverify shelled out to a mutation: {args}")

        seams = {"_gh_json": read_only_gh_json,
                 "_run_gh": read_only_run_gh,
                 "_paginated": lambda repo, issue, resource: list(comments),
                 "_is_human_maintainer": lambda repo, login: login == "jeswr"}
        saved = {name: globals()[name] for name in seams}
        globals().update(seams)
        try:
            def prepub(gate=gate_ok, key="77.1", mode="pre-publish", root=model_tree,
                       author="jeswr", body="task"):
                try:
                    reverify("o/r", 1, author, body_sha(body), str(gate), "sparq[bot]",
                             str(issue_file), key, mode, root and str(root))
                    return "accepted"
                except WorkerIssueError as exc:
                    return f"refused: {exc}"

            # The live path: this run's bound ready -> in-progress claim publishes, and the
            # snapshot the publisher reads is re-attested seconds earlier.
            assert prepub() == "accepted"
            assert json.loads(issue_file.read_text(encoding="utf-8")) == item
            snapshot = issue_file.read_text(encoding="utf-8")
            # The SAME live state still fails DISPATCH mode: the fix is a dedicated bound mode,
            # never a loosened dispatch check (and the r2 always-reject regression stays visible).
            assert "status:ready" in prepub(mode="dispatch")

            # --- criterion 2: the verifier may never resolve into the model-mutable tree. The
            # model rewrote `target/` (a trust-surface issue legitimately edits trust-gate.py
            # there), so executing that copy would let the candidate change authorize its own
            # publication. Direct path, `..` traversal, and a symlink all refuse; the pinned
            # snapshot is what passes, and a missing forbidden root refuses too.
            assert "model-mutable tree" in prepub(gate=model_gate)
            assert "model-mutable tree" in prepub(
                gate=pinned / ".." / "target" / "scripts" / "trust-gate.py")
            assert "model-mutable tree" in prepub(gate=symlinked)
            assert "model-mutable root" in prepub(root=None)

            # --- criterion 3/6: fail-closed against every other claim + gate state, while this
            # run's own claim keeps working. Each case restores the accepting state afterwards,
            # so a stuck refusal cannot silently pass the next assertion.
            comments.append(newer_foreign)
            assert "another run" in prepub()
            comments[:] = [newer_foreign]
            assert "another run" in prepub()
            comments[:] = [own_claim, own_attempt]
            assert prepub() == "accepted"
            assert "run key" in prepub(key=None)

            # --- criterion 1/4: live human intervention during the model+gate span aborts.
            for extra, needle in (("needs:user", "needs:user"),
                                  ("status:blocked", "status:blocked"),
                                  ("status:parked", "status:parked"),
                                  ("status:ready", "dispatch pool")):
                item["labels"] = [{"name": n} for n in sorted(live_labels | {extra})]
                assert needle in prepub(), extra
            item["labels"] = [{"name": n} for n in sorted(live_labels - {"status:in-progress"})]
            assert "status:in-progress claim" in prepub()
            item["labels"] = [{"name": n} for n in sorted(live_labels)]
            item["state"] = "closed"
            assert "no longer open" in prepub()
            item["state"] = "open"
            item["body"] = "rewritten by the maintainer"
            assert "body changed" in prepub()
            item["body"] = "task"
            # The trust gate stays load-bearing on the pre-publish path.
            assert "trust gate" in prepub(gate=gate_dead)
            # Every refusal above left the publisher's snapshot exactly as it was: no mutation of
            # the issue (the seams would have raised) and no re-freshened stale snapshot.
            assert issue_file.read_text(encoding="utf-8") == snapshot
            assert prepub() == "accepted"
        finally:
            globals().update(saved)

    # (x) set_status park transitions (park-policy defects 1+2): real set_status wiring with the
    # GitHub seams patched; the recorded label POSTs/DELETEs prove which park label lands and
    # that the sticky human-unpark veto suppresses the whole mutation.
    import contextlib
    import io

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    posts, deletes, timeline = [], [], []

    def fake_run_gh(args, *, input_text=None, check=True):
        if args[1] == "-X" and args[2] == "DELETE":
            deletes.append(args[3])
        result = _Result()
        if "/collaborators/" in str(args[1]):
            # The strict maintainer probe (_is_human_maintainer): jeswr is a repo admin,
            # everyone else is not — the park veto only honours PROVEN humans.
            result.stdout = "admin" if "/collaborators/jeswr/" in args[1] else "none"
        return result

    def fake_gh_json(args, *, input_doc=None):
        if input_doc is not None and "labels" in input_doc:
            posts.append(input_doc["labels"])
        return {}

    def fake_paginated(repo, issue, resource):
        assert resource == "timeline"
        return list(timeline)

    park_seams = {"_run_gh": fake_run_gh, "_gh_json": fake_gh_json, "_paginated": fake_paginated}
    saved = {name: globals()[name] for name in park_seams}
    globals().update(park_seams)
    try:
        def park_event(kind, label, ts, login):
            return {"event": kind, "label": {"name": label},
                    "created_at": ts, "actor": {"login": login}}

        # (x-i) a CAPACITY park writes status:parked (+ status:deferred) — NEVER needs:user.
        set_status("o/r", 9, "parked")
        assert posts == [["status:deferred", "status:parked"]], posts
        assert all("needs:user" not in labels for labels in posts), posts
        assert any(path.endswith("labels/status:ready") for path in deletes), deletes
        # (x-ii) sticky human unpark: bot labeled < human unlabeled => the veto suppresses the
        # ENTIRE park transition (no add, no remove) and says so loudly.
        posts.clear(); deletes.clear()
        timeline[:] = [
            park_event("labeled", "status:parked", "2026-07-18T10:00:00Z", "sparq[bot]"),
            park_event("unlabeled", "status:parked", "2026-07-18T11:00:00Z", "jeswr"),
        ]
        vetoed_out = io.StringIO()
        with contextlib.redirect_stdout(vetoed_out):
            set_status("o/r", 9, "parked")
        assert posts == [] and deletes == [], (posts, deletes)
        assert "park suppressed" in vetoed_out.getvalue(), vetoed_out.getvalue()
        # (x-iii) human unlabeled < bot labeled (a NEWER application supersedes) => no veto, the
        # park proceeds.
        timeline.append(
            park_event("labeled", "status:parked", "2026-07-18T12:00:00Z", "sparq[bot]"))
        set_status("o/r", 9, "parked")
        assert posts == [["status:deferred", "status:parked"]], posts
        # (x-iv) a timeline read failure NEVER parks (fail open only toward NOT parking) and is
        # logged loudly.
        posts.clear(); deletes.clear()

        def broken_paginated(repo, issue, resource):
            raise WorkerIssueError("timeline unavailable")

        globals()["_paginated"] = broken_paginated
        broken_out = io.StringIO()
        with contextlib.redirect_stdout(broken_out):
            set_status("o/r", 9, "needs-user")
        assert posts == [] and deletes == [], (posts, deletes)
        assert "timeline read failed" in broken_out.getvalue(), broken_out.getvalue()
        globals()["_paginated"] = fake_paginated
        # (x-v) the human-question park still lands when no veto exists, and it SUPERSEDES a
        # machine park (status:parked is removed alongside the busy statuses).
        timeline.clear()
        set_status("o/r", 9, "needs-user")
        assert posts == [["needs:user", "status:deferred"]], posts
        assert any(path.endswith("labels/status:parked") for path in deletes), deletes
        # (x-vi) readmission: the deferred-retry `retry` flip clears the machine park.
        posts.clear(); deletes.clear()
        set_status("o/r", 9, "retry")
        assert posts == [["status:ready"]], posts
        assert any(path.endswith("labels/status:parked") for path in deletes), deletes
        assert any(path.endswith("labels/status:deferred") for path in deletes), deletes
        # (x-vi-b) [registry #614] `readmitted`: the source-issue half of re-admitting a MACHINE
        # capacity park on a PR-BACKED issue. It clears status:parked/status:deferred and restores
        # in-progress-review — NOT status:ready, which would put the issue back in the
        # IMPLEMENTATION-dispatch lane while its worker PR is open. It applies no park label, so
        # a standing human unlabel cannot suppress it (clearing a park points the same way).
        posts.clear(); deletes.clear()
        timeline[:] = [
            park_event("labeled", "status:parked", "2026-07-25T02:19:49Z", "sparq[bot]"),
            park_event("unlabeled", "status:parked", "2026-07-25T05:00:00Z", "jeswr"),
        ]
        set_status("o/r", 9, "readmitted")
        assert posts == [["status:in-progress-review"]], posts
        assert any(path.endswith("labels/status:parked") for path in deletes), deletes
        assert any(path.endswith("labels/status:deferred") for path in deletes), deletes
        assert all("status:ready" not in labels for labels in posts), posts
        # (x-vi-c) [registry #797] `handback`: the source-issue half of a MACHINE-TERMINAL
        # retirement. Its worker PR has just been CLOSED, so — unlike `readmitted`, whose PR is
        # still open — the issue goes back to the IMPLEMENTATION frontier: status:ready, with the
        # machine park AND every in-flight posture cleared. Each removal is load-bearing: a
        # handback that left `status:parked` (or `status:deferred`, or the in-progress-review
        # posture of the PR it just closed) standing would be gated straight back out of the
        # ready engine, and the work the retirement was supposed to preserve would be lost
        # silently — which is exactly the absorbing state the retirement exists to escape.
        posts.clear(); deletes.clear()
        timeline.clear()
        set_status("o/r", 9, "handback")
        assert posts == [["status:ready"]], posts
        for cleared in ("status:parked", "status:deferred", "status:in-progress",
                        "status:in-progress-review"):
            assert any(path.endswith(f"labels/{cleared}") for path in deletes), (cleared, deletes)
        # (x-vii) STRICT human probe (park-policy hygiene finding): an unlabel by an actor the
        # collaborator probe cannot confirm as a maintainer mints NO veto — the park proceeds.
        posts.clear(); deletes.clear()
        timeline[:] = [
            park_event("labeled", "status:parked", "2026-07-18T10:00:00Z", "sparq[bot]"),
            park_event("unlabeled", "status:parked", "2026-07-18T11:00:00Z", "drive-by"),
        ]
        set_status("o/r", 9, "parked")
        assert posts == [["status:deferred", "status:parked"]], posts
    finally:
        globals().update(saved)

    # (xi) malformed timeline PAGE (finding E): a non-list page could hold the newest human
    # unlabel, so _paginated must RAISE — the veto then suppresses the park (its documented
    # fail direction) instead of parking over an invisible human unpark.
    good_page = [{"event": "unlabeled", "label": {"name": "status:parked"},
                  "created_at": "2026-07-23T09:00:00Z", "actor": {"login": "jeswr"}}]

    def malformed_page_gh_json(args, *, input_doc=None):
        return [good_page, "not-a-list-page"]

    saved_json = globals()["_gh_json"]
    globals()["_gh_json"] = malformed_page_gh_json
    try:
        try:
            _paginated("o/r", 9, "timeline")
            raise AssertionError("malformed timeline page did not raise")
        except WorkerIssueError as exc:
            assert "malformed timeline page" in str(exc), exc
        # Round-4 finding 4: ENTRY validation — [[null]] passed the page-only check and
        # crashed the first consumer (None.get()) mid-decision. A non-dict entry raises for
        # every resource; a comment entry additionally needs the user/body/created_at shape.
        globals()["_gh_json"] = lambda args, *, input_doc=None: [[None]]
        for resource in ("timeline", "comments"):
            try:
                _paginated("o/r", 9, resource)
                raise AssertionError(f"[[null]] {resource} entry did not raise")
            except WorkerIssueError as exc:
                assert f"malformed {resource} entry" in str(exc), exc
        good_comment = {"user": {"login": "sparq[bot]"}, "body": "x",
                        "created_at": "2026-07-23T09:00:00Z"}
        for bad in ({**good_comment, "user": None}, {**good_comment, "body": None},
                    {**good_comment, "created_at": None}):
            globals()["_gh_json"] = lambda args, *, input_doc=None: [[good_comment, bad]]
            try:
                _paginated("o/r", 9, "comments")
                raise AssertionError(f"malformed comment entry did not raise ({bad!r})")
            except WorkerIssueError as exc:
                assert "malformed comments entry" in str(exc), exc
        globals()["_gh_json"] = lambda args, *, input_doc=None: [[good_comment]]
        assert _paginated("o/r", 9, "comments") == [good_comment]
    finally:
        globals()["_gh_json"] = saved_json

    # (xii) round-4 finding 1 (windowed-vs-lifetime split brain), the FULL sequence: CLAIM
    # grants a readmission on the windowed count -> the WORKER-side budget check must derive
    # the SAME cutoff (park_policy.readmission_cutoff over the live timeline, strict
    # maintainer probe) and charge the windowed count -> the model actually runs (attempt
    # recording succeeds instead of "exhausted before model launch"). Real attempt_check/
    # record_attempt wiring with only the GitHub seams patched.
    seq_state = {"comments": [], "timeline": []}
    seq_posts = []

    class _SeqResult:
        returncode = 0
        stdout = ""
        stderr = ""

    def seq_run_gh(args, *, input_text=None, check=True):
        result = _SeqResult()
        if "/collaborators/" in str(args[1]):
            result.stdout = "admin" if "/collaborators/jeswr/" in args[1] else "none"
        return result

    def seq_gh_json(args, *, input_doc=None):
        if input_doc is not None and "body" in input_doc:
            seq_posts.append(input_doc["body"])
        return {}

    def seq_paginated(repo, issue, resource):
        return list(seq_state[resource if resource in seq_state else "comments"])

    seq_seams = {"_run_gh": seq_run_gh, "_gh_json": seq_gh_json, "_paginated": seq_paginated}
    saved_seq = {name: globals()[name] for name in seq_seams}
    saved_output = os.environ.get("GITHUB_OUTPUT")
    globals().update(seq_seams)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            def budget_outputs():
                output_file = Path(tmp) / "outputs.txt"
                output_file.write_text("", encoding="utf-8")
                os.environ["GITHUB_OUTPUT"] = str(output_file)
                attempt_check("o/r", 9, 2, "sparq[bot]")
                return dict(line.split("=", 1) for line in
                            output_file.read_text(encoding="utf-8").splitlines())

            receipt = {"user": {"login": "sparq[bot]"}, "created_at": "2026-07-20T00:00:00Z",
                       "body": f"x {ATTEMPT_MARKER} run=1 -->"}
            receipt2 = {**receipt, "created_at": "2026-07-21T00:00:00Z",
                        "body": f"x {ATTEMPT_MARKER} run=2 -->"}
            seq_state["comments"] = [receipt, receipt2]  # lifetime budget of 2 is spent
            park_applied = {"event": "labeled", "label": {"name": "status:parked"},
                            "created_at": "2026-07-21T12:00:00Z",
                            "actor": {"login": "sparq-orchestrator[bot]"}}
            human_readmit = {"event": "unlabeled", "label": {"name": "status:parked"},
                             "created_at": "2026-07-22T09:00:00Z",
                             "actor": {"login": "jeswr"}}
            # (xii-a) NO gesture: the lifetime count stands — exhausted, and the recorder
            # refuses the launch (the pre-fix behaviour below the budget line is unchanged).
            seq_state["timeline"] = [park_applied]
            assert budget_outputs() == {"used": "2", "exhausted": "true"}
            try:
                record_attempt("o/r", 9, 2, "sparq[bot]", "77.1")
                raise AssertionError("exhausted recorder did not refuse the launch")
            except WorkerIssueError as exc:
                assert "exhausted before model launch" in str(exc), exc
            assert seq_posts == []
            # (xii-b) THE SEQUENCE: a proven-human unlabel (the same gesture CLAIM granted
            # the readmission on) => the worker-side count is WINDOWED (both receipts predate
            # the cutoff) => attempt-check admits the run and the recorder posts the attempt
            # receipt — the model actually runs instead of the no-op relaunch loop.
            seq_state["timeline"] = [park_applied, human_readmit]
            assert budget_outputs() == {"used": "0", "exhausted": "false"}
            record_attempt("o/r", 9, 2, "sparq[bot]", "77.1")
            assert len(seq_posts) == 1 and f"{ATTEMPT_MARKER} run=77.1 -->" in seq_posts[0]
            assert "attempt 1/2" in seq_posts[0]  # numbering restarts inside the window
            # (xii-c) an UNVERIFIABLE gesture (bot unlabel) opens no window: still exhausted.
            bot_unlabel = {**human_readmit, "actor": {"login": "sparq-orchestrator[bot]"}}
            seq_state["timeline"] = [park_applied, bot_unlabel]
            seq_posts.clear()
            assert budget_outputs() == {"used": "2", "exhausted": "true"}
            # (xii-d) an UNREADABLE timeline keeps the FULL count (fail toward exhaustion —
            # CLAIM freezes its ladder on the same view; no fresh budget on unproven data).
            def raising_paginated(repo, issue, resource):
                if resource == "timeline":
                    raise WorkerIssueError("timeline unavailable")
                return list(seq_state["comments"])

            globals()["_paginated"] = raising_paginated
            assert budget_outputs() == {"used": "2", "exhausted": "true"}
            globals()["_paginated"] = seq_paginated
    finally:
        globals().update(saved_seq)
        if saved_output is None:
            os.environ.pop("GITHUB_OUTPUT", None)
        else:
            os.environ["GITHUB_OUTPUT"] = saved_output
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

    # [registry #596] Un-charge this run's attempt when the launch died on the account credential.
    # The class gate lives in worker-pr.is_credential_outage (pure + self-tested), NOT in a workflow
    # `if:` expression, so the non-chargeable rule is testable and shared with the review path.
    avoid = subparsers.add_parser("void-attempt", parents=[common])
    avoid.add_argument("--bot-login", required=True)
    avoid.add_argument("--run-key", required=True)
    avoid.add_argument("--exit-class", required=True,
                       help="worker-live.sh exit class for THIS run; only a credential-outage "
                            "class voids the attempt (every other value is a no-op)")

    trust = subparsers.add_parser("reverify", parents=[common])
    trust.add_argument("--expected-author", required=True)
    trust.add_argument("--expected-body-sha", required=True)
    trust.add_argument("--trust-gate", required=True)
    trust.add_argument("--bot-login", required=True)
    trust.add_argument("--issue-file", required=True)
    # [issue #568] The pre-publish re-check, run in the fresh publisher immediately before
    # push/PR. `--mode pre-publish` accepts THIS run's own ready -> in-progress claim (dispatch
    # mode demands status:ready, which the workflow itself removed at claim time, so it would
    # refuse every real publish) bound to the run key below; `--forbid-gate-root` is the
    # model-mutable tree the verifier must NOT resolve into. Both are mandatory in that mode.
    trust.add_argument("--current-run-key", default=None)
    trust.add_argument("--mode", choices=("dispatch", "pre-publish"), default="dispatch")
    trust.add_argument("--forbid-gate-root", default=None)

    status = subparsers.add_parser("status", parents=[common])
    # Derived from STATUS_TRANSITIONS, never re-declared: a transition added to the table without
    # a CLI choice is unreachable from every helper call site (worker-pr, dispatch-claim), and
    # this list silently drifting out of date is exactly how a new exit becomes a no-op.
    status.add_argument("--status", choices=tuple(sorted(STATUS_TRANSITIONS)), required=True)

    receipt = subparsers.add_parser("claim-receipt", parents=[common])
    receipt.add_argument("--model", required=True)
    receipt.add_argument("--run-url", required=True)
    # [issue #568] The receipt is the ownership half of the shared status:in-progress label, so it
    # carries this run's key and is posted BEFORE the label flip; --bot-login scopes the
    # idempotency probe to the bot's own comments.
    receipt.add_argument("--run-key", required=True)
    receipt.add_argument("--bot-login", required=True)

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
        elif args.command == "void-attempt":
            void_attempt_on_outage(args.repo, args.issue, args.bot_login, args.run_key,
                                   args.exit_class)
        elif args.command == "reverify":
            reverify(args.repo, args.issue, args.expected_author, args.expected_body_sha,
                     args.trust_gate, args.bot_login, args.issue_file, args.current_run_key,
                     args.mode, args.forbid_gate_root)
        elif args.command == "status":
            set_status(args.repo, args.issue, args.status)
        elif args.command == "claim-receipt":
            claim_receipt(args.repo, args.issue, args.model, args.run_url, args.run_key,
                          args.bot_login)
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
