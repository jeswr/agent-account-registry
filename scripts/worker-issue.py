#!/usr/bin/env python3
# [GPT-5.6] REG-3 target-issue control plane: revision-bound trust revalidation, durable attempt
# accounting, and fail-closed status transitions. It never reads registry account credentials.
"""Small GitHub API helper for the live registry worker."""

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
# [issue #1075] PRE-MODEL REFUSAL receipt — the budget unit for a dispatch that died at the
# last-step trust/revision revalidation, before the model ever launched.
#
# THE DEFECT IT CLOSES. worker.yml's `trust` step is `continue-on-error` and runs BEFORE `prepare`,
# so a refusal skipped `Record model attempt` entirely: the run consumed a whole dispatch cycle
# (runner, App token, target checkout) and incremented NOTHING. `max_attempts` is checked against a
# counter the refusal path could not move, so the deferred-retry lane re-admitted the same issue
# forever — target issue #834 was dispatched ~34 times in one day (next-highest: 3), ~18% of the
# day's dispatch capacity. Every one of those refusals was CORRECT (a bot-authored issue with no
# human `approved` comment); the defect is the unbounded repetition, never the refusal, so the fix
# BOUNDS the repetition and does not widen the trust boundary by one login.
#
# DELIBERATELY a distinct marker from ATTEMPT_MARKER, not an alias of it:
#   * cost/health accounting (groom.py's stall + model-health windows, count_attempts here) means
#     "the model ran" — charging a refusal there would invent model spend that never happened;
#   * find_maintainer_approval anchors approval staleness on ATTEMPT_MARKER ("did the human see the
#     failure being retried?"). A refusal is not a failed model run, and moving the anchor would
#     invalidate an `approved` comment a maintainer posted between two refusals — the very gesture
#     the refusal is asking for. The anchor therefore stays attempt-only.
# The two counters are SUMMED into one budget by budget_used() and nowhere else, so the per-issue
# dispatch bound sees every consumed cycle while the model-spend counter stays honest.
#
# No void twin (contrast ATTEMPT_VOID_MARKER): a refusal charge is not conditional on an exit class
# — the cycle was spent by definition — and it is windowed by the SAME human-readmission cutoff as
# attempts, so a human unpark still re-opens the budget. Bot-authored only, like every other durable
# marker: a third party can neither forge one to burn an issue's budget nor suppress one.
REFUSAL_MARKER = "<!-- sparq-worker-refusal:v1"
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


def _receipt_run_keys(body, marker):
    """The run keys carried by one comment body's receipts of `marker`."""
    return set(re.findall(re.escape(marker) + r" run=(\S+) -->", body))


def _attempt_run_keys(body):
    """The run keys carried by the attempt receipts in one comment body."""
    return _receipt_run_keys(body, ATTEMPT_MARKER)


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


def _count_receipts(comments, bot_login, marker, voided=frozenset(), since=None, log=print):
    """Bot-authored receipts of `marker` CHARGED to a budget, optionally windowed by `since`.

    ONE implementation behind count_attempts/count_refusals and their windowed forms (issue
    #1075): the refusal counter must charge, window and fail in EXACTLY the way the attempt
    counter does, and a second hand-written copy is how the two silently drift apart.

    Fail directions, all toward CHARGING (never a fresh budget on unproven data): a receipt whose
    run key is entirely `voided` is uncharged (registry #596) but one with no run key at all is a
    legacy/degenerate form and stays charged; a falsy or UNPARSEABLE `since` (loudly) charges the
    whole history; a receipt with no created_at, or one whose created_at cannot be parsed
    (loudly), is charged; an instant tie with the cutoff is charged. The window compare is over
    PARSED aware datetimes (park_policy.parse_ts), never raw strings — an equally-valid spelling
    like the space-separator "2026-07-23 10:30:00Z" VALIDATES yet sorts lexicographically before
    "2026-07-23T09:00:00Z", so a string compare read a post-cutoff receipt as pre-cutoff and
    silently un-charged it (round-4 finding 3 + round-5 finding 2)."""
    since_instant = None
    parse_ts = None
    if since:
        parse_ts = _park_policy().parse_ts
        try:
            since_instant = parse_ts(since)
        except ValueError:
            log(f"::warning::readmission cutoff {since!r} is not a parseable timestamp — the "
                "attempt budget keeps the FULL historical count (never a fresh budget on "
                "unproven data)")
    bot = bot_login.casefold()
    charged = 0
    for comment in comments:
        if str(comment.get("user", {}).get("login", "")).casefold() != bot:
            continue
        body = str(comment.get("body", ""))
        if marker not in body:
            continue
        keys = _receipt_run_keys(body, marker)
        if keys and keys <= voided:
            continue
        if since_instant is not None:
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


def count_attempts(comments, bot_login):
    """Durable MODEL attempts CHARGED to the budget. A receipt whose run was voided as a
    credential outage (registry #596 — the model never launched, so no attempt was spent) is
    subtracted; a receipt with no run key at all is a legacy/degenerate form and stays charged
    (the fail direction is always toward CHARGING).

    This counter means "the model ran" and is what cost/health accounting reads. A PRE-MODEL
    refusal is NOT one of these (issue #1075) — see count_refusals; budget_used sums them."""
    return _count_receipts(comments, bot_login, ATTEMPT_MARKER,
                           voided=attempt_voids(comments, bot_login))


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
    # Void subtraction is GLOBAL, exactly as in worker-pr.count_rounds_since (registry #596): a
    # credential-outage attempt is uncharged whichever side of the readmission cutoff it landed on.
    return _count_receipts(comments, bot_login, ATTEMPT_MARKER,
                           voided=attempt_voids(comments, bot_login), since=since, log=log)


def count_refusals(comments, bot_login):
    """Durable PRE-MODEL REFUSALS charged to the per-issue dispatch budget (issue #1075).

    One receipt per dispatch cycle that reached the last-step trust/revision revalidation and was
    refused there. It is a spent cycle — runner, App token and target checkout — so it charges the
    budget; it is NOT a model attempt, so it never appears in count_attempts (cost/health) and
    never moves find_maintainer_approval's staleness anchor.

    No void twin: unlike a credential-outage attempt (registry #596), a refusal has no exit class
    that could un-spend the cycle, so there is nothing to subtract."""
    return _count_receipts(comments, bot_login, REFUSAL_MARKER)


def count_refusals_since(comments, bot_login, since, log=print):
    """count_refusals windowed by the human-readmission cutoff, on exactly the terms
    count_attempts_since uses. Load-bearing, not symmetry for its own sake: without it a human
    unpark would re-open the ATTEMPT half of the budget while the refusal half stayed charged
    forever, and an issue that once burned its budget on refusals could never be readmitted."""
    return _count_receipts(comments, bot_login, REFUSAL_MARKER, since=since, log=log)


def budget_used(comments, bot_login, since=None, log=print):
    """The per-issue DISPATCH budget charge: model attempts PLUS pre-model refusals (#1075).

    THE one place the two counters are summed. `max_attempts` bounds dispatch CYCLES, not model
    spend — a cycle that allocated a runner, minted a token and checked out the target repo before
    refusing consumed exactly the capacity the bound exists to protect. Keeping the sum here (and
    the counters distinct underneath) is what lets the budget see every cycle while cost/health
    accounting still sees only runs where a model actually ran."""
    if since:
        return (count_attempts_since(comments, bot_login, since, log)
                + count_refusals_since(comments, bot_login, since, log))
    return count_attempts(comments, bot_login) + count_refusals(comments, bot_login)


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


def _windowed_budget(repo, issue, comments, bot_login, max_attempts):
    """The dispatch-cycle count CHARGED to the budget: the plain lifetime count below the
    budget line, the readmission-windowed count at/above it (round-4 finding 1 — the
    windowed-vs-lifetime split brain). CLAIM grants a readmission on the WINDOWED count
    (dispatch-claim's deferred lane); the old worker-side re-check used the UNWINDOWED
    lifetime count, so the launched retry declared itself exhausted, ran no model, the final
    re-park was vetoed by the very unlabel that granted the readmission, status:ready
    persisted, and every tick relaunched a no-op workflow forever. The cutoff is probed only
    once the lifetime count is exhausted, exactly like CLAIM.

    [issue #1075] The charge is budget_used — attempts PLUS pre-model refusals — because the
    thing `max_attempts` bounds is dispatch cycles. Counting attempts alone left the refusal
    path incrementing nothing at all, so a permanently-refused issue was re-admitted forever
    (target #834: ~34 dispatches in one day, ~18% of the day's capacity)."""
    used = budget_used(comments, bot_login)
    if used < max_attempts:
        return used
    cutoff = _readmission_cutoff(repo, issue)
    if not cutoff:
        return used
    charged = budget_used(comments, bot_login, cutoff)
    if charged < used:
        print(f"readmission window open: a human unlabeled a park label at {cutoff}; the "
              f"attempt budget charges {charged} of {used} recorded dispatch cycle(s)")
    return charged


def attempt_check(repo, issue, max_attempts, bot_login):
    comments = _paginated(repo, issue, "comments")
    used = _windowed_budget(repo, issue, comments, bot_login, max_attempts)
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
    used = _windowed_budget(repo, issue, comments, bot_login, max_attempts)
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


def _refusal_outputs(used, max_attempts):
    """The refusal recorder's step outputs — the POST-charge budget state.

    [issue #1075 review round 1] `exhausted` is here because the worker job's own `exhausted`
    output cannot come from `attempt-check` alone on this path: that step runs BEFORE `trust`,
    so on the terminal refusal it reports the PRE-charge state (used=N-1, exhausted=false) and
    final_state's exhaustion arm — which reads that output — could never observe the slot this
    very run just spent. It is the same `used >= max_attempts` predicate attempt_check applies,
    evaluated after the charge instead of before it, so the two can only ever agree."""
    return {"used": used, "exhausted": used >= max_attempts}


def record_refusal(repo, issue, max_attempts, bot_login, run_key, run_url):
    """[issue #1075] Charge THIS dispatch cycle to the durable per-issue budget when the
    last-step trust/revision revalidation REFUSED before the model launched.

    worker.yml runs `trust` with continue-on-error and BEFORE `prepare`, so a refusal skips
    `Record model attempt` — the cycle cost a runner, an App token and a target checkout and
    incremented nothing, leaving `max_attempts` unable to bound it. This is the missing
    increment: same durable comment plane as the attempt receipt, distinct marker, so
    attempt_check/record_attempt see the spent cycle (budget_used) while cost/health accounting
    and the maintainer-approval anchor keep seeing model attempts only.

    It does NOT raise on an exhausted budget — the cycle already happened and the charge must
    land regardless; the NEXT tick's attempt_check reads it and final_state converges the issue
    to the machine-owned status:parked hold. Idempotent per run key, like every recorder here: a
    re-entered step re-uses its receipt instead of double-charging.

    The comment carries NO refusal detail beyond the run link. The reason is derived from live
    target-repo state (author, body, labels, trust verdict) and this receipt is posted into that
    same public issue, so echoing it here would relay untrusted target text through the bot's own
    voice; the run log is the trustworthy place for the cause."""
    comments = _paginated(repo, issue, "comments")
    # The number quoted to the maintainer is the WINDOWED charge attempt_check will read, not the
    # lifetime one: after a human readmission the two differ, and a receipt claiming "3/3 used"
    # on a budget the human just re-opened would read as a terminal state that is not one.
    charged = _windowed_budget(repo, issue, comments, bot_login, max_attempts)
    exact_marker = f"{REFUSAL_MARKER} run={run_key} -->"
    for comment in comments:
        if (str(comment.get("user", {}).get("login", "")).casefold() == bot_login.casefold()
                and exact_marker in str(comment.get("body", ""))):
            _write_outputs(_refusal_outputs(min(charged, max_attempts), max_attempts))
            print(f"pre-model refusal already recorded (run {run_key})")
            return
    used = min(charged + 1, max_attempts)
    body = (
        "> 🤖 SPARQ agent — this dispatch was REFUSED at the last-step trust/issue-revision "
        "revalidation, before any model ran. No work was attempted and no model spend was "
        f"incurred, but the dispatch cycle IS charged against this issue's budget "
        f"({used}/{max_attempts} cycles used), so a permanently-refused issue stops being "
        "re-dispatched instead of retrying forever (registry #1075).\n\n"
        f"- Refused run: {run_url}\n\n"
        "The refusal itself is correct behaviour — the run log above names the cause. If this "
        "issue should proceed, resolve that cause (for a third-party/bot-authored issue, a human "
        "maintainer commenting `approved` is the required evidence); once the budget is spent, a "
        "human must also remove the park label to re-open it.\n\n"
        f"{exact_marker}"
    )
    _gh_json(
        ["api", "-X", "POST", f"repos/{repo}/issues/{issue}/comments", "--input", "-"],
        input_doc={"body": body},
    )
    _write_outputs(_refusal_outputs(used, max_attempts))
    print(f"pre-model refusal charged to the dispatch budget: {used}/{max_attempts}")


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
    # ORDER IS LOAD-BEARING [issue #1058]: every DELETE runs BEFORE the single add POST, and the
    # add POST is one atomic call. The old order (add, then remove label-by-label) opened a window
    # on EVERY status:ready <-> status:deferred flip in which both labels were live, and any
    # failure in the remove half made that contradictory pair durable — a state no
    # STATUS_TRANSITIONS entry describes, which is the measured producer of the contradictory rows
    # on the live board. Removing first makes every intermediate and every crash state a SUBSET of
    # the consistent state we started from: the issue can lose its positive attestation (fail
    # CLOSED — the ready engine demands `status:ready`, so an issue with none is simply not
    # dispatched) but it can never be dispatchable AND deferred at once, i.e. claimed by two lanes.
    for label in sorted(remove - add):
        _remove_label(repo, issue, label)
    for label in sorted(add):
        _ensure_label(repo, label)
    if add:
        _gh_json(
            ["api", "-X", "POST", f"repos/{repo}/issues/{issue}/labels", "--input", "-"],
            input_doc={"labels": sorted(add)},
        )
    _assert_status_landed(repo, issue, status, add, remove - add)
    print(f"target issue state: {status}")


def _assert_status_landed(repo, issue, status, add, drop):
    """Re-read the LIVE label set and refuse to report a partial write as success [issue #1058].

    The ordering above bounds the DAMAGE of a half-write; this bounds the LIE. A DELETE or POST
    that fails without raising (an API success that did not land, an eventually-consistent read, a
    concurrent writer) previously left the issue in a label state no STATUS_TRANSITIONS entry
    describes while `set_status` printed the transition as done. The postcondition of
    STATUS_TRANSITIONS[status] is exactly: every added label live, every dropped label gone. Fail
    LOUDLY when it does not hold — the caller must see a failed status write, never a silent one.
    """
    live = _live_issue_labels(repo, issue)
    missing = sorted(add - live)
    residue = sorted(drop & live)
    if missing or residue:
        raise WorkerIssueError(
            f"status {status!r} did not land on {repo}#{issue}: missing {missing}, still present "
            f"{residue} — the live label set matches no STATUS_TRANSITIONS state and this "
            f"partial write must not be reported as success")


def _live_issue_labels(repo, issue):
    item = _gh_json(["api", f"repos/{repo}/issues/{issue}"])
    if not isinstance(item, dict) or not isinstance(item.get("labels"), list):
        raise WorkerIssueError(
            f"GitHub API returned no readable label set for {repo}#{issue} — the status write "
            f"cannot be confirmed")
    names = set()
    for label in item["labels"]:
        # An entry we cannot READ is not evidence that a label is ABSENT — and absence is exactly
        # what `_assert_status_landed` reads this set for (`drop & live` must come back empty).
        # Discarding a malformed entry would let `{"labels": [null, ...]}` certify that every
        # dropped label is gone, the one conclusion an unreadable response cannot support, and a
        # removal-only transition would pass its confirmation on that. Refuse the whole read, the
        # same direction `_paginated` takes on a malformed entry.
        if not isinstance(label, dict) or not isinstance(label.get("name"), str):
            raise WorkerIssueError(
                f"GitHub API returned a malformed label entry ({label!r}) for {repo}#{issue} — "
                f"the status write cannot be confirmed")
        names.add(label["name"])
    return names


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


# Distinguishes "not looked up yet" from a lookup that legitimately answered None (unreadable
# vocabulary). Using None for both would re-issue the `gh label list` on every subsequent failure.
_UNREAD = object()


def followup_label_plan(declared, known_labels):
    """`(apply, dropped, area_missing)` for ONE follow-up's label set. Pure.

    A LABEL-FREE CREATE MUST NEVER BE THE *FIRST* RECOVERY. `gh issue create` fails the WHOLE
    create when any one `--label` does not exist on the target, and the original recovery here
    re-issued the create with NO labels at all, immediately. So a model that supplied a correct
    `area:dispatch` alongside a single typo'd or not-yet-declared label had EVERY label discarded
    — including the `area:`.

    That is the one input no lane in this estate can manufacture. `curate-frontier.derive_area`
    refuses rather than guesses (measured: the directory-hint fallback it replaced was 12.9%
    precise on this repository, #809), and `triage.triage()` can never mint an `area:*` at all, so
    a follow-up minted label-free lands in the `status:untriaged` pile with no route out and is
    counted, permanently, by `triage-stock-alert.census()`'s `unattributable` bucket.

    `known_labels` of `None` means the label vocabulary could not be read. That is not evidence
    that a label is invalid, so nothing is dropped — the caller retries with the declared set
    unchanged and lets `gh` be the judge, which is the fail-closed direction for a DROP decision.

    What this function does NOT decide is the last rung. `create_followups` still falls back to a
    label-free create when every labelled attempt has failed, because the alternative there is not
    "a correctly-labelled issue", it is NO ISSUE AT ALL — and an item that is never created is
    absent from every census, which is a strictly worse instance of the #971 population-shrink
    shape than an item that is created unattributable and therefore COUNTED. That rung is loud,
    and it records the intended labels in the issue body. See `create_followups`.
    """
    declared = {label for label in (declared or []) if isinstance(label, str) and label}
    area_missing = not any(label.startswith("area:") for label in declared)
    if known_labels is None:
        return sorted(declared), [], area_missing
    known = set(known_labels)
    return sorted(declared & known), sorted(declared - known), area_missing


def _known_labels(repo):
    """The target's declared label vocabulary, or None when it cannot be read (never a guess).

    The `except` is the whole contract, not defensive padding. `_gh_json` -> `_run_gh(check=True)`
    RAISES on a non-zero `gh`, and a non-zero `gh` is exactly what "cannot be read" means here, so
    without this the documented `None` was reachable only via the degenerate `gh`-succeeded-but-
    returned-non-list case and the fail-closed branch in `followup_label_plan` could not be
    entered in production by the cause that names it.

    It is also the CORRELATED case: this call is made only after an `issue create` already failed,
    so whatever broke that create (rate limit, 502, token scope) is likely to break this read in
    the same second. Raising here propagated that one entry's bad luck into the whole batch.
    """
    try:
        rows = _gh_json(["label", "list", "-R", repo, "--limit", "200", "--json", "name"])
    except WorkerIssueError as exc:
        print(f"::warning::could not read {repo}'s label vocabulary ({exc}); no label will be "
              "dropped on the strength of an unreadable vocabulary")
        return None
    if not isinstance(rows, list):
        return None
    names = {str(row.get("name", "")) for row in rows if isinstance(row, dict)}
    return {name for name in names if name} or None


def create_followups(repo, source_issue, spec_file):
    """Create de-duplicated follow-up issues from a JSONL file the model wrote (one {title, body, labels}
    per line) while implementing `source_issue`. Each is linked back + labelled from:agent +
    self-improvement so the issue-sweeper actions them. This is the procedure for the orchestrator
    to capture discovered work.

    THE BATCH PROPERTY, and it is the point of the per-entry `try` below: ONE follow-up failing
    must not stop the others from being created. Each line is an INDEPENDENT item of discovered
    work; there is no ordering or dependency between them, so nothing about entry 1's bad luck is
    evidence about entry 2. An earlier revision put a raising helper (`_known_labels`) inside this
    loop and a single unlucky entry destroyed the whole remaining batch while both call sites
    (`worker.yml`, `review-fix.yml`) swallow the exit code with `|| true` — a silent
    population-shrink, which is the exact failure class this function was being fixed for.

    Fail directions, in order:
      * a create that fails with the model's labels is retried with the labels the target actually
        DECLARES, so a typo cannot take a valid `area:` down with it;
      * an UNREADABLE vocabulary drops nothing (see `_known_labels`);
      * if every labelled attempt fails, the issue is created WITHOUT labels rather than lost, and
        said out loud, with the intended labels recorded in its body.

    Honest scope of "best-effort": a failure creating any ONE follow-up is contained here and
    never raises. The `gh issue list` read ABOVE the loop is not contained — if the existing-title
    set cannot be read there is no de-duplication, and re-minting issues the model already filed
    is a worse outcome than deferring the batch, so that one propagates to `main()` (exit 1, which
    both call sites deliberately swallow) after this annotation.
    """
    path = Path(spec_file)
    if not path.exists():
        print("no follow-ups declared")
        return
    try:
        existing = {str(i.get("title", "")) for i in (_gh_json(
            ["issue", "list", "-R", repo, "--state", "open", "--limit", "300",
             "--json", "title"]) or [])}
    except WorkerIssueError as exc:
        # Both call sites `|| true` the exit code, so the ANNOTATION is the only surviving signal
        # that a whole batch of discovered work was deferred. Emit it, then let it propagate.
        print(f"::error::follow-up capture skipped for {repo}: the open-issue list could not be "
              f"read ({exc}), so de-duplication is impossible and NO follow-up was created")
        raise
    created = 0
    # Read the label vocabulary at most once, and only if a create actually fails: the happy path
    # must not pay a `gh label list` per worker run.
    known_labels = _UNREAD
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
        # The labels that actually reach the created issue. NOT the declared set: the whole point
        # of the ladder below is that they can differ, and the area-missing signal has to be read
        # off what LANDED or it goes quiet on the one path that needs it most — a model that
        # declared `area:dsipatch` has a label starting `area:`, so a declared-set test says
        # "area present" while the retry drops it and the issue is born unattributable anyway.
        applied = labels
        try:
            result = _run_gh(args, check=False)
            if result.returncode != 0:
                # An unknown label fails the whole create. Retry with the labels the target
                # actually DECLARES — not label-free at this rung (see `followup_label_plan`):
                # dropping the model's `area:` is the one loss no later lane can repair.
                if known_labels is _UNREAD:
                    known_labels = _known_labels(repo)
                keep, dropped, _ = followup_label_plan(labels, known_labels)
                if dropped:
                    print(f"::warning::follow-up {title!r}: dropping undeclared label(s) "
                          f"{', '.join(dropped)}; retrying with {', '.join(keep) or 'no labels'}")
                retry = ["issue", "create", "-R", repo, "--title", title, "--body", body]
                for label in keep:
                    retry += ["--label", label]
                applied = keep
                result = _run_gh(retry, check=False)
                if result.returncode != 0 and keep:
                    # LAST RUNG. Every labelled attempt has failed, so the choice is no longer
                    # "right labels vs wrong labels", it is "an unattributable issue vs no issue".
                    # An issue that is never created is absent from every census — including the
                    # `unattributable` bucket that exists to find exactly this — so it is created
                    # bare, loudly, with the intended labels written into the body so the
                    # attribution is recoverable by whoever reads it.
                    print(f"::warning::follow-up {title!r}: could not be created carrying "
                          f"{', '.join(keep)}; creating it WITHOUT labels so the discovered work "
                          "is not lost. It is born unattributable — the intended labels are "
                          "recorded in its body.")
                    # NOT prefixed `sparq-followup`: the body already carries
                    # `<!-- sparq-followup:v1 -->`, and a second marker sharing that prefix makes
                    # any substring probe for the provenance link ambiguous.
                    bare = body + f"\n<!-- sparq-intended-labels: {','.join(labels)} -->"
                    applied = []
                    result = _run_gh(["issue", "create", "-R", repo, "--title", title,
                                      "--body", bare], check=False)
        except (WorkerIssueError, OSError) as exc:
            # ISOLATION (see the docstring). Contain it to THIS entry and keep going: the rest of
            # the batch is independent work and there is no evidence against it. Deliberately NOT
            # a bare `except` — a TypeError/AttributeError here is a defect in this file, not an
            # operational failure of one follow-up, and must stay loud.
            print(f"::warning::follow-up {title!r} abandoned: {exc}. The remaining follow-ups are "
                  "still attempted — one failure must not shrink the batch.")
            continue
        if result.returncode == 0:
            created += 1
            existing.add(title)
            # An `area:` is the one label neither `triage.triage()` nor `curate-frontier` can
            # manufacture, so a follow-up minted without one is born into the unattributable
            # class. Say so at the point of creation, where the model that knows the answer is
            # still in the loop — the alternative is discovering it in a census days later.
            if followup_label_plan(applied, None)[2]:
                print(f"::warning::follow-up {title!r} carries no `area:` label — it cannot be "
                      "staged by any lane until one is attributed "
                      "(triage-stock-alert.census: unattributable)")
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
    # [issue #1058] The seam models the issue's LIVE label set, not just the calls made against
    # it, so the order of those calls and the state they leave behind are both observable. `calls`
    # is the interleaved log (ordering), `snapshots` the label set after every mutating call (the
    # co-live invariant), and the two levers simulate an API call that reports success without
    # landing — the exact half-write that made the contradictory pair durable.
    live, snapshots, calls = set(), [], []
    drop_deletes, drop_posts = [False], [False]

    def fake_run_gh(args, *, input_text=None, check=True):
        if args[1] == "-X" and args[2] == "DELETE":
            deletes.append(args[3])
            calls.append(("DELETE", args[3].rsplit("/labels/", 1)[-1]))
            if not drop_deletes[0]:
                live.discard(args[3].rsplit("/labels/", 1)[-1])
            snapshots.append(set(live))
        result = _Result()
        if "/collaborators/" in str(args[1]):
            # The strict maintainer probe (_is_human_maintainer): jeswr is a repo admin,
            # everyone else is not — the park veto only honours PROVEN humans.
            result.stdout = "admin" if "/collaborators/jeswr/" in args[1] else "none"
        return result

    def fake_gh_json(args, *, input_doc=None):
        if input_doc is not None and "labels" in input_doc:
            posts.append(input_doc["labels"])
            calls.append(("POST", tuple(input_doc["labels"])))
            if not drop_posts[0]:
                live.update(input_doc["labels"])
            snapshots.append(set(live))
            return {}
        if "-X" not in args:                        # set_status's post-write label re-read
            return {"labels": [{"name": name} for name in sorted(live)]}
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

        # (x-vii-b) [issue #1058] the DEFERRAL flip is the other half of the contradictory pair,
        # and it is pinned by CONTENT, not by the ordering loop below: a `deferred` that left
        # `status:ready` standing would mint status:ready + status:deferred no matter what order
        # the calls went out in. Nothing else in this suite pinned it — emptying this entry's
        # remove set left the whole self-test green — so ordering coverage alone would have read
        # as table coverage it does not provide.
        posts.clear(); deletes.clear(); timeline.clear()
        live.clear()
        live.update({"status:ready", "role:impl"})
        set_status("o/r", 9, "deferred")
        assert posts == [["status:deferred"]], posts
        for cleared in ("status:ready", "status:in-progress", "status:in-progress-review"):
            assert any(path.endswith(f"labels/{cleared}") for path in deletes), (cleared, deletes)
        assert live == {"role:impl", "status:deferred"}, sorted(live)

        # (x-viii) [issue #1058] the WRITE-ORDER invariant, over the WHOLE table rather than one
        # hand-picked flip: for EVERY transition, seeded from the worst case (every label the
        # transition drops is live), no observable state holds an added label and a dropped label
        # at the same time, and every DELETE is issued before the add POST. The add-then-remove
        # order this replaces put `add` on the issue while the whole drop set was still live, so
        # it fails the co-live assertion on all seven status:ready <-> status:deferred flips —
        # the assertion is load-bearing, not decorative.
        for name, (added, removed) in sorted(STATUS_TRANSITIONS.items()):
            dropped = removed - added
            posts.clear(); deletes.clear(); calls.clear(); snapshots.clear(); timeline.clear()
            live.clear()
            live.update(dropped | {"role:impl"})
            seeded = set(live)
            set_status("o/r", 9, name)
            for state in [seeded, *snapshots]:
                assert not (state & added and state & dropped), (name, sorted(state))
            verbs = [verb for verb, _ in calls]
            if added and dropped:
                assert "POST" in verbs and verbs.index("POST") > max(
                    index for index, verb in enumerate(verbs) if verb == "DELETE"), (name, calls)
            # ...and the transition still lands exactly what its table entry describes.
            assert live == (seeded - dropped) | added, (name, sorted(live))

        # (x-ix) [issue #1058] a HALF-write is never reported as success. Both halves are covered
        # by a seam that returns 200 without landing the change: a DELETE that leaves the dropped
        # label live (this is the durable status:ready + status:deferred pair measured on the live
        # board) and a POST that never adds. Before the post-write re-read, both printed
        # "target issue state: retry" over a label set no STATUS_TRANSITIONS entry describes.
        for lever, needle in ((drop_deletes, "still present ['status:deferred']"),
                              (drop_posts, "missing ['status:ready']")):
            posts.clear(); deletes.clear(); calls.clear(); timeline.clear()
            live.clear()
            live.add("status:deferred")
            lever[0] = True
            try:
                set_status("o/r", 9, "retry")
                raise AssertionError(f"half-written flip reported as success ({needle})")
            except WorkerIssueError as exc:
                assert "must not be reported as success" in str(exc), exc
                assert needle in str(exc), exc
            finally:
                lever[0] = False
        # ...and the same flip over a HEALTHY seam raises nothing: the re-read is a confirmation,
        # not a blanket veto that would fail every real status write.
        posts.clear(); deletes.clear()
        live.clear()
        live.add("status:deferred")
        set_status("o/r", 9, "retry")
        assert live == {"status:ready"}, sorted(live)

        # (x-x) a re-read that cannot be PARSED is a failure to confirm, never a pass — the write
        # may well have half-landed, so it fails toward the maintainer.
        live.clear()
        live.add("status:deferred")

        def unreadable_gh_json(args, *, input_doc=None):
            if input_doc is not None and "labels" in input_doc:
                return fake_gh_json(args, input_doc=input_doc)
            return "not-an-issue-object"

        globals()["_gh_json"] = unreadable_gh_json
        landed = True
        try:
            set_status("o/r", 9, "retry")
        except WorkerIssueError as exc:
            landed = False
            assert "cannot be confirmed" in str(exc), exc
        except Exception as exc:        # a raw crash is malformedness, not a diagnosable refusal
            raise AssertionError(
                f"unreadable re-read crashed instead of refusing: {exc!r}") from exc
        finally:
            globals()["_gh_json"] = fake_gh_json
        assert not landed, "unconfirmable status write reported as success"

        # (x-x-b) round-2 finding: the same refusal for a malformed ENTRY inside an otherwise
        # well-formed labels list. This is the case that reads as PROOF rather than as a crash —
        # a filtered-out `null` is indistinguishable from "the dropped label is gone", so the
        # removal-only `complete` flip (add == set(), drop == {status:in-progress, ...}) would
        # confirm itself against a response nothing can be concluded from. Discarding the entry
        # instead of raising makes `set_status` return cleanly here, so this assertion is what
        # kills that variant.
        live.clear()
        live.add("status:in-progress")

        def malformed_entry_gh_json(args, *, input_doc=None):
            if input_doc is not None and "labels" in input_doc:
                return fake_gh_json(args, input_doc=input_doc)
            return {"labels": [None, {"name": "role:impl"}]}

        globals()["_gh_json"] = malformed_entry_gh_json
        landed = True
        try:
            set_status("o/r", 9, "complete")
        except WorkerIssueError as exc:
            landed = False
            assert "malformed label entry" in str(exc), exc
            assert "cannot be confirmed" in str(exc), exc
        except Exception as exc:        # a raw crash is malformedness, not a diagnosable refusal
            raise AssertionError(
                f"malformed label entry crashed instead of refusing: {exc!r}") from exc
        finally:
            globals()["_gh_json"] = fake_gh_json
        assert not landed, "status write confirmed against an unreadable label entry"
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

    _refusal_budget_self_test()
    _followup_label_self_test()
    print("worker-issue self-test PASSED")


_WF_STEP_RE = re.compile(r"^      - name: (?P<name>.*)$", re.M)


def _workflow_steps(text):
    """Every `      - name:` step of a workflow, as {name, gate, body}.

    A TEXT split, not a YAML parse, deliberately: this suite runs under bare python (PyYAML is
    provisioned only for the scripts that import it), and a lazily-imported parser would make the
    seam assertions below silently un-runnable in exactly the sandbox that is supposed to run
    them. The usual objection to regex-over-YAML — that it stays green through the mutation it
    was written to catch — is answered by EXECUTION, not by trust: worker_refusal_seam is run
    against MUTATED copies of the live workflow and asserted to go red on each one."""
    marks = list(_WF_STEP_RE.finditer(text))
    steps = []
    for index, mark in enumerate(marks):
        end = marks[index + 1].start() if index + 1 < len(marks) else len(text)
        body = text[mark.start():end]
        gate = re.search(r"^        if: (?P<gate>.*)$", body, re.M)
        steps.append({"name": mark.group("name").strip(),
                      "gate": gate.group("gate") if gate else "",
                      "body": body})
    return steps


# The exhausted -> status:parked arm of final_state, matched as an ARM and not as two loose
# substrings: `status=parked` also appears on the final-attempt-with-no-PR arm below it, so a
# plain `"status=parked" in text` stays green when the exhaustion arm alone is rewritten.
_PARK_ARM_RE = re.compile(r'"\$EXHAUSTED" == true \]\]; then(?:(?!\n\s*elif ).)*?\n\s*status=parked',
                          re.S)

# The `worker` job output the park arm above is the consumer of. Exactly one such binding must
# exist: two would mean the arm reads a value this seam is not following.
_WORKER_EXHAUSTED_OUTPUT_RE = re.compile(r"^      exhausted: \$\{\{(?P<expr>[^{}]*)\}\}$", re.M)
_STEP_OUTPUT_REF_RE = re.compile(r"steps\.(?P<step>[A-Za-z0-9_-]+)\.outputs\.(?P<name>[A-Za-z0-9_-]+)")
_FINAL_STATE_STEP = "Set final target issue state"
_ENV_BINDING_RE = re.compile(r"^          (?P<name>[A-Z_][A-Z0-9_]*): \$\{\{(?P<expr>[^{}]*)\}\}$",
                             re.M)
_RUN_BLOCK_RE = re.compile(r"^        run: \|\n(?P<body>(?:^ {10}.*\n)+)", re.M)
_GHA_INTERPOLATION_RE = re.compile(r"\$\{\{[^{}]*\}\}")


def _refusal_charge_step(text):
    """worker.yml's refusal-charging step and its `id:`.

    The id is READ from the file, never assumed: it is the name the worker job's `exhausted`
    output has to reference, so a rename that leaves that output pointing at nothing must break
    the seam rather than slide past it."""
    charge = [step for step in _workflow_steps(text)
              if "worker-issue.py record-refusal" in step["body"]]
    step = charge[0] if len(charge) == 1 else {"gate": "", "body": ""}
    ident = re.search(r"^        id: (?P<id>\S+)$", step["body"], re.M)
    return charge, step, (ident.group("id") if ident else "")


def _worker_exhausted_expr(text):
    """The expression bound to the `worker` job's `exhausted` output, as written."""
    found = _WORKER_EXHAUSTED_OUTPUT_RE.findall(text)
    if len(found) != 1:
        raise WorkerIssueError(
            f"expected exactly one `exhausted:` worker job output, found {len(found)}")
    return found[0].strip()


def _eval_step_output_expr(expr, step_outputs):
    """Evaluate a `A || B || ...` GitHub-Actions expression over step outputs.

    GitHub coerces a string operand to false ONLY when it is empty, and `||` yields the first
    truthy operand (the last one when every operand is falsy). An output that was never written —
    a skipped step, or one that died before writing — is the empty string, which is why the
    fallback works at all. An operand this cannot model RAISES instead of evaluating to empty: an
    expression the seam does not understand must fail it, never quietly satisfy it."""
    value = ""
    for operand in expr.split("||"):
        match = _STEP_OUTPUT_REF_RE.fullmatch(operand.strip())
        if match is None:
            raise WorkerIssueError(
                f"unmodelled operand in the `exhausted` output: {operand.strip()!r}")
        value = str(step_outputs.get(match.group("step"), {}).get(match.group("name"), ""))
        if value:
            return value
    return value


def _final_state_status(text, needs):
    """The status final_state converges to — derived by RUNNING worker.yml's own shell body.

    Deliberately not a Python re-implementation of that if/elif ladder: an expected value
    re-derived from a copy of the code under test cannot fail (AGENTS.md pre-flight 2b), and this
    seam is precisely where review round 1 of #1075 found a live gap — the worker exported the
    PRE-refusal exhaustion value, so the ladder's exhaustion arm was unreachable on the very run
    that ended the budget.

    `needs` maps a `needs.<job>.outputs.<name>` expression to its value; the step's OWN `env:`
    block supplies the wiring, so a rename or a re-point of a binding this test supplies is an
    error rather than a silent empty string. Bindings it does not supply (the App token) are
    empty, exactly as a skipped upstream job would leave them. `python3` is shadowed by a shell
    function (functions beat PATH lookup), so the status is captured from the ARGUMENTS of the
    real write call — not from a variable the body might no longer pass to it."""
    step = next((s for s in _workflow_steps(text) if s["name"] == _FINAL_STATE_STEP), None)
    if step is None:
        raise WorkerIssueError(f"worker.yml has no {_FINAL_STATE_STEP!r} step")
    bindings = {match.group("expr").strip(): match.group("name")
                for match in _ENV_BINDING_RE.finditer(step["body"])}
    unbound = sorted(set(needs) - set(bindings))
    if unbound:
        raise WorkerIssueError(f"{_FINAL_STATE_STEP!r} no longer binds {unbound}")
    run = _RUN_BLOCK_RE.search(step["body"])
    if run is None:
        raise WorkerIssueError(f"{_FINAL_STATE_STEP!r} has no runnable shell body")
    body = _GHA_INTERPOLATION_RE.sub(
        "gha-interpolated", re.sub(r"^ {10}", "", run.group("body"), flags=re.M))
    env = {name: str(needs.get(expr, "")) for expr, name in bindings.items()}
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    with tempfile.TemporaryDirectory() as tmp:
        capture = Path(tmp) / "status-write.txt"
        script = Path(tmp) / "final-state.sh"
        script.write_text('python3() { printf "%s\\n" "$*" > "$SEAM_CAPTURE"; }\n' + body,
                          encoding="utf-8")
        env["SEAM_CAPTURE"] = str(capture)
        result = subprocess.run(["bash", str(script)], env=env,
                                capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise WorkerIssueError(f"{_FINAL_STATE_STEP!r} body failed: {result.stderr.strip()}")
        if not capture.is_file():
            raise WorkerIssueError(f"{_FINAL_STATE_STEP!r} never called the status writer")
        written = capture.read_text(encoding="utf-8").split()
    if "--status" not in written:
        raise WorkerIssueError(f"the final-state write carries no --status: {written}")
    return written[written.index("--status") + 1]


def worker_refusal_seam(text):
    """[issue #1075] Findings about worker.yml's refusal-charging wiring. Pure over the workflow
    TEXT so the self-test can run it over the LIVE file AND over deliberately broken copies.

    The counter change is inert without this wiring — that is the whole shape of the defect it
    fixes (a documented invariant that nothing implemented) — so the seam is asserted, not
    assumed."""
    park = [step for step in _workflow_steps(text) if '"$EXHAUSTED" == true' in step["body"]]
    charge, step, charge_id = _refusal_charge_step(text)

    def exhausted_output(refusal, budget):
        """What the `worker` job exports for `exhausted`, per the workflow's own expression."""
        if not charge_id:
            return ""
        try:
            return _eval_step_output_expr(
                _worker_exhausted_expr(text), {charge_id: refusal, "budget": budget})
        except WorkerIssueError:
            return ""

    return {
        # The charging step exists, exactly once.
        "charges_refusal": len(charge) == 1,
        # `outcome` is the step's own result BEFORE continue-on-error rewrites `conclusion`; the
        # `== 'failure'` form is what distinguishes a REFUSAL from a step that never ran at all
        # (a `!= 'success'` gate also fires on `skipped` and charges a cycle nobody spent).
        "gated_on_trust_failure": "steps.trust.outcome == 'failure'" in step["gate"],
        # ...and only on a real, claimed, still-in-budget live dispatch.
        "gated_on_live_dispatch": all(
            fragment in step["gate"] for fragment in (
                "!inputs.dry_run",
                "needs.claim.outputs.acquired == 'true'",
                "steps.budget.outputs.exhausted != 'true'")),
        # Idempotency + the readmission window both key on the run identity and the policy bound.
        "binds_run_key": '--run-key "$GITHUB_RUN_ID.$GITHUB_RUN_ATTEMPT"' in step["body"],
        "binds_max_attempts": '--max-attempts "${{ needs.resolve.outputs.max_attempts }}"'
                              in step["body"],
        # A charge that fails silently restores the unbounded loop, so the step must be loud.
        "charge_is_loud": len(charge) == 1 and "continue-on-error" not in step["body"],
        # The consequence of an exhausted budget: the machine-owned `status:parked` hold.
        # It is the DURABLE half, not the whole bound — `parked` also re-applies
        # `status:deferred` (STATUS_TRANSITIONS) and dispatch.yml deliberately leaves parked rows
        # in the deferred-retry candidate set (that lane IS the park's readmission hook), so what
        # actually stops re-admission is dispatch-claim's budget arm reading the same
        # `budget_used` charge. This finding pins the worker-side half; the claim-side half is
        # pinned by dispatch-claim's own #1075 seam assertion.
        "parks_when_exhausted": len(park) == 1 and bool(_PARK_ARM_RE.search(park[0]["body"])),
        # [review round 1] ...and the arm above must be REACHABLE from a terminal refusal. The
        # `budget` step runs BEFORE `trust`, so exporting its result alone means the terminal
        # refusal exports exhausted=false: the run that ENDED the budget is also the one that
        # leaves the issue in the retry frontier. The refusal's POST-charge result wins.
        "exhaustion_follows_refusal": exhausted_output(
            {"exhausted": "true"}, {"exhausted": "false"}) == "true",
        # ...without discarding the budget result on the runs that never reach a refusal at all
        # (a skipped step writes no output), which is nearly every run.
        "exhaustion_keeps_budget": exhausted_output({}, {"exhausted": "true"}) == "true",
    }


def _refusal_budget_self_test():
    """[issue #1075] A pre-model trust refusal is CHARGED to the durable per-issue budget.

    The defect: worker.yml's `trust` step is continue-on-error and precedes `prepare`, so a
    refusal skipped `Record model attempt` and incremented nothing — `max_attempts` was checked
    against a counter the refusal path could not move, and the deferred-retry lane re-admitted the
    same issue forever (target #834: ~34 dispatches in one day, ~18% of the day's capacity).

    Asserted here, end to end: (1) a simulated refusal increments the durable counter; (2)
    `max_attempts` consecutive refusals exhaust the budget, so the model is refused a launch —
    the deferred-retry lane's own gate is dispatch-claim's budget arm, which charges the SAME
    `budget_used` quantity and is pinned by that module's #1075 seam assertion; (3) the refusal
    counter and the MODEL-attempt counter are distinct, not aliased — including the consent
    surface (a refusal must not move find_maintainer_approval's staleness anchor); (4) the wiring
    that makes (1) reachable from the workflow actually exists; (5) the TERMINAL refusal actually
    reaches final_state's exhaustion arm.

    (5) is review round 1's finding, and it is why (2) stops at "refused a launch": (2) proved
    the budget exhausts and then ASSUMED the worker told final_state so. It did not — the
    `exhausted` output was the `budget` step's result, and that step runs BEFORE `trust`, so the
    run that spent the last cycle exported exhausted=false and the ladder converged it to
    `deferred`. Nothing on the path between the two was executed, so nothing went red. (5) now
    executes all of it: the recorder's REAL outputs, joined by worker.yml's OWN `exhausted`
    expression, fed into worker.yml's OWN final_state shell body.

    MUTATION-CHECKED (the acceptance criterion): deleting the refusal charge from budget_used
    turns (1) and (2) red, aliasing the two markers turns (3) red, dropping `exhausted` from the
    recorder or re-pointing the worker output back at `budget` turns (5) red, and each workflow
    mutation below turns its own seam finding red — every one of those is executed here, not
    asserted about."""
    bot = "sparq[bot]"
    # --- (3) DISTINCT COUNTERS, not one counter with two names ---------------------------------
    # Substring containment either way would make one marker silently count the other's receipts.
    assert ATTEMPT_MARKER not in REFUSAL_MARKER and REFUSAL_MARKER not in ATTEMPT_MARKER
    mixed = [
        {"user": {"login": bot}, "created_at": "2026-07-20T00:00:00Z",
         "body": f"x {ATTEMPT_MARKER} run=1.1 -->"},
        {"user": {"login": "SPARQ[bot]"}, "created_at": "2026-07-21T00:00:00Z",
         "body": f"x {REFUSAL_MARKER} run=2.1 -->"},
        {"user": {"login": bot}, "created_at": "2026-07-22T00:00:00Z",
         "body": f"x {REFUSAL_MARKER} run=3.1 -->"},
        # A third party can neither burn the budget nor mint one: not bot-authored, never charged.
        {"user": {"login": "someone"}, "created_at": "2026-07-22T00:00:00Z",
         "body": f"x {REFUSAL_MARKER} run=4.1 -->"},
    ]
    assert count_attempts(mixed, bot) == 1      # cost/health: only runs where a model ran
    assert count_refusals(mixed, bot) == 2      # case-insensitive bot match, third party excluded
    assert budget_used(mixed, bot) == 3         # the dispatch bound sees every spent cycle
    # The readmission window covers BOTH halves — without it a budget spent on refusals could
    # never be re-opened by the human unpark gesture, i.e. the park would be terminal.
    assert count_refusals_since(mixed, bot, "2026-07-22T00:00:00Z") == 1   # tie is charged
    assert budget_used(mixed, bot, "2026-07-21T12:00:00Z") == 1
    assert budget_used(mixed, bot, "2026-07-19T00:00:00Z") == 3
    # A voided attempt (registry #596) stays uncharged through the sum, and no void marker can
    # un-charge a refusal (the run keys live in different marker namespaces).
    voided = mixed + [{"user": {"login": bot}, "created_at": "2026-07-22T01:00:00Z",
                       "body": f"x {ATTEMPT_VOID_MARKER} run=1.1 -->"},
                      {"user": {"login": bot}, "created_at": "2026-07-22T02:00:00Z",
                       "body": f"x {ATTEMPT_VOID_MARKER} run=3.1 -->"}]
    assert count_attempts(voided, bot) == 0
    assert count_refusals(voided, bot) == 2 and budget_used(voided, bot) == 2

    # The CONSENT surface must not move: a maintainer's `approved`, posted after the last model
    # attempt, still approves once a later refusal lands. Aliasing the markers is what breaks it —
    # executed below, so this assertion is not merely restating the implementation.
    approval_history = [
        {"user": {"login": bot}, "created_at": "2026-07-20T00:00:00Z",
         "body": f"x {ATTEMPT_MARKER} run=1.1 -->"},
        {"user": {"login": "jeswr", "type": "User"}, "created_at": "2026-07-21T00:00:00Z",
         "body": "approved"},
        {"user": {"login": bot}, "created_at": "2026-07-22T00:00:00Z",
         "body": f"x {REFUSAL_MARKER} run=2.1 -->"},
    ]
    assert find_maintainer_approval(approval_history, bot, lambda login: login == "jeswr")
    aliased = [dict(comment, body=comment["body"].replace(REFUSAL_MARKER, ATTEMPT_MARKER))
               for comment in approval_history]
    assert find_maintainer_approval(aliased, bot, lambda login: login == "jeswr") is None

    # --- (1) + (2) THE INCREMENT AND THE BOUND, through the real entry points ------------------
    posts = []
    state = {"comments": [], "timeline": []}

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run_gh(args, *, input_text=None, check=True):
        result = _Result()
        if "/collaborators/" in str(args[1]):
            result.stdout = "admin" if "/collaborators/jeswr/" in args[1] else "none"
        return result

    def fake_gh_json(args, *, input_doc=None):
        body = (input_doc or {}).get("body")
        if body is not None:
            posts.append(body)
            # Receipts land in chronological order; the timestamps matter to the window below.
            state["comments"].append({"user": {"login": bot},
                                      "created_at": f"2026-07-2{len(posts)}T00:00:00Z",
                                      "body": body})
        return {}

    def fake_paginated(repo, issue, resource):
        return list(state[resource if resource in state else "comments"])

    seams = {"_run_gh": fake_run_gh, "_gh_json": fake_gh_json, "_paginated": fake_paginated}
    saved = {name: globals()[name] for name in seams}
    saved_output = os.environ.get("GITHUB_OUTPUT")
    globals().update(seams)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            def outputs(call):
                output_file = Path(tmp) / "outputs.txt"
                output_file.write_text("", encoding="utf-8")
                os.environ["GITHUB_OUTPUT"] = str(output_file)
                call()
                return dict(line.split("=", 1) for line in
                            output_file.read_text(encoding="utf-8").splitlines())

            # A fresh issue is admitted: nothing has been spent yet.
            assert outputs(lambda: attempt_check("o/r", 834, 2, bot)) == {
                "used": "0", "exhausted": "false"}
            # (1) ONE refusal charges exactly ONE cycle — the increment the refusal path lacked.
            # The recorder publishes the POST-charge budget state (review round 1): the `budget`
            # step ran before `trust`, so it is the ONLY step on this path that can tell the
            # worker job whether the cycle it just charged was the last one.
            charged = outputs(lambda: record_refusal("o/r", 834, 2, bot, "77.1", "https://run/77"))
            assert charged == {"used": "1", "exhausted": "false"}, charged
            assert len(posts) == 1 and f"{REFUSAL_MARKER} run=77.1 -->" in posts[0]
            assert ATTEMPT_MARKER not in posts[0]   # never masquerades as model spend
            assert outputs(lambda: attempt_check("o/r", 834, 2, bot)) == {
                "used": "1", "exhausted": "false"}
            # Idempotent per run key: a re-entered step re-uses its receipt, never double-charges
            # — and republishes the same post-charge state, so a retried step cannot un-exhaust.
            replayed = outputs(lambda: record_refusal("o/r", 834, 2, bot, "77.1", "https://run/77"))
            assert replayed == charged, (replayed, charged)
            assert len(posts) == 1
            # This is the budget the LAST admitted run's `budget` step sees: N-1, not exhausted.
            pre_charge = outputs(lambda: attempt_check("o/r", 834, 2, bot))
            assert pre_charge == {"used": "1", "exhausted": "false"}, pre_charge
            # (2) THE BOUND: max_attempts consecutive pre-model refusals exhaust the budget...
            terminal = outputs(lambda: record_refusal("o/r", 834, 2, bot, "78.1", "https://run/78"))
            assert terminal == {"used": "2", "exhausted": "true"}, terminal
            assert len(posts) == 2
            assert outputs(lambda: attempt_check("o/r", 834, 2, bot)) == {
                "used": "2", "exhausted": "true"}
            # ...so the next dispatch is refused a model launch (worker.yml gates `prepare` and
            # `model` on this; dispatch-claim's budget arm reads the same charge and stops
            # re-admitting the row before a runner is ever allocated). The park THIS run converges
            # to is (5) below — executed, not assumed.
            try:
                record_attempt("o/r", 834, 2, bot, "79.1")
                raise AssertionError("a budget spent on refusals still launched the model")
            except WorkerIssueError as exc:
                assert "exhausted before model launch" in str(exc), exc
            assert len(posts) == 2   # and no attempt receipt was posted
            # (3) again, on the LIVE receipts this run produced: not one model attempt among them.
            assert count_attempts(state["comments"], bot) == 0
            assert count_refusals(state["comments"], bot) == 2
            # The exhaustion is UNDOABLE by the same human gesture that re-opens an attempt
            # budget: a proven-human unlabel after both refusals re-admits the issue.
            state["timeline"] = [
                {"event": "labeled", "label": {"name": "status:parked"},
                 "created_at": "2026-07-23T00:00:00Z",
                 "actor": {"login": "sparq-orchestrator[bot]"}},
                {"event": "unlabeled", "label": {"name": "status:parked"},
                 "created_at": "2026-07-24T00:00:00Z", "actor": {"login": "jeswr"}},
            ]
            assert outputs(lambda: attempt_check("o/r", 834, 2, bot)) == {
                "used": "0", "exhausted": "false"}
            # A BOT unlabel proves nothing and opens no window (fail toward exhaustion).
            state["timeline"][1] = {**state["timeline"][1],
                                    "actor": {"login": "sparq-orchestrator[bot]"}}
            assert outputs(lambda: attempt_check("o/r", 834, 2, bot)) == {
                "used": "2", "exhausted": "true"}
    finally:
        globals().update(saved)
        if saved_output is None:
            os.environ.pop("GITHUB_OUTPUT", None)
        else:
            os.environ["GITHUB_OUTPUT"] = saved_output

    # --- (4) THE WORKFLOW SEAM, proven non-vacuous against mutated copies ----------------------
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "worker.yml"
    assert workflow.is_file(), f"worker.yml not found for the seam check: {workflow}"
    text = workflow.read_text(encoding="utf-8")
    live = worker_refusal_seam(text)
    assert all(live.values()), f"worker.yml refusal wiring is incomplete: {live}"

    # --- (5) TERMINAL REFUSAL -> PARK, end to end through the workflow's own expressions --------
    # Review round 1 of #1075: (2) above proved the BUDGET exhausts, and then ASSUMED the worker
    # told final_state about it. It did not — `exhausted` was the `budget` step's result, read
    # before `trust` ran, so the run that spent the last cycle still exported exhausted=false and
    # final_state fell through to `deferred`. Nothing between the two was executed, so nothing
    # went red. This closes that gap by EXECUTION: `terminal`/`pre_charge` are the real outputs
    # the recorder wrote above, the join is worker.yml's own `exhausted` expression, and the
    # ladder is worker.yml's own shell body — no re-implementation anywhere on the path.
    _, _, charge_id = _refusal_charge_step(text)
    assert charge_id, "the refusal-charging step has no `id:` for the worker output to reference"
    exported = _eval_step_output_expr(_worker_exhausted_expr(text),
                                      {charge_id: terminal, "budget": pre_charge})

    def converged(exhausted, source=None):
        """final_state's status for THIS run: claimed, refused pre-model, no attempt, no PR."""
        return _final_state_status(text if source is None else source, {
            "needs.claim.outputs.acquired": "true",
            "needs.worker.outputs.exhausted": exhausted,
            "needs.worker.outputs.trust_outcome": "failure",
            "needs.worker.outputs.attempt_number": "",
            "needs.worker.outputs.attempt_voided": "",
            "needs.resolve.outputs.max_attempts": "2",
            "needs.publish.outputs.pr_url": "",
        })

    assert exported == "true", (exported, terminal, pre_charge)
    assert converged(exported) == "parked", converged(exported)
    # ...and the PRE-charge value the worker used to export is what converged the SAME run to
    # `deferred`. One input differs; the defect is the difference, executed rather than described.
    assert pre_charge["exhausted"] == "false", pre_charge
    assert converged(pre_charge["exhausted"]) == "deferred", converged(pre_charge["exhausted"])

    # The (5) harness must FAIL CLOSED on a workflow it can no longer model, or a rename quietly
    # degrades it into a check that evaluates to "" and passes anyway. Every guard below is a line
    # the assertions above never execute, so each one is proved REACHABLE here rather than assumed.
    def refuses(call, fragment):
        try:
            call()
        except WorkerIssueError as exc:
            assert fragment in str(exc), (fragment, exc)
            return
        raise AssertionError(f"the seam harness accepted a workflow it cannot model: {fragment}")

    refuses(lambda: _worker_exhausted_expr(_WORKER_EXHAUSTED_OUTPUT_RE.sub("", text, count=1)),
            "expected exactly one")
    refuses(lambda: _eval_step_output_expr("github.event_name", {}), "unmodelled operand")
    refuses(lambda: converged("true", text.replace(_FINAL_STATE_STEP, "Renamed step", 1)),
            "has no")
    # The arm stops reading the worker's exhaustion output at all: caught by the binding check...
    refuses(lambda: converged("true", text.replace("needs.worker.outputs.exhausted",
                                                   "needs.worker.outputs.exhausted_x", 1)),
            "no longer binds")
    # ...and the env var alone renamed is caught by the body's own `set -u`, which is why this
    # harness runs the shell instead of paraphrasing it.
    refuses(lambda: converged("true", text.replace("          EXHAUSTED: ",
                                                   "          EXHAUSTION: ", 1)),
            "EXHAUSTED: unbound variable")
    # The writer call dropped. Mutated INSIDE the step's own body: that command line occurs twice
    # in worker.yml, and a whole-file replace silently hits the other one (AGENTS.md mutation
    # hygiene — mutate by line and verify the tree actually changed).
    final_step = next(s for s in _workflow_steps(text) if s["name"] == _FINAL_STATE_STEP)
    writer_line = "          python3 registry/scripts/worker-issue.py status \\\n"
    no_writer = text.replace(
        final_step["body"], final_step["body"].replace(writer_line, "            true \\\n", 1))
    assert no_writer != text, "the missing-writer mutation no longer applies to worker.yml"
    refuses(lambda: converged("true", no_writer), "never called the status writer")
    # ...and a binding re-pointed at something that is not a step output at all must make the seam
    # finding FALSE, never accidentally satisfy it.
    unmodelled = _WORKER_EXHAUSTED_OUTPUT_RE.sub(
        "      exhausted: ${{ github.event_name }}", text, count=1)
    assert unmodelled != text
    assert worker_refusal_seam(unmodelled)["exhaustion_follows_refusal"] is False

    charge_step = next(step for step in _workflow_steps(text)
                       if "worker-issue.py record-refusal" in step["body"])
    mutants = {
        # The whole charging step deleted — the pre-fix workflow, exactly.
        "charges_refusal": text.replace(charge_step["body"], ""),
        # The gate widened to fire on `skipped` too (budget already exhausted / no claim), which
        # would charge cycles that were never spent.
        "gated_on_trust_failure": text.replace("steps.trust.outcome == 'failure'",
                                               "steps.trust.outcome != 'success'"),
        # The dry-run/claim/budget guards dropped from that same gate.
        "gated_on_live_dispatch": text.replace(
            "&& steps.budget.outputs.exhausted != 'true' && steps.trust.outcome == 'failure' }}",
            "&& steps.trust.outcome == 'failure' }}"),
        # The run key dropped: idempotency gone, so a re-entered step double-charges.
        "binds_run_key": text.replace(
            charge_step["body"],
            charge_step["body"].replace(
                '            --run-key "$GITHUB_RUN_ID.$GITHUB_RUN_ATTEMPT" \\\n', "")),
        # The policy bound replaced by a hard-coded one.
        "binds_max_attempts": text.replace(
            charge_step["body"],
            charge_step["body"].replace('"${{ needs.resolve.outputs.max_attempts }}"', '"3"')),
        # The charge made soft: a failed charge silently restores the unbounded loop.
        "charge_is_loud": text.replace("        id: refusal\n",
                                       "        id: refusal\n        continue-on-error: true\n"),
        # The consequence removed: an exhausted budget that converges to `deferred` leaves the
        # issue in the very label the deferred-retry lane re-admits on.
        "parks_when_exhausted": _PARK_ARM_RE.sub(
            lambda match: match.group(0)[:-len("parked")] + "deferred", text, count=1),
        # The binding reverted to the PRE-refusal value — the exact defect review round 1 found.
        "exhaustion_follows_refusal": text.replace(
            "exhausted: ${{ steps.refusal.outputs.exhausted "
            "|| steps.budget.outputs.exhausted }}",
            "exhausted: ${{ steps.budget.outputs.exhausted }}"),
        # ...and the opposite over-correction: the budget fallback dropped, so every run that
        # never reached a refusal (the overwhelming majority) exports an empty exhaustion value
        # and a genuinely exhausted budget stops parking at all.
        "exhaustion_keeps_budget": text.replace(
            "exhausted: ${{ steps.refusal.outputs.exhausted "
            "|| steps.budget.outputs.exhausted }}",
            "exhausted: ${{ steps.refusal.outputs.exhausted }}"),
    }
    for finding, mutated in mutants.items():
        assert mutated != text, f"the {finding} mutation no longer applies to worker.yml"
        broken = worker_refusal_seam(mutated)
        assert broken[finding] is False, f"the {finding} seam check survived its own mutation"
    # The two workflow mutants that break the terminal-refusal -> park path must ALSO be caught by
    # the executed (5) join, not only by the structural findings above: run each through the same
    # expression + shell body and require the convergence to stop being `parked`.
    for finding in ("exhaustion_follows_refusal", "parks_when_exhausted"):
        mutated = mutants[finding]
        stale = _eval_step_output_expr(_worker_exhausted_expr(mutated),
                                       {charge_id: terminal, "budget": pre_charge})
        status = _final_state_status(mutated, {
            "needs.claim.outputs.acquired": "true",
            "needs.worker.outputs.exhausted": stale,
            "needs.worker.outputs.trust_outcome": "failure",
            "needs.worker.outputs.attempt_number": "",
            "needs.worker.outputs.attempt_voided": "",
            "needs.resolve.outputs.max_attempts": "2",
            "needs.publish.outputs.pr_url": "",
        })
        assert status != "parked", f"the {finding} mutation still parked the terminal refusal"


def _followup_label_self_test():
    """`followup_label_plan` + the structural claim that `create_followups` CONSULTS it.

    The behavioural half alone is vacuous against the regression it exists to prevent: the old
    label-free retry would keep every one of these assertions green while still discarding the
    model's `area:` at the call site, because the discard lived in `create_followups`, not in any
    function a unit test called. So the AST half below is the load-bearing one.
    """
    known = {"area:dispatch", "from:agent", "self-improvement", "role:impl"}

    # (i) THE REGRESSION. A typo'd label must not take the valid `area:` down with it.
    keep, dropped, missing = followup_label_plan(
        ["area:dispatch", "from:agent", "aera:worker"], known)
    assert keep == ["area:dispatch", "from:agent"], keep
    assert dropped == ["aera:worker"], dropped
    assert missing is False

    # (ii) an UNREADABLE vocabulary drops NOTHING (a failed read is not evidence of invalidity).
    keep, dropped, _ = followup_label_plan(["area:dispatch", "aera:worker"], None)
    assert keep == ["aera:worker", "area:dispatch"], keep
    assert dropped == [], dropped

    # (iii) the area-missing signal, both directions.
    assert followup_label_plan(["from:agent"], known)[2] is True
    assert followup_label_plan(["area:dispatch"], known)[2] is False
    # An area declaration is a PREFIX, not a substring. `needs:area` does not discriminate (it
    # has no trailing colon, so a substring test agrees by accident); a label that embeds the
    # prefix does, and pins the intended contract.
    assert followup_label_plan(["needs:area"], known)[2] is True
    assert followup_label_plan(["sub-area:dispatch"], known)[2] is True

    # (iv) malformed entries are ignored, never crash the best-effort path.
    assert followup_label_plan([None, "", 7, "area:dispatch"], known)[0] == ["area:dispatch"]

    # (v) STRUCTURAL: `create_followups` must call `followup_label_plan`, on a live branch, and
    # must retain NO `issue create` retry that passes a bare arg list with no labels appended.
    import ast
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    func = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "create_followups")

    def live(node):
        """Nodes of `node` excluding statically-dead `if False:` / `while False:` bodies."""
        out = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.If, ast.While)):
                dead = (isinstance(child.test, ast.Constant) and not child.test.value)
                if dead:
                    out.extend(live(ast.Module(body=child.orelse, type_ignores=[])))
                    continue
            out.append(child)
            out.extend(live(child))
        return out

    nodes = live(func)
    # NOT "is the name called somewhere" — `create_followups` calls it twice (once for the
    # area-missing signal), so a mere name check stays green while the RETRY stops using it.
    # Measured: that weaker assertion let both the deleted-call and the dead-branch mutant
    # survive. Bind the check to the names the retry actually consumes.
    planned = set()
    for node in nodes:
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "followup_label_plan"):
            for target in node.targets:
                if isinstance(target, ast.Tuple):
                    planned |= {e.id for e in target.elts if isinstance(e, ast.Name)}
    assert {"keep", "dropped"} <= planned, (
        "the retry's kept/dropped labels are no longer bound by a LIVE followup_label_plan call "
        "in create_followups — the retry can discard the model's area: label again")

    # DELETED, deliberately: an assertion that scanned for a `_run_gh` call whose FIRST ARGUMENT
    # is a literal `["issue", "create", ...]`. On this tree the loop body executed ZERO times —
    # both live calls are handed a Name (`args`, `retry`), so the assertion inside it had never
    # once been evaluated and could not have failed for any edit. A check that has never visited a
    # node is not a check, and keeping it inflated the apparent coverage of this function. What it
    # was trying to pin — "the retry does not go label-free" — is now asserted on the argv that
    # actually reaches `gh`, in `_followup_create_behaviour_self_test` below, which is strictly
    # stronger: it fails on a label-free retry however that retry is spelled.
    _followup_create_behaviour_self_test()


def _followup_create_behaviour_self_test():
    """EXECUTE `create_followups` and assert on what reaches the outside world.

    Everything above this is a structural (AST) claim, and structure is not behaviour. MEASURED:
    two mutants that reproduce the ORIGINAL defect exactly — replacing the retry's label loop with
    `for label in []`, and deleting that loop outright — survive every assertion above, because
    `keep`/`dropped` are still bound by a live `followup_label_plan` tuple-assign and `_run_gh` is
    still handed a Name. Both send a label-free retry to `gh`. They die here, on the argv.

    The `gh` stub reproduces the behaviour that caused the defect: `gh issue create` fails the
    WHOLE create when any one `--label` is not declared on the target.
    """
    import contextlib
    import io

    spec_rows = [
        {"title": "T1 typo", "body": "b1", "labels": ["area:dispatch", "aera:worker"]},
        {"title": "T2 valid", "body": "b2", "labels": ["area:worker", "role:impl"]},
        {"title": "T3 valid", "body": "b3", "labels": ["area:review"]},
    ]
    vocab = {"area:dispatch", "area:worker", "area:review", "role:impl",
             "from:agent", "self-improvement"}
    auto = {"from:agent", "self-improvement"}

    class _Result:
        def __init__(self, returncode):
            self.returncode, self.stdout, self.stderr = returncode, "", ""

    def _labels_of(argv):
        return {argv[i + 1] for i, item in enumerate(argv) if item == "--label"}

    def _title_of(argv):
        return argv[argv.index("--title") + 1]

    def drive(rows=None, *, vocabulary_readable=True, create_raises_on=None,
              issue_list_raises=False):
        """Returns `(creates, landed, log, raised)`.

        `raised` is the exception that ESCAPED `create_followups`, or None. It is returned rather
        than propagated so every scenario can assert on it BY NAME: a mutant that re-breaks the
        batch guarantee otherwise kills the suite by crashing it, and a crash names no property —
        it reads identically whether the guarantee broke or the stub did.
        """
        argvs = []

        def fake_run_gh(args, *, input_text=None, check=True):
            argvs.append(list(args))
            if args[:2] != ["issue", "create"]:
                return _Result(0)
            if create_raises_on is not None and _title_of(args) == create_raises_on:
                raise WorkerIssueError("simulated transport failure on create")
            # THE REAL `gh` SEMANTICS: one undeclared label fails the entire create.
            return _Result(1 if _labels_of(args) - vocab else 0)

        def fake_gh_json(args, *, input_doc=None):
            if args[:2] == ["issue", "list"]:
                if issue_list_raises:
                    raise WorkerIssueError("GitHub API request failed for issue")
                return []
            if args[:2] == ["label", "list"]:
                if not vocabulary_readable:
                    # EXACTLY how the live read fails: `_gh_json` -> `_run_gh(check=True)` raises.
                    raise WorkerIssueError("GitHub API request failed for label")
                return [{"name": name} for name in sorted(vocab)]
            raise AssertionError(f"unexpected _gh_json call: {args}")

        saved = {"_run_gh": globals()["_run_gh"], "_gh_json": globals()["_gh_json"]}
        globals().update({"_run_gh": fake_run_gh, "_gh_json": fake_gh_json})
        log, raised = io.StringIO(), None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                spec_file = Path(tmp) / "followups.jsonl"
                spec_file.write_text(
                    "\n".join(json.dumps(row) for row in (spec_rows if rows is None else rows)),
                    encoding="utf-8")
                with contextlib.redirect_stdout(log):
                    try:
                        create_followups("o/r", 42, str(spec_file))
                    except (WorkerIssueError, OSError) as exc:
                        raised = exc
        finally:
            globals().update(saved)
        creates = [argv for argv in argvs if argv[:2] == ["issue", "create"]]
        # What the stub ACCEPTED is what exists on the target afterwards.
        landed = {_title_of(argv): _labels_of(argv)
                  for argv in creates if not _labels_of(argv) - vocab}
        return creates, landed, log.getvalue(), raised

    # (A) SUCCESS PATH — the vocabulary is readable. All three follow-ups are created, and the one
    # carrying a typo keeps its `area:` instead of being minted bare.
    creates, landed, log, raised = drive()
    assert raised is None, ("BATCH_COMPLETE_READABLE: create_followups raised", repr(raised))
    t1 = [argv for argv in creates if _title_of(argv) == "T1 typo"]
    assert len(t1) == 2, ("expected exactly one retry for the typo'd follow-up", t1)
    assert "area:dispatch" in _labels_of(t1[1]), (
        "RETRY_KEEPS_AREA: the retry argv carries no `area:dispatch` — the unknown-label recovery "
        "discarded the model's area label again, which no later lane can repair")
    assert "aera:worker" not in _labels_of(t1[1]), (
        "RETRY_DROPS_UNDECLARED: the retry re-sent the undeclared label that failed the create")
    assert set(landed) == {"T1 typo", "T2 valid", "T3 valid"}, (
        "BATCH_COMPLETE_READABLE: not every follow-up was created", sorted(landed))
    assert landed["T1 typo"] == {"area:dispatch"} | auto, landed["T1 typo"]
    assert landed["T2 valid"] == {"area:worker", "role:impl"} | auto, landed["T2 valid"]
    assert landed["T3 valid"] == {"area:review"} | auto, landed["T3 valid"]
    assert "follow-up issues created: 3" in log, log

    # (B) FIRST-FAILURE PATH — `gh label list` RAISES, which is what a rate limit or 502 on the
    # already-failing create looks like (the read happens seconds later, against the same API).
    # This is the regression under review: the raise escaped `create_followups` and destroyed the
    # two follow-ups whose labels were entirely valid, while both call sites `|| true` the exit.
    creates, landed, log, raised = drive(vocabulary_readable=False)
    assert raised is None, (
        "BATCH_COMPLETE_UNREADABLE: the unreadable-vocabulary read escaped create_followups — "
        "this is the exact regression under review", repr(raised))
    assert set(landed) == {"T1 typo", "T2 valid", "T3 valid"}, (
        "BATCH_COMPLETE_UNREADABLE: one follow-up's failure removed the others from the batch — "
        "the population-shrink shape this function exists to prevent", sorted(landed))
    assert landed["T2 valid"] == {"area:worker", "role:impl"} | auto, landed["T2 valid"]
    assert landed["T3 valid"] == {"area:review"} | auto, landed["T3 valid"]
    t1 = [argv for argv in creates if _title_of(argv) == "T1 typo"]
    assert len(t1) == 3, ("declared retry, then the bare last rung", t1)
    assert _labels_of(t1[1]) == {"area:dispatch", "aera:worker"} | auto, (
        "UNREADABLE_DROPS_NOTHING: an unreadable vocabulary is not evidence that a label is "
        "invalid, so the retry must re-send the declared set unchanged", _labels_of(t1[1]))
    assert landed["T1 typo"] == set(), landed["T1 typo"]
    assert "creating it WITHOUT labels" in log, log
    assert "sparq-intended-labels: aera:worker,area:dispatch,from:agent,self-improvement" in (
        t1[2][t1[2].index("--body") + 1]), (
        "BARE_RUNG_RECORDS_INTENDED_LABELS: the last rung minted an unattributable issue without "
        "recording what it should have carried, so the attribution is unrecoverable", t1[2])
    # The provenance marker must stay UNAMBIGUOUS: exactly one `sparq-followup` comment in the body.
    assert t1[2][t1[2].index("--body") + 1].count("sparq-followup") == 1, t1[2]

    # (C) ISOLATION, on a raise that is NOT the one just fixed: any per-entry failure is contained.
    # `_known_labels` no longer raises, so without the per-entry guard this property would rest on
    # a single `except` in a single helper — one more raising call added to this loop later and the
    # batch shrinks again, silently, exactly as it did here.
    creates, landed, log, raised = drive(create_raises_on="T1 typo")
    assert raised is None, (
        "BATCH_ISOLATION: a failure creating ONE follow-up escaped create_followups and aborted "
        "the whole batch", repr(raised))
    assert set(landed) == {"T2 valid", "T3 valid"}, (
        "BATCH_ISOLATION: a raise while creating ONE follow-up prevented the others from being "
        "created", sorted(landed))
    assert "abandoned" in log, log

    # (D) THE AREA WARNING MUST READ WHAT LANDED, NOT WHAT WAS DECLARED. A model that typo'd the
    # area itself (`area:dsipatch`) declares a label starting `area:`, so a declared-set test says
    # "area present" and stays silent — on the ONE path where the created issue really is born
    # unattributable, because the retry drops that very label.
    creates, landed, log, _ = drive(
        [{"title": "T4 typo'd area", "body": "b4", "labels": ["area:dsipatch"]}])
    assert landed["T4 typo'd area"] == auto, landed["T4 typo'd area"]
    assert "carries no `area:` label" in log, (
        "AREA_WARNING_READS_APPLIED: the follow-up landed with no `area:` and said nothing", log)
    # ...and it stays quiet when an area really did land, so the signal is not a constant.
    _, landed, log, _ = drive([{"title": "T5 ok", "body": "b5", "labels": ["area:review"]}])
    assert landed["T5 ok"] == {"area:review"} | auto, landed["T5 ok"]
    assert "carries no `area:` label" not in log, log

    # (E) THE ONE FAILURE THAT IS *NOT* CONTAINED, pinned so the docstring cannot drift from the
    # code. Without the existing-title set there is no de-duplication, and re-minting issues the
    # model already filed is worse than deferring the batch — so this one aborts. Both call sites
    # `|| true` the exit code, which makes the ANNOTATION the only surviving evidence that a batch
    # of discovered work was dropped; assert the annotation, not just the abort.
    creates, landed, log, raised = drive(issue_list_raises=True)
    assert isinstance(raised, WorkerIssueError), (
        "DEDUP_UNREADABLE_ABORTS: an unreadable open-issue list must abort the batch rather than "
        "create follow-ups it cannot de-duplicate", repr(raised))
    assert creates == [], ("DEDUP_UNREADABLE_ABORTS: created issues without de-duplication",
                           creates)
    assert "::error::follow-up capture skipped" in log, (
        "DEDUP_ABORT_IS_ANNOTATED: the batch was dropped silently — `|| true` at worker.yml and "
        "review-fix.yml swallows the exit code, so a bare raise leaves NO signal at all", log)



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

    # [issue #1075] Charge a PRE-MODEL trust refusal to the same durable per-issue budget. Invoked
    # from worker.yml the instant the continue-on-error `trust` step fails, i.e. the one path that
    # spends a whole dispatch cycle without ever reaching `record-attempt`.
    refusal = subparsers.add_parser("record-refusal", parents=[common])
    refusal.add_argument("--max-attempts", required=True, type=int)
    refusal.add_argument("--bot-login", required=True)
    refusal.add_argument("--run-key", required=True)
    refusal.add_argument("--run-url", required=True)

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
        elif args.command == "record-refusal":
            record_refusal(args.repo, args.issue, args.max_attempts, args.bot_login,
                           args.run_key, args.run_url)
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
