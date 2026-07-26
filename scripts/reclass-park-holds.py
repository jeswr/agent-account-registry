#!/usr/bin/env python3
# One-shot, OPERATOR-INVOKED migration that reclassifies a HUMAN-owned park hold
# (review:needs-user / needs:user) which the now-fixed MISSED_FIX_LIMIT capacity-park defect
# (registry #610) MANUFACTURED, into the MACHINE-owned park class (review:parked /
# status:parked) so the automatic cause-recovery re-admission (registry #620) can clear it
# normally.
#
# WHY THIS EXISTS. `review:needs-user` / `needs:user` are HUMAN-owned terminal holds: they mean
# "a human must decide this" (park_policy.py invariant 1). Before #610 the MISSED_FIX_LIMIT
# capacity stop in dispatch-claim.py read a RAW LIFETIME `missed`-marker count that nothing
# reset, so it could fire with NO head advance and NO review round — growing purely from
# allocator starvation — and stamp a terminal HUMAN-owned label on what was really a machine
# capacity stop. #610 stops new ones. #620 auto-re-admits MACHINE parks on proven
# cause-recovery but deliberately never touches a human-owned hold
# (capacity_park_admission's live_holds gate), so it cannot reach the ones already stamped.
#
# WHY IT IS A TESTED, EVIDENCE-GATED TOOL AND NOT AN AGENT'S JUDGEMENT CALL. Inferring "this
# label was a machine artefact" from the prose of a bot comment bypasses the exact human-review
# backstop the park policy exists to provide. So the reclassification is gated on DURABLE,
# BOT-AUTHORED RECEIPTS plus the SAME proven-human predicate every park writer already uses
# (park_policy._is_proven_human, reused — never re-implemented), and EVERY ambiguity fails
# toward LEAVING THE HUMAN LABEL ALONE.
#
# THE THREE HARD SAFETY PROPERTIES (each has its own non-vacuous self-test below):
#   1. DRY RUN IS THE DEFAULT. Without --apply the tool performs ZERO writes — not "writes that
#      happen to be no-ops": the single mutation seam (LabelWriter) refuses to call GitHub at
#      all and its `performed` list is empty by construction.
#   2. A HOLD A HUMAN TOUCHED IS NEVER CLEARED. Any PROVEN-HUMAN event on ANY park-ownership
#      label (needs:user / review:needs-user / status:parked / review:parked) on EITHER surface
#      — apply OR remove — and any proven-human comment/review/arm gesture on either surface,
#      SKIPS the PR permanently. Not "the most recent event wins" (that is the sticky-veto rule
#      for APPLYING a park); here ANY human touch at all is disqualifying, because this path
#      WEAKENS a human-owned label rather than declining to strengthen one.
#   3. IT ONLY EVER NARROWS. The only writes it can plan are: ADD the machine twin
#      (review:parked / status:parked) and REMOVE the human hold it replaces. It can never
#      apply a new hold, never remove a machine park, never arm, never mark ready, never merge,
#      never comment. plan_writes() is total over the decision and the self-test asserts the
#      write vocabulary structurally.
#
# WIRED INTO NO AUTOMATION. There is deliberately no workflow, no cron, and no caller: the
# scope of a human-hold weakening must be reviewed by a human before it is applied. Run it,
# read the table, then decide.
"""reclass-park-holds — evidence-gated, dry-run-by-default reclassification of human-hold park
labels that the fixed capacity-park defect manufactured.

Usage (dry run — reports only, writes nothing):
    python3 scripts/reclass-park-holds.py --target-repo sparq-org/sparq

Usage (apply, after a human has reviewed the dry-run table):
    python3 scripts/reclass-park-holds.py --target-repo sparq-org/sparq --apply
"""

import argparse
import collections
import importlib.util
import json
from pathlib import Path
import re
import sys


# The HUMAN-owned holds this migration may reclassify, mapped to the MACHINE-owned twin that
# replaces each (park_policy.py ownership split). Read from park_policy at runtime rather than
# re-spelt here — see _label_map().
HOLD_TO_MACHINE_NAMES = (("HUMAN_PR_PARK_LABEL", "MACHINE_PARK_PR_LABEL"),
                         ("HUMAN_PARK_LABEL", "MACHINE_PARK_LABEL"))

# The attempt-counter grammars a park-generation receipt's `attempt=` component can carry, one
# per exhaustion branch that writes a capacity park. These are the DURABLE, machine-written
# record of WHICH budget the escalation derived from — the whole reason this tool never reads
# comment prose:
#   missed<round>=<lifetime>  dispatch-claim's MISSED_FIX_LIMIT branch — THE DEFECT. The
#                             counter is the LIFETIME `missed`-marker count, which grows purely
#                             from allocator starvation (no head advance, no review round).
#   rounds=<n>                the review-ROUND budget — a genuinely CONSUMED budget of real
#                             model reviews. NOT this defect: escalating on it is the loop
#                             working as designed, so it is never reclassified.
#   nochange<round>=<n>       fix rounds that actually RAN and changed nothing, and local gate
#   gatefail<round>=<n>       failures of fixes that actually RAN. Work genuinely consumed —
#                             also not this defect.
DEFECT_ATTEMPT_RE = re.compile(r"missed([1-9][0-9]*)=([0-9]+)")
ROUND_BUDGET_ATTEMPT_RE = re.compile(r"rounds=([0-9]+)")
CONSUMED_WORK_ATTEMPT_RE = re.compile(r"(nochange|gatefail)([1-9][0-9]*)=([0-9]+)")
HEAD_SHA_RE = re.compile(r"[0-9a-f]{40}")

# How far BEFORE the label application a park-generation receipt may sit and still be accepted
# as the receipt that BOUND that application.
#
# WHY A BOUND AT ALL: the receipt and the label write are two API calls inside ONE
# needs_user(park_class="capacity") invocation, in RECEIPT-FIRST order (worker-pr.py). So the
# receipt that caused a label always precedes it by seconds. A receipt that precedes the label
# by days did NOT cause it — some LATER path (a groom age-park, a question-class stop, a
# re-apply after a human unlabel) did, and that path's class is unknown to us. Accepting a
# stale receipt would let an unrelated human-owned stop inherit a months-old capacity receipt's
# authority, which is exactly the inference this tool must not make.
#
# WHY 15 MINUTES: generous enough to absorb the shared bounded-retry layer's backoff on either
# call plus clock skew between the comment and event streams, and far smaller than the gap to
# any plausible unrelated later label write. The direction is safe both ways — too small only
# causes a SKIP.
RECEIPT_LABEL_MAX_SKEW_S = 900

# Timeline event kinds that are NOT a human decision about this PR even when their actor is a
# proven human, and are therefore ignored by the human-touch gate. This is an explicit
# ALLOW-list, not a deny-list: any event kind not named here counts as a human touch, so a new
# or unrecognised GitHub event kind fails toward SKIP.
#   mentioned/subscribed/unsubscribed — GENERATED BY the bot's own `@maintainer` ping in the
#     park comment; the actor is the mentioned human, who did nothing. Counting these would
#     make every parked PR permanently unreadable to this tool for a reason that is an artefact
#     of the park comment itself.
#   cross-referenced/referenced — someone linked this PR from elsewhere; not a decision here.
#   committed — carries no login (git identity, not a GitHub actor) and cannot prove a human;
#     a human PUSH is caught far more strongly by the head-unadvanced gate.
#   labeled/unlabeled — handled by the dedicated, park-label-scoped human-touch gate, which is
#     stricter than this one; a human adding an unrelated `area:*` label is not a park decision.
IGNORABLE_HUMAN_EVENT_KINDS = frozenset({
    "mentioned", "subscribed", "unsubscribed", "cross-referenced", "referenced", "committed",
    "labeled", "unlabeled",
})


class ReclassError(RuntimeError):
    """A concise, credential-free operational error."""


Decision = collections.namedtuple(
    "Decision", "repo pr issue decision failures evidence plan advisory")


def _load_script_module(filename, module_name):
    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ReclassError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _park_policy():
    return _load_script_module("park_policy.py", "registry_park_policy")


def _worker_pr():
    return _load_script_module("worker-pr.py", "registry_worker_pr")


def _dispatch_claim():
    """dispatch-claim.py — imported for MISSED_FIX_LIMIT (the exact constant the defective
    branch compared against) and provenance_admission_error (the review loop's OWN definition
    of an admissible provenance record). Imported, never replicated, so this tool's judgement
    and the loop's judgement cannot drift."""
    return _load_script_module("dispatch-claim.py", "registry_dispatch_claim")


def _label_map(policy):
    """{human-owned hold -> machine-owned twin}, read from park_policy so the ownership split
    has exactly one definition."""
    return {getattr(policy, human): getattr(policy, machine)
            for human, machine in HOLD_TO_MACHINE_NAMES}


def _park_ownership_labels(policy):
    """Every label whose presence/absence expresses PARK OWNERSHIP: the two human-owned holds
    plus the two machine-owned twins (park_policy.READMISSION_LABELS ∪ the PR-side human
    hold). A proven-human event on ANY of them is a human decision about this PR's park state,
    so the human-touch gate spans all four rather than only the label being converted."""
    return tuple(sorted(set(policy.READMISSION_LABELS) | set(_label_map(policy))))


# ---------------------------------------------------------------------------------------------
# The mutation seam — the ONLY place this tool can write.
# ---------------------------------------------------------------------------------------------
class LabelWriter:
    """The single mutation surface, and the mechanism that makes "dry run writes nothing" a
    structural property rather than a convention.

    `performed` records every write ACTUALLY sent to GitHub. In dry-run mode no branch of this
    class calls `add_label`/`remove_label`, so `performed` is empty BY CONSTRUCTION — which is
    what the self-test asserts (a test on final label state alone would pass even if a write
    had been attempted and failed)."""

    def __init__(self, apply_changes, add_label=None, remove_label=None):
        self.apply_changes = bool(apply_changes)
        self.performed = []
        self._add_label = add_label
        self._remove_label = remove_label

    def run(self, plan):
        """Execute `plan` (a sequence of ("add"|"remove", repo, number, label) tuples) and
        return the number of writes performed. In dry-run mode: zero, no calls."""
        if not self.apply_changes:
            return 0
        for op, repo, number, label in plan:
            if op == "add":
                self._add_label(repo, number, label)
            elif op == "remove":
                self._remove_label(repo, number, label)
            else:
                raise ReclassError(f"refusing an unknown write op {op!r}")
            self.performed.append((op, repo, number, label))
        return len(plan)


def plan_writes(policy, surfaces):
    """The COMPLETE write vocabulary of this tool, for a decided conversion.

    `surfaces` is [(number, hold_label)] — the surface each live human hold sits on. For each,
    exactly two writes: ADD the machine twin, then REMOVE the human hold.

    ORDER IS LOAD-BEARING (the worker-pr set_review_state rationale): every ADD precedes every
    REMOVE, so a crash mid-plan can only ever leave a SUPERSET of holds — never a window in
    which nothing holds the PR. Fail-closed in the same direction as everything else here."""
    label_map = _label_map(policy)
    adds, removes = [], []
    for repo, number, hold in surfaces:
        machine = label_map[hold]
        adds.append(("add", repo, number, machine))
        removes.append(("remove", repo, number, hold))
    return adds + removes


# ---------------------------------------------------------------------------------------------
# Evidence reading (pure helpers over already-fetched payloads).
# ---------------------------------------------------------------------------------------------
def hold_label_events(policy, events, labels):
    """{label: [(created, kind, login, via_app)]} for `labels` over one surface's timeline,
    using park_policy._event_rows — the SAME normalizer the veto and the readmission window
    use, so a malformed relevant event RAISES MalformedTimelineError here exactly as it does
    there (and the caller SKIPS, its documented fail direction)."""
    return {label: policy._event_rows(events, label) for label in labels}


def latest_application(rows):
    """(created, login, via_app) of the newest `labeled` event in `rows`, or None."""
    applications = [(created, login, via_app)
                    for created, kind, login, via_app in rows if kind == "labeled"]
    return max(applications) if applications else None


def possibly_human(login, via_app):
    """True unless the actor is PROVABLY not a person: a `[bot]`-suffixed login, or an event
    GitHub attributes to an App (`performed_via_github_app`). An EMPTY or unrecognised login is
    POSSIBLY HUMAN.

    THIS IS DELIBERATELY THE OPPOSITE FAIL DIRECTION TO park_policy._is_proven_human, and the
    inversion is the whole reason it exists. park_policy asks "may the machine APPLY a park?",
    where an unverifiable actor must NOT mint a human veto — so unprovable => not human is the
    conservative answer there. This tool asks "may the machine WEAKEN a human hold?", where
    unprovable => not human would be the DANGEROUS answer: a maintainer whose collaborator
    permission probe 404s, whose token lacks the scope to read it, or who has since lost write
    access would silently stop counting as human and their touch would stop protecting the
    hold.
    """
    return not via_app and not str(login or "").endswith("[bot]")


def _touch_note(policy, login, via_app, probe):
    """How to describe a disqualifying actor, or None when the actor is provably not a person.
    A PROVEN human (the strict park_policy predicate, reused) is named as such; anything else
    that is not provably the bot is reported as unverified — and both disqualify, so the
    DECISION never depends on the maintainer probe succeeding."""
    if policy._is_proven_human(login, via_app, probe):
        return f"PROVEN HUMAN {login}"
    if possibly_human(login, via_app):
        return f"unverified non-bot actor {login or '<no login>'!s}"
    return None


def human_label_touches(policy, rows_by_surface, probe):
    """Every event on a park-ownership label whose actor is not provably a bot, as sorted
    "<surface> <kind> <label> at <stamp> by <actor>" strings — apply OR remove, on either
    surface.

    NOT most-recent-event-wins (that is the sticky-veto rule for APPLYING a park): ANY human
    touch in the whole history disqualifies, because a human who once removed this hold and let
    the machine re-apply it has still expressed a decision about it."""
    touches = []
    for surface, rows_by_label in rows_by_surface:
        for label, rows in rows_by_label.items():
            for created, kind, login, via_app in rows:
                note = _touch_note(policy, login, via_app, probe)
                if note:
                    touches.append(f"{surface} {kind} {label} at {created} by {note}")
    return sorted(touches)


def human_comment_touches(policy, comments_by_surface, probe):
    """Every comment on either surface whose author is not provably a bot, as sorted strings.

    Deliberately NOT keyed on what the comment SAYS: "a human comment asserting a decision"
    cannot be recognised from prose without exactly the natural-language inference this tool
    must not make. So ANY such comment disqualifies the PR. The fail direction is
    over-skipping, which is the safe one."""
    touches = []
    for surface, comments in comments_by_surface:
        for comment in comments or []:
            if not isinstance(comment, dict):
                raise ReclassError(f"{surface} comment payload is malformed")
            user = comment.get("user")
            login = str(user.get("login", "")) if isinstance(user, dict) else ""
            via_app = comment.get("performed_via_github_app") is not None
            note = _touch_note(policy, login, via_app, probe)
            if note:
                touches.append(f"{surface} comment at {comment.get('created_at')} by {note}")
    return sorted(touches)


def human_gesture_touches(policy, timelines, probe):
    """Every timeline event NOT in IGNORABLE_HUMAN_EVENT_KINDS whose actor is not provably a bot
    — a review, a force-push, an arm/disarm, a draft conversion, a close/reopen, an assignment:
    any human gesture on the PR or its source issue. The event-kind filter is an ALLOW-list, so
    an unrecognised event kind counts as a touch and the PR SKIPS."""
    touches = []
    for surface, events in timelines:
        for event in events or []:
            if not isinstance(event, dict):
                raise ReclassError(f"{surface} timeline event is malformed")
            kind = event.get("event")
            if kind in IGNORABLE_HUMAN_EVENT_KINDS:
                continue
            actor = event.get("actor") if isinstance(event.get("actor"), dict) else None
            user = event.get("user") if isinstance(event.get("user"), dict) else None
            login = str((actor or user or {}).get("login", ""))
            via_app = event.get("performed_via_github_app") is not None
            note = _touch_note(policy, login, via_app, probe)
            if note:
                touches.append(f"{surface} {kind} at {event.get('created_at')} by {note}")
    return sorted(touches)


def park_receipts(worker_pr, comments, bot_login, log=print):
    """[(created_at, record)] for every WELL-FORMED bot-authored park-generation receipt, where
    `record` is exactly what worker-pr's own park_generation_records produces
    ({"window", "generation", "fingerprint"}).

    The parser is worker-pr's, invoked ONE COMMENT AT A TIME so each record keeps the comment
    timestamp it was posted at — the timestamp is what binds a receipt to the label write it
    caused. Re-implementing the receipt grammar here would be the drift this repo's
    one-parser rule exists to prevent."""
    records = []
    for comment in comments or []:
        if not isinstance(comment, dict):
            raise ReclassError("comment payload is malformed")
        created = comment.get("created_at")
        for record in worker_pr.park_generation_records([comment], bot_login, log):
            records.append((created, record))
    return records


def split_fingerprint(fingerprint):
    """(head_sha, attempt_key) from a park receipt's attempt FINGERPRINT
    (park_policy.park_fingerprint == "<head-sha>/<attempt-counter>"), or (None, None).

    Split on the FIRST separator and require the left side to be a 40-hex SHA: that is a
    POSITIVE parse. Splitting from the right would mis-parse an attempt counter that itself
    contained a `/` (the fingerprint grammar permits one), and a fingerprint we cannot parse
    unambiguously must prove nothing."""
    if not isinstance(fingerprint, str):
        return None, None
    head, sep, attempt = fingerprint.partition("/")
    if not sep or not HEAD_SHA_RE.fullmatch(head) or not attempt:
        return None, None
    return head, attempt


def attempt_class(attempt_key):
    """Which exhaustion branch a receipt's attempt counter came from: "defect" (the
    MISSED_FIX_LIMIT lifetime count), "round-budget", "consumed-work", or "unknown"."""
    if DEFECT_ATTEMPT_RE.fullmatch(attempt_key or ""):
        return "defect"
    if ROUND_BUDGET_ATTEMPT_RE.fullmatch(attempt_key or ""):
        return "round-budget"
    if CONSUMED_WORK_ATTEMPT_RE.fullmatch(attempt_key or ""):
        return "consumed-work"
    return "unknown"


def missed_marker_advisory(worker_pr, comments, bot_login, missed_fix_limit):
    """ADVISORY ONLY (never gate-satisfying): the rounds whose durable bot-authored `missed`
    marker count has reached the limit the defective branch compared against.

    WHY ADVISORY. These markers prove that the defect's COUNTER was at its limit; they do NOT
    prove the escalation that stamped the human hold came from THAT branch. dispatch-claim
    evaluates the round budget FIRST, so a PR can carry a maxed-out missed counter and still
    have been parked by an exhausted round budget. Establishing which branch fired would mean
    re-deriving decide_budget from state that has since moved — an inference, not a record. So
    the count is REPORTED to help a human triage, and the gate keys strictly on the receipt."""
    rounds = []
    for round_n in range(1, worker_pr.HARD_CAP_ROUNDS + 1):
        count = len(worker_pr.marker_runs(comments, bot_login, "missed", round_n))
        if count >= missed_fix_limit:
            rounds.append(f"missed{round_n}={count}")
    return rounds


# ---------------------------------------------------------------------------------------------
# The evidence gate.
# ---------------------------------------------------------------------------------------------
def classify(evidence, policy, worker_pr, missed_fix_limit, is_human=None, log=print):
    """Decide whether ONE PR's live human-owned park hold is PROVABLY an artefact of the fixed
    MISSED_FIX_LIMIT capacity-park defect, and may therefore be reclassified to the
    machine-owned class.

    Returns a Decision. `decision` is "convert" iff EVERY gate below passes; otherwise "skip"
    and `failures` names each gate that did not, in gate order. `plan` is the write plan (empty
    for a skip). `advisory` carries prose-free indicators for a human reader and NEVER
    influences the decision.

    THE GATE (all must hold; any ambiguity, unreadable timeline, missing receipt or malformed
    record fails toward LEAVING THE HUMAN LABEL ALONE):

    G0 scope             a human-owned hold is actually live on the PR or its source issue.
    G1 source-issue      the provenance-linked source issue resolved from an ADMISSIBLE
                         registry provenance record; without it the issue-side evidence
                         surface is unreadable and nothing can be proven about it.
    G2 bot-applied       the LATEST application of each live hold was made by EXACTLY the
                         orchestrator bot login, and the proven-human predicate rejects that
                         actor. POSITIVE bot evidence is required: an UNVERIFIABLE actor
                         (missing login, deleted user, some other bot) is not "the bot".
    G3 no-human-label    NO event of ANY kind (apply or remove) by an actor that is not
                         provably a bot, on ANY park-ownership label, on EITHER surface.
    G4 no-human-voice    NO comment, review, force-push, arm, draft-flip, close or other
                         non-ignorable gesture by a not-provably-a-bot actor on either surface.

    PROBE INDEPENDENCE (load-bearing). G3/G4 disqualify on `possibly_human`, which is TRUE for
    every non-`[bot]` actor whether or not the collaborator-permission probe can confirm them.
    So a probe that 404s, lacks scope, or raises can never turn a SKIP into a CONVERT — it only
    changes whether the reported reason says "PROVEN HUMAN" or "unverified non-bot actor". The
    park policy's own probe fails toward not-human, which is right for APPLYING a park and
    would be exactly backwards here.
    G5 defect-signature  a well-formed bot-authored PARK-GENERATION receipt binds the label
                         application (newest receipt at-or-before it, within
                         RECEIPT_LABEL_MAX_SKEW_S), its generation is the terminal escalation
                         (>= PARK_ESCALATION_GENERATIONS — the only capacity path that writes a
                         human-owned hold), and its attempt counter is the DEFECT class
                         (missed<round>=<lifetime>) — not a consumed round budget, not fix work
                         that actually ran. Corroborated against the other durable family: the
                         PR really does carry >= MISSED_FIX_LIMIT `missed` markers for that
                         round, and the receipt's lifetime count matches that marker count.
    G6 head-unadvanced   the receipt's head SHA equals the LIVE head SHA: nothing was pushed
                         since the park, so the situation cannot have genuinely changed.
    """
    repo = evidence["repo"]
    pr_number = evidence["pr"]
    issue_number = evidence.get("issue")
    failures = []
    detail = {}
    label_map = _label_map(policy)
    ownership = _park_ownership_labels(policy)
    probe = policy._human_probe(is_human)

    # ---- G0 scope ---------------------------------------------------------------------------
    pr_labels = evidence.get("pr_labels") or set()
    issue_labels = evidence.get("issue_labels")
    # PR surface first, then the source issue: the PR is the unit this migration is scoped to,
    # and a deterministic order makes the write plan reproducible for a human reviewing it.
    surfaces = []            # (repo, number, hold_label, surface_name)
    for number, live, surface in ((pr_number, pr_labels, f"pr#{pr_number}"),
                                  (issue_number, issue_labels or set(),
                                   f"issue#{issue_number}")):
        if number is None:
            continue
        for hold in sorted(label_map):
            if hold in live:
                surfaces.append((repo, number, hold, surface))
    if not surfaces:
        failures.append("G0 scope: no human-owned park hold is live on either surface")

    # ---- G1 source issue --------------------------------------------------------------------
    if evidence.get("issue_error"):
        failures.append(f"G1 source-issue: {evidence['issue_error']} — the source-issue "
                        "evidence surface is unreadable, so no human touch there can be ruled "
                        "out")

    # ---- normalize both label timelines (a malformed RELEVANT event skips) -------------------
    rows_by_surface, label_at, timelines, comment_surfaces = [], None, [], []
    try:
        rows_by_surface.append((f"pr#{pr_number}",
                                hold_label_events(policy, evidence["pr_timeline"], ownership)))
        timelines.append((f"pr#{pr_number}", evidence["pr_timeline"]))
        comment_surfaces.append((f"pr#{pr_number}", evidence["pr_comments"]))
        if issue_number and evidence.get("issue_timeline") is not None:
            rows_by_surface.append(
                (f"issue#{issue_number}",
                 hold_label_events(policy, evidence["issue_timeline"], ownership)))
            timelines.append((f"issue#{issue_number}", evidence["issue_timeline"]))
            comment_surfaces.append((f"issue#{issue_number}", evidence.get("issue_comments")))
    except (policy.MalformedTimelineError, KeyError, TypeError) as exc:
        failures.append(f"G2/G3 timeline: the label timeline could not be read ({exc}) — "
                        "an unreadable timeline can never prove the absence of a human touch")
        return Decision(repo, pr_number, issue_number, "skip", failures, detail, [], {})

    # ---- G2 bot-applied --------------------------------------------------------------------
    applications = []
    bot = evidence.get("bot_login") or ""
    if not bot.endswith("[bot]"):
        failures.append(f"G2 bot-applied: no orchestrator bot login was supplied "
                        f"({bot!r}), so no label application can be attributed to the bot")
    for surface_repo, number, hold, surface in surfaces:
        rows = dict(rows_by_surface).get(surface, {}).get(hold, [])
        latest = latest_application(rows)
        if latest is None:
            failures.append(f"G2 bot-applied: {surface} carries {hold} but its timeline holds "
                            "no application event for it (unattributable label)")
            continue
        created, login, via_app = latest
        if policy._is_proven_human(login, via_app, probe):
            failures.append(f"G2 bot-applied: {hold} on {surface} was applied by the PROVEN "
                            f"HUMAN {login} at {created}")
            continue
        if login != bot or not bot.endswith("[bot]"):
            failures.append(f"G2 bot-applied: the latest {hold} application on {surface} at "
                            f"{created} was not made by the orchestrator bot "
                            f"(login={login!r}, expected {bot!r}, via_app={via_app}) — only "
                            "positive bot evidence counts")
            continue
        applications.append((created, hold, surface, login))
    if applications:
        label_at = max(created for created, _hold, _surface, _login in applications)
        detail["label_applied_at"] = label_at
        detail["label_applications"] = [f"{hold} on {surface} at {created} by {login}"
                                        for created, hold, surface, login in applications]

    # ---- G3 no human event on any park-ownership label --------------------------------------
    label_touches = human_label_touches(policy, rows_by_surface, probe)
    if label_touches:
        failures.append("G3 no-human-label: a non-bot actor TOUCHED a park-ownership "
                        "label — "
                        + "; ".join(label_touches))

    # ---- G4 no human comment / review / gesture ---------------------------------------------
    try:
        voice = (human_comment_touches(policy, comment_surfaces, probe)
                 + human_gesture_touches(policy, timelines, probe))
    except ReclassError as exc:
        failures.append(f"G4 no-human-voice: {exc} — an unreadable human-activity surface can "
                        "never prove the absence of a human decision")
        voice = []
    if voice:
        failures.append("G4 no-human-voice: a non-bot actor spoke on this PR — "
                        + "; ".join(voice))

    # ---- advisory (never gate-satisfying) ---------------------------------------------------
    bot_login = bot
    advisory = {}
    try:
        advisory["missed_markers"] = missed_marker_advisory(
            worker_pr, evidence["pr_comments"], bot_login, missed_fix_limit)
    except Exception as exc:  # noqa: BLE001 — an advisory can never fail the run
        advisory["missed_markers_error"] = str(exc)

    # ---- G5 defect signature (durable receipts only) ----------------------------------------
    receipt = None
    try:
        receipts = park_receipts(worker_pr, evidence["pr_comments"], bot_login, log)
    except ReclassError as exc:
        failures.append(f"G5 defect-signature: the park-receipt comments are unreadable ({exc})")
        receipts = None
    if receipts is None:
        pass
    elif not receipts:
        failures.append(
            "G5 defect-signature: NO durable bot-authored park-generation receipt exists on "
            "this PR, so the escalation class cannot be established from durable records "
            "(labels applied before the receipt machinery landed are in exactly this state)")
    elif label_at is None:
        pass                # G2 already failed; no application instant to bind a receipt to
    else:
        bound, skew = _bind_receipt(policy, receipts, label_at)
        if bound is None:
            newest = max(created for created, _record in receipts)
            why = ("every receipt is NEWER than the application" if skew is None else
                   f"the closest earlier receipt is {int(skew)}s older, past the "
                   f"{RECEIPT_LABEL_MAX_SKEW_S}s binding bound")
            failures.append(
                f"G5 defect-signature: no park-generation receipt binds the label application "
                f"at {label_at} (newest receipt {newest}; {why})")
        else:
            created, record = bound
            detail["receipt_at"] = created
            detail["receipt_generation"] = record["generation"]
            detail["receipt_fingerprint"] = record["fingerprint"]
            receipt = record
            if (record["generation"] or 0) < policy.PARK_ESCALATION_GENERATIONS:
                failures.append(
                    f"G5 defect-signature: the bound receipt is generation "
                    f"{record['generation']}, below the terminal escalation "
                    f"({policy.PARK_ESCALATION_GENERATIONS}) — a non-terminal capacity park "
                    "writes the MACHINE label and never a human-owned hold, so this receipt "
                    "cannot explain a human-owned label")
            head_sha, attempt_key = split_fingerprint(record["fingerprint"])
            if head_sha is None:
                failures.append(
                    "G5 defect-signature: the bound receipt carries no parseable attempt "
                    f"fingerprint ({record['fingerprint']!r}) — the escalation's derivation "
                    "cannot be read")
            else:
                detail["attempt_key"] = attempt_key
                klass = attempt_class(attempt_key)
                detail["attempt_class"] = klass
                if klass != "defect":
                    failures.append(
                        f"G5 defect-signature: the escalation derived from {attempt_key!r} "
                        f"({klass}), not from the missed-marker lifetime count — "
                        + {"round-budget": "a genuinely CONSUMED review-round budget is the "
                                           "loop working as designed",
                           "consumed-work": "fix rounds that actually RAN are work genuinely "
                                            "consumed",
                           "unknown": "an unrecognised attempt grammar can prove nothing"}[klass])
                else:
                    round_n, lifetime = DEFECT_ATTEMPT_RE.fullmatch(attempt_key).groups()
                    markers = len(worker_pr.marker_runs(
                        evidence["pr_comments"], bot_login, "missed", int(round_n)))
                    detail["missed_markers_for_round"] = f"round={round_n} markers={markers}"
                    if markers < missed_fix_limit or markers != int(lifetime):
                        failures.append(
                            f"G5 defect-signature: the receipt claims a lifetime missed count "
                            f"of {lifetime} for round {round_n}, but the durable `missed` "
                            f"markers for that round number {markers} (limit "
                            f"{missed_fix_limit}) — the two durable families DISAGREE")

    # ---- G6 head unadvanced -----------------------------------------------------------------
    live_head = evidence.get("head_sha") or ""
    if not HEAD_SHA_RE.fullmatch(live_head):
        failures.append(f"G6 head-unadvanced: the live head SHA is unreadable ({live_head!r})")
    elif receipt is not None:
        receipt_head, _attempt = split_fingerprint(receipt["fingerprint"])
        if receipt_head is None:
            pass                                    # already reported by G5
        elif receipt_head != live_head:
            failures.append(
                f"G6 head-unadvanced: the head ADVANCED since the park — the receipt was "
                f"bound to {receipt_head[:12]} and the live head is {live_head[:12]}; new work "
                "happened, so the situation may genuinely differ")
        else:
            detail["head_unchanged_since_park"] = live_head

    decision = "convert" if not failures else "skip"
    plan = (plan_writes(policy, [(surface_repo, number, hold)
                                 for surface_repo, number, hold, _s in surfaces])
            if decision == "convert" else [])
    return Decision(repo, pr_number, issue_number, decision, failures, detail, plan, advisory)


def _bind_receipt(policy, receipts, label_at):
    """(newest receipt at-or-before `label_at` within the skew bound, skew_seconds), or
    (None, skew_of_the_closest_earlier_receipt or None).

    Ordering is over PARSED aware datetimes (park_policy.parse_ts) — never raw strings, which
    do not order across equally-valid ISO spellings. A receipt whose stamp cannot be parsed is
    dropped: unprovable time can bind nothing."""
    label_instant = policy.parse_ts(label_at)
    best, best_skew = None, None
    for created, record in receipts:
        if not policy.valid_timestamp(created):
            continue
        instant = policy.parse_ts(created)
        if instant > label_instant:
            continue
        skew = (label_instant - instant).total_seconds()
        if best_skew is None or skew < best_skew:
            best, best_skew = (created, record), skew
    if best is None:
        return None, None
    if best_skew > RECEIPT_LABEL_MAX_SKEW_S:
        return None, best_skew
    return best, best_skew


# ---------------------------------------------------------------------------------------------
# Live evidence collection + reporting.
# ---------------------------------------------------------------------------------------------
def source_issue(worker_pr, admission_error, registry_repo, repo, pr_number):
    """(issue_number, error) from the PR's REGISTRY provenance record — ledger copy first, then
    master (the reader order every consumer uses). A missing, undecodable or INADMISSIBLE
    record yields an error: the source issue is then unknown, its evidence surface unreadable,
    and the PR skips."""
    path = worker_pr.provenance_path(repo, pr_number)
    try:
        body, _sha = worker_pr._probe_registry_file(registry_repo, path,
                                                    ref=worker_pr.LEDGER_REF)
        if body is None:
            body, _sha = worker_pr._probe_registry_file(registry_repo, path, ref=None)
    except Exception as exc:  # noqa: BLE001 — an unreadable registry probe skips the PR
        return None, f"the registry provenance probe failed ({exc})"
    if body is None:
        return None, "no registry provenance record exists for this PR"
    try:
        record = json.loads(body)
    except ValueError:
        return None, "the registry provenance record is not valid JSON"
    error = admission_error(record, pr_number)
    if error:
        return None, f"the registry provenance record is inadmissible ({error})"
    return record["issue"], None


def collect_evidence(gh_json, worker_pr, admission_error, registry_repo, repo, pr_number,
                     bot_login):
    """Read every evidence surface for one PR. A read failure becomes a recorded ERROR rather
    than an exception, so one unreadable PR never aborts the sweep — and an unreadable surface
    always ends in a SKIP."""
    evidence = {"repo": repo, "pr": pr_number, "bot_login": bot_login,
                "pr_labels": set(), "issue_labels": None, "pr_timeline": [], "issue_timeline":
                None, "pr_comments": [], "issue_comments": None, "head_sha": "", "issue": None,
                "issue_error": None}
    pull = gh_json(["api", f"repos/{repo}/pulls/{pr_number}"])
    head = pull.get("head") if isinstance(pull, dict) else None
    evidence["head_sha"] = str(head.get("sha", "")) if isinstance(head, dict) else ""
    evidence["pr_labels"] = _label_names(pull)
    evidence["pr_timeline"] = worker_pr._issue_timeline(repo, pr_number)
    evidence["pr_comments"] = worker_pr._paginated_comments(repo, pr_number)
    issue_number, error = source_issue(worker_pr, admission_error, registry_repo, repo,
                                       pr_number)
    evidence["issue"], evidence["issue_error"] = issue_number, error
    if issue_number:
        try:
            issue = gh_json(["api", f"repos/{repo}/issues/{issue_number}"])
            evidence["issue_labels"] = _label_names(issue)
            evidence["issue_timeline"] = worker_pr._issue_timeline(repo, issue_number)
            evidence["issue_comments"] = worker_pr._paginated_comments(repo, issue_number)
        except Exception as exc:  # noqa: BLE001 — unreadable source issue => skip
            evidence["issue_error"] = f"the source issue #{issue_number} is unreadable ({exc})"
    return evidence


def _label_names(payload):
    labels = payload.get("labels") if isinstance(payload, dict) else None
    if not isinstance(labels, list):
        raise ReclassError("label payload is malformed")
    names = set()
    for label in labels:
        name = label.get("name") if isinstance(label, dict) else None
        if not isinstance(name, str):
            raise ReclassError("label payload is malformed")
        names.add(name)
    return names


def audit_line(decision):
    """The per-PR audit line, suitable for pasting into an issue."""
    reason = " | ".join(decision.failures) if decision.failures else "; ".join(
        f"{key}={value}" for key, value in sorted(decision.evidence.items()))
    advisory = ",".join(decision.advisory.get("missed_markers") or []) or "none"
    return (f"AUDIT | {decision.repo}#{decision.pr} | issue="
            f"{decision.issue if decision.issue else '?'} | "
            f"decision={decision.decision.upper()} | writes={len(decision.plan)} | "
            f"advisory_missed_markers={advisory} | {reason}")


def markdown_row(decision):
    reason = "<br>".join(decision.failures) if decision.failures else "; ".join(
        f"`{key}`={value}" for key, value in sorted(decision.evidence.items()))
    return (f"| {decision.repo}#{decision.pr} | "
            f"{decision.issue if decision.issue else '?'} | "
            f"{decision.decision} | "
            f"{','.join(decision.advisory.get('missed_markers') or []) or '-'} | "
            f"{reason} |")


def sweep(repo, registry_repo, bot_login, apply_changes, only=(), log=print):
    """The operator entry point. Enumerates the OPEN PRs carrying the PR-side human hold, gates
    each, reports every decision, and applies only under `apply_changes`."""
    policy, worker_pr = _park_policy(), _worker_pr()
    dispatch_claim = _dispatch_claim()
    label_map = _label_map(policy)
    hold_label = policy.HUMAN_PR_PARK_LABEL
    writer = LabelWriter(
        apply_changes,
        add_label=lambda r, n, label: _add_label(worker_pr, r, n, label),
        remove_label=lambda r, n, label: worker_pr._remove_label(r, n, label))
    pulls = _open_holds(worker_pr._gh_json, repo, hold_label)
    if only:
        pulls = [number for number in pulls if number in set(only)]
    log(f"reclass-park-holds: {len(pulls)} open PR(s) carry {hold_label} in {repo} "
        f"({'APPLY' if apply_changes else 'DRY RUN — no writes'})")
    decisions = []
    for number in pulls:
        try:
            evidence = collect_evidence(worker_pr._gh_json, worker_pr,
                                        dispatch_claim.provenance_admission_error,
                                        registry_repo, repo, number, bot_login)
        except Exception as exc:  # noqa: BLE001 — one unreadable PR must not abort the sweep
            log(f"SKIP {repo}#{number}: the evidence surfaces could not be read ({exc})")
            decisions.append(Decision(repo, number, None, "skip",
                                      [f"evidence read failed ({exc})"], {}, [], {}))
            continue
        decision = classify(evidence, policy, worker_pr, dispatch_claim.MISSED_FIX_LIMIT,
                            is_human=lambda login: worker_pr._is_human_maintainer(repo, login),
                            log=log)
        decisions.append(decision)
        log(audit_line(decision))
        if decision.decision == "convert":
            for op, write_repo, write_number, label in decision.plan:
                log(f"  {'WRITE' if apply_changes else 'WOULD'} {op} {label} on "
                    f"{write_repo}#{write_number}")
            writer.run(decision.plan)
    converted = sum(1 for decision in decisions if decision.decision == "convert")
    log("")
    log(f"| PR | source issue | decision | advisory missed markers | evidence / reason |")
    log("| --- | --- | --- | --- | --- |")
    for decision in decisions:
        log(markdown_row(decision))
    log("")
    log(f"reclass-park-holds complete: {converted} convertible, "
        f"{len(decisions) - converted} skipped, {len(writer.performed)} write(s) performed "
        f"({'APPLY' if apply_changes else 'DRY RUN'}); machine twins in use: "
        f"{', '.join(f'{h} -> {m}' for h, m in sorted(label_map.items()))}")
    return decisions, writer


def _add_label(worker_pr, repo, number, label):
    worker_pr._ensure_label(repo, label)
    worker_pr._gh_json(["api", "-X", "POST", f"repos/{repo}/issues/{number}/labels",
                        "--input", "-"], input_doc={"labels": [label]})


def _open_holds(gh_json, repo, label):
    """The OPEN PR numbers carrying `label`, from the LIST API (never the search index, whose
    label counts lag)."""
    pages = gh_json(["api", "--paginate", "--slurp",
                     f"repos/{repo}/issues?labels={label}&state=open&per_page=100"])
    if not isinstance(pages, list):
        raise ReclassError("issue listing is malformed")
    numbers = []
    for page in pages:
        if not isinstance(page, list):
            raise ReclassError("issue listing page is malformed")
        for item in page:
            if not isinstance(item, dict):
                raise ReclassError("issue listing entry is malformed")
            # `pull_request` is an OBJECT on a PR row and absent on a plain issue: test the
            # SHAPE, never truthiness — an empty object is still a pull request.
            if isinstance(item.get("pull_request"), dict) and isinstance(
                    item.get("number"), int):
                numbers.append(item["number"])
    return sorted(numbers, reverse=True)


# ---------------------------------------------------------------------------------------------
# Self-test.
# ---------------------------------------------------------------------------------------------
def _self_test():  # noqa: C901 — one linear scenario table, deliberately unfactored
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    policy, worker_pr = _park_policy(), _worker_pr()
    dispatch_claim = _dispatch_claim()
    limit = dispatch_claim.MISSED_FIX_LIMIT
    bot = "sparq-orchestrator[bot]"
    human = "jeswr"
    head = "a" * 40
    other_head = "b" * 40
    trusted = lambda login: login == human  # noqa: E731 — the strict maintainer probe stub

    check("the machine twin map comes from park_policy", _label_map(policy),
          {"review:needs-user": "review:parked", "needs:user": "status:parked"})
    check("the human-touch gate spans all FOUR park-ownership labels",
          _park_ownership_labels(policy),
          ("needs:user", "review:needs-user", "review:parked", "status:parked"))

    def label_event(kind, label, created, login=bot, via_app=False):
        event = {"event": kind, "label": {"name": label}, "created_at": created,
                 "actor": {"login": login}}
        if via_app:
            event["performed_via_github_app"] = {"slug": "x"}
        return event

    def missed_comments(count, created="2026-07-20T09:00:00Z", round_n=3, start=1):
        return [{"user": {"login": bot}, "created_at": created,
                 "body": f"x {worker_pr.MARKER_KINDS['missed']} round={round_n} "
                         f"run={n}.1 -->"}
                for n in range(start, start + count)]

    def receipt_comment(created, generation=2, window="2026-07-20T08:00:00Z",
                        head_sha=head, attempt=f"missed3={limit}", login=bot):
        return {"user": {"login": login}, "created_at": created,
                "body": f"stop\n\n{worker_pr.PARK_GENERATION_MARKER} gen={generation} "
                        f"cutoff={window} head={head_sha} attempt={attempt} -->"}

    LABEL_AT = "2026-07-20T09:30:00Z"
    RECEIPT_AT = "2026-07-20T09:29:58Z"

    def base_evidence(**overrides):
        evidence = {
            "repo": "o/r", "pr": 41, "issue": 7, "issue_error": None, "bot_login": bot,
            "head_sha": head,
            "pr_labels": {"review:needs-user"},
            "issue_labels": {"needs:user"},
            "pr_timeline": [label_event("labeled", "review:needs-user", LABEL_AT)],
            "issue_timeline": [label_event("labeled", "needs:user", LABEL_AT)],
            "pr_comments": missed_comments(limit) + [receipt_comment(RECEIPT_AT)],
            "issue_comments": [],
        }
        evidence.update(overrides)
        return evidence

    def decide(**overrides):
        return classify(base_evidence(**overrides), policy, worker_pr, limit,
                        is_human=trusted, log=lambda *a, **k: None)

    # ---- (a) the ONE convertible shape ------------------------------------------------------
    good = decide()
    check("(a) bot-applied + defect receipt + unadvanced head + zero human events => CONVERT",
          (good.decision, good.failures), ("convert", []))
    check("(a) the plan ADDS both machine twins before REMOVING either human hold", good.plan,
          [("add", "o/r", 41, "review:parked"), ("add", "o/r", 7, "status:parked"),
           ("remove", "o/r", 41, "review:needs-user"), ("remove", "o/r", 7, "needs:user")])
    check("(a) the audit line names the decision and the write count",
          audit_line(good).split(" | ")[3:5], ["decision=CONVERT", "writes=4"])
    check("(a) the bound receipt evidence is reported",
          (good.evidence["attempt_class"], good.evidence["receipt_generation"],
           good.evidence["head_unchanged_since_park"]), ("defect", 2, head))

    # ---- (b) ANY human touch => SKIP (three separate variants) ------------------------------
    human_apply = decide(pr_timeline=[
        label_event("labeled", "review:needs-user", LABEL_AT, login=human)])
    check("(b1) a HUMAN-APPLIED hold => skip", human_apply.decision, "skip")
    check("(b1) ...and the reason names the human application",
          any("applied by the PROVEN HUMAN" in f for f in human_apply.failures), True)
    check("(b1) ...and NOTHING is planned", human_apply.plan, [])

    human_remove = decide(pr_timeline=[
        label_event("unlabeled", "review:needs-user", "2026-07-19T10:00:00Z", login=human),
        label_event("labeled", "review:needs-user", LABEL_AT)])
    check("(b2) an EARLIER human REMOVAL of the same hold => skip (any touch, not "
          "most-recent-wins)", human_remove.decision, "skip")
    check("(b2) ...and the reason names the human unlabel",
          any("TOUCHED a park-ownership label" in f and "unlabeled" in f
              for f in human_remove.failures), True)

    human_comment = decide(pr_comments=(
        missed_comments(limit) + [receipt_comment(RECEIPT_AT),
                                 {"user": {"login": human},
                                  "created_at": "2026-07-20T10:00:00Z",
                                  "body": "looks fine to me"}]))
    check("(b3) a HUMAN COMMENT on the PR => skip", human_comment.decision, "skip")
    check("(b3) ...and the reason is the human voice gate",
          any("a non-bot actor spoke on this PR" in f and "PROVEN HUMAN jeswr" in f
              for f in human_comment.failures), True)

    human_on_issue = decide(issue_timeline=[
        label_event("labeled", "needs:user", LABEL_AT),
        label_event("unlabeled", "status:parked", "2026-07-19T09:00:00Z", login=human)])
    check("(b4) a human touch on the SOURCE ISSUE's machine park => skip",
          (human_on_issue.decision,
           any("issue#7 unlabeled status:parked" in f for f in human_on_issue.failures)),
          ("skip", True))
    human_review = decide(pr_timeline=[
        label_event("labeled", "review:needs-user", LABEL_AT),
        {"event": "reviewed", "created_at": "2026-07-20T09:40:00Z",
         "user": {"login": human}}])
    check("(b5) a human REVIEW => skip", (human_review.decision,
          any("reviewed" in f for f in human_review.failures)), ("skip", True))
    notification_only = decide(pr_timeline=[
        label_event("labeled", "review:needs-user", LABEL_AT),
        {"event": "mentioned", "created_at": LABEL_AT, "actor": {"login": human}},
        {"event": "subscribed", "created_at": LABEL_AT, "actor": {"login": human}}])
    check("(b6) the bot's own @mention/subscribe of the maintainer is NOT a human touch",
          notification_only.decision, "convert")
    novel_event = decide(pr_timeline=[
        label_event("labeled", "review:needs-user", LABEL_AT),
        {"event": "some_future_gesture", "created_at": LABEL_AT, "actor": {"login": human}}])
    check("(b7) an UNRECOGNISED human event kind fails toward skip (allow-list)",
          novel_event.decision, "skip")

    # ---- unverifiable / App actors ----------------------------------------------------------
    no_login = decide(pr_timeline=[
        {"event": "labeled", "label": {"name": "review:needs-user"}, "created_at": LABEL_AT,
         "actor": None}])
    check("an application by an UNVERIFIABLE actor is not 'the bot' => skip",
          (no_login.decision,
           any("was not made by the orchestrator bot" in f for f in no_login.failures)),
          ("skip", True))
    other_bot = decide(pr_timeline=[
        label_event("labeled", "review:needs-user", LABEL_AT, login="dependabot[bot]")])
    check("an application by a DIFFERENT bot is not 'the bot' => skip", other_bot.decision,
          "skip")
    no_bot_login = decide(bot_login="")
    check("no orchestrator bot login supplied => skip (nothing can be attributed)",
          (no_bot_login.decision,
           any("no orchestrator bot login was supplied" in f
               for f in no_bot_login.failures)), ("skip", True))

    # ---- PROBE INDEPENDENCE: the decision never relies on the maintainer probe --------------
    raising = lambda login: (_ for _ in ()).throw(RuntimeError("HTTP 403"))  # noqa: E731
    denying = lambda login: False                                            # noqa: E731
    probe_raises = classify(base_evidence(), policy, worker_pr, limit, is_human=raising,
                            log=lambda *a, **k: None)
    check("a RAISING maintainer probe cannot invent a human touch (still converts on a "
          "bot-only PR)", probe_raises.decision, "convert")
    touched = dict(pr_timeline=[
        label_event("unlabeled", "review:needs-user", "2026-07-19T10:00:00Z", login=human),
        label_event("labeled", "review:needs-user", LABEL_AT)])
    verdicts = {name: classify(base_evidence(**touched), policy, worker_pr, limit,
                               is_human=probe, log=lambda *a, **k: None).decision
                for name, probe in (("trusted", trusted), ("denying", denying),
                                    ("raising", raising), ("absent", None))}
    check("a human-touched hold SKIPS under EVERY probe outcome — trusted, denying, raising, "
          "absent (park_policy's unprovable=>not-human direction would be backwards here)",
          verdicts,
          {"trusted": "skip", "denying": "skip", "raising": "skip", "absent": "skip"})
    check("...and a DENYING probe still names the actor honestly as unverified",
          any("unverified non-bot actor jeswr" in f
              for f in classify(base_evidence(**touched), policy, worker_pr, limit,
                                is_human=denying,
                                log=lambda *a, **k: None).failures), True)
    check("possibly_human: only a [bot] login or an App-driven event is provably not a person",
          [possibly_human("jeswr", False), possibly_human("", False),
           possibly_human("x[bot]", False), possibly_human("jeswr", True)],
          [True, True, False, False])

    # ---- (c) head advanced ------------------------------------------------------------------
    advanced = decide(head_sha=other_head)
    check("(c) the head ADVANCED since the park => skip", advanced.decision, "skip")
    check("(c) ...and the reason names both SHAs",
          any("the head ADVANCED since the park" in f and other_head[:12] in f
              for f in advanced.failures), True)
    bad_head = decide(head_sha="not-a-sha")
    check("(c2) an unreadable live head SHA => skip",
          (bad_head.decision, any("live head SHA is unreadable" in f
                                  for f in bad_head.failures)), ("skip", True))

    # ---- (d) a genuinely consumed budget is NOT this defect ---------------------------------
    round_budget = decide(pr_comments=[receipt_comment(RECEIPT_AT, attempt="rounds=5")])
    check("(d1) an escalation from a CONSUMED ROUND BUDGET => skip", round_budget.decision,
          "skip")
    check("(d1) ...and the reason names the round-budget class",
          any("'rounds=5' (round-budget)" in f for f in round_budget.failures), True)
    nochange = decide(pr_comments=[receipt_comment(RECEIPT_AT, attempt="nochange2=2")])
    check("(d2) an escalation from fix rounds that actually RAN => skip",
          (nochange.decision, any("(consumed-work)" in f for f in nochange.failures)),
          ("skip", True))
    novel_attempt = decide(pr_comments=[receipt_comment(RECEIPT_AT, attempt="future=1")])
    check("(d3) an UNRECOGNISED attempt grammar => skip",
          (novel_attempt.decision, any("(unknown)" in f for f in novel_attempt.failures)),
          ("skip", True))
    disagreeing = decide(pr_comments=(missed_comments(limit - 1)
                                      + [receipt_comment(RECEIPT_AT)]))
    check("(d4) the receipt's claimed lifetime count must MATCH the durable markers",
          (disagreeing.decision,
           any("two durable families DISAGREE" in f for f in disagreeing.failures)),
          ("skip", True))

    # ---- (e) missing / unreadable receipts and surfaces -------------------------------------
    no_receipt = decide(pr_comments=missed_comments(limit))
    check("(e1) NO park-generation receipt => skip (the pre-receipt population)",
          (no_receipt.decision,
           any("NO durable bot-authored park-generation receipt" in f
               for f in no_receipt.failures)), ("skip", True))
    forged = decide(pr_comments=(missed_comments(limit)
                                 + [receipt_comment(RECEIPT_AT, login="attacker")]))
    check("(e2) a NON-BOT-authored receipt is invisible to the parser => skip",
          forged.decision, "skip")
    malformed_receipt = decide(pr_comments=(
        missed_comments(limit) + [receipt_comment(RECEIPT_AT, window="not-a-timestamp")]))
    check("(e3) a MALFORMED receipt cutoff drops the receipt => skip",
          malformed_receipt.decision, "skip")
    no_fingerprint = decide(pr_comments=(missed_comments(limit) + [
        {"user": {"login": bot}, "created_at": RECEIPT_AT,
         "body": f"x {worker_pr.PARK_GENERATION_MARKER} gen=2 "
                 f"cutoff=2026-07-20T08:00:00Z -->"}]))
    check("(e4) a LEGACY receipt with no attempt fingerprint => skip",
          (no_fingerprint.decision,
           any("no parseable attempt fingerprint" in f for f in no_fingerprint.failures)),
          ("skip", True))
    stale_receipt = decide(pr_comments=(missed_comments(limit)
                                        + [receipt_comment("2026-07-19T09:00:00Z")]))
    check("(e5) a receipt too OLD to have bound this label write => skip",
          (stale_receipt.decision,
           any("no park-generation receipt binds the label application" in f
               for f in stale_receipt.failures)), ("skip", True))
    non_terminal = decide(pr_comments=(missed_comments(limit)
                                       + [receipt_comment(RECEIPT_AT, generation=1)]))
    check("(e6) a NON-TERMINAL (generation 1) receipt writes the machine label, so it cannot "
          "explain a human hold => skip",
          (non_terminal.decision,
           any("below the terminal escalation" in f for f in non_terminal.failures)),
          ("skip", True))
    malformed_timeline = decide(pr_timeline=[
        {"event": "labeled", "label": {"name": "review:needs-user"}, "created_at": "zzz",
         "actor": {"login": bot}}])
    check("(e7) an UNREADABLE label timeline => skip",
          (malformed_timeline.decision,
           any("label timeline could not be read" in f
               for f in malformed_timeline.failures)), ("skip", True))
    no_provenance = decide(issue=None, issue_labels=None, issue_timeline=None,
                           issue_error="no registry provenance record exists for this PR")
    check("(e8) an unresolvable SOURCE ISSUE => skip",
          (no_provenance.decision,
           any("G1 source-issue" in f for f in no_provenance.failures)), ("skip", True))
    no_hold = decide(pr_labels=set(), issue_labels=set())
    check("(e9) no live human hold => skip (nothing in scope)",
          (no_hold.decision, any("G0 scope" in f for f in no_hold.failures)), ("skip", True))

    # ---- every failure is reported, not just the first --------------------------------------
    multi = decide(head_sha=other_head,
                   pr_comments=[receipt_comment(RECEIPT_AT, attempt="rounds=5")],
                   pr_timeline=[label_event("labeled", "review:needs-user", LABEL_AT),
                                {"event": "reviewed", "created_at": LABEL_AT,
                                 "user": {"login": human}}])
    check("every failed gate is reported for a human reader",
          sorted(f.split(":")[0] for f in multi.failures),
          ["G4 no-human-voice", "G5 defect-signature", "G6 head-unadvanced"])

    # ---- (f) DRY RUN performs ZERO writes ---------------------------------------------------
    # The stubs RECORD rather than raise, so a regression that lets the dry run write shows the
    # exact writes it would have made instead of an opaque traceback. BOTH lists are asserted:
    # `attempted` catches a write that reached GitHub, `performed` catches the bookkeeping.
    attempted = []
    dry = LabelWriter(False,
                      add_label=lambda r, n, label: attempted.append(("add", r, n, label)),
                      remove_label=lambda r, n, label: attempted.append(("remove", r, n, label)))
    check("(f) a DRY RUN over a convertible plan performs 0 writes", dry.run(good.plan), 0)
    check("(f) ...and NO write reached the GitHub seam", attempted, [])
    check("(f) ...and the PERFORMED write list is EMPTY", dry.performed, [])

    # ---- (g) the apply path converts to the MACHINE class and nothing else ------------------
    calls = []
    live = LabelWriter(True,
                       add_label=lambda r, n, label: calls.append(("add", r, n, label)),
                       remove_label=lambda r, n, label: calls.append(("remove", r, n, label)))
    check("(g) the apply path performs exactly the planned writes", live.run(good.plan), 4)
    check("(g) ...in add-then-remove order, machine twins in / human holds out", calls,
          [("add", "o/r", 41, "review:parked"), ("add", "o/r", 7, "status:parked"),
           ("remove", "o/r", 41, "review:needs-user"), ("remove", "o/r", 7, "needs:user")])
    check("(g) ...and `performed` mirrors them exactly", live.performed, calls)
    check("(g) an unknown write op is REFUSED",
          _raises(lambda: LabelWriter(True, add_label=lambda *a: None,
                                      remove_label=lambda *a: None).run(
                                          [("arm", "o/r", 41, "x")]), ReclassError), True)

    # ---- scope: the write vocabulary can never widen ----------------------------------------
    machine_labels = set(_label_map(policy).values())
    human_labels = set(_label_map(policy))
    every_plan = plan_writes(policy, [("o/r", 41, "review:needs-user"),
                                      ("o/r", 7, "needs:user")])
    check("the ONLY adds are machine twins",
          {label for op, _r, _n, label in every_plan if op == "add"}, machine_labels)
    check("the ONLY removes are the human holds",
          {label for op, _r, _n, label in every_plan if op == "remove"}, human_labels)
    check("no op other than add/remove exists in any plan",
          {op for op, _r, _n, _l in every_plan}, {"add", "remove"})
    check("a machine park is NEVER removed",
          machine_labels & {label for op, _r, _n, label in every_plan if op == "remove"},
          set())

    # ---- fingerprint + attempt-class parsing ------------------------------------------------
    check("fingerprint splits on the FIRST separator with a 40-hex head",
          split_fingerprint(f"{head}/missed3=6"), (head, "missed3=6"))
    check("an attempt counter containing a slash still parses",
          split_fingerprint(f"{head}/a/b"), (head, "a/b"))
    check("a non-hex head proves nothing", split_fingerprint("nothex/missed3=6"), (None, None))
    check("a fingerprint with no separator proves nothing", split_fingerprint(head),
          (None, None))
    check("attempt classes", [attempt_class(k) for k in
                              ("missed3=6", "rounds=5", "nochange2=2", "gatefail1=1", "x", "")],
          ["defect", "round-budget", "consumed-work", "consumed-work", "unknown", "unknown"])
    check("a park_fingerprint round-trips through split_fingerprint",
          split_fingerprint(policy.park_fingerprint(head, f"missed3={limit}")),
          (head, f"missed3={limit}"))

    # ---- the real provenance admission is used, never replicated ----------------------------
    valid = {"pr_number": 41, "impl_provider": "anthropic", "impl_alias": "fable",
             "impl_account_h": "ab" * 8, "issue": 7, "head_sha_at_open": "ab" * 20}
    probes = []

    def probe(registry_repo, path, ref=None):
        probes.append(ref)
        return (json.dumps(valid), "sha") if ref == worker_pr.LEDGER_REF else (None, None)

    saved = worker_pr._probe_registry_file
    try:
        worker_pr._probe_registry_file = probe
        check("the source issue comes from the LEDGER provenance record",
              source_issue(worker_pr, dispatch_claim.provenance_admission_error, "o/reg",
                           "o/r", 41), (7, None))
        check("  ...ledger probed first", probes, [worker_pr.LEDGER_REF])
        worker_pr._probe_registry_file = lambda *a, **k: (json.dumps(
            {**valid, "issue": 0}), "sha")
        bad_issue = source_issue(worker_pr, dispatch_claim.provenance_admission_error, "o/reg",
                                 "o/r", 41)
        check("an INADMISSIBLE record yields an error, never a guessed issue",
              (bad_issue[0], bad_issue[1] is not None), (None, True))
        worker_pr._probe_registry_file = lambda *a, **k: ("{not json", "sha")
        check("an undecodable record yields an error",
              source_issue(worker_pr, dispatch_claim.provenance_admission_error, "o/reg",
                           "o/r", 41),
              (None, "the registry provenance record is not valid JSON"))
        worker_pr._probe_registry_file = lambda *a, **k: (None, None)
        check("an ABSENT record yields an error",
              source_issue(worker_pr, dispatch_claim.provenance_admission_error, "o/reg",
                           "o/r", 41),
              (None, "no registry provenance record exists for this PR"))
    finally:
        worker_pr._probe_registry_file = saved

    # ---- enumeration reads the LIST API and fails closed on shape --------------------------
    listing = [[{"number": 3, "pull_request": {"url": "u"}}, {"number": 4}],
               [{"number": 5, "pull_request": {}}]]
    check("only PULL REQUESTS are enumerated, newest first (an EMPTY pull_request object is "
          "still a PR)",
          _open_holds(lambda args: listing, "o/r", "review:needs-user"), [5, 3])
    check("a malformed listing fails closed",
          _raises(lambda: _open_holds(lambda args: [[1]], "o/r", "x"), ReclassError), True)

    # ---- advisory indicators are reported but never gate ------------------------------------
    check("the missed-marker advisory is reported",
          decide().advisory["missed_markers"], [f"missed3={limit}"])
    check("...and a maxed advisory alone can NEVER convert (no receipt)",
          decide(pr_comments=missed_comments(limit + 3)).decision, "skip")

    print("reclass-park-holds self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _raises(thunk, exc_type):
    try:
        thunk()
    except exc_type:
        return True
    except Exception:  # noqa: BLE001 — a DIFFERENT exception is not the assertion under test
        return False
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Reclassify human-hold park labels the fixed capacity-park defect "
                    "manufactured (dry run unless --apply).")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--target-repo", default="sparq-org/sparq")
    parser.add_argument("--registry-repo", default="jeswr/agent-account-registry")
    parser.add_argument("--bot-login", default="sparq-orchestrator[bot]",
                        help="the durable-receipt trust filter (bot-authored receipts only)")
    parser.add_argument("--pr", type=int, action="append", default=[],
                        help="restrict the sweep to these PR numbers (repeatable)")
    parser.add_argument("--apply", action="store_true",
                        help="actually reclassify (default: DRY RUN — reports only, zero "
                             "writes)")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    try:
        sweep(args.target_repo, args.registry_repo, args.bot_login, args.apply, only=args.pr)
    except ReclassError as exc:
        print(f"reclass-park-holds: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
