#!/usr/bin/env python3
"""[registry #446] The STUCK-ESCALATION AUTO-ADJUDICATOR: a bounded sweep that drains PRs held in
the HUMAN terminal (`review:needs-user`) for a MACHINE reason, and gives every park it does NOT
drain a machine-readable reason.

THE STALL. Measured 2026-07-19: 36 open PRs (19 sparq + 17 registry) terminally parked on
`review:needs-user`, and nothing auto-resolved any of them. The review loop parks there on
round-budget exhaustion and on parks that recorded no cause at all, both of which are MACHINE
outcomes; `review:needs-user` is HUMAN-owned (park_policy invariant 3), so the only exit was the
maintainer. The active review set drained and merges stopped.

WHAT "ADJUDICATION" IS HERE, AND WHERE IT IS NOT. The adjudication that decides whether such a PR
is actually good is a CROSS-PROVIDER, ORCHESTRATOR-TIER READ OF THE DIFF — and the review lane
already is exactly that: review-fix.yml picks the OPPOSITE provider from the implementer at the
orchestrator tier, reads the diff plus the prior round's recorded verdict, grades progress, and
routes its result through the existing arm gate (trust surfaces human-arm, security surfaces never
auto-arm). So this sweep does NOT run a second judge and does NOT decide correctness. It decides
the ONE question the review lane cannot ask for itself, because a human-owned label is in the way:

    may this PR re-enter the loop at all, and with what budget?

  * `return-to-loop` — nothing human owns this hold and the park cause is machine-owned. The PR
    returns to `review:needs` with a REAL budget window, and the cross-provider re-review that
    buys is the adjudication. If that review approves, the EXISTING arm gate arms it — that is the
    "override-arm" outcome, reached through the gate rather than around it.
  * `genuinely-human` — anything else. The PR stays exactly where it is and gains a durable,
    machine-readable reason marker, so "36 parked PRs" stops being an undifferentiated pile.

THERE IS DELIBERATELY NO THIRD DISPOSITION. This sweep cannot arm, cannot label `review:pass`,
cannot touch a test, a gate, or a verdict. A second authority that could arm a PR by declaring a
reviewer's finding spurious IS the "weaken a trust check to arm" failure the issue's own guardrail
forbids, and it would be strictly weaker than the gate it bypassed. `_self_test` asserts the
disposition set stays closed at two.

FAIL-CLOSED, AND BOUNDED. `admission` is PURE and refuses on every ambiguity — an unreadable
timeline, a park-reason marker that failed validation, a `needs:*` hold that would survive the
move, a trust surface with a live blocking finding. Re-admissions are counted with the SAME
counter that bounds automatic re-admission everywhere else
(worker-pr.auto_readmission_marker_count against park_policy.AUTO_READMISSION_MAX), so the two can
never drift and this can never become a treadmill: past the cap the PR stays human, permanently.
The ONE exception is an unfinished transaction OF THIS SWEEP'S OWN (`incomplete_readmission`): a
receipt whose writes never reached the commit has ALREADY spent its slot, so refusing to finish it
leaves the PR stranded one write short of done while the cap counts the very receipt that stranded
it. Finishing grants no budget and posts no second receipt, and it is allowed only on proof that
the still-live hold PREDATES the receipt — a hold applied after it is a NEW park and the cap
stands, so the exception cannot become the treadmill the cap exists to prevent.
Because the granted window is a MACHINE window, registry #797's window-authority attribution
charges it to the MACHINE ladder — a PR that fails its adjudicated round lands on the machine
terminal (retire, hand the issue back for decomposition), never back in the maintainer's inbox.

WHO COUNTS AS HUMAN IS THE SHARED DEFINITION, NOT A LOGIN. Every ownership decision runs the
strict collaborator-permission probe (`MaintainerProbe` -> park_policy.probe_maintainer:
permission in {admin, maintain, write}) that worker-pr / dispatch-claim / groom / curate-frontier
already run. An equality test against one configured handle would call every OTHER authorized
maintainer a machine — and this sweep DELETES holds it believes a machine applied, so that is a
licence to erase a second maintainer's gesture. And because label_application_machine_owned reads
"unverifiable actor" as MACHINE, a probe call that cannot COMPLETE is remembered and refuses here
(`hold_machine_owned`): everywhere else that direction only suppresses a veto, but here it would
authorise a delete.

DRY-RUN IS THE DEFAULT. `--apply` is required to write anything.

THE WRITE PATH IS A TRANSACTION, AND IT COMMITS LAST. Nothing here is atomic with anything else,
so the write path is built so that every state it can die in is either COMPLETE or still VISIBLE
to the next sweep:

  * MUTATION BOUNDARY. Every decision above is re-derived from a label + timeline read taken
    immediately before the FIRST write, through the SAME pure `admission`. A hold whose live
    application is no longer provably machine-owned stands the whole transaction down, mutating
    nothing — a stale ownership proof never authorises a delete.
  * COMMIT LAST. `readmission_writes` orders the transaction receipt -> `review:needs` ->
    the issue's `needs:user` -> and only THEN the PR's `review:needs-user`. That last delete is
    the label this sweep's own listing filters on, so a failure at any earlier point leaves the PR
    still listed and `readmission_writes` re-plans exactly the missing writes from LIVE state on
    the next sweep. The receipt suppresses only the COMMENT, never the label writes, so an
    incomplete transaction can never be mistaken for a finished one and reconciliation never
    spends a second automatic re-admission.
  * DETECT AND REPAIR THE UN-CLOSEABLE WINDOW. A label carries no per-application identity, so a
    human application landing between the ownership re-check and the DELETE would be erased with
    no trace in the live label set. The TIMELINE keeps it (an `unlabeled` never erases a
    `labeled`), so `clear_hold_with_repair` re-reads ownership AFTER the delete and PUTS THE HOLD
    BACK when it can no longer prove the application it deleted was the machine's. The restoration
    posts a `hold-restored` receipt, and that marker — not the timeline, which now shows the bot
    as the latest applier — is what makes the restored human gesture STICKY forever.
"""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import park_policy

ADJUDICATION_MARKER = "<!-- sparq-adjudication:v1"

# THE CLOSED DISPOSITION SET. Two members, and the reason a third is absent is in the module
# docstring. Every consumer may assume this set never grows to include an arming action.
RETURN_TO_LOOP = "return-to-loop"
GENUINELY_HUMAN = "genuinely-human"
DISPOSITIONS = (RETURN_TO_LOOP, GENUINELY_HUMAN)

# The label that re-enters the review lane. `review:needs` is dispatch-claim's authoritative
# re-entry signal for a FRESH cross-provider review round (enumerate_review_items), which is what
# an adjudication needs — not `review:changes`, which dispatches a FIX seeded from a recorded
# verdict that the park has already proven inconclusive.
REENTRY_LABEL = "review:needs"

# THE CLOSED REASON TAXONOMY: code -> (disposition, sentence). A code outside it is never written
# and never read as a decision — `adjudication_marker` raises and `parse_adjudication` drops the
# marker, the same doctrine park_policy.parse_park_reason applies to a park cause.
ADJUDICATION_REASONS = {
    # --- machine-owned parks: the population this sweep exists to drain --------------------
    "budget-park": (RETURN_TO_LOOP,
                    "the park records a CAPACITY-class cause (a spent round budget or another "
                    "machine outcome), which is not a maintainer question"),
    "silent-park": (RETURN_TO_LOOP,
                    "the park recorded NO cause at all — a silent escalation, which cannot be a "
                    "human decision because no decision was written down"),
    # --- genuine human questions, and every ambiguity ---------------------------------------
    "not-parked": (GENUINELY_HUMAN, "no live `review:needs-user` — nothing to adjudicate"),
    "deny-prose": (GENUINELY_HUMAN,
                   "an injection or human-arm signal is recorded on this PR; no machine path may "
                   "ever re-admit those causes, at any position in the history"),
    "human-applied": (GENUINELY_HUMAN,
                      "a PROVEN human applied the hold — a human decision is not the machine's "
                      "to undo (and an unreadable timeline counts as human)"),
    "hold-restored": (GENUINELY_HUMAN,
                      "a human applied a hold on this PR or its source issue inside the window "
                      "between a re-admission's ownership proof and its DELETE; the sweep put "
                      "that hold back, and a restored human gesture is sticky at every later "
                      "position in the history"),
    "question-cause": (GENUINELY_HUMAN,
                       "the park records a QUESTION-class cause, which by taxonomy has no "
                       "machine exit"),
    "unclassified-park": (GENUINELY_HUMAN,
                          "a park-reason marker is present but failed validation, so the park is "
                          "unclassified — every consumer reads that as a human question"),
    "residual-hold": (GENUINELY_HUMAN,
                      "a human-owned hold would still be live after the move, so re-admitting "
                      "would trade a visible stall for a silent one"),
    "machine-park-live": (GENUINELY_HUMAN,
                          "a MACHINE park is also live on this PR or its source issue "
                          "(`review:parked` / `status:parked`), and the review lane excludes any "
                          "parked PR outright; whichever mechanism applied that park owns its "
                          "exit, so re-admitting here would be a silent no-op relabel that also "
                          "raced another sweep"),
    "issue-hold-human": (GENUINELY_HUMAN,
                         "the source issue's `needs:user` is human-owned or unprovable; the "
                         "review lane excludes any PR whose issue carries a `needs:*` hold, so "
                         "re-admitting the PR alone would be a no-op relabel"),
    "readmissions-spent": (GENUINELY_HUMAN,
                           "this PR has already spent every automatic re-admission "
                           "`AUTO_READMISSION_MAX` allows; more machine retries is not an answer"),
    "no-round-history": (GENUINELY_HUMAN,
                         "no review round was ever recorded, so this is not a round-budget or "
                         "silent park — something else put it here and that something is unread"),
    "trust-surface-finding": (GENUINELY_HUMAN,
                              "this is a ZK/MPC/security/trust surface and its last verdict "
                              "carries (or may carry) a blocking finding — those default to the "
                              "maintainer unless the standoff is provably not substantive"),
}

BLOCKING_SEVERITIES = frozenset({"blocker", "critical", "major"})

_ADJUDICATION_RE = re.compile(
    re.escape(ADJUDICATION_MARKER)
    + r" disposition=(\S+) reason=(\S+) head=(\S+) episode=(\S+) -->")


def _load(modname, filename):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _quiet(*_args, **_kwargs):
    return None


def admission(*, pr_labels, issue_labels, park_records, park_marker_present, bot_bodies,
              hold_applied_by_human, hold_restored, issue_hold_machine_owned, rounds_recorded,
              readmissions_spent, readmission_in_flight, trust_surface, blocking_findings):
    """PURE. (disposition, reason, detail) — may this PR re-enter the review loop?

    `disposition` is a member of DISPOSITIONS and `reason` is a key of ADJUDICATION_REASONS whose
    registered disposition equals it; every branch below is one of those keys, so the marker
    writer can never be handed a code it must reject.

    Every refusal is a REFUSAL CONDITION: anything unproven leaves the PR exactly where it is.
    The caller MUST fail closed on each probe it cannot complete — `hold_applied_by_human=True`
    when the timeline is unreadable, `issue_hold_machine_owned=False` when the issue's label
    ownership is unprovable, `trust_surface=True` when the keyword union cannot be loaded,
    `blocking_findings=None` when the last verdict record cannot be read, and
    `readmission_in_flight=False` on every unknown, because that one flag is the only input here
    that can WIDEN an outcome rather than narrow it (`incomplete_readmission` owns that proof and
    returns False for every ambiguity).

    `park_records` is park_policy.park_reason_records output (oldest first, bot-authored only);
    `park_marker_present` is whether the BOT's history contains a raw PARK_REASON_MARKER at all,
    which is what separates a SILENT park (no marker — drainable) from a park whose marker was
    REJECTED by validation (unclassified — a human question). Reading only the parsed records
    would collapse those two into one and drain the dangerous half.

    `blocking_findings` is the count of blocker/critical/major findings in the LATEST recorded
    verdict, or None when that record is unreadable. It gates ONLY the trust-surface guardrail: a
    non-trust PR with real findings is precisely the "real but fixable" case that belongs back in
    the loop.

    `hold_restored` is whether a previous sweep ever RESTORED a hold on this PR after detecting a
    human application inside the un-closeable write window (`clear_hold_with_repair`). It refuses
    unconditionally and order-independently, exactly like the deny signal, because the restoration
    itself destroys the evidence every other probe reads: the label was re-applied BY THE BOT, so
    `hold_applied_by_human` is False and the timeline names a machine. The receipt is the only
    surviving record that a human ever made the gesture, so it — and not the timeline — decides."""
    def out(reason, extra=""):
        disposition, sentence = ADJUDICATION_REASONS[reason]
        return (disposition, reason, f"{sentence}{extra}")

    if park_policy.HUMAN_PR_PARK_LABEL not in set(pr_labels or []):
        return out("not-parked")
    # DENY FIRST, unconditionally and order-independently (park_policy.LEGACY_PARK_DENY_PROSE):
    # a capacity comment landing after a security escalation must never talk a park out of the
    # terminal, whichever order the two were written in.
    for body in bot_bodies or []:
        for pattern, denied in park_policy.LEGACY_PARK_DENY_PROSE:
            if pattern.search(str(body)):
                return out("deny-prose", f" (signal: {denied})")
    # ...and the RESTORED-HOLD signal beside it, for the same order-independent reason: it is the
    # only evidence that survives a restoration, and it must outrank every later machine event.
    if hold_restored:
        return out("hold-restored")
    if hold_applied_by_human:
        return out("human-applied")
    records = [record for record in (park_records or []) if isinstance(record, dict)]
    if records:
        latest = records[-1]
        cause = str(latest.get("cause", ""))
        # Trust the CLASS the taxonomy assigns the cause, never the class the marker claims —
        # parse_park_reason has already rejected any marker where the two disagree, so a record
        # reaching here is self-consistent, and re-deriving keeps it that way if that changes.
        if park_policy.park_cause_class(cause) != park_policy.PARK_CLASS_CAPACITY:
            return out("question-cause", f" (cause: {cause or 'unknown'})")
        machine_reason = "budget-park"
        machine_extra = f" (cause: {cause})"
    elif park_marker_present:
        return out("unclassified-park")
    else:
        machine_reason = "silent-park"
        machine_extra = ""
    residual = park_policy.migration_residual_holds(
        set(pr_labels or []) - {park_policy.HUMAN_PR_PARK_LABEL}, set(issue_labels or []),
        clearing=[park_policy.HUMAN_PARK_LABEL])
    if residual:
        return out("residual-hold", f" ({'/'.join(residual)})")
    # A re-admission that the review lane will not act on is worse than no re-admission: it
    # reads as "drained" in every count while the PR stays exactly as stuck. dispatch-claim's
    # enumerate_review_items excludes a PR outright when EITHER machine park label is live, so
    # this sweep must not move a PR that is also machine-parked — that park has its own owner and
    # its own exit (capacity_park_admission / the cause-gated sweeps), and racing them is how two
    # mechanisms end up half-clearing one park.
    machine_parks = ({park_policy.MACHINE_PARK_PR_LABEL} & set(pr_labels or [])) | \
                    ({park_policy.MACHINE_PARK_LABEL} & set(issue_labels or []))
    if machine_parks:
        return out("machine-park-live", f" ({'/'.join(sorted(machine_parks))})")
    if park_policy.HUMAN_PARK_LABEL in set(issue_labels or []) and not issue_hold_machine_owned:
        return out("issue-hold-human")
    # THE CAP, and its ONE exception. A corrupt counter always refuses. A counter AT the cap
    # refuses too — UNLESS this sweep's own previous transaction for this head provably never
    # reached its commit (`readmission_in_flight`, from `incomplete_readmission`). That receipt
    # already spent the slot it is being charged for, and FINISHING it posts no second receipt and
    # grants no second window (`readmission_writes` plans no comment once the marker exists), so
    # refusing here does not conserve budget — it just strands the PR one write short of done,
    # forever, on the strength of the receipt that stranded it.
    if not isinstance(readmissions_spent, int) or isinstance(readmissions_spent, bool) \
            or (readmissions_spent >= park_policy.AUTO_READMISSION_MAX
                and not readmission_in_flight):
        return out("readmissions-spent",
                   f" ({readmissions_spent} of {park_policy.AUTO_READMISSION_MAX} spent)")
    if not isinstance(rounds_recorded, int) or isinstance(rounds_recorded, bool) \
            or rounds_recorded < 1:
        return out("no-round-history")
    # THE TRUST-SURFACE DEFAULT (issue #446 guardrail). `!= 0` and not `> 0`: an unreadable
    # verdict record arrives as None and must block, exactly like a real blocker would.
    if trust_surface and blocking_findings != 0:
        found = "unreadable" if blocking_findings is None else f"{blocking_findings} finding(s)"
        return out("trust-surface-finding", f" ({found})")
    return out(machine_reason, machine_extra)


def adjudication_marker(disposition, reason, head, episode):
    """The durable, machine-readable record of one adjudication decision.

    Raises on anything outside the closed taxonomy or on a part that could break out of the
    `... key=<value> -->` grammar every receipt reader keys on (park_policy.safe_receipt_part) —
    a marker is only worth reading if it could not have been written wrong."""
    registered = ADJUDICATION_REASONS.get(reason)
    if registered is None:
        raise ValueError(f"adjudication reason {reason!r} is outside the closed taxonomy")
    if registered[0] != disposition:
        raise ValueError(f"reason {reason!r} belongs to disposition {registered[0]!r}, "
                         f"not {disposition!r}")
    for part in (str(head), str(episode)):
        if not park_policy.safe_receipt_part(part):
            raise ValueError("adjudication marker parts must be safe receipt parts")
    return (f"{ADJUDICATION_MARKER} disposition={disposition} reason={reason} "
            f"head={head} episode={episode} -->")


def parse_adjudication(body):
    """The LAST well-formed adjudication marker in `body`, else None. A marker whose disposition
    disagrees with its reason's registered disposition is DROPPED, not repaired: the dangerous
    direction is obvious, and a self-contradicting receipt is evidence of corruption or forgery."""
    if not isinstance(body, str):
        return None
    found = None
    for match in _ADJUDICATION_RE.finditer(body):
        disposition, reason, head, episode = match.groups()
        registered = ADJUDICATION_REASONS.get(reason)
        if registered is None or registered[0] != disposition:
            continue
        found = {"disposition": disposition, "reason": reason,
                 "head": head, "episode": episode}
    return found


def adjudication_records(comments, bot_login):
    """Every well-formed adjudication marker across the BOT's OWN comments, oldest first. Only
    the orchestration bot's comments are receipts — a third party must not be able to fake a
    prior decision, nor to suppress one by posting a corrupt copy."""
    if not bot_login:
        return []
    records = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        if str((comment.get("user") or {}).get("login", "")).casefold() \
                != str(bot_login).casefold():
            continue
        record = parse_adjudication(str(comment.get("body", "")))
        if record:
            records.append(record)
    return records


def already_recorded(comments, bot_login, disposition, head):
    """True when THIS head already carries THIS disposition from a previous sweep. Idempotence,
    per head rather than per PR: a genuinely-human park is explained ONCE (no comment spam every
    15 minutes), and a head that has moved since is a new fact worth re-recording."""
    return any(record["disposition"] == disposition and record["head"] == str(head)
               for record in adjudication_records(comments, bot_login))


# The writes ONE return-to-loop transaction is made of, in the ONLY order that makes a partial
# failure recoverable. See `readmission_writes` for why the order is load-bearing.
READMISSION_WRITES = ("comment", "add-reentry", "clear-issue-hold", "delete-hold")


def readmission_writes(*, pr_labels, issue_labels, recorded, issue_hold_machine_owned):
    """PURE. The writes the return-to-loop transaction for this head STILL OWES, given the LIVE
    label state, in COMMIT-LAST order. Called only once `admission` has returned return-to-loop
    against that same live state, so every write below is already authorised.

    INTENT IS NOT COMPLETION. The receipt is posted FIRST — deliberately, so a crash leaves an
    explained, window-bearing PR rather than a silently relabelled one — which means the receipt
    exists in states where NONE of the label writes landed. Reading it as "this head is done" is
    what made a partial failure PERMANENT: the next sweep saw the marker, no-oped, and the PR
    stayed parked forever having spent an automatic re-admission it never received. So the receipt
    suppresses ONLY the comment; every label write is planned from live state and therefore
    reconciles itself, and because reconciliation posts no second receipt it cannot spend a second
    re-admission against the cap.

    THE ORDER IS THE INVARIANT, not a style choice. `delete-hold` removes the very label this
    sweep's listing query filters on, so it is the COMMIT: after it the PR is invisible to the
    next sweep and must therefore already be complete, and before it the PR is still listed and
    still reconcilable. Every other write is placed ahead of it:
      - `add-reentry` is monotone and cannot re-admit anything early — the review lane excludes a
        PR carrying the human hold outright, so `review:needs` sits inert until the commit.
      - `clear-issue-hold` likewise: dispatch dedupes issue re-dispatch behind the open worker PR
        (dispatch-claim._linked_open_pr_issues), so an issue unheld while its PR is still parked
        cannot relaunch a second worker.
    Move `delete-hold` earlier and a failure after it strands the PR outside every future sweep's
    listing — the exact terminal-park-forever outcome this ordering exists to make impossible."""
    live = {label for label in (pr_labels or []) if isinstance(label, str)}
    issue_live = {label for label in (issue_labels or []) if isinstance(label, str)}
    writes = []
    if not recorded:
        writes.append("comment")
    if REENTRY_LABEL not in live:
        writes.append("add-reentry")
    if park_policy.HUMAN_PARK_LABEL in issue_live and issue_hold_machine_owned:
        writes.append("clear-issue-hold")
    writes.append("delete-hold")
    return tuple(writes)


def newest_label_application(events, label):
    """PURE. The newest `labeled` instant for EXACTLY `label` in a timeline, or None.

    None means UNKNOWN — an unreadable timeline, a malformed event, a stamp that will not parse,
    or simply no application at all — and every consumer must read it as a refusal rather than as
    "the hold is old". `unlabeled` events are ignored on purpose: this answers "when was the hold
    that is live NOW put there", which is the question a re-application after a receipt changes."""
    newest = None
    try:
        for event in events if isinstance(events, list) else []:
            if not isinstance(event, dict) or event.get("event") != "labeled":
                continue
            if (event.get("label") or {}).get("name") != label:
                continue
            instant = park_policy.parse_ts(event.get("created_at"))
            if newest is None or instant > newest:
                newest = instant
    except Exception:  # noqa: BLE001 — a malformed timeline proves nothing
        return None
    return newest


def incomplete_readmission(*, recorded, receipt_stamps, hold_applied_at):
    """PURE. True when THIS head carries a re-admission of this sweep's own whose transaction
    provably NEVER COMMITTED, and which must therefore be finished rather than charged again
    against AUTO_READMISSION_MAX. This is the ONLY input to `admission` that can widen an
    outcome, so every unknown returns False and leaves the cap in force.

    THE PROOF is an ordering, because the labels cannot tell the two states apart. A transaction
    that died before its commit and a COMPLETED transaction whose PR the review lane later
    re-parked look identical live: the hold is on, `review:needs` is off. What separates them is
    WHICH APPLICATION of the hold is live. The commit is the DELETE of the hold, so:

      - receipt written AFTER the live application  -> that application is the one the receipt was
        written against, it is still there, so the delete never happened: IN FLIGHT.
      - live application written AFTER the receipt   -> the delete DID happen and something parked
        the PR again. That is a NEW park, the cap owns it, and re-admitting on the strength of an
        old receipt would be an unbounded treadmill at a fixed head.

    A same-instant tie refuses: GitHub stamps are second-resolution and cannot order that race.

    `recorded` is whether the head also carries this sweep's own RETURN_TO_LOOP adjudication
    marker. Both halves live in ONE comment (`readmission_body`), so requiring both is not
    belt-and-braces: it is what makes "reconciling spends nothing" STRUCTURAL, since the marker is
    exactly what makes `readmission_writes` plan no second `comment`."""
    if not recorded or hold_applied_at is None:
        return False
    newest = None
    for stamp in receipt_stamps or []:
        try:
            instant = park_policy.parse_ts(stamp)
        except Exception:  # noqa: BLE001 — an unreadable receipt time proves nothing
            return False
        if newest is None or instant > newest:
            newest = instant
    if newest is None:
        return False
    return newest > hold_applied_at


def clear_hold_with_repair(*, machine_owned_now, delete, restore):
    """Delete a human-owned hold a prior proof said the machine applied — and make a human
    application that lands in the race window DETECTABLE and RECOVERABLE.

    GitHub has no compare-and-swap on labels, and a label carries no per-application identity: a
    maintainer re-asserting the hold between an ownership proof and the DELETE is erased with no
    trace whatsoever in the live label set. The TIMELINE does keep it — an `unlabeled` event never
    erases a `labeled` one — so the race is detectable AFTER the write, and that is what makes it
    repairable. The protocol is therefore check -> delete -> re-check -> restore:

      - "stood-down": the re-check taken immediately before the delete already shows a human
        application. NOTHING is written; the hold stays and the caller abandons the transaction.
      - "cleared": the re-check taken AFTER the delete still proves machine ownership, so the
        application actually deleted was the machine's own.
      - "restored": it does not — a human application landed inside the un-closeable window (or
        the probe is unreadable, which fails the same way, because an unprovable answer must never
        authorise destroying a human gesture). The hold is PUT BACK and the caller must post the
        sticky `hold-restored` receipt: the restore re-applies the label AS THE BOT, so nothing in
        the timeline would stop the next sweep from deleting it all over again."""
    if not machine_owned_now():
        return "stood-down"
    delete()
    if machine_owned_now():
        return "cleared"
    restore()
    return "restored"


def blocking_finding_count(record):
    """Blocker/critical/major findings in a recorded review verdict, or None when the record is
    not readable as one. None means UNKNOWN and every consumer must treat it as blocking — a
    verdict we cannot read is not a verdict with no findings."""
    if not isinstance(record, dict):
        return None
    issues = record.get("issues")
    if not isinstance(issues, list):
        return None
    count = 0
    for issue in issues:
        if not isinstance(issue, dict):
            return None
        if str(issue.get("severity", "")).strip().casefold() in BLOCKING_SEVERITIES:
            count += 1
    return count


def latest_verdict(verdict_roots, repo, pr_number):
    """The highest-round recorded verdict for this PR across the ledger/master record roots, or
    None. Host-validated registry records only — the PR's own comments are never read for this."""
    owner, _, name = str(repo).partition("/")
    best = None
    pattern = re.compile(rf"^{re.escape(owner)}--{re.escape(name)}--pr{int(pr_number)}"
                         r"-round([1-9][0-9]*)\.json$")
    for root in verdict_roots:
        directory = Path(root)
        if not directory.is_dir():
            continue
        for path in directory.iterdir():
            match = pattern.match(path.name)
            if not match:
                continue
            round_n = int(match.group(1))
            if best is None or round_n > best[0]:
                best = (round_n, path)
    if best is None:
        return (None, None)
    try:
        return (best[0], json.loads(best[1].read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return (best[0], None)


def target_matrix(targets):
    """PURE. The Actions matrix this sweep fans out over: one entry per ENABLED policy target,
    split into the owner and name a per-repo App-token mint needs so each job holds a token
    scoped to exactly the one repository it sweeps. Raises on a name that is not `owner/repo` —
    a malformed row must fail the plan, never mint a wider token by accident."""
    entries = []
    for target in targets or []:
        owner, slash, name = str(target).partition("/")
        if not (owner and slash and name) or "/" in name:
            raise ValueError(f"policy target {target!r} is not an <owner>/<repo> name")
        entries.append({"repo": target, "owner": owner, "name": name})
    return entries


def human_park_body(reason, detail, head, episode):
    """The comment a `genuinely-human` park gains: the machine-readable reason the issue asked
    for, plus the prose that makes it auditable without re-deriving it."""
    return (
        "> 🤖 SPARQ agent — **stuck-escalation adjudication: leaving this park in place** "
        "(registry #446)\n\n"
        f"The auto-adjudicator swept this pull request's `{park_policy.HUMAN_PR_PARK_LABEL}` "
        "hold and is **leaving it exactly as it is**. No label, comment, verdict, or budget on "
        "this PR was changed by that decision — this comment is the only thing it wrote.\n\n"
        f"**Why it was not drained:** {detail}.\n\n"
        "The sweep re-admits a park only when it can prove nothing human owns it, that its cause "
        "is machine-owned, and that re-admitting would actually put the PR back in front of a "
        "reviewer. It cannot prove all three here, so it stops — and records WHY, so this park "
        "is now distinguishable from the rest of the parked population instead of being one more "
        "undifferentiated entry in it.\n\n"
        f"{adjudication_marker(GENUINELY_HUMAN, reason, head, episode)}")


def readmission_body(receipt, reason, detail, head, episode):
    """The comment a `return-to-loop` re-admission posts, RECEIPT FIRST: `receipt` is
    worker-pr.auto_readmission_receipt under the `adjudication/` evidence namespace (the budget
    window itself, in the one format every budget consumer already reads), and this appends the
    adjudication's own machine-readable decision. One comment, two markers, two readers — and a
    crash after it leaves an EXPLAINED PR whose window is already durable, rather than a silently
    relabelled one."""
    return (
        f"{receipt}\n\n"
        f"**Why this park was machine-owned:** {detail}.\n\n"
        f"**What happens next:** the hold moves to `{REENTRY_LABEL}` and the loop runs one "
        "cross-provider, orchestrator-tier review round against the current head. That review — "
        "not this sweep — decides the outcome, and its approval routes through the unchanged arm "
        "gate (a trust surface still human-arms; a security surface still never auto-arms). If "
        "it does not converge, the window this receipt opened is a MACHINE window, so the "
        "escalation ladder charges the MACHINE terminal (registry #797): the PR retires and the "
        "source issue is handed back for decomposition. It does not come back to you.\n\n"
        "A human can hold this PR again at any time by re-applying the label — that gesture is "
        "sticky and no automation may override it.\n\n"
        f"{adjudication_marker(RETURN_TO_LOOP, reason, head, episode)}")


def restored_hold_body(surface, head, episode):
    """The comment a RESTORED hold posts, and the only durable record that the human gesture it
    restored ever happened. `clear_hold_with_repair` puts the label back AS THE BOT, so from here
    on the timeline names a machine as the latest applier and every ownership probe would agree
    the hold is drainable — this marker is what makes the restored gesture STICKY instead."""
    return (
        "> 🤖 SPARQ agent — **stuck-escalation adjudication: a human hold was restored** "
        "(registry #446)\n\n"
        f"While this re-admission was mid-write, a human applied {surface}. A GitHub label "
        "carries no per-application identity, so the sweep's own DELETE removed that gesture — "
        "but the "
        "timeline still recorded it, the sweep re-read it immediately after the write, and **the "
        "hold has been put back exactly as it was**.\n\n"
        "The re-admission receipt above is therefore RETRACTED as an outcome: the transaction was "
        "abandoned where it stood and this pull request stays with its human. It did spend one "
        "automatic re-admission, which no longer changes anything — this marker makes every "
        "future sweep read this PR as a human question, whatever the label timeline says next."
        "\n\n"
        f"{adjudication_marker(GENUINELY_HUMAN, 'hold-restored', head, episode)}")


class MaintainerProbe:
    """The SHARED strict human test, bound to this sweep's target token — plus the one extra
    fail-closed direction this call site needs.

    WHO IS HUMAN. A repo COLLABORATOR whose permission is in
    park_policy.HUMAN_MAINTAINER_PERMISSIONS ({admin, maintain, write}), decided by the shared
    park_policy.probe_maintainer wrapper exactly as worker-pr._is_human_maintainer,
    dispatch-claim._target_is_human_maintainer, groom, curate-frontier and resolve-conflicts all
    decide it. It is deliberately NOT an equality test against a configured handle: this sweep
    DELETES holds it believes a machine applied, so a human set narrower than the policy's is a
    licence to erase any OTHER authorized maintainer's hold on both the PR and its source issue.

    WHY THE `unverified` FLAG. Everywhere else the shared probe is consulted, "unverifiable actor
    -> not human" is the SAFE direction: it suppresses a veto or a budget window. Here it is the
    DANGEROUS one, because park_policy.label_application_machine_owned returns `not newest_human`
    — so a probe outage would silently promote every human-applied hold to "machine-applied" and
    authorise its DELETE. A probe call that could not complete is therefore remembered here, and
    `hold_machine_owned` refuses on it.

    A FAILURE IS NEVER CACHED. Caching it would answer the NEXT decision from the cache without
    re-raising, and `unverified` would read clean for a login that is still unverifiable — the
    fail-closed flag would hold for one decision and silently lapse for every later one."""

    def __init__(self, repo, read_permission, log=print):
        self.repo = repo
        self.unverified = False
        self._read = read_permission
        self._log = log
        self._cache = {}

    def reset(self):
        """Begin a new ownership decision: `unverified` describes THAT decision only, so one
        PR's probe outage never freezes the rest of the sweep."""
        self.unverified = False

    def __call__(self, login):
        if login in self._cache:
            return self._cache[login]
        failures = []

        def read_permission(probe_login):
            try:
                return self._read(probe_login)
            except Exception:
                failures.append(probe_login)  # remembered here, then re-raised so the shared
                raise                         # wrapper still logs it and still yields not-human

        human = park_policy.probe_maintainer(self.repo, login, read_permission, log=self._log)
        if failures:
            self.unverified = True
            return False
        self._cache[login] = human
        return human


def hold_machine_owned(repo, number, label, fetch_events, probe, log=_quiet):
    """park_policy.label_application_machine_owned for a hold this sweep may DELETE, with the one
    extra refusal that authority demands: ownership is proven only when the shared helper says
    MACHINE **and** every collaborator-permission probe it consulted actually COMPLETED (see
    MaintainerProbe). Any exception at all is False — an unreadable answer proves nothing, and
    only a PROOF of machine ownership may authorise removing a human-owned label."""
    probe.reset()
    try:
        owned = park_policy.label_application_machine_owned(
            repo, number, label, fetch_events, is_human=probe, log=log)
    except Exception as exc:  # noqa: BLE001 — an unreadable answer proves nothing
        log(f"hold ownership unknown for {repo}#{number} {label!r} ({exc}); not clearable")
        return False
    return bool(owned) and not probe.unverified


def _gh(args, token=None, check=True):
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh", *args], capture_output=True, text=True, env=env, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {result.stderr[:300]}")
    return result


def _gh_json(args, token=None):
    return json.loads(_gh(args, token=token).stdout or "null")


def _paginated(repo, number, kind, token=None):
    pages = _gh_json(["api", "--paginate", "--slurp",
                      f"repos/{repo}/issues/{number}/{kind}?per_page=100"], token=token)
    if not isinstance(pages, list):
        raise RuntimeError(f"malformed {kind} payload for {repo}#{number}")
    out = []
    for page in pages:
        if not isinstance(page, list):
            raise RuntimeError(f"malformed {kind} page for {repo}#{number}")
        out.extend(page)
    return out


def _label_names(container):
    return [label.get("name") for label in (container.get("labels") or [])
            if isinstance(label, dict) and isinstance(label.get("name"), str)]


def _collaborator_permission(repo, login, token):
    """The TARGET repo's collaborator permission for `login`, read under the per-repo App token
    (the same read dispatch-claim._target_is_human_maintainer takes), or None for a clean 404 —
    "not a collaborator" is an ANSWER, not an outage. Every other failure RAISES, because
    park_policy.probe_maintainer must be able to tell an unverifiable actor apart from a verified
    non-maintainer: the first refuses this sweep, the second does not."""
    result = _gh(["api", f"repos/{repo}/collaborators/"
                  f"{urllib.parse.quote(str(login), safe='')}/permission"],
                 token=token, check=False)
    if result.returncode != 0:
        if "HTTP 404" in (result.stderr or ""):
            return None
        raise RuntimeError(f"collaborator permission probe exited {result.returncode}: "
                           f"{(result.stderr or '')[:200]}")
    payload = json.loads(result.stdout or "null")
    if not isinstance(payload, dict):
        raise RuntimeError("collaborator permission payload is malformed")
    return payload.get("permission")


def _hold_machine_owned_now(repo, number, label, probe, token):
    """Whether the LIVE newest application of `label` on `repo#number` is provably the machine's,
    from a timeline read taken RIGHT NOW. FAIL-CLOSED in the only direction that matters: an
    unreadable answer — an unreachable timeline OR a collaborator-permission probe that could not
    complete — is a NEGATIVE answer, so it can never authorise a delete and always triggers a
    restore."""
    return hold_machine_owned(
        repo, number, label,
        lambda _repo, _num: _paginated(repo, number, "timeline", token=token),
        probe, log=lambda message: print(f"  {message}"))


def _live_hold(repo, number, label, probe, token):
    """The MUTATION-BOUNDARY snapshot of `repo#number`: (live label names, hold machine-owned).
    Ownership is True when the label is not live at all — there is nothing to own — and otherwise
    the fail-closed live probe."""
    issue = _gh_json(["api", f"repos/{repo}/issues/{number}"], token=token)
    labels = _label_names(issue if isinstance(issue, dict) else {})
    if label not in set(labels):
        return labels, True
    return labels, _hold_machine_owned_now(repo, number, label, probe, token)


def _sweep(args, worker_pr, policy_resolve):
    """One sweep over the target's live `review:needs-user` PRs."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # FAIL CLOSED on the trust-surface keyword union: policy-resolve raises rather than return a
    # reduced set, and a set we could not load must classify EVERY PR as a trust surface.
    keywords, keyword_error = (), None
    try:
        keywords = tuple(policy_resolve.routing_security_keywords(
            args.repo, policy_file=args.policy_file, target_root=args.target_root))
    except Exception as exc:  # noqa: BLE001 — any failure means "assume trust surface"
        keyword_error = str(exc)[:160]
        print(f"::warning::trust-surface keywords unavailable ({keyword_error}); every PR in "
              "this sweep is classified as a trust surface")

    held = _gh_json(["api", f"repos/{args.repo}/issues?state=open"
                     f"&labels={urllib.parse.quote(park_policy.HUMAN_PR_PARK_LABEL)}"
                     "&per_page=100", "--paginate", "--slurp"], token=args.token)
    rows = [row for page in (held if isinstance(held, list) else []) if isinstance(page, list)
            for row in page if isinstance(row, dict) and row.get("pull_request")]
    print(f"{len(rows)} open PR(s) on {park_policy.HUMAN_PR_PARK_LABEL} in {args.repo}")
    # ONE probe for the whole sweep: the same maintainers recur across PRs, so a completed
    # collaborator read is answered from its cache instead of re-billed per PR. Failures are not
    # cached, and `hold_machine_owned` resets the flag per decision (MaintainerProbe).
    is_human = MaintainerProbe(
        args.repo, lambda login: _collaborator_permission(args.repo, login, args.token))
    readmitted, explained, skipped = [], [], []
    for row in sorted(rows, key=lambda row: row.get("number") or 0):
        number = row["number"]
        try:
            comments = _paginated(args.repo, number, "comments", token=args.token)
            timeline = _paginated(args.repo, number, "timeline", token=args.token)
            bot_bodies = [str(comment.get("body", ""))
                          for comment in comments if isinstance(comment, dict)
                          and str((comment.get("user") or {}).get("login", "")).casefold()
                          == args.bot_login.casefold()]
            # FAIL CLOSED: anything we cannot read — an unreadable timeline, or a
            # collaborator-permission probe that could not complete — counts as "a human applied
            # it" (hold_machine_owned owns both directions).
            applied_by_human = not hold_machine_owned(
                args.repo, number, park_policy.HUMAN_PR_PARK_LABEL,
                lambda _repo, _num: timeline, is_human,
                log=lambda message: print(f"  #{number}: {message}"))

            pull = _gh_json(["api", f"repos/{args.repo}/pulls/{number}"], token=args.token)
            head_sha = str(((pull or {}).get("head") or {}).get("sha", ""))
            head_match = worker_pr.WORKER_HEAD_RE.fullmatch(
                str(((pull or {}).get("head") or {}).get("ref", "")))
            issue_number = int(head_match.group(1)) if head_match else None
            issue_labels, issue_hold_machine_owned = [], True
            if issue_number:
                issue = _gh_json(["api", f"repos/{args.repo}/issues/{issue_number}"],
                                 token=args.token)
                issue_labels = _label_names(issue if isinstance(issue, dict) else {})
                if park_policy.HUMAN_PARK_LABEL in set(issue_labels):
                    # Fail-closed on BOTH halves, exactly like the PR's own hold above: an
                    # unreadable issue timeline and an incomplete permission probe are each a
                    # negative answer, and a negative answer keeps the issue's hold human.
                    issue_hold_machine_owned = hold_machine_owned(
                        args.repo, issue_number, park_policy.HUMAN_PARK_LABEL,
                        lambda _repo, num: _paginated(args.repo, num, "timeline",
                                                      token=args.token),
                        is_human, log=lambda message: print(f"  #{number}: {message}"))

            pr_labels = _label_names(row)
            trust_surface = True
            if keyword_error is None:
                trust_surface = worker_pr.security_flagged(
                    set(pr_labels) | set(issue_labels), extra_keywords=keywords)
            round_n, verdict_record = latest_verdict(args.verdict_root, args.repo, number)
            blocking = blocking_finding_count(verdict_record)
            readmissions_spent = worker_pr.auto_readmission_marker_count(comments, args.bot_login)

            # A RETURN_TO_LOOP receipt records INTENT, never completion, so it suppresses only the
            # comment (see readmission_writes). A GENUINELY_HUMAN receipt IS the whole transaction,
            # so it still short-circuits the PR entirely.
            recorded_loop = already_recorded(comments, args.bot_login, RETURN_TO_LOOP, head_sha)
            recorded_human = already_recorded(comments, args.bot_login, GENUINELY_HUMAN, head_sha)
            # ...and an intent that never reached its commit is an UNFINISHED transaction, not a
            # spent budget. The evidence key ties the receipt to THIS head, and the ordering
            # against the live hold application is what separates "died mid-write" from
            # "finished, then re-parked" (incomplete_readmission).
            evidence_prefix = f"{worker_pr.AUTO_READMIT_ADJUDICATION_PREFIX}{head_sha[:12]}/"
            in_flight = incomplete_readmission(
                recorded=recorded_loop,
                receipt_stamps=[record["at"] for record
                                in worker_pr.auto_readmission_records(comments, args.bot_login,
                                                                      log=_quiet)
                                if str(record.get("key", "")).startswith(evidence_prefix)],
                hold_applied_at=newest_label_application(timeline,
                                                         park_policy.HUMAN_PR_PARK_LABEL))

            # Everything `admission` reads that is NOT label/ownership state: it is re-run
            # verbatim at the mutation boundary below over freshly-read labels and ownership, so
            # these must be computed once and shared rather than re-derived and allowed to drift.
            probe = dict(
                park_records=park_policy.park_reason_records(comments, args.bot_login,
                                                             log=_quiet),
                park_marker_present=any(park_policy.PARK_REASON_MARKER in body
                                        for body in bot_bodies),
                bot_bodies=bot_bodies,
                hold_restored=any(record["reason"] == "hold-restored"
                                  for record in adjudication_records(comments, args.bot_login)),
                rounds_recorded=worker_pr.count_rounds(comments, args.bot_login),
                readmissions_spent=readmissions_spent,
                readmission_in_flight=in_flight,
                trust_surface=trust_surface,
                blocking_findings=blocking)
            disposition, reason, detail = admission(
                pr_labels=pr_labels,
                issue_labels=issue_labels,
                hold_applied_by_human=applied_by_human,
                issue_hold_machine_owned=issue_hold_machine_owned,
                **probe)
            episode = readmissions_spent + 1
            verdict_note = (f"round {round_n} verdict: "
                            f"{'unreadable' if blocking is None else f'{blocking} blocking'}"
                            if round_n else "no recorded verdict")
            print(f"  #{number}: {disposition} [{reason}] — {detail} "
                  f"({verdict_note}; trust_surface={trust_surface})")

            if not park_policy.safe_receipt_part(head_sha):
                print(f"  #{number}: SKIP — head sha is missing or unsafe for a receipt")
                skipped.append((number, "unsafe head sha"))
                continue
            if issue_number is None:
                # Not a worker branch, so dispatch's head-ref gate would exclude it from the
                # review lane anyway: re-admitting it would be a relabel that changes nothing,
                # and there is no source issue whose holds this sweep could even read.
                print(f"  #{number}: SKIP — head is not a worker branch; the review lane could "
                      "not re-enter this PR and there is no source issue to read")
                skipped.append((number, "not a worker branch"))
                continue
            if reason == "not-parked":
                # The label went away between the listing and this read. There is nothing to
                # explain and nothing to drain — never comment a park onto an unparked PR.
                print(f"  #{number}: SKIP — the hold was cleared while this sweep was running")
                skipped.append((number, "hold cleared mid-sweep"))
                continue
            if disposition == GENUINELY_HUMAN and recorded_human:
                print(f"  #{number}: already recorded for head {head_sha[:12]} — no-op")
                continue
            if not args.apply:
                (readmitted if disposition == RETURN_TO_LOOP else explained).append(
                    (number, f"dry-run/{reason}"))
                continue
            if args.limit and len(readmitted) + len(explained) >= args.limit:
                print(f"  #{number}: deferred — --limit {args.limit} reached this run")
                break

            if disposition == GENUINELY_HUMAN:
                _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/comments",
                     "-f", f"body={human_park_body(reason, detail, head_sha, episode)}"],
                    token=args.token)
                explained.append((number, reason))
                continue

            # ---- THE MUTATION BOUNDARY -----------------------------------------------------
            # Everything above was decided from reads taken several API round trips ago, and a
            # maintainer can apply either hold inside that gap. Re-read the AUTHORITATIVE label
            # and timeline state NOW and re-run the SAME pure adjudicator over it, so no delete is
            # ever planned against a stale ownership proof. This runs before the FIRST write, so a
            # stand-down here mutates nothing at all.
            live_labels, hold_owned = _live_hold(
                args.repo, number, park_policy.HUMAN_PR_PARK_LABEL, is_human, args.token)
            live_issue_labels, live_issue_owned = _live_hold(
                args.repo, issue_number, park_policy.HUMAN_PARK_LABEL, is_human, args.token)
            live_disposition, live_reason, live_detail = admission(
                pr_labels=live_labels, issue_labels=live_issue_labels,
                hold_applied_by_human=not hold_owned,
                issue_hold_machine_owned=live_issue_owned, **probe)
            if live_disposition != RETURN_TO_LOOP:
                print(f"  #{number}: STOOD DOWN at the mutation boundary — the live state now "
                      f"reads [{live_reason}]; nothing was written")
                if live_reason != "not-parked" and not recorded_human:
                    _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/comments",
                         "-f", "body=" + human_park_body(live_reason, live_detail,
                                                         head_sha, episode)],
                        token=args.token)
                    explained.append((number, live_reason))
                else:
                    skipped.append((number, f"boundary/{live_reason}"))
                continue
            writes = readmission_writes(pr_labels=live_labels, issue_labels=live_issue_labels,
                                        recorded=recorded_loop,
                                        issue_hold_machine_owned=live_issue_owned)
            if recorded_loop:
                print(f"  #{number}: RECONCILING an incomplete re-admission for head "
                      f"{head_sha[:12]} — owed writes {'/'.join(writes)} (no second receipt, so "
                      "no second automatic re-admission is spent)")
            stood_down = None
            for write in writes:
                if write == "comment":
                    # RECEIPT FIRST. The comment carries the budget window (the auto-readmission
                    # receipt) AND the decision, so a crash before the label writes leaves a PR
                    # that is explained and window-bearing rather than one quietly moved.
                    # ONE definition of the evidence key, shared with the reader above, so a
                    # reconciliation can never fail to recognise the receipt it wrote itself.
                    receipt = worker_pr.auto_readmission_receipt(f"{evidence_prefix}{episode}",
                                                                 now)
                    _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/comments",
                         "-f", "body=" + readmission_body(receipt, live_reason, live_detail,
                                                          head_sha, episode)],
                        token=args.token)
                elif write == "add-reentry":
                    _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/labels",
                         "-f", f"labels[]={REENTRY_LABEL}"], token=args.token)
                else:
                    # The two hold DELETEs, each through the detect-and-repair protocol. The issue
                    # half comes first and the PR's own hold LAST — that delete is the commit.
                    target, label, surface = (
                        (issue_number, park_policy.HUMAN_PARK_LABEL,
                         "the source issue's `needs:user`")
                        if write == "clear-issue-hold" else
                        (number, park_policy.HUMAN_PR_PARK_LABEL,
                         "this pull request's `review:needs-user`"))
                    outcome = clear_hold_with_repair(
                        machine_owned_now=(lambda t=target, la=label: _hold_machine_owned_now(
                            args.repo, t, la, is_human, args.token)),
                        delete=(lambda t=target, la=label: _gh(
                            ["api", "-X", "DELETE", f"repos/{args.repo}/issues/{t}/labels/"
                             + urllib.parse.quote(la, safe="")], token=args.token)),
                        restore=(lambda t=target, la=label: _gh(
                            ["api", "-X", "POST", f"repos/{args.repo}/issues/{t}/labels",
                             "-f", f"labels[]={la}"], token=args.token)))
                    if outcome == "restored":
                        _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/comments",
                             "-f", "body=" + restored_hold_body(surface, head_sha, episode)],
                            token=args.token)
                    if outcome != "cleared":
                        stood_down = f"{write}/{outcome}"
                        break
            if stood_down:
                print(f"  #{number}: STOOD DOWN at {stood_down} — a human application raced this "
                      "re-admission; the hold is intact and the transaction is abandoned")
                skipped.append((number, stood_down))
                continue
            readmitted.append((number, live_reason if "comment" in writes else "reconciled"))
        except Exception as exc:  # noqa: BLE001 — one bad PR never stops the sweep
            print(f"  #{number}: SKIP — {exc}")
            skipped.append((number, str(exc)[:120]))
    print(f"\n{'APPLIED' if args.apply else 'DRY RUN'}: {len(readmitted)} re-admitted, "
          f"{len(explained)} explained-and-left, {len(skipped)} skipped")
    for number, reason in readmitted:
        print(f"  re-admitted #{number} ({reason})")
    for number, reason in explained:
        print(f"  left with the maintainer #{number} ({reason})")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--print-matrix", action="store_true",
                        help="print the GITHUB_OUTPUT matrix line over enabled policy targets")
    parser.add_argument("--repo")
    parser.add_argument("--bot-login")
    # There is deliberately NO --maintainer/handle option: "human" is the shared
    # collaborator-permission set (MaintainerProbe), and a configurable login would be a way to
    # narrow it — which on this sweep means authorising the deletion of somebody else's hold.
    parser.add_argument("--token", default=None)
    parser.add_argument("--policy-file", default="policy/repos.toml")
    parser.add_argument("--target-root", default=".",
                        help="checkout root the target's routing pointer resolves against")
    parser.add_argument("--verdict-root", action="append", default=None,
                        help="recorded-verdict directory (repeatable; ledger copy first)")
    parser.add_argument("--apply", action="store_true",
                        help="write. Without it the run is a DRY RUN and mutates nothing.")
    parser.add_argument("--limit", type=int, default=0, help="0 = no cap")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.print_matrix:
        grant_account = _load("registry_grant_account", "grant-account.py")
        targets = grant_account.enabled_targets(
            Path(args.policy_file).read_text(encoding="utf-8"))
        print("matrix=" + json.dumps({"include": target_matrix(targets)},
                                     separators=(",", ":")))
        return 0
    if not (args.repo and args.bot_login):
        parser.error("--repo and --bot-login are required outside --self-test")
    if not args.verdict_root:
        args.verdict_root = ["ledger/orchestration/review-verdicts",
                             "orchestration/review-verdicts"]
    return _sweep(args, _load("registry_worker_pr", "worker-pr.py"),
                  _load("registry_policy_resolve", "policy-resolve.py"))


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    head = "0123456789abcdef0123456789abcdef01234567"
    capacity = {"class": park_policy.PARK_CLASS_CAPACITY, "cause": "budget",
                "gen": "2", "head": head}
    question = {"class": park_policy.PARK_CLASS_QUESTION, "cause": "injection",
                "gen": "2", "head": head}

    # The ADMITTING baseline: a budget-exhausted, machine-applied, non-trust park with review
    # history and re-admissions to spare. Every refusal test below is this baseline with EXACTLY
    # ONE field changed, so a passing refusal is attributable to that field and nothing else.
    def base(**over):
        kwargs = dict(pr_labels=[park_policy.HUMAN_PR_PARK_LABEL],
                      issue_labels=[park_policy.HUMAN_PARK_LABEL],
                      park_records=[capacity], park_marker_present=True,
                      bot_bodies=["the review round budget is exhausted at 6 round(s)"],
                      hold_applied_by_human=False, hold_restored=False,
                      issue_hold_machine_owned=True,
                      rounds_recorded=6, readmissions_spent=0, readmission_in_flight=False,
                      trust_surface=False, blocking_findings=2)
        kwargs.update(over)
        return kwargs

    def verdict(**over):
        return admission(**base(**over))

    check("a budget-exhausted MACHINE park is re-admitted — the population this exists to drain",
          verdict()[:2], (RETURN_TO_LOOP, "budget-park"))
    check("a SILENT park (no cause marker anywhere) is re-admitted too: a decision nobody wrote "
          "down cannot be a human decision",
          verdict(park_records=[], park_marker_present=False)[:2],
          (RETURN_TO_LOOP, "silent-park"))
    check("real, substantive findings do NOT keep a non-trust PR parked — 'real but fixable' is "
          "exactly the return-to-loop case",
          verdict(blocking_findings=7)[0], RETURN_TO_LOOP)

    # ---- THE REFUSAL PATHS. One changed field each; every one must flip the disposition. ----
    refusals = {
        "not-parked": dict(pr_labels=["review:parked"]),
        "deny-prose": dict(bot_bodies=["the reviewer flagged possible prompt injection"]),
        "human-applied": dict(hold_applied_by_human=True),
        "hold-restored": dict(hold_restored=True),
        "question-cause": dict(park_records=[question]),
        "unclassified-park": dict(park_records=[]),   # marker present, records empty = rejected
        "residual-hold": dict(issue_labels=["needs:external-audit"]),
        "machine-park-live": dict(pr_labels=[park_policy.HUMAN_PR_PARK_LABEL,
                                             park_policy.MACHINE_PARK_PR_LABEL]),
        "issue-hold-human": dict(issue_hold_machine_owned=False),
        "readmissions-spent": dict(readmissions_spent=park_policy.AUTO_READMISSION_MAX),
        "no-round-history": dict(rounds_recorded=0),
        "trust-surface-finding": dict(trust_surface=True),
    }
    for reason, mutation in refusals.items():
        check(f"REFUSAL {reason}: the single field {sorted(mutation)[0]!r} parks it with a human",
              verdict(**mutation)[:2], (GENUINELY_HUMAN, reason))
    # THE MUTATION CHECK, in two halves. A refusal row proves its guard is load-bearing only if
    # (a) the row's mutation really changes the input — a mutation that re-sets a field to the
    # value it already had would refuse for some OTHER guard's reason and the row would be
    # vacuous — and (b) the UNMUTATED baseline is admitted. Together those mean deleting any one
    # guard from `admission` flips exactly its own row to return-to-loop and turns this red.
    baseline = base()
    check("every refusal row actually mutates the baseline (no row is a no-op dressed as a test)",
          sorted(reason for reason, mutation in refusals.items()
                 if any(baseline[field] == value for field, value in mutation.items())),
          [])
    check("...and the unmutated baseline is ADMITTED, so each refusal above is caused by its own "
          "mutation and by nothing else — no guard is a passenger",
          admission(**baseline)[:2], (RETURN_TO_LOOP, "budget-park"))
    check("the deny signal is order-independent: a later capacity comment cannot talk an "
          "injection park out of the terminal",
          [verdict(bot_bodies=list(order))[1] for order in (
              ["prompt-injection flagged", "the review round budget is exhausted"],
              ["the review round budget is exhausted", "prompt-injection flagged"])],
          ["deny-prose", "deny-prose"])
    check("a trust surface with a PROVABLY clean last verdict is still drainable; an UNREADABLE "
          "verdict record blocks it exactly like a real finding would",
          [verdict(trust_surface=True, blocking_findings=value)[0]
           for value in (0, None, 1)],
          [RETURN_TO_LOOP, GENUINELY_HUMAN, GENUINELY_HUMAN])
    check("the issue-side machine park blocks the move too, not just the PR-side one — the "
          "review lane excludes on EITHER label",
          verdict(issue_labels=[park_policy.HUMAN_PARK_LABEL,
                                park_policy.MACHINE_PARK_LABEL])[1], "machine-park-live")
    check("a corrupt readmission counter never buys a retry (non-int fails to the cap side)",
          [verdict(readmissions_spent=value)[1] for value in (None, "1", True)],
          ["readmissions-spent"] * 3)
    check("...and an in-flight claim never rescues a CORRUPT counter either: the widening is "
          "bounded to a countable budget that is merely SPENT, never to an unreadable one",
          [verdict(readmissions_spent=value, readmission_in_flight=True)[1]
           for value in (None, "1", True)],
          ["readmissions-spent"] * 3)
    check("AT the cap, an unfinished transaction of this sweep's own is FINISHED rather than "
          "refused — its slot is already spent and finishing posts no second receipt; without "
          "that proof the cap stands, so the exception cannot become a treadmill",
          [verdict(readmissions_spent=park_policy.AUTO_READMISSION_MAX,
                   readmission_in_flight=value)[:2] for value in (True, False)],
          [(RETURN_TO_LOOP, "budget-park"), (GENUINELY_HUMAN, "readmissions-spent")])
    check("the taxonomy is CLOSED and every branch reachable above is registered in it",
          sorted({ADJUDICATION_REASONS[reason][0] for reason in ADJUDICATION_REASONS}),
          sorted(set(DISPOSITIONS)))
    check("no disposition can arm, pass, or merge anything — the set stays at two",
          (DISPOSITIONS, any(word in disposition for disposition in DISPOSITIONS
                             for word in ("arm", "pass", "merge", "approve"))),
          ((RETURN_TO_LOOP, GENUINELY_HUMAN), False))
    check("every human-only park cause the taxonomy names is refused, not just injection",
          sorted({verdict(park_records=[{"class": park_policy.PARK_CLASS_QUESTION,
                                         "cause": cause}])[1]
                  for cause in park_policy.PARK_HUMAN_ONLY_CAUSES}),
          ["question-cause"])
    check("an UNKNOWN cause is a human question, never silently drained",
          verdict(park_records=[{"class": "capacity", "cause": "not-a-real-cause"}])[1],
          "question-cause")

    # ---- the durable marker: round-trip, forgery, and self-contradiction --------------------
    marker = adjudication_marker(RETURN_TO_LOOP, "budget-park", head, 1)
    check("the marker round-trips through its own reader",
          parse_adjudication(f"prose\n\n{marker}"),
          {"disposition": RETURN_TO_LOOP, "reason": "budget-park",
           "head": head, "episode": "1"})
    check("a marker whose disposition contradicts its reason is DROPPED, never repaired",
          parse_adjudication(f"{ADJUDICATION_MARKER} disposition={RETURN_TO_LOOP} "
                             f"reason=human-applied head={head} episode=1 -->"), None)
    check("a marker naming a reason outside the taxonomy is dropped too",
          parse_adjudication(f"{ADJUDICATION_MARKER} disposition={GENUINELY_HUMAN} "
                             f"reason=made-up head={head} episode=1 -->"), None)
    bad = []
    for label, call in (("unknown reason", lambda: adjudication_marker(
                            RETURN_TO_LOOP, "made-up", head, 1)),
                        ("mismatched disposition", lambda: adjudication_marker(
                            RETURN_TO_LOOP, "human-applied", head, 1)),
                        ("unsafe head", lambda: adjudication_marker(
                            RETURN_TO_LOOP, "budget-park", "a b --> c", 1))):
        try:
            call()
        except ValueError:
            continue
        bad.append(label)
    check("the writer REFUSES an unknown reason, a mismatched disposition, and an unsafe part "
          "(a marker is only worth reading if it could not be written wrong)", bad, [])
    bot = "sparq-orchestrator[bot]"
    check("markers are trusted ONLY from the bot's own comments",
          (len(adjudication_records([{"user": {"login": bot}, "body": marker}], bot)),
           len(adjudication_records([{"user": {"login": "drive-by"}, "body": marker}], bot))),
          (1, 0))
    check("idempotence is keyed on (disposition, head): the same head is never re-commented, a "
          "moved head is a new fact",
          (already_recorded([{"user": {"login": bot}, "body": marker}], bot,
                            RETURN_TO_LOOP, head),
           already_recorded([{"user": {"login": bot}, "body": marker}], bot,
                            GENUINELY_HUMAN, head),
           already_recorded([{"user": {"login": bot}, "body": marker}], bot,
                            RETURN_TO_LOOP, "f" * 40)),
          (True, False, False))

    # ---- WHO IS HUMAN: collaborator PERMISSION, not one configured login --------------------
    # Both holds this sweep can DELETE are deleted on the strength of this answer, so the human
    # set must be the SHARED policy set (park_policy.HUMAN_MAINTAINER_PERMISSIONS). A login
    # equality test admits exactly one maintainer and calls every other one a machine.
    permissions = {"jeswr": "admin", "second-maintainer": "write", "third-maintainer": "maintain",
                   "triager": "triage", "drive-by": "read"}

    def applied(login, label, ts="2026-07-28T10:00:00Z"):
        return [{"event": "labeled", "label": {"name": label}, "created_at": ts,
                 "actor": {"login": login}, "performed_via_github_app": None}]

    def owned_by_machine(login, label, reader=None):
        prober = MaintainerProbe("o/r", reader or (lambda who: permissions.get(who)), log=_quiet)
        return hold_machine_owned("o/r", 41, label,
                                  lambda _repo, _num: applied(login, label), prober)

    for label in (park_policy.HUMAN_PR_PARK_LABEL, park_policy.HUMAN_PARK_LABEL):
        check(f"a WRITE and a MAINTAIN collaborator who are NOT the default handle each own their "
              f"{label} hold — a second maintainer's gesture is not the machine's to delete",
              [owned_by_machine(login, label)
               for login in ("second-maintainer", "third-maintainer")], [False, False])
        check(f"...the default handle still owns theirs, and the BOT's own application is still "
              f"drainable — the widened human set refuses more, never fewer ({label})",
              (owned_by_machine("jeswr", label),
               owned_by_machine("sparq-orchestrator[bot]", label)), (False, True))
        check(f"a permission BELOW the shared maintainer set is not a human hold ({label}) — the "
              "set is park_policy's, not a looser local one",
              [owned_by_machine(login, label) for login in ("triager", "drive-by")], [True, True])

    def boom(_login):
        raise RuntimeError("collaborator API unavailable")

    check("a permission probe that cannot COMPLETE fails CLOSED here — the shared helper alone "
          "reads an unverifiable actor as MACHINE and would authorise the delete, so an outage "
          "must not be allowed to answer this question at all",
          (park_policy.label_application_machine_owned(
              "o/r", 41, park_policy.HUMAN_PR_PARK_LABEL,
              lambda _repo, _num: applied("second-maintainer", park_policy.HUMAN_PR_PARK_LABEL),
              is_human=MaintainerProbe("o/r", boom, log=_quiet), log=_quiet),
           owned_by_machine("second-maintainer", park_policy.HUMAN_PR_PARK_LABEL, boom)),
          (True, False))
    flaky = MaintainerProbe("o/r", boom, log=_quiet)
    flaky("second-maintainer")
    flaky.reset()
    flaky("second-maintainer")
    check("a FAILED probe is NEVER cached: the next decision re-probes and is unverifiable again "
          "instead of inheriting a clean-looking cached answer that lapses the refusal",
          flaky.unverified, True)
    reads = []
    cached = MaintainerProbe("o/r", lambda who: (reads.append(who), permissions.get(who))[1],
                             log=_quiet)
    check("a COMPLETED probe IS cached per login — one collaborator read per actor per sweep",
          (cached("jeswr"), cached("jeswr"), reads, cached.unverified), (True, True, ["jeswr"],
                                                                        False))
    def unreadable(_repo, _number):
        raise RuntimeError("timeline read failed")

    check("an unreadable TIMELINE is refused by the same wrapper, with no probe involved at all",
          hold_machine_owned("o/r", 41, park_policy.HUMAN_PR_PARK_LABEL, unreadable,
                             MaintainerProbe("o/r", lambda who: permissions.get(who), log=_quiet),
                             log=_quiet),
          False)
    # ...and the END-TO-END consequence, which is the whole point: that one answer must stop the
    # DELETE on BOTH surfaces this sweep can write to.
    check("a second maintainer's hold parks the PR with its human on either surface — the PR's "
          "own hold routes into `hold_applied_by_human`, the source issue's into "
          "`issue_hold_machine_owned`, and each alone refuses the whole transaction",
          [verdict(hold_applied_by_human=not owned_by_machine(
              "second-maintainer", park_policy.HUMAN_PR_PARK_LABEL))[:2],
           verdict(issue_hold_machine_owned=owned_by_machine(
               "second-maintainer", park_policy.HUMAN_PARK_LABEL))[:2]],
          [(GENUINELY_HUMAN, "human-applied"), (GENUINELY_HUMAN, "issue-hold-human")])
    attempted = []
    check("...and at the MUTATION BOUNDARY the same answer stands the DELETE down having written "
          "nothing at all — no delete, and therefore no restore to repair",
          (clear_hold_with_repair(
              machine_owned_now=lambda: owned_by_machine("second-maintainer",
                                                         park_policy.HUMAN_PR_PARK_LABEL),
              delete=lambda: attempted.append("delete"),
              restore=lambda: attempted.append("restore")), attempted),
          ("stood-down", []))

    # ---- THE UN-CLOSEABLE WRITE WINDOW: detected after the write, and REPAIRED --------------
    # A label carries no per-application identity, so a human re-asserting the hold between the
    # ownership proof and the DELETE is erased with no trace in the live label set. All three
    # protocol outcomes are pinned, including the exact writes each one performs: delete the
    # `restore()` call, or make the post-write re-check unconditional, and one of these reds.
    def clear(before, after):
        trace = []
        answers = iter((before, after))
        outcome = clear_hold_with_repair(
            machine_owned_now=lambda: next(answers),
            delete=lambda: trace.append("delete"),
            restore=lambda: trace.append("restore"))
        return (outcome, trace)

    check("a hold whose live application is ALREADY not provably machine-owned is never deleted "
          "at all — the pre-write re-check stands the transaction down mutation-free",
          clear(False, True), ("stood-down", []))
    check("a delete whose POST-WRITE re-read still proves machine ownership stands",
          clear(True, True), ("cleared", ["delete"]))
    check("a human application landing INSIDE the window between that proof and the DELETE is "
          "detected from the timeline afterwards and the hold is PUT BACK — the gesture the live "
          "label set cannot preserve is recovered",
          clear(True, False), ("restored", ["delete", "restore"]))
    restored = restored_hold_body("this pull request's `review:needs-user`", head, 1)
    check("the restoration receipt is what makes the restored gesture STICKY: the restore re-adds "
          "the label AS THE BOT, so the timeline now says 'machine' and ONLY this marker refuses "
          "— an admission carrying it stays human even with every other probe saying drain it",
          (parse_adjudication(restored)["reason"],
           [record["reason"] for record in adjudication_records(
               [{"user": {"login": bot}, "body": restored}], bot)],
           verdict(hold_restored=True, hold_applied_by_human=False)[:2]),
          ("hold-restored", ["hold-restored"], (GENUINELY_HUMAN, "hold-restored")))
    check("the restoration receipt retracts the re-admission it undoes, and claims nothing else",
          ("the hold has been put back exactly as it was" in restored,
           "RETRACTED as an outcome" in restored,
           restored.startswith("> 🤖 SPARQ agent")), (True, True, True))

    # ---- INTENT IS NOT COMPLETION: the transaction reconciles, and COMMITS LAST --------------
    held_pr = [park_policy.HUMAN_PR_PARK_LABEL]
    held_issue = [park_policy.HUMAN_PARK_LABEL]

    def plan(pr, issue, recorded=False, issue_owned=True):
        return readmission_writes(pr_labels=pr, issue_labels=issue, recorded=recorded,
                                  issue_hold_machine_owned=issue_owned)

    check("the full transaction, in COMMIT-LAST order",
          plan(held_pr, held_issue),
          ("comment", "add-reentry", "clear-issue-hold", "delete-hold"))
    check("the receipt suppresses ONLY the comment — every label write is still owed, which is "
          "the whole of the finding: a receipt-first partial failure used to read as 'done'",
          plan(held_pr, held_issue, recorded=True),
          ("add-reentry", "clear-issue-hold", "delete-hold"))
    check("writes already landed are not re-issued, and an issue hold that is NOT provably "
          "machine-owned is never planned at all",
          (plan(held_pr + [REENTRY_LABEL], held_issue, recorded=True),
           plan(held_pr, held_issue, recorded=True, issue_owned=False),
           plan(held_pr, [], recorded=True)),
          (("clear-issue-hold", "delete-hold"), ("add-reentry", "delete-hold"),
           ("add-reentry", "delete-hold")))
    check("`delete-hold` is LAST in every plan — it removes the label the sweep's own listing "
          "filters on, so it is the COMMIT and nothing may follow it",
          sorted({writes[-1] for writes in (
              plan(held_pr, held_issue), plan(held_pr, held_issue, recorded=True),
              plan(held_pr + [REENTRY_LABEL], [], recorded=True))}),
          ["delete-hold"])
    check("every planned write is a member of the closed write set",
          sorted(set(plan(held_pr, held_issue)) - set(READMISSION_WRITES)), [])

    # WHICH APPLICATION OF THE HOLD IS LIVE is the only thing that separates an unfinished
    # transaction from a finished one whose PR was re-parked afterwards — the labels are
    # identical in both. Every unknown reads as "not in flight", which leaves the cap in force.
    hold_at = park_policy.parse_ts("2026-07-28T10:00:00Z")

    def in_flight(stamps, applied_at=hold_at, recorded=True):
        return incomplete_readmission(recorded=recorded, receipt_stamps=stamps,
                                      hold_applied_at=applied_at)

    check("a receipt written AFTER the application that is STILL live proves the DELETE never "
          "happened: the transaction is in flight and must be finished, not re-charged",
          in_flight(["2026-07-28T10:05:00Z"]), True)
    check("an application written AFTER the receipt is a NEW park — the delete DID happen and "
          "something parked the PR again, so the cap owns it and no treadmill is possible",
          in_flight(["2026-07-28T10:05:00Z"], park_policy.parse_ts("2026-07-28T11:00:00Z")),
          False)
    check("every unknown leaves the cap in force: no receipt for this head, no adjudication "
          "marker beside it (so finishing WOULD post a second receipt), an unreadable receipt "
          "stamp, an unreadable hold application, and a same-second tie that cannot be ordered",
          [in_flight([]), in_flight(["2026-07-28T10:05:00Z"], recorded=False),
           in_flight(["not-a-timestamp"]), in_flight(["2026-07-28T10:05:00Z"], None),
           in_flight(["2026-07-28T10:00:00Z"])],
          [False, False, False, False, False])
    check("the live application is the NEWEST `labeled` for EXACTLY that label — an `unlabeled`, "
          "another label, a malformed stamp and an unreadable timeline are UNKNOWN, never 'old'",
          [newest_label_application(
              applied("jeswr", park_policy.HUMAN_PR_PARK_LABEL, "2026-07-28T09:00:00Z")
              + applied("jeswr", park_policy.HUMAN_PR_PARK_LABEL, "2026-07-28T10:00:00Z")
              + [{"event": "unlabeled", "label": {"name": park_policy.HUMAN_PR_PARK_LABEL},
                  "created_at": "2026-07-28T23:00:00Z", "actor": {"login": "jeswr"}}]
              + applied("jeswr", REENTRY_LABEL, "2026-07-28T22:00:00Z"),
              park_policy.HUMAN_PR_PARK_LABEL),
           newest_label_application(applied("jeswr", REENTRY_LABEL),
                                    park_policy.HUMAN_PR_PARK_LABEL),
           newest_label_application(applied("jeswr", park_policy.HUMAN_PR_PARK_LABEL, "nope"),
                                    park_policy.HUMAN_PR_PARK_LABEL),
           newest_label_application("not-a-timeline", park_policy.HUMAN_PR_PARK_LABEL)],
          [hold_at, None, None, None])

    def replay(fail_after, spent=0):
        """Sweep the PR until its transaction completes, with the API call for write index
        `fail_after` raising on the FIRST sweep. The `while` condition IS the sweep's listing
        query — a PR is re-swept if and ONLY if it still carries the human hold — so a plan that
        commits before it is complete simply falls out of the loop half-finished. Each pass first
        runs the REAL `admission`, because the receipt this transaction posts also RAISES the live
        re-admission count: a sweep that refuses its own unfinished transaction strands the PR
        here exactly as it did in production. `spent` is what the PR had already spent before this
        transaction, so `AUTO_READMISSION_MAX - 1` is the LAST-SLOT case."""
        pr, issue = set(held_pr), set(held_issue)
        recorded, receipts, sweeps, stamps = False, 0, 0, []
        while park_policy.HUMAN_PR_PARK_LABEL in pr and sweeps < 6:
            sweeps += 1
            if admission(**base(pr_labels=sorted(pr), issue_labels=sorted(issue),
                                readmissions_spent=spent + receipts,
                                readmission_in_flight=in_flight(stamps,
                                                                recorded=recorded)))[0] \
                    != RETURN_TO_LOOP:
                break                   # the sweep leaves the park with a human: STRANDED
            for index, write in enumerate(plan(sorted(pr), sorted(issue), recorded=recorded)):
                if sweeps == 1 and index == fail_after:
                    break               # the API call raised; the sweep's handler skips the PR
                if write == "comment":
                    recorded, receipts = True, receipts + 1
                    stamps.append("2026-07-28T10:30:00Z")
                elif write == "add-reentry":
                    pr.add(REENTRY_LABEL)
                elif write == "clear-issue-hold":
                    issue.discard(park_policy.HUMAN_PARK_LABEL)
                elif write == "delete-hold":
                    pr.discard(park_policy.HUMAN_PR_PARK_LABEL)
        return (sorted(pr), sorted(issue), receipts, sweeps)

    completed = ([([REENTRY_LABEL], [], 1, 2)] * len(READMISSION_WRITES)
                 + [([REENTRY_LABEL], [], 1, 1)])
    check("a failure after ANY write is RECONCILED to the same complete state by the next sweep, "
          "and the receipt is posted EXACTLY ONCE however many sweeps it takes — so reconciling "
          "can never spend a second automatic re-admission against the cap",
          [replay(fail_after) for fail_after in range(len(READMISSION_WRITES) + 1)], completed)
    check("...and that holds from the LAST SLOT too, which is where it used to fail: the receipt "
          "this transaction posts takes the live count TO AUTO_READMISSION_MAX, so the next sweep "
          "must FINISH it rather than refuse it as a spent budget — refusing there stranded the "
          "PR permanently, one write short of done, on the strength of its own receipt",
          [replay(fail_after, park_policy.AUTO_READMISSION_MAX - 1)
           for fail_after in range(len(READMISSION_WRITES) + 1)], completed)
    check("...but a PR that is AT the cap with no unfinished transaction of its own is still "
          "refused, mutation-free: the exception is bounded to finishing a receipt this sweep "
          "provably left in flight, and buys no new re-admission for anyone",
          replay(len(READMISSION_WRITES), park_policy.AUTO_READMISSION_MAX),
          ([park_policy.HUMAN_PR_PARK_LABEL], [park_policy.HUMAN_PARK_LABEL], 0, 1))

    # ---- the recorded-verdict reader: UNKNOWN is never zero ---------------------------------
    check("blocking findings are counted by severity, and an unreadable record is None (never 0)",
          [blocking_finding_count(record) for record in (
              {"issues": [{"severity": "major"}, {"severity": "minor"},
                          {"severity": "blocker"}]},
              {"issues": []}, {"issues": "nope"}, {}, None, {"issues": ["nope"]})],
          [2, 0, None, None, None, None])

    # ---- the comment bodies -----------------------------------------------------------------
    human_body = human_park_body("trust-surface-finding",
                                 ADJUDICATION_REASONS["trust-surface-finding"][1], head, 1)
    check("the genuinely-human comment self-identifies, states that nothing was changed, and "
          "carries its own machine-readable reason",
          (human_body.startswith("> 🤖 SPARQ agent"),
           "leaving it exactly as it is" in human_body,
           parse_adjudication(human_body)["reason"]),
          (True, True, "trust-surface-finding"))
    loop_body = readmission_body("RECEIPT-TEXT", "budget-park",
                                 ADJUDICATION_REASONS["budget-park"][1], head, 1)
    check("the re-admission comment leads with the budget RECEIPT, names the re-entry label, "
          "disclaims any arm authority, and says the machine terminal — not the maintainer — "
          "catches a failed adjudication",
          (loop_body.startswith("RECEIPT-TEXT"), REENTRY_LABEL in loop_body,
           "not this sweep — decides the outcome" in loop_body,
           "It does not come back to you." in loop_body,
           parse_adjudication(loop_body)["disposition"]),
          (True, True, True, True, RETURN_TO_LOOP))
    check("neither comment claims the PR is correct, ready, approved, or armed",
          sorted({word for body in (human_body, loop_body)
                  for word in ("is correct", "is ready", "approved", "armed")
                  if word in body}), [])

    # ---- the fan-out plan: least-privilege token scoping is a property of this split ---------
    check("the matrix splits each enabled target into the owner+name its own mint needs",
          target_matrix(["sparq-org/sparq", "jeswr/agent-account-registry"]),
          [{"repo": "sparq-org/sparq", "owner": "sparq-org", "name": "sparq"},
           {"repo": "jeswr/agent-account-registry", "owner": "jeswr",
            "name": "agent-account-registry"}])
    bad_targets = []
    for target in ("noslash", "owner/", "/name", "owner/extra/name", ""):
        try:
            target_matrix([target])
        except ValueError:
            continue
        bad_targets.append(target)
    check("a malformed policy target FAILS the plan rather than minting a wider-scoped token",
          bad_targets, [])

    print("adjudicate-stuck self-test " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
