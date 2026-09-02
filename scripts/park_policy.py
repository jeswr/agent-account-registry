#!/usr/bin/env python3
# Shared park-label policy for every orchestration park writer (dispatch-claim / groom /
# worker-issue / worker-pr / resolve-conflicts / curate-frontier). Two invariants live here so
# no writer can drift:
#
# 1. LABEL OWNERSHIP. `needs:user` is HUMAN-owned: it is applied ONLY by paths that pose a
#    genuine human question (a steering question, a corrupt-marker inspection, an unresolvable
#    routing, a conflict a machine must not guess). `status:parked` is the MACHINE-owned soft
#    hold for capacity/decline/budget-driven parks on a SOURCE ISSUE, and `review:parked` is its
#    PR-SIDE twin (worker-pr needs_user park_class="capacity"): both exclude the surface from
#    autonomous dispatch/enumeration WITHOUT posing a human question, and a human readmission
#    gesture (see readmission_cutoff) re-admits them. A capacity blip must never masquerade as a
#    human question (live incident 2026-07-18: a mass park applied `needs:user` +
#    `status:deferred` to ~18 source issues and terminally absorbed the whole draft-PR fleet).
#
# 2. STICKY HUMAN UNPARKS. Before ANY automation path applies a park label it must read the
#    issue/PR label timeline: if a PROVEN-HUMAN actor removed that same label more recently than
#    any application of it, the park is SUPPRESSED (the machine never overrides a human's
#    explicit unpark — live incident 2026-07-18: the orchestrator re-applied `needs:user` 37
#    minutes after the maintainer removed it). A human RE-adding the label later re-enables
#    automation parking — the comparison is strictly most-recent-event-wins.
#
#    FAIL DIRECTIONS (two DIFFERENT failure classes, deliberately distinct):
#    - TIMELINE READ/SHAPE failure (fetch error, truncated page, malformed relevant event): the
#      veto suppresses the park (never park when you cannot prove no human veto), while the
#      budget/readmission side keeps the FULL historical count (never mint a fresh budget on
#      unproven data).
#    - ACTOR UNVERIFIABLE (missing login, `[bot]` suffix, `performed_via_github_app` set, or a
#      collaborator-permission probe that fails or denies): the actor is treated as NOT human on
#      BOTH sides — no veto and no readmission window. An actor you cannot prove is a trusted
#      human must never mint a veto or a fresh budget; only the strict maintainer probe
#      (permission in {admin, maintain, write}, the worker-issue.py _is_human_maintainer
#      pattern) counts.
#
# 3. AUTOMATIC RE-ADMISSION OF A MACHINE PARK ON PROVEN CAUSE-RECOVERY (registry #614). A
#    MACHINE-owned park used to be clearable only by a HUMAN gesture: capacity_park_readmitted
#    admits exactly one thing — an UNCONSUMED proven-human unlabel — so a capacity OUTAGE
#    permanently stranded every PR it parked, even after the outage ended, and the label
#    description ("cleared automatically on readmission") was simply false. Live evidence
#    2026-07-25: acct01 (the fleet's ONLY cross-provider review account) failed every review with
#    model-exit-class=auth (#596), which capacity-parked registry PRs #587/#590/#585/#593 with
#    their source issues #574/#577/#582/#572 plus 6 sparq PRs; the credential fix restores review
#    capacity but NONE of those parks recover without a hand-unlabel of every one.
#    capacity_park_admission therefore adds an ADDITIONAL, STRICTLY NARROWER admission beside the
#    human one:
#    - MACHINE-OWNED LABELS only, and OWNERSHIP IS DECIDED BY TWO FACTS ABOUT THE PARK, NOT BY THE
#      ACTOR'S IDENTITY. A live `needs:*` / `review:needs-user` refuses unconditionally
#      (human_owned_holds), and so does a park whose LATEST application was a proven human applying
#      the human-owned terminal `needs:user`. A proven human applying `review:parked` /
#      `status:parked` may be re-admitted, but ONLY when BOTH hold:
#        (i)  the label they chose is a MACHINE-owned soft hold (MACHINE_OWNED_PARK_LABELS —
#             a POSITIVE subset proof, so an unclassified label fails closed); and
#        (ii) THE BOT'S OWN park-reason receipt already classified the episode `class=capacity`
#             (human_park_capacity_proof).
#      (ii) is what makes this safe rather than merely consistent, and it was added after review
#      demolished the first cut. (i) alone proves ownership and says NOTHING about cause: measured
#      on the live sparq population it admitted 12 PRs of which 12/12 recovered on the labelled
#      AGED-OUT HEURISTIC and 0/12 on proof that their own cause cleared, so the only per-PR
#      condition left was "older than six hours"; and 5 of those 12 had no bot receipt of ANY kind,
#      the exact case in which `cause_gated_park_episode` is inert and registry #769's "age is not
#      its own recovery proof" guard cannot fire. A machine must not clear a park no machine ever
#      classified. Note what (ii) is NOT resting on: what a LABEL DESCRIPTION promises a human. The
#      first cut argued exactly that, and the argument was true of the code and false of the world —
#      `_ensure_label` wrote descriptions once at creation and never reconciled them, so live
#      `review:parked` read "Registry cross-provider review-loop state". The descriptions are now
#      reconciled (worker-pr / groom `_ensure_label`), but the admission rests on the bot's own
#      durable receipt, which is a fact about the park rather than about what a human was told.
#      Keying on the ACTOR instead made a human-applied `review:parked` unrecoverable BY
#      CONSTRUCTION, and `_migrate_legacy_park` could not reach it either (that migration fires only
#      on `review:needs-user`). MEASURED on sparq-org/sparq 2026-07-28: open worker PRs stalled in
#      exactly that state, refusing with PARK_REFUSAL_HUMAN_APPLIED even when handed the strongest
#      possible recovery evidence — see park_application_view. The sticky human-unpark veto
#      (invariant 2) is untouched either way: the automatic path only ever CLEARS a park, it never
#      applies one, so it cannot interact with the veto at all.
#    - Evidence-gated on the CAUSE, never on elapsed time: the caller supplies positive
#      per-account model-health evidence (model-health.capacity_recovery_evidence — the SAME
#      records #604's auth_cooldowns / account-auth-cooldown read, never a parallel health store)
#      that the account which was failing when the park landed has since recorded a SUCCESSFUL
#      run STRICTLY AFTER the park application. No evidence, an unreadable/ambiguous health read,
#      an unreadable timeline, or an instant tie all fail toward STAYING PARKED — the same
#      direction the human path already fails in.
#      AND WHERE THAT PROOF IS UNOBTAINABLE (registry #691): the health window is a rolling 48 h,
#      so a park older than it — or one applied while the fleet was healthy — can never satisfy
#      the cause condition, and the "automatic" exit silently expired into a permanent hold. The
#      caller's probe therefore falls back, ONLY once the strong exit is provably unreachable, to
#      model-health.sustained_fleet_health_evidence: an explicitly-LABELLED HEURISTIC ("the fleet
#      has been demonstrably healthy for a sustained span") rather than proof of this park's own
#      cause. It is an additional evidence SOURCE consumed through this same function — it widens
#      nothing here: the human-hold refusal, the human-applied-park refusal, the strictly-after
#      ordering, the consume-exactly-once key and the AUTO_READMISSION_MAX cap all apply to it
#      unchanged.
#    - Bounded, and unable to loop, because this is exactly why the human-only rule existed:
#      every automatic re-admission is receipted durably (worker-pr AUTO_READMIT_MARKER, the same
#      bot-authored-receipt style as #610's park-generation receipts, which it EXTENDS rather than
#      replaces), and
#        INVARIANT: an automatic re-admission CONSUMES its recovery evidence EXACTLY ONCE and can
#        never be re-earned by the same evidence. A subsequent park requires a NEW
#        outage-and-recovery pair (a success strictly after THAT park), and at most
#        AUTO_READMISSION_MAX automatic re-admissions may ever be granted to one PR — past the cap
#        the loop stops trying and says so LOUDLY, because a flapping account is a genuine human
#        question.
"""Machine/human park-label ownership + the sticky human-unpark veto (one shared helper)."""

import argparse
import re
import sys
from datetime import datetime, timedelta, timezone


# The machine-owned soft hold for SOURCE ISSUES (capacity/decline/budget parks). Ensured on
# target repos at write time via each writer's _ensure_label idiom.
MACHINE_PARK_LABEL = "status:parked"
# The machine-owned soft hold for WORKER PRS (worker-pr needs_user park_class="capacity"): the
# PR-side twin of status:parked. Excluded from active review/fix enumeration like a soft hold,
# veto-gated like every park label, and cleared by a human unlabel (either surface — see
# READMISSION_LABELS) or by the loop itself on readmission.
MACHINE_PARK_PR_LABEL = "review:parked"
# The human-owned terminal (genuine human questions only).
HUMAN_PARK_LABEL = "needs:user"
# Its PR-side twin (worker-pr's review:needs-user, dispatch-claim's HUMAN_HOLD_PR_LABELS): the
# review loop's own human-question terminal. Named here so the automatic-readmission path can
# recognise a human-owned hold without importing a writer module.
HUMAN_PR_PARK_LABEL = "review:needs-user"
PARK_LABELS = (HUMAN_PARK_LABEL, MACHINE_PARK_LABEL, MACHINE_PARK_PR_LABEL)
# A human unlabel of ANY of these — on the PR or its provenance-linked source issue, latest
# event wins — is an explicit readmission gesture: it opens the round/attempt-budget readmission
# window AND re-admits a capacity-parked PR to enumeration.
READMISSION_LABELS = (HUMAN_PARK_LABEL, MACHINE_PARK_LABEL, MACHINE_PARK_PR_LABEL)
# The MACHINE-owned subset of READMISSION_LABELS — the soft holds whose own published description
# (MACHINE_PARK_DESCRIPTION) promises an automatic exit. capacity_park_admission consumes this as a
# POSITIVE PROOF SET: it admits a park a proven human applied only when EVERY label that human
# applied at the latest instant is a member. The positive direction is load-bearing. Asking instead
# "is none of them human-owned" would fail OPEN the moment a new human-owned label joined
# READMISSION_LABELS — a label nobody had classified would silently become auto-clearable. This way
# an unclassified label refuses, which is the direction every other ambiguity in this module takes.
MACHINE_OWNED_PARK_LABELS = frozenset({MACHINE_PARK_LABEL, MACHINE_PARK_PR_LABEL})
# Bounded post-readmission escalation: an item that is human-readmitted and exhausts its
# round/attempt budget again this many times escalates to a QUESTION-class park (terminal
# review:needs-user / needs:user with a comment naming the repeated failure) so nothing can
# spin through readmission windows forever. GENERATIONS ARE TRACKED SOLELY BY BOT-AUTHORED
# RECEIPTS (round-3 finding 1): every consumed budget window — including the INITIAL
# full-budget window, which has no readmission cutoff — is receipted with a
# PARK_GENERATION_MARKER whose window key is the cutoff (or PARK_WINDOW_NONE for the initial
# window). Label writes are best-effort UI on top: a sticky-veto-suppressed label re-apply
# never stalls the ladder, because the ladder never reads labels.
#
# [registry #797] ONLY A HUMAN'S DECISION MAY CHARGE ONE OF THESE GENERATIONS. The counter above
# says "human-readmitted", and the escalation comment it drives says so out loud — but until this
# fix the ladder could not tell a human's unlabel from the loop's OWN automatic re-admission
# (invariant 3 / registry #614), because both arrive as a bare `cutoff` string through
# effective_readmission_cutoff. MEASURED on the live sparq population 2026-07-27: 35 open draft
# PRs sat on the human-owned `review:needs-user` terminal, all 73 applications of it made by
# `sparq-orchestrator[bot]` and NONE by a human; of the 21 carrying generation receipts, 20 had
# escalated on a window minted by an AUTOMATIC re-admission (the window key is byte-identical to
# the PR's own `sparq-auto-readmit` stamp — e.g. #4422 gen=2 cutoff=2026-07-27T08:02:21Z, and
# #3595 whose BOTH windows are auto stamps) and ZERO on a window a human opened. The loop parked
# its own PRs, re-admitted them itself, counted its own re-admission as a human generation, and
# then paged the maintainer claiming they had readmitted it.
#
# So the generation counter is now attributed: see WINDOW_AUTHORITY_* / readmission_window, and
# park_ladder_decision's REQUIRED `window_authority`. A window the machine minted charges the
# MACHINE ladder (PARK_MACHINE_TERMINAL_GENERATIONS) instead, whose terminal is machine-owned.
PARK_ESCALATION_GENERATIONS = 2
# WHO opened the readmission window a park-generation is charged to. `readmission_window` derives
# it; `park_ladder_decision` REQUIRES it (keyword-only, no default) so no call site can reach the
# human terminal by forgetting to attribute its window — the defect above in one word.
#   human    a PROVEN-human unlabel of a park label (readmission_cutoff's strict maintainer probe)
#            is the newest gesture. ONLY this may charge a PARK_ESCALATION_GENERATIONS generation
#            and so ONLY this can ever reach the human-owned terminal.
#   machine  the loop's own automatic re-admission receipt is the newest gesture (or ties the
#            human one — a tie proves nothing about the human's intent and resolves to machine).
#   unknown  no window at all, an unreadable timeline, or a caller that cannot attribute. Treated
#            exactly like `machine` for the terminal, and — having no attribution to count with —
#            it counts EVERY consumed window on the machine ladder so it still terminates.
WINDOW_AUTHORITY_HUMAN = "human"
WINDOW_AUTHORITY_MACHINE = "machine"
WINDOW_AUTHORITY_UNKNOWN = "unknown"
# The receipt window key for a budget exhaustion with NO readmission cutoff (the initial
# full-budget window). Never a valid ISO-8601 timestamp, so it can never collide with a real
# cutoff key.
PARK_WINDOW_NONE = "none"
# Sentinel a caller may request from readmission_cutoff (on_unreadable=WINDOW_UNREADABLE) to
# DISTINGUISH "no proven human unlabel exists" (None) from "the timeline could not be read"
# (this sentinel). The escalation ladder must FREEZE on an unreadable timeline — advancing a
# generation (or minting a PARK_WINDOW_NONE receipt) on a failed read would corrupt the durable
# ladder — while plain budget consumers keep the default None => full-historical-count path.
WINDOW_UNREADABLE = "window-unreadable"
# Character class a park FINGERPRINT component (head SHA / attempt counter) must satisfy: no
# whitespace and no `>`, so the value can never break out of the `head=<sha> attempt=<key> -->`
# receipt marker (the readers key on `(\S+)` groups terminated by ` -->`).
_FINGERPRINT_PART = re.compile(r"[A-Za-z0-9._=/:-]{1,120}")
# The strict maintainer probe set (the worker-issue.py _is_human_maintainer pattern): repo
# collaborator permission must be one of these for an actor to count as a trusted human.
HUMAN_MAINTAINER_PERMISSIONS = {"admin", "maintain", "write"}
MACHINE_PARK_COLOUR = "1d76db"
# HONEST label text (invariant 3): a machine park clears on a human unlabel, on proven
# cause-recovery (capacity_park_admission), or — once that proof has aged out of the health
# window — on the capped sustained-fleet-health retry (registry #691). The original wording
# ("cleared automatically on readmission") described a mechanism that did not exist; the #614
# wording was true only for the first 48 h, after which the proof became unobtainable and the
# hold was permanent in fact while claiming otherwise. Keep this in sync with groom.LABELS
# (GitHub caps a label description at 100 characters).
MACHINE_PARK_DESCRIPTION = (
    "Machine-owned capacity park (soft hold; human unlabel, proven recovery, or capped retry)"
)
# HARD per-PR ceiling on AUTOMATIC re-admissions (invariant 3). Two is deliberate: one covers the
# ordinary outage-then-recovery shape this exists for, the second covers a genuine second outage,
# and anything past that is an account flapping — a state whose right answer is a human decision,
# not a third machine retry. The cap bounds the ping-pong a flapping account could otherwise drive
# even though each individual re-admission already needs its own fresh, unconsumed recovery
# evidence; the two bounds are independent on purpose.
AUTO_READMISSION_MAX = 2
# [registry #797] The MACHINE-owned counterpart of PARK_ESCALATION_GENERATIONS: how many
# MACHINE-minted budget windows may be consumed before the loop gives up on this PR and RETIRES it
# (park_ladder_decision's `machine-terminal` action). Deliberately equal to AUTO_READMISSION_MAX —
# machine windows are minted only by automatic re-admissions, which that constant already caps at
# two per PR, so this fires exactly when the machine has spent its last automatic chance and the
# item failed anyway. Past that point nothing further is learned by trying again, and — the whole
# point of #797 — nothing about a HUMAN's attention has been established either, so the exit must
# be a machine-owned retirement, never a page.
PARK_MACHINE_TERMINAL_GENERATIONS = AUTO_READMISSION_MAX
# ---------------------------------------------------------------------------------------------
# [registry #764] THE ABSORBING-PARK EXIT. `park_ladder_decision` has five outcomes; three of them
# neither attempt work nor advance the generation counter, so an item that lands on one lands on
# it FOREVER unless a human intervenes:
#
#   legacy-quiet  a pre-receipt park: `not cutoff and already_labeled and not receipts`. It
#                 returns BEFORE `generation = len(receipts) + 1`, so no receipt is ever minted,
#                 so `receipts` stays empty, so the next tick takes the same branch. The stated
#                 intent ("the ladder starts counting with the first receipted window") is
#                 unreachable: nothing on this path ever writes that first receipt.
#   dedupe        the window key is already receipted. A NEW key is minted only by a human
#                 unlabel (readmission_cutoff), so with no gesture this repeats indefinitely.
#   unchanged     a fresh window whose park fingerprint has not moved. Correct as idempotence,
#                 but with nothing else attempting the item it too has no self-clearing exit.
#
# MEASURED 2026-07-27, registry dispatch run 30263179462: seven sparq issues (#2392 dedupe,
# #2640/#2642/#2685/#2714/#2868/#2951 legacy-quiet) were 7 of 7 planned worker rows, launched 0.
# They are NOT free: `compute_ready` serializes one row per `area:` package, so each one RESERVES
# its package against every sibling. Eleven deferred candidates (nine still holding a live attempt
# budget) sat behind those seven packages, and re-running the frontier with the seven removed
# admits three of them immediately. An item that can never launch was holding the partition of
# items that can.
#
# `freeze` is DELIBERATELY absent: an unreadable timeline must prove nothing at all (the ladder
# never advances on unproven data), so it can neither start nor age an absorbing streak.
PARK_ABSORBING_ACTIONS = frozenset({"legacy-quiet", "dedupe", "unchanged"})
# Bounded grace before an absorbing park is RETIRED to the question-class terminal. The unit is
# wall-clock, not ticks: the dispatch cron is every 10 minutes but an item is only OBSERVED on a
# tick where it also won its package, so a tick count would measure contention rather than
# stuckness. Six hours is ~36 scheduled ticks — long enough that a transient (a capacity dip, a
# groom pass mid-flight, a human about to unpark) resolves on its own, short enough that a
# genuinely stuck partition frees inside one working session.
PARK_ABSORBING_GRACE_SECONDS = 6 * 3600
# Every disposition absorbing_park_disposition can return. Closed set: the census map below
# raises on anything outside it, so a new disposition cannot be added without also being counted.
PARK_ABSORBING_DISPOSITIONS = ("observe", "wait", "retire", "spent", "hold-linked-pr",
                               "not-absorbing")
# The CLOSED census enum for the deferred-issue budget-exhaustion leg. Every population entering
# the leg leaves through exactly one of these buckets, so the buckets SUM to the population and a
# future missing edge shows as a growing bucket rather than as silence. Keyed by
# (ladder action, absorbing disposition) — `None` where the action has no absorbing disposition.
BUDGET_EXHAUSTED_CENSUS = {
    ("freeze", None): "budget-exhausted-frozen",
    ("park", None): "budget-exhausted",
    ("terminal", None): "budget-exhausted-escalated",
    # [registry #797] The MACHINE terminal. Declared here even though the deferred-issue lane
    # passes WINDOW_AUTHORITY_HUMAN (its cutoff comes straight from readmission_cutoff, so it can
    # only ever mint human windows): the enum RAISES on an undeclared pair, so if that lane is
    # ever wired to an attributed window the exit lands in a counted bucket instead of crashing
    # the tick — and, more to the point, instead of being silently re-routed to the human one.
    ("machine-terminal", None): "budget-exhausted-machine-retired",
    ("legacy-quiet", "observe"): "budget-exhausted-absorbing",
    ("legacy-quiet", "wait"): "budget-exhausted-absorbing",
    ("legacy-quiet", "retire"): "budget-exhausted-retired",
    ("legacy-quiet", "spent"): "budget-exhausted-retired",
    ("legacy-quiet", "hold-linked-pr"): "budget-exhausted-absorbing-linked-pr",
    ("dedupe", "observe"): "budget-exhausted-absorbing",
    ("dedupe", "wait"): "budget-exhausted-absorbing",
    ("dedupe", "retire"): "budget-exhausted-retired",
    ("dedupe", "spent"): "budget-exhausted-retired",
    ("dedupe", "hold-linked-pr"): "budget-exhausted-absorbing-linked-pr",
    ("unchanged", "observe"): "budget-exhausted-absorbing",
    ("unchanged", "wait"): "budget-exhausted-absorbing",
    ("unchanged", "retire"): "budget-exhausted-retired",
    ("unchanged", "spent"): "budget-exhausted-retired",
    ("unchanged", "hold-linked-pr"): "budget-exhausted-absorbing-linked-pr",
}


def budget_exhausted_bucket(action, disposition=None):
    """The ONE census bucket for a budget-exhaustion outcome — a CLOSED enum that RAISES on an
    undeclared (action, disposition) pair rather than inventing a counter nobody reads.

    This is what makes "the counts sum to the population" checkable: every path out of the
    deferred-issue budget-exhaustion leg must name its bucket through this function, so a new
    exit added without a bucket fails loudly at the call site instead of vanishing from the
    tick summary."""
    key = (action, disposition)
    if key not in BUDGET_EXHAUSTED_CENSUS:
        raise KeyError(
            f"undeclared budget-exhaustion census key {key!r}: every exit from the "
            "deferred-issue budget leg must map to exactly one bucket (declare it in "
            "BUDGET_EXHAUSTED_CENSUS) — refusing to count it as nothing")
    return BUDGET_EXHAUSTED_CENSUS[key]


def absorbing_park_disposition(action, streak_started_at, now, linked_open_pr=False,
                               already_retired=False,
                               grace=PARK_ABSORBING_GRACE_SECONDS, log=print):
    """PURE. What to do about a park that has landed on an ABSORBING ladder action — the exit
    `park_ladder_decision` structurally cannot provide for itself.

    `action` is the ladder action; `streak_started_at` is the canonical stamp of the OLDEST
    still-live absorbing receipt for this window ("" or None when none has been written yet);
    `now` is a unix instant; `linked_open_pr` says whether the source issue has an open worker PR.

    Returns (disposition, streak_started_at) with disposition one of:

    - "not-absorbing": `action` is not in PARK_ABSORBING_ACTIONS (`freeze` and `park` and
      `terminal` all own their own exits). The caller's existing behaviour is unchanged.
    - "hold-linked-pr": the issue has an OPEN worker PR. Retiring it would apply `needs:user`,
      which is exactly the 2026-07-18 mass-park failure — a human hold on the source issue
      terminally strips its open PR from the review loop. The park stands, uncounted-as-retired
      and separately bucketed, and the PR's own review lane owns the outcome. FAIL-CLOSED: the
      caller passes True whenever it cannot PROVE the issue has no linked open PR.
    - "observe": no receipt for this window yet — START the clock. The caller writes exactly ONE
      durable observation receipt. Nothing else: no label, no escalation.
    - "wait": the clock is running and the grace has NOT elapsed. Write nothing (the receipt is
      already durable); count it and stay quiet.
    - "spent": this window's terminal is ALREADY receipted. Stay quiet — the disposition was
      taken once and is durable. This is what caps retirement at one per window even when a
      sticky human unpark VETOED the `needs:user` write, leaving the item in the lane: without
      it, every later expired clock would retire it again.
    - "retire": the absorbing state has PERSISTED past `grace`. The caller escalates to the
      question-class terminal — receipt first, then the veto-checked `needs:user` write — which
      both records the disposition on the issue and removes it from the deferred-retry lane
      (dispatch.yml's PLAN filter drops any `needs:*` label), releasing its package.

    UNPROVABLE TIME FREEZES, it never retires: a `streak_started_at` that will not parse returns
    ("wait", "") with a loud log. The conservative residue is that the next tick re-observes and
    writes a good receipt — the streak restarts, escalation is delayed, never fabricated. This is
    the same direction park_generation_records takes on a malformed cutoff.

    RE-ADMISSION IS CONSUMED ONCE AND CAPPED, and this function is why: the caller keys the
    receipt on the ladder's WINDOW, and only a human gesture mints a new window key
    (readmission_cutoff). So a re-admitted item starts a brand-new streak with zero receipts, gets
    exactly one fresh grace, and cannot inherit the aged clock of the park it was admitted out of.
    """
    if action not in PARK_ABSORBING_ACTIONS:
        return ("not-absorbing", "")
    if already_retired:
        return ("spent", "")
    if linked_open_pr:
        return ("hold-linked-pr", streak_started_at or "")
    if not streak_started_at:
        return ("observe", "")
    try:
        # Ordering by PARSED instants, never raw strings (round-5 finding 2): a space-separator
        # stamp sorts lexicographically before a `T` one of a LATER instant, which would read a
        # minutes-old streak as hours old and retire it on the spot.
        started = parse_ts(streak_started_at)
        threshold = datetime.fromtimestamp(int(now) - int(grace), tz=timezone.utc)
    except (ValueError, TypeError, OSError, OverflowError):
        log(f"::warning::absorbing-park clock unreadable ({streak_started_at!r}) — freezing: "
            "no retirement on unprovable time; the next tick re-observes")
        return ("wait", "")
    if started <= threshold:
        return ("retire", streak_started_at)
    return ("wait", streak_started_at)


class MalformedTimelineError(RuntimeError):
    """A label-timeline payload whose RELEVANT shape cannot be trusted (non-dict event,
    unreadable label field, or a relevant event without a readable timestamp). Raised instead
    of silently dropping the entry: a dropped malformed page/event could hide the newest human
    unlabel, so each caller applies its documented fail direction instead (veto => suppress the
    park; budget/readmission => the full historical count)."""


def parse_ts(value):
    """Parse ONE decision-logic timestamp to a timezone-AWARE datetime, raising ValueError on
    anything else — the single parser EVERY timestamp ordering comparison in the park/budget
    decision surface (park_policy / worker-pr / worker-issue / dispatch-claim) must route
    through (round-5 finding 2). Raw ISO-8601 STRINGS do not order correctly across
    equally-valid spellings: "2026-07-23 10:30:00Z" (space separator) parses fine yet sorts
    lexicographically BEFORE "2026-07-23T09:00:00Z", so a string compare would read a
    post-cutoff receipt as pre-cutoff and silently mint budget (and a "+00:00" spelling
    sorts before the same instant's "Z" spelling, breaking tie handling). A NAIVE stamp (no
    UTC offset) also raises: it cannot be soundly ordered against aware stamps. Window-key
    IDENTITY (receipt-set membership / dedupe) stays string EQUALITY, but over the CANONICAL
    spelling (canonical_ts, round-6 finding 2) — exact source-string identity could not
    round-trip a space-form cutoff through the receipt marker.

    Round-7 finding 1: a stamp can PASS fromisoformat yet OVERFLOW UTC normalization —
    "0001-01-01T00:00:00+23:59" parses to an aware datetime whose astimezone(utc) subtracts
    the offset under datetime.min and raises OverflowError, escaping every ValueError-keyed
    malformed-timestamp handler and CRASHING the sweep (canonical_ts sits outside the
    per-surface try in readmission_cutoff, and park_generation_cutoffs guards receipts with
    valid_timestamp before canonicalizing). parse_ts therefore PROVES UTC normalization here
    and re-raises OverflowError/OSError as ValueError, so valid_timestamp rejects the stamp
    and every existing handler (freeze / receipt-absent / event-cannot-prove) applies
    unchanged. Only stamps within ~a day of year 1 / year 9999 are affected — never a real
    GitHub event time."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"not a timestamp: {value!r}")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"naive (offset-free) timestamp cannot be ordered: {value!r}")
    try:
        parsed.astimezone(timezone.utc)
    except (OverflowError, OSError) as exc:
        raise ValueError(f"timestamp overflows UTC normalization: {value!r}") from exc
    return parsed


def canonical_ts(value):
    """The ONE canonical spelling of a decision-logic timestamp: parse_ts(value) normalized
    to UTC and rendered as compact ISO-8601 Z-form ("2026-07-23T10:30:00Z" — T separator,
    trailing Z, no spaces, deterministic). Round-6 finding 2: window-key/receipt identity
    previously kept the EXACT source-string spelling, but a space-form cutoff
    ("2026-07-23 10:30:00Z") cannot round-trip through the receipt marker — worker-pr's
    `cutoff=(\\S+) -->` pattern can never match a space — so the gen-1 receipt was written
    unparseable, never deduped, and the ladder minted generation 1 forever (the terminal
    gen-2 escalation was unreachable). Every window key is therefore canonicalized at
    WRITE/derive time (latest_human_unlabel / readmission_cutoff / park_ladder_decision)
    and every receipt reader canonicalizes at parse time (worker-pr
    park_generation_cutoffs), so receipt equality is over one deterministic spelling.
    Raises ValueError exactly like parse_ts on anything unparseable — including a stamp
    that parses but OVERFLOWS UTC normalization (round-7 finding 1; parse_ts proves the
    normalization, and the wrap here is the defensive rail against drift): every caller
    keys its malformed-timestamp handling on ValueError, and an OverflowError would crash
    the sweep instead."""
    try:
        return parse_ts(value).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError) as exc:
        raise ValueError(f"timestamp overflows UTC normalization: {value!r}") from exc


def valid_timestamp(value):
    """STRICT timestamp check for every stamp consumed by a park decision (round-3 finding
    3/4; round-5 finding 2): True iff parse_ts accepts it — ISO-8601 WITH a UTC offset,
    parseable to an aware datetime. A garbage string like "zzz" (or a naive, unorderable
    stamp) would otherwise slip into an ordering decision and silently mint (or destroy) a
    veto/cutoff."""
    try:
        parse_ts(value)
    except ValueError:
        return False
    return True


def _event_rows(events, label):
    """Normalize a GitHub issue-timeline payload to (created_at, kind, actor_login, via_app)
    rows for `label`. RAISES MalformedTimelineError on any malformed RELEVANT shape — a
    non-dict event, a labeled/unlabeled event whose label field is unreadable, or a matching
    event without a STRICT ISO-8601 created_at — because a silently dropped entry could be the
    newest human unlabel (the exact event the veto and the readmission window hinge on).
    Irrelevant event kinds and readable other-label events are skipped as before. A
    missing/unreadable actor is preserved as login "" (an UNVERIFIABLE actor — not human on
    either side), and a non-null performed_via_github_app marks the event as App-driven (never
    human).

    Round-3 finding 3/4 (timestamp direction, deliberately RAISE not skip): a relevant event
    whose created_at fails the strict ISO parse can never prove a gesture — and raising is
    uniformly AT LEAST as conservative as skipping at every consumer (veto => the park is
    suppressed; readmission/budget => the full historical count; capacity_park_readmitted =>
    stays parked). Skipping instead would be ANTI-conservative at two sites: a skipped
    malformed park-APPLICATION event shrinks latest_labeled/latest_park, making the veto and
    the readmission proof EASIER on corrupt data."""
    rows = []
    for event in events or []:
        if not isinstance(event, dict):
            raise MalformedTimelineError("timeline event is not an object")
        kind = event.get("event")
        if kind not in ("labeled", "unlabeled"):
            continue
        label_field = event.get("label")
        name = label_field.get("name") if isinstance(label_field, dict) else None
        if not isinstance(name, str):
            raise MalformedTimelineError(f"{kind} event has an unreadable label field")
        if name != label:
            continue
        created = event.get("created_at")
        if not valid_timestamp(created):
            raise MalformedTimelineError(
                f"{kind} event for {label} has an unreadable/non-ISO-8601 created_at")
        actor = event.get("actor")
        login = str(actor.get("login", "")) if isinstance(actor, dict) else ""
        via_app = event.get("performed_via_github_app") is not None
        rows.append((created, kind, login, via_app))
    return rows


def _human_probe(is_human):
    """Wrap the caller-supplied strict maintainer probe with a per-decision login cache and the
    documented failure direction: a probe that raises (or is absent) yields NOT-human — an
    unverifiable actor must never mint a veto or a budget window."""
    cache = {}

    def probe(login):
        if login not in cache:
            try:
                cache[login] = bool(is_human(login)) if is_human is not None else False
            except Exception:  # noqa: BLE001 — probe failure = unverifiable = not human
                cache[login] = False
        return cache[login]

    return probe


def _is_proven_human(login, via_app, probe):
    """The ONE human test both the veto and the readmission window share (the strict
    worker-issue._is_human_maintainer pattern): a present, non-`[bot]` login, NOT App-driven
    (performed_via_github_app is null), whose collaborator permission the probe confirms in
    HUMAN_MAINTAINER_PERMISSIONS. Anything unverifiable is NOT human."""
    return bool(login) and not login.endswith("[bot]") and not via_app and probe(login)


def _is_proven_machine(login, via_app, machine_logins):
    """POSITIVE proof that an event was performed by AUTOMATION: an App-driven event
    (`performed_via_github_app` non-null), a `[bot]`-suffixed login, or a login the caller named
    as its own automation in `machine_logins` (case-insensitive, the `bot_login` convention every
    other reader in this module already uses).

    Deliberately NOT the negation of `_is_proven_human`. Everywhere the boolean ownership
    projection is consulted the answer authorises a DELETE, so "not provably human" is the safe
    reading. `human_hold_deleted_by_machine` asks the opposite-facing question — it authorises
    RE-APPLYING a hold — and there "not provably human" would let an actor whose collaborator
    probe merely FAILED stand in for the bot, so a maintainer's own removal could be undone. An
    unverifiable actor is neither human nor machine here; both proofs are positive and an actor
    that satisfies neither yields no action at all."""
    if via_app:
        return True
    login = str(login or "")
    if not login:
        return False
    return login.endswith("[bot]") or login.casefold() in machine_logins


def human_unpark_veto(events, label, is_human=None):
    """(veto, detail) for applying park `label` given the issue/PR timeline `events`.

    Most-recent-event-wins: the veto stands iff the newest PROVEN-HUMAN `unlabeled` event for
    `label` is at least as recent as the newest `labeled` event (by ANY actor — a human
    RE-adding the label is a labeled event, so it re-enables automation parking). "Proven
    human" is the strict maintainer probe (`is_human(login)` — collaborator permission in
    HUMAN_MAINTAINER_PERMISSIONS), with `[bot]` logins, App-driven events
    (performed_via_github_app), missing logins, and failed/denying probes all counting as NOT
    human: an unverifiable actor must never mint a veto. An exact INSTANT tie between a
    proven-human removal and an application fails toward NOT parking (ordering is by PARSED
    aware datetimes — parse_ts, round-5 finding 2 — never by raw strings, so a "+00:00"
    spelling ties with the same instant's "Z" spelling instead of sorting before it).
    Malformed relevant events RAISE MalformedTimelineError (the park_vetoed wrapper
    suppresses the park on it)."""
    rows = _event_rows(events, label)
    probe = _human_probe(is_human)
    latest_labeled = max(
        (parse_ts(created) for created, kind, _login, _app in rows if kind == "labeled"),
        default=None)
    human_unlabels = [(parse_ts(created), created)
                      for created, kind, login, via_app in rows
                      if kind == "unlabeled" and _is_proven_human(login, via_app, probe)]
    if human_unlabels:
        latest_instant, latest_stamp = max(human_unlabels)
        if latest_labeled is None or latest_instant >= latest_labeled:
            return True, f"human unlabeled {label} at {latest_stamp}"
    return False, ""


def park_vetoed(repo, number, label, fetch_events, is_human=None, log=print):
    """True when applying park `label` to `repo#number` must be SUPPRESSED (the shared
    `_human_unpark_veto` gate every park writer calls before its label write).

    `fetch_events(repo, number)` returns the full parsed issue timeline
    (`repos/{repo}/issues/{number}/timeline`, paginated — the newest events are on the LAST
    page, so a truncated read must raise rather than return a prefix). `is_human(login)` is the
    per-repo strict maintainer probe. ANY fetch failure OR malformed timeline shape suppresses
    the park with a loud log line: a TIMELINE failure fails open ONLY in the direction of NOT
    parking — never park when you cannot prove no human veto. (An UNVERIFIABLE ACTOR is the
    opposite: it is not a timeline failure, and it mints no veto — see the module header.)"""
    try:
        events = fetch_events(repo, number)
        veto, detail = human_unpark_veto(events, label, is_human=is_human)
    except Exception as exc:  # noqa: BLE001 — ANY read/shape failure must suppress the park
        log(f"park suppressed: timeline read failed for {repo}#{number} "
            f"({exc}); cannot prove no human unpark veto for {label} — NOT parking")
        return True
    if veto:
        log(f"park suppressed: {detail} (repo {repo}#{number}) more recently than any "
            f"automation application — a human unpark is sticky; NOT re-applying {label}")
    return veto


def latest_human_unlabel(repo, number, label, fetch_events, is_human=None, log=print):
    """Newest PROVEN-HUMAN `unlabeled` timestamp for `label` on `repo#number`, or None.

    The ROUND-BUDGET readmission window (live evidence sparq#2804/PR#3442, 2026-07-23): a human
    removing a park label is an explicit re-admission, so the budget re-derivation counts only
    rounds recorded AFTER this timestamp. "Human" is the SAME strict maintainer probe as the
    veto (worker-issue._is_human_maintainer pattern) — an unverifiable actor opens NO window.
    A fetch failure or malformed timeline shape returns None with a LOUD log line: no cutoff =
    the full historical count, the old conservative behaviour (the OPPOSITE fail direction to
    the veto's timeline-failure handling, by design — silently retrying forever is the harm
    here, over-parking is the harm there)."""
    try:
        events = fetch_events(repo, number)
        rows = _event_rows(events, label)
    except Exception as exc:  # noqa: BLE001 — a budget question must never crash the sweep
        log(f"readmission window unknown: timeline read failed for {repo}#{number} ({exc}); "
            f"the round budget keeps the FULL historical count (no readmission credit for "
            f"{label})")
        return None
    probe = _human_probe(is_human)
    candidates = [(parse_ts(created), created)
                  for created, kind, login, via_app in rows
                  if kind == "unlabeled" and _is_proven_human(login, via_app, probe)]
    # Ordering is by parsed instant (round-5 finding 2); the RETURNED value is the CANONICAL
    # spelling (canonical_ts, round-6 finding 2) so receipt window keys share one
    # deterministic identity across equally-valid source spellings.
    return canonical_ts(max(candidates)[1]) if candidates else None


def readmission_cutoff(repo, pr_number, issue_number, fetch_events, is_human=None, log=print,
                       labels=READMISSION_LABELS, on_unreadable=None):
    """The budget readmission cutoff for a worker PR (or a bare source issue): the LATEST
    proven-human `unlabeled` event for ANY of `labels` (default READMISSION_LABELS —
    needs:user / status:parked / review:parked) across the PR itself and its provenance-linked
    source issue (either surface is an explicit human re-admission; latest event wins;
    ordering is by PARSED instants — parse_ts, round-5 finding 2 — while the returned cutoff
    is the CANONICAL spelling — canonical_ts, round-6 finding 2: a source-spelled space-form
    cutoff could never round-trip through the receipt marker, so gen-1 repeated forever).
    `issue_number` may be falsy (no linked issue) — only the PR timeline is consulted.

    FAIL CLOSED ON ANY PARTIAL VIEW: if EITHER timeline read fails (or returns a malformed
    shape), the whole cutoff is None — the full historical count — with a loud log line. A
    surviving side must never mint readmission credit while the other side is unreadable: the
    unreadable side could hold a newer PARK application or a newer event that changes the
    picture, and a budget window opened on half the evidence silently retries forever. None =
    no proven human unlabel anywhere = the caller keeps the full historical count.

    `on_unreadable` (default None — the plain full-count path) lets an ESCALATION-LADDER
    caller distinguish a failed/malformed read (return `on_unreadable`, typically
    WINDOW_UNREADABLE) from a genuinely windowless timeline (None): the ladder must FREEZE on
    an unreadable view — never mint a PARK_WINDOW_NONE receipt or advance a generation on
    unproven data — while budget consumers keep the conservative full count either way."""
    probe = _human_probe(is_human)
    stamps = []
    surfaces = [pr_number] + ([issue_number] if issue_number else [])
    for number in surfaces:
        try:
            events = fetch_events(repo, number)
            for label in labels:
                stamps.extend(
                    (parse_ts(created), created)
                    for created, kind, login, via_app in _event_rows(events, label)
                    if kind == "unlabeled" and _is_proven_human(login, via_app, probe))
        except Exception as exc:  # noqa: BLE001 — a budget question must never crash the sweep
            log(f"readmission window unknown: timeline read failed for {repo}#{number} "
                f"({exc}); NO readmission credit on a partial view — the budget keeps the "
                f"FULL historical count")
            return on_unreadable
    return canonical_ts(max(stamps)[1]) if stamps else None


def capacity_park_readmitted(repo, pr_number, issue_number, fetch_events, is_human=None,
                             log=print, consumed=frozenset()):
    """True when a capacity park (durably receipted, whatever labels currently remain) has
    been superseded by an UNCONSUMED human readmission gesture: the readmission cutoff (latest
    proven-human unlabel of any READMISSION_LABELS across both surfaces) is strictly MORE
    RECENT than the LATEST park-label application on EITHER surface — the max over `labeled`
    events for ANY of READMISSION_LABELS across the PR and its provenance-linked source issue
    (round-5 finding 1: the old PR-only `review:parked` compare accepted a stale gesture after
    the sequence PR park lands -> maintainer unlabels the PR park -> a LATER source-side
    `status:parked` lands -> triage removes the source label; the completed park was NEWER on
    the source surface, so the gesture proved nothing about it — the recency proof must span
    the SAME surfaces and labels the cutoff itself spans) — AND that cutoff's window has not
    already been consumed-and-receipted. Most-recent-event-wins, with ambiguity (no cutoff, a
    failed/malformed read on either surface, or an instant tie) failing toward STAYING PARKED —
    re-admission dispatches real work, so it runs only on proven, newest evidence. Ordering is
    by parsed instants (parse_ts, round-5 finding 2), never raw strings.

    `consumed` is the durable receipt set (worker-pr park_generation_cutoffs — bot-authored
    only, CANONICAL window keys — canonical_ts, round-6 finding 2 — matching the canonical
    cutoff this helper derives): a gesture whose cutoff is already receipted was consumed by
    a previous budget window that then re-exhausted; it must never re-admit AGAIN — this is
    what keeps the proof label-INDEPENDENT (round-3 finding 2): a veto-suppressed re-apply leaves
    no fresh `labeled` event to out-date the old gesture, so without the receipt check a
    single stale gesture would re-admit forever."""
    cutoff = readmission_cutoff(repo, pr_number, issue_number, fetch_events,
                                is_human=is_human, log=log)
    if not cutoff:
        return False
    if cutoff in consumed:
        log(f"readmission declined for {repo}#{pr_number}: the human gesture at {cutoff} "
            "was already consumed by a receipted budget window — a FRESH gesture is "
            "required")
        return False
    latest_park, _human_park, readable = park_applications(
        repo, pr_number, issue_number, fetch_events, log=log)
    if not readable:
        return False
    return latest_park is None or parse_ts(cutoff) > latest_park


def park_application_view(repo, pr_number, issue_number, fetch_events, is_human=None, log=print):
    """(latest_park_instant, latest_was_human, human_labels, readable) — the FULL park-application
    view for `repo#pr_number` and its provenance-linked source issue: the LATEST `labeled` event
    for ANY of READMISSION_LABELS across BOTH surfaces (round-5 finding 1: the recency proof must
    span the same surfaces and labels the readmission cutoff spans).

    `latest_park_instant` is a parsed aware datetime (None when no park label was ever applied on
    either surface — e.g. every write was veto-suppressed). `latest_was_human` is True when a
    PROVEN HUMAN (the strict maintainer probe; `is_human=None` can prove nothing and yields False)
    applied a park at that latest instant. `human_labels` is the sorted tuple of the park labels a
    proven human applied AT that latest instant — WHICH label, not merely that there was one; it is
    empty whenever `latest_was_human` is False. `readable` is False on ANY read/shape failure, and
    every caller's documented fail direction on that is to STAY PARKED.

    WHY `human_labels` EXISTS (registry: human-applied machine park). `latest_was_human` alone
    conflates two states with opposite correct answers, and the conflation was a permanent stall by
    construction. A proven human who applies `needs:user` is asking a question no machine may
    answer. A proven human who applies `review:parked` / `status:parked` has selected the
    MACHINE-owned soft hold — the label whose own published description (MACHINE_PARK_DESCRIPTION)
    promises it clears on "human unlabel, proven recovery, or capped retry" — so honouring that
    promise is honouring the hold the actor actually chose, not overriding it. MEASURED on
    sparq-org/sparq 2026-07-28: 7 open worker PRs (#3620 #4199 #4212 #4218 #4338 #4355 #4519) sat
    on a human-applied `review:parked`; driving THIS module against their live GitHub timelines
    with the strongest possible cause-recovery evidence returned `None` /
    PARK_REFUSAL_HUMAN_APPLIED for every one, i.e. the refusal was about WHO applied the label and
    could not be lifted by any amount of recovery. On five of them the same actor had removed
    `review:needs-user` in the SAME second — it was converting the human terminal back to the
    machine soft hold, an *un*-hold — and the bot's own park-reason receipts on those PRs read
    `class=capacity cause=budget`, so the actor and the bot agreed the cause was capacity.

    Extracted verbatim from capacity_park_readmitted so the human path and the automatic path
    (capacity_park_admission) can never disagree about when a park was applied."""
    probe = _human_probe(is_human)
    rows = []
    for number in [pr_number] + ([issue_number] if issue_number else []):
        try:
            events = fetch_events(repo, number)
            for label in READMISSION_LABELS:
                for created, kind, login, via_app in _event_rows(events, label):
                    if kind != "labeled":
                        continue
                    rows.append((parse_ts(created), label, str(login),
                                 _is_proven_human(login, via_app, probe)))
        except Exception as exc:  # noqa: BLE001 — ambiguity stays parked
            log(f"readmission unknown: timeline read failed for {repo}#{number} ({exc}); "
                "the capacity park stands")
            return None, False, (), (), None, False
    if not rows:
        return None, False, (), (), None, True
    latest = max(instant for instant, _l, _login, _h in rows)
    at_latest = [row for row in rows if row[0] == latest]
    # An instant tie between a human and a machine application resolves toward HUMAN-OWNED: the
    # automatic path must never clear a park a human might have applied. Every human label at the
    # tie is recorded, so a tie that includes a human `needs:user` still refuses below even when a
    # machine `review:parked` shares the instant.
    latest_human = any(human for _i, _l, _login, human in at_latest)
    human_labels = {label for _i, label, _login, human in at_latest if human}
    human_logins = {login for _i, _l, login, human in at_latest if human}
    # THE LOWER BOUND IS THE NEWEST FOREIGN APPLICATION — the newest one by an actor OTHER than the
    # actor(s) applying the latest park — NOT simply the second-newest write.
    #
    # A park is a PAIR, and its writer applies both halves in ONE operation seconds apart:
    # reconcile-park-misescalation.py writes its attestation, then `review:parked` on the PR, then
    # `status:parked` on the source issue. MEASURED on sparq #4375 — attestation 19:23:58,
    # PR label 19:23:59, issue label 19:24:02. Taking the second-newest WRITE as the bound made the
    # writer's own PR-side half look like a closed earlier episode and excluded its own
    # attestation, so the whole population refused at the SWEEP level (which reads both surfaces)
    # while passing a PR-only predicate check. One actor's contiguous burst is ONE application; the
    # episode boundary is the last time somebody ELSE parked this PR.
    # Relative to the HUMAN appliers specifically, not to every login at the latest instant. On an
    # instant TIE between a human and a machine application — which the tie rule resolves toward
    # HUMAN-OWNED — using every login would exclude that machine actor's EARLIER parks from
    # `foreign`, moving the bound earlier and WIDENING the window. Wider is the anti-conservative
    # direction, and the park being cleared on this branch is the human-applied one by definition.
    appliers = set(human_logins) or {login for _i, _l, login, _h in at_latest}
    foreign = [instant for instant, _l, login, _h in rows
               if login not in appliers and instant < latest]
    previous = max(foreign) if foreign else None
    return (latest, latest_human, tuple(sorted(human_labels)), tuple(sorted(human_logins)),
            previous, True)


def well_formed_reason_records(reason_records):
    """The park-reason receipts of `reason_records` that are shaped like receipts at all.
    ONE spelling of "which of these count", shared by human_park_capacity_proof (which asks what
    they SAY) and park_is_receiptless (which asks whether any exist). Two hand-copied filters would
    let the two questions drift, and the whole receipt-less exit turns on them agreeing."""
    return [record for record in (reason_records or []) if isinstance(record, dict)]


def park_is_receiptless(reason_records):
    """[registry #1309] True when NOT ONE well-formed bot park-reason receipt exists for this PR.

    THE POPULATION THIS NAMES, and why it needed a name. human_park_capacity_proof refuses on two
    materially different states and returns the same answer for both:

      * an OFF-CLASS receipt stands ("a non-capacity park-reason receipt stands in this PR's
        history") — the machine DID form an opinion about this park and it was not "capacity". A
        raised question. There is nothing to fix and nothing here touches it.
      * NO receipt exists at all — the machine never formed any opinion. Measured on
        sparq-org/sparq (2026-07-26/29): of 24 open PRs on `review:parked` with no human-terminal
        hold, 17 had never had the label removed, and 14 of those carried no cause receipt of any
        kind. The un-park path reads the receipt to learn the cause and then requires that cause to
        have recovered — so a park with NO cause has no cause to prove recovered, and no recovery
        that could ever satisfy the gate. Not "waiting on a closed gate": waiting on a gate that
        CANNOT BE EVALUATED for it. Permanent by construction.

    Absence-of-a-receipt is still not permission — see machine_operated_park_proof for the second,
    independent proof the void exit requires on top of it. This predicate only says which question
    is being asked."""
    return not well_formed_reason_records(reason_records)


def human_park_capacity_proof(reason_records):
    """(proven, detail) — whether the BOT's OWN machine-readable receipts positively classify this
    PR's park episode as CAPACITY. The extra gate a HUMAN-applied machine park must pass, and one a
    bot-applied park passes by construction rather than by luck.

    WHY THIS EXISTS, measured rather than assumed (review of the first cut of this change). Keying
    admission on the label the actor chose was correct about OWNERSHIP and silent about CAUSE. Run
    against the live sparq population it admitted 12 PRs, and the recovery evidence that fired was
    `sustained_fleet_health_evidence` — the labelled AGED-OUT HEURISTIC — for **12 of 12**;
    `capacity_recovery_evidence`, the proof that THIS park's own cause cleared, fired for NONE. The
    only per-PR condition left was that the park was more than SUSTAINED_HEALTH_SPAN_SECONDS old.
    An exit briefed as "gated on proven cause-recovery, never elapsed time" was, for that
    population, a six-hour timer wearing an evidence gate's name.

    Worse, the sub-population where that mattered most was the one with NO receipts at all: 5 of
    the 12 (#4197 #4207 #4212 #4222 #4318) carried no bot park-reason marker of any kind, and
    `cause_gated_park_episode` is INERT BY ITS OWN CLAUSE 1 in exactly that case — so registry
    #769's "age is not its own recovery proof" guard could not fire for them either. Nothing in the
    pipeline had ever formed a machine-readable opinion that those parks were capacity-class, and
    the fix would have cleared them anyway.

    A bot capacity park cannot be in that state: PARK_CAUSES carries `capacity-unspecified`
    precisely so that EVERY capacity park emits SOME cause receipt. Requiring the receipt therefore
    does not invent a new obligation — it makes the human-applied path prove what the bot-applied
    path already proves, which is the one-shared-rule discipline the rest of this module runs on.
    It also confines the new admission to the population where #769's guard is live.

    ALL of the following must hold; every ambiguity refuses:
      1. At least one WELL-FORMED bot park-reason receipt exists. Absence is not permission — it is
         the absence of any machine opinion at all. (`parse_park_reason` already drops a marker
         whose `class=` contradicts its cause, so a forged `class=capacity cause=injection` is not
         a receipt here.)
      2. NO receipt anywhere in the history is non-capacity. Deliberately UNCONDITIONAL and
         ORDER-INDEPENDENT, the LEGACY_PARK_DENY_PROSE rule and for the same measured reason: a
         raised question is a property of the PR's whole history, not of its newest comment, and a
         recency rule would hand back a PR whose `injection` receipt happened to be followed by a
         capacity one.

    THIS PREDICATE IS ENTITY-SCOPED, NOT INSTANCE-SCOPED, AND THAT IS NOT SUFFICIENT ON ITS OWN.
    It answers "has the machine EVER classified a park on this PR as capacity, and never as a
    question" — a monotone property of the PR's whole history. The instance question, "is this
    record ABOUT the park application I am clearing", is answered separately by
    park_instance_attested, and capacity_park_admission requires BOTH.

    The first cut declined an instance binding on a rationale that was simply FALSE, and the
    correction matters more than the original claim: it said `cause_gated_park_episode` already
    answers the episode question upstream. It does not. That predicate keys on
    CAUSE_GATED_PARK_OWNERS — `GROOM_AGE_PARK_MARKER` and `CONFLICT_STUCK_PARK_MARKER` — and NOT on
    PARK_REASON_MARKER at all, so on the shape this gate admits it returns `(False, "")`; and the
    sweep consults it BEFORE the admission and `continue`s on a hit, so it can never be live for a
    PR this gate admits. It could not have covered the instance axis for any PR, ever.

    What that missing conjunct cost, measured: all three PRs the first cut admitted rode a
    `gen=1 class=capacity cause=budget` receipt written for a bot episode the bot itself had
    UNLABELLED 9-19 hours earlier, and between receipt and park the bot had escalated all three to
    `review:needs-user`. Generalised, that is worse than the three PRs: because the class is
    established about ANYTHING in the PR's history, forever and monotonically, any PR that was ever
    bot-capacity-parked would have been permanently immune to a hand-applied hold."""
    records = well_formed_reason_records(reason_records)
    if not records:
        return False, ("no bot park-reason receipt exists, so nothing ever classified this park "
                       "as capacity — a human applied it and the machine has no opinion")
    off_class = sorted({str(record.get("cause")) for record in records
                        if record.get("class") != PARK_CLASS_CAPACITY})
    if off_class:
        return False, ("a non-capacity park-reason receipt stands in this PR's history "
                       f"({'/'.join(off_class)}) — a raised question is a property of the whole "
                       "history, never of the newest comment")
    # No third "the newest receipt is capacity" check: gate 2 already rejects EVERY non-capacity
    # receipt, so such a branch could never execute. The first cut had it, line-granular coverage
    # showed it at 0%, and dead code that asserts a rule is worse than no code — it reads like a
    # guard while proving nothing. If gate 2 is ever narrowed to "the newest wins", the rule has to
    # be written HERE, with a test that reaches it.
    return True, (f"the bot's own park-reason receipt classifies this park episode as "
                  f"class=capacity cause={records[-1].get('cause')}")


# The durable attestation `reconcile-park-misescalation.py` writes IMMEDIATELY BEFORE it converts a
# mis-escalated human terminal into `review:parked` — receipt-first, the ordering every park writer
# in this tree uses. Declared HERE, and imported by that script, so the writer and the reader can
# never drift onto two spellings.
RECONCILE_MARKER = "<!-- sparq-park-misescalation-reconciled:v1"

# THE ATTESTATION VOCABULARY — a LIST, in the shape of CAUSE_GATED_PARK_OWNERS, because the
# misescalation reconciler is not the only program of its kind. Registry #956 (in review as this
# lands) adds `reconcile-conflict-park.py`, whose own `<!-- sparq-conflict-park-reconciled:v1`
# attests the SAME act — a hand-run, per-PR-audited conversion of a machine-manufactured hold into
# `review:parked` — for the conflict-park population. Adding it is ONE LINE here once #956 merges
# and its spelling is fixed; it is deliberately not pre-added, because pinning an unmerged
# constant is how two files come to disagree. A converter whose marker is NOT in this tuple simply
# does not bind an instance, which is the conservative direction: its PRs stay parked.
PARK_RECONCILE_ATTESTATIONS = (
    (RECONCILE_MARKER, "reconcile-park-misescalation.py"),
)


def reconcile_attestations(comments):
    """[{"login", "at"}] for every reconcile attestation in `comments`, oldest first.

    NO trust filter here on purpose — park_instance_attested applies the one that is actually
    sound for this record, which is not "was it the bot" (the script is HAND-RUN under a
    maintainer token, so its markers are authored by that maintainer, not by the App) but "was it
    the same actor that applied the park it is attesting to"."""
    rows = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        body = str(comment.get("body", ""))
        if not any(marker in body for marker, _owner in PARK_RECONCILE_ATTESTATIONS):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        rows.append({"login": login, "at": comment.get("created_at")})
    return rows


def park_instance_attested(attestations, parked_at, previous_parked_at, park_logins):
    """(attested, detail) — whether a reconcile attestation belongs to THE PARK APPLICATION BEING
    CLEARED, rather than merely to the same PR.

    THE RULE THIS ENFORCES: *is this record ABOUT the thing I am admitting, or merely about the
    same entity?* human_park_capacity_proof answers the second question. This answers the first,
    and capacity_park_admission requires both.

    An attestation counts iff BOTH hold:

      1. IT WAS WRITTEN BY AN ACTOR THAT APPLIED THIS PARK. `reconcile-park-misescalation.py`
         writes its marker and then, in the same operation, performs the label conversion; so the
         attesting login and the applying login are the same actor by construction. Requiring that
         is what makes the attestation UNFORGEABLE IN THE ONLY DIRECTION THAT MATTERS: a third
         party's marker attests to a park they did not apply and is ignored. It also grants the
         attester no capability they lacked — an actor who can apply this park is by definition a
         proven human (this branch is only reached for a human-applied park), and a proven human
         can already clear a capacity park outright via capacity_park_readmitted's unlabel
         gesture. The attestation only makes an intent that actor already had machine-readable.

      2. IT FALLS INSIDE THIS PARK'S OWN WINDOW: strictly AFTER every earlier park application on
         either surface, and at or before this one. Receipt-first ordering makes the upper bound
         the right one (the marker is written ~1s before the label). The lower bound is what
         actually closes the hole: a record from a CLOSED earlier episode — the 9-to-19-hour-old
         `class=capacity` receipts the first cut rode, or the constructed 19-day-old one — sits at
         or before the previous application and can never re-enter.

    Every ambiguity refuses: no attestation, an unparseable stamp, an unknown park instant, an
    unattributable applying actor, or an attestation outside the window."""
    if parked_at is None:
        return False, "the park application instant is unknown, so nothing can be bound to it"
    applying = {str(login) for login in (park_logins or []) if str(login)}
    if not applying:
        return False, ("the actor that applied this park is unattributable, so no attestation can "
                       "be bound to it")
    for row in attestations or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("login", "")) not in applying:
            continue                      # somebody else's attestation about somebody else's act
        if not valid_timestamp(row.get("at")):
            continue                      # unprovable time can never bind an instance
        at = parse_ts(row["at"])
        if at > parsed_park_instant(parked_at):
            continue                      # written after the park it claims to justify
        if previous_parked_at is not None and at <= previous_parked_at:
            continue                      # belongs to a CLOSED earlier episode
        return True, (f"a park-misescalation attestation by {row['login']!r} at "
                      f"{canonical_ts(row['at'])} falls inside this park's own window")
    return False, ("no park-misescalation attestation by the actor that applied this park falls "
                   "inside this park's window — the capacity classification is about the PR's "
                   "history, not about this park application")


def parsed_park_instant(value):
    """The park application instant as an aware datetime, accepting either the parsed instant the
    view already produced or its canonical string. One coercion, so the window comparison can never
    silently compare a string to a datetime."""
    return value if isinstance(value, datetime) else parse_ts(value)


def human_park_is_machine_owned(latest_was_human, human_labels):
    """Whether a park a PROVEN HUMAN applied may still be evaluated by the AUTOMATIC path: True
    iff the human applied at least one park label and EVERY label they applied at the latest
    instant is in MACHINE_OWNED_PARK_LABELS.

    THE ONE PLACE the label-vs-actor ownership question is answered, so no caller can restate it
    differently. Named (rather than inlined into capacity_park_admission) because two of its three
    branches are unreachable from production data and would otherwise be untestable claims:

    - `latest_was_human` False => False. The caller never asks in that case, but a future caller
      that forgets the guard order must not get an admission out of it.
    - `latest_was_human` True with NO labels => False. park_application_view cannot produce that
      pair today; it is the rail that keeps a drifted/partial view from reading as permission,
      which is the same failure mode label_application_machine_owned documents ("absence of
      evidence is NOT proof of machine ownership").
    - The subset test is POSITIVE and directional: a label MACHINE_OWNED_PARK_LABELS does not name
      refuses. Asking "is none of them human-owned" instead would admit any unclassified label
      added to READMISSION_LABELS later."""
    if not latest_was_human or not human_labels:
        return False
    return set(human_labels) <= MACHINE_OWNED_PARK_LABELS


def park_applications(repo, pr_number, issue_number, fetch_events, is_human=None, log=print):
    """(latest_park_instant, latest_was_human, readable) — the three-element PROJECTION of
    park_application_view, for the callers that only need "when, and was it human" (the human
    readmission path in capacity_park_readmitted, and groom's age-park recency check).

    Deliberately a projection of the ONE walk rather than a second walk: a duplicate traversal is
    exactly how the human path and the automatic path would come to disagree about when a park was
    applied, which is the drift the extraction note below exists to prevent."""
    latest, latest_human, _labels, _logins, _previous, readable = park_application_view(
        repo, pr_number, issue_number, fetch_events, is_human=is_human, log=log)
    return latest, latest_human, readable


def human_owned_holds(labels):
    """The HUMAN-OWNED holds among `labels`: `review:needs-user` or ANY `needs:*`.

    THE ONE RULE for what blocks an automatic re-admission. Today its consumer is
    capacity_park_admission, which REFUSES while any of these is live; it is factored out here
    because a park is a PAIR (`review:needs-user` on the PR AND `needs:user` on the source issue)
    and every future consumer that has to reason about holds — notably the legacy-park migration,
    which must prove none SURVIVES its conversion — has to apply exactly this rule or the two
    will drift. A guard scoped to one symptom does not generalise; one shared rule does."""
    return sorted({label for label in labels
                   if isinstance(label, str)
                   and (label == HUMAN_PR_PARK_LABEL or label.startswith("needs:"))})


def retirement_handback(issue_labels):
    """[registry #797] PURE. What happens to the SOURCE ISSUE when its worker PR is RETIRED by
    the machine terminal — the half of the machine-owned give-up that keeps the WORK alive after
    the attempt is abandoned.

    Returns (action, labels, detail) with `labels` the full desired label set (None when nothing
    is to be written):

    - ("hold", None, ...): a HUMAN-owned hold (`human_owned_holds` — `review:needs-user` or any
      `needs:*`) is live on the issue. A human is holding this work for a reason of their own;
      the retirement records itself on the PR and touches the issue not at all. FAIL-CLOSED: the
      caller passes the labels it could actually read, and an unreadable issue never reaches here.
    - ("reroute", labels, ...): the issue is still on the IMPLEMENTATION route (`role:impl`).
      Re-dispatching the same route is what just failed twice, so the role is swapped to
      `role:research` for architect decomposition — the SAME hand-off the issue-side repeated-
      decline path already makes (dispatch-claim._replace_issue_role_with_research), for the same
      reason: the evidence says the item as specified is not implementable in one pass, not that
      a human must adjudicate it.
    - ("requeue", labels, ...): the issue is already off the impl route (research/docs/ci/site,
      or no role at all). Swapping again would loop, so the labels are returned unchanged and
      only the machine park is lifted by the caller's status transition.

    The role swap is returned as a COMPLETE label set, never an add/remove pair: add-then-remove
    can strand the issue with two role labels and remove-then-add with none, and the planner
    rejects both shapes."""
    labels = {label for label in (issue_labels or []) if isinstance(label, str)}
    held = human_owned_holds(labels)
    if held:
        return ("hold", None,
                f"human-owned hold(s) live on the source issue ({'/'.join(held)}) — the "
                "retirement records itself on the PR and leaves the issue to its human")
    if "role:impl" in labels:
        return ("reroute", sorted((labels - {"role:impl"}) | {"role:research"}),
                "the implementation route exhausted two full budgets — handing the issue to "
                "architect decomposition (role:impl -> role:research)")
    return ("requeue", sorted(labels),
            "the issue is already off the implementation route — the park is lifted without a "
            "second reroute, which would loop")


# --- THE THREE-STATE OWNERSHIP ANSWER --------------------------------------------------------
#
# `label_application_machine_owned` answers a BOOLEAN, and its False conflates two states with
# different correct handling: "a human applied this" and "nobody can tell who applied this".
# For the callers that only ask *may I clear it?* the conflation is right and deliberate — both
# answers are "no". For a caller that must also decide *and is my not-clearing SILENT or LOUD?*
# it is not: a hold nobody can attribute has no proven owner, so leaving it in place is a state
# with no forward edge and must be reported, while a hold a human demonstrably applied has an
# owner and is correctly quiet. Registry #1191 is that distinction going missing.
LABEL_OWNER_HUMAN = "human"
LABEL_OWNER_MACHINE = "machine"
LABEL_OWNER_UNKNOWN = "unknown"


def label_application_ownership(repo, number, label, fetch_events, is_human=None, log=print):
    """Who applied the newest `labeled` event for THIS EXACT `label` on `repo#number`:
    ``LABEL_OWNER_HUMAN``, ``LABEL_OWNER_MACHINE``, or ``LABEL_OWNER_UNKNOWN``.

    UNKNOWN covers every ambiguity — an unreadable timeline, a malformed event shape, and the
    case that matters most, a label with NO `labeled` event at all. Absence of evidence is
    neither proof of machine ownership nor proof of human ownership.

    `label_application_machine_owned` is the boolean projection of this walk (MACHINE, and
    nothing else, is permission), so the two can never disagree about who applied a label."""
    probe = _human_probe(is_human)
    try:
        events = fetch_events(repo, number)
    except Exception as exc:  # noqa: BLE001 — an unreadable timeline proves nothing
        log(f"label ownership unknown for {repo}#{number} {label!r} ({exc}); not clearable")
        return LABEL_OWNER_UNKNOWN
    newest, newest_human = None, False
    try:
        for created, kind, login, via_app in _event_rows(events, label):
            if kind != "labeled":
                continue
            instant = parse_ts(created)
            human = _is_proven_human(login, via_app, probe)
            if newest is None or instant > newest:
                newest, newest_human = instant, human
            elif instant == newest and human:
                newest_human = True     # an instant tie resolves toward HUMAN-owned
    except Exception as exc:  # noqa: BLE001 — malformed shape proves nothing
        log(f"label ownership unknown for {repo}#{number} {label!r} ({exc}); not clearable")
        return LABEL_OWNER_UNKNOWN
    if newest is None:
        log(f"label ownership unknown for {repo}#{number} {label!r}: no `labeled` event exists, "
            "so nothing proves a machine applied it; not clearable")
        return LABEL_OWNER_UNKNOWN
    return LABEL_OWNER_HUMAN if newest_human else LABEL_OWNER_MACHINE


def label_application_machine_owned(repo, number, label, fetch_events, is_human=None, log=print):
    """Whether the newest `labeled` event for THIS EXACT `label` on `repo#number` was applied by
    something other than a proven human — i.e. whether an automated path may clear it.

    Returns False for every ambiguity, including the one that matters most: a label with NO
    `labeled` event at all. Absence of evidence is NOT proof of machine ownership.

    WHY THIS IS NOT park_applications (blocking review finding, #690). park_applications answers
    "when was the newest park applied across READMISSION_LABELS, and was that human" — a question
    about THREE labels (needs:user / status:parked / review:parked) collectively. Using it to
    authorise deleting a DIFFERENT label is a domain mismatch, and it fails in three separate
    directions, all demonstrated by execution:
      - a human-applied `needs:user` is cleared because a LATER bot `status:parked` event exists
        (only `labeled` events are read, so a since-removed park still counts);
      - a human-applied `needs:external-audit` or `needs:ec2` is cleared with NO evidence about
        that label whatsoever;
      - with no park events at all it returns "not human", so absence reads as permission.
    Live prevalence on sparq-org/sparq makes the third case load-bearing rather than theoretical:
    `needs:area` 200, `needs:ec2` 33, `needs:docker` 4, `needs:zk` 3, `needs:external-subject` 2,
    `needs:maintainer` 2, `needs:upstream` 1, and `needs:external-audit` 1 — that last one is the
    sq-qhy4 external accredited-cryptographer audit gate, whose silent deletion is the worst
    single outcome available on this path."""
    return label_application_ownership(
        repo, number, label, fetch_events, is_human=is_human, log=log
    ) == LABEL_OWNER_MACHINE


# --- [registry #976] THE RESIDUAL AN OWNERSHIP PROOF CANNOT CLOSE ----------------------------
#
# `label_application_machine_owned` authorises DELETING a hold, and the careful writers re-prove
# it immediately BEFORE the delete and again immediately AFTER, putting the label back when a
# human application landed inside the window (adjudicate-stuck's check -> delete -> re-check ->
# restore protocol, registry #965). That closes the race as far as the GitHub API allows: labels
# have no compare-and-swap and a label carries no per-application identity, so a maintainer
# re-asserting a hold between the proof and the DELETE leaves NOTHING in the live label set.
#
# One residual is irreducible inside a single sweep. If the process DIES between the delete and
# the restore — runner eviction, token expiry, OOM — nobody re-reads: the human's `labeled` event
# survives only in the TIMELINE, the live label set shows nothing, and no later sweep enumerates
# the surface at all, because the listing query filters on the very label that is gone. The
# gesture is lost silently.
#
# It stays DETECTABLE because an `unlabeled` event never erases the `labeled` one it removed.
# This predicate is that reading and nothing else — pure, one timeline, no I/O — so a reconciler
# enumerating over some OTHER durable handle (the adjudication receipt, not the hold) can ask the
# question without re-deriving it. It lives here rather than in the sweep for the reason stated
# at the top of AGENTS.md: a rule with two definitions drifts, and this one is read by the sweep
# that must not re-delete a restored hold AND by any reconciler that would restore one.


def human_hold_deleted_by_machine(events, label, machine_logins=(), is_human=None):
    """(lost, detail) — did AUTOMATION delete a PROVEN HUMAN's application of `label`, with
    nothing since putting it back? `events` is one issue/PR label timeline; nothing else is read.

    True requires ALL of these, each a POSITIVE proof:
      - the newest event for `label` is an `unlabeled` (so the label is gone, not live);
      - every removal at that newest instant is provably automation (`_is_proven_machine`) and
        none of them is a proven human — a human removing a hold is a human gesture, not a loss;
      - the newest `labeled` event is STRICTLY older than that removal and every application at
        that instant is a proven human — the gesture that was destroyed must be attributable.

    EVERY other reading returns ``(False, ...)``, because the only action this answer authorises
    is RE-APPLYING a hold, and a hold no human asked for is exactly the harm the sticky-unpark
    invariant (module header, invariant 2) exists to prevent. So a malformed timeline, an
    unattributable actor on either side, an instant tie, a `labeled` at or after the removal
    (something already restored or re-asserted it), and a removal with no application before it
    at all all fail to no action. A FETCH failure fails the same way and stays the caller's: this
    function never reads GitHub, and an unreadable timeline reaches it as no timeline at all.

    ⚠️ This is HALF of the detection. The other half is durable and lives on the surface: a
    restore posts adjudicate-stuck's sticky `hold-restored` receipt, and the restore re-applies
    the label AS THE BOT — so a repaired hold looks machine-owned to every ownership probe, and
    the receipt, not the timeline, is what keeps it from being drained again. A caller acting on
    ``True`` must therefore check that receipt too, and must post it when it restores; the
    timeline alone cannot distinguish a hold that was already repaired from one that was not."""
    try:
        rows = _event_rows(events, label)
    except MalformedTimelineError as exc:
        # Both fail directions of this question point the same way — never restore on unprovable
        # data — so the absorption is HERE rather than in a wrapper each caller could get wrong.
        return False, f"timeline unreadable: {exc}"
    probe = _human_probe(is_human)
    # No empty-login filter here on purpose: `_is_proven_machine` already refuses an empty login,
    # and a second copy of that floor would make each copy individually unkillable (AGENTS.md
    # pre-flight 4, mutually-masking duplicates). One guard, in the function that owns the proof.
    known = {str(login).casefold() for login in (machine_logins or [])}
    applications, removals = [], []
    for created, kind, login, via_app in rows:
        # parse_ts cannot raise here: _event_rows already proved every returned row's created_at
        # against valid_timestamp, which is parse_ts itself.
        bucket = applications if kind == "labeled" else removals
        bucket.append((parse_ts(created), created, login, via_app))
    if not removals:
        return False, ""
    newest_removal = max(instant for instant, _stamp, _login, _app in removals)
    if any(instant >= newest_removal for instant, _stamp, _login, _app in applications):
        return False, ""
    latest_removals = [row for row in removals if row[0] == newest_removal]
    if any(_is_proven_human(login, via_app, probe)
           for _instant, _stamp, login, via_app in latest_removals):
        return False, ""
    if not all(_is_proven_machine(login, via_app, known)
               for _instant, _stamp, login, via_app in latest_removals):
        return False, ""
    if not applications:
        return False, ""
    newest_application = max(instant for instant, _stamp, _login, _app in applications)
    latest_applications = [row for row in applications if row[0] == newest_application]
    if not all(_is_proven_human(login, via_app, probe)
               for _instant, _stamp, login, via_app in latest_applications):
        return False, ""
    return True, (f"machine unlabeled {label} at {latest_removals[0][1]}, deleting the human "
                  f"application at {latest_applications[0][1]}")


def migration_residual_holds(pr_labels, issue_labels, clearing=()):
    """The human-owned holds that would STILL be live after a legacy migration that removes
    `clearing`. EMPTY means the migrated park is actually releasable; anything else means the
    migration would strand it, and the caller must DEFER instead.

    This is the hold-axis twin of model_health.park_cause_provable's evidence axis: together they
    are the full "will the machine class actually be able to release this?" precondition. Neither
    alone is sufficient — the first cut had only the evidence half and stranded 19 of the 20 PRs
    it would have migrated on the live sparq population."""
    dropped = {label for label in clearing if isinstance(label, str)}
    return human_owned_holds(
        ({label for label in pr_labels if isinstance(label, str)}
         | {label for label in issue_labels if isinstance(label, str)}) - dropped)


# --- G5: the closed taxonomy of AUTOMATIC-READMISSION REFUSAL codes --------------------------
#
# G4 (above) made a PARK's own cause machine-readable, because "a park whose cause no machine can
# read has no machine exit by construction". capacity_park_admission then reproduced precisely
# that defect ONE LAYER UP, in this same file: it answers every refusal with a free-prose
# `detail` string, so no caller can tell apart two structurally different refusal classes:
#
#   * EXIT-REACHABLE — the park is machine-owned and a later tick can still clear it unaided:
#     the recovery evidence has not appeared YET, the probe failed, the timeline was unreadable.
#     Waiting IS the correct action, and the state is self-healing.
#   * HUMAN-TERMINAL — nothing this machine will ever do can clear it. A human-owned hold is
#     live, or a PROVEN HUMAN applied the park themselves, or the automatic cap is spent. The
#     only exit is a human gesture, and until one arrives the state is frozen.
#
# Both print one indistinguishable "park stands" line per tick, forever, and the only aggregate
# any sweep emits lumps them into a single bucket. MEASURED on sparq-org/sparq at
# 2026-07-27T11:53Z (dispatch run 30262478746): 21 open PRs carried `review:parked`, and the
# review-enumeration aggregate reported one undifferentiated
# "machine capacity park stands (...)=13". Splitting that bucket by the per-PR CLAIM-half lines
# in the SAME run gives 3 exit-reachable (#4528/#4519/#4133, "no recorded recovery of the park's
# starvation cause") against 10 human-terminal — of which 4 (#4197/#3620/#3598/#3577) refuse on
# "the latest park application is HUMAN-owned". Their timelines confirm it: `jeswr` (type=User)
# hand-applied `review:parked`, the MACHINE-owned soft hold, which park_applications correctly
# reads as a human-owned park.
#
# That last state is the missing edge. It is terminal; it is carried on the one label whose
# documented contract (invariant 1) is "excludes the surface WITHOUT posing a human question"
# and promises a machine exit; and it is counted by NOTHING, because every human-question census
# keys on `needs:user` / `review:needs-user`. A population with no machine exit that no aggregate
# can express is exactly the shape #753/#754 removed from the conflict lane.
#
# THIS TAXONOMY CHANGES NO DECISION. Every branch returns byte-identically what it returned
# before; the code is recorded ALONGSIDE the answer so the population becomes countable. Nothing
# here re-admits anything, and no fail-closed exclusion is weakened to raise a re-admission count
# — the whole point is that the correct refusals become VISIBLE rather than more numerous.
PARK_REFUSAL_HUMAN_HOLD = "human-hold"              # needs:* / review:needs-user live
PARK_REFUSAL_HUMAN_APPLIED = "human-applied"        # a proven human applied the HUMAN terminal
# A proven human applied the MACHINE-owned soft hold — so ownership is fine — but NO bot
# park-reason receipt ever classified the episode as capacity, so nothing proves the park was a
# capacity stop rather than a judgement (human_park_capacity_proof). Human-terminal by nature: a
# receipt that does not exist for an already-parked PR cannot appear on a later tick, because only
# a fresh BOT park would write one, and that park would not be human-applied.
PARK_REFUSAL_HUMAN_APPLIED_UNCLASSIFIED = "human-applied-unclassified"
# The class proof holds but is ABOUT THE PR, NOT ABOUT THIS PARK: no reconcile attestation by the
# actor that applied this park falls inside this park's own window (park_instance_attested).
# Human-terminal, and for a stronger reason than the code above: the attestation is written at the
# instant of a conversion, so one that does not exist for a park already applied can never appear
# later. Without this code the census could not tell "never classified" from "classified about a
# DIFFERENT, closed episode", which are different remedies.
PARK_REFUSAL_HUMAN_APPLIED_UNBOUND = "human-applied-unbound"
PARK_REFUSAL_CAP = "cap"                            # AUTO_READMISSION_MAX spent
PARK_REFUSAL_TIMELINE_UNREADABLE = "timeline-unreadable"
PARK_REFUSAL_PROBE_FAILED = "probe-failed"
PARK_REFUSAL_NO_EVIDENCE = "no-evidence"            # cause recovery not recorded (yet)
PARK_REFUSAL_EVIDENCE_MALFORMED = "evidence-malformed"
PARK_REFUSAL_EVIDENCE_CONSUMED = "evidence-consumed"
PARK_REFUSAL_EVIDENCE_STALE = "evidence-stale"      # recovery not strictly after the park
PARK_REFUSAL_NOT_OFFERED = "not-offered"            # proof-gate call: auto_evidence is None
# The two exits a SWEEP takes BEFORE it ever reaches capacity_park_admission. Review of the first
# round of this taxonomy measured 8 parked PRs in, 5 census rows out: both of these `continue`
# before the admission call, so neither was written, and the rows summed to the ADMISSIONS rather
# than to the population. `tick-deferred` is benign (it logs per PR and self-heals next tick);
# `read-failed` is not — a PR whose GitHub read fails on every tick is precisely a stuck-forever
# population, and it was absent from the only aggregate that could have expressed it. That is the
# same missing-edge defect this taxonomy exists to remove, one layer down, so both are codes.
PARK_REFUSAL_READ_FAILED = "read-failed"            # the PR's own GitHub state was unreadable
PARK_REFUSAL_TICK_DEFERRED = "tick-deferred"        # AUTO_READMISSION_PER_TICK_MAX spent
# [registry #769] The park is live, machine-owned and hold-free, but it belongs to ANOTHER
# mechanism's cause-gated park EPISODE — today groom's age park — whose own sweep owns its exit.
# Deliberately NOT folded into `not-offered`: that code means "a read-only proof-gate call passed
# no probe", i.e. nothing was ever going to be minted on that call, whereas this is a MINTING
# sweep declining a park it does not own. The tree already records what conflating two states
# with different remedies costs (the `no-evidence` note in #835's review), so the second one gets
# its own code rather than the nearest existing one.
PARK_REFUSAL_FOREIGN_EPISODE = "foreign-episode"    # another mechanism's cause-gated park
# [registry #1309] The RECEIPT-LESS park's one-shot void exit is already SPENT. Human-terminal, and
# for the same structural reason `cap` is: the exit exists once per PR, a second receipt-less park on
# a PR that already used it is not a machine accident twice over, and a hand-applied hold that keeps
# recurring is a genuine human question. Distinguished from `cap` because the two counters are
# separate on purpose (see RECEIPTLESS_VOID_MAX) and an operator who sees this code needs to know
# WHICH budget is gone.
PARK_REFUSAL_RECEIPTLESS_SPENT = "receiptless-spent"
# [registry #1309, review round 1 finding B1] The void is EARNED but cannot be WRITTEN cleanly: the
# PR's `review:*` namespace is ambiguous independently of the park, so no strip leaves a determinate
# state (see receiptless_void_label_plan). HUMAN-TERMINAL, and honestly so — nothing in this tree
# de-ambiguates a split review namespace, and worker-pr's issue-#138 rule resolves one toward the
# human terminal, so a later tick cannot clear this. Its own code because the remedy is specific and
# small: a human picks the one review state that PR should be in.
PARK_REFUSAL_RECEIPTLESS_AMBIGUOUS = "receiptless-ambiguous"

# Which refusals a later tick can clear WITHOUT a human. The split is the whole point of the
# taxonomy, so it is data, not a predicate scattered across callers.
#
# `cap` is HUMAN-TERMINAL deliberately, and the refusal's own log line already says why: "an
# account that keeps flapping is a genuine human question; the park stands until a human acts".
# `evidence-consumed` is EXIT-REACHABLE: it demands a NEW outage-and-recovery pair, which a later
# tick can genuinely observe. `not-offered` is EXIT-REACHABLE because it is not a refusal about
# the PR at all — it is the CLAIM proof gate deliberately evaluating without minting.
# `foreign-episode` is EXIT-REACHABLE, and that classification is a CLAIM this file has to keep
# honest rather than a label of convenience: it asserts that some OTHER sweep will clear the park
# without a human. It is only ever emitted for a park whose owning mechanism has a machine exit —
# age_park_episode's contract — so a park that reaches this code is countable, named every tick,
# and attributable to the sweep that owes it an answer. Filing it as human-terminal would be the
# opposite lie (nobody is waiting on a human).
PARK_REFUSAL_HUMAN_TERMINAL = frozenset({
    PARK_REFUSAL_HUMAN_HOLD, PARK_REFUSAL_HUMAN_APPLIED, PARK_REFUSAL_CAP,
    PARK_REFUSAL_HUMAN_APPLIED_UNCLASSIFIED, PARK_REFUSAL_HUMAN_APPLIED_UNBOUND,
    PARK_REFUSAL_RECEIPTLESS_SPENT, PARK_REFUSAL_RECEIPTLESS_AMBIGUOUS,
})
PARK_REFUSAL_CODES = frozenset({
    PARK_REFUSAL_HUMAN_HOLD, PARK_REFUSAL_HUMAN_APPLIED, PARK_REFUSAL_CAP,
    PARK_REFUSAL_HUMAN_APPLIED_UNCLASSIFIED, PARK_REFUSAL_HUMAN_APPLIED_UNBOUND,
    PARK_REFUSAL_TIMELINE_UNREADABLE, PARK_REFUSAL_PROBE_FAILED, PARK_REFUSAL_NO_EVIDENCE,
    PARK_REFUSAL_EVIDENCE_MALFORMED, PARK_REFUSAL_EVIDENCE_CONSUMED,
    PARK_REFUSAL_EVIDENCE_STALE, PARK_REFUSAL_NOT_OFFERED,
    PARK_REFUSAL_READ_FAILED, PARK_REFUSAL_TICK_DEFERRED,
    PARK_REFUSAL_FOREIGN_EPISODE, PARK_REFUSAL_RECEIPTLESS_SPENT,
    PARK_REFUSAL_RECEIPTLESS_AMBIGUOUS,
})

# The ADMITTING actions and the human-gesture action are not refusals; they are recorded in
# the census under these codes so one census row exists per decision and the populations sum.
PARK_ADMIT_CODES = {"auto-mint": "admitted-auto-mint",
                    "auto-receipt": "admitted-auto-receipt",
                    "human": "admitted-human-gesture",
                    # [registry #1309] the receipt-less VOID exit, counted APART from the
                    # cause-recovery admissions on purpose: these two admissions rest on entirely
                    # different proofs (a recovered cause vs a park that never recorded one), and a
                    # census that merged them could not answer "how many parks did we clear WITHOUT
                    # proving a cause recovered" — which is the number that has to stay small.
                    "void-mint": "admitted-void-receiptless",
                    "void-receipt": "admitted-void-receipt"}


def park_refusal_exit_class(code):
    """"human-terminal" / "exit-reachable" for a refusal `code`, else None for a code outside the
    closed taxonomy. An UNRECOGNISED code is NOT silently filed as self-healing: None forces the
    caller to surface it, because a refusal nobody classified is the very thing this exists to
    stop being invisible."""
    if code in PARK_REFUSAL_HUMAN_TERMINAL:
        return "human-terminal"
    if code in PARK_REFUSAL_CODES:
        return "exit-reachable"
    return None


def park_census_record(census, repo, pr_number, code, detail):
    """Append EXACTLY ONE census row to `census` (a no-op for a non-list, the out-list idiom).

    THE ONLY WRITER of a census row, used both by capacity_park_admission's own `_answer` and by
    the sweep's pre-admission exits (`read-failed`, `tick-deferred`). One writer is the point: a
    second hand-built `census.append(...)` elsewhere is how the `exit` class silently drifts from
    park_refusal_exit_class, and the exit class is what splits "no tick will ever clear this"
    from "a later tick will"."""
    if not isinstance(census, list):
        return
    census.append({"repo": repo, "number": pr_number, "code": code,
                   "exit": (None if code in set(PARK_ADMIT_CODES.values())
                            else park_refusal_exit_class(code)),
                   "detail": detail})


def park_census_summary(records):
    """PURE. Aggregate census `records` (as appended by capacity_park_admission's `census`
    out-list) into (counts_by_code, human_terminal_numbers, unclassified_numbers).

    `counts_by_code` is an ordered {code: count} over every well-formed record. The two number
    lists are ascending and de-duplicated: the HUMAN-TERMINAL population is the one an operator
    has to act on, and the UNCLASSIFIED population is the one that proves this taxonomy has
    drifted from its writers. Malformed rows are counted under the reserved `"malformed"` code
    rather than dropped — a census that silently discards what it cannot parse is how a
    population goes missing in the first place."""
    counts, terminal, unclassified = {}, set(), set()
    for record in records if isinstance(records, (list, tuple)) else []:
        if not isinstance(record, dict):
            counts["malformed"] = counts.get("malformed", 0) + 1
            continue
        code = record.get("code")
        number = record.get("number")
        if not isinstance(code, str) or not code:
            counts["malformed"] = counts.get("malformed", 0) + 1
            continue
        counts[code] = counts.get(code, 0) + 1
        if not isinstance(number, int) or isinstance(number, bool):
            continue
        if code in PARK_ADMIT_CODES.values():
            continue
        exit_class = park_refusal_exit_class(code)
        if exit_class == "human-terminal":
            terminal.add(number)
        elif exit_class is None:
            unclassified.add(number)
    ordered = {code: counts[code] for code in sorted(counts)}
    return ordered, sorted(terminal), sorted(unclassified)


def capacity_park_admission(repo, pr_number, issue_number, fetch_events, is_human=None,
                            log=print, consumed=frozenset(), auto_receipts=(),
                            auto_marker_count=None, auto_evidence=None, live_holds=(),
                            census=None, reason_records=(), attestations=(),
                            self_id_rows=(), void_receipts=(), void_marker_count=None,
                            void_offered=False, pr_review_labels=()):
    """Whether a MACHINE capacity park may be re-admitted now, and on WHOSE authority
    (invariant 3). Returns (action, evidence, detail), where `evidence` is None or
    {"key", "at"} — the recovery event's durable identity plus its canonical recovery stamp, i.e.
    exactly what the caller receipts — and action is one of:

    - "human"       — capacity_park_readmitted is True: an UNCONSUMED proven-human readmission
                      gesture newer than every park application. UNCHANGED semantics, and it is
                      checked FIRST so a human gesture always takes precedence and NO automatic
                      evidence is consumed when one exists (no double consumption).
    - "auto-receipt"— a well-formed bot-authored automatic-readmission receipt is already newer
                      than every park application: this PR was ALREADY automatically re-admitted
                      and the receipt is the durable gesture. Idempotent — no new evidence is
                      consumed, so a crashed label write converges on a later tick, and the
                      receipt-driven CLAIM proof gate can admit the PR after the sweep cleared
                      its labels (without this, the machine's own re-admission would be invisible
                      to the proof gate and the PR would defer forever — the very deadlock this
                      whole change exists to remove).
    - "auto-mint"   — a NEW automatic re-admission is earned: fresh, unconsumed recovery
                      evidence strictly newer than the latest park application, under the
                      AUTO_READMISSION_MAX cap. The caller MUST receipt `evidence` durably
                      BEFORE it clears any label (RECEIPT-FIRST, #610's ordering: dying
                      receipt-then-label is recoverable — the "auto-receipt" branch above
                      converges it — while label-then-receipt would erase the re-admission from
                      every proof surface and re-strand the PR).
    - "void-receipt"— [registry #1309] a well-formed bot-authored RECEIPT-LESS VOID receipt is
                      already newer than every park application: this PR's receipt-less park was
                      ALREADY voided and the receipt is the durable gesture. Idempotent, and NOT
                      optional — the void is one-shot, so without this branch a crash between the
                      receipt and the label write would leave a PR holding a spent budget and a
                      live park, i.e. it would reproduce the permanent strand this exit exists to
                      remove. Available on EVERY call, including the read-only proof gate.
    - "void-mint"   — a NEW receipt-less void is earned: the latest park application is a
                      human-applied MACHINE-owned hold, NOT ONE park-reason receipt exists for
                      this PR, the applying actor's provenance is proven MACHINE
                      (machine_operated_park_proof), RECEIPTLESS_VOID_MAX is unspent, and every
                      pre-existing gate below passed. Requires `void_offered=True`, so a read-only
                      gate can never mint. RECEIPT-FIRST like "auto-mint", for the same reason.
                      This action asserts NOTHING about why the PR was parked — see
                      park_is_receiptless and receiptless_void_comment.
    - None          — stays parked; `detail` says why.

    `consumed` is the park-GENERATION receipt set (worker-pr park_generation_cutoffs) the human
    path already consults. `auto_receipts` are the well-formed AUTOMATIC receipts
    (worker-pr auto_readmission_records — [{"key": evidence key, "at": canonical stamp}]);
    `auto_marker_count` is the count of ALL bot-authored auto-readmit markers including
    malformed ones (worker-pr auto_readmission_marker_count) and defaults to len(auto_receipts).
    The cap counts MARKERS, not well-formed records, so a corrupt receipt can never buy an extra
    automatic re-admission. `live_holds` are the labels currently live on either surface: ANY
    `needs:*` label or `review:needs-user` among them is a HUMAN-OWNED hold and blocks the
    automatic path outright — the same rule the review lane's own admission applies, so
    "human-held there" and "never auto-re-admitted here" cannot drift.
    `auto_evidence(parked_at)` is the caller's recovery-evidence probe — called at most once,
    with the canonical stamp of the latest park application (None when none was ever applied) —
    returning {"key", "recovered_at"} or None; pass None (the CLAIM proof gate) to evaluate the
    human + already-receipted paths WITHOUT minting anything.

    `self_id_rows` (self_identified_machine_comments), `void_receipts`
    (receiptless_void_records — [{"key", "at"}]), `void_marker_count`
    (receiptless_void_marker_count, defaulting to len(void_receipts)), `void_offered`, and
    `pr_review_labels` (the PR's OWN live label set, from which receiptless_void_label_plan takes
    the `review:` namespace) are the
    RECEIPT-LESS VOID exit's inputs. Their defaults are the pre-#1309 behaviour EXACTLY: with no
    self-ID rows the provenance proof fails closed and a receipt-less human-applied park refuses
    with the same code and the same detail string it refused with before, and with
    `void_offered=False` nothing can be minted at all. That is deliberate — but it also means a
    caller that forgets to pass them gets a silently inert exit, which is why
    dispatch-claim._readmit_capacity_parks AST-asserts the wiring in its own self-test rather than
    trusting a comment.

    EVERY ambiguity fails toward staying parked: an unreadable timeline, an unreadable/absent
    health record, a probe that raises, an unsafe evidence key, a recovery that is not STRICTLY
    after the park (a tie included), a human-owned label, a proven human applying the HUMAN-OWNED
    terminal `needs:user` (or any park label MACHINE_OWNED_PARK_LABELS cannot classify), and the
    cap. A proven human applying a MACHINE-owned soft hold (`review:parked` / `status:parked`) is
    deliberately NOT an ambiguity — the actor chose the label whose description promises this exit —
    and it proceeds under every one of those gates unchanged.

    `census`, when a list is passed, receives EXACTLY ONE row for this decision (the `occupancy`
    out-list idiom used elsewhere in this pipeline):
    {"repo", "number", "code", "exit", "detail"} — where `code` is a G5 taxonomy code and `exit`
    is park_refusal_exit_class(code) (None for the admitting actions). It is a pure OBSERVATION
    side channel: passing it changes no decision and no returned value, and park_census_summary
    aggregates the rows so the human-terminal population stops being invisible."""
    def _answer(action, evidence, code, detail):
        """Record one census row and return the answer UNCHANGED. The recording is strictly
        additive — a census list that is absent, or of the wrong type, is simply not written.
        Delegates to park_census_record so this and the sweep's pre-admission exits cannot
        disagree about the row shape or the exit class."""
        park_census_record(census, repo, pr_number, PARK_ADMIT_CODES.get(action, code), detail)
        return (action, evidence, detail)

    if capacity_park_readmitted(repo, pr_number, issue_number, fetch_events,
                                is_human=is_human, log=log, consumed=consumed):
        return _answer("human", None, None, "unconsumed proven-human readmission gesture")
    held = human_owned_holds(live_holds)
    if held:
        return _answer(
            None, None, PARK_REFUSAL_HUMAN_HOLD,
            f"human-owned hold(s) live ({'/'.join(held)}) — never auto-re-admitted")
    latest_park, human_park, human_park_labels, human_park_logins, previous_park, readable = \
        park_application_view(repo, pr_number, issue_number, fetch_events, is_human=is_human,
                              log=log)
    if not readable:
        return _answer(None, None, PARK_REFUSAL_TIMELINE_UNREADABLE,
                       "the park application timeline could not be read")
    machine_owned = human_park_is_machine_owned(human_park, human_park_labels)
    if human_park and not machine_owned:
        # The human applied a HUMAN-OWNED terminal (or a label this module cannot classify, or —
        # defensively, against a drifted view — none it can name): a question no machine answers.
        return _answer(
            None, None, PARK_REFUSAL_HUMAN_APPLIED,
            "the latest park application is the HUMAN-owned terminal "
            f"({'/'.join(human_park_labels) or 'unattributable'}) — only a human clears it")
    # [registry #1309] THE VOID'S IDEMPOTENT CONVERGENCE, and its POSITION is the load-bearing part.
    #
    # It sits here — above every gate that can refuse a receipt-less park, and in particular above
    # the one-shot RECEIPTLESS_VOID_MAX check — because the void is ONE-SHOT. A crash between the
    # receipt and the label write leaves a PR whose only budget is spent and whose park is still
    # live; had this check sat with the automatic convergence further down, that PR would have hit
    # `receiptless-spent` on every subsequent tick and been stranded FOREVER by the very exit built
    # to un-strand it. (The first cut of this change did exactly that. The failure mode of a
    # one-shot exit is not the same as that of a capped one, and it is not enough to copy the capped
    # one's shape.)
    #
    # Deliberately NOT gated on `void_offered`: converging a write that is already publicly
    # receipted mints nothing, so the read-only proof gate needs it too — otherwise the machine's
    # own void would be invisible to the gate and the PR would defer forever.
    #
    # It sits BELOW the human-terminal refusal above, so a standing void receipt can never talk a
    # `needs:user` out of the human terminal.
    # The binding is on the EPISODE KEY, not on recency. The void key IS the park application
    # instant (receiptless_void_key), so "a standing receipt whose key is the LIVE park's key" is an
    # exact statement that THIS park was already voided — where the automatic path's `stamp > park`
    # comparison is only a proxy for it, and one this exit cannot borrow anyway (a void receipt is
    # stamped when the void was GRANTED, which says nothing about which park it voided).
    live_void_key = (receiptless_void_key(canonical_ts(latest_park.isoformat()))
                     if latest_park is not None else None)
    if live_void_key:
        # [registry #1309, review round 2 BLOCKER] THE CONVERGENCE MUST CARRY THE PLAN.
        #
        # It did not, and the branch was therefore INERT — the one defect in this change that
        # re-created, through its own recovery path, exactly the permanent strand the exit exists to
        # remove. The evidence dict omitted "plan", so the sweep passed `evidence.get("plan")` =
        # None into `void_labels`, whose argv built `"--expect-plan", str(None)` = the STRING
        # "None"; and `expect_plan is not None and plan != expect_plan` treats that string as a real
        # expectation, so the writer stood down on EVERY convergence. Executed against the real
        # writer: `{changes, parked}` with expect_plan="None" -> `plan-changed`, nothing written, for
        # both plan shapes. Any transient failure of the label write after the receipt landed — 403,
        # secondary rate limit, 503, all attested in this estate — would have left that PR with a
        # SPENT one-shot budget and a LIVE park, forever, healing on no later tick.
        #
        # The plan is derived HERE rather than reused from the mint branch below because the mint
        # branch is not reached on this path. It is deliberately allowed to be None: the ACTION stays
        # `void-receipt` regardless, so a read-only proof gate still ADMITS a PR whose void is
        # publicly receipted (a None-plan refusal at the ADMISSION would re-create the #614
        # defer-forever state M14 exists to guard). What a None plan changes is only the WRITE: the
        # sweep omits `--expect-plan` and the writer re-derives on its own fresh read, refusing and
        # censusing rather than improvising.
        converge_plan, converge_plan_detail = receiptless_void_label_plan(pr_review_labels)
        for receipt in void_receipts:
            if not isinstance(receipt, dict) or receipt.get("key") != live_void_key:
                continue                  # a void of a DIFFERENT, closed park episode
            if not valid_timestamp(receipt.get("at")):
                continue                  # malformed receipts prove nothing (they still count
                # toward RECEIPTLESS_VOID_MAX below, so they can never buy an extra void)
            return _answer(
                "void-receipt", {"key": live_void_key, "at": canonical_ts(receipt["at"]),
                                 "plan": converge_plan}, None,
                f"this receipt-less park was already voided at {canonical_ts(receipt['at'])} "
                f"(void evidence {live_void_key!r}); no new budget consumed; "
                f"{converge_plan_detail}")
    # [registry #1309] Set iff the RECEIPT-LESS VOID exit is earned. The decision is TAKEN in the
    # human-applied branch below (that is where the population dies today) but RETURNED after the
    # auto-receipt convergence and the AUTO_READMISSION_MAX cap, so the void inherits every one of
    # those gates instead of routing around them. It does not SPEND the capacity cap — the two
    # budgets are separate (RECEIPTLESS_VOID_MAX) for the reason groom's age-unpark states: routing
    # one mechanism's receipts through another's cap makes the two consume each other.
    void_evidence = void_detail = None
    if human_park:
        # SECOND GATE, and it is the one that makes this safe rather than merely consistent. The
        # label the actor chose proves OWNERSHIP; it proves nothing about CAUSE, and a human-applied
        # park carries no cause receipt of its own. Require the BOT's own machine-readable
        # classification of the park episode — the thing a bot-applied park has by construction.
        # Measured: without it this admission cleared 5 PRs on which no bot receipt of any kind
        # existed, riding the aged-out health HEURISTIC while #769's age guard sat inert. See
        # human_park_capacity_proof.
        proven, why = human_park_capacity_proof(reason_records)
        if not proven:
            # [registry #1309] SPLIT ON WHY THE PROOF FAILED, because the two states have different
            # remedies and one of them had no remedy at all.
            #
            # An OFF-CLASS receipt STANDS => unchanged, byte for byte. The machine did classify this
            # park and it was not "capacity"; a raised question is a property of the PR's whole
            # history and nothing here may touch it.
            #
            # NO receipt exists at all => the receipt-less class. Handled below, and note the fail
            # direction: EVERY refusal in this sub-branch returns the SAME code and the SAME detail
            # string the unconditional refusal returned before, so an ambiguous receipt-less park is
            # indistinguishable from the pre-#1309 answer. Only a POSITIVELY PROVEN machine
            # provenance changes any outcome.
            if not park_is_receiptless(reason_records):
                return _answer(None, None, PARK_REFUSAL_HUMAN_APPLIED_UNCLASSIFIED,
                               f"a human applied the machine soft hold, but {why}")
            machine_made, how, prover_row = machine_operated_park_proof(
                self_id_rows, latest_park, previous_park, human_park_logins)
            if not machine_made:
                # FAIL CLOSED. `actor.__typename == "User"` is NOT decisive for human here, but the
                # converse is not free either: absent a positive machine signal this park may
                # genuinely be a human's, so it keeps the human terminal it has today.
                return _answer(None, None, PARK_REFUSAL_HUMAN_APPLIED_UNCLASSIFIED,
                               f"a human applied the machine soft hold, but {why}")
            # [B1] WHAT THE VOID WOULD WRITE, decided BEFORE the budget is spent. A void that
            # cannot be written deterministically must never be minted: burning the one-shot exit
            # to move a PR into a stricter hold is worse than leaving it parked.
            void_plan, plan_detail = receiptless_void_label_plan(pr_review_labels)
            if void_plan is None:
                return _answer(None, None, PARK_REFUSAL_RECEIPTLESS_AMBIGUOUS,
                               f"the void is earned but cannot be written cleanly: {plan_detail}")
            if not void_offered:
                # A read-only proof gate evaluated a mintable state without being asked to mint.
                # EXIT-REACHABLE, and truthfully so: the minting sweep clears it on a later tick.
                return _answer(None, None, PARK_REFUSAL_NOT_OFFERED,
                               "a receipt-less machine park is voidable, but this call offered no "
                               "void (read-only proof gate)")
            spent = (len(void_receipts) if void_marker_count is None else void_marker_count)
            if spent >= RECEIPTLESS_VOID_MAX:
                log(f"::warning::receipt-less void REFUSED for {repo}#{pr_number}: "
                    f"{spent} void(s) already granted (cap {RECEIPTLESS_VOID_MAX}) and a "
                    "receipt-less park was applied again — one void per PR is the whole bound; a "
                    "hold that keeps recurring by hand is a genuine human question")
                return _answer(None, None, PARK_REFUSAL_RECEIPTLESS_SPENT,
                               f"the one-shot receipt-less void is spent ({spent}/"
                               f"{RECEIPTLESS_VOID_MAX})")
            # NO "if not void_key" guard here, and its ABSENCE is deliberate. `latest_park` is an
            # aware datetime the module itself parsed, so canonical_ts of it is always a valid
            # stamp and the derived key always satisfies safe_receipt_part — the branch was
            # STRUCTURALLY UNREACHABLE, line-granular coverage showed it at 0 %, and this file's own
            # precedent is to delete rather than keep it (see human_park_capacity_proof's note on
            # the third check it removed: "dead code that asserts a rule is worse than no code — it
            # reads like a guard while proving nothing"). If the key format is ever widened to
            # something unsafe, `receiptless_void_marker` raises ValueError at the WRITER, which is
            # the loud direction this module wants anyway. receiptless_void_key keeps its own None
            # returns because it is public and directly tested.
            void_key = receiptless_void_key(canonical_ts(latest_park.isoformat()))
            void_evidence = {"key": void_key,
                             "park_at": canonical_ts(latest_park.isoformat()),
                             "prover": str(prover_row.get("login")),
                             "prover_at": canonical_ts(prover_row.get("at")),
                             # [B1] The EXACT label write the caller is authorised to perform. It
                             # travels WITH the evidence rather than being re-derived at the call
                             # site, so the decision that spent the one-shot budget and the write
                             # that follows it cannot be about two different plans.
                             "plan": void_plan}
            void_detail = (f"no park-reason receipt of any kind exists, and {how} — voiding this "
                           f"park FOR WANT OF A RECEIPT (no cause is claimed to have recovered, "
                           f"and none was reconstructed); {plan_detail}")
            log(f"receipt-less MACHINE park on {repo}#{pr_number} "
                f"({'/'.join(human_park_labels)} at "
                f"{canonical_ts(latest_park.isoformat())}): {void_detail}")
        else:
            # THIRD GATE — the INSTANCE binding. The class proof above is entity-scoped and
            # monotone: it is satisfied by anything in the PR's history, forever. On its own it made
            # every PR that was ever bot-capacity-parked permanently immune to a hand-applied hold.
            # The record must be ABOUT THIS PARK APPLICATION, not merely about the same PR.
            attested, how = park_instance_attested(
                attestations, latest_park, previous_park, human_park_logins)
            if not attested:
                return _answer(None, None, PARK_REFUSAL_HUMAN_APPLIED_UNBOUND,
                               f"a human applied the machine soft hold and {why}, but {how}")
            # Both gates hold. Proceed into exactly the same evidence-gated path a bot-applied park
            # takes — nothing below is relaxed: the live human-owned-hold refusal above already ran,
            # the recovery must still be STRICTLY after this application, its evidence key is still
            # consumed exactly once, and AUTO_READMISSION_MAX still caps the PR.
            log(f"human-applied MACHINE park on {repo}#{pr_number} "
                f"({'/'.join(human_park_labels)} at "
                f"{canonical_ts(latest_park.isoformat())}): the actor selected the machine-owned "
                f"soft hold AND {why} — evaluating the ordinary machine exit under every unchanged "
                "gate (a human-owned hold, or an unclassified park, would have refused above)")
    parked_at = canonical_ts(latest_park.isoformat()) if latest_park is not None else None
    for receipt in auto_receipts:
        stamp = receipt.get("at") if isinstance(receipt, dict) else None
        if not valid_timestamp(stamp):
            continue                    # malformed receipts prove nothing (they still count
            # toward the cap below, so they can never buy an extra re-admission)
        if latest_park is None or parse_ts(stamp) > latest_park:
            return _answer(
                "auto-receipt", {"key": receipt.get("key"), "at": canonical_ts(stamp)}, None,
                f"already automatically re-admitted at {canonical_ts(stamp)} "
                f"(receipt evidence {receipt.get('key')!r}); no new evidence consumed")
    minted = len(auto_receipts) if auto_marker_count is None else auto_marker_count
    if minted >= AUTO_READMISSION_MAX:
        log(f"::warning::automatic readmission REFUSED for {repo}#{pr_number}: "
            f"{minted} automatic re-admission(s) already granted (cap "
            f"{AUTO_READMISSION_MAX}) and the park fired again — an account that keeps "
            "flapping is a genuine human question; the park stands until a human acts")
        return _answer(None, None, PARK_REFUSAL_CAP,
                       f"automatic-readmission cap reached ({minted}/"
                       f"{AUTO_READMISSION_MAX})")
    # [registry #1309] THE VOID MINT, returned HERE rather than at the point of decision so it
    # inherits — not routes around — every gate between: the live human-owned hold, the unreadable
    # timeline, the human-owned terminal, an already-standing automatic re-admission, and the
    # AUTO_READMISSION_MAX flap cap immediately above. The void does not SPEND that cap (separate
    # budgets, RECEIPTLESS_VOID_MAX) but it does OBEY it: a PR that has already flapped twice does
    # not get a third exit through a different door.
    #
    # It returns BEFORE the recovery-evidence path below, and that is the honest ordering rather than
    # a shortcut: for a park with no recorded cause there is no cause whose recovery could be
    # probed, so running the probe could only produce an answer about some OTHER condition — which
    # is precisely the "six-hour timer wearing an evidence gate's name" that human_park_capacity_proof
    # was built to stop.
    if void_evidence is not None:
        return _answer("void-mint", void_evidence, None, void_detail)
    if auto_evidence is None:
        return _answer(None, None, PARK_REFUSAL_NOT_OFFERED,
                       "no unconsumed human gesture and no recovery evidence offered")
    try:
        evidence = auto_evidence(parked_at)
    except Exception as exc:  # noqa: BLE001 — an unreadable cause probe stays parked
        log(f"automatic readmission unknown for {repo}#{pr_number}: the recovery-evidence "
            f"probe failed ({exc}); the capacity park stands")
        return _answer(None, None, PARK_REFUSAL_PROBE_FAILED,
                       "the recovery-evidence probe failed")
    if not evidence:
        return _answer(None, None, PARK_REFUSAL_NO_EVIDENCE,
                       "no recorded recovery of the park's starvation cause")
    key = evidence.get("key") if isinstance(evidence, dict) else None
    recovered_at = evidence.get("recovered_at") if isinstance(evidence, dict) else None
    if not safe_receipt_part(key) or not valid_timestamp(recovered_at):
        log(f"automatic readmission unknown for {repo}#{pr_number}: the recovery evidence is "
            f"malformed (key={key!r}, recovered_at={recovered_at!r}); the capacity park stands")
        return _answer(None, None, PARK_REFUSAL_EVIDENCE_MALFORMED,
                       "the recovery evidence is malformed")
    recovered_canonical = canonical_ts(recovered_at)
    if key in {receipt.get("key") for receipt in auto_receipts if isinstance(receipt, dict)}:
        log(f"automatic readmission declined for {repo}#{pr_number}: the recovery evidence "
            f"{key!r} was already consumed by a receipted automatic re-admission — a NEW "
            "outage-and-recovery pair is required")
        return _answer(None, None, PARK_REFUSAL_EVIDENCE_CONSUMED,
                       f"recovery evidence {key!r} already consumed")
    if latest_park is not None and parse_ts(recovered_at) <= latest_park:
        return _answer(None, None, PARK_REFUSAL_EVIDENCE_STALE,
                       f"the recovery at {recovered_canonical} is not STRICTLY after the park "
                       f"application at {parked_at}")
    return _answer("auto-mint", {"key": key, "at": recovered_canonical}, None,
                   f"recovery evidence {key!r} recorded at {recovered_canonical}, strictly after "
                   f"the park application at {parked_at}")


def readmission_window(human_cutoff, auto_stamps=(), log=print):
    """[registry #797] The budget readmission window AND WHO OPENED IT.

    Returns {"cutoff", "authority", "machine_windows"}:
      - "cutoff": exactly what effective_readmission_cutoff returns (the LATEST of the
        proven-human cutoff and every well-formed automatic re-admission stamp, canonical
        spelling; WINDOW_UNREADABLE is contagious; None when there is no window).
      - "authority": WINDOW_AUTHORITY_HUMAN only when the winning window key is the PROVEN-HUMAN
        gesture and NO automatic stamp shares that key; WINDOW_AUTHORITY_MACHINE when an
        automatic re-admission receipt won (or tied — see below); WINDOW_AUTHORITY_UNKNOWN when
        there is no window at all or the timeline was unreadable.
      - "machine_windows": the canonical keys of every well-formed automatic stamp, so the ladder
        can tell which of the PR's ALREADY-RECEIPTED windows were the machine's own and exclude
        them from the human generation count.

    A TIE RESOLVES TO MACHINE. If a human unlabel and an automatic re-admission canonicalise to
    the same instant, the machine's re-admission is sufficient on its own to explain the window,
    so the human's gesture is not PROVEN to be what opened it. Everywhere else in this module
    ambiguity fails toward staying parked; here the equivalent conservative direction is failing
    toward the MACHINE class, because the harm being fixed is a page nobody asked for.

    THE DEFECT THIS SPLIT EXISTS FOR: the caller used to receive one bare string and had no way
    to ask where it came from, so `park_ladder_decision` charged the machine's own re-admissions
    to the human escalation ladder. See PARK_ESCALATION_GENERATIONS for the measured population.
    """
    if human_cutoff == WINDOW_UNREADABLE:
        return {"cutoff": WINDOW_UNREADABLE, "authority": WINDOW_AUTHORITY_UNKNOWN,
                "machine_windows": frozenset()}
    machine, human = [], None
    for source, stamp in ([("human gesture", human_cutoff)] if human_cutoff else []) \
            + [("automatic re-admission", stamp) for stamp in (auto_stamps or [])]:
        if not valid_timestamp(stamp):
            log(f"::warning::readmission window: dropping the malformed {source} stamp "
                f"{stamp!r} — unprovable time can never mint a budget window")
            continue
        entry = (parse_ts(stamp), canonical_ts(stamp))
        if source == "human gesture":
            human = entry
        else:
            machine.append(entry)
    candidates = ([human] if human else []) + machine
    if not candidates:
        return {"cutoff": None, "authority": WINDOW_AUTHORITY_UNKNOWN,
                "machine_windows": frozenset()}
    machine_windows = frozenset(key for _instant, key in machine)
    key = max(candidates)[1]
    authority = (WINDOW_AUTHORITY_MACHINE if key in machine_windows
                 else WINDOW_AUTHORITY_HUMAN)
    return {"cutoff": key, "authority": authority, "machine_windows": machine_windows}


def effective_readmission_cutoff(human_cutoff, auto_stamps=(), log=print):
    """The budget readmission window a re-admitted PR actually gets: the LATEST of the
    proven-human cutoff (readmission_cutoff) and every well-formed AUTOMATIC re-admission
    receipt stamp, in canonical spelling.

    WHY the automatic stamp must count here too: clearing the park label without granting a
    budget window would leave the PR enumerable but permanently un-dispatchable — every tick
    would re-derive the SAME exhausted lifetime counters (the missed-fix marker budget grows
    purely from allocator starvation, so an outage pins it) and quietly re-defer forever. The
    automatic re-admission grants EXACTLY the window a human gesture grants, and it is bounded
    by exactly the same two things that bound the re-admission itself: fresh unconsumed
    evidence and AUTO_READMISSION_MAX.

    [registry #797] WHAT THIS FUNCTION MUST NOT BE USED FOR. The BUDGET is rightly blind to who
    opened the window — a re-admitted PR gets a real retry either way, which is the whole point
    of #614. The ESCALATION LADDER is not: this docstring used to claim that "a PR that is
    automatically re-admitted and then exhausts its real budget again still reaches a human — it
    just does so having actually retried", and that was the defect stated as a feature. Reaching
    a human is only correct when a human decided something; when the MACHINE re-admitted, the
    re-exhaustion establishes nothing whatsoever about a human's attention. Ladder callers use
    readmission_window (which returns the same cutoff PLUS its authority) and pass that authority
    to park_ladder_decision; this function stays as the cutoff-only view the BUDGET consumers
    want, and delegates so the two can never disagree about the cutoff itself.

    WINDOW_UNREADABLE is contagious and wins outright: an automatic stamp must never mask an
    unreadable label timeline (the ladder has to FREEZE on unproven data). A malformed automatic
    stamp is dropped with a loud log — unprovable time can never mint a window."""
    return readmission_window(human_cutoff, auto_stamps, log=log)["cutoff"]


def safe_receipt_part(value):
    """True when `value` may be embedded in a durable park-receipt marker: non-empty, bounded,
    and free of whitespace and `>` (_FINGERPRINT_PART), so it can never break out of the
    `... key=<value> -->` marker every receipt reader keys on. Shared by park_fingerprint's
    components and by the automatic-readmission evidence key (registry #614) so ONE grammar
    governs everything a receipt can carry."""
    return isinstance(value, str) and bool(_FINGERPRINT_PART.fullmatch(value))


def park_fingerprint(head_sha, attempt_key):
    """The ATTEMPT fingerprint a capacity park is receipted against (#555 recurrence gap):
    the pair (PR head SHA, monotone attempt counter) that the exhaustion decision was
    derived from. Two parks with an EQUAL fingerprint were derived from byte-identical
    per-PR state — nothing new was attempted between them — so the second one is pure noise
    (see park_ladder_decision's "unchanged" action).

    Returns None when either component is unknown: an unknown fingerprint can prove
    nothing, so the ladder falls back to its pre-fix behaviour (the park is emitted). That
    is the conservative direction here — over-emitting a park is recoverable churn, whereas
    suppressing on unproven identity would silently drop a due park.

    `attempt_key` MUST be a monotone, space-free counter of work ATTEMPTED (a global round
    number, a lifetime per-round missed/nochange/gatefail marker count) — never a
    window-relative count, which resets on every readmission and would collide across
    windows. Any character outside [A-Za-z0-9._=/:-] is rejected (None) so the value can
    never break out of the `attempt=<key> -->` receipt marker."""
    if not head_sha or not attempt_key:
        return None
    head, attempt = str(head_sha), str(attempt_key)
    if not _FINGERPRINT_PART.fullmatch(head) or not _FINGERPRINT_PART.fullmatch(attempt):
        return None
    return f"{head}/{attempt}"


# --- THE RESERVED `<!-- sparq-` NAMESPACE, and the ONE sanitiser every writer shares -----------
#
# [registry #1096] A parser that emits examples of its own syntax will parse them back. Every
# durable control marker the fleet writes and later re-reads out of BOT-AUTHORED comments — the
# review-round budget, the fix-outcome counters, the reviewed-sha binding, and the park-reason
# receipt below — opens with this exact literal. Any program that interpolates a
# REPOSITORY-CONTROLLED string (a git pathname, a branch ref, a model's free text) into a comment
# it posts under the App installation can therefore MINT one of those markers on behalf of an
# attacker: the author filter is sound (only the App token posts as `<slug>[bot]`, and a `[bot]`
# login is unregistrable), but authorship is not what is being forged — CONTENT is, and the
# consumers trust content they did not themselves write.
#
# The sanitiser lived in worker-pr.py alone (issue #137), which made it a per-writer defence that
# a SIBLING writer could silently skip — and resolve-conflicts.py did skip it, echoing raw `git
# diff` pathnames straight into an App-authored comment, so a crafted pathname carrying a
# `sparq-park-reason` receipt survived intact into a comment `park_reason_records` reads. Declared
# HERE for the same reason CONFLICT_STUCK_PARK_MARKER is: the writers are separate entry points
# with separate checkout roots, and a hand-copied sanitiser is a defence that can drift silently
# from the parser it is supposed to protect. One spelling, imported by every writer.
#
# The parsers require the exact `<!-- sparq-` opener, so DETECTION/DEFANGING is deliberately WIDER
# than matching: case-insensitive with optional inner whitespace, so no near-miss opener can be
# massaged back into a live marker. Naming a marker in prose (`sparq-review-round`) never trips
# this — only the literal HTML-comment opener does.
#
# worker-pr.py KEEPS its own copy rather than delegating here, and that is a deliberate, bounded
# choice rather than an oversight: it loads this module LAZILY, once per call site, so routing
# `contains_reserved_marker` through it would either re-exec this module ~30 times per verdict
# validation or force an eager import onto every worker-pr entry point. The duplicate is made safe
# the only way a duplicate can be — --self-test loads worker-pr.py and asserts the two are one
# sanitiser, by PATTERN, by FLAGS, and behaviourally over a sample set.
RESERVED_MARKER_RE = re.compile(r"<!--\s*sparq-", re.IGNORECASE)


def contains_reserved_marker(text):
    """True when `text` carries the reserved `<!-- sparq-` bot-marker opener. Used to REJECT
    model-derived free text at validation (fail closed) where defanging would silently alter a
    field a human then reads as verbatim."""
    return bool(RESERVED_MARKER_RE.search(str(text)))


def neutralize_reserved_markers(text):
    """Visibly defang the reserved `<!-- sparq-` namespace so republished repository-controlled or
    model-derived text can never mint a durable bot marker. Breaking the opener to `<!- sparq-` is
    sufficient (the parsers require the exact opener) and leaves the text readable to a human.
    Reformation-safe — the replacement never re-contains the opener — and idempotent."""
    return RESERVED_MARKER_RE.sub("<!- sparq-", str(text))


# --- G4: the machine-readable PARK REASON marker ---------------------------------------------
#
# Every park exit used to record its cause in FREE PROSE only. That is why triaging the 33
# stalled sparq draft PRs (sparq-org/sparq#3809) needed a hand timeline reconstruction: five of
# them DID state a cause ("the PR head no longer descends from the worker-opened commit",
# "round-budget escalation-marker validation failed") but only a human could read it. A park
# whose cause no machine can read has no machine exit by construction — nothing downstream can
# tell a transient capacity blip apart from a genuine human question.
#
# The marker is written BESIDE the human-readable park comment (same comment body), by the same
# bot, under the same receipt grammar every other durable marker uses (safe_receipt_part), so it
# inherits the existing trust filter: only the orchestration bot's own comments are receipts, and
# a third party cannot forge one.
PARK_REASON_MARKER = "<!-- sparq-park-reason:v1"

PARK_CLASS_CAPACITY = "capacity"
PARK_CLASS_QUESTION = "question"

# --- [registry #769] groom's AGE park, and the episode binding that keeps it groom's ------------
#
# `review:parked` is a SHARED, MULTI-WRITER label. It is written by worker-pr's capacity ladder,
# by dispatch-claim's starvation park and legacy migration, and — since groom's age hand-off took
# the machine class — by groom's timeout park. Each of those writers has its OWN cause and its
# OWN cause-gated exit, and the label alone cannot tell them apart.
#
# These two markers are declared HERE, not in groom, for the same reason human_owned_holds is:
# the writer (groom) and the reader (dispatch-claim's re-admission sweep) are separate entry
# points with separate checkout roots, and a hand-copied literal in the reader is a spelling that
# can drift silently from the writer. One spelling, imported by both, cannot.
GROOM_AGE_PARK_MARKER = "<!-- registry-groom-age-park:v1"
GROOM_AGE_UNPARK_MARKER = "<!-- registry-groom-age-unpark:v1"

# --- the CONFLICT RESOLVER's stuck-attempt park, declared here for the same reason -------------
#
# resolve-conflicts.py's grace-window exit used to write the HUMAN terminal for a TIMEOUT — the
# identical defect #769 closed for groom, on a program #769 did not touch. It now writes the
# machine class with its own cause-gated exit, which puts a SECOND foreign episode into the
# `review:parked` population the capacity sweep reads. The writer (resolve-conflicts) and the
# reader (dispatch-claim's re-admission sweep) are, again, separate entry points, so the spelling
# lives here and neither side hand-copies it.
CONFLICT_STUCK_PARK_MARKER = "<!-- conflict-resolver stuck-park:v1"
CONFLICT_STUCK_UNPARK_MARKER = "<!-- conflict-resolver stuck-unpark:v1"

# Every mechanism whose `review:parked` park is CAUSE-GATED and cleared by its OWN sweep, as
# (durable park-receipt marker, what to call it, why fleet health cannot speak to its cause).
# The capacity sweep must leave EVERY row here alone; adding a mechanism is adding a row.
#
# THIS TUPLE IS THE POINT. `age_park_episode` is a per-mechanism predicate only by accident of
# having had one mechanism; the property it actually tests — "some other sweep owns this park's
# exit, and the sustained-fleet-health heuristic would clear it on AGE ALONE" — is shared by
# every cause-gated writer. Keeping it per-mechanism means each new writer silently re-acquires
# #769's defect until someone remembers to add a guard at the reader, which is a checkout root
# away.
CAUSE_GATED_PARK_OWNERS = (
    (GROOM_AGE_PARK_MARKER,
     "groom's cause-gated AGE park",
     "its exit is groom's own cause proof, and sustained fleet health is not evidence about an "
     "orphan draft or a wedged merge state"),
    (CONFLICT_STUCK_PARK_MARKER,
     "the conflict resolver's cause-gated STUCK-ATTEMPT park",
     "its exit is the resolver's own cause proof — the PR head moving, or the conflict "
     "resolving — and sustained fleet health is evidence about neither"),
)


def cause_gated_park_episode(labels, comments, bot_login, superseding_markers=(), log=print):
    """``(owned, detail)`` — whether the live machine park belongs to a CAUSE-GATED episode owned
    by another sweep (CAUSE_GATED_PARK_OWNERS), and therefore is NOT the capacity sweep's to
    clear. `detail` names WHICH mechanism owns it.

    THE DEFECT THIS EXISTS TO CLOSE (registry #769, reproduced end to end against the real
    dispatch-claim sweep over real model-health records). groom's age park writes
    `review:parked`, which puts it in the exact candidate population
    `_readmit_capacity_parks` sweeps. Its cause — an orphan draft, a wedged merge state — is not
    an account starvation, so `capacity_recovery_evidence` finds nothing and
    `park_cause_provable` is False; the probe therefore falls through to the labelled
    `sustained_fleet_health_evidence` HEURISTIC, which fires on "the park is at least
    SUSTAINED_HEALTH_SPAN_SECONDS old AND the fleet has been healthy across that span".
    MEASURED: the identical park and the identical health window yield `None` at 3 h and
    `auto-mint` at 7 h. The only variable is crossing the span — so the evidence clearing an AGE
    park was, in substance, MORE AGE. A timeout is not a human question, and it is not its own
    recovery proof either.

    WHY THE HEURISTIC IS NOT SIMPLY REMOVED. It was added by registry #691 for parks that had NO
    machine exit at all — measured, all 32 sparq legacy parks — and deleting it restores exactly
    that stall. The narrower true statement is that it is the WRONG EVIDENCE FOR THIS CLASS: an
    age park is not a park without an exit, it is a park whose exit lives in another sweep
    (groom's `age_park_cause_recovered`, gated on the park's own cause). So the class is made
    ineligible for health-only clearance and nothing else changes. Genuine capacity parks keep
    the heuristic byte-for-byte.

    WHAT IS ACCEPTED INSTEAD, and it is strictly MORE than the heuristic offered:
      * groom's own cause proof — an admissible provenance record on the live ledger ref for an
        orphan-draft park, or a `mergeable_state` out of BAD_MERGE_STATES for a merge park;
      * a proven-human gesture, which `capacity_park_admission` checks BEFORE this predicate is
        ever consulted and which is therefore untouched;
      * groom's escalation to the human class once the age cap is spent.

    THE SHAPE IS `starvation_park_owner`'s, and for the same stated reason: a receipt that is not
    bound to an EPISODE lives forever and eventually authorises a write it never earned. Here the
    binding runs the other way — this predicate proves the park is SOMEONE ELSE'S — so every
    ambiguity resolves toward the age episode owning it, i.e. toward the capacity sweep leaving
    the park alone.

      0. THE PR-SIDE MACHINE PARK MUST BE LIVE — starvation_park_owner's clause 1, and it is
         load-bearing rather than a formality. This predicate makes a claim about ONE label:
         "this `review:parked` is groom's". Where no `review:parked` is live the claim has no
         subject, and answering it anyway strands a real park: the re-admission sweep also
         admits a PR whose SOURCE ISSUE carries `status:parked` with no PR-side label at all,
         and such a PR can still carry an age receipt from an EARLIER, already-closed episode
         (groom parked it, the cause recovered, groom cleared the label). Judging that receipt
         would refuse an issue-side capacity park groom has no exit for.
      1. INERT UNLESS PROVEN RELEVANT. With no bot-authored receipt from ANY row of
         CAUSE_GATED_PARK_OWNERS anywhere in the history the answer is False with no timestamp
         parsing at all. This is what makes the change safe for the entire existing capacity
         population: a PR that has never seen a cause-gated park cannot reach a single new
         branch, so no legacy park loses the #691 exit.
      2. TRUST FILTER FIRST. Only the orchestration bot's own comments are receipts (the rule
         every other receipt reader here applies), so a third party cannot forge an age receipt
         and talk a genuine capacity park into standing forever.
      3. EPISODE BINDING. `superseding_markers` are the durable park receipts of the OTHER
         mechanisms — worker-pr's park-generation receipt and PARK_REASON_MARKER. One of those
         STRICTLY newer than the newest age receipt means another mechanism has parked since, so
         the age episode is closed and the ordinary capacity path resumes. They are passed in
         rather than hard-coded because the generation marker's spelling is owned by worker-pr;
         the caller pins it against the real module.
      4. TIES LEAVE THE PARK ALONE. A superseding receipt sharing an instant with the age
         receipt is the ambiguous case, so it does NOT close the episode (the mirror of
         starvation_park_owner's `>=`-refuses, in the direction that refuses to clear).
      5. AN UNREADABLE STAMP IS NOT AN EPISODE BOUNDARY. Once an age receipt is known to exist,
         a bot comment whose `created_at` cannot be parsed makes the boundary unprovable, and
         the answer is True — the age episode keeps the park.

    Note what is deliberately NOT a superseding marker: groom's own un-park receipt. groom writes
    the receipt BEFORE it deletes the label, so a receipt with the label still live is groom's
    own crash residue, which groom's convergence branch completes. Treating it as an episode
    boundary would hand that residue to the capacity sweep, which would clear it while minting a
    receipt claiming a starvation recovery that never happened. The SAME reasoning covers
    CONFLICT_STUCK_UNPARK_MARKER, which is written receipt-first by the same discipline.

    MULTI-OWNER RESOLUTION. When receipts from more than one owner are on record the NEWEST one
    names the episode, by the same strictly-newer rule the superseding markers use — an older
    mechanism's receipt cannot claim a park a newer mechanism has since applied. A tie keeps the
    FIRST row of CAUSE_GATED_PARK_OWNERS, which is arbitrary but deterministic: both answers are
    True, and only the `detail` prose differs."""
    if MACHINE_PARK_PR_LABEL not in {label for label in (labels or ())
                                     if isinstance(label, str)}:
        return (False, "")
    if not bot_login:
        return (False, "")
    rows = []
    seen_owned = False
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        # `(comment.get("user") or {}).get(...)` is the house spelling, but it raises on a
        # non-empty non-dict `user` — and this predicate runs inside the re-admission sweep's
        # per-PR `try`, which catches DispatchError/WorkerPrError only, so an AttributeError here
        # would abort the WHOLE tick rather than skip one PR. Production `_pr_comments` validates
        # the shape, so this is unreachable today; it is written so that it stays a REFUSAL rather
        # than a head-of-line abort if that ever stops being true.
        user = comment.get("user")
        login = str(user.get("login", "")) if isinstance(user, dict) else ""
        if login.casefold() != str(bot_login).casefold():
            continue
        body = str(comment.get("body", ""))
        if any(marker in body for marker, _name, _why in CAUSE_GATED_PARK_OWNERS):
            seen_owned = True
        rows.append((comment.get("created_at"), body))
    if not seen_owned:
        return (False, "")
    newest_owned = None
    owner_name = owner_why = ""
    stamped = []
    for stamp, body in rows:
        if not valid_timestamp(stamp):
            log(f"::warning::a bot receipt carries an unreadable stamp {stamp!r}, so the "
                "cause-gated park episode boundary cannot be established; the park stands")
            return (True, "a bot receipt carries an unreadable stamp, so the cause-gated park "
                          "episode boundary cannot be established")
        instant = parse_ts(stamp)
        stamped.append((instant, body))
        for marker, name, why in CAUSE_GATED_PARK_OWNERS:
            if marker in body and (newest_owned is None or instant > newest_owned):
                newest_owned, owner_name, owner_why = instant, name, why
    for instant, body in stamped:
        if instant <= newest_owned:
            continue                    # a tie is ambiguous: it does NOT close the episode
        for marker in superseding_markers:
            if marker and marker in body:
                return (False,
                        f"another park mechanism receipted at {canonical_ts(instant.isoformat())}"
                        ", strictly after the newest cause-gated park receipt — that episode is "
                        "closed and this park is the capacity sweep's again")
    return (True,
            f"{owner_name} (newest receipt {canonical_ts(newest_owned.isoformat())}) — "
            f"{owner_why}")


# The spelling dispatch-claim's re-admission sweep calls. It is NOT deprecated prose: the two
# names are the same object, and the old one is kept because scripts/dispatch-claim.py is
# concurrently owned by other in-flight work — a one-line rename there would be a merge conflict
# bought for nothing, while the predicate it resolves to is the one that must not drift.
age_park_episode = cause_gated_park_episode

# The CLOSED taxonomy of park causes and the class each belongs to. The class decides label
# ownership (invariant 1): a capacity cause takes the MACHINE-owned soft hold (review:parked /
# status:parked) and therefore has a machine exit; a question cause takes the HUMAN-owned
# terminal (review:needs-user / needs:user) and is cleared only by a human.
#
# An UNKNOWN cause is not silently admitted anywhere: park_cause_class returns None and every
# consumer's documented fail direction is to treat it as a QUESTION (stay parked, ask a human) —
# the same direction every other ambiguity in this module fails in.
PARK_CAUSES = {
    # --- capacity / infra: transient, self-correcting, machine-owned -------------------------
    "budget": PARK_CLASS_CAPACITY,            # review round budget exhausted
    "dispatch-missed": PARK_CLASS_CAPACITY,   # consecutive fix dispatches missed (starvation)
    "nochange": PARK_CLASS_CAPACITY,          # repeated clean model exits producing no change
    "gatefail": PARK_CLASS_CAPACITY,          # repeated local gate failures
    "cold-groom": PARK_CLASS_CAPACITY,        # groom's age/staleness hand-off (G3)
    # The dispatcher's own crate-partition starvation (registry #677): this PR is holding the
    # serializing `__global__` partition, the issue lane planned NOTHING behind it, and parking it
    # provably frees that partition. It is a SCHEDULING action about the fleet, not a judgement
    # about the diff — which is exactly what makes it capacity-class. It must NEVER be allowed to
    # graduate into the human terminal (registry #703: parks are a conveyor into `needs:user`), so
    # the writer of this cause parks the PR label DIRECTLY and never routes through the
    # generation-counting escalation ladder that turns an exhausted capacity park into a question.
    "partition": PARK_CLASS_CAPACITY,
    # The honest fallback for a capacity park whose writer did not state a narrower cause
    # (worker-pr.needs_user(park_class="capacity") reached from a call site that passes no
    # `park_cause`). It exists so that EVERY capacity park emits SOME park-reason receipt: a park
    # episode with no cause receipt at all is what let a stale `cause=partition` receipt stay
    # "newest" forever and authorise releasing a park a different mechanism had applied. An
    # unspecified cause is deliberately NOT a lie about which mechanism parked the PR — it says
    # exactly what is known, which is "capacity, unattributed".
    "capacity-unspecified": PARK_CLASS_CAPACITY,
    # --- genuine human questions: terminal, human-owned --------------------------------------
    "injection": PARK_CLASS_QUESTION,         # prompt-injection flag raised on the PR
    "human-arm": PARK_CLASS_QUESTION,         # a human requested changes / asked to arm by hand
    "history-rewritten": PARK_CLASS_QUESTION,  # head no longer descends from the opened commit
    "marker-corrupt": PARK_CLASS_QUESTION,    # durable round/model/pin markers failed validation
    "routing-unresolvable": PARK_CLASS_QUESTION,  # no concrete provider model in the catalog
    # [registry #972] review-fix.yml's `Verify target App identity and default branch` step
    # refused the run. QUESTION and not CAPACITY, decided by the ONE property that separates the
    # two halves of this table: every capacity cause caps something that CAN come out differently
    # on the next attempt (a different model tier, a re-run gate, a freed lease), which is what
    # makes a machine re-admission worth minting. This gate's inputs are the target repo's own
    # `full_name`/`default_branch`, the App's own login, and the PR's author — a re-dispatch
    # changes NONE of them, so a retry is identical BY CONSTRUCTION and a capacity park's
    # auto-readmission would deliver the PR straight back into the same refusal. Terminal on the
    # first observation, exactly like `history-rewritten` and `routing-unresolvable`, which are
    # terminal for the same reason.
    "target-identity": PARK_CLASS_QUESTION,   # target-App identity gate refused the review run
}

# Causes NO machine path may ever re-classify, re-admit, or convert out of the human terminal —
# not on a marker, not on prose, not on a cap, not ever. These are the parks that exist BECAUSE a
# judgement was made; unparking them automatically would present un-reviewed (or actively
# hostile) work as ready. Consulted by every automatic path; see reclassify_legacy_park.
PARK_HUMAN_ONLY_CAUSES = frozenset({"injection", "human-arm"})


def park_cause_class(cause):
    """The class of `cause` (PARK_CLASS_CAPACITY / PARK_CLASS_QUESTION), or None when the cause
    is not in the closed PARK_CAUSES taxonomy. None means UNKNOWN, and every caller's fail
    direction on unknown is to treat the park as a human question."""
    if not isinstance(cause, str):
        return None
    return PARK_CAUSES.get(cause)


def park_reason_marker(cause, generation=None, head=None):
    """The durable machine-readable stop-reason marker for one park exit, to be appended to the
    park comment body. The `class=` field is DERIVED from the taxonomy here rather than passed in,
    so a writer can never emit a marker whose class contradicts its cause (that mismatch is what a
    reader would have to trust to route an `injection` park into the machine class).

    Raises ValueError on a cause outside PARK_CAUSES, or on a generation/head that cannot be
    safely embedded — an unrepresentable marker must fail LOUD at the writer rather than be
    written unparseable, which is exactly how #610's gen-1 receipts were silently lost."""
    park_class = park_cause_class(cause)
    if park_class is None:
        raise ValueError(f"unknown park cause {cause!r} (not in PARK_CAUSES)")
    marker = f"{PARK_REASON_MARKER} class={park_class} cause={cause}"
    if generation is not None:
        if not safe_receipt_part(str(generation)):
            raise ValueError(f"unsafe park-reason generation {generation!r}")
        marker += f" gen={generation}"
    if head:
        if not safe_receipt_part(str(head)):
            raise ValueError(f"unsafe park-reason head {head!r}")
        marker += f" head={head}"
    return marker + " -->"


# [registry #1096] ANCHORED TO A WHOLE LINE. Every writer of this receipt emits it as
# `"\n\n" + park_reason_marker(...)` — on its own line, at top level, at the end of the body — so
# requiring the marker to BE a line costs a genuine receipt nothing. What it buys is that a marker
# ECHOED inside some other line (`- conflict-file: "<path>"`, a list item, a quoted diff hunk) is
# structurally not a receipt. Unanchored, ANY App-authored comment that interpolated an attacker's
# string was a receipt-minting surface, because park_reason_records scans every App comment rather
# than only the parks. The writer-side sanitiser is the primary defence; this is the reader-side
# half, and it holds even for a writer that has not yet been taught to sanitise.
_PARK_REASON_RE = re.compile(
    r"^" + re.escape(PARK_REASON_MARKER)
    + r" class=(\S+) cause=(\S+?)(?: gen=(\S+))?(?: head=(\S+))? -->[ \t]*$",
    re.MULTILINE)

# Lines that OPEN or CLOSE a fenced code block, and lines that are markdown-QUOTED. Both are how a
# comment says "this text is not mine, I am echoing it" — which is exactly the context a forged
# receipt would arrive in, and never a context a real receipt is written in.
#
# [registry #1096, review round 2] The fence run is matched with MARKDOWN's boundaries, not with
# `^(?:```|~~~)`, because a stripper that disagrees with the RENDERER is a bypass rather than a
# defence: every line where the renderer still says "code" but the stripper says "prose" is a line
# whose forged receipt this parser would trust. The naive form diverged three ways, each reachable
# from text a writer merely echoes into a fence — (a) an OPENER indented 0-3 spaces (legal
# markdown) was not seen as a fence at all, so the whole block read as the bot's own voice;
# (b) a run of three inside a longer fence, and (c) the OTHER delimiter character, each toggled the
# state off while the renderer stayed inside the block. So: capture the opener's character and run
# LENGTH, and close only on the same character, a run at least as long, and nothing but whitespace
# after it (a closing fence takes no info string). Every remaining disagreement now errs the other
# way — the stripper can only stay fenced LONGER than the renderer, which drops a receipt (an
# unreadable cause is a human question) instead of trusting an echoed one.
_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*(.*)$")
_QUOTE_RE = re.compile(r"^>")


def strip_quoted_contexts(body):
    """`body` with every fenced-code-block and blockquote line removed.

    A receipt is a statement the bot makes in its OWN voice. Text the bot merely ECHOES — a diff
    hunk in a fence, a maintainer's comment re-quoted with `>` — carries no authority even though
    the App authored the comment that contains it. Dropping those lines before the receipt scan is
    what makes "the App said it" mean "the App said it", rather than "the App printed it".

    Lines are DROPPED rather than blanked in place; nothing downstream keys on line numbers, and
    the anchored `_PARK_REASON_RE` needs the surviving lines to still be whole lines."""
    kept = []
    fence = None  # (delimiter char, opening run length) while inside a fenced block
    for line in str(body).splitlines():
        match = _FENCE_RE.match(line)
        if fence is None:
            if match:
                # An unterminated fence swallows the rest of the body: the fail-closed direction
                # (a receipt after a dangling fence is unreadable, and unreadable is a question).
                fence = (match.group(1)[0], len(match.group(1)))
                continue
        else:
            if (match and match.group(1)[0] == fence[0]
                    and len(match.group(1)) >= fence[1] and not match.group(2)):
                fence = None
            # Everything from the opener to the closer inclusive is echoed text, including a
            # SHORTER or MISMATCHED run that markdown renders as content rather than as a closer.
            continue
        if _QUOTE_RE.match(line):
            continue
        kept.append(line)
    return "\n".join(kept)


def parse_park_reason(body, log=print):
    """The LAST well-formed park-reason marker in `body` as
    {"class", "cause", "gen", "head"}, else None.

    The marker must occupy a WHOLE LINE of the bot's own unquoted prose (`_PARK_REASON_RE` is
    line-anchored, and `strip_quoted_contexts` removes fenced/quoted lines first): a receipt is
    something the bot ASSERTS, not something it echoed. See registry #1096 — resolve-conflicts.py
    interpolated raw git pathnames into an App-authored comment, so a crafted pathname could mint
    a receipt that this parser then trusted.

    A marker whose `class=` DISAGREES with its cause's registered class, or whose cause is
    outside the closed taxonomy, is REJECTED (dropped with a loud log), not repaired. Repairing it
    would mean choosing which half to believe, and the dangerous direction is obvious: a marker
    reading `class=capacity cause=injection` must never be read as a capacity park. Rejection
    leaves the park unclassified, which every consumer treats as a human question."""
    if not isinstance(body, str):
        return None
    found = None
    for match in _PARK_REASON_RE.finditer(strip_quoted_contexts(body)):
        park_class, cause, generation, head = match.groups()
        expected = park_cause_class(cause)
        if expected is None:
            log(f"::warning::park-reason marker names an unknown cause {cause!r}; ignoring it "
                "(the park stays unclassified — a human question)")
            continue
        if park_class != expected:
            log(f"::warning::park-reason marker for cause {cause!r} claims class "
                f"{park_class!r} but the taxonomy says {expected!r}; ignoring the marker "
                "(a class that contradicts its cause is never trusted)")
            continue
        found = {"class": park_class, "cause": cause, "gen": generation, "head": head}
    return found


def park_reason_records(comments, bot_login, log=print):
    """Every well-formed park-reason marker across the BOT's OWN comments, oldest first.

    Only the orchestration bot's comments are receipts — the same trust filter
    park_generation_cutoffs / auto_readmission_records apply — so a third party cannot forge a
    cause and talk a park out of the human terminal. Without a `bot_login` nothing is trusted."""
    if not bot_login:
        return []
    records = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        if login.casefold() != str(bot_login).casefold():
            continue
        record = parse_park_reason(str(comment.get("body", "")), log=log)
        if record:
            records.append(record)
    return records


# --- G1: one-shot re-classification of a LEGACY (pre-marker) park ----------------------------
#
# Parks written before PARK_REASON_MARKER recorded their cause in prose only. 31 of the 33 sparq
# draft PRs stalled on review:needs-user (sparq-org/sparq#3809) were parked before the
# capacity/question split landed, so they carry the HUMAN-owned terminal for an INFRA cause and
# nothing downstream will ever re-classify them: capacity_park_admission keys on review:parked
# plus bot receipts, which these PRs do not have. They are stalled permanently by construction.
#
# These patterns are matched ONLY against the orchestration BOT's OWN comments (park_reason_
# records' trust filter), never a third party's, so no one can talk a park out of the human
# terminal by quoting a string.

# Prose that, ANYWHERE in a PR's bot history, permanently disqualifies it from automatic
# re-classification. DENY IS UNCONDITIONAL AND ORDER-INDEPENDENT — deliberately NOT "the most
# recent cause wins".
#
# LIVE EVIDENCE for that choice (sparq-org/sparq, 2026-07-25): #3743 and #3608 are both genuine
# injection escalations that ALSO carry a LATER capacity-park comment ("two consecutive fix
# attempts made no change"). Under a recency rule both would re-classify as `nochange` and be
# handed back to the machine — re-admitting two PRs a human parked for a security reason. A
# raised injection flag is a property of the PR's whole history, not of its newest comment.
#
# [registry #814] THE SIGNAL IS THE LOOP'S OWN ESCALATION SENTENCE, NOT THE PHRASE ITSELF.
#
# The first cut denied on `prompt[- ]injection` occurring ANYWHERE in the bot's history. But the
# bot does not only ASSERT under its own identity — `worker-pr.post_findings` REPUBLISHES
# model-derived verdict text (summary, issue titles/bodies) as a bot comment, and a reviewer
# reporting the ABSENCE of injection writes exactly that phrase. So the deny fired on a sentence
# asserting the OPPOSITE of the signal it looks for. Measured on sparq-org/sparq, 2026-07-27 —
# three PRs refused re-classification with no injection signal present anywhere:
#
#   #3901  "No instruction-like prompt injection was detected in the diff."
#   #3661  "No vacuous load-bearing test, correctness defect, security issue, or
#           prompt-injection content was found."
#   #3554  "No correctness, soundness, test-validity, security, or prompt-injection issue
#           remains in the diff-scoped evidence."
#
# The fail direction was safe (the hold stands), but the effect is a PR pinned to the human-owned
# terminal for a condition that does not exist, with no machine exit, forever — and a PR about
# injection DEFENCES would be permanently unreclassifiable for the same reason.
#
# So the deny narrows to the SHAPE the loop's own escalation writes:
#
#   (a) the ESCALATION SENTENCE emitted by all three injection write sites — worker-pr's
#       `INJECTION_PROSE_REVIEW` / `INJECTION_PROSE_FIX` / `INJECTION_PROSE_FINDINGS`, i.e.
#       "flagged … possible prompt[- ]injection" — the shape #814's own survey found on every one
#       of the eight genuine live escalations (#3542 #3563 #3585 #3608 #3609 #3618 #3743 #4406),
#       six of which are pinned as fixtures below. The gap is bounded and newline-free, so the
#       two halves must be ONE sentence rather than two facts a page apart; and
#   (b) the machine-composed PARK LEAD naming injection as the stop cause, so a historical stop
#       sentence worded without "flagged"/"possible" is still denied.
#
# [registry #814 round 2] NEITHER SHAPE IS PROVENANCE, AND CLAIMING IT WAS WAS THE DEFECT.
#
# The first cut of this note said these sentences are ones "no model can author into a verdict".
# That is FALSE. `worker-pr.post_findings` republishes the model's `summary` / issue `title` /
# `body` / `fix_hint` VERBATIM under the bot's own identity, so a reviewer — hostile, or merely
# quoting the diff it is reviewing — can place either sentence byte for byte into a bot comment
# while `injection_detected` is FALSE. Matching a sentence can only ever establish that the
# sentence is present; it cannot establish WHO WROTE IT. A narrower sentence is a smaller target,
# not an authenticated one, and what it buys on a hit is the same permanent, machine-exitless
# hold on a PR nobody flagged that the negations above document.
#
# PROVENANCE COMES FROM WHERE THE TEXT SITS, NOT FROM WHAT IT SAYS. So `legacy_deny_signal`
# below — the one seam every consumer of this table goes through — reads a bot comment as:
#
#   * REVIEW_INJECTION_MARKER, the durable receipt post_findings writes BESIDE the findings
#     prose. It is in the reserved `<!-- sparq-` namespace that every republish sink runs
#     `neutralize_reserved_markers` over, so no model field can carry one across that sink. This
#     is the ONLY injection evidence a findings comment can offer, and it is unforgeable; then
#   * the prose table — applied ONLY to comments that republish nothing. A post_findings body is
#     machine-composed on its FIRST line and model-derived below it, and no test on the text can
#     tell those apart, so its prose is not read as a signal at all.
#
# WHAT THAT COSTS THE HISTORICAL POPULATION: nothing measured. `worker-pr.decide_review` returns
# "needs-user" UNCONDITIONALLY on an injection flag, so every escalation ALSO writes a
# machine-composed park comment carrying INJECTION_PROSE_REVIEW / INJECTION_PROSE_FIX — which is
# where all six genuine fixtures pinned below record it, and that comment republishes nothing.
# The findings copy was always the redundant one; from now on it carries the receipt instead,
# which also covers the crash window where the findings comment lands and the park does not.
#
# NARROWING A SECURITY CLASSIFIER IS THE DANGEROUS DIRECTION, so the binding is doubled: the
# self-test below pins the three measured NEGATIONS as non-signals AND every genuine escalation
# shape as denied, and worker-pr's own self-test runs its three real write sites under an
# injection flag and passes the text they EMITTED through this table by identity. Reword a write
# site and that guard reds — it is not satisfied by any copy of a sentence.
LEGACY_PARK_DENY_PROSE = (
    (re.compile(r"flagged\b[^\n]{0,64}?\bpossible prompt[- ]injection", re.IGNORECASE),
     "injection"),
    (re.compile(r"the autonomous review loop (?:stopped|parked this PR):[^\n]*prompt[- ]injection",
                re.IGNORECASE), "injection"),
    (re.compile(r"needs a human decision.*security", re.IGNORECASE), "human-arm"),
)

# --- [registry #814 round 2] the UNFORGEABLE half: the findings-comment injection receipt ------
#
# Declared HERE, beside the reader, for the same reason every other cross-entry-point marker in
# this file is (PARK_REASON_MARKER, GROOM_AGE_PARK_MARKER, CONFLICT_STUCK_PARK_MARKER): the
# writer (worker-pr.post_findings) and the readers live in separate entry points with separate
# checkout roots, and a hand-copied literal is a spelling that can drift silently.
REVIEW_INJECTION_MARKER = "<!-- sparq-review-injection:v1"


def review_injection_marker(round_n=None):
    """The durable receipt written beside worker-pr.INJECTION_PROSE_FINDINGS. It asserts "the LOOP
    raised this flag", where the prose beside it can only say "some text claims a flag was raised".

    `round_n` is recorded when it can be safely embedded and OMITTED when it cannot, never raised
    on: this receipt rides on the comment that escalates an injection flag to a human, and a
    receipt that refuses to render must not be able to prevent that comment — the same fail
    direction worker-pr.needs_user takes with an unrepresentable head."""
    marker = REVIEW_INJECTION_MARKER
    if round_n is not None and safe_receipt_part(str(round_n)):
        marker += f" round={round_n}"
    return marker + " -->"


# Line-anchored, and read only AFTER strip_quoted_contexts — exactly the `_PARK_REASON_RE`
# discipline (#1096): a marker echoed inside a longer line, a fenced block or a `>` quote is text
# the bot PRINTED, never text it ASSERTED.
_REVIEW_INJECTION_RE = re.compile(
    r"^" + re.escape(REVIEW_INJECTION_MARKER) + r"(?: round=(\S+))? -->[ \t]*$", re.MULTILINE)


def carries_review_injection_receipt(body):
    """True when `body` asserts the machine-authored review-injection receipt in its own voice."""
    return bool(_REVIEW_INJECTION_RE.search(strip_quoted_contexts(str(body))))


# The lead line worker-pr.post_findings composes for a republished verdict. It is ALWAYS that
# body's first line and every model-derived field is below it, so this is a POSITIONAL test that
# no model field can satisfy — which is the whole reason it may be trusted to say "nothing under
# this line is the loop's own voice".
REPUBLISHED_FINDINGS_LEAD_RE = re.compile(
    r"^>\s*🤖 SPARQ agent — cross-provider review round \d+:")


def republishes_model_text(body):
    """True when this bot comment REPUBLISHES model-authored text (a post_findings verdict).

    Its prose is the MODEL's, not the loop's, so no sentence in it may be read as a signal. The
    machine-authored evidence such a comment can still carry is REVIEW_INJECTION_MARKER, which
    the sink's own `neutralize_reserved_markers` pass makes unforgeable."""
    for line in str(body).splitlines():
        if not line.strip():
            continue
        return bool(REPUBLISHED_FINDINGS_LEAD_RE.match(line))
    return False


def legacy_deny_signal(body):
    """The deny cause ONE bot comment RECORDS, or None.

    The single seam every consumer of LEGACY_PARK_DENY_PROSE goes through (reclassify_legacy_park,
    reconcile-park-misescalation, reconcile-conflict-park), so the provenance rule cannot hold in
    one of them and quietly not in another — all three read the same bot histories."""
    text = str(body)
    if carries_review_injection_receipt(text):
        return "injection"
    if republishes_model_text(text):
        return None
    for pattern, denied in LEGACY_PARK_DENY_PROSE:
        if pattern.search(text):
            return denied
    return None


# Prose -> cause for legacy parks. A CAPACITY cause here is eligible for re-classification; a
# QUESTION cause is recognised so the stop reason becomes machine-readable, but it is NEVER
# migrated (it already sits in the right state — the human terminal).
LEGACY_PARK_PROSE = (
    (re.compile(r"the review round budget is exhausted at"), "budget"),
    (re.compile(r"consecutive fix dispatches missed"), "dispatch-missed"),
    (re.compile(r"consecutive fix attempts made no change"), "nochange"),
    (re.compile(r"consecutive local gate failures|the local gate failed"), "gatefail"),
    (re.compile(r"no longer descends from the worker-opened commit"), "history-rewritten"),
    (re.compile(r"escalation-marker validation failed"), "marker-corrupt"),
    (re.compile(r"unresolvable in the target routing"), "routing-unresolvable"),
)


def reclassify_legacy_park(comments, bot_login, stale_marker=None, log=print):
    """Decide whether a LEGACY prose-only park may be re-classified into the machine class.

    Returns (cause, park_class, detail). `cause` is None whenever the park must STAY exactly
    where it is — which is the fail direction for every ambiguity, as everywhere else here.

    The decision, in strict order:

    1. ALREADY CLASSIFIED. A well-formed PARK_REASON_MARKER on the bot's own comments means this
       park was written by a post-marker writer and already carries its class. Nothing legacy to
       migrate — re-classifying it would double-write a cause the writer already decided.
    2. DENY, UNCONDITIONALLY AND ORDER-INDEPENDENTLY (see LEGACY_PARK_DENY_PROSE). One injection
       or human-arm signal anywhere in the bot history disqualifies the PR forever. This is
       checked BEFORE any cause is derived so no ordering, recency, or precedence rule can ever
       reach past it. The signal is read by `legacy_deny_signal`, which keys on WHO WROTE the
       text and not merely on what it says: the bot republishes model-derived verdict text under
       its own identity, so a republished verdict is read only for the machine-authored
       REVIEW_INJECTION_MARKER, and a reviewer merely REPORTING injection — its absence, or the
       diff's own injection-defence fixtures — can neither raise nor forge a flag (#814).
    3. The NEWEST recognised cause decides — but only a CAPACITY cause migrates. A question-class
       cause is returned with its class so the caller can record the marker WITHOUT moving the
       label: `history-rewritten` and `marker-corrupt` are genuine human questions and the human
       terminal is already the correct state for them.
    4. `stale_marker` True (groom's registry-groom-stale-pr receipt is present) yields
       `cold-groom` when no stronger cause was recognised — groom's age hand-off records its
       cause in a marker rather than in a parseable sentence.
    5. Nothing recognised -> (None, None, ...). An unreadable cause is a human question.
    """
    if not bot_login:
        return (None, None, "no bot login — no comment on this PR can be trusted as a receipt")
    bot_bodies = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        if login.casefold() != str(bot_login).casefold():
            continue
        bot_bodies.append(str(comment.get("body", "")))

    for body in bot_bodies:
        if parse_park_reason(body, log=lambda *_a, **_k: None):
            return (None, None,
                    "the park already carries a machine-readable reason marker (not legacy)")

    # 2 — deny wins over everything, at any position in history.
    for body in bot_bodies:
        denied = legacy_deny_signal(body)
        if denied:
            return (None, None,
                    f"a {denied!r} signal is recorded on this PR — never automatically "
                    "re-classified, at any position in its history")

    # 3 — newest recognised cause wins among what is left.
    cause = None
    for body in bot_bodies:
        for pattern, candidate in LEGACY_PARK_PROSE:
            if pattern.search(body):
                cause = candidate
    if cause is None and stale_marker:
        cause = "cold-groom"
    if cause is None:
        return (None, None, "no recognised park cause in the bot's own comments")
    park_class = park_cause_class(cause)
    if park_class is None:                      # defensive: taxonomy drift
        log(f"::warning::legacy park cause {cause!r} is not in PARK_CAUSES; the park stands")
        return (None, None, f"cause {cause!r} is outside the taxonomy")
    return (cause, park_class, f"legacy prose classifies this park as {cause!r} ({park_class})")


# --- [registry #1309] THE RECEIPT-LESS PARK CLASS, AND ITS ONE-SHOT VOID EXIT -----------------
#
# THE DEFECT. Every OTHER `review:parked` episode in this tree belongs to a class whose exit some
# sweep owns: a capacity park exits on its own cause recovering (capacity_park_admission), an age
# park and a stuck-attempt park exit on their owner's cause proof (CAUSE_GATED_PARK_OWNERS), a
# legacy prose park is re-classified into one of those (reclassify_legacy_park). ALL of those exits
# are reached by READING A RECEIPT. A park with no receipt reaches none of them:
#
#   * capacity_park_admission's human-applied branch demands the bot's own capacity classification
#     (human_park_capacity_proof) — absent, so it refuses `human-applied-unclassified`, a code this
#     module itself documents as human-terminal BY NATURE ("a receipt that does not exist for an
#     already-parked PR cannot appear on a later tick");
#   * cause_gated_park_episode is INERT BY ITS OWN CLAUSE 1 with no owner receipt;
#   * reclassify_legacy_park reads only the BOT's comments, and this population's park comments were
#     authored by a USER account, so its prose is not even visible to it.
#
# So the park falls through every predicate and is permanent. Measured: 14 such PRs on
# sparq-org/sparq, 10 with a park comment authored by `jeswr` — which is the ORCHESTRATOR's account,
# not a human sitting at a keyboard. `actor.__typename == "User"` on those events therefore proves
# nothing about intent. This is machine damage that the machine had no way to undo.
#
# WHAT THIS DOES NOT DO: it does not reconstruct a cause. Nothing below parses the park comment's
# prose — not one character of it — so there is no "absent / ambiguous / wrong" case to fail on. A
# fabricated cause would be worse than none: it would enter the taxonomy as a fact, be read by
# park_cause_class, and route the park into a recovery predicate about a condition nobody observed.
# The park is instead voided FOR WANT OF A RECEIPT: the honest finding is not "the cause recovered",
# it is "no cause was ever recorded, so this park records no decision the machine can honour".
#
# WHY IT TERMINATES — the property that had to hold before any of this was worth shipping:
#
#   1. RECEIPT-MONOTONICITY. The exit's own precondition is "zero park-reason receipts, ever".
#      Comments are append-only, and every machine capacity park emits a receipt by construction
#      (PARK_CAUSES carries `capacity-unspecified` precisely so it always does). So the instant any
#      machine re-parks a voided PR, park_is_receiptless is FALSE FOREVER and this exit can never
#      fire for that PR again. The class is SELF-EXTINGUISHING: it cannot be re-entered through the
#      machine path at all.
#   2. AN EXPLICIT ONE-SHOT COUNTER, because (1) is an argument and this is an invariant.
#      RECEIPTLESS_VOID_MAX bounds the void at ONE PER PR FOR THE PR'S WHOLE LIFETIME, counting
#      MARKERS rather than parsed records (AUTO_READMIT_MARKER's rule: a corrupt receipt is still
#      proof the exit was taken, so it must spend the budget). Even a hand-park repeated by the same
#      orchestrator gets exactly one void, then `receiptless-spent`, which is human-terminal.
#   3. IT BORROWS NO OTHER BUDGET AND LENDS NONE. Separate counter from AUTO_READMISSION_MAX for the
#      reason groom's age-unpark records in as many words: routing one mechanism's receipts through
#      another's cap makes the two re-admission budgets consume each other. It still READS the
#      capacity cap and refuses under it (see capacity_park_admission), so a PR that has already
#      flapped twice does not get a third exit through a different door.
#
# The bound is therefore <= 1 void per PR, ever — a finite, per-entity, monotone budget, with no
# state in which voiding produces a condition that permits another void.
RECEIPTLESS_VOID_MARKER = "<!-- sparq-park-receiptless-void:v1"

# ONE void per PR, for the PR's whole lifetime. Deliberately not "per park episode": an episode
# counter would be re-armed by every fresh hand-park, which is exactly the unbounded cycle the
# termination obligation forbids.
RECEIPTLESS_VOID_MAX = 1

# How close to the park application a self-identifying comment must sit to be part of the SAME
# operation. Measured on the live population: the orchestrator posts its park comment 2 SECONDS
# before the label, receipt-first, on every PR checked (sparq #4197/#4207/#4212). 60s is that
# observation plus slack for API latency and retries — and it is the whole reason the window exists:
# sparq #4212 also carries a bare `> 🤖 SPARQ agent` comment from a DIFFERENT operation two days
# later, and a rule with no window would let that comment retroactively authorise a park it had
# nothing to do with.
MACHINE_PROVENANCE_WINDOW_SECONDS = 60

# The self-identification every agent in this fleet is required to open a comment with (AGENTS.md:
# "Identify yourself with this blockquote in every issue/PR/comment you author"), matched on the
# body's FIRST LINE only.
#
# ANCHORED, AND EMPHASIS-TOLERANT, and both halves are load-bearing:
#   * anchored to the first line, because a self-ID quoted deeper inside a body is a comment ABOUT
#     an agent, not a comment BY one — groom.WORKER_PR_MARKER is consumed the same way
#     (`body.lstrip().startswith(...)`, see pr-body-ref.py);
#   * emphasis-tolerant, because the live population writes `> 🤖 **SPARQ agent** — parking ...`
#     while the bot's own comments write `> 🤖 SPARQ agent — ...`. A literal `startswith("> 🤖 SPARQ
#     agent")` matches the second and MISSES THE FIRST — i.e. it would have matched every PR except
#     the 10 this exit exists for, and shipped as a fix that measured +0 in production.
_SELF_ID_RE = re.compile(r"^ {0,3}>\s*🤖\s*\**\s*SPARQ\s+agent\b", re.IGNORECASE)


def self_identified_machine_comments(comments):
    """[{"login", "at"}] for every comment whose FIRST LINE is the SPARQ-agent self-ID, oldest
    first.

    NO trust filter here, exactly as reconcile_attestations declines one: the filter that is
    actually sound for this record is not "was it the App" — an App-authored park is not in this
    population at all — but "was it the same actor that applied the park being voided", which
    machine_operated_park_proof applies."""
    rows = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        body = str(comment.get("body", ""))
        first_line = body.lstrip("\r\n").split("\n", 1)[0]
        if not _SELF_ID_RE.match(first_line):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        rows.append({"login": login, "at": comment.get("created_at")})
    return rows


def machine_operated_park_proof(self_id_rows, parked_at, previous_parked_at, park_logins,
                                window_seconds=MACHINE_PROVENANCE_WINDOW_SECONDS):
    """(proven, detail, row) — whether THE ACTOR THAT APPLIED THIS PARK was demonstrably a machine
    operating a user account, rather than a human making a decision. `row` is the self-ID row that
    BOUND (None when nothing did).

    Returning the binding row — where the sibling park_instance_attested returns only a 2-tuple — is
    deliberate: the caller has to name that exact row in the durable receipt, and a caller that
    re-scanned `self_id_rows` to find it could pick a DIFFERENT row than the one that authorised the
    void. One scan, one row, no second opinion.

    THE ASYMMETRY THIS ENCODES, and it is the whole reason this population exists.
    `actor.__typename == "Bot"` is decisive for machine. `"User"` is NOT decisive for human: the
    orchestrator runs under the maintainer's own account, and that is precisely how these parks were
    created. So a User-applied hold gets no exit on the strength of being User-applied; it needs a
    SECOND, positive signal that a machine was driving.

    That signal is a self-identifying comment by THE SAME ACTOR, inside the SAME OPERATION:

      1. AUTHORED BY AN ACTOR THAT APPLIED THIS PARK. park_instance_attested's clause 1, for its
         reason as well as its shape: it makes the signal unforgeable IN THE ONLY DIRECTION THAT
         MATTERS, and it grants the author no capability they did not already hold. Anyone who can
         apply `review:parked` to a bot-authored PR in this repo is a proven human by this module's
         own probe, and a proven human can ALREADY clear a machine park outright via
         capacity_park_readmitted's unlabel gesture. So the most a forged self-ID buys is voiding a
         park YOU YOURSELF applied — which you could do with one click. A third party's self-ID,
         however perfectly forged, is ignored.
      2. WITHIN `window_seconds` OF THE PARK, EITHER SIDE. The comment and the label are one
         operation or they are unrelated; see MACHINE_PROVENANCE_WINDOW_SECONDS for the measured
         2-second ordering and for the live comment this bound excludes.
      3. STRICTLY AFTER EVERY EARLIER PARK APPLICATION. park_instance_attested's lower bound, kept
         even though the tight window very nearly implies it: it costs nothing and it is what stops
         a record from a CLOSED earlier episode from binding to this one.

    Every ambiguity refuses: no rows, an unattributable applying actor, an unknown park instant, an
    unparseable stamp, a row outside the window."""
    if parked_at is None:
        return (False,
                "the park application instant is unknown, so no operation can be bound to it",
                None)
    applying = {str(login) for login in (park_logins or []) if str(login)}
    if not applying:
        return (False, "the actor that applied this park is unattributable, so its provenance "
                       "cannot be proven", None)
    park_instant = parsed_park_instant(parked_at)
    for row in self_id_rows or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("login", "")) not in applying:
            continue                      # somebody else's self-ID about somebody else's act
        if not valid_timestamp(row.get("at")):
            continue                      # unprovable time can never bind an operation
        at = parse_ts(row["at"])
        if abs((at - park_instant).total_seconds()) > window_seconds:
            continue                      # a different operation that merely self-identified
        if previous_parked_at is not None and at <= previous_parked_at:
            continue                      # belongs to a CLOSED earlier episode
        return (True, (f"a SPARQ-agent self-identification by {row['login']!r} at "
                       f"{canonical_ts(row['at'])} sits within {window_seconds}s of this park "
                       "application by the same actor — the park was applied by a machine "
                       "operating a user account"), row)
    return (False, ("no SPARQ-agent self-identification by the actor that applied this park sits "
                    f"within {window_seconds}s of it — a User-applied hold is NOT assumed to be "
                    "machine-made, so the park stands"), None)


# --- [registry #1309, review round 1 finding B1] WHAT THE VOID IS ALLOWED TO WRITE -------------
#
# THE DEFECT THIS CLOSES, and it was worse than the one the void exists to fix. The first cut
# cleared the park through the SAME `clear_labels` the capacity path uses — `worker-pr review-state
# set --state needs`. But set_review_state's issue-#138 ambiguity rule CONVERGES to the HUMAN-owned
# `review:needs-user` whenever MORE THAN ONE `review:*` label is live, and a hand-applied
# `review:parked` was added ALONGSIDE the PR's existing review state rather than replacing it.
#
# Measured against the live label sets of the 8 candidate PRs: 5 of them (#3641 #4207 #4212 #4222
# #4318) carry >=2 live `review:*` labels, so the void would have converged them to
# `review:needs-user` — a hold `human_owned_holds` refuses forever and issue #138 blocks every
# automated transition away from — WITH THE ONE-SHOT VOID ALREADY SPENT. That is not "frees
# nothing"; it is actively worse than doing nothing, because it burns the only exit these PRs have
# in order to move them into a STRICTER hold. Every self-test stubbed the label writer, so nothing
# could have caught it.
#
# THE FIX IS TO WRITE LESS, NOT MORE. The true inverse of a hand-applied park is to REMOVE THAT ONE
# LABEL and touch nothing else — which restores the exact review state the PR was in before the
# park (`review:changes` for four of them; the fix lane, which is where they were). Forcing
# `review:needs` instead would ERASE a real `review:changes` and re-run a review where a fix was
# owed, i.e. it would assert a destination the machine has no basis for. So:
#
#   - residual namespace EMPTY  -> strip the park AND stamp `review:needs`, which is unambiguous by
#     construction (a single write into an empty namespace cannot trip the ambiguity rule);
#   - residual namespace exactly ONE label -> strip the park ONLY; the PR is back in its pre-park
#     state and no state was invented;
#   - residual namespace TWO OR MORE -> REFUSE. The ambiguity exists independently of the park
#     (#3641 carries review:needs AND review:changes), so no strip can leave a clean state and
#     anything written would eventually converge to the human terminal anyway. It is censused as its
#     own human-terminal code rather than swept into a generic refusal.
RECEIPTLESS_VOID_PLAN_STRIP = "strip-only"
RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS = "strip-and-needs"
RECEIPTLESS_VOID_PLANS = (RECEIPTLESS_VOID_PLAN_STRIP, RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS)


def receiptless_void_label_plan(pr_review_labels):
    """(plan, detail) — the ONLY label write a receipt-less void may perform, or (None, why) when
    it cannot be performed deterministically. Every ambiguity refuses.

    THE REVIEW NAMESPACE IS TAKEN BY PREFIX (`review:`), deliberately NOT by intersecting a closed
    label list. worker-pr's `_live_review_labels` intersects with its own `REVIEW_LABELS`, so a
    `review:something-new` it does not know about is invisible to it but VISIBLE here. That
    disagreement is one-directional and it is the safe direction: this predicate counts MORE labels,
    so it refuses MORE often. A closed list copied here could silently disagree with the writer's,
    which is the one direction that would let an ambiguous namespace through.

    ONE SPELLING, TWO READERS: capacity_park_admission consults this before spending the one-shot
    budget, and worker-pr's `void_receiptless_park` re-derives it from a FRESH read immediately
    before writing. Both call THIS function — a hand-copied second rule at the writer is exactly how
    the gate and the write come to disagree about what is deterministic."""
    if isinstance(pr_review_labels, str) or not isinstance(
            pr_review_labels, (set, frozenset, list, tuple)):
        return None, "the live PR label set is unreadable, so no write can be proven deterministic"
    if any(not isinstance(name, str) for name in pr_review_labels):
        return None, "the live PR label set is malformed, so no write can be proven deterministic"
    review = {name for name in pr_review_labels if name.startswith("review:")}
    if MACHINE_PARK_PR_LABEL not in review:
        return None, (f"no live {MACHINE_PARK_PR_LABEL} to strip — this void has no subject on the "
                      "PR surface")
    if HUMAN_PR_PARK_LABEL in review:
        # Belt and braces: human_owned_holds already refuses this upstream. A second, independent
        # refusal here means the WRITER cannot be talked into erasing a human terminal even if it is
        # ever called from somewhere that skipped that gate.
        return None, (f"{HUMAN_PR_PARK_LABEL} is live — a human terminal is never cleared by a "
                      "machine void")
    residual = sorted(review - {MACHINE_PARK_PR_LABEL})
    if not residual:
        return RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS, (
            f"the park is the ONLY live review:* label, so stripping it and stamping "
            f"review:needs is unambiguous by construction")
    if len(residual) == 1:
        return RECEIPTLESS_VOID_PLAN_STRIP, (
            f"stripping the park alone restores this PR's pre-park review state ({residual[0]}); "
            "no review state is invented")
    return None, (f"the review:* namespace is ambiguous independently of the park ({'/'.join(residual)}"
                  ") — no strip can leave a clean state, and any stamp would converge to the human "
                  "terminal (worker-pr issue #138)")


def receiptless_void_key(parked_at):
    """The single-use evidence key for voiding the receipt-less park applied at `parked_at`, or None
    when it cannot be safely embedded in a marker.

    Keyed on THE PARK INSTANT and nothing else, which is what makes it a FACT rather than a
    reconstruction: it identifies which park application was voided, it is unique per episode, and
    it can be checked for prior consumption exactly like a recovery-evidence key. It asserts nothing
    whatsoever about why the park was applied, because nothing knows."""
    if not valid_timestamp(parked_at):
        return None
    key = f"receiptless-void/{canonical_ts(parked_at)}"
    return key if safe_receipt_part(key) else None


def receiptless_void_marker(void_key, voided_at, prover_login, prover_at):
    """The durable machine-readable receipt for one receipt-less VOID, to be appended to the void
    comment body. Raises ValueError on any component that cannot be safely embedded — an
    unrepresentable receipt must fail LOUD at the writer rather than be written unparseable, which
    is how #610's gen-1 receipts were silently lost."""
    for name, part in (("key", void_key), ("prover", prover_login)):
        if not safe_receipt_part(str(part) if part is not None else ""):
            raise ValueError(f"unsafe receipt-less void {name} {part!r}")
    for name, stamp in (("voided_at", voided_at), ("prover_at", prover_at)):
        if not valid_timestamp(stamp):
            raise ValueError(f"receipt-less void {name} {stamp!r} is not a strict ISO-8601 stamp")
    return (f"{RECEIPTLESS_VOID_MARKER} key={void_key} at={canonical_ts(voided_at)} "
            f"prover={prover_login} prover_at={canonical_ts(prover_at)} -->")


# Anchored to a WHOLE LINE, for registry #1096's measured reason: unanchored, any App comment that
# interpolated an attacker's string would be a receipt-minting surface, because the reader below
# scans every App comment rather than only the voids.
_RECEIPTLESS_VOID_RE = re.compile(
    r"^" + re.escape(RECEIPTLESS_VOID_MARKER)
    + r" key=(\S+) at=(\S+) prover=(\S+) prover_at=(\S+) -->[ \t]*$",
    re.MULTILINE)


def receiptless_void_records(comments, bot_login, log=print):
    """Every WELL-FORMED bot-authored receipt-less VOID receipt as {"key", "at"} — the same shape
    capacity_park_admission's automatic-receipt convergence consumes, so one branch reads both.

    Bot-authored only: the void is minted by the sweep under the App identity, so a receipt that is
    not the App's proves no void. A malformed stamp is dropped LOUDLY (it can prove no void, so the
    park stays parked) and still spends the cap via receiptless_void_marker_count."""
    if not bot_login:
        return []
    records = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        if login.casefold() != str(bot_login).casefold():
            continue
        # QUOTED AND FENCED CONTEXTS STRIPPED FIRST, exactly as parse_park_reason does, and for
        # #1096's measured reason rather than by analogy: resolve-conflicts.py interpolates raw git
        # pathnames into App-authored comment bodies, so a crafted pathname is a receipt-minting
        # surface for any App-comment scanner. The writer-side defence already covers this marker by
        # construction — it carries the `sparq-` prefix RESERVED_MARKER_RE keys on, so
        # neutralize_reserved_markers disarms it at the writer — but the reader-side half must hold
        # for a writer that has not yet been taught to sanitise, and forging THIS marker would make
        # the sweep clear a park's labels.
        for match in _RECEIPTLESS_VOID_RE.finditer(
                strip_quoted_contexts(str(comment.get("body", "")))):
            key, stamp = match.group(1), match.group(2)
            if not valid_timestamp(stamp):
                log(f"::warning::malformed receipt-less void stamp {stamp!r} treated as absent — "
                    "it can prove no void (the park stands), and it still counts toward "
                    "RECEIPTLESS_VOID_MAX")
                continue
            records.append({"key": key, "at": canonical_ts(stamp)})
    return records


def receiptless_void_marker_count(comments, bot_login):
    """How many bot-authored void receipts a PR carries, WELL-FORMED OR NOT — the per-PR
    RECEIPTLESS_VOID_MAX counter. Counting markers rather than parsed records is load-bearing and is
    AUTO_READMIT_MARKER's rule: a receipt with a corrupt field is still proof the exit was taken, so
    it must spend the one-shot budget. Without this a writer that corrupts its own stamp would earn
    unlimited voids."""
    if not bot_login:
        return 0
    total = 0
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        if login.casefold() != str(bot_login).casefold():
            continue
        total += len(re.findall(re.escape(RECEIPTLESS_VOID_MARKER),
                                str(comment.get("body", ""))))
    return total


def receiptless_void_comment(evidence, voided_at, pr_number=None):
    """The receipt BODY the sweep posts (RECEIPT-FIRST) before clearing a receipt-less park's
    labels. One writer, one format, one place the claim is stated.

    `voided_at` is the instant the void is GRANTED and is supplied by the caller, because
    capacity_park_admission is deliberately clock-free — every other instant it reasons about is read
    from GitHub. It is the receipt's `at=` field; the park application instant travels separately as
    `evidence["park_at"]`, and it is the void KEY that binds the receipt to its episode.

    THE SENTENCE IS THE POINT. This receipt states what is actually known — that no cause was ever
    recorded — and explicitly refuses to claim the thing the neighbouring auto-readmission receipt
    claims, that a cause recovered. A receipt is the durable public record of why automation acted,
    and overclaiming here would launder a guess into the taxonomy.

    THE DESTINATION SENTENCE IS DERIVED FROM `evidence["plan"]`, not asserted (review round 2). It
    used to say unconditionally that the PR "returns to `review:needs`", which is FALSE for the
    `strip-only` plan — three of the seven live rows (#4212 #4222 #4318) return to `review:changes`,
    their own pre-park verdict. The harm was only a labelling one (no exit is burned, and
    `review:changes` is the right state), but a false statement in a durable receipt on three live
    PRs is exactly the overclaiming this docstring forbids two paragraphs up."""
    if not isinstance(evidence, dict):
        raise ValueError("a receipt-less void receipt needs the void evidence")
    body = receiptless_void_marker(evidence.get("key"), voided_at,
                                   evidence.get("prover"), evidence.get("prover_at"))
    where = f" on #{pr_number}" if isinstance(pr_number, int) and not isinstance(
        pr_number, bool) else ""
    # The DESTINATION, derived from the plan rather than asserted. An unknown plan says nothing about
    # a destination at all — silence is the honest fallback, and it is the same fail direction the
    # rest of this module takes on an unknown value.
    plan = evidence.get("plan")
    if plan == RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS:
        _where = (f"The park was the ONLY live `review:` label, so the PR returns to "
                  f"`{MACHINE_PARK_PR_LABEL.split(':', 1)[0]}:needs` — which puts it back in the "
                  "review lane's candidate set and census. That is **not** a claim that a review "
                  "has been scheduled.")
    elif plan == RECEIPTLESS_VOID_PLAN_STRIP:
        _where = ("Only the park label is removed, so the PR returns to **the review state it held "
                  "before the park** — its own pre-park verdict, restored rather than replaced. No "
                  "review state is invented, and this is **not** a claim that a review or fix has "
                  "been scheduled.")
    else:
        _where = ("The park label is removed and no review state is written or asserted by this "
                  "receipt.")
    return (
        f"> 🤖 SPARQ agent — VOIDING a receipt-less machine park{where}. **No cause has been "
        "reconstructed, because none was ever recorded.**\n\n"
        f"The `{MACHINE_PARK_PR_LABEL}` on this PR was applied at "
        f"`{canonical_ts(evidence['park_at'])}` by `{evidence.get('prover')}` — an account a "
        "SPARQ agent was operating, proven by that same account's self-identifying comment at "
        f"`{canonical_ts(evidence.get('prover_at'))}`, inside the same operation. No "
        "`sparq-park-reason` receipt of any kind exists for this PR, so **no cause was ever "
        "recorded for this park.**\n\n"
        "That is not a park waiting on a gate that is closed — it is a park waiting on a gate that "
        "cannot be evaluated for it at all: the machine exit reads the cause receipt to learn what "
        "must recover, and there is nothing to read. The park is therefore being voided **for want "
        "of a receipt**, not because anything is known to have recovered. Nothing here asserts why "
        "the PR was parked, and the park comment's prose was not read.\n\n"
        "This exit is one-shot: `RECEIPTLESS_VOID_MAX` is spent for this PR now, and any future "
        f"machine park will carry its own cause receipt and take its own cause-gated exit. {_where}"
        "\n\n"
        f"{body}")


def park_ladder_decision(cutoff, receipts, *, window_authority, already_labeled=False,
                         fingerprint=None, consumed_fingerprints=frozenset(),
                         machine_windows=frozenset()):
    """The ONE label-independent capacity-park escalation ladder (round-3 finding 1), shared
    by the deferred-issue lane (dispatch-claim) and the worker-PR lane (worker-pr needs_user).
    `cutoff` is readmission_cutoff(..., on_unreadable=WINDOW_UNREADABLE); `receipts` is the
    durable bot-authored receipt set (worker-pr park_generation_cutoffs); `already_labeled`
    says whether the machine park label is currently live (COMMENT-DEDUPE input only — the
    generation math never reads it).

    `window_authority` (REQUIRED, keyword-only — WINDOW_AUTHORITY_*) says WHO opened this
    window, and `machine_windows` says which of the ALREADY-RECEIPTED windows the machine
    opened. Both come from readmission_window. It is required and keyword-only ON PURPOSE:
    [registry #797] the live defect was a call site handing over a bare cutoff string with no
    attribution at all, so the loop's own automatic re-admissions were charged to the HUMAN
    escalation ladder and 20 of 21 live escalations paged the maintainer for a re-admission the
    maintainer never made. A default would have let exactly that call site keep compiling.

    Returns (action, window_key, generation):

    - ("freeze", None, None): the timeline was unreadable — no window, no receipt, no label,
      no comment; the ladder never advances on unproven data.
    - ("dedupe", window_key, None): this exact window is already receipted — the park (or the
      terminal escalation) for it was recorded once, honestly; re-defer QUIETLY until a fresh
      human gesture mints a new window key. Dedupe applies to COMMENTS/labels only: the
      generation progression is already durable in the receipts.
    - ("unchanged", window_key, None): a FRESH window, but the exhaustion decision re-derived
      from the SAME per-PR state as an already-receipted park (equal park_fingerprint — same
      head SHA, same attempt counter). Nothing was attempted since that park, so re-emitting
      its terminal verdict is pure noise: skip QUIETLY (a log line, no label, no comment, NO
      generation consumed). See below for why this is what makes readmission mean anything.
    - ("legacy-quiet", None, None): a pre-receipt park (label live, no gesture, no receipts)
      — stay quiet; generation accounting starts with the first receipted window.
    - ("terminal", window_key, generation): PARK_ESCALATION_GENERATIONS HUMAN-CHARGED windows
      consumed — escalate to the question class. The terminal label write must consult the
      sticky veto and the comment must be HONEST when the write was suppressed (never claim a
      label that did not land). Requires a REAL cutoff: the initial PARK_WINDOW_NONE window
      alone can never escalate, and a cutoff that regressed to None cannot prove a fresh
      window. [registry #797] It ALSO requires `window_authority == WINDOW_AUTHORITY_HUMAN`:
      a human question must mean a human is genuinely required, so ONLY a window a PROVEN
      human opened may charge one of these generations, and MACHINE-minted windows are
      excluded from the count of prior ones as well (`machine_windows`) — otherwise the very
      first human re-admission after two of the loop's own would land straight on the terminal.
    - ("machine-terminal", window_key, generation): [registry #797] the MACHINE ladder's own
      exit — PARK_MACHINE_TERMINAL_GENERATIONS machine-minted windows consumed. The machine
      re-admitted this item and it failed again, which establishes that the approach is not
      converging and establishes NOTHING about a human's attention; the caller RETIRES it
      (machine-owned class, worker PR closed, source issue handed back for decomposition)
      instead of paging. Reached by every non-human authority, WINDOW_AUTHORITY_UNKNOWN
      included: an unattributable window may never reach the human terminal, and must still
      terminate.
    - ("park", window_key, generation): consume this window — soft park (veto-gated label,
      best-effort) + the MANDATORY receipt binding window_key.

    IDEMPOTENCE AGAINST AN UNCHANGED HEAD (#555 recurrence gap; live evidence sparq PR #3488
    re-admitted 2026-07-22T16:36:56Z and re-escalated 16:44:10Z — ~7 minutes later, unchanged
    head, no work attempted; PR #3472 re-escalated seconds apart with byte-identical
    boilerplate five days after the last commit or review round on either PR). #555 made the
    park CLASSIFICATION correct and gave the budget a readmission WINDOW, but the ladder
    itself keyed only on the window: a human re-admission mints a BRAND-NEW window key, so
    the very next tick that re-derived exhaustion from unchanged persisted state consumed
    that window immediately and — with the gen-1 receipt already standing — went straight to
    the gen-2 QUESTION-class terminal. The readmission gesture therefore accomplished
    nothing. The fingerprint axis fixes exactly that: a new window can only be CONSUMED by a
    park whose decision inputs actually moved.

    BOUNDED ESCALATION IS PRESERVED (this is why the fingerprint is (head, ATTEMPT-count),
    not the head alone): every path that can re-park without moving the head still moves its
    attempt counter — a re-review consumes a global round number, a no-change fix and a local
    gate failure each add a per-round marker, a missed fix dispatch adds a missed marker — so
    genuinely consumed work always yields a fresh fingerprint, the window is consumed, and
    PARK_ESCALATION_GENERATIONS consumed windows still reach the terminal. Only a tick that
    attempted NOTHING is silenced, and a silenced tick leaves the previous park's receipt (and
    any label a human did not remove) standing.

    The window key is CANONICALIZED here (canonical_ts, round-6 finding 2) — this is the
    value every writer embeds in the receipt marker, so it must be the one deterministic
    space-free spelling receipt readers (park_generation_cutoffs) key on; an exact
    source-string key could carry a space and never round-trip through `cutoff=(...) -->`.
    """
    if cutoff == WINDOW_UNREADABLE:
        return ("freeze", None, None)
    if cutoff:
        try:
            cutoff = canonical_ts(cutoff)
        except ValueError:
            # An unparseable cutoff can mint neither a window key nor a receipt: FREEZE —
            # no receipt, no label, no comment — exactly like an unreadable timeline.
            # readmission_cutoff only returns validated stamps, so this is a defensive
            # rail against a drifted caller, never a live path.
            return ("freeze", None, None)
    window_key = cutoff or PARK_WINDOW_NONE
    if window_key in receipts:
        return ("dedupe", window_key, None)
    # Checked AFTER the window dedupe (which already covers the same-window repeat) and
    # BEFORE any generation is minted: an unchanged-state re-derivation must never advance
    # the ladder, or the escalation bound would be spent on ticks that attempted nothing.
    if fingerprint and fingerprint in consumed_fingerprints:
        return ("unchanged", window_key, None)
    if not cutoff and already_labeled and not receipts:
        return ("legacy-quiet", None, None)
    # [registry #797] TWO LADDERS, ATTRIBUTED. `charged` is the HUMAN ladder's history — the
    # initial PARK_WINDOW_NONE window (never a machine re-admission) plus every window a proven
    # human opened; the machine's own re-admission windows are subtracted out, so they can
    # neither reach the human terminal themselves nor push a later human window onto it.
    charged = {key for key in receipts if key not in machine_windows}
    if not cutoff:
        # The INITIAL full-budget window. No re-admission of any kind happened, so no ladder can
        # escalate on it alone — unchanged from before, and deliberately not attributed.
        return ("park", window_key, len(charged) + 1)
    if window_authority == WINDOW_AUTHORITY_HUMAN and window_key not in machine_windows:
        generation = len(charged) + 1
        if generation >= PARK_ESCALATION_GENERATIONS:
            return ("terminal", window_key, generation)
        return ("park", window_key, generation)
    # MACHINE (or unattributable) window: the machine ladder, whose terminal is a retirement.
    # An UNKNOWN authority has no attribution to count with, so it counts EVERY consumed window
    # — over-counting only makes it retire SOONER, which is the safe direction; under-counting
    # would leave it absorbing (the #764 failure) with no exit at all.
    machine_generation = (len(receipts) + 1 if window_authority == WINDOW_AUTHORITY_UNKNOWN
                          else len(receipts) - len(charged) + 1)
    if machine_generation >= PARK_MACHINE_TERMINAL_GENERATIONS:
        return ("machine-terminal", window_key, machine_generation)
    return ("park", window_key, machine_generation)


def probe_maintainer(repo, login, read_permission, log=print):
    """The shared strict-maintainer probe wrapper (round-3 Opus finding): `read_permission(
    login)` returns the collaborator permission value for `login` on `repo` (None for a clean
    404 "not a collaborator"), RAISING on any probe-call failure (transport error, non-zero
    exit, malformed payload). A raising probe emits ONE distinct loud diagnostic and yields
    False — the fail DIRECTION is unchanged (unverifiable = not human; no veto, no window) —
    while a genuine not-a-maintainer permission stays QUIET (an expected result, not an
    outage). Without the diagnostic, a broken/expired probe token silently degrades every
    human gesture to "not human" with zero operator signal."""
    try:
        permission = read_permission(login)
    except Exception as exc:  # noqa: BLE001 — probe failure = unverifiable = not human
        log(f"::warning::maintainer probe FAILED for {repo} actor={login} "
            f"({type(exc).__name__}) — treating as not-human")
        return False
    return permission in HUMAN_MAINTAINER_PERMISSIONS


def _self_test():
    ok = True

    def attempt(thunk):
        """Evaluate `thunk()` TOTALLY: its value, or ("raised", ExceptionName).

        REPAIR (review finding). Splitting a shared `check` so each predicate case got its own row
        was necessary but NOT sufficient: under the `P-empty-is-permission` mutant the row printed
        its clean named FAIL and the very next call still RAISED, aborting ~106 of 311 checks. The
        mutation sweep counted that as a kill and never noticed that a third of the suite had
        stopped executing — a kill on a suite that is no longer running is not evidence. Every read
        whose mutant can plausibly raise goes through here, so the row reports and the suite
        continues; the sweep now also records checks-executed per mutant so a truncated run is
        visible as a number rather than inferred."""
        try:
            return thunk()
        except Exception as exc:  # noqa: BLE001 — a raising READ must report, never abort
            # A 3-TUPLE, deliberately: callers index [0]/[1]/[2] on an admission answer, and a
            # shorter sentinel would raise AT THE INDEX and abort the suite anyway — re-creating
            # the very truncation this exists to remove, one layer out.
            name = type(exc).__name__
            return ("raised", name, f"raised {name}")

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def event(kind, label, ts, login, via_app=None):
        return {"event": kind, "label": {"name": label},
                "created_at": ts, "actor": {"login": login},
                "performed_via_github_app": via_app}

    # The strict maintainer probe every production site supplies (collaborator permission in
    # HUMAN_MAINTAINER_PERMISSIONS): jeswr is the trusted human; everyone else is not.
    trusted = lambda login: login == "jeswr"  # noqa: E731 — trivial trusted-set stub

    # [registry #797] `window_authority` is a REQUIRED keyword on park_ladder_decision. Every
    # pre-#797 ladder assertion below models a window a PROVEN HUMAN opened — that is what they
    # always meant, because the old ladder had no other kind — so this shim states it once
    # instead of 24 times. The #797 block calls park_ladder_decision DIRECTLY with the machine
    # and unknown authorities, and pins the required-ness itself.
    def ladder(cutoff, receipts, window_authority=WINDOW_AUTHORITY_HUMAN, **kwargs):
        return park_ladder_decision(cutoff, receipts, window_authority=window_authority,
                                    **kwargs)

    bot_park = event("labeled", "needs:user", "2026-07-18T10:00:00Z", "sparq-orchestrator[bot]")
    human_unpark = event("unlabeled", "needs:user", "2026-07-18T11:00:00Z", "jeswr")
    human_repark = event("labeled", "needs:user", "2026-07-18T12:00:00Z", "jeswr")

    # (1) the live incident: bot labeled, human unlabeled LATER -> the veto stands.
    check("bot labeled < human unlabeled => veto",
          human_unpark_veto([bot_park, human_unpark], "needs:user", trusted),
          (True, "human unlabeled needs:user at 2026-07-18T11:00:00Z"))
    # (2) human unlabeled, bot labeled LATER (a fresh application supersedes) -> no veto.
    late_bot = event("labeled", "needs:user", "2026-07-18T11:30:00Z", "sparq-orchestrator[bot]")
    check("human unlabeled < bot labeled => no veto",
          human_unpark_veto([bot_park, human_unpark, late_bot], "needs:user", trusted),
          (False, ""))
    # (3) a human RE-adding the label re-enables automation parking (most-recent-event wins).
    check("human re-add clears the veto",
          human_unpark_veto([bot_park, human_unpark, human_repark], "needs:user", trusted),
          (False, ""))
    # (4) an exact timestamp tie is ambiguous and fails toward NOT parking.
    tie = event("labeled", "needs:user", "2026-07-18T11:00:00Z", "sparq-orchestrator[bot]")
    check("timestamp tie => veto",
          human_unpark_veto([tie, human_unpark], "needs:user", trusted)[0], True)
    # (5) no events / no removal -> no veto.
    check("empty timeline => no veto", human_unpark_veto([], "needs:user", trusted), (False, ""))
    check("labeled only => no veto", human_unpark_veto([bot_park], "needs:user", trusted),
          (False, ""))
    # (6) other labels' events never leak into the decision.
    other = event("unlabeled", "status:parked", "2026-07-18T13:00:00Z", "jeswr")
    check("unrelated label events are ignored",
          human_unpark_veto([bot_park, other], "needs:user", trusted), (False, ""))
    check("machine park label is judged independently",
          human_unpark_veto([bot_park, other], "status:parked", trusted)[0], True)
    # (7) a BOT removal (e.g. the readmission lane clearing its own park) is not a human veto.
    bot_unpark = event("unlabeled", "needs:user", "2026-07-18T11:00:00Z",
                       "sparq-orchestrator[bot]")
    check("bot unlabeled => no veto",
          human_unpark_veto([bot_park, bot_unpark], "needs:user", trusted), (False, ""))
    # (8) UNVERIFIABLE actors mint NO veto (strict maintainer probe — the OPPOSITE of the old
    # missing-actor-counts-as-human rule): a missing actor, a non-maintainer login, an
    # App-driven removal under a maintainer login, and a raising probe are all NOT human.
    ghost = {"event": "unlabeled", "label": {"name": "needs:user"},
             "created_at": "2026-07-18T11:00:00Z", "actor": None}
    check("missing-actor removal => NO veto (unverifiable is not human)",
          human_unpark_veto([bot_park, ghost], "needs:user", trusted)[0], False)
    outsider_unpark = event("unlabeled", "needs:user", "2026-07-18T11:00:00Z", "drive-by")
    check("non-maintainer removal => NO veto",
          human_unpark_veto([bot_park, outsider_unpark], "needs:user", trusted)[0], False)
    app_unpark = event("unlabeled", "needs:user", "2026-07-18T11:00:00Z", "jeswr",
                       via_app={"id": 7, "slug": "registry-app"})
    check("App-driven removal under a maintainer login => NO veto",
          human_unpark_veto([bot_park, app_unpark], "needs:user", trusted)[0], False)

    def raising_probe(_login):
        raise RuntimeError("permission probe unavailable")

    check("probe failure => NO veto (unverifiable is not human)",
          human_unpark_veto([bot_park, human_unpark], "needs:user", raising_probe)[0], False)
    check("absent probe => NO veto (no trusted set = nothing provable)",
          human_unpark_veto([bot_park, human_unpark], "needs:user")[0], False)
    # (9) malformed relevant events RAISE (finding E: a dropped entry could BE the newest human
    # unlabel) — park_vetoed then suppresses the park, latest_human_unlabel keeps the full count.
    for garbage in (None, 7, {"event": "unlabeled", "label": "needs:user"},
                    {"event": "labeled", "label": {"name": "needs:user"}, "created_at": None}):
        try:
            human_unpark_veto([garbage, bot_park, human_unpark], "needs:user", trusted)
            check(f"malformed event raises ({garbage!r})", "no error", "MalformedTimelineError")
        except MalformedTimelineError:
            check(f"malformed event raises ({garbage!r})", "raised", "raised")
    check("a readable OTHER-label event with a broken timestamp stays irrelevant",
          human_unpark_veto(
              [{"event": "unlabeled", "label": {"name": "status:parked"}, "created_at": None},
               bot_park, human_unpark], "needs:user", trusted)[0], True)

    # (10) park_vetoed: a timeline read failure suppresses the park AND logs it (fail open ONLY
    # toward NOT parking).
    logs = []

    def boom(_repo, _number):
        raise RuntimeError("timeline unavailable")

    check("timeline read error => park suppressed",
          park_vetoed("o/r", 5, "status:parked", boom, is_human=trusted, log=logs.append),
          True)
    check("timeline read error is logged loudly",
          any("park suppressed" in line and "timeline read failed" in line for line in logs),
          True)
    # A malformed page/event takes the SAME veto fail direction: suppress the park loudly.
    logs.clear()
    check("malformed timeline => park suppressed",
          park_vetoed("o/r", 5, "needs:user",
                      lambda _r, _n: [bot_park, "garbage-page-entry"],
                      is_human=trusted, log=logs.append), True)
    check("malformed timeline is logged loudly",
          any("park suppressed" in line and "timeline read failed" in line for line in logs),
          True)
    # (11) the veto path logs the exact human-unpark line; the clean path stays quiet.
    logs.clear()
    check("veto => park suppressed",
          park_vetoed("o/r", 5, "needs:user",
                      lambda _r, _n: [bot_park, human_unpark],
                      is_human=trusted, log=logs.append), True)
    check("veto log names the label and timestamp",
          any("park suppressed: human unlabeled needs:user at 2026-07-18T11:00:00Z" in line
              for line in logs), True)
    logs.clear()
    check("no veto => park proceeds",
          park_vetoed("o/r", 5, "needs:user",
                      lambda _r, _n: [bot_park], is_human=trusted, log=logs.append), False)
    check("no veto stays quiet", logs, [])

    # ---- [registry #976] human_hold_deleted_by_machine: the crash-between-delete-and-restore
    # residual. The literal label, logins and stamps below are written OUT rather than derived
    # from the module's own constants: the predicate takes its label as an argument and reads no
    # constant, so a fixture built from HUMAN_PR_PARK_LABEL would only prove the constant equals
    # itself (AGENTS.md pre-flight 2b/2c). The two directions are both pinned — the True rows
    # kill an always-False body, the bot-deletes-bot / restored / unattributable rows kill an
    # always-True one, and the machine_logins pair differs ONLY in that argument.
    lost_bot = "sparq-orchestrator[bot]"
    held = event("labeled", "review:needs-user", "2026-07-28T10:00:00Z", "jeswr")
    drained = event("unlabeled", "review:needs-user", "2026-07-28T10:00:05Z", lost_bot)
    check("human application deleted by the bot, never restored => LOST",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, drained], "review:needs-user", is_human=trusted)),
          (True, "machine unlabeled review:needs-user at 2026-07-28T10:00:05Z, deleting the "
                 "human application at 2026-07-28T10:00:00Z"))
    # The acceptance's named negative: the sweep deleting its OWN application is the normal,
    # correct drain and must never mint a restore.
    check("bot applied, bot deleted => NOT lost (the ordinary drain)",
          attempt(lambda: human_hold_deleted_by_machine(
              [event("labeled", "review:needs-user", "2026-07-28T10:00:00Z", lost_bot), drained],
              "review:needs-user", is_human=trusted)),
          (False, ""))
    check("a later re-application (the in-sweep restore) => NOT lost",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, drained,
               event("labeled", "review:needs-user", "2026-07-28T10:00:09Z", lost_bot)],
              "review:needs-user", is_human=trusted)),
          (False, ""))
    # The re-application rows below are deliberately HUMAN. A bot re-application is
    # VALUE-IDENTICAL under both mutants of this guard (the human-application guard further down
    # answers (False, "") for it anyway, so relaxing `>=` to `>` or deleting the guard outright
    # changes nothing) — measured, both survived. A human re-assertion is the shape that
    # discriminates: without this guard the predicate reports a hold that is LIVE RIGHT NOW as
    # lost, and a reconciler would re-apply a label the maintainer is already holding.
    check("a HUMAN re-application at the SAME instant as the removal is ambiguous => NOT lost",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, drained,
               event("labeled", "review:needs-user", "2026-07-28T10:00:05Z", "jeswr")],
              "review:needs-user", is_human=trusted)),
          (False, ""))
    check("the human re-applying the hold themselves => NOT lost (it is live again)",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, drained,
               event("labeled", "review:needs-user", "2026-07-28T10:00:09Z", "jeswr")],
              "review:needs-user", is_human=trusted)),
          (False, ""))
    # The live shape, and the one that pins LATEST-event selection on both axes: the bot parked
    # it, a maintainer re-asserted the hold on top, the bot drained it. Reading the OLDEST
    # application (a bot) or the OLDEST removal instead of the newest flips every one of these.
    bot_park_first = event("labeled", "review:needs-user", "2026-07-28T09:30:00Z", lost_bot)
    check("bot park, human re-assertion ON TOP, bot drain => LOST (newest application wins)",
          attempt(lambda: human_hold_deleted_by_machine(
              [bot_park_first, held, drained], "review:needs-user", is_human=trusted))[0],
          True)
    check("an EARLIER bot removal does not displace the newest one",
          attempt(lambda: human_hold_deleted_by_machine(
              [event("unlabeled", "review:needs-user", "2026-07-28T09:00:00Z", lost_bot),
               held, drained], "review:needs-user", is_human=trusted))[0],
          True)
    check("an EARLIER HUMAN removal does not excuse the newest bot one",
          attempt(lambda: human_hold_deleted_by_machine(
              [event("unlabeled", "review:needs-user", "2026-07-28T09:00:00Z", "jeswr"),
               bot_park_first, held, drained], "review:needs-user", is_human=trusted))[0],
          True)
    check("the human removing their OWN hold is a gesture, not a loss",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, event("unlabeled", "review:needs-user", "2026-07-28T10:00:05Z", "jeswr")],
              "review:needs-user", is_human=trusted)),
          (False, ""))
    check("a removal with NO application before it proves nothing => NOT lost",
          attempt(lambda: human_hold_deleted_by_machine(
              [drained], "review:needs-user", is_human=trusted)),
          (False, ""))
    check("a hold that is still LIVE (no removal at all) => NOT lost",
          attempt(lambda: human_hold_deleted_by_machine(
              [held], "review:needs-user", is_human=trusted)),
          (False, ""))
    check("an application by a NON-maintainer is not a human gesture => NOT lost",
          attempt(lambda: human_hold_deleted_by_machine(
              [event("labeled", "review:needs-user", "2026-07-28T10:00:00Z", "drive-by"), drained],
              "review:needs-user", is_human=trusted)),
          (False, ""))
    # The deleter must be provably automation, NOT merely "not provably human" — otherwise a
    # maintainer whose collaborator probe simply FAILED has their removal silently undone.
    outsider_drain = event("unlabeled", "review:needs-user", "2026-07-28T10:00:05Z", "drive-by")
    check("an UNATTRIBUTABLE deleter => NOT lost (no machine proof, no restore)",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, outsider_drain], "review:needs-user", is_human=trusted)),
          (False, ""))
    ghost_drain = {"event": "unlabeled", "label": {"name": "review:needs-user"},
                   "created_at": "2026-07-28T10:00:05Z", "actor": None}
    check("a removal with NO actor at all is neither human nor machine => NOT lost",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, ghost_drain], "review:needs-user",
              machine_logins=(lost_bot,), is_human=trusted)),
          (False, ""))
    check("an EMPTY machine_logins entry cannot launder a missing actor into automation",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, ghost_drain], "review:needs-user",
              machine_logins=("",), is_human=trusted)),
          (False, ""))
    check("...the SAME deleter named in machine_logins IS proven automation => LOST",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, outsider_drain], "review:needs-user",
              machine_logins=("Drive-By",), is_human=trusted))[0],
          True)
    check("a machine_logins entry that ALSO passes the human probe stays a human gesture",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, event("unlabeled", "review:needs-user", "2026-07-28T10:00:05Z", "jeswr")],
              "review:needs-user", machine_logins=("jeswr",), is_human=trusted)),
          (False, ""))
    check("an App-driven removal is proven automation without any machine_logins",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, event("unlabeled", "review:needs-user", "2026-07-28T10:00:05Z", "jeswr",
                           via_app={"id": 7, "slug": "registry-app"})],
              "review:needs-user", is_human=trusted))[0],
          True)
    check("events for OTHER labels never mint a loss",
          attempt(lambda: human_hold_deleted_by_machine(
              [event("labeled", "needs:user", "2026-07-28T10:00:00Z", "jeswr"), drained],
              "review:needs-user", is_human=trusted)),
          (False, ""))
    # Fail-closed on unprovable data: an unreadable timeline is ABSORBED to no action here (both
    # of this question's fail directions point the same way), never raised into a caller that
    # might read a spurious restore out of it.
    check("a malformed timeline => NOT lost (never restore on unprovable data)",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, "garbage-page-entry", drained], "review:needs-user", is_human=trusted))[0],
          False)
    check("...and it says WHY, so a caller can log the difference",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, "garbage-page-entry", drained],
              "review:needs-user", is_human=trusted))[1].split(":")[0],
          "timeline unreadable")
    check("an unverifiable PROBE cannot prove the deleted application was human",
          attempt(lambda: human_hold_deleted_by_machine(
              [held, drained], "review:needs-user", is_human=raising_probe)),
          (False, ""))

    # ---- latest_human_unlabel / readmission_cutoff (the budget readmission window,
    # sparq#2804/PR#3442): a proven-human unlabel opens the window; bot / unverifiable /
    # absent / failed reads keep the FULL historical count (None) ----
    timelines = {}

    def fetch(_repo, number):
        events = timelines.get(number)
        if events is None:
            raise RuntimeError("timeline unavailable")
        return events

    timelines[9] = [bot_park, human_unpark]
    check("human unlabel yields its timestamp",
          latest_human_unlabel("o/r", 9, "needs:user", fetch, is_human=trusted),
          "2026-07-18T11:00:00Z")
    later_unpark = event("unlabeled", "needs:user", "2026-07-23T09:18:19Z", "jeswr")
    timelines[9] = [bot_park, human_unpark, later_unpark]
    check("the LATEST human unlabel wins",
          latest_human_unlabel("o/r", 9, "needs:user", fetch, is_human=trusted),
          "2026-07-23T09:18:19Z")
    bot_unpark2 = event("unlabeled", "needs:user", "2026-07-18T11:00:00Z",
                        "sparq-orchestrator[bot]")
    timelines[9] = [bot_park, bot_unpark2]
    check("bot unlabel opens NO window",
          latest_human_unlabel("o/r", 9, "needs:user", fetch, is_human=trusted), None)
    timelines[9] = [bot_park]
    check("no unlabel event => no window",
          latest_human_unlabel("o/r", 9, "needs:user", fetch, is_human=trusted), None)
    # Unverifiable actors open NO budget window (same strict probe as the veto): an unproven
    # actor must never mint a fresh budget.
    timelines[9] = [bot_park, ghost]
    check("unattributed unlabel opens NO budget window",
          latest_human_unlabel("o/r", 9, "needs:user", fetch, is_human=trusted), None)
    timelines[9] = [bot_park, outsider_unpark]
    check("non-maintainer unlabel opens NO budget window",
          latest_human_unlabel("o/r", 9, "needs:user", fetch, is_human=trusted), None)
    timelines[9] = [bot_park, app_unpark]
    check("App-driven unlabel opens NO budget window",
          latest_human_unlabel("o/r", 9, "needs:user", fetch, is_human=trusted), None)
    timelines[9] = [bot_park, event("unlabeled", "status:parked",
                                    "2026-07-18T11:00:00Z", "jeswr")]
    check("other labels' unlabels never leak into the single-label window",
          latest_human_unlabel("o/r", 9, "needs:user", fetch, is_human=trusted), None)
    # A failed timeline read keeps the full count — None — and logs LOUDLY.
    logs.clear()
    check("timeline read error => no window (full count)",
          latest_human_unlabel("o/r", 404, "needs:user", fetch, is_human=trusted,
                               log=logs.append), None)
    check("timeline read error is logged loudly",
          any("readmission window unknown" in line and "timeline read failed" in line
              for line in logs), True)
    # E: a malformed page CONTAINING the newest human unlabel keeps the full count too.
    logs.clear()
    timelines[9] = [bot_park, "malformed-entry", later_unpark]
    check("malformed timeline => no window (full count)",
          latest_human_unlabel("o/r", 9, "needs:user", fetch, is_human=trusted,
                               log=logs.append), None)
    check("malformed timeline is logged loudly",
          any("readmission window unknown" in line for line in logs), True)

    # readmission_cutoff: the LATEST proven-human unlabel of ANY readmission label ACROSS the
    # PR and its source issue.
    timelines[41] = [bot_park, human_unpark]
    timelines[7] = [bot_park, later_unpark]
    check("cutoff takes the latest across PR and issue",
          readmission_cutoff("o/r", 41, 7, fetch, is_human=trusted), "2026-07-23T09:18:19Z")
    timelines[7] = [bot_park]
    check("PR-side unlabel alone still opens the window",
          readmission_cutoff("o/r", 41, 7, fetch, is_human=trusted), "2026-07-18T11:00:00Z")
    check("no linked issue consults only the PR",
          readmission_cutoff("o/r", 41, None, fetch, is_human=trusted), "2026-07-18T11:00:00Z")
    # A(c): the trio — a human unlabel of status:parked OR review:parked opens the window too.
    timelines[41] = [event("labeled", "review:parked", "2026-07-18T10:00:00Z", "b[bot]")]
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-20T08:00:00Z", "jeswr")]
    check("issue-side status:parked unlabel opens the window",
          readmission_cutoff("o/r", 41, 7, fetch, is_human=trusted), "2026-07-20T08:00:00Z")
    timelines[41] = [event("unlabeled", "review:parked", "2026-07-21T08:00:00Z", "jeswr")]
    timelines[7] = [bot_park]
    check("PR-side review:parked unlabel opens the window (latest wins)",
          readmission_cutoff("o/r", 41, 7, fetch, is_human=trusted), "2026-07-21T08:00:00Z")
    # C: a ONE-SIDED timeline read failure returns NO window (the full count) and logs loudly —
    # a surviving side must never mint readmission credit on a partial view.
    logs.clear()
    timelines[41] = [bot_park, human_unpark]
    check("one-sided read failure => NO window (full count)",
          readmission_cutoff("o/r", 41, 404, fetch, is_human=trusted, log=logs.append), None)
    check("one-sided read failure logs loudly",
          any("timeline read failed" in line and "FULL historical count" in line
              for line in logs), True)
    logs.clear()
    check("PR-side read failure => NO window even with a clean issue side",
          readmission_cutoff("o/r", 404, 7, fetch, is_human=trusted, log=logs.append), None)
    check("PR-side read failure logs loudly",
          any("timeline read failed" in line for line in logs), True)
    # E again at the cutoff surface: a malformed page on EITHER side is a read failure.
    timelines[41] = [bot_park, 7, human_unpark]
    timelines[7] = [bot_park]
    check("malformed PR page => NO window",
          readmission_cutoff("o/r", 41, 7, fetch, is_human=trusted, log=logs.append), None)
    timelines[41] = [bot_park]
    check("no human unlabel anywhere => no cutoff",
          readmission_cutoff("o/r", 41, 7, fetch, is_human=trusted), None)

    # ---- capacity_park_readmitted: review:parked still ON the PR, human gesture on either
    # surface re-admits iff it is strictly NEWER than the latest park application ----
    park_applied = event("labeled", "review:parked", "2026-07-22T10:00:00Z", "b[bot]")
    timelines[41] = [park_applied]
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-23T09:00:00Z", "jeswr")]
    check("newer issue-side gesture re-admits a live review:parked",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), True)
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-21T09:00:00Z", "jeswr")]
    check("a gesture OLDER than the park application stays parked",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), False)
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-22T10:00:00Z", "jeswr")]
    check("a timestamp tie stays parked (ambiguity fails toward exclusion)",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), False)
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-23T09:00:00Z",
                          "sparq-orchestrator[bot]")]
    check("a bot gesture never re-admits",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), False)
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-23T09:00:00Z", "jeswr")]
    check("an unreadable side stays parked",
          capacity_park_readmitted("o/r", 41, 404, fetch, is_human=trusted), False)
    # Round-3 finding 2: a CONSUMED (receipted) gesture never re-admits — even when the
    # veto-suppressed label re-apply left no fresh `labeled` event to out-date it.
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-23T09:00:00Z", "jeswr")]
    logs.clear()
    check("a receipted (consumed) gesture never re-admits",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted,
                                   log=logs.append,
                                   consumed={"2026-07-23T09:00:00Z"}), False)
    check("the consumed decline is logged loudly",
          any("already consumed" in line and "FRESH gesture" in line for line in logs), True)
    check("an UNCONSUMED newer gesture still re-admits with receipts present",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted,
                                   consumed={"2026-07-20T00:00:00Z"}), True)
    # A park whose review:parked write was ALWAYS veto-suppressed leaves no `labeled` event;
    # a fresh (unconsumed) gesture still re-admits it, a consumed one still does not.
    timelines[43] = []
    check("no label application ever + fresh gesture => re-admitted",
          capacity_park_readmitted("o/r", 43, 7, fetch, is_human=trusted), True)
    check("no label application ever + consumed gesture => stays parked",
          capacity_park_readmitted("o/r", 43, 7, fetch, is_human=trusted,
                                   consumed={"2026-07-23T09:00:00Z"}), False)
    # ---- Round-5 finding 1: the gesture must out-date the LATEST park application on
    # EITHER surface, over ALL park labels. The exact live failure sequence: receipt -> PR
    # park lands -> maintainer unlabels the PR park -> a LATER source-side status:parked
    # lands -> triage (a bot) removes the source label. The old PR-only review:parked compare
    # accepted the stale gesture; the completed park is NEWER on the source surface => NO
    # readmission.
    timelines[41] = [event("labeled", "review:parked", "2026-07-22T10:00:00Z", "b[bot]"),
                     event("unlabeled", "review:parked", "2026-07-22T12:00:00Z", "jeswr")]
    timelines[7] = [event("labeled", "status:parked", "2026-07-22T14:00:00Z", "b[bot]"),
                    event("unlabeled", "status:parked", "2026-07-22T15:00:00Z",
                          "sparq-orchestrator[bot]")]
    check("round-5 f1: a source park NEWER than the gesture blocks readmission "
          "(PR park -> human unlabel -> later source park -> bot source unlabel)",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), False)
    # The same shape with the gesture NEWER than every application (either surface) re-admits.
    timelines[41] = [event("labeled", "review:parked", "2026-07-22T10:00:00Z", "b[bot]"),
                     event("unlabeled", "review:parked", "2026-07-23T09:00:00Z", "jeswr")]
    check("round-5 f1: a gesture newer than BOTH surfaces' park applications re-admits",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), True)
    # An instant tie between the gesture and the source-side application stays parked.
    timelines[41] = [event("labeled", "review:parked", "2026-07-22T10:00:00Z", "b[bot]"),
                     event("unlabeled", "review:parked", "2026-07-22T14:00:00Z", "jeswr")]
    check("round-5 f1: a gesture tying the source park application stays parked",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), False)
    # A needs:user application on the source AFTER the gesture blocks too (the recency proof
    # spans the same READMISSION_LABELS window the cutoff spans).
    timelines[41] = [event("labeled", "review:parked", "2026-07-22T10:00:00Z", "b[bot]"),
                     event("unlabeled", "review:parked", "2026-07-22T12:00:00Z", "jeswr")]
    timelines[7] = [event("labeled", "needs:user", "2026-07-22T14:00:00Z", "b[bot]")]
    check("round-5 f1: a source needs:user applied after the gesture blocks readmission",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), False)

    # ---- STRICT ISO-8601 timestamps (round-3 finding 3/4): a "not-a-timestamp" relevant
    # event RAISES — it can never be a cutoff, never mint a veto, never loosen the park ----
    check("valid_timestamp accepts real ISO-8601 UTC", valid_timestamp("2026-07-23T09:18:19Z"),
          True)
    for garbage_ts in ("zzz-later-than-everything", "not-a-timestamp", "2026-13-99T99:99:99Z",
                      "", None, 7, "2026-07-23T09:18:19"):  # naive (offset-free) is unorderable
        check(f"valid_timestamp rejects {garbage_ts!r}", valid_timestamp(garbage_ts), False)
    garbage_unlabel = event("unlabeled", "needs:user", "not-a-timestamp", "jeswr")
    try:
        human_unpark_veto([bot_park, garbage_unlabel], "needs:user", trusted)
        check("non-ISO relevant timestamp raises", "no error", "MalformedTimelineError")
    except MalformedTimelineError:
        check("non-ISO relevant timestamp raises", "raised", "raised")
    timelines[9] = [bot_park, garbage_unlabel]
    logs.clear()
    check("a not-a-timestamp event cannot be a cutoff (full count)",
          latest_human_unlabel("o/r", 9, "needs:user", fetch, is_human=trusted,
                               log=logs.append), None)
    check("the malformed-timestamp fallback logs loudly",
          any("readmission window unknown" in line for line in logs), True)
    # a lexicographically-huge garbage stamp on a LABELED event must not dominate the veto
    # comparison either — it raises instead of silently out-dating the human unlabel.
    garbage_label = event("labeled", "needs:user", "zzzz-not-a-timestamp", "b[bot]")
    try:
        human_unpark_veto([bot_park, human_unpark, garbage_label], "needs:user", trusted)
        check("garbage labeled timestamp raises (never out-dates a human)", "no error",
              "MalformedTimelineError")
    except MalformedTimelineError:
        check("garbage labeled timestamp raises (never out-dates a human)", "raised", "raised")

    # ---- Round-5 finding 2: ordering is by PARSED INSTANT (parse_ts), never by raw string.
    # "2026-07-23 10:30:00Z" (space separator) VALIDATES yet sorts lexicographically before
    # "2026-07-23T09:00:00Z"; "+00:00" sorts before the same instant's "Z" spelling. ----
    check("parse_ts: Z and +00:00 spellings are the same instant",
          parse_ts("2026-07-23T09:00:00Z") == parse_ts("2026-07-23T09:00:00+00:00"), True)
    check("parse_ts: a space-separator stamp orders by instant, not by string",
          parse_ts("2026-07-23 10:30:00Z") > parse_ts("2026-07-23T09:00:00Z"), True)
    for bad_ts in ("2026-07-23T09:18:19", "zzz", "", None, 7):
        try:
            parse_ts(bad_ts)
            check(f"parse_ts rejects {bad_ts!r}", "no error", "ValueError")
        except ValueError:
            check(f"parse_ts rejects {bad_ts!r}", "raised", "raised")
    # A space-separator human unlabel LATER by instant must veto even though it sorts
    # lexicographically BEFORE the labeled stamp (the old string compare read it as older).
    check("round-5 f2: space-separator later unlabel still vetoes",
          human_unpark_veto(
              [event("labeled", "needs:user", "2026-07-23T09:00:00Z", "b[bot]"),
               event("unlabeled", "needs:user", "2026-07-23 10:30:00Z", "jeswr")],
              "needs:user", trusted)[0], True)
    # A +00:00-spelled unlabel tying a Z-spelled application is an instant TIE => veto stands
    # (the old string compare read "+00:00" < "Z" and dropped the tie protection).
    check("round-5 f2: +00:00 vs Z same-instant tie still vetoes",
          human_unpark_veto(
              [event("labeled", "needs:user", "2026-07-23T09:00:00Z", "b[bot]"),
               event("unlabeled", "needs:user", "2026-07-23T09:00:00+00:00", "jeswr")],
              "needs:user", trusted)[0], True)
    # The cutoff picks the latest INSTANT across spellings and returns the CANONICAL spelling
    # (round-6 finding 2: the old exact-source-string return could carry a space and never
    # round-trip through the receipt marker).
    timelines[41] = [event("unlabeled", "needs:user", "2026-07-23T09:00:00Z", "jeswr")]
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-23 10:30:00Z", "jeswr")]
    check("round-5 f2 + round-6 f2: the cutoff picks the latest instant across spellings "
          "and returns it CANONICALIZED",
          readmission_cutoff("o/r", 41, 7, fetch, is_human=trusted), "2026-07-23T10:30:00Z")
    # A space-separator gesture AFTER the park application re-admits (string compare said no).
    timelines[41] = [event("labeled", "review:parked", "2026-07-23T09:00:00Z", "b[bot]")]
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-23 10:30:00Z", "jeswr")]
    check("round-5 f2: a space-separator gesture after the park re-admits",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), True)
    # A +00:00 gesture tying the Z-spelled park application is NOT strictly newer => parked.
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-23T09:00:00+00:00", "jeswr")]
    check("round-5 f2: a +00:00 vs Z same-instant gesture stays parked",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), False)

    # ---- Round-6 finding 2: window-key identity is the CANONICAL spelling (canonical_ts).
    # A space-form cutoff written raw into a receipt (`cutoff=2026-07-23 10:30:00Z -->`)
    # never matched the reader's `cutoff=(\S+) -->`, so the gen-1 receipt was invisible:
    # never deduped, gen-2 never reachable. Canonical form: compact Z, T separator, UTC. ----
    check("round-6 f2: canonical_ts normalizes the space-form spelling",
          canonical_ts("2026-07-23 10:30:00Z"), "2026-07-23T10:30:00Z")
    check("round-6 f2: canonical_ts normalizes the +00:00 spelling",
          canonical_ts("2026-07-23T10:30:00+00:00"), "2026-07-23T10:30:00Z")
    check("round-6 f2: canonical_ts renders a non-UTC offset in UTC",
          canonical_ts("2026-07-23T11:30:00+01:00"), "2026-07-23T10:30:00Z")
    check("round-6 f2: canonical_ts is idempotent on the canonical form",
          canonical_ts(canonical_ts("2026-07-23 10:30:00Z")), "2026-07-23T10:30:00Z")
    check("round-6 f2: the canonical form carries no whitespace",
          " " in canonical_ts("2026-07-23 10:30:00.500Z"), False)
    for bad_canonical in ("2026-07-23T09:18:19", "zzz", "", None, 7):
        try:
            canonical_ts(bad_canonical)
            check(f"canonical_ts rejects {bad_canonical!r}", "no error", "ValueError")
        except ValueError:
            check(f"canonical_ts rejects {bad_canonical!r}", "raised", "raised")
    # A space-form gesture whose CANONICAL key is already receipted was consumed: it must
    # not re-admit (cross-spelling receipt membership — the round-trip that used to fail).
    timelines[41] = [event("labeled", "review:parked", "2026-07-23T09:00:00Z", "b[bot]")]
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-23 10:30:00Z", "jeswr")]
    check("round-6 f2: a space-form gesture already receipted under its canonical key "
          "stays parked",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted,
                                   consumed={"2026-07-23T10:30:00Z"}), False)
    check("round-6 f2: the same space-form gesture unreceipted still re-admits",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted,
                                   consumed=set()), True)

    # ---- Round-7 finding 1: a stamp that PASSES parsing but OVERFLOWS UTC normalization
    # ("0001-01-01T00:00:00+23:59" — astimezone subtracts the offset under year 1) must raise
    # ValueError, never OverflowError: every malformed-timestamp handler (freeze /
    # receipt-absent / event-cannot-prove) keys on ValueError/valid_timestamp, and an
    # OverflowError escaping them crashed the sweep. ----
    for overflow_ts in ("0001-01-01T00:00:00+23:59",   # underflows datetime.min in UTC
                        "9999-12-31T23:59:59-23:59"):  # overflows datetime.max in UTC
        for name, fn in (("canonical_ts", canonical_ts), ("parse_ts", parse_ts)):
            try:
                fn(overflow_ts)
                check(f"round-7 f1: {name} raises ValueError on {overflow_ts!r}",
                      "no error", "ValueError")
            except ValueError:
                check(f"round-7 f1: {name} raises ValueError on {overflow_ts!r}",
                      "ValueError", "ValueError")
            except OverflowError:
                check(f"round-7 f1: {name} raises ValueError on {overflow_ts!r}",
                      "OverflowError", "ValueError")
        check(f"round-7 f1: valid_timestamp rejects {overflow_ts!r}",
              valid_timestamp(overflow_ts), False)
    # As a relevant EVENT timestamp reaching readmission_cutoff: the malformed-event
    # direction applies unchanged (MalformedTimelineError -> the per-surface read-failure
    # handler -> full historical count, loud log) — the sweep never crashes.
    logs.clear()
    timelines[41] = [event("unlabeled", "needs:user", "0001-01-01T00:00:00+23:59", "jeswr")]
    timelines[7] = [bot_park]
    check("round-7 f1: an overflow event timestamp takes the malformed-event direction "
          "(full count, no crash)",
          readmission_cutoff("o/r", 41, 7, fetch, is_human=trusted, log=logs.append), None)
    check("round-7 f1: the overflow-event fallback logs loudly",
          any("timeline read failed" in line for line in logs), True)
    check("round-7 f1: the ladder caller sees WINDOW_UNREADABLE (freeze), not a crash",
          readmission_cutoff("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                             on_unreadable=WINDOW_UNREADABLE), WINDOW_UNREADABLE)
    check("round-7 f1: park_vetoed suppresses the park on an overflow event timestamp",
          park_vetoed("o/r", 41, "needs:user",
                      lambda _r, n: timelines[n], is_human=trusted, log=logs.append), True)
    # An overflow cutoff handed straight to the ladder freezes on the defensive rail —
    # it can mint neither a window key nor a receipt.
    check("round-7 f1: an overflow cutoff freezes the ladder",
          ladder("0001-01-01T00:00:00+23:59", set()), ("freeze", None, None))

    # ---- readmission_cutoff on_unreadable: the ladder can DISTINGUISH windowless from
    # unreadable; default callers keep the plain None => full-count path ----
    timelines[41] = [bot_park, human_unpark]
    check("on_unreadable sentinel returned on a failed read",
          readmission_cutoff("o/r", 41, 404, fetch, is_human=trusted, log=logs.append,
                             on_unreadable=WINDOW_UNREADABLE), WINDOW_UNREADABLE)
    check("readable windowless timeline still returns None with on_unreadable set",
          readmission_cutoff("o/r", 41, None, fetch, is_human=trusted,
                             labels=("status:parked",),
                             on_unreadable=WINDOW_UNREADABLE), None)

    # ---- park_ladder_decision: the ONE receipts-driven escalation ladder ----
    check("ladder: unreadable timeline freezes",
          ladder(WINDOW_UNREADABLE, set()), ("freeze", None, None))
    check("ladder: initial park consumes the PARK_WINDOW_NONE window as generation 1",
          ladder(None, set()), ("park", PARK_WINDOW_NONE, 1))
    check("ladder: the initial window re-fires quietly once receipted",
          ladder(None, {PARK_WINDOW_NONE}), ("dedupe", PARK_WINDOW_NONE, None))
    check("ladder: legacy pre-receipt park stays quiet (no receipt minted)",
          ladder(None, set(), already_labeled=True),
          ("legacy-quiet", None, None))
    check("ladder: a fresh gesture window after the initial receipt is TERMINAL at gen 2",
          ladder("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE}),
          ("terminal", "2026-07-23T09:18:19Z", 2))
    check("ladder: a fresh gesture window with NO prior receipts parks as generation 1",
          ladder("2026-07-23T09:18:19Z", set()),
          ("park", "2026-07-23T09:18:19Z", 1))
    check("ladder: an already-receipted gesture window dedupes (comments), never advances",
          ladder("2026-07-23T09:18:19Z", {"2026-07-23T09:18:19Z"}),
          ("dedupe", "2026-07-23T09:18:19Z", None))
    check("ladder: a cutoff regressed to None can NEVER escalate past prior receipts",
          ladder(None, {"2026-07-21T08:00:00Z"}),
          ("park", PARK_WINDOW_NONE, 2))
    check("ladder: already_labeled never suppresses a due receipt once a window exists",
          ladder("2026-07-23T09:18:19Z", set(), already_labeled=True),
          ("park", "2026-07-23T09:18:19Z", 1))
    # Round-6 finding 2: the ladder CANONICALIZES the window key it hands to every receipt
    # writer — a space-form cutoff mints the compact Z-form key (writable + round-trippable),
    # dedupes against its canonical receipt, and escalates on the canonical identity.
    check("ladder round-6 f2: a space-form cutoff mints the CANONICAL window key",
          ladder("2026-07-23 10:30:00Z", set()),
          ("park", "2026-07-23T10:30:00Z", 1))
    check("ladder round-6 f2: a space-form cutoff dedupes against its canonical receipt",
          ladder("2026-07-23 10:30:00Z", {"2026-07-23T10:30:00Z"}),
          ("dedupe", "2026-07-23T10:30:00Z", None))
    check("ladder round-6 f2: a space-form cutoff reaches the gen-2 terminal",
          ladder("2026-07-23 10:30:00Z", {PARK_WINDOW_NONE}),
          ("terminal", "2026-07-23T10:30:00Z", 2))
    check("ladder round-6 f2: an unparseable cutoff freezes (defensive rail — it can mint "
          "neither a window key nor a receipt)",
          ladder("not-a-timestamp", set()), ("freeze", None, None))

    # ---- park_fingerprint + the UNCHANGED-HEAD idempotence axis (#555 recurrence gap).
    # THE DEFECT: a human readmission mints a BRAND-NEW window key, so the next tick that
    # re-derived exhaustion from unchanged persisted state consumed that window immediately and
    # — with the gen-1 receipt standing — jumped to the gen-2 question-class terminal. Live:
    # sparq PR #3488 re-admitted 2026-07-22T16:36:56Z, re-escalated 16:44:10Z (~7 min, unchanged
    # head); PR #3472 seconds later with byte-identical boilerplate. ----
    head = "a" * 40
    check("fingerprint: head + monotone attempt counter",
          park_fingerprint(head, "rounds=5"), f"{head}/rounds=5")
    check("fingerprint: an unknown head claims NO idempotence (pre-fix behaviour)",
          park_fingerprint("", "rounds=5"), None)
    check("fingerprint: an unknown attempt counter claims NO idempotence",
          park_fingerprint(head, ""), None)
    check("fingerprint: a marker-breaking component is rejected, never smuggled into a receipt",
          (park_fingerprint(head, "rounds=5 -->"), park_fingerprint("a b", "rounds=5")),
          (None, None))
    consumed = {f"{head}/rounds=5"}
    # (a) THE BOUNCE: a fresh readmission window whose exhaustion re-derives the SAME
    # fingerprint is NOT consumed — quiet skip, no generation, no terminal.
    check("(a) ladder: a fresh window + an unchanged fingerprint is skipped QUIETLY (the "
          "#3488 bounce), never consumed",
          ladder("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE},
                               fingerprint=f"{head}/rounds=5",
                               consumed_fingerprints=consumed),
          ("unchanged", "2026-07-23T09:18:19Z", None))
    # (b) the head ADVANCED => real work was attempted => the window is consumed normally.
    check("(b) ladder: an advanced head consumes the fresh window (gen-2 terminal at the "
          "configured bound)",
          ladder("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE},
                               fingerprint=f"{'b' * 40}/rounds=5",
                               consumed_fingerprints=consumed),
          ("terminal", "2026-07-23T09:18:19Z", 2))
    # (b') the head did NOT move but the ATTEMPT COUNTER did (a re-review on the same head, a
    # no-change fix, a failed local gate, another missed dispatch): genuinely consumed work, so
    # the window IS consumed — this is what keeps the escalation bound reachable.
    check("(b') ladder: an advanced attempt counter on an UNCHANGED head still consumes the "
          "window (bounded escalation survives)",
          ladder("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE},
                               fingerprint=f"{head}/rounds=6",
                               consumed_fingerprints=consumed),
          ("terminal", "2026-07-23T09:18:19Z", 2))
    check("ladder: the FIRST park always lands — no receipted fingerprint can match",
          ladder(None, set(), fingerprint=f"{head}/rounds=5",
                               consumed_fingerprints=frozenset()),
          ("park", PARK_WINDOW_NONE, 1))
    check("ladder: a legacy receipt (no fingerprint recorded) claims no idempotence",
          ladder("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE},
                               fingerprint=f"{head}/rounds=5",
                               consumed_fingerprints=frozenset()),
          ("terminal", "2026-07-23T09:18:19Z", 2))
    check("ladder: an unknown fingerprint (None) can never suppress a due park",
          ladder("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE},
                               fingerprint=None, consumed_fingerprints=consumed),
          ("terminal", "2026-07-23T09:18:19Z", 2))
    # Precedence: the window dedupe (already receipted) and the freeze (unproven timeline)
    # both outrank the fingerprint check — an unchanged fingerprint must never turn a frozen
    # or already-receipted decision into a different action.
    check("ladder: the same-window dedupe still wins over the fingerprint check",
          ladder("2026-07-23T09:18:19Z", {"2026-07-23T09:18:19Z"},
                               fingerprint=f"{head}/rounds=5",
                               consumed_fingerprints=consumed),
          ("dedupe", "2026-07-23T09:18:19Z", None))
    check("ladder: an unreadable timeline still FREEZES ahead of the fingerprint check",
          ladder(WINDOW_UNREADABLE, {PARK_WINDOW_NONE},
                               fingerprint=f"{head}/rounds=5",
                               consumed_fingerprints=consumed),
          ("freeze", None, None))
    # (d) THE BOUND STILL TERMINATES. Walk the ladder from nothing, alternating a GENUINELY
    # consumed window (the fingerprint moved: real work was attempted) with an UNCHANGED-state
    # re-derivation of the same window's exhaustion (the bounce). The unchanged ticks must be
    # invisible to the ladder — they neither advance nor block it — and after
    # PARK_ESCALATION_GENERATIONS consumed windows the ladder is TERMINAL and stays terminal.
    # Asserted against the CONSTANT, never a hard-coded 2.
    ladder_receipts, ladder_consumed = set(), set()
    real_actions, bounce_actions = [], []
    for step in range(1, PARK_ESCALATION_GENERATIONS + 2):
        window = f"2026-07-23T{step:02d}:00:00Z"
        fingerprint = f"{head}/r={step}"
        action, key, _generation = ladder(
            window, ladder_receipts, fingerprint=fingerprint,
            consumed_fingerprints=ladder_consumed)
        real_actions.append(action)
        ladder_receipts.add(key)
        ladder_consumed.add(fingerprint)
        # ... the very next tick re-derives the SAME exhaustion from the SAME state under a
        # BRAND-NEW readmission window (a human just re-admitted): the #3488 bounce.
        bounce_actions.append(ladder(
            f"2026-07-24T{step:02d}:00:00Z", ladder_receipts, fingerprint=fingerprint,
            consumed_fingerprints=ladder_consumed)[0])
    check("(d) genuinely consumed windows climb the ladder to the configured TERMINAL and "
          "stay there",
          real_actions,
          ["park"] * (PARK_ESCALATION_GENERATIONS - 1) + ["terminal", "terminal"])
    check("(d) an unchanged-state re-derivation NEVER advances the ladder at any generation "
          "(the bound is spent only on work actually attempted)",
          bounce_actions, ["unchanged"] * (PARK_ESCALATION_GENERATIONS + 1))

    # ---- [registry #797] THE GENERATION COUNTER IS ATTRIBUTED: a MACHINE re-admission may not
    # charge a HUMAN generation, and may never reach the human-owned terminal.
    #
    # THE LIVE DEFECT, verbatim from sparq PR #4422: gen=1 cutoff=none (the initial window), then
    # an automatic re-admission receipted `at=2026-07-27T08:02:21Z`, then gen=2 with a cutoff
    # BYTE-IDENTICAL to that auto stamp and a comment reading "This PR was human-readmitted and
    # exhausted its budget again ... @jeswr this pull request needs a human decision". No human
    # touched it: all 73 live applications of review:needs-user across the 35 held PRs were made
    # by sparq-orchestrator[bot], and 20 of the 21 PRs carrying generation receipts had escalated
    # on a machine-minted window (the other is a genuine injection escalation, #3743). ----
    auto_stamp = "2026-07-27T08:02:21Z"
    human_stamp = "2026-07-27T12:00:00Z"
    machine_only = frozenset({auto_stamp})
    # (i) THE HEADLINE GUARD. The exact #4422 state — the initial window receipted, and this
    # window opened by the loop's OWN automatic re-admission. It must NOT be the human terminal.
    check("#797 (i): the MACHINE's own re-admission window can NEVER reach the human terminal "
          "(the #4422 false page)",
          park_ladder_decision(auto_stamp, {PARK_WINDOW_NONE},
                               window_authority=WINDOW_AUTHORITY_MACHINE,
                               machine_windows=machine_only)[0] != "terminal", True)
    check("#797 (i): ...it stays in the MACHINE class as that ladder's generation 1 — the "
          "machine re-admitted once, so it still owns the outcome",
          park_ladder_decision(auto_stamp, {PARK_WINDOW_NONE},
                               window_authority=WINDOW_AUTHORITY_MACHINE,
                               machine_windows=machine_only),
          ("park", auto_stamp, 1))
    # (i') #3595's real history: BOTH receipted windows are the loop's own auto stamps. The
    # machine has now spent its AUTO_READMISSION_MAX chances, so THIS is where it gives up —
    # on the machine terminal, still not on the maintainer's desk.
    second_auto = "2026-07-26T14:50:59Z"
    check("#797 (i'): a SECOND machine window exhausts the MACHINE ladder and RETIRES (#3595), "
          "never pages",
          park_ladder_decision(second_auto, {PARK_WINDOW_NONE, auto_stamp},
                               window_authority=WINDOW_AUTHORITY_MACHINE,
                               machine_windows=frozenset({auto_stamp, second_auto})),
          ("machine-terminal", second_auto, PARK_MACHINE_TERMINAL_GENERATIONS))
    # (ii) THE MIRROR. The SAME receipt history under a GENUINE human re-admission still reaches
    # the human terminal — the protection this ladder exists for is preserved, not removed.
    check("#797 (ii): a GENUINE human re-admission on the same history still escalates to the "
          "human terminal",
          park_ladder_decision(human_stamp, {PARK_WINDOW_NONE},
                               window_authority=WINDOW_AUTHORITY_HUMAN,
                               machine_windows=machine_only),
          ("terminal", human_stamp, PARK_ESCALATION_GENERATIONS))
    # (iii) MACHINE WINDOWS ARE SUBTRACTED FROM THE HUMAN COUNT. #3595's real history: BOTH
    # receipted windows are auto stamps. The maintainer's FIRST actual re-admission must get a
    # full human generation-1 window, not inherit two the machine spent on its own behalf.
    check("#797 (iii): a human's first re-admission after two MACHINE windows gets generation 1, "
          "not the machine's inherited count (#3595)",
          park_ladder_decision(human_stamp, {auto_stamp, "2026-07-26T14:50:59Z"},
                               window_authority=WINDOW_AUTHORITY_HUMAN,
                               machine_windows=frozenset({auto_stamp,
                                                          "2026-07-26T14:50:59Z"})),
          ("park", human_stamp, 1))
    # (iv) THE MACHINE LADDER STILL TERMINATES, and does so BOUNDED BY THE CONSTANT. Walk it
    # from nothing with machine-only windows: the first machine window parks, and the
    # PARK_MACHINE_TERMINAL_GENERATIONS-th retires. Asserted against the constant, never a 2.
    machine_receipts, machine_actions = {PARK_WINDOW_NONE}, []
    for step in range(1, PARK_MACHINE_TERMINAL_GENERATIONS + 2):
        window = f"2026-07-28T{step:02d}:00:00Z"
        seen = frozenset(key for key in machine_receipts if key != PARK_WINDOW_NONE) | {window}
        action, key, _generation = park_ladder_decision(
            window, machine_receipts, window_authority=WINDOW_AUTHORITY_MACHINE,
            machine_windows=seen)
        machine_actions.append(action)
        machine_receipts.add(key)
    check("#797 (iv): the MACHINE ladder terminates at PARK_MACHINE_TERMINAL_GENERATIONS and "
          "stays there — a machine park is never absorbing",
          machine_actions,
          ["park"] * (PARK_MACHINE_TERMINAL_GENERATIONS - 1)
          + ["machine-terminal"] * 2)
    # (v) UNATTRIBUTABLE IS NOT HUMAN — and still terminates. A caller that cannot attribute its
    # window must not be able to page anyone, and must not land in an absorbing state either.
    check("#797 (v): an UNATTRIBUTABLE window never reaches the human terminal",
          park_ladder_decision(human_stamp, {PARK_WINDOW_NONE},
                               window_authority=WINDOW_AUTHORITY_UNKNOWN)[0],
          "machine-terminal")
    # (vi) THE ARGUMENT IS REQUIRED. This is what stops a future call site re-introducing the
    # defect by simply not attributing its window: there is no default to fall back to.
    try:
        park_ladder_decision(human_stamp, {PARK_WINDOW_NONE})
        required = "NO ERROR"
    except TypeError as exc:
        required = "window_authority" in str(exc)
    check("#797 (vi): park_ladder_decision REFUSES to decide without an attributed window",
          required, True)
    # (vii) THE INITIAL WINDOW IS UNCHANGED under every authority: no re-admission of any kind
    # happened, so it parks as generation 1 and can escalate nowhere.
    check("#797 (vii): the initial no-cutoff window is authority-independent",
          {authority: park_ladder_decision(None, set(), window_authority=authority)
           for authority in (WINDOW_AUTHORITY_HUMAN, WINDOW_AUTHORITY_MACHINE,
                             WINDOW_AUTHORITY_UNKNOWN)},
          {WINDOW_AUTHORITY_HUMAN: ("park", PARK_WINDOW_NONE, 1),
           WINDOW_AUTHORITY_MACHINE: ("park", PARK_WINDOW_NONE, 1),
           WINDOW_AUTHORITY_UNKNOWN: ("park", PARK_WINDOW_NONE, 1)})

    # ---- [registry #797] readmission_window: the ATTRIBUTION itself ----
    check("#797 window: a human gesture newer than every auto stamp is HUMAN-authorised",
          readmission_window(human_stamp, [auto_stamp]),
          {"cutoff": human_stamp, "authority": WINDOW_AUTHORITY_HUMAN,
           "machine_windows": machine_only})
    check("#797 window: an auto stamp newer than the human gesture is MACHINE-authorised",
          readmission_window("2026-07-26T00:00:00Z", [auto_stamp]),
          {"cutoff": auto_stamp, "authority": WINDOW_AUTHORITY_MACHINE,
           "machine_windows": machine_only})
    check("#797 window: an auto re-admission with NO human gesture at all is MACHINE-authorised "
          "(the whole live population)",
          readmission_window(None, [auto_stamp]),
          {"cutoff": auto_stamp, "authority": WINDOW_AUTHORITY_MACHINE,
           "machine_windows": machine_only})
    check("#797 window: a TIE resolves to MACHINE — an auto stamp at the same instant is a "
          "sufficient explanation, so the human's intent is not PROVEN",
          readmission_window(auto_stamp, [auto_stamp])["authority"],
          WINDOW_AUTHORITY_MACHINE)
    check("#797 window: an EQUIVALENT space-form spelling still ties to MACHINE (canonical "
          "identity, round-6 finding 2)",
          readmission_window("2026-07-27 08:02:21Z", [auto_stamp])["authority"],
          WINDOW_AUTHORITY_MACHINE)
    check("#797 window: no gesture of any kind is UNKNOWN, never human",
          readmission_window(None, []),
          {"cutoff": None, "authority": WINDOW_AUTHORITY_UNKNOWN,
           "machine_windows": frozenset()})
    check("#797 window: an unreadable timeline is contagious AND unattributable",
          readmission_window(WINDOW_UNREADABLE, [auto_stamp]),
          {"cutoff": WINDOW_UNREADABLE, "authority": WINDOW_AUTHORITY_UNKNOWN,
           "machine_windows": frozenset()})
    logs.clear()
    check("#797 window: a malformed auto stamp is dropped loudly and cannot mint a window",
          (readmission_window(None, ["zzz"], log=logs.append), len(logs)), (
              {"cutoff": None, "authority": WINDOW_AUTHORITY_UNKNOWN,
               "machine_windows": frozenset()}, 1))
    check("#797 window: effective_readmission_cutoff is the same decision, cutoff-only (the "
          "budget view and the ladder view can never disagree)",
          [effective_readmission_cutoff(h, a) == readmission_window(h, a)["cutoff"]
           for h, a in ((human_stamp, [auto_stamp]), (None, [auto_stamp]), (None, []),
                        (WINDOW_UNREADABLE, [auto_stamp]), ("2026-07-25 01:00:00Z", []))],
          [True] * 5)

    # ---- [registry #797] retirement_handback: the SOURCE ISSUE half of a machine retirement ----
    check("#797 handback: an impl-route issue is handed to architect decomposition",
          retirement_handback(["area:engine", "role:impl", "status:parked"])[:2],
          ("reroute", ["area:engine", "role:research", "status:parked"]))
    check("#797 handback: an issue already off the impl route is requeued, never re-rerouted",
          retirement_handback(["area:engine", "role:research"])[:2],
          ("requeue", ["area:engine", "role:research"]))
    check("#797 handback: a HUMAN-held source issue is not touched at all",
          [retirement_handback(["role:impl", hold])[:2]
           for hold in ("needs:user", "needs:external-audit", HUMAN_PR_PARK_LABEL)],
          [("hold", None)] * 3)

    # ---- capacity_park_admission: AUTOMATIC re-admission of a MACHINE park on proven
    # cause-recovery (invariant 3, registry #614). THE DEFECT: a machine-owned park could only
    # ever be cleared by a HUMAN gesture, so the acct01 credential outage (#596) parked
    # registry PRs #587/#590/#585/#593 + issues #574/#577/#582/#572 and 6 sparq PRs that the
    # credential fix could NOT recover — every one needed a hand-unlabel. ----
    machine_park = event("labeled", "review:parked", "2026-07-25T02:19:47Z",
                         "sparq-orchestrator[bot]")
    machine_park_issue = event("labeled", "status:parked", "2026-07-25T02:19:49Z",
                               "sparq-orchestrator[bot]")

    def evidence_at(key, stamp):
        """A recovery-evidence probe that answers only when the recovery is after the park."""
        def probe(parked_at):
            probe.seen.append(parked_at)
            return {"key": key, "recovered_at": stamp}
        probe.seen = []
        return probe

    timelines[41], timelines[7] = [machine_park], [machine_park_issue]
    # (a) a machine capacity park + a recorded success on the same account STRICTLY AFTER the
    # park => automatically re-admitted, exactly once, consuming that evidence.
    recovery = evidence_at("openai/dc2d7519aaaa0001/6041.1", "2026-07-25T03:10:00Z")
    logs.clear()
    check("(a) machine park + post-park success => auto-mint, carrying the recovery identity "
          "the caller must receipt",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                                  auto_evidence=recovery)[:2],
          ("auto-mint", {"key": "openai/dc2d7519aaaa0001/6041.1",
                         "at": "2026-07-25T03:10:00Z"}))
    check("(a) the probe is asked about the LATEST park application (either surface)",
          recovery.seen, ["2026-07-25T02:19:49Z"])
    # (b) the SAME evidence a second time (its receipt now stands) is NOT re-admitted — the
    # receipt was consumed exactly once and cannot be re-earned. The receipt's own stamp is
    # OLDER than a NEWER park application here, so the "auto-receipt" branch cannot admit it
    # either: a fresh park needs a fresh outage-and-recovery pair.
    consumed_receipt = [{"key": "openai/dc2d7519aaaa0001/6041.1", "at": "2026-07-25T03:10:00Z"}]
    timelines[41] = [machine_park, event("labeled", "review:parked", "2026-07-25T04:00:00Z",
                                         "sparq-orchestrator[bot]")]
    logs.clear()
    action_b = capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                                       auto_receipts=consumed_receipt,
                                       auto_evidence=evidence_at(
                                           "openai/dc2d7519aaaa0001/6041.1",
                                           "2026-07-25T03:10:00Z"))
    check("(b) the SAME recovery evidence never re-admits twice", action_b[0], None)
    check("(b) the consumed-evidence decline names a NEW outage-and-recovery pair",
          any("already consumed" in line and "NEW outage-and-recovery pair" in line
              for line in logs), True)
    # ... and the consume-once rule holds on EVIDENCE IDENTITY, not merely on recency: the same
    # recovery event RE-STAMPED later (a rewritten/forged ledger record reusing one run identity to
    # spring the park again) clears the strictly-after-the-park test and is STILL refused.
    logs.clear()
    check("(b) a RE-STAMPED replay of consumed evidence is refused on identity alone",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                                  auto_receipts=consumed_receipt,
                                  auto_evidence=evidence_at(
                                      "openai/dc2d7519aaaa0001/6041.1",
                                      "2026-07-25T05:00:00Z")),
          (None, None,
           "recovery evidence 'openai/dc2d7519aaaa0001/6041.1' already consumed"))
    check("(b) the re-stamped replay is logged loudly",
          any("already consumed" in line for line in logs), True)
    check("(b) a DIFFERENT recovery event after that same park is a fresh pair and admits",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  auto_receipts=consumed_receipt,
                                  auto_evidence=evidence_at(
                                      "openai/dc2d7519aaaa0001/6099.1",
                                      "2026-07-25T05:00:00Z"))[0], "auto-mint")
    # ... while the receipt DOES keep proving the re-admission it already granted, for as long
    # as no NEWER park application supersedes it (the idempotent converge path the CLAIM proof
    # gate and a crashed label write both need).
    timelines[41] = [machine_park]
    check("(b') an unsuperseded automatic receipt keeps proving its own re-admission",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  auto_receipts=consumed_receipt)[0], "auto-receipt")
    # (c) NO post-park success => stays parked.
    check("(c) no recorded recovery => stays parked",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  auto_evidence=lambda _parked_at: None),
          (None, None, "no recorded recovery of the park's starvation cause"))
    check("(c') a success NOT strictly after the park application => stays parked",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T02:19:49Z"))[0],
          None)
    check("(c'') a pre-park success => stays parked",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T01:00:00Z"))[0],
          None)
    # (d) an UNREADABLE / ambiguous health record (the probe raises, or answers malformed) and an
    # unreadable park timeline all stay parked.
    logs.clear()

    def raising_evidence(_parked_at):
        raise RuntimeError("model-health ledger unreadable")

    check("(d) an unreadable health record => stays parked",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                                  auto_evidence=raising_evidence)[0], None)
    check("(d) the unreadable health read is logged loudly",
          any("recovery-evidence probe failed" in line for line in logs), True)
    for ambiguous in ({"key": "openai/a/1", "recovered_at": "not-a-timestamp"},
                      {"key": "openai/a 1", "recovered_at": "2026-07-25T03:10:00Z"},
                      {"key": "openai/a/1 -->", "recovered_at": "2026-07-25T03:10:00Z"},
                      {"key": None, "recovered_at": "2026-07-25T03:10:00Z"},
                      {"recovered_at": "2026-07-25T03:10:00Z"}, "garbage"):
        check(f"(d) ambiguous evidence {ambiguous!r} => stays parked",
              capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                                      auto_evidence=lambda _p, e=ambiguous: e)[0], None)
    check("(d) an unreadable park timeline => stays parked",
          capacity_park_admission("o/r", 41, 404, fetch, is_human=trusted, log=logs.append,
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T03:10:00Z")),
          (None, None, "the park application timeline could not be read"))
    # (e) a HUMAN-OWNED hold is NEVER auto-re-admitted — neither a live human label nor a park
    # a PROVEN HUMAN applied.
    check("(e) a live needs:user is never auto-re-admitted",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  live_holds=["needs:user"],
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T03:10:00Z"))[0], None)
    check("(e) a live review:needs-user is never auto-re-admitted",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  live_holds=["review:needs-user", "area:x"],
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T03:10:00Z"))[0], None)
    check("(e) ANY needs:* hold (the review lane's own rule) blocks the automatic path",
          [capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                   live_holds=["area:x", hold],
                                   auto_evidence=evidence_at("openai/a/1",
                                                             "2026-07-25T03:10:00Z"))[0]
           for hold in ("needs:user", "needs:decision", "needs:ec2")], [None] * 3)
    check("(e) an ordinary machine label is NOT a human hold (the path still works)",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  live_holds=["review:parked", "status:parked", "area:x"],
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T03:10:00Z"))[0],
          "auto-mint")
    check("(e) even an already-receipted automatic re-admission cannot clear a human hold",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  live_holds=["needs:user"],
                                  auto_receipts=consumed_receipt)[0], None)
    # (e2) OWNERSHIP IS TWO FACTS ABOUT THE PARK: THE LABEL THE ACTOR CHOSE, AND THE BOT'S OWN
    # CLASSIFICATION OF THE EPISODE. Neither alone is enough — see the module header and
    # human_park_capacity_proof for the measured reason the second gate exists.
    #
    # `admit` supplies the capacity receipt by default so these rows isolate the OWNERSHIP axis;
    # the receipt axis gets its own block below, where the default is overridden explicitly.
    capacity_receipt = ({"class": PARK_CLASS_CAPACITY, "cause": "budget",
                         "gen": None, "head": None},)
    # The default INSTANCE attestation: written by the actor that applies the human park in these
    # fixtures ("jeswr"), one second before it — the receipt-first ordering the real reconcile
    # script uses. Supplied by default so the (e2)/(e3) rows isolate their own axis; the (e4)
    # block below overrides it explicitly.
    park_attestation = ({"login": "jeswr", "at": "2026-07-25T02:19:46Z"},)

    def admit(**kwargs):
        # TOTAL by construction (review repair, round 2). Wrapping only the PREDICATE reads was
        # again not enough: under the `R-absence-is-permission` mutant the ADMISSION raised an
        # IndexError from a non-mutated line and aborted 114 of 324 checks, and the sweep scored
        # that as a kill. Every read a mutant can make raise now reports instead of terminating.
        kwargs.setdefault("reason_records", capacity_receipt)
        kwargs.setdefault("attestations", park_attestation)
        return attempt(lambda: capacity_park_admission(
            "o/r", 41, 7, fetch, is_human=trusted, **kwargs))

    # (e2) THE OWNERSHIP SIGNAL IS THE LABEL THE ACTOR CHOSE, NOT THE ACTOR'S IDENTITY.
    #
    # A proven human applying the HUMAN-OWNED terminal `needs:user` is a question no machine may
    # answer, and still refuses. A proven human applying a MACHINE-OWNED soft hold
    # (`review:parked` / `status:parked`) selected the label whose own description promises
    # "human unlabel, proven recovery, or capped retry", and is now evaluated on that promise —
    # keying on the actor made a human-applied `review:parked` unrecoverable BY CONSTRUCTION
    # (7 live sparq PRs, 2026-07-28; see park_application_view).
    #
    # Every fixture below enters through the REAL parser: `fetch` -> _event_rows -> the
    # production walk. Nothing hand-builds a view object.
    human_pr_park = event("labeled", "review:parked", "2026-07-25T02:19:47Z", "jeswr")
    human_terminal_park = event("labeled", "needs:user", "2026-07-25T02:19:47Z", "jeswr")
    timelines[41] = [human_pr_park]
    timelines[7] = []
    logs.clear()
    check("(e2) a MAINTAINER-applied review:parked is evaluated on recovery, not refused",
          admit(log=logs.append, auto_evidence=evidence_at("openai/a/1", "2026-07-25T03:10:00Z")),
          ("auto-mint", {"key": "openai/a/1", "at": "2026-07-25T03:10:00Z"},
           "recovery evidence 'openai/a/1' recorded at 2026-07-25T03:10:00Z, strictly after the "
           "park application at 2026-07-25T02:19:47Z"))
    check("(e2) the human-applied MACHINE park is announced, never silent",
          any("human-applied MACHINE park on o/r#41" in line
              and "review:parked at 2026-07-25T02:19:47Z" in line for line in logs), True)
    # A human park on the SOURCE issue reads the same way — the proof spans both surfaces.
    timelines[41] = [machine_park]
    timelines[7] = [event("labeled", "status:parked", "2026-07-25T02:30:00Z", "jeswr")]
    check("(e2) a source-side MAINTAINER-applied status:parked is evaluated too",
          admit(attestations=({"login": "jeswr", "at": "2026-07-25T02:29:59Z"},),
                auto_evidence=evidence_at("openai/a/1", "2026-07-25T03:10:00Z"))[0],
          "auto-mint")
    # THE PRESERVED GUARD. The human terminal is still terminal, on EITHER surface, and the
    # refusal now NAMES the label so a reader can tell the two states apart.
    timelines[41] = [human_terminal_park]
    timelines[7] = []
    check("(e2) a MAINTAINER-applied needs:user is STILL only clearable by a human",
          admit(auto_evidence=evidence_at("openai/a/1", "2026-07-25T03:10:00Z")),
          (None, None, "the latest park application is the HUMAN-owned terminal "
                       "(needs:user) — only a human clears it"))
    timelines[41] = [machine_park]
    timelines[7] = [event("labeled", "needs:user", "2026-07-25T02:30:00Z", "jeswr")]
    check("(e2) a source-side MAINTAINER-applied needs:user is STILL terminal",
          admit(auto_evidence=evidence_at("openai/a/1", "2026-07-25T03:10:00Z"))[0], None)
    # TIES. The tie resolution is unchanged (human wins), but WHICH human labels tied now decides:
    # a human `needs:user` sharing the instant with a machine park still refuses, while a human
    # MACHINE-owned park sharing the instant with another machine park proceeds. The set test is a
    # POSITIVE subset proof, so a human terminal in the tie set can never be outvoted.
    timelines[41] = [human_terminal_park,
                     event("labeled", "review:parked", "2026-07-25T02:19:47Z",
                           "sparq-orchestrator[bot]")]
    timelines[7] = []
    check("(e2) a tie whose HUMAN label is the terminal still refuses",
          admit(auto_evidence=evidence_at("openai/a/1", "2026-07-25T03:10:00Z"))[0], None)
    timelines[41] = [human_pr_park, human_terminal_park]
    check("(e2) a tie where the human applied BOTH refuses (the terminal is not outvoted)",
          admit(auto_evidence=evidence_at("openai/a/1", "2026-07-25T03:10:00Z")),
          (None, None, "the latest park application is the HUMAN-owned terminal "
                       "(needs:user/review:parked) — only a human clears it"))
    timelines[41] = [human_pr_park,
                     event("labeled", "status:parked", "2026-07-25T02:19:47Z",
                           "sparq-orchestrator[bot]")]
    check("(e2) a tie whose HUMAN label is machine-owned proceeds",
          admit(auto_evidence=evidence_at("openai/a/1", "2026-07-25T03:10:00Z"))[0],
          "auto-mint")
    # ORDER AND SCOPE. A human-applied MACHINE park unlocks NOTHING else: the live human-hold
    # refusal still runs FIRST, the recovery must still be STRICTLY after the application, and the
    # per-PR cap still applies. These are the gates whose removal the change could plausibly have
    # been mistaken for.
    timelines[41] = [human_pr_park]
    timelines[7] = []
    check("(e2) a human-applied MACHINE park + a LIVE needs:user still refuses (hold first)",
          admit(live_holds=["needs:user"], auto_evidence=evidence_at("openai/a/1", "2026-07-25T03:10:00Z"))[0], None)
    check("(e2) a human-applied MACHINE park still needs recovery STRICTLY after it",
          admit(auto_evidence=evidence_at("openai/a/1", "2026-07-25T02:19:47Z")),
          (None, None, "the recovery at 2026-07-25T02:19:47Z is not STRICTLY after the park "
                       "application at 2026-07-25T02:19:47Z"))
    check("(e2) a human-applied MACHINE park is still capped by AUTO_READMISSION_MAX",
          admit(log=logs.append, auto_marker_count=AUTO_READMISSION_MAX, auto_evidence=evidence_at("openai/a/1", "2026-07-25T03:10:00Z"))[0], None)
    # park_application_view reports WHICH labels the human applied — the value the admission
    # branches on — and reports NO labels when the latest application was a machine's.
    check("(e2) park_application_view names the human-applied label AND its actor",
          park_application_view("o/r", 41, 7, fetch, is_human=trusted)[1:4],
          (True, ("review:parked",), ("jeswr",)))
    timelines[41] = [machine_park]
    check("(e2) park_application_view attributes NO label and NO actor to a machine park",
          park_application_view("o/r", 41, 7, fetch, is_human=trusted)[1:4],
          (False, (), ()))
    check("(e2) an unreadable surface yields no attribution at all",
          park_application_view("o/r", 41, 404, fetch, is_human=trusted,
                                log=logs.append), (None, False, (), (), None, False))
    # park_applications MUST stay exactly park_application_view's projection. Nothing in production
    # reads the projection's `latest_was_human` element today (capacity_park_readmitted and groom
    # both discard it), so without this the element could silently drift to a constant — measured:
    # a `return latest, False, readable` mutant survived the whole suite before this check existed.
    for surface, note in ((human_pr_park, "a human-applied park"),
                          (machine_park, "a machine-applied park")):
        timelines[41] = [surface]
        timelines[7] = []
        view = park_application_view("o/r", 41, 7, fetch, is_human=trusted)
        check(f"(e2) park_applications is exactly the view's projection for {note}",
              park_applications("o/r", 41, 7, fetch, is_human=trusted),
              (view[0], view[1], view[5]))
    check("(e2) ...and the MACHINE-applied case reports human=False (not vacuous)",
          park_applications("o/r", 41, 7, fetch, is_human=trusted)[1], False)
    timelines[41] = [human_pr_park]
    check("(e2) ...while the human-applied case reports human=True",
          park_applications("o/r", 41, 7, fetch, is_human=trusted)[1], True)
    # human_park_is_machine_owned DIRECTLY — the two branches production data cannot reach, which
    # would otherwise be untestable claims. Both must read as NOT machine-owned (refuse).
    # Every call goes through `attempt` so a mutant that makes the read RAISE still reports its row
    # and lets the remaining ~106 checks run (see attempt()).
    check("(e2) predicate: not-human is never machine-owned (guard order is not load-bearing)",
          attempt(lambda: human_park_is_machine_owned(False, ("review:parked",))), False)
    # Two SEPARATE checks, not one list: a combined list dies on the first raise and never reports
    # the second case (measured — mutant P-empty-is-permission).
    check("(e2) predicate: a human park with NO attributed label is NOT permission",
          attempt(lambda: human_park_is_machine_owned(True, ())), False)
    check("(e2) predicate: an ABSENT attribution is NOT permission either",
          attempt(lambda: human_park_is_machine_owned(True, None)), False)
    check("(e2) predicate: every MACHINE-owned park label is accepted, alone and together",
          [attempt(lambda: human_park_is_machine_owned(True, (MACHINE_PARK_PR_LABEL,))),
           attempt(lambda: human_park_is_machine_owned(True, (MACHINE_PARK_LABEL,))),
           attempt(lambda: human_park_is_machine_owned(
               True, (MACHINE_PARK_LABEL, MACHINE_PARK_PR_LABEL)))],
          [True, True, True])
    check("(e2) predicate: the human terminal is rejected, alone and mixed in",
          [attempt(lambda: human_park_is_machine_owned(True, (HUMAN_PARK_LABEL,))),
           attempt(lambda: human_park_is_machine_owned(
               True, (HUMAN_PARK_LABEL, MACHINE_PARK_PR_LABEL)))],
          [False, False])
    check("(e2) predicate: a label the taxonomy does not name refuses (POSITIVE proof set)",
          attempt(lambda: human_park_is_machine_owned(
              True, ("review:parked", "needs:some-future-hold"))), False)
    # ...and the taxonomy itself: MACHINE_OWNED_PARK_LABELS must be the machine subset of
    # READMISSION_LABELS, no more and no less. A drifted membership is the one way every check
    # above could pass while the decision was wrong.
    # ---- (e4) THE THIRD GATE: the record must be ABOUT THIS PARK, not about the PR -----------
    #
    # THE CONSTRUCTED GENERAL CASE review used to fail round 2, reproduced here as the first row:
    # a PR bot-capacity-parked long ago, then hand-parked today. The class proof is satisfied
    # forever and monotonically, so without an instance binding EVERY such PR is permanently immune
    # to a hand-applied hold.
    old_bot_park = event("labeled", "review:parked", "2026-07-08T02:19:47Z",
                         "sparq-orchestrator[bot]")
    todays_human_park = event("labeled", "review:parked", "2026-07-27T19:23:59Z", "jeswr")
    timelines[41] = [old_bot_park, todays_human_park]
    timelines[7] = []
    stale_attestation = ({"login": "jeswr", "at": "2026-07-08T02:19:46Z"},)
    bound_attestation = ({"login": "jeswr", "at": "2026-07-27T19:23:58Z"},)
    late_evidence = evidence_at("openai/a/2", "2026-07-27T20:30:00Z")
    check("(e4) THE CONSTRUCTED CASE: a hand-applied hold on a PR that was EVER bot-capacity-"
          "parked is refused — no attestation binds the class to THIS park",
          admit(attestations=(), auto_evidence=late_evidence),
          (None, None,
           "a human applied the machine soft hold and the bot's own park-reason receipt "
           "classifies this park episode as class=capacity cause=budget, but no park-"
           "misescalation attestation by the actor that applied this park falls inside this "
           "park's window — the capacity classification is about the PR's history, not about "
           "this park application"))
    check("(e4) ...and it is censused as HUMAN-TERMINAL under its OWN code, distinguishable from "
          "\"never classified\"",
          (lambda rows: [(row["code"], row["exit"]) for row in rows])(
              (lambda out: (admit(attestations=(), auto_evidence=late_evidence, census=out),
                            out)[1])([])),
          [(PARK_REFUSAL_HUMAN_APPLIED_UNBOUND, "human-terminal")])
    check("(e4) an attestation from the CLOSED earlier episode does not re-enter",
          admit(attestations=stale_attestation, auto_evidence=late_evidence)[0], None)
    check("(e4) an attestation inside THIS park's window admits",
          admit(attestations=bound_attestation, auto_evidence=late_evidence)[0], "auto-mint")
    check("(e4) an attestation by a DIFFERENT actor than the one that applied the park is ignored",
          admit(attestations=({"login": "drive-by", "at": "2026-07-27T19:23:58Z"},),
                auto_evidence=late_evidence)[0], None)
    check("(e4) an attestation written AFTER the park it claims to justify is ignored "
          "(receipt-first ordering is the rule, not decoration)",
          admit(attestations=({"login": "jeswr", "at": "2026-07-27T19:24:30Z"},),
                auto_evidence=late_evidence)[0], None)
    check("(e4) an attestation AT the park instant is inside the window (<=, not <)",
          admit(attestations=({"login": "jeswr", "at": "2026-07-27T19:23:59Z"},),
                auto_evidence=late_evidence)[0], "auto-mint")
    check("(e4) an attestation AT the PREVIOUS park instant is OUTSIDE it (<=, not <)",
          admit(attestations=({"login": "jeswr", "at": "2026-07-08T02:19:47Z"},),
                auto_evidence=late_evidence)[0], None)
    check("(e4) a malformed/unparseable attestation stamp can never bind an instance",
          [admit(attestations=({"login": "jeswr", "at": "zzz"},),
                 auto_evidence=late_evidence)[0],
           admit(attestations=({"login": "jeswr"},), auto_evidence=late_evidence)[0],
           admit(attestations=("garbage",), auto_evidence=late_evidence)[0]],
          [None, None, None])
    # The predicate DIRECTLY, through `attempt`, including the branches production cannot reach.
    check("(e4) predicate: an unknown park instant binds nothing",
          attempt(lambda: park_instance_attested(bound_attestation, None, None, ("jeswr",))[0]),
          False)
    # ASSERTED ON THE DETAIL, not only the action. Deleting the `if not applying` early exit is an
    # EQUIVALENT MUTANT on the action axis — with an empty `applying` set every attestation is
    # skipped by the login test and the function returns False anyway — and it SURVIVED a sweep
    # that only read [0]. The two states are different operator remedies ("nobody can be shown to
    # have applied this park" vs "no attestation falls in its window"), so the detail is the thing
    # that must not drift, and asserting it is what makes the guard non-vacuous.
    check("(e4) predicate: an unattributable applying actor binds nothing, and SAYS SO",
          [attempt(lambda: park_instance_attested(
              bound_attestation, parse_ts("2026-07-27T19:23:59Z"), None, ())),
           attempt(lambda: park_instance_attested(
               bound_attestation, parse_ts("2026-07-27T19:23:59Z"), None, ("",)))],
          [(False, "the actor that applied this park is unattributable, so no attestation can "
                   "be bound to it")] * 2)
    check("(e4) predicate: with NO earlier park there is no lower bound, so any earlier "
          "attestation by the applying actor binds",
          attempt(lambda: park_instance_attested(
              stale_attestation, parse_ts("2026-07-27T19:23:59Z"), None, ("jeswr",))[0]), True)
    check("(e4) the attestation vocabulary is a LIST every member of which is read (so adding "
          "#956's conflict-park marker is one line, not a re-derivation)",
          [len(reconcile_attestations([
              {"user": {"login": "u"}, "created_at": "2026-07-27T19:23:58Z",
               "body": f"x\n\n{marker} pr=1 -->"}]))
           for marker, _owner in PARK_RECONCILE_ATTESTATIONS],
          [1] * len(PARK_RECONCILE_ATTESTATIONS))
    check("(e4) a marker OUTSIDE the vocabulary attests nothing (conservative direction)",
          reconcile_attestations([
              {"user": {"login": "u"}, "created_at": "2026-07-27T19:23:58Z",
               "body": "x\n\n<!-- sparq-some-other-reconciled:v1 pr=1 -->"}]), [])
    # THE MULTI-SURFACE BURST — the shape that actually occurs, and the one my first binding got
    # WRONG. The park writer applies the PAIR in one operation: attestation, then `review:parked`
    # on the PR, then `status:parked` on the source issue, seconds apart. Taking the second-newest
    # WRITE as the lower bound made the writer's own PR-side half look like a closed earlier
    # episode; the SWEEP (which reads both surfaces) then refused every PR while a PR-only check
    # passed. Live instants from sparq #4375.
    timelines[41] = [event("labeled", "review:parked", "2026-07-27T00:00:19Z",
                           "sparq-orchestrator[bot]"),
                     event("labeled", "review:parked", "2026-07-27T19:23:59Z", "jeswr")]
    timelines[7] = [event("labeled", "status:parked", "2026-07-27T19:24:02Z", "jeswr")]
    burst_attestation = ({"login": "jeswr", "at": "2026-07-27T19:23:58Z"},)
    check("(e4) the park PAIR written across BOTH surfaces by one actor is ONE application — its "
          "own attestation is not excluded by its own second half",
          admit(attestations=burst_attestation,
                auto_evidence=evidence_at("openai/a/3", "2026-07-27T21:00:00Z"))[0], "auto-mint")
    check("(e4) ...and the lower bound is the newest FOREIGN application, so a stale attestation "
          "from before the bot's earlier park still cannot re-enter",
          admit(attestations=({"login": "jeswr", "at": "2026-07-27T00:00:18Z"},),
                auto_evidence=evidence_at("openai/a/3", "2026-07-27T21:00:00Z"))[0], None)
    check("(e4) a FOREIGN application landing between the attestation and this park excludes it "
          "(somebody else parked in between: a new episode)",
          (lambda: (timelines.__setitem__(41, [
              event("labeled", "review:parked", "2026-07-27T19:23:59Z", "jeswr"),
              event("labeled", "review:parked", "2026-07-27T19:24:00Z",
                    "sparq-orchestrator[bot]"),
              event("labeled", "review:parked", "2026-07-27T19:24:05Z", "jeswr")]),
                    timelines.__setitem__(7, []),
                    admit(attestations=burst_attestation,
                          auto_evidence=evidence_at("openai/a/3", "2026-07-27T21:00:00Z"))[0])[-1])(),
          None)
    # A BURST ACROSS DIFFERENT PRs cannot cross-bind by construction: attestations are read from
    # THIS PR's own comments and the window is THIS PR's own timeline. Pinned because the live
    # parks arrived in scripted bursts (three PRs inside 17 seconds), which is exactly where a
    # time-window binding would have matched the wrong park.
    timelines[41] = [event("labeled", "review:parked", "2026-07-27T19:23:59Z", "jeswr")]
    timelines[7] = []
    check("(e4) on a human/machine TIE the bound is relative to the HUMAN applier, so that "
          "machine's earlier park still closes the window (narrower, not wider)",
          (lambda: (timelines.__setitem__(41, [
              event("labeled", "review:parked", "2026-07-27T00:00:19Z",
                    "sparq-orchestrator[bot]"),
              event("labeled", "review:parked", "2026-07-27T19:23:59Z", "jeswr"),
              event("labeled", "status:parked", "2026-07-27T19:23:59Z",
                    "sparq-orchestrator[bot]")]),
                    timelines.__setitem__(7, []),
                    admit(attestations=({"login": "jeswr", "at": "2026-07-27T00:00:18Z"},),
                          auto_evidence=evidence_at("openai/a/3",
                                                    "2026-07-27T21:00:00Z"))[0])[-1])(),
          None)
    timelines[41] = [event("labeled", "review:parked", "2026-07-27T19:23:59Z", "jeswr")]
    timelines[7] = []
    check("(e4) a sibling PR's attestation, 1s away in the same burst, binds NOTHING here",
          admit(attestations=(), auto_evidence=evidence_at("openai/a/3",
                                                           "2026-07-27T21:00:00Z"))[0], None)
    # TWO MUTANTS SURVIVED the round-3 catalogue and both were real test gaps, not equivalences.
    #
    # (i) `at_latest = list(rows)` — collecting the human attribution across EVERY application
    # rather than only those at the latest instant. Invisible until an EARLIER application carries
    # a different human label: here the same actor applied the human terminal first and the machine
    # soft hold later, so the mutant drags `needs:user` into human_labels and refuses.
    timelines[41] = [event("labeled", "needs:user", "2026-07-26T09:00:00Z", "jeswr"),
                     event("labeled", "review:parked", "2026-07-27T19:23:59Z", "jeswr")]
    timelines[7] = []
    check("(e4) only the applications AT the latest instant attribute it — an earlier "
          "human `needs:user` on the same PR does not make today's machine park terminal",
          admit(attestations=({"login": "jeswr", "at": "2026-07-27T19:23:58Z"},),
                auto_evidence=evidence_at("openai/a/4", "2026-07-27T21:00:00Z"))[0], "auto-mint")
    # (ii) `previous = min(foreign)` — the OLDEST foreign application instead of the newest.
    # Invisible with one foreign application; with two, an attestation between them must be
    # EXCLUDED (it predates the newer foreign park, so it belongs to a closed episode).
    timelines[41] = [event("labeled", "review:parked", "2026-07-20T01:00:00Z",
                           "sparq-orchestrator[bot]"),
                     event("labeled", "review:parked", "2026-07-26T01:00:00Z",
                           "sparq-orchestrator[bot]"),
                     event("labeled", "review:parked", "2026-07-27T19:23:59Z", "jeswr")]
    check("(e4) the lower bound is the NEWEST foreign application, not the oldest: an "
          "attestation predating a LATER foreign park belongs to a closed episode",
          admit(attestations=({"login": "jeswr", "at": "2026-07-22T01:00:00Z"},),
                auto_evidence=evidence_at("openai/a/4", "2026-07-27T21:00:00Z"))[0], None)
    check("(e4) ...while one after the newest foreign park still binds",
          admit(attestations=({"login": "jeswr", "at": "2026-07-27T19:23:58Z"},),
                auto_evidence=evidence_at("openai/a/4", "2026-07-27T21:00:00Z"))[0], "auto-mint")
    timelines[41] = [event("labeled", "review:parked", "2026-07-27T19:23:59Z", "jeswr")]
    timelines[7] = []
    check("(e4) reconcile_attestations reads the marker the SCRIPT writes, with its author",
          reconcile_attestations([
              {"user": {"login": "jeswr"}, "created_at": "2026-07-27T19:23:58Z",
               "body": f"audit\n\n{RECONCILE_MARKER} pr=4375 window=x -->"},
              {"user": {"login": "jeswr"}, "created_at": "2026-07-27T19:00:00Z",
               "body": "an ordinary comment"},
              "malformed"]),
          [{"login": "jeswr", "at": "2026-07-27T19:23:58Z"}])
    # LIVE SHAPE, end to end through the real reader: #4375's actual marker and actual instants.
    check("(e4) the LIVE sparq #4375 shape (bot park 2026-07-27T00:00:19Z, hand park 19:23:59Z, "
          "attestation 19:23:58Z) binds; deleting the attestation refuses",
          [admit(attestations=reconcile_attestations([
              {"user": {"login": "jeswr"}, "created_at": "2026-07-27T19:23:58Z",
               "body": f"x\n\n{RECONCILE_MARKER} pr=4375 window=2026-07-27T06:03:10Z -->"}]),
              auto_evidence=late_evidence)[0],
           admit(attestations=reconcile_attestations([]), auto_evidence=late_evidence)[0]],
          ["auto-mint", None])
    timelines[41] = [human_pr_park]
    timelines[7] = []

    # ---- (e3) THE SECOND GATE: the bot's own capacity classification of the episode -----------
    #
    # The measured hole in the first cut of this change. `admit`'s default receipt is overridden
    # explicitly in every row here, so each one isolates the RECEIPT axis with ownership already
    # satisfied (timelines[41] is still the human-applied review:parked).
    timelines[41] = [human_pr_park]
    timelines[7] = []
    fresh_evidence = evidence_at("openai/a/1", "2026-07-25T03:10:00Z")

    def receipt(cause, park_class=None):
        return {"class": park_class or park_cause_class(cause), "cause": cause,
                "gen": None, "head": None}

    check("(e3) NO bot receipt => a human-applied machine park is NOT admitted",
          admit(reason_records=(), auto_evidence=fresh_evidence),
          (None, None, "a human applied the machine soft hold, but no bot park-reason receipt "
                       "exists, so nothing ever classified this park as capacity — a human "
                       "applied it and the machine has no opinion"))
    unclassified_census = []
    admit(reason_records=(), auto_evidence=fresh_evidence, census=unclassified_census)
    check("(e3) ...and it is censused as HUMAN-TERMINAL, not as a capacity refusal",
          [(row["code"], row["exit"]) for row in unclassified_census],
          [(PARK_REFUSAL_HUMAN_APPLIED_UNCLASSIFIED, "human-terminal")])
    check("(e3) a QUESTION-class receipt ANYWHERE refuses, even with a NEWER capacity receipt",
          admit(reason_records=(receipt("injection"), receipt("budget")),
                auto_evidence=fresh_evidence)[0], None)
    check("(e3) ...and the refusal NAMES the disqualifying cause (order-independent deny)",
          "injection" in admit(reason_records=(receipt("injection"), receipt("budget")),
                               auto_evidence=fresh_evidence)[2], True)
    check("(e3) every CAPACITY cause in the closed taxonomy admits",
          [admit(reason_records=(receipt(cause),), auto_evidence=fresh_evidence)[0]
           for cause, klass in sorted(PARK_CAUSES.items()) if klass == PARK_CLASS_CAPACITY],
          ["auto-mint"] * sum(1 for k in PARK_CAUSES.values() if k == PARK_CLASS_CAPACITY))
    check("(e3) every QUESTION cause in the closed taxonomy refuses",
          sorted({admit(reason_records=(receipt(cause),), auto_evidence=fresh_evidence)[0]
                  for cause, klass in PARK_CAUSES.items() if klass == PARK_CLASS_QUESTION},
                 key=str), [None])
    check("(e3) a receipt whose class is not the capacity CONSTANT refuses (no truthiness, and "
          "case matters)",
          [admit(reason_records=(receipt("budget", park_class="Capacity"),),
                 auto_evidence=fresh_evidence)[0],
           admit(reason_records=({"cause": "budget", "gen": None, "head": None},),
                 auto_evidence=fresh_evidence)[0]], [None, None])
    check("(e3) a malformed (non-dict) receipt is not a receipt",
          [admit(reason_records=("budget",), auto_evidence=fresh_evidence)[0],
           admit(reason_records=(None,), auto_evidence=fresh_evidence)[0]], [None, None])
    # THE BOT PATH IS BYTE-FOR-BYTE UNCHANGED: a machine-applied park never consults the receipt
    # gate at all, so no legacy capacity park loses the #691 exit to this change.
    timelines[41] = [machine_park]
    check("(e3) a MACHINE-applied park is admitted with NO receipt (the bot path is untouched)",
          admit(reason_records=(), auto_evidence=fresh_evidence)[0], "auto-mint")
    check("(e3) ...and is equally admitted with a QUESTION receipt (gate is human-branch only)",
          admit(reason_records=(receipt("injection"),), auto_evidence=fresh_evidence)[0],
          "auto-mint")
    # human_park_capacity_proof DIRECTLY, through `attempt` so a raising mutant still reports.
    check("(e3) proof predicate: absence is not permission",
          [attempt(lambda: human_park_capacity_proof(())[0]),
           attempt(lambda: human_park_capacity_proof(None)[0]),
           attempt(lambda: human_park_capacity_proof(("garbage",))[0])], [False, False, False])
    check("(e3) proof predicate: a lone capacity receipt proves it",
          attempt(lambda: human_park_capacity_proof((receipt("budget"),))[0]), True)
    check("(e3) proof predicate: deny is order-independent in BOTH orders",
          [attempt(lambda: human_park_capacity_proof(
              (receipt("budget"), receipt("injection")))[0]),
           attempt(lambda: human_park_capacity_proof(
               (receipt("injection"), receipt("budget")))[0])], [False, False])

    # ---- (e5) [registry #1309] THE RECEIPT-LESS PARK CLASS AND ITS ONE-SHOT VOID EXIT ---------
    #
    # THE POPULATION, measured on sparq-org/sparq 2026-07-29 over the paginated LIST endpoint (44
    # rows — not a round number, so not a cap — and every receipt count cross-checked against raw
    # comment bodies rather than inferred): 44 open PRs carry `review:parked`; 29 carry ZERO bot
    # park-reason receipts; 14 of those had the park applied by `jeswr`/User, and 10 of the 14 carry
    # no human-terminal hold. Those 10 reached NO predicate in this tree and were permanent.
    #
    # The self-ID window is NOT a permissive filter, and that was measured too rather than assumed:
    # 34 of the 44 PRs carry MORE THAN ONE qualifying self-ID from the parking actor, and on 27 of
    # them the SECOND-closest candidate is outside the window (next-nearest deltas −100s, +6417s,
    # +13775s). The window rejects; the population simply narrates every park within seconds.
    #
    # Every fixture below is a REAL shape from that population, entering through the REAL parser.
    receiptless_park_at = "2026-07-26T18:34:32Z"    # sparq #4197: the real park application
    receiptless_self_id = "2026-07-26T18:34:30Z"    # ...and its real self-ID, 2 seconds earlier
    receiptless_void = "receiptless-void/2026-07-26T18:34:32Z"
    receiptless_park = event("labeled", "review:parked", receiptless_park_at, "jeswr")
    orchestrator_self_id = ({"login": "jeswr", "at": receiptless_self_id},)
    # A recovery that WOULD admit if the void path fell through to it — so every row below that
    # expects a refusal is refusing on its own gate, not on a missing probe.
    post_park_evidence = evidence_at("openai/a/9", "2026-07-27T00:00:00Z")

    def void_admit(**kwargs):
        kwargs.setdefault("reason_records", ())          # the receipt-less population, by definition
        kwargs.setdefault("self_id_rows", orchestrator_self_id)
        kwargs.setdefault("void_offered", True)
        # [B1] The park is the only live review:* label unless a row says otherwise, so these rows
        # isolate their own axis; the LABEL-PLAN axis gets its own block below.
        kwargs.setdefault("pr_review_labels", [MACHINE_PARK_PR_LABEL])
        return admit(**kwargs)

    timelines[41] = [receiptless_park]
    timelines[7] = []
    logs.clear()
    # THE HEADLINE GUARD. The live #4197 shape earns the void, and the evidence is exactly what the
    # caller must receipt. `auto_evidence=None` is passed EXPLICITLY: before this change that call
    # returned `not-offered`, and the void must not need a recovery probe it can never satisfy.
    check("(e5) the LIVE sparq #4197 shape (review:parked by jeswr/User at 18:34:32Z, a self-ID by "
          "the SAME account 2s earlier, ZERO park-reason receipts) earns the one-shot VOID",
          void_admit(log=logs.append, auto_evidence=None)[:2],
          ("void-mint", {"key": receiptless_void, "park_at": receiptless_park_at,
                         "prover": "jeswr", "prover_at": receiptless_self_id,
                         # [B1] the exact label write the caller is authorised to perform
                         "plan": RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS}))
    # THE CLAIM THE RECEIPT MAKES is the whole reason this exit is allowed to exist. It must state
    # what is known and must NOT claim a cause — a fabricated cause would be worse than none.
    check("(e5) the detail states WHAT IS KNOWN and explicitly refuses to claim a cause",
          [phrase in void_admit()[2] for phrase in (
              "no park-reason receipt of any kind exists", "FOR WANT OF A RECEIPT",
              "no cause is claimed to have recovered", "none was reconstructed")], [True] * 4)
    check("(e5) ...and the decision is announced, never silent",
          any("receipt-less MACHINE park on o/r#41" in line
              and f"review:parked at {receiptless_park_at}" in line for line in logs), True)
    # FAIL CLOSED, and this is the row that keeps `User`-is-not-decisive honest in BOTH directions:
    # absent a POSITIVE machine signal the park keeps the human terminal it has today, with the
    # pre-#1309 code and the pre-#1309 detail string, byte for byte.
    unproven_census = []
    check("(e5) FAIL CLOSED: with NO self-ID the answer is the pre-#1309 refusal, byte for byte",
          void_admit(self_id_rows=(), auto_evidence=post_park_evidence, census=unproven_census),
          (None, None, "a human applied the machine soft hold, but no bot park-reason receipt "
                       "exists, so nothing ever classified this park as capacity — a human "
                       "applied it and the machine has no opinion"))
    check("(e5) ...and it is still censused HUMAN-TERMINAL (an unproven actor may be a real human)",
          [(row["code"], row["exit"]) for row in unproven_census],
          [(PARK_REFUSAL_HUMAN_APPLIED_UNCLASSIFIED, "human-terminal")])
    check("(e5) a THIRD PARTY's self-ID never binds — only the actor that APPLIED this park, so a "
          "forged self-ID buys nothing its author could not already do with one unlabel click",
          void_admit(self_id_rows=({"login": "drive-by", "at": receiptless_self_id},),
                     auto_evidence=post_park_evidence)[0], None)
    check("(e5) a self-ID OUTSIDE the window is a DIFFERENT operation, not a proof (the live sparq "
          "#4212 stray `> 🤖 SPARQ agent` comment, two days later, and a 61s miss)",
          [void_admit(self_id_rows=({"login": "jeswr", "at": at},),
                      auto_evidence=post_park_evidence)[0]
           for at in ("2026-07-28T03:48:59Z", "2026-07-26T18:33:31Z")], [None, None])
    check("(e5) ...while the window boundary itself binds (asserted against the CONSTANT)",
          void_admit(self_id_rows=({"login": "jeswr", "at": canonical_ts(
              (parse_ts(receiptless_park_at) - timedelta(
                  seconds=MACHINE_PROVENANCE_WINDOW_SECONDS)).isoformat())},))[0], "void-mint")
    check("(e5) an unparseable self-ID stamp can never bind an operation",
          void_admit(self_id_rows=({"login": "jeswr", "at": "not-a-timestamp"},),
                     auto_evidence=post_park_evidence)[0], None)
    # THE CLOSED-EPISODE LOWER BOUND. Added because the mutation sweep for this change found it
    # SURVIVED: no row reached it, so it was a guard that read like a rule and proved nothing. It is
    # reachable in practice precisely because the window is wide enough to span two parks — a bot
    # park at 18:34:00 and a hand re-park 32s later — and without it a self-ID belonging to the
    # EARLIER, already-closed episode would authorise voiding the LATER one.
    timelines[41] = [event("labeled", "review:parked", "2026-07-26T18:34:00Z",
                           "sparq-orchestrator[bot]"), receiptless_park]
    timelines[7] = []
    check("(e5) a self-ID inside the window but belonging to a CLOSED EARLIER episode binds "
          "nothing — while the same row moved past that episode's boundary does",
          [void_admit(self_id_rows=({"login": "jeswr", "at": "2026-07-26T18:33:58Z"},),
                      auto_evidence=post_park_evidence)[0],
           void_admit(self_id_rows=({"login": "jeswr", "at": "2026-07-26T18:34:01Z"},))[0]],
          [None, "void-mint"])
    # THE BOUNDARY ITSELF, because the row above cannot see `<=` weakened to `<`: at 18:33:58 both
    # spellings exclude. Review round 1 predicted this survivor and it did. A self-ID landing EXACTLY
    # at the previous park instant belongs to that closed episode — receipt-first ordering means the
    # earlier park's own narration sits at or just before it — so the bound must be INCLUSIVE.
    check("(e5) ...and the closed-episode bound is INCLUSIVE: a self-ID exactly AT the previous "
          "park instant belongs to that episode, not to this one",
          void_admit(self_id_rows=({"login": "jeswr", "at": "2026-07-26T18:34:00Z"},),
                     auto_evidence=post_park_evidence)[0], None)
    timelines[41] = [receiptless_park]
    timelines[7] = []
    # THE DISCRIMINATION THAT PROVES THE GATE WAS NARROWED, NOT WIDENED. An OFF-CLASS receipt is not
    # receipt-lessness: the machine DID form an opinion about that park and it was not "capacity".
    # Unchanged, and no void is offered for it at any window or provenance.
    check("(e5) an OFF-CLASS receipt is NOT receipt-less — unchanged, and NEVER voidable",
          void_admit(reason_records=(receipt("injection"),),
                     auto_evidence=post_park_evidence)[:2], (None, None))
    check("(e5) ...and the refusal is still the UNCLASSIFIED code naming the disqualifying cause",
          "injection" in void_admit(reason_records=(receipt("injection"),),
                                    auto_evidence=post_park_evidence)[2], True)
    check("(e5) park_is_receiptless splits exactly the two states, and shares ONE filter with "
          "human_park_capacity_proof (a second hand-copied filter is how they would drift)",
          [attempt(lambda: park_is_receiptless(())),
           attempt(lambda: park_is_receiptless(None)),
           attempt(lambda: park_is_receiptless(("garbage", None))),
           attempt(lambda: park_is_receiptless((receipt("budget"),))),
           attempt(lambda: park_is_receiptless((receipt("injection"),)))],
          [True, True, True, False, False])
    # THE VOID INHERITS EVERY PRE-EXISTING GATE. These are exactly the gates whose bypass this
    # change could plausibly have been mistaken for, and it returns AFTER all of them.
    check("(e5) inherits: a LIVE human-owned hold refuses (hold first, as ever)",
          void_admit(live_holds=["needs:user"])[0], None)
    check("(e5) inherits: the AUTO_READMISSION_MAX flap cap refuses — the void does not SPEND that "
          "budget, but it does OBEY it, so a twice-flapped PR gets no third door",
          void_admit(auto_marker_count=AUTO_READMISSION_MAX)[0], None)
    check("(e5) inherits: an unreadable park timeline refuses",
          attempt(lambda: capacity_park_admission(
              "o/r", 41, 404, fetch, is_human=trusted, reason_records=(),
              self_id_rows=orchestrator_self_id, void_offered=True))[0], None)
    check("(e5) inherits: a standing AUTOMATIC re-admission still takes precedence over a mint",
          void_admit(auto_receipts=[{"key": "openai/a/1", "at": "2026-07-26T19:00:00Z"}])[0],
          "auto-receipt")
    timelines[41] = [human_terminal_park]
    check("(e5) inherits: a human-applied HUMAN-owned terminal is never voided, self-ID or not",
          void_admit(self_id_rows=({"login": "jeswr", "at": "2026-07-25T02:19:46Z"},))[0], None)
    timelines[41] = [machine_park]
    check("(e5) a MACHINE-applied park never reaches the void at all — the bot path already has an "
          "exit and is untouched",
          void_admit(auto_evidence=post_park_evidence)[0], "auto-mint")
    # ---- TERMINATION. The obligation this whole exit had to earn. ----
    #
    # BOUND 1, WALKED rather than asserted: RECEIPTLESS_VOID_MAX+1 successive receipt-less parks,
    # each with its own in-window self-ID, each strictly newer than the last void receipt. Exactly
    # MAX voids are granted and then the exit is closed for the PR's whole lifetime. Asserted against
    # the CONSTANT, never a hard-coded 1.
    void_walk_receipts, void_walk_actions = [], []
    for step in range(1, RECEIPTLESS_VOID_MAX + 2):
        walk_park_at = f"2026-07-26T{step + 9:02d}:00:00Z"
        timelines[41] = [event("labeled", "review:parked", walk_park_at, "jeswr")]
        timelines[7] = []
        logs.clear()
        walk_action, walk_evidence, _walk_detail = void_admit(
            log=logs.append, self_id_rows=({"login": "jeswr", "at": walk_park_at},),
            void_receipts=list(void_walk_receipts),
            void_marker_count=len(void_walk_receipts))
        void_walk_actions.append(walk_action)
        if walk_action == "void-mint":
            void_walk_receipts.append({"key": walk_evidence["key"],
                                       "at": f"2026-07-26T{step + 9:02d}:30:00Z"})
    check("(e5) TERMINATION bound 1: exactly RECEIPTLESS_VOID_MAX voids are granted, then the exit "
          "is closed for the PR's whole lifetime",
          void_walk_actions, ["void-mint"] * RECEIPTLESS_VOID_MAX + [None])
    # ⚠️ THE WALK ABOVE IS TAUTOLOGICAL ON ITS OWN, and review round 1 measured exactly that:
    # `RECEIPTLESS_VOID_MAX = 2` and `= 3` both SURVIVED the whole suite, and `= 99` "died" only to
    # fixture overflow (the hour field reaching 24), which is a FALSE KILL. The loop bound and the
    # expected list BOTH derive from the constant, so the walk proves the counter is HONOURED and
    # can never prove it is ONE. The headline claim ("<=1 void per PR, ever") therefore needs a
    # check whose expected value does NOT come from the symbol under test.
    #
    # AGENTS.md pre-flight item 2(c) is the general rule: an input derived from the constant the code
    # reads cannot falsify that constant.
    check("(e5) TERMINATION bound 1, PINNED INDEPENDENTLY: the one-shot budget is literally ONE — "
          "the walk above cannot express this, because its expected value is derived from the very "
          "symbol whose value is the claim",
          RECEIPTLESS_VOID_MAX, 1)
    timelines[41] = [receiptless_park]          # the walk above left its own park behind
    timelines[7] = []
    check("(e5) ...and ONE void is what a PR with ONE prior void marker gets refused for, on a "
          "fixture whose count is a LITERAL rather than the constant",
          [void_admit(void_receipts=(), void_marker_count=1)[0],
           void_admit(void_receipts=(), void_marker_count=0)[0]], [None, "void-mint"])
    check("(e5) ...and the spent refusal is HUMAN-TERMINAL, so the cohort is named rather than "
          "quietly re-counted as self-healing every tick",
          park_refusal_exit_class(PARK_REFUSAL_RECEIPTLESS_SPENT), "human-terminal")
    check("(e5) ...and hitting it is logged LOUDLY as a genuine human question",
          any("::warning::receipt-less void REFUSED" in line
              and "one void per PR is the whole bound" in line for line in logs), True)
    # BOUND 2, INDEPENDENT OF THE COUNTER, and it is the bound that makes the class SELF-EXTINGUISHING:
    # the exit's own precondition is "zero park-reason receipts, ever". Comments are append-only and
    # every machine capacity park emits a receipt by construction (`capacity-unspecified` exists so it
    # always does), so the instant anything re-parks a voided PR the precondition is false FOREVER —
    # the void cannot be re-entered through the machine path at any counter value.
    timelines[41] = [receiptless_park]
    timelines[7] = []
    check("(e5) TERMINATION bound 2: a re-park writes a receipt, and the void's own precondition is "
          "then false forever — at a FRESH counter, which is what makes this bound independent",
          [void_admit(reason_records=(receipt("capacity-unspecified"),), void_marker_count=0,
                      auto_evidence=post_park_evidence)[0],
           park_is_receiptless((receipt("capacity-unspecified"),))],
          ["auto-mint", False])
    # ---- THE CRASH RESIDUE, which a ONE-SHOT exit fails at differently from a CAPPED one ----
    #
    # Receipt-first: if the label write dies, the PR holds a SPENT budget and a LIVE park. The
    # convergence branch therefore sits ABOVE the spent check. The first cut of this change copied
    # the automatic path's placement (below the cap) and would have stranded exactly such a PR
    # FOREVER — by the very exit built to un-strand it. This row is that regression.
    standing_void = [{"key": receiptless_void, "at": "2026-07-26T19:00:00Z"}]
    check("(e5) CRASH RESIDUE converges: a standing void receipt for the LIVE park re-admits, "
          "spends no new budget, and does so WITH the one-shot budget already spent",
          void_admit(void_receipts=standing_void,
                     void_marker_count=RECEIPTLESS_VOID_MAX)[:2],
          ("void-receipt", {"key": receiptless_void, "at": "2026-07-26T19:00:00Z",
                            # [round 2 BLOCKER] THE PLAN, and this is the whole repair. Without it
                            # the sweep passed `evidence.get("plan")` = None into the writer's
                            # `str(plan)`, producing the STRING "None", which the writer's
                            # `expect_plan is not None` test read as a real expectation and stood
                            # down on — so the convergence NEVER WROTE. A transient failure of the
                            # label write after the receipt landed would then have left the PR with a
                            # spent one-shot budget and a live park FOREVER: the exact strand this
                            # exit removes, re-created through its own recovery path.
                            "plan": RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS}))
    check("(e5) ...and the convergence's plan tracks the LIVE namespace, so it writes what THIS "
          "PR now needs rather than what the mint decided at some earlier instant",
          [void_admit(pr_review_labels=labels, void_receipts=standing_void,
                      void_marker_count=RECEIPTLESS_VOID_MAX)[1]["plan"]
           for labels in ([MACHINE_PARK_PR_LABEL],
                          [MACHINE_PARK_PR_LABEL, "review:changes"],
                          [MACHINE_PARK_PR_LABEL, "review:changes", "review:needs"])],
          [RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS, RECEIPTLESS_VOID_PLAN_STRIP, None])
    check("(e5) ...and an un-writable convergence STILL returns void-receipt, so a read-only proof "
          "gate admits a publicly-receipted void rather than deferring forever (#614 / M14)",
          void_admit(pr_review_labels=[MACHINE_PARK_PR_LABEL, "review:changes", "review:needs"],
                     void_offered=False, void_receipts=standing_void,
                     void_marker_count=RECEIPTLESS_VOID_MAX)[0], "void-receipt")
    check("(e5) ...and the READ-ONLY proof gate converges it too, so the machine's own void is "
          "never invisible to the gate that reads it (the #614 deadlock, not re-created)",
          void_admit(void_offered=False, void_receipts=standing_void,
                     void_marker_count=RECEIPTLESS_VOID_MAX)[0], "void-receipt")
    check("(e5) ...while the READ-ONLY gate MINTS NOTHING on a mintable state",
          void_admit(void_offered=False, auto_evidence=None),
          (None, None, "a receipt-less machine park is voidable, but this call offered no void "
                       "(read-only proof gate)"))
    check("(e5) a void receipt with a MALFORMED stamp converges nothing and still spends the "
          "one-shot budget, so a writer that corrupts its own stamp earns no extra void",
          void_admit(void_receipts=[{"key": receiptless_void, "at": "not-a-timestamp"}],
                     void_marker_count=RECEIPTLESS_VOID_MAX)[0], None)
    # THE BUDGET COUNTS MARKERS, NOT PARSED RECORDS — AUTO_READMIT_MARKER's rule, and this row is
    # what makes it non-vacuous. Added because the mutation sweep found `spent = len(void_receipts)`
    # SURVIVED the suite: the row above passes BOTH counts, so it could not tell them apart. Here the
    # marker is corrupt enough to yield NO parsed record at all, which is exactly the state in which
    # ignoring `void_marker_count` would hand a self-corrupting writer unlimited voids.
    check("(e5) a marker too corrupt to parse at all STILL spends the one-shot budget (the count is "
          "of MARKERS, not of records)",
          [void_admit(void_receipts=(), void_marker_count=RECEIPTLESS_VOID_MAX)[0],
           void_admit(void_receipts=(), void_marker_count=RECEIPTLESS_VOID_MAX - 1)[0]],
          [None, "void-mint"])
    # EPISODE BINDING on the void receipt: a void of a DIFFERENT park application can never clear
    # this one. The key IS the park instant, so this is exact rather than a recency proxy.
    timelines[41] = [receiptless_park,
                     event("labeled", "review:parked", "2026-07-27T02:00:00Z", "jeswr")]
    check("(e5) a STALE void receipt (a different, closed park episode) clears NOTHING, and the "
          "one-shot budget then refuses a second void rather than granting one",
          void_admit(self_id_rows=({"login": "jeswr", "at": "2026-07-27T01:59:58Z"},),
                     void_receipts=standing_void,
                     void_marker_count=RECEIPTLESS_VOID_MAX)[1:],
          (None, f"the one-shot receipt-less void is spent ({RECEIPTLESS_VOID_MAX}/"
                 f"{RECEIPTLESS_VOID_MAX})"))
    # ---- THE CENSUS: the void is counted, and counted APART. ----
    timelines[41] = [receiptless_park]
    timelines[7] = []
    void_census = []
    void_action = void_admit(census=void_census)[0]
    check("(e5) census: exactly one row, under its OWN admit code — a census that merged the void "
          "with the cause-recovery admissions could not answer 'how many parks did we clear WITHOUT "
          "proving a cause recovered', which is the number that must stay small",
          (void_action, [(row["code"], row["exit"]) for row in void_census]),
          ("void-mint", [("admitted-void-receiptless", None)]))
    void_census.clear()
    void_admit(census=void_census, void_receipts=standing_void,
               void_marker_count=RECEIPTLESS_VOID_MAX)
    check("(e5) census: the convergence has its own admit code too",
          [(row["code"], row["exit"]) for row in void_census],
          [("admitted-void-receipt", None)])
    check("(e5) census: every void code round-trips the taxonomy (no unclassified drift)",
          sorted(code for code in PARK_REFUSAL_CODES if park_refusal_exit_class(code) is None), [])
    # ---- THE READER AND THE WRITER, on production shapes. ----
    #
    # THE EMPHASIS FORM IS THE WHOLE REACHABILITY QUESTION. The live population writes
    # `> 🤖 **SPARQ agent** — parking ...`; the bot writes `> 🤖 SPARQ agent — ...`. A literal
    # `startswith("> 🤖 SPARQ agent")` matches the SECOND and misses the FIRST, i.e. it would match
    # every PR except the ten this exit exists for — correct, tested, and +0 in production.
    check("(e5) the self-ID reader accepts BOTH live spellings, including the emphasised one a "
          "literal startswith would MISS",
          self_identified_machine_comments([
              {"user": {"login": "jeswr"}, "created_at": receiptless_self_id,
               "body": "> 🤖 **SPARQ agent** — parking to restore worker dispatch. **Nothing is "
                       "wrong with this PR.**"},
              {"user": {"login": "sparq-orchestrator"}, "created_at": "2026-07-26T18:27:03Z",
               "body": "> 🤖 SPARQ agent — fix round 1 executed by `opus5`."}]),
          [{"login": "jeswr", "at": receiptless_self_id},
           {"login": "sparq-orchestrator", "at": "2026-07-26T18:27:03Z"}])
    check("(e5) the self-ID reader is ANCHORED to the first line: a self-ID quoted DEEPER in a body "
          "is a comment ABOUT an agent, not one BY an agent",
          self_identified_machine_comments([
              {"user": {"login": "jeswr"}, "created_at": receiptless_self_id,
               "body": "as it happens\n\n> 🤖 SPARQ agent — I parked this"}]), [])
    check("(e5) the self-ID reader survives hostile rows",
          attempt(lambda: self_identified_machine_comments(
              ["garbage", None, {}, {"body": 7}, {"body": None, "user": None}])), [])
    check("(e5) ...and a non-list is not a source of signals",
          attempt(lambda: self_identified_machine_comments("not a list")), [])
    void_body = receiptless_void_comment(
        {"key": receiptless_void, "park_at": receiptless_park_at, "prover": "jeswr",
         "prover_at": receiptless_self_id}, "2026-07-26T19:00:00Z", pr_number=4197)
    check("(e5) the void receipt ROUND-TRIPS through the real reader, bot-filtered",
          [receiptless_void_records([{"user": {"login": "sparq-orchestrator[bot]"},
                                      "body": void_body}], "sparq-orchestrator[bot]"),
           receiptless_void_records([{"user": {"login": "drive-by"}, "body": void_body}],
                                    "sparq-orchestrator[bot]"),
           receiptless_void_records([{"user": {"login": "sparq-orchestrator[bot]"},
                                      "body": void_body}], "")],
          [[{"key": receiptless_void, "at": "2026-07-26T19:00:00Z"}], [], []])
    check("(e5) the void receipt SAYS what it is and refuses to claim a cause",
          [phrase in void_body for phrase in (
              "> 🤖 SPARQ agent", "No cause has been reconstructed, because none was ever recorded",
              "for want of a receipt",
              "not because anything is known to have recovered",
              "the park comment's prose was not read")], [True] * 5)
    # [round 2] THE DESTINATION SENTENCE IS DERIVED, NOT ASSERTED. Round 1's receipt said
    # unconditionally that the PR "returns to review:needs" — FALSE for the `strip-only` plan, i.e.
    # for three of the seven live rows (#4212 #4222 #4318), which return to `review:changes`. The
    # harm was a labelling one, but a false statement in a durable receipt on three live PRs is
    # precisely the overclaiming this receipt exists to avoid.
    def void_body_for(plan):
        return receiptless_void_comment(
            {"key": receiptless_void, "park_at": receiptless_park_at, "prover": "jeswr",
             "prover_at": receiptless_self_id, "plan": plan}, "2026-07-26T19:00:00Z", pr_number=41)

    check("(e5) the receipt's DESTINATION sentence follows the plan: only strip-and-needs may claim "
          "review:needs, and strip-only says the PRE-PARK state is restored",
          [("returns to `review:needs`" in void_body_for(RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS),
            "review:needs" in void_body_for(RECEIPTLESS_VOID_PLAN_STRIP)),
           ("the review state it held before the park" in void_body_for(
               RECEIPTLESS_VOID_PLAN_STRIP),
            "no review state is written or asserted" in void_body_for(None))],
          [(True, False), (True, True)])
    check("(e5) ...and NO plan may claim a review was scheduled",
          [("not** a claim that a review" in void_body_for(plan)
            or "no review state is written or asserted" in void_body_for(plan))
           for plan in (RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS, RECEIPTLESS_VOID_PLAN_STRIP, None)],
          [True] * 3)
    check("(e5) the marker is ANCHORED to a whole line, so a marker ECHOED inside another line is "
          "structurally not a receipt (#1096's rule, inherited not re-derived)",
          receiptless_void_records([{"user": {"login": "bot"}, "body": f"- x: \"{void_body}\""}],
                                   "bot"), [])
    # ...and the OTHER half of #1096: a marker on its own line but inside a context the comment
    # itself marks as echoed. Forging this marker would make the sweep clear a park's labels, and
    # resolve-conflicts.py interpolates raw git pathnames into App-authored bodies — so an App
    # comment is a receipt-minting surface unless BOTH halves hold.
    void_marker_line = void_body.rsplit("\n", 1)[-1]
    check("(e5) a void marker inside a FENCED or QUOTED context is structurally not a receipt",
          [receiptless_void_records(
              [{"user": {"login": "bot"}, "body": f"echoing:\n\n```\n{void_marker_line}\n```\n"}],
              "bot"),
           receiptless_void_records(
               [{"user": {"login": "bot"}, "body": f"they wrote:\n\n> {void_marker_line}\n"}],
               "bot"),
           receiptless_void_records(
               [{"user": {"login": "bot"}, "body": f"echoing:\n\n  ```\n{void_marker_line}\n  ```"}],
               "bot")],
          [[], [], []])
    check("(e5) ...while the marker in the bot's OWN unquoted prose still parses (the strip is not "
          "simply eating every receipt)",
          [row["key"] for row in receiptless_void_records(
              [{"user": {"login": "bot"}, "body": void_body}], "bot")], [receiptless_void])
    check("(e5) the self-ID reader cannot be reached from a fenced context either: a fence OPENER "
          "is never itself a self-ID, and only line 1 is read",
          self_identified_machine_comments([
              {"user": {"login": "jeswr"}, "created_at": receiptless_self_id,
               "body": "```\n> 🤖 SPARQ agent — echoed\n```"}]), [])
    # The marker also carries the `sparq-` prefix the WRITER-side sanitiser keys on, so the two
    # halves of #1096's defence are both live for it rather than only the one written here.
    check("(e5) the void marker is inside RESERVED_MARKER_RE's namespace, so the writer-side "
          "sanitiser disarms an echoed copy too",
          [contains_reserved_marker(RECEIPTLESS_VOID_MARKER),
           RECEIPTLESS_VOID_MARKER in neutralize_reserved_markers(
               f"echo {RECEIPTLESS_VOID_MARKER} -->")], [True, False])
    # EVERY comment is counted, not just the first. Review round 1 predicted this survivor and it
    # did: every cap fixture was a SINGLE-element list, so `comments[:1]` was invisible — and that
    # mutant hands a PR unlimited voids the moment its receipt is not the newest comment, which is
    # the normal case (the conflict resolver comments on these PRs constantly).
    check("(e5) the cap counter scans EVERY comment, not merely the first — a fixture of one can "
          "never see a slice",
          [receiptless_void_marker_count(
              [{"user": {"login": "bot"}, "body": "an ordinary earlier comment"},
               {"user": {"login": "bot"}, "body": void_body}], "bot"),
           receiptless_void_marker_count(
               [{"user": {"login": "drive-by"}, "body": "noise"},
                {"user": {"login": "bot"}, "body": void_body},
                {"user": {"login": "bot"}, "body": "a later unrelated comment"}], "bot")],
          [1, 1])
    check("(e5) ...and the RECORD reader does too, for the same reason",
          [row["key"] for row in receiptless_void_records(
              [{"user": {"login": "bot"}, "body": "earlier"},
               {"user": {"login": "bot"}, "body": void_body}], "bot")], [receiptless_void])
    check("(e5) the cap counts MARKERS, well-formed or not",
          [receiptless_void_marker_count([{"user": {"login": "bot"}, "body": void_body}], "bot"),
           receiptless_void_marker_count(
               [{"user": {"login": "bot"},
                 "body": f"{RECEIPTLESS_VOID_MARKER} corrupt -->"}], "bot"),
           receiptless_void_marker_count([{"user": {"login": "drive-by"}, "body": void_body}],
                                         "bot"),
           receiptless_void_marker_count([{"user": {"login": "bot"}, "body": void_body}], "")],
          [1, 1, 0, 0])
    check("(e5) the writer FAILS LOUD on anything it cannot represent, rather than writing an "
          "unparseable receipt",
          [attempt(lambda: receiptless_void_marker("a b", "2026-07-26T19:00:00Z", "jeswr",
                                                   receiptless_self_id)),
           attempt(lambda: receiptless_void_marker("key -->", "2026-07-26T19:00:00Z", "jeswr",
                                                   receiptless_self_id)),
           attempt(lambda: receiptless_void_marker(receiptless_void, "nope", "jeswr",
                                                   receiptless_self_id)),
           attempt(lambda: receiptless_void_marker(receiptless_void, "2026-07-26T19:00:00Z", None,
                                                   receiptless_self_id))],
          [("raised", "ValueError", "raised ValueError")] * 4)
    check("(e5) the void KEY is derived from the park instant and nothing else — a FACT about which "
          "application was voided, never a reconstruction of why",
          [receiptless_void_key(receiptless_park_at), receiptless_void_key("not-a-timestamp"),
           receiptless_void_key(None)],
          [receiptless_void, None, None])
    # ---- [B1] THE LABEL-PLAN AXIS: what the void is ALLOWED to write. ----
    #
    # Review round 1's serious finding. `clear_labels` transitions through worker-pr's
    # `review-state set --state needs`, whose issue-#138 ambiguity rule converges a split `review:*`
    # namespace to the HUMAN-owned `review:needs-user` — so voiding through it would have spent each
    # PR's one-shot exit to move it into a STRICTER hold. Five of the eight live candidates.
    #
    # The plan predicate is pinned here on the REAL live label sets, and the WRITER's half (through
    # the real set_review_state) is pinned in worker-pr's own self-test — the two must agree, which
    # is why both call this one function rather than each carrying a rule.
    live_label_sets = {
        3577: ["area:site", MACHINE_PARK_PR_LABEL],
        3598: ["area:deps", "area:sparq-zk", MACHINE_PARK_PR_LABEL],
        3641: ["area:bench", "review:needs", "review:changes", MACHINE_PARK_PR_LABEL],
        4197: [MACHINE_PARK_PR_LABEL],
        4207: ["review:needs", MACHINE_PARK_PR_LABEL],
        4212: ["review:changes", MACHINE_PARK_PR_LABEL],
        4222: ["review:changes", MACHINE_PARK_PR_LABEL],
        4318: ["area:site", "review:changes", "area:ci", "area:docs", MACHINE_PARK_PR_LABEL],
    }
    check("(e5/B1) the plan over the 8 REAL live label sets: 3 strip-and-stamp, 4 strip-only (back "
          "to their pre-park state), and the one ambiguous independently of the park REFUSES",
          {number: receiptless_void_label_plan(labels)[0]
           for number, labels in sorted(live_label_sets.items())},
          {3577: RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS,
           3598: RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS,
           3641: None,
           4197: RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS,
           4207: RECEIPTLESS_VOID_PLAN_STRIP,
           4212: RECEIPTLESS_VOID_PLAN_STRIP,
           4222: RECEIPTLESS_VOID_PLAN_STRIP,
           4318: RECEIPTLESS_VOID_PLAN_STRIP})
    check("(e5/B1) NON-review labels never make a namespace ambiguous — only the review: prefix "
          "counts, so an area:/trust-surface pile-up cannot refuse a clean void",
          [receiptless_void_label_plan([MACHINE_PARK_PR_LABEL, "area:ci", "area:docs",
                                        "trust-surface"])[0],
           receiptless_void_label_plan([MACHINE_PARK_PR_LABEL, "review:changes", "area:ci"])[0]],
          [RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS, RECEIPTLESS_VOID_PLAN_STRIP])
    check("(e5/B1) every ambiguity refuses: no live park, a live human terminal, a malformed or "
          "unreadable label surface",
          [receiptless_void_label_plan(["review:needs"])[0],
           receiptless_void_label_plan([MACHINE_PARK_PR_LABEL, HUMAN_PR_PARK_LABEL])[0],
           receiptless_void_label_plan([MACHINE_PARK_PR_LABEL, 7])[0],
           receiptless_void_label_plan(MACHINE_PARK_PR_LABEL)[0],
           receiptless_void_label_plan(None)[0],
           receiptless_void_label_plan(7)[0]],
          [None] * 6)
    check("(e5/B1) an unknown review:* label the writer's closed list does not name STILL counts "
          "here — the two disagree in the REFUSING direction only",
          receiptless_void_label_plan(
              [MACHINE_PARK_PR_LABEL, "review:changes", "review:something-new"])[0], None)
    # THE ADMISSION REFUSES BEFORE SPENDING THE BUDGET. This is the row that makes the finding
    # structural: an un-writable void must never be minted, because burning the one-shot exit to
    # move a PR into a stricter hold is worse than leaving it parked.
    ambiguous_census = []
    check("(e5/B1) the admission REFUSES an un-writable void rather than spending the one-shot "
          "budget on it",
          void_admit(pr_review_labels=live_label_sets[3641], census=ambiguous_census)[:2],
          (None, None))
    check("(e5/B1) ...censused under its OWN code, HUMAN-TERMINAL (nothing de-ambiguates a split "
          "review namespace, and issue #138 resolves one toward the human terminal)",
          [(row["code"], row["exit"]) for row in ambiguous_census],
          [(PARK_REFUSAL_RECEIPTLESS_AMBIGUOUS, "human-terminal")])
    check("(e5/B1) ...and the refusal NAMES the labels that made it ambiguous",
          all(token in void_admit(pr_review_labels=live_label_sets[3641])[2]
              for token in ("review:changes", "review:needs", "ambiguous")), True)
    check("(e5/B1) the plan TRAVELS with the evidence, so the decision that spent the budget and "
          "the write that follows cannot be about two different plans",
          [void_admit(pr_review_labels=live_label_sets[number])[1]["plan"]
           for number in (4197, 4212)],
          [RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS, RECEIPTLESS_VOID_PLAN_STRIP])
    check("(e5/B1) a caller that forgets pr_review_labels gets a REFUSAL, never a write",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=lambda *_a: None,
                                  reason_records=(), self_id_rows=orchestrator_self_id,
                                  void_offered=True)[0], None)
    check("(e5/B1) every declared plan is one the writer knows how to execute",
          sorted(RECEIPTLESS_VOID_PLANS),
          sorted({RECEIPTLESS_VOID_PLAN_STRIP, RECEIPTLESS_VOID_PLAN_STRIP_AND_NEEDS}))

    # ---- THE REMAINING FAIL-CLOSED LINES, reached DIRECTLY. ----
    #
    # Added because line-granular coverage (AGENTS.md pre-flight item 1) found them at 0 % after the
    # mutation sweep had already run and reported 16/16. A guard the suite never executes is not
    # protected by a kill count, and every line below is a REFUSAL — the direction where an
    # unexecuted guard is silently permissive.
    check("(e5) provenance predicate: an unknown park instant binds nothing",
          attempt(lambda: machine_operated_park_proof(
              orchestrator_self_id, None, None, ("jeswr",))[:2]),
          (False, "the park application instant is unknown, so no operation can be bound to it"))
    check("(e5) provenance predicate: an unattributable applying actor binds nothing",
          [attempt(lambda: machine_operated_park_proof(
              orchestrator_self_id, receiptless_park_at, None, logins)[0])
           for logins in ((), None, ("",))], [False, False, False])
    check("(e5) provenance predicate: a malformed self-ID ROW is not a signal",
          attempt(lambda: machine_operated_park_proof(
              ("garbage", None, 7, {"login": "jeswr"}), receiptless_park_at, None,
              ("jeswr",))[0]), False)
    check("(e5) provenance predicate: ...while a well-formed row among the malformed ones IS",
          attempt(lambda: machine_operated_park_proof(
              ("garbage", None, {"login": "jeswr", "at": receiptless_self_id}),
              receiptless_park_at, None, ("jeswr",))[0]), True)
    check("(e5) the void-receipt READER drops a marker whose stamp is unparseable, LOUDLY, and "
          "counts it toward the cap anyway",
          [attempt(lambda: receiptless_void_records(
              [{"user": {"login": "bot"},
                "body": f"x\n\n{RECEIPTLESS_VOID_MARKER} key={receiptless_void} at=garbage "
                        f"prover=jeswr prover_at={receiptless_self_id} -->"}],
              "bot", log=logs.append)),
           attempt(lambda: receiptless_void_marker_count(
               [{"user": {"login": "bot"},
                 "body": f"x\n\n{RECEIPTLESS_VOID_MARKER} key={receiptless_void} at=garbage "
                         f"prover=jeswr prover_at={receiptless_self_id} -->"}], "bot"))],
          [[], 1])
    check("(e5) ...and says so",
          any("malformed receipt-less void stamp" in line
              and "still counts toward RECEIPTLESS_VOID_MAX" in line for line in logs), True)
    check("(e5) the void-receipt reader and the cap counter both survive hostile comment rows",
          [attempt(lambda: receiptless_void_records(["garbage", None, 7, {}], "bot")),
           attempt(lambda: receiptless_void_marker_count(["garbage", None, 7, {}], "bot")),
           attempt(lambda: receiptless_void_records("not a list", "bot")),
           attempt(lambda: receiptless_void_marker_count("not a list", "bot"))],
          [[], 0, [], 0])
    check("(e5) the void comment writer REFUSES a non-dict evidence rather than writing a receipt "
          "with no subject",
          [attempt(lambda: receiptless_void_comment(None, "2026-07-26T19:00:00Z")),
           attempt(lambda: receiptless_void_comment("garbage", "2026-07-26T19:00:00Z"))],
          [("raised", "ValueError", "raised ValueError")] * 2)
    timelines[41] = [human_pr_park]
    timelines[7] = []
    check("(e2) MACHINE_OWNED_PARK_LABELS is exactly the machine subset of READMISSION_LABELS",
          (sorted(MACHINE_OWNED_PARK_LABELS),
           sorted(set(READMISSION_LABELS) - MACHINE_OWNED_PARK_LABELS)),
          (sorted({MACHINE_PARK_LABEL, MACHINE_PARK_PR_LABEL}), [HUMAN_PARK_LABEL]))
    timelines[41] = [human_pr_park]
    timelines[7] = []
    # A park applied by an UNVERIFIABLE actor is NOT human-owned (same strict probe as the veto),
    # so it remains automatically re-admittable.
    timelines[41] = [event("labeled", "review:parked", "2026-07-25T02:19:47Z", "drive-by")]
    check("(e) an unverifiable actor's park is not human-owned (auto-re-admittable)",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T03:10:00Z"))[0],
          "auto-mint")
    # (f) THE STICKY HUMAN-UNPARK VETO IS UNTOUCHED: the automatic path only ever CLEARS a
    # machine park, never applies one, so a standing human unlabel still suppresses every park
    # write regardless of any recovery evidence or automatic receipt.
    timelines[41] = [machine_park, event("unlabeled", "review:parked", "2026-07-25T05:00:00Z",
                                         "jeswr")]
    logs.clear()
    check("(f) the sticky human-unpark veto still suppresses the park write",
          park_vetoed("o/r", 41, "review:parked", fetch, is_human=trusted, log=logs.append),
          True)
    check("(f) the veto log is unchanged",
          any("park suppressed: human unlabeled review:parked at 2026-07-25T05:00:00Z" in line
              for line in logs), True)
    # ... and that human gesture (newer than every application, unconsumed) takes PRECEDENCE:
    # (h) the HUMAN path admits and NO automatic evidence is consumed.
    precedence_probe = evidence_at("openai/a/1", "2026-07-25T06:00:00Z")
    check("(h) a human gesture and automatic evidence both present => HUMAN precedence",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  auto_evidence=precedence_probe),
          ("human", None, "unconsumed proven-human readmission gesture"))
    check("(h) the human path consumes NO automatic evidence (the probe is never called)",
          precedence_probe.seen, [])
    check("(h) capacity_park_readmitted itself still admits that gesture unchanged",
          capacity_park_readmitted("o/r", 41, 7, fetch, is_human=trusted), True)
    # A CONSUMED human gesture falls through to the automatic path instead of admitting.
    timelines[41] = [machine_park, event("unlabeled", "review:parked", "2026-07-25T05:00:00Z",
                                         "jeswr")]
    check("(h) a receipted (consumed) human gesture falls through to the automatic path",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  consumed={"2026-07-25T05:00:00Z"},
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T06:00:00Z"))[0],
          "auto-mint")
    # (g) the per-PR automatic cap TERMINATES and logs loudly. Walk AUTO_READMISSION_MAX real
    # outage-and-recovery pairs (each park newer than the last receipt, each recovery newer than
    # its park — genuinely distinct events), then prove the next one is refused. Asserted against
    # the CONSTANT, never a hard-coded 2.
    receipts, actions = [], []
    for step in range(1, AUTO_READMISSION_MAX + 2):
        timelines[41] = [event("labeled", "review:parked", f"2026-07-25T{step:02d}:00:00Z",
                              "sparq-orchestrator[bot]")]
        timelines[7] = []
        logs.clear()
        action, evidence, _detail = capacity_park_admission(
            "o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
            auto_receipts=list(receipts),
            auto_evidence=evidence_at(f"openai/a/{step}", f"2026-07-25T{step:02d}:30:00Z"))
        actions.append(action)
        if action == "auto-mint":
            receipts.append(evidence)
    check("(g) exactly AUTO_READMISSION_MAX automatic re-admissions are granted, then the cap "
          "refuses",
          actions, ["auto-mint"] * AUTO_READMISSION_MAX + [None])
    check("(g) hitting the cap logs LOUDLY as a genuine human question",
          any("::warning::automatic readmission REFUSED" in line
              and "genuine human question" in line for line in logs), True)
    check("(g) the cap counts MALFORMED markers too — a corrupt receipt buys no extra "
          "re-admission",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                                  auto_receipts=[], auto_marker_count=AUTO_READMISSION_MAX,
                                  auto_evidence=evidence_at("openai/a/9",
                                                            "2026-07-25T09:30:00Z"))[0],
          None)
    # The CLAIM proof gate passes NO evidence probe: it evaluates the human + already-receipted
    # paths only, and mints nothing.
    timelines[41] = [machine_park]
    check("the proof gate (no evidence probe) mints nothing",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted),
          (None, None, "no unconsumed human gesture and no recovery evidence offered"))

    # ---- G5 census: every decision lands in a VISIBLE, COUNTED state with a reason ----------
    #
    # The population these guard is real. MEASURED on sparq-org/sparq at 2026-07-27T11:53Z
    # (dispatch run 30262478746): 21 open PRs on `review:parked`, reported by the only aggregate
    # that exists as one undifferentiated "machine capacity park stands (...)=13" — inside which
    # 3 PRs were waiting on recovery evidence that a later tick can genuinely supply, and 4 were
    # frozen behind a maintainer's own hand-applied `review:parked` that NO tick will ever clear.
    # A per-run success signal cannot express the difference; these checks make it structural.
    fresh = "2026-07-25T03:10:00Z"

    def admission_census(**kwargs):
        """One admission call, returning (action, the single census row it recorded)."""
        rows = []
        action = capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                         log=logs.append, census=rows, **kwargs)[0]
        return action, (rows[0] if len(rows) == 1 else rows)

    # THE HEADLINE GUARD. A maintainer's hand-applied HUMAN-OWNED TERMINAL is refused (unchanged)
    # AND is counted as HUMAN-TERMINAL rather than disappearing into the capacity bucket.
    # (The label is `needs:user`, not `review:parked`: a hand-applied MACHINE-owned soft hold is no
    # longer a human-terminal exit — see the (e2) block — so using it here would have pinned the
    # census row to a state that no longer produces one.)
    timelines[41] = [event("labeled", "needs:user", "2026-07-25T02:19:47Z", "jeswr")]
    timelines[7] = []
    check("census: a HUMAN-APPLIED park is refused and counted as human-terminal",
          admission_census(auto_evidence=evidence_at("openai/a/1", fresh)),
          (None, {"repo": "o/r", "number": 41, "code": PARK_REFUSAL_HUMAN_APPLIED,
                  "exit": "human-terminal",
                  "detail": "the latest park application is the HUMAN-owned terminal "
                            "(needs:user) — only a human clears it"}))
    # ... and the CONTRAST that gives the taxonomy its meaning: the same PR, parked by the
    # MACHINE with no recovery yet, is the SAME refusal answer but a DIFFERENT exit class.
    timelines[41] = [machine_park]
    check("census: a machine park awaiting recovery is refused but EXIT-REACHABLE",
          admission_census(auto_evidence=lambda _parked_at: None),
          (None, {"repo": "o/r", "number": 41, "code": PARK_REFUSAL_NO_EVIDENCE,
                  "exit": "exit-reachable",
                  "detail": "no recorded recovery of the park's starvation cause"}))
    check("census: a live needs:user is refused and counted as human-terminal",
          admission_census(live_holds=["needs:user"],
                           auto_evidence=evidence_at("openai/a/1", fresh)),
          (None, {"repo": "o/r", "number": 41, "code": PARK_REFUSAL_HUMAN_HOLD,
                  "exit": "human-terminal",
                  "detail": "human-owned hold(s) live (needs:user) — never auto-re-admitted"}))
    check("census: the CAP is human-terminal — a flapping account is a human question",
          admission_census(auto_marker_count=AUTO_READMISSION_MAX,
                           auto_evidence=evidence_at("openai/a/9", fresh))[1]["exit"],
          "human-terminal")
    unreadable_rows = []
    capacity_park_admission("o/r", 41, 404, fetch, is_human=trusted, log=logs.append,
                            census=unreadable_rows,
                            auto_evidence=evidence_at("openai/a/1", fresh))
    check("census: an unreadable timeline is COUNTED, not silent",
          [(row["code"], row["exit"]) for row in unreadable_rows],
          [(PARK_REFUSAL_TIMELINE_UNREADABLE, "exit-reachable")])
    # THE SWEEP'S OWN EXITS. Two decisions about a parked PR are made BEFORE the admission is
    # ever called (dispatch-claim._readmit_capacity_parks): the per-tick pacing defer and a
    # per-PR GitHub read that failed. Review measured 8 parked PRs in and 5 rows out because of
    # them. They are written through the SAME single writer, so their row shape and exit class
    # cannot drift from the admission's.
    sweep_exits = []
    park_census_record(sweep_exits, "o/r", 10, PARK_REFUSAL_READ_FAILED, "comments unreadable")
    park_census_record(sweep_exits, "o/r", 70, PARK_REFUSAL_TICK_DEFERRED, "cap 5 spent")
    check("census: the sweep's PRE-ADMISSION exits are counted, with the admission's row shape",
          sweep_exits,
          [{"repo": "o/r", "number": 10, "code": PARK_REFUSAL_READ_FAILED,
            "exit": "exit-reachable", "detail": "comments unreadable"},
           {"repo": "o/r", "number": 70, "code": PARK_REFUSAL_TICK_DEFERRED,
            "exit": "exit-reachable", "detail": "cap 5 spent"}])
    # ...and NEITHER is human-terminal: a read failure and a paced defer are both things a later
    # tick can genuinely clear. Filing either as human-terminal would put a transient blip into
    # the cohort an operator is told needs a HUMAN gesture, which is how that warning stops
    # meaning anything.
    check("census: neither sweep exit is filed as human-terminal", park_census_summary(
        sweep_exits), ({PARK_REFUSAL_READ_FAILED: 1, PARK_REFUSAL_TICK_DEFERRED: 1}, [], []))
    check("census: the single writer ignores a non-list census (the out-list idiom)",
          park_census_record(None, "o/r", 1, PARK_REFUSAL_READ_FAILED, "x"), None)
    # An ADMISSION is censused too, so the rows sum to the population rather than to the
    # refusals alone, and it belongs to NEITHER blocked class.
    check("census: an auto-mint is recorded under an admit code with no exit class",
          admission_census(auto_evidence=evidence_at("openai/a/1", fresh)),
          ("auto-mint", {"repo": "o/r", "number": 41, "code": "admitted-auto-mint",
                         "exit": None,
                         "detail": "recovery evidence 'openai/a/1' recorded at "
                                   "2026-07-25T03:10:00Z, strictly after the park application "
                                   "at 2026-07-25T02:19:47Z"}))
    # EXACTLY ONE ROW PER DECISION. A census that double-counts or silently skips is worse than
    # none, so the arity is pinned over a mixed batch rather than assumed.
    batch = []
    for holds, probe in ((["needs:user"], evidence_at("openai/a/1", fresh)),
                         ([], lambda _parked_at: None),
                         ([], evidence_at("openai/a/1", fresh))):
        capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                                live_holds=holds, auto_evidence=probe, census=batch)
    check("census: exactly one row per decision, none skipped, none doubled", len(batch), 3)
    check("census: summary counts by code and names the human-terminal population",
          park_census_summary(batch),
          ({"admitted-auto-mint": 1, PARK_REFUSAL_HUMAN_HOLD: 1, PARK_REFUSAL_NO_EVIDENCE: 1},
           [41], []))
    # The FAIL DIRECTION of the classifier: an unrecognised code must never be filed as
    # self-healing. Silently reading "exit-reachable" for a code nobody registered is exactly how
    # a stalled population goes missing again.
    check("census: an UNKNOWN refusal code is not silently self-healing",
          park_refusal_exit_class("some-future-code"), None)
    check("census: an unknown code surfaces in the UNCLASSIFIED population",
          park_census_summary([{"repo": "o/r", "number": 99, "code": "some-future-code"}]),
          ({"some-future-code": 1}, [], [99]))
    check("census: malformed rows are COUNTED, never dropped",
          park_census_summary(["garbage", {"number": 1}, {"code": "", "number": 2}])[0],
          {"malformed": 3})
    # TAXONOMY DRIFT GUARD: every registered code classifies, and the two classes partition it.
    check("census: every registered refusal code has an exit class",
          sorted(code for code in PARK_REFUSAL_CODES
                 if park_refusal_exit_class(code) is None), [])
    check("census: the human-terminal set is a strict subset of the registered codes",
          PARK_REFUSAL_HUMAN_TERMINAL < PARK_REFUSAL_CODES, True)
    check("census: an admit code is never mistaken for a refusal code",
          sorted(set(PARK_ADMIT_CODES.values()) & PARK_REFUSAL_CODES), [])

    # ---- effective_readmission_cutoff: an automatic re-admission grants the SAME real budget
    # window a human gesture grants (without it the cleared park is inert — every tick
    # re-derives the same exhausted starvation counters and quietly re-defers forever) ----
    check("cutoff: the automatic stamp is used when there is no human gesture",
          effective_readmission_cutoff(None, ["2026-07-25T03:10:00Z"]), "2026-07-25T03:10:00Z")
    check("cutoff: the LATEST of the human and automatic stamps wins (human newer)",
          effective_readmission_cutoff("2026-07-25T09:00:00Z", ["2026-07-25T03:10:00Z"]),
          "2026-07-25T09:00:00Z")
    check("cutoff: the LATEST of the human and automatic stamps wins (automatic newer)",
          effective_readmission_cutoff("2026-07-25T01:00:00Z",
                                       ["2026-07-25T03:10:00Z", "2026-07-24T00:00:00Z"]),
          "2026-07-25T03:10:00Z")
    check("cutoff: no gesture and no automatic receipt => no window (full historical count)",
          effective_readmission_cutoff(None, []), None)
    check("cutoff: WINDOW_UNREADABLE wins outright — an automatic stamp never masks an "
          "unreadable timeline (the ladder must FREEZE)",
          effective_readmission_cutoff(WINDOW_UNREADABLE, ["2026-07-25T03:10:00Z"]),
          WINDOW_UNREADABLE)
    logs.clear()
    check("cutoff: a malformed automatic stamp is dropped loudly, never minting a window",
          effective_readmission_cutoff(None, ["zzz"], log=logs.append), None)
    check("cutoff: the dropped stamp is logged loudly",
          any("::warning::readmission window" in line and "unprovable time" in line
              for line in logs), True)
    check("cutoff: spellings are canonicalized like every other window key",
          effective_readmission_cutoff(None, ["2026-07-25 03:10:00Z"]), "2026-07-25T03:10:00Z")

    # ---- park_applications: the shared park-application view both paths read ----
    timelines[41] = [machine_park]
    timelines[7] = [machine_park_issue]
    check("park_applications: the latest application across BOTH surfaces",
          park_applications("o/r", 41, 7, fetch, is_human=trusted)[0],
          parse_ts("2026-07-25T02:19:49Z"))
    check("park_applications: no application anywhere is not an error",
          park_applications("o/r", 43, None, fetch, is_human=trusted), (None, False, True))
    check("park_applications: an unreadable surface is reported, never guessed",
          park_applications("o/r", 41, 404, fetch, is_human=trusted, log=logs.append),
          (None, False, False))

    # ---- [registry #769] age_park_episode: which mechanism's park is this `review:parked`? ----
    # The consumer is dispatch-claim's automatic re-admission sweep, which drives this END TO END
    # against the real groom module; these are the unit-level directions, including the ones the
    # sweep's fixtures cannot cheaply reach.
    logs.clear()
    _epi_bot = "app[bot]"

    def _epi(body, at, login=_epi_bot):
        return {"user": {"login": login}, "body": body, "created_at": at}

    _age = f"{GROOM_AGE_PARK_MARKER} cause=orphan-draft head={'c' * 40} gen=1 -->"
    _ladder = "<!-- sparq-park-generation:v1 gen=1 cutoff=none -->"
    _sup = ("<!-- sparq-park-generation:v1", PARK_REASON_MARKER)
    _live = (MACHINE_PARK_PR_LABEL,)

    def _total(labels, comments, bot):
        """age_park_episode, but TOTAL: a raise becomes a value. An assertion that crashes on a
        mutant reports a crash-kill, which hides which guard failed."""
        try:
            return age_park_episode(labels, comments, bot, _sup)
        except Exception as exc:      # noqa: BLE001 — the point is to name the class
            return type(exc).__name__

    # CLAUSE 0 first, because it is the one that decides whether the question is even asked. A PR
    # with no live PR-side park still reaches the re-admission sweep through its source issue's
    # `status:parked`, and it can still carry an age receipt from an EARLIER, already-closed
    # episode. Judging that receipt would refuse an issue-side capacity park groom has no exit
    # for — a stranding this predicate must not cause. Every hold spelling is driven because the
    # label set here is the PR's own, not the pair.
    for _absent in ((), ("review:needs", "needs:user"), ("status:parked",), None):
        check(f"age_park_episode: NO live `{MACHINE_PARK_PR_LABEL}` ({_absent!r}) => the "
              "predicate declines to answer, however loud the age receipt",
              age_park_episode(_absent, [_epi(_age, "2026-07-26T10:00:00Z")], _epi_bot, _sup),
              (False, ""))
    check("age_park_episode: INERT with no age receipt — the entire existing capacity "
          "population reaches no new branch (this is what keeps #691's exit intact)",
          age_park_episode(_live, [_epi("nothing here", "2026-07-26T10:00:00Z"),
                                   _epi(_ladder, "bad-stamp")], _epi_bot, _sup,
                           log=logs.append),
          (False, ""))
    check("age_park_episode: ...and an inert answer parses no stamps at all, so a malformed one "
          "cannot make a non-age park unreadable", logs, [])
    check("age_park_episode: a bot age receipt with no later foreign park receipt is groom's",
          age_park_episode(_live, [_epi(_age, "2026-07-26T10:00:00Z")], _epi_bot, _sup)[0], True)
    check("age_park_episode: TRUST FILTER — a third party cannot forge an age receipt and "
          "freeze a genuine capacity park",
          age_park_episode(_live, [_epi(_age, "2026-07-26T10:00:00Z", login="drive-by")],
                           _epi_bot, _sup),
          (False, ""))
    check("age_park_episode: a STRICTLY newer foreign park receipt CLOSES the episode — the "
          "label is that mechanism's park now, and the capacity path must resume",
          age_park_episode(_live, [_epi(_age, "2026-07-26T10:00:00Z"),
                            _epi(_ladder, "2026-07-26T11:00:00Z")], _epi_bot, _sup)[0],
          False)
    check("age_park_episode: a TIE does NOT close it — the ambiguous case leaves the park alone",
          age_park_episode(_live, [_epi(_age, "2026-07-26T10:00:00Z"),
                            _epi(_ladder, "2026-07-26T10:00:00Z")], _epi_bot, _sup)[0],
          True)
    check("age_park_episode: an OLDER foreign receipt does not close a NEWER age park",
          age_park_episode(_live, [_epi(_ladder, "2026-07-26T09:00:00Z"),
                            _epi(_age, "2026-07-26T10:00:00Z")], _epi_bot, _sup)[0],
          True)
    check("age_park_episode: the NEWEST age receipt is the boundary, not the oldest",
          age_park_episode(_live, [_epi(_age, "2026-07-26T09:00:00Z"),
                            _epi(_ladder, "2026-07-26T10:00:00Z"),
                            _epi(_age, "2026-07-26T11:00:00Z")], _epi_bot, _sup)[0],
          True)
    check("age_park_episode: groom's OWN un-park receipt is not a foreign park — receipt-first "
          "ordering makes receipt-no-label groom's convergence to complete, not this sweep's",
          age_park_episode(
              _live,
              [_epi(_age, "2026-07-26T10:00:00Z"),
               _epi(f"{GROOM_AGE_UNPARK_MARKER} cause=orphan-draft head={'c' * 40} gen=1 -->",
                    "2026-07-26T11:00:00Z")], _epi_bot, _sup)[0],
          True)
    check("age_park_episode: FAIL CLOSED — once an age receipt exists, an unreadable bot stamp "
          "leaves the boundary unprovable and the park stays with groom",
          age_park_episode(_live, [_epi(_age, "2026-07-26T10:00:00Z"),
                            _epi(_ladder, None)], _epi_bot, _sup, log=logs.append)[0],
          True)
    check("age_park_episode: no bot identity, a non-list and a malformed row are all inert",
          [_total(_live, [_epi(_age, "2026-07-26T10:00:00Z")], ""),
           _total(_live, "not a list", _epi_bot),
           _total(_live, [None, "x", {"user": None, "body": None}], _epi_bot),
           # A non-empty NON-DICT `user` is the shape the house spelling raises on. This runs
           # inside the sweep's per-PR try, which catches DispatchError only — so an exception
           # here would abort the whole tick instead of skipping one PR. `_total` turns a raise
           # into a VALUE so this reports WHICH guard failed rather than a bare traceback.
           _total(_live, [{"user": ["nope"], "body": _age},
                          {"user": "nope", "body": _age}], _epi_bot),
           _total(_live, [{"body": _age}], _epi_bot)],
          [(False, ""), (False, ""), (False, ""), (False, ""), (False, "")])
    # THE MARKERS ARE WIRE FORMAT, and nothing else in this tree can notice a rename. groom
    # ALIASES these constants, and every fixture on both sides is built from the alias, so a
    # renamed marker stays perfectly self-consistent across all three suites while ORPHANING
    # every receipt already durable on a live PR: the un-park sweep stops recognising its own
    # parks, and the re-admission sweep stops recognising groom's. The version suffix is what
    # makes that a deliberate act rather than a refactor, so the literal is pinned here — the
    # ONE place a rename has to be argued for.
    check("age_park_episode: the marker spellings are WIRE FORMAT — a rename orphans every "
          "receipt already durable on a live PR, so it must be a version bump, never a refactor",
          (GROOM_AGE_PARK_MARKER, GROOM_AGE_UNPARK_MARKER),
          ("<!-- registry-groom-age-park:v1", "<!-- registry-groom-age-unpark:v1"))
    check("age_park_episode: `foreign-episode` is a declared code and is EXIT-REACHABLE — the "
          "census must never file it as needing a human",
          (PARK_REFUSAL_FOREIGN_EPISODE in PARK_REFUSAL_CODES,
           park_refusal_exit_class(PARK_REFUSAL_FOREIGN_EPISODE),
           PARK_REFUSAL_FOREIGN_EPISODE in PARK_REFUSAL_HUMAN_TERMINAL),
          (True, "exit-reachable", False))

    # ---- the predicate is PER-CLASS, not per-mechanism: the conflict resolver's stuck-attempt
    # park is the second cause-gated writer of `review:parked`, and it acquired #769's defect on
    # a program #769 did not touch. Its exit is the resolver's own cause proof (the head moving,
    # the conflict resolving), so the sustained-fleet-health heuristic — whose only condition
    # this class can satisfy is BEING OLD ENOUGH — must not reach it either. ----
    _stuck = (f"{CONFLICT_STUCK_PARK_MARKER} cause=head-unmoved head={'b' * 40} gen=1 -->")
    check("cause_gated_park_episode: the CONFLICT RESOLVER's stuck-attempt park is bound too, "
          "and the detail names WHICH mechanism owns the exit",
          (cause_gated_park_episode(_live, [_epi(_stuck, "2026-07-28T10:00:00Z")],
                                    _epi_bot, _sup)[0],
           "conflict resolver" in cause_gated_park_episode(
               _live, [_epi(_stuck, "2026-07-28T10:00:00Z")], _epi_bot, _sup)[1],
           "groom" in cause_gated_park_episode(
               _live, [_epi(_stuck, "2026-07-28T10:00:00Z")], _epi_bot, _sup)[1]),
          (True, True, False))
    check("cause_gated_park_episode: CONTROL — the groom age park still answers with GROOM's "
          "detail, so the two owners are not collapsed into one another",
          ("groom" in cause_gated_park_episode(
              _live, [_epi(_age, "2026-07-28T10:00:00Z")], _epi_bot, _sup)[1],
           "conflict resolver" in cause_gated_park_episode(
               _live, [_epi(_age, "2026-07-28T10:00:00Z")], _epi_bot, _sup)[1]),
          (True, False))
    check("cause_gated_park_episode: with BOTH owners on record the NEWEST receipt names the "
          "episode — an older mechanism cannot claim a park a newer one has since applied",
          ("conflict resolver" in cause_gated_park_episode(
              _live, [_epi(_age, "2026-07-28T09:00:00Z"), _epi(_stuck, "2026-07-28T10:00:00Z")],
              _epi_bot, _sup)[1],
           "groom" in cause_gated_park_episode(
               _live, [_epi(_stuck, "2026-07-28T09:00:00Z"), _epi(_age, "2026-07-28T10:00:00Z")],
               _epi_bot, _sup)[1]),
          (True, True))
    check("cause_gated_park_episode: a stuck-attempt park is superseded on exactly the same "
          "rule the age park is — strictly newer, ties leave the park alone",
          (cause_gated_park_episode(
              _live, [_epi(_stuck, "2026-07-28T10:00:00Z"),
                      _epi(PARK_REASON_MARKER, "2026-07-28T11:00:00Z")], _epi_bot, _sup)[0],
           cause_gated_park_episode(
               _live, [_epi(_stuck, "2026-07-28T10:00:00Z"),
                       _epi(PARK_REASON_MARKER, "2026-07-28T10:00:00Z")], _epi_bot, _sup)[0]),
          (False, True))
    check("cause_gated_park_episode: the stuck-attempt marker spellings are WIRE FORMAT too, and "
          "`age_park_episode` is the SAME object (dispatch-claim's call site cannot drift)",
          (CONFLICT_STUCK_PARK_MARKER, CONFLICT_STUCK_UNPARK_MARKER,
           age_park_episode is cause_gated_park_episode,
           tuple(marker for marker, _n, _w in CAUSE_GATED_PARK_OWNERS)),
          ("<!-- conflict-resolver stuck-park:v1", "<!-- conflict-resolver stuck-unpark:v1", True,
           (GROOM_AGE_PARK_MARKER, CONFLICT_STUCK_PARK_MARKER)))
    logs.clear()

    # ---- probe_maintainer (round-3 Opus finding): a probe-call FAILURE warns loudly and
    # fails toward not-human; a genuine not-a-maintainer stays quiet ----
    logs.clear()

    def broken_probe(_login):
        raise RuntimeError("collaborator API unavailable")

    check("probe-call failure => not human", probe_maintainer("o/r", "jeswr", broken_probe,
                                                              log=logs.append), False)
    check("probe-call failure emits the distinct ::warning:: diagnostic",
          logs, ["::warning::maintainer probe FAILED for o/r actor=jeswr (RuntimeError) — "
                 "treating as not-human"])
    logs.clear()
    check("genuine not-a-maintainer stays quiet and False",
          (probe_maintainer("o/r", "drive-by", lambda login: "read", log=logs.append), logs),
          (False, []))
    check("a clean 404 (None permission) stays quiet and False",
          (probe_maintainer("o/r", "ghost", lambda login: None, log=logs.append), logs),
          (False, []))
    check("a maintainer permission passes",
          probe_maintainer("o/r", "jeswr", lambda login: "admin"), True)

    # ---- G4: the machine-readable park-reason marker ----------------------------------------
    bot = "sparq-orchestrator[bot]"

    def bot_comment(body, login=bot):
        return {"user": {"login": login}, "body": body}

    check("every taxonomy cause resolves to a class",
          sorted({park_cause_class(cause) for cause in PARK_CAUSES}),
          [PARK_CLASS_CAPACITY, PARK_CLASS_QUESTION])
    check("an unknown cause has NO class (callers treat it as a human question)",
          park_cause_class("not-a-cause"), None)
    # registry #677: the dispatcher's crate-partition starvation park. It is a CAPACITY action
    # (a scheduling decision about the fleet, never a judgement about the diff), so it must land
    # on the MACHINE-owned soft hold and inherit the machine exit. If this ever flipped to the
    # question class the sweep would start writing `needs:user` — the terminal human hold
    # registry #703 says parks must not be a conveyor into.
    check("the partition-starvation cause is CAPACITY-class (never the human terminal)",
          park_cause_class("partition"), PARK_CLASS_CAPACITY)
    check("the partition-starvation cause is not a human-only cause",
          "partition" in PARK_HUMAN_ONLY_CAUSES, False)
    check("the partition marker renders class=capacity",
          park_reason_marker("partition"),
          "<!-- sparq-park-reason:v1 class=capacity cause=partition -->")
    check("the marker DERIVES class from the cause (a writer cannot contradict the taxonomy)",
          park_reason_marker("budget", generation=1, head="abc123"),
          "<!-- sparq-park-reason:v1 class=capacity cause=budget gen=1 head=abc123 -->")
    check("a question cause renders class=question",
          park_reason_marker("injection"),
          "<!-- sparq-park-reason:v1 class=question cause=injection -->")
    for bad in ("unknown-cause", "", None):
        try:
            park_reason_marker(bad)
            check(f"writing an unrepresentable cause {bad!r} RAISES", "no raise", "ValueError")
        except ValueError:
            check(f"writing an unrepresentable cause {bad!r} RAISES", "ValueError", "ValueError")
    check("round-trip: parse recovers what the writer wrote",
          parse_park_reason(f"prose\n\n{park_reason_marker('budget', 2, 'deadbeef')}"),
          {"class": "capacity", "cause": "budget", "gen": "2", "head": "deadbeef"})
    check("optional fields absent parse as None",
          parse_park_reason(park_reason_marker("injection")),
          {"class": "question", "cause": "injection", "gen": None, "head": None})
    # THE load-bearing rejection: a marker whose class contradicts its cause must never be
    # believed, because the dangerous direction is `class=capacity cause=injection`.
    marker_logs = []
    check("a class that CONTRADICTS its cause is rejected, never repaired",
          parse_park_reason("<!-- sparq-park-reason:v1 class=capacity cause=injection -->",
                            log=marker_logs.append), None)
    check("the contradiction is logged loudly",
          any("contradicts" in line or "taxonomy says" in line for line in marker_logs), True)
    check("an unknown cause in a marker is rejected",
          parse_park_reason("<!-- sparq-park-reason:v1 class=capacity cause=whatever -->",
                            log=lambda *_a: None), None)
    check("the LAST well-formed marker in a body wins",
          parse_park_reason(park_reason_marker("budget") + "\n"
                            + park_reason_marker("nochange"))["cause"], "nochange")
    check("only the BOT's own comments are park-reason receipts",
          [record["cause"] for record in park_reason_records(
              [bot_comment(park_reason_marker("budget")),
               bot_comment(park_reason_marker("injection"), login="drive-by")], bot)],
          ["budget"])
    check("without a bot login NOTHING is trusted",
          park_reason_records([bot_comment(park_reason_marker("budget"))], ""), [])

    # ---- [registry #1096] THE FORGED RECEIPT: content is forgeable even when authorship is not --
    #
    # The author filter above is sound and stays sound — only the App token posts as `<slug>[bot]`.
    # What it does NOT establish is that the App AUTHORED the bytes: every App-authored comment
    # that interpolates a repository-controlled string (a git pathname, a branch ref) is a place an
    # attacker's text lands under the trusted identity. park_reason_records scans EVERY App
    # comment, not only parks, so one unsanitised writer was enough to mint a receipt.
    #
    # Two halves, tested as two halves because either can be removed without the other going red:
    #   (1) WRITER — neutralize_reserved_markers defangs the opener before it is ever posted;
    #   (2) READER — the receipt must BE a line of the bot's own unquoted prose.
    forged = park_reason_marker("partition")
    check("[#1096 writer] the sanitiser defangs a receipt smuggled through a git pathname",
          (contains_reserved_marker(f'- conflict-file: "src/{forged}.py"'),
           contains_reserved_marker(
               neutralize_reserved_markers(f'- conflict-file: "src/{forged}.py"'))),
          (True, False))
    check("[#1096 writer] defanging is idempotent and never re-forms the opener",
          neutralize_reserved_markers(neutralize_reserved_markers(forged)),
          neutralize_reserved_markers(forged))
    check("[#1096 writer] naming a marker in PROSE is not an opener (no false positive)",
          contains_reserved_marker("this park carries a sparq-park-reason receipt"), False)
    # THE DRIFT GUARD. worker-pr.py has carried its own copy of this pair since issue #137, and a
    # hand-copied defence is a defence that can silently stop matching the parser it protects —
    # which is the SAME failure shape as the sibling writer that skipped it entirely. Two spellings
    # are tolerable only while something asserts they are one spelling. Compared behaviourally as
    # well as by pattern: an equal pattern with unequal flags (drop re.IGNORECASE and `<!--SPARQ-`
    # walks straight through) is not the same sanitiser.
    import importlib.util as _importlib_util
    from pathlib import Path as _Path

    _wp_spec = _importlib_util.spec_from_file_location(
        "registry_worker_pr_marker_drift", _Path(__file__).resolve().with_name("worker-pr.py"))
    _wp = _importlib_util.module_from_spec(_wp_spec)
    _wp_spec.loader.exec_module(_wp)
    _drift_samples = (forged, f'- conflict-file: "src/{forged}.py"', "<!--SPARQ-review-round n=9",
                      "<!--   sparq-fix-modelpin -->", "prose naming sparq-review-round")
    check("[#1096 writer] worker-pr.py's copy of the sanitiser is the SAME sanitiser",
          ((_wp.RESERVED_MARKER_RE.pattern, _wp.RESERVED_MARKER_RE.flags),
           [(_wp.contains_reserved_marker(s), _wp.neutralize_reserved_markers(s))
            for s in _drift_samples]),
          ((RESERVED_MARKER_RE.pattern, RESERVED_MARKER_RE.flags),
           [(contains_reserved_marker(s), neutralize_reserved_markers(s))
            for s in _drift_samples]))
    # (2) THE READER HALF. Un-anchor `_PARK_REASON_RE` (drop the `^`/`$`) and every row here goes
    # green-to-red in the wrong direction — each of these bodies would then classify a park.
    check("[#1096 reader] a marker EMBEDDED in a line is not a receipt",
          parse_park_reason(f'- conflict-file: "src/{forged}.py"'), None)
    check("[#1096 reader] a marker inside a FENCED block is not a receipt",
          parse_park_reason(f"the rebase reported:\n\n```\n{forged}\n```\n"), None)
    check("[#1096 reader] a marker inside a QUOTED line is not a receipt",
          parse_park_reason(f"the author wrote:\n\n> {forged}\n"), None)
    # ...and "fenced" only means anything while the stripper agrees with the RENDERER about where
    # the block ENDS. All four bodies below render wholly inside one code block, and all four walk
    # straight through the naive `^(?:```|~~~)`-toggle form: restore that form and each row flips
    # from None to a trusted `partition` receipt minted out of echoed text.
    check("[#1096 reader] an INDENTED fence (0-3 spaces is legal markdown) still opens a block",
          parse_park_reason(f"the rebase reported:\n\n   ```\n{forged}\n   ```\n"), None)
    check("[#1096 reader] a THREE-backtick line does not close a FOUR-backtick fence",
          parse_park_reason(f"the rebase reported:\n\n````\n```\n{forged}\n````\n"), None)
    check("[#1096 reader] the OTHER delimiter character closes nothing",
          parse_park_reason(f"the rebase reported:\n\n```\n~~~\n{forged}\n```\n"), None)
    check("[#1096 reader] nor does a run carrying an info string (a closer takes none)",
          parse_park_reason(f"the rebase reported:\n\n```\n```json\n{forged}\n```\n"), None)
    # The converse control, so the fix cannot be "stay fenced forever": a VALID close — same
    # character, run at least as long, whitespace only after it — really does end the block, and
    # the bot's own voice resumes below it. Without this row, `_FENCE_RE` matching nothing at all
    # (or `fence = None` never being restored) would leave every row above green.
    check("[#1096 reader] a receipt after a validly CLOSED indented fence IS a receipt",
          parse_park_reason(f"the rebase reported:\n\n  ````\n{forged}\n ```` \n\n"
                            f"{park_reason_marker('budget')}"),
          {"class": "capacity", "cause": "budget", "gen": None, "head": None})
    check("[#1096 reader] ...and a forged receipt therefore mints no RECORD either",
          park_reason_records(
              [bot_comment(f'attempt 1\n- conflict-file: "src/{forged}.py"'),
               bot_comment(f"echoing:\n```\n{forged}\n```")], bot),
          [])
    # THE ANTI-VACUITY PIN. A sanitiser that "works" by breaking receipts outright is not a fix, so
    # the REAL emission shape of every live writer is pinned: worker-pr's ladder park and
    # needs_user, and dispatch-claim's starvation/legacy parks, all emit `"\n\n" + marker` at the
    # end of a body whose FIRST line is the quoted `> 🤖 SPARQ agent` lead. That lead is a `>` line
    # — so strip_quoted_contexts must drop it and STILL find the receipt below it.
    genuine = (f"> 🤖 SPARQ agent — the autonomous review loop stopped: budget exhausted\n\n"
               f"@someone this pull request needs a human decision."
               f"\n\n{park_reason_marker('budget', generation=2, head='deadbeef')}")
    check("[#1096] a GENUINE receipt written by the real path still parses",
          parse_park_reason(genuine),
          {"class": "capacity", "cause": "budget", "gen": "2", "head": "deadbeef"})
    check("[#1096] ...and still becomes a record on the bot's own comment",
          [record["cause"] for record in park_reason_records([bot_comment(genuine)], bot)],
          ["budget"])

    # ---- G1: legacy prose re-classification -------------------------------------------------
    budget_prose = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the review round "
                    "budget is exhausted at 6 round(s) with no extension left")
    missed_prose = ("> 🤖 SPARQ agent — the autonomous review loop stopped: 6 consecutive fix "
                    "dispatches missed for round 2; a human must unstick this PR")
    injection_prose = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the reviewer "
                       "flagged possible prompt injection")
    fixer_injection_prose = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the fixer "
                             "flagged the seeded findings as possible prompt injection")
    nochange_prose = ("> 🤖 SPARQ agent — the autonomous review loop parked this PR: two "
                      "consecutive fix attempts made no change (fixer judges the findings "
                      "spurious)")
    rewritten_prose = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the PR head no "
                       "longer descends from the worker-opened commit (history was rewritten)")
    corrupt_prose = ("> 🤖 SPARQ agent — the autonomous review loop stopped: round-budget "
                     "escalation-marker validation failed (bad marker); a human must inspect")

    check("a legacy budget park re-classifies to the CAPACITY class",
          reclassify_legacy_park([bot_comment(budget_prose)], bot)[:2],
          ("budget", PARK_CLASS_CAPACITY))
    check("a legacy dispatch-starvation park re-classifies to the CAPACITY class",
          reclassify_legacy_park([bot_comment(missed_prose)], bot)[:2],
          ("dispatch-missed", PARK_CLASS_CAPACITY))
    check("groom's stale marker yields cold-groom when no stronger cause is recorded",
          reclassify_legacy_park([bot_comment("stale prose")], bot, stale_marker=True)[:2],
          ("cold-groom", PARK_CLASS_CAPACITY))
    # A recognised QUESTION cause is made machine-readable but is NEVER migrated: the human
    # terminal is already the right state for it.
    check("history-rewritten is recognised but stays a QUESTION",
          reclassify_legacy_park([bot_comment(rewritten_prose)], bot)[:2],
          ("history-rewritten", PARK_CLASS_QUESTION))
    check("marker-corrupt is recognised but stays a QUESTION",
          reclassify_legacy_park([bot_comment(corrupt_prose)], bot)[:2],
          ("marker-corrupt", PARK_CLASS_QUESTION))
    check("an unrecognised park stays put (an unreadable cause is a human question)",
          reclassify_legacy_park([bot_comment("something went wrong")], bot)[0], None)
    # The receipt is on its OWN LINE, exactly as every writer emits it (`"\n\n" + marker`), because
    # since #1096 that is what a receipt IS — a marker glued onto the end of a prose line is echoed
    # text, not an assertion.
    check("a park that ALREADY carries a reason marker is not legacy",
          reclassify_legacy_park(
              [bot_comment(budget_prose + "\n\n" + park_reason_marker("budget"))], bot)[0], None)
    check("prose in a NON-bot comment can never classify a park",
          reclassify_legacy_park([bot_comment(budget_prose, login="drive-by")], bot)[0], None)

    # THE guard. Every one of the six genuine sparq escalations (#3542 #3563 #3608 #3609 #3618
    # #3743) is refused. #3743 and #3608 are the load-bearing fixtures: each carries a genuine
    # injection flag AND a LATER capacity-park comment, so any "newest cause wins" rule would
    # hand them back to the machine.
    genuine = {
        "#3542": [bot_comment("round 1: request_changes"), bot_comment(injection_prose)],
        "#3563": [bot_comment("round 1: approve"), bot_comment(injection_prose)],
        "#3608": [bot_comment(nochange_prose), bot_comment(fixer_injection_prose)],
        "#3609": [bot_comment(injection_prose), bot_comment("round 2: approve"),
                  bot_comment(injection_prose)],
        "#3618": [bot_comment(injection_prose), bot_comment("round 3: approve"),
                  bot_comment(injection_prose)],
        # the exact live shape: injection FIRST, capacity park LAST.
        "#3743": [bot_comment(injection_prose), bot_comment(nochange_prose)],
    }
    for name, fixture in genuine.items():
        cause, park_class, _detail = reclassify_legacy_park(fixture, bot)
        check(f"genuine escalation {name} is REFUSED re-classification",
              (cause, park_class), (None, None))
    # ...and order-independence is the property, not an accident of these fixtures.
    check("deny wins even when the injection flag is the OLDEST comment",
          reclassify_legacy_park(
              [bot_comment(injection_prose), bot_comment(budget_prose)], bot)[0], None)
    check("deny wins even when the injection flag is the NEWEST comment",
          reclassify_legacy_park(
              [bot_comment(budget_prose), bot_comment(injection_prose)], bot)[0], None)

    # ---- [registry #814] THE DENY IS THE LOOP'S OWN SENTENCE, NOT THE PHRASE -----------------
    # worker-pr.post_findings REPUBLISHES model-derived verdict text under the bot's identity, and
    # reviewers routinely report the ABSENCE of injection in it — so a rule matching the phrase
    # ANYWHERE in the bot history fires on a sentence asserting the OPPOSITE of the signal, and
    # pins the PR to the human terminal with no machine exit, forever. The three summaries below
    # are the VERBATIM live text of the three PRs measured doing exactly that (sparq-org/sparq,
    # 2026-07-27). They are quoted from the population and derive from nothing this module
    # defines, so widening the rule back toward "any occurrence of the phrase" reds this block.
    republished_negations = {
        "#3901": "No instruction-like prompt injection was detected in the diff.",
        "#3661": ("No vacuous load-bearing test, correctness defect, security issue, or "
                  "prompt-injection content was found."),
        "#3554": ("No correctness, soundness, test-validity, security, or prompt-injection issue "
                  "remains in the diff-scoped evidence."),
    }
    for name, summary in republished_negations.items():
        negation_findings = ("> 🤖 SPARQ agent — cross-provider review round 2: **approve**."
                             f"\n\n{summary}")
        check(f"[#814] a republished verdict NEGATING injection ({name}) matches no deny pattern",
              [cause for pattern, cause in LEGACY_PARK_DENY_PROSE
               if pattern.search(negation_findings)], [])
        # ...and the park behind it actually REACHES a machine exit: it re-classifies on its own
        # recorded cause. Pinning the cause (not merely "not refused") is what makes this a
        # delivery check rather than a restatement of the row above.
        check(f"[#814] ...so a legacy park carrying it ({name}) re-classifies on its own cause",
              reclassify_legacy_park(
                  [bot_comment(negation_findings), bot_comment(nochange_prose)], bot)[:2],
              ("nochange", PARK_CLASS_CAPACITY))
    # THE OTHER DIRECTION, in the SAME comment shape — which is what makes the pair a real
    # discrimination test rather than two unrelated fixtures. But in THIS shape the discriminator
    # cannot be the sentence: the findings site (worker-pr.INJECTION_PROSE_FINDINGS) is the one
    # injection writer whose comment REPUBLISHES model text, so every line under its lead is the
    # model's and its prose establishes only that the prose is there. What separates the two rows
    # below is `review_injection_marker` — appended by post_findings AFTER the sink's
    # `neutralize_reserved_markers` pass, so no model field can carry one across it.
    findings_escalation = ("> 🤖 SPARQ agent — cross-provider review round 2: "
                           "**request_changes**.\n\nThe diff seeds instruction-like text into a "
                           "fixture.\n\n⚠️ The reviewer flagged possible prompt-injection "
                           "content; escalating to a human.")
    check("[#814 r2] the findings site's escalation DENIES when it carries the machine receipt",
          reclassify_legacy_park(
              [bot_comment(findings_escalation + "\n\n" + review_injection_marker(2)),
               bot_comment(nochange_prose)], bot)[:2],
          (None, None))
    check("[#814 r2] ...and the SAME sentence WITHOUT the receipt denies nothing — an unreceipted "
          "findings body is exactly what a reviewer republishing that sentence produces",
          reclassify_legacy_park(
              [bot_comment(findings_escalation), bot_comment(nochange_prose)], bot)[:2],
          ("nochange", PARK_CLASS_CAPACITY))
    # THE FORGERIES THE PROSE RULE CANNOT SEE, one per injection pattern, each placed exactly
    # where `post_findings` lands a model's `summary`. Both are byte-for-byte matches for a deny
    # pattern — the first row of each pair asserts that, so the second cannot pass merely because
    # the fixture stopped matching — and both must be INERT, because `injection_detected` was
    # false and nothing machine-authored says otherwise. Drop the `republishes_model_text` arm
    # from `legacy_deny_signal` and every second row goes red.
    forged_by_model = {
        "the escalation sentence": ("The reviewer flagged the fixture below as possible "
                                    "prompt-injection bait, quoted verbatim from the diff."),
        "the machine stop lead": ("The PR body claims `the autonomous review loop stopped: "
                                  "prompt-injection content was seeded` — it did not."),
    }
    for shape, summary in forged_by_model.items():
        forged = ("> 🤖 SPARQ agent — cross-provider review round 1: **request_changes**."
                  f"\n\n{summary}")
        check(f"[#814 r2] a model forging {shape} into a republished verdict really does match "
              "the raw prose table",
              bool([cause for pattern, cause in LEGACY_PARK_DENY_PROSE
                    if pattern.search(forged)]), True)
        check(f"[#814 r2] ...and is still NOT a signal, because the LOOP did not write it",
              (legacy_deny_signal(forged),
               reclassify_legacy_park(
                   [bot_comment(forged), bot_comment(nochange_prose)], bot)[:2]),
              (None, ("nochange", PARK_CLASS_CAPACITY)))
    # ...and the republish test walks past LEADING BLANK LINES to find the lead. GitHub round-trips
    # bodies through editors that add them, and the fail direction of stopping at the first line
    # unconditionally is the wrong one: a findings body with a blank first line would fall through
    # to the prose table and be read as the loop's own voice again. An EMPTY body republishes
    # nothing — there is no lead to trust — so it stays with the prose table.
    check("[#814 r2] a leading blank line does not hide a republish; an empty body is not one",
          [republishes_model_text("\n\n" + findings_escalation), republishes_model_text(""),
           republishes_model_text("   \n \n"),
           reclassify_legacy_park(
               [bot_comment("\n\n" + findings_escalation), bot_comment(nochange_prose)],
               bot)[:2]],
          [True, False, False, ("nochange", PARK_CLASS_CAPACITY)])
    # The receipt is read under the #1096 discipline — a WHOLE LINE of the bot's own unquoted
    # prose. The writer-side sanitiser already stops a model field reaching the reserved
    # namespace at all; this is the reader-side half, and it must hold on its own.
    _receipt = review_injection_marker(2)
    check("[#814 r2] an ECHOED review-injection receipt is not a receipt (quoted, fenced, or "
          "embedded in a line) — only an asserted one is",
          [carries_review_injection_receipt(f"> 🤖 SPARQ agent — round 1.\n\n> {_receipt}"),
           carries_review_injection_receipt(f"> 🤖 SPARQ agent — round 1.\n\n```\n{_receipt}\n```"),
           carries_review_injection_receipt(f"the reviewer echoed {_receipt} back"),
           carries_review_injection_receipt(f"> 🤖 SPARQ agent — round 1.\n\n{_receipt}")],
          [False, False, False, True])
    # ...and the writer can never REFUSE to render: this receipt rides on the comment that
    # escalates an injection flag to a human, so an unrepresentable round degrades the field away
    # (still a parseable receipt) instead of raising and taking the escalation comment with it.
    # The raise is CAUGHT rather than allowed to abort: a writer that raises here must red ONE
    # named row, not kill every row below it (AGENTS.md pre-flight item 4, crash-after-partial).
    def _rendered(round_n=None):
        try:
            return review_injection_marker(round_n)
        except Exception as exc:                    # noqa: BLE001 — refusing to render IS the bug
            return f"RAISED {type(exc).__name__}"

    check("[#814 r2] the receipt writer degrades an unsafe round rather than raising",
          [_rendered(3), _rendered("2 -->\nboom"), _rendered(),
           carries_review_injection_receipt(_rendered("2 -->\nboom"))],
          [f"{REVIEW_INJECTION_MARKER} round=3 -->", f"{REVIEW_INJECTION_MARKER} -->",
           f"{REVIEW_INJECTION_MARKER} -->", True])
    # THE TWO HALVES OF THE FIRST PATTERN ARE BOTH LOAD-BEARING, and each is pinned by a sentence
    # a reviewer plausibly writes. Neither of the two below is quoted from the live population —
    # they are CONSTRUCTED, and are labelled so rather than dressed up as measurement — but each
    # is a partial revert of this change that the three measured negations above cannot see:
    #   (i)  dropping the `flagged` half leaves "any occurrence of `possible prompt-injection`",
    #        which is the pre-#814 rule for exactly the population the issue names — a PR about
    #        injection DEFENCES, whose review says the words without ever raising the flag;
    #   (ii) unbounding the gap lets a `flagged` about something else, a clause away, pair with a
    #        NEGATED mention later in the same line.
    check("[#814] a verdict discussing injection without RAISING it is not a signal (the "
          "`flagged` half of the rule)",
          [cause for pattern, cause in LEGACY_PARK_DENY_PROSE
           if pattern.search("> 🤖 SPARQ agent — cross-provider review round 1: **approve**."
                             "\n\nThe fixture adds a possible prompt-injection vector to the "
                             "defence test; the guard handles it.")], [])
    check("[#814] a `flagged` about something ELSE cannot pair with a negated mention a clause "
          "away (the bounded-gap half of the rule)",
          [cause for pattern, cause in LEGACY_PARK_DENY_PROSE
           if pattern.search("> 🤖 SPARQ agent — cross-provider review round 1: **approve**."
                             "\n\nThe reviewer flagged 3 correctness defects and one "
                             "test-validity issue in the fixture harness; no possible "
                             "prompt-injection content was found.")], [])
    # ...and the narrowed rule is still not defeated by CASING, which is the one widening the two
    # rows above must not have taken with them: every deny pattern here has been case-insensitive
    # since it was written, and a security classifier a capital letter walks past is not one.
    check("[#814] the injection deny is not defeated by casing",
          [cause for pattern, cause in LEGACY_PARK_DENY_PROSE
           if pattern.search("⚠️ The Reviewer FLAGGED Possible Prompt-Injection content; "
                             "escalating to a human.")], ["injection"])
    # A machine park LEAD that names injection as the stop cause is denied even when it is worded
    # without the flagged/possible shape, so a reworded historical stop sentence stays refused.
    stop_lead_only = ("> 🤖 SPARQ agent — the autonomous review loop stopped: prompt-injection "
                      "content was seeded into the review findings; a human must decide")
    check("[#814] a machine STOP LEAD naming injection denies without the flagged/possible shape",
          reclassify_legacy_park(
              [bot_comment(stop_lead_only), bot_comment(nochange_prose)], bot)[:2], (None, None))
    # ...and it is the LEAD doing that work: the identical words with the machine lead removed are
    # ordinary republished prose and deny nothing. Without this control the row above would pass
    # for the first pattern's reason and the lead pattern could be deleted unnoticed.
    check("[#814] ...and the same words WITHOUT the machine lead are not a signal",
          [cause for pattern, cause in LEGACY_PARK_DENY_PROSE
           if pattern.search("prompt-injection content was seeded into the review findings; "
                             "a human must decide")], [])

    print("park-policy self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    parser.error("park_policy.py is a shared helper module; only --self-test runs standalone")
    return 2


if __name__ == "__main__":
    sys.exit(main())
