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
#    - MACHINE parks only. `needs:user` / `review:needs-user` and a park whose LATEST application
#      was made by a PROVEN HUMAN are never auto-re-admitted, and the sticky human-unpark veto
#      (invariant 2) is untouched — the automatic path only ever CLEARS a machine park, it never
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
from datetime import datetime, timezone


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


def park_applications(repo, pr_number, issue_number, fetch_events, is_human=None, log=print):
    """(latest_park_instant, latest_was_human, readable) for `repo#pr_number` and its
    provenance-linked source issue — the LATEST `labeled` event for ANY of READMISSION_LABELS
    across BOTH surfaces (round-5 finding 1: the recency proof must span the same surfaces and
    labels the readmission cutoff spans).

    `latest_park_instant` is a parsed aware datetime (None when no park label was ever applied
    on either surface — e.g. every write was veto-suppressed). `latest_was_human` is True when
    a PROVEN HUMAN (the strict maintainer probe; `is_human=None` can prove nothing and yields
    False) applied a park at that latest instant — a HUMAN-OWNED park, which the automatic
    re-admission path must never clear. `readable` is False on ANY read/shape failure, and
    every caller's documented fail direction on that is to STAY PARKED.

    Extracted verbatim from capacity_park_readmitted so the human path and the automatic path
    (capacity_park_admission) can never disagree about when a park was applied."""
    probe = _human_probe(is_human)
    latest, latest_human = None, False
    for number in [pr_number] + ([issue_number] if issue_number else []):
        try:
            events = fetch_events(repo, number)
            for label in READMISSION_LABELS:
                for created, kind, login, via_app in _event_rows(events, label):
                    if kind != "labeled":
                        continue
                    instant = parse_ts(created)
                    human = _is_proven_human(login, via_app, probe)
                    if latest is None or instant > latest:
                        latest, latest_human = instant, human
                    elif instant == latest and human:
                        # An instant tie between a human and a machine application resolves
                        # toward HUMAN-OWNED: the automatic path must never clear a park a
                        # human might have applied.
                        latest_human = True
        except Exception as exc:  # noqa: BLE001 — ambiguity stays parked
            log(f"readmission unknown: timeline read failed for {repo}#{number} ({exc}); "
                "the capacity park stands")
            return None, False, False
    return latest, latest_human, True


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
    probe = _human_probe(is_human)
    try:
        events = fetch_events(repo, number)
    except Exception as exc:  # noqa: BLE001 — an unreadable timeline proves nothing
        log(f"label ownership unknown for {repo}#{number} {label!r} ({exc}); not clearable")
        return False
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
        return False
    if newest is None:
        log(f"label ownership unknown for {repo}#{number} {label!r}: no `labeled` event exists, "
            "so nothing proves a machine applied it; not clearable")
        return False
    return not newest_human


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
PARK_REFUSAL_HUMAN_APPLIED = "human-applied"        # a proven human applied the park itself
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

# Which refusals a later tick can clear WITHOUT a human. The split is the whole point of the
# taxonomy, so it is data, not a predicate scattered across callers.
#
# `cap` is HUMAN-TERMINAL deliberately, and the refusal's own log line already says why: "an
# account that keeps flapping is a genuine human question; the park stands until a human acts".
# `evidence-consumed` is EXIT-REACHABLE: it demands a NEW outage-and-recovery pair, which a later
# tick can genuinely observe. `not-offered` is EXIT-REACHABLE because it is not a refusal about
# the PR at all — it is the CLAIM proof gate deliberately evaluating without minting.
PARK_REFUSAL_HUMAN_TERMINAL = frozenset({
    PARK_REFUSAL_HUMAN_HOLD, PARK_REFUSAL_HUMAN_APPLIED, PARK_REFUSAL_CAP,
})
PARK_REFUSAL_CODES = frozenset({
    PARK_REFUSAL_HUMAN_HOLD, PARK_REFUSAL_HUMAN_APPLIED, PARK_REFUSAL_CAP,
    PARK_REFUSAL_TIMELINE_UNREADABLE, PARK_REFUSAL_PROBE_FAILED, PARK_REFUSAL_NO_EVIDENCE,
    PARK_REFUSAL_EVIDENCE_MALFORMED, PARK_REFUSAL_EVIDENCE_CONSUMED,
    PARK_REFUSAL_EVIDENCE_STALE, PARK_REFUSAL_NOT_OFFERED,
    PARK_REFUSAL_READ_FAILED, PARK_REFUSAL_TICK_DEFERRED,
})

# The two ADMITTING actions and the human-gesture action are not refusals; they are recorded in
# the census under these codes so one census row exists per decision and the populations sum.
PARK_ADMIT_CODES = {"auto-mint": "admitted-auto-mint",
                    "auto-receipt": "admitted-auto-receipt",
                    "human": "admitted-human-gesture"}


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
                            census=None):
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

    EVERY ambiguity fails toward staying parked: an unreadable timeline, an unreadable/absent
    health record, a probe that raises, an unsafe evidence key, a recovery that is not STRICTLY
    after the park (a tie included), a human-owned label, a human-applied park, and the cap.

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
    latest_park, human_park, readable = park_applications(
        repo, pr_number, issue_number, fetch_events, is_human=is_human, log=log)
    if not readable:
        return _answer(None, None, PARK_REFUSAL_TIMELINE_UNREADABLE,
                       "the park application timeline could not be read")
    if human_park:
        return _answer(
            None, None, PARK_REFUSAL_HUMAN_APPLIED,
            "the latest park application is HUMAN-owned — only a human clears it")
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


_PARK_REASON_RE = re.compile(
    re.escape(PARK_REASON_MARKER)
    + r" class=(\S+) cause=(\S+?)(?: gen=(\S+))?(?: head=(\S+))? -->")


def parse_park_reason(body, log=print):
    """The LAST well-formed park-reason marker in `body` as
    {"class", "cause", "gen", "head"}, else None.

    A marker whose `class=` DISAGREES with its cause's registered class, or whose cause is
    outside the closed taxonomy, is REJECTED (dropped with a loud log), not repaired. Repairing it
    would mean choosing which half to believe, and the dangerous direction is obvious: a marker
    reading `class=capacity cause=injection` must never be read as a capacity park. Rejection
    leaves the park unclassified, which every consumer treats as a human question."""
    if not isinstance(body, str):
        return None
    found = None
    for match in _PARK_REASON_RE.finditer(body):
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

# --- [registry #814] THE INJECTION DENY IS AFFIRMATIVE-ONLY ----------------------------------
#
# THE DEFECT. The injection half of the deny table below used to be a bare substring rule —
# `prompt[- ]injection` matched ANYWHERE in the bot's own history. But the bot REPUBLISHES
# model-derived verdict text under its own identity (worker-pr.post_findings), and a reviewer
# reporting a CLEAN diff says exactly that, in those words. So the deny fired on a NEGATION and
# stranded three live sparq PRs on the HUMAN-owned terminal for a signal that is not there. Their
# real sentences (pinned verbatim as self-test fixtures below, so this can never silently regress):
#
#   #3554  "No correctness, soundness, test-validity, security, or prompt-injection issue remains
#           in the diff-scoped evidence."   and   "No instruction-like prompt injection appears in
#           the diff."
#   #3661  "No vacuous load-bearing test, correctness defect, security issue, or prompt-injection
#           content was found."
#   #3901  "No instruction-like prompt injection was detected in the diff."
#
# THE DIRECTION OF THIS CHANGE, STATED PLAINLY. Narrowing a deny WIDENS what automation may act
# on. This rule is the only thing keeping `reclassify_legacy_park` (and therefore
# dispatch-claim._migrate_legacy_park) and `reconcile-park-misescalation` from taking a security
# escalation out of a human's hands. It is therefore built to DENY BY DEFAULT and release ONLY on
# PROOF, in two tiers:
#
#   TIER A — an UNCONDITIONALLY affirmative marker ANYWHERE in the text denies, full stop, and no
#            negation anywhere can cancel it. Every one of the eight genuine live escalations
#            (#3542 #3563 #3585 #3608 #3609 #3618 #3743 #4406) carries one, because the prose
#            worker-pr writes at both injection park sites is "flagged possible prompt injection"
#            / "flagged possible prompt-injection content". Tier A is also what makes a body
#            carrying BOTH a negation and an affirmative fail CLOSED.
#   TIER B — every REMAINING mention denies UNLESS its negation is PROVEN: a recognised negator
#            must govern that mention from inside the mention's OWN sentence, with nothing between
#            the two that breaks the negator's reach (a contrast word, a coordination, or a verb
#            that starts a fresh predicate). "Cannot prove a negation" is NOT "is a negation" — it
#            denies.
#
# THE RELEASE CONDITION, in full: no affirmative marker anywhere AND every single mention proven
# negated. Everything else denies, including anything unclassifiable — a non-string body or a
# failure inside the classifier itself (see injection_prose_denied's except arm).
#
# WHAT DID NOT CHANGE. The mention TERM is byte-identical to the pattern this rule has always
# used (`prompt[- ]injection`, case-insensitive; the old separate `possible prompt injection`
# entry was strictly subsumed by it, and now appears as a Tier-A affirmative marker). Deny is
# still UNCONDITIONAL and ORDER-INDEPENDENT over the bot's whole history, the `human-arm` rule is
# untouched, and no other prose rule, cause, or label authority moves.

# The mention. Byte-identical to the historic deny pattern: #814 narrows WHEN a mention denies,
# never WHICH strings count as a mention.
_INJECTION_TERM = re.compile(r"prompt[- ]injection", re.IGNORECASE)

# TIER A. Intrinsically affirmative constructions. A match ANYWHERE denies unconditionally — a
# negation elsewhere in the body cannot cancel one of these, which is the fail-closed direction.
_INJECTION_AFFIRMATIVE = (
    # "possible prompt injection" / "possible prompt-injection content": the literal prose
    # worker-pr writes at both injection park sites, and the reason all eight genuine live
    # escalations deny. Note the deliberate consequence: "no possible prompt injection was found"
    # ALSO denies. That is the correct direction for a security deny — an affirmative noun phrase
    # is never talked away.
    re.compile(r"\b(?:possible|potential|suspected|apparent|likely|probable|attempted)\s+"
               r"prompt[- ]injection", re.IGNORECASE),
    # A FLAG verb reaching the mention without leaving the sentence — "the reviewer flagged
    # possible prompt injection", "the fixer flagged the seeded findings as possible prompt
    # injection".
    re.compile(r"\bflag(?:ged|ging|s)?\b[^.;!?\n]{0,80}?prompt[- ]injection", re.IGNORECASE),
    # An explicit affirmative field value — "prompt injection: yes".
    re.compile(r"prompt[- ]injection\s*[:=]\s*(?:yes|true|confirmed|detected|present)\b",
               re.IGNORECASE),
    # A mention naming an ACT rather than a category — "a prompt-injection attempt". The plural
    # is load-bearing: "No prompt-injection attemptS were found in round 1" is a search that came
    # up empty in ONE round, not a clean bill, and the singular-only form let every plural past.
    re.compile(r"prompt[- ]injection\s+(?:attempt|attack|payload|vector)s?\b", re.IGNORECASE),
)

# TIER B machinery — A POLARITY MODEL, NOT A NEGATOR SEARCH.
#
# THE PROPOSITION THIS MUST PROVE. The release condition is "the text asserts that injection is
# ABSENT". It is emphatically NOT "a negator governs the mention's predicate": those two come
# apart, and every case where they do releases text that asserts injection EXISTS —
#
#     "Prompt injection was not ruled out."          a negator, and it means PRESENT
#     "The prompt-injection risk was not mitigated." a negator, and it means PRESENT
#     "There is no evidence that prompt injection is absent."      likewise
#     "no doubt that prompt injection exists"                      likewise
#     "not sure whether prompt injection is present"               likewise
#     'The author claims: "No prompt injection was detected." That claim is false.'
#
# So Tier B computes a POLARITY over a SMALL CLOSED VOCABULARY and DENIES ON ANYTHING OUTSIDE IT.
# Three inputs, combined by one explicit table (_INJECTION_POLARITY):
#
#   1. VOICE — is the mention in the bot's OWN voice? A negation the bot merely REPORTS someone
#      else making is not the bot's finding of absence (and can be repudiated in the very next
#      sentence). A mention inside a quotation, or downstream of an attribution verb, DENIES.
#   2. PRE — does a recognised negator GOVERN the mention's noun phrase? It must sit in the
#      mention's own sentence, within a bounded reach, with nothing between the two that breaks
#      its reach: a contrast word, a coordination, a COMPLEMENTIZER ("no evidence THAT ...",
#      "not sure WHETHER ..." — where the negator negates the matrix noun, not the mention), a
#      verb starting a fresh predicate, or a comma that is not part of a coordinated noun list
#      ("No gate failures, prompt-injection content is present." is two clauses, not one).
#   3. TAIL — the polarity of the mention's OWN predicate, parsed against closed verb sets. The
#      load-bearing distinction is PRESENCE verbs (detected / found / appears / remains) against
#      ABSENCE verbs (ruled out / mitigated / fixed / addressed / resolved / absent). Negating a
#      PRESENCE verb yields absence; negating an ABSENCE verb yields PRESENCE. A tail the closed
#      grammar cannot parse at all is UNKNOWN, and UNKNOWN denies.
#
# "Cannot prove a negation" is not "is a negation" — everything unproven denies.
#
# Sentence scoping is DELIBERATELY over-eager (a bare `.`, `|` or newline ends a sentence):
# over-splitting can only shrink the window a negator is allowed to reach across, and a negator
# that cannot reach its mention leaves the mention DENYING. Over-splitting is fail-closed. It is
# also exactly why Tier A scans the WHOLE text: Tier A is the backstop for an affirmative marker
# that an over-eager split put out of Tier B's reach.
_INJECTION_SENTENCE_BOUNDARY = re.compile(r"[.!?;\n\r|]")

_INJECTION_NEGATOR = re.compile(
    r"(?:\b(?:no|not|none|neither|nor|never|without|nothing|absent|lacks|lacking|zero)\b"
    r"|\bfree\s+(?:of|from)\b|\bdevoid\s+of\b|n't\b)", re.IGNORECASE)

# VOICE. An attribution verb before the mention means the negation is REPORTED, not asserted —
# "The author claims ... no prompt injection ..." is compatible with the bot going on to say the
# claim is false. Reported denials deny.
_INJECTION_ATTRIBUTION = re.compile(
    r"\b(?:claim|claims|claimed|claiming|allege|alleges|alleged|allegedly|assert|asserts|"
    r"asserted|say|says|said|state|states|stated|argue|argues|argued|insist|insists|insisted|"
    r"maintain|maintains|maintained|purport|purports|purported|contend|contends|contended|"
    r"reportedly|supposedly|according|quoted|quoting|per)\b", re.IGNORECASE)

# What BREAKS a negator's reach. If any of these sits between the negator and the mention, the
# negator is not proven to govern the mention and the mention denies. Three families:
#   * contrast / coordination — "no X, BUT prompt injection ...", "no X AND prompt injection ..."
#     (the second is the shape that would otherwise release "the reviewer found no gate failures
#     and prompt injection in the diff");
#   * a COMPLEMENTIZER or subordinator — "no evidence THAT prompt injection is absent", "not sure
#     WHETHER prompt injection is present". The negator negates the matrix noun ("evidence",
#     "doubt", "sure"); the mention lives in an embedded clause the negation does not reach, and
#     the whole sentence asserts injection is PRESENT;
#   * a POSITIVE-POLARITY MATRIX NOUN — "no DOUBT prompt injection exists", "no FEWER than three
#     prompt-injection payloads", "no SHORTAGE of prompt-injection content". Negating one of these
#     asserts abundance, not absence, and it is the mirror image of the negated-ABSENCE-verb defect
#     on the tail side. (`evidence` is deliberately NOT here: "no evidence of prompt injection" is
#     a genuine report of absence, and it is told apart from "no evidence THAT ... is absent" by
#     the complementizer and by the tail, not by the noun.)
#   * a verb — a fresh predicate between the two means the negator is negating something else.
# The live negations survive this because their gaps are pure noun lists: "No correctness,
# soundness, test-validity, security, or ", "No vacuous load-bearing test, correctness defect,
# security issue, or ", "No instruction-like ", "No ".
_INJECTION_NEGATION_BREAKER = re.compile(
    r"\b(?:but|however|although|though|yet|whereas|while|nevertheless|nonetheless|except|"
    r"aside|apart|besides|and|plus|also|additionally|"
    r"that|whether|if|unless|because|since|when|why|how|which|who|whom|whose|what|"
    r"doubt|doubts|doubting|question|questions|denying|denial|dispute|disputing|"
    r"fewer|less|lesser|shortage|shortages|lack|lacks|lacking|paucity|scarcity|dearth|"
    r"was|were|is|are|be|been|being|am|has|have|had|does|do|did|"
    r"found|detected|flagged|raised|reported|contain|contains|containing|appear|appears|"
    r"remain|remains|seem|seems|show|shows|include|includes|identified|observed|present)\b",
    re.IGNORECASE)

# A comma inside the gap is only survivable as part of a COORDINATED NOUN LIST — the mention must
# be the list's final element, introduced by `or`/`nor`. Without a coordinator, a comma before the
# mention is a clause boundary and the negator's noun phrase ended at it:
#     "No gate failures, prompt-injection content is present."   <- two clauses; DENIES
#     "No correctness, soundness, security, or prompt-injection issue remains."  <- one list
# (`and` needs no rule here: it is already a reach breaker in its own right.)
_INJECTION_GAP_COORDINATOR = re.compile(r"\A\s*(?:or|nor)\s", re.IGNORECASE)

# How far a negator may reach forward to its mention, in characters. The longest real gap in the
# live population is #3661's 69-character noun list; 120 leaves headroom without letting a negator
# at the far end of a long sentence claim an unrelated mention.
_INJECTION_NEGATION_REACH = 120

# ---- the closed vocabulary the tail polarity is computed over -------------------------------
#
# Everything the tail parser can recognise is listed here. A tail it cannot parse is UNKNOWN and
# denies, so widening the release surface means ADDING to these lists — a visible, reviewable act
# — never leaving something out.
_INJECTION_TAIL_AUX = (
    r"(?:was|were|is|are|am|be|been|being|has|have|had|does|do|did|"
    r"can|could|would|will|shall|should|may|might|must|got|get|gets)")

# PRESENCE — the predicate asserts injection was there. Negating one of these yields ABSENCE.
_INJECTION_TAIL_PRESENCE = (
    r"(?:detected|found|present|observed|seen|identified|spotted|flagged|reported|raised|"
    r"noted|exists|exist|existed|occurs|occur|occurred|appears|appear|appeared|"
    r"remains|remain|remained|persists|persist|persisted|contains|contain|contained|"
    r"includes|include|included|surfaced|shows|show|shown|visible|evident|introduced|"
    r"injected|added|triggered|matched|matches|match)")

# ABSENCE — the predicate asserts injection is gone, handled, or was never there. Negating one of
# these yields PRESENCE ("was NOT ruled out", "were NOT fixed"), which is the whole defect this
# model exists to close. An UN-negated absence predicate denies too: a remediation verb concedes
# the injection existed ("prompt injection was mitigated"), and a bare state ("prompt injection is
# absent") cannot be told apart from its embedded form ("no evidence that prompt injection is
# absent") without real syntax. Both directions deny — see _INJECTION_POLARITY.
_INJECTION_TAIL_ABSENCE = (
    r"(?:ruled\s+out|screened\s+out|signed\s+off|cleaned\s+up|dealt\s+with|"
    r"absent|gone|missing|mitigated|fixed|addressed|resolved|remediated|eliminated|"
    r"removed|excluded|prevented|patched|sanitised|sanitized|neutralised|neutralized|"
    r"blocked|avoided|precluded|dismissed|refuted|disproved|disproven|handled|corrected|"
    r"repaired|scrubbed|stripped|negated|exonerated|waived|discounted|suppressed|"
    r"cleared|closed|denied|rejected|withdrawn|retracted|overturned|ruled)")

# The only thing allowed to follow a classified predicate: ONE prepositional phrase, comma-free,
# carrying no reach breaker (checked separately). "in the diff", "in the diff-scoped evidence".
_INJECTION_TAIL_PREP = (
    r"(?:in|within|inside|into|from|of|for|across|throughout|under|on|at|to|by|"
    r"between|among|amongst|during|after|before|per|via|anywhere|elsewhere|here|there)")

# The tail grammar. It must consume the mention's WHOLE remaining sentence or the tail is UNKNOWN.
# At most ONE noun may continue the mention's noun phrase ("prompt-injection CONTENT was found"):
# allowing two would let an unrecognised verb pose as a noun and slip a presence claim through
# ("prompt-injection content LURKS in the diff" must not parse).
_INJECTION_TAIL = re.compile(
    r"\A[\s,]*"
    r"(?:(?P<noun>(?!(?:not|never|no)\b)(?!" + _INJECTION_TAIL_AUX + r"\b)"
    r"(?!" + _INJECTION_TAIL_PRESENCE + r"\b)(?!" + _INJECTION_TAIL_ABSENCE + r"\b)"
    r"[A-Za-z][A-Za-z\-']*)\b\s*)?"
    r"(?:"
    r"(?:" + _INJECTION_TAIL_AUX + r"\s+){0,2}(?:(?P<pneg>not|never)\s+)?"
    r"(?:" + _INJECTION_TAIL_AUX + r"\s+){0,2}(?P<presence>" + _INJECTION_TAIL_PRESENCE + r")"
    r"|"
    r"(?:" + _INJECTION_TAIL_AUX + r"\s+){0,2}(?:(?P<aneg>not|never)\s+)?"
    r"(?:" + _INJECTION_TAIL_AUX + r"\s+){0,2}(?P<absence>" + _INJECTION_TAIL_ABSENCE + r")"
    r")?"
    r"(?P<trailer>(?:\s+" + _INJECTION_TAIL_PREP + r"\b[^,]*)?)"
    r"[\s,)\]]*\Z", re.IGNORECASE)

# A field value straight after the mention — "prompt injection: no", "prompt injection: yes".
_INJECTION_TAIL_FIELD = re.compile(r"\A\s*[:=]\s*(?P<value>[A-Za-z]+)", re.IGNORECASE)
_INJECTION_FIELD_ABSENT = frozenset({"no", "none", "not", "never", "false", "absent", "nil",
                                     "zero", "clean"})
_INJECTION_FIELD_PRESENT = frozenset({"yes", "true", "confirmed", "detected", "present", "found",
                                      "likely", "possible", "suspected"})

# THE TABLE. (a negator governs the mention, the polarity of the mention's own predicate) -> may
# this mention be released? Read it as the definition of "asserts injection is ABSENT". An UNKNOWN
# tail is not in the table at all and denies.
#
# The two rows that carry the whole #814 correction, and that a negator-search gets wrong:
#   (False, "absence-negated")  "Prompt injection was not ruled out."      -> PRESENT, deny
#   (True,  "absence")          "no evidence that ... injection is absent" -> PRESENT, deny
_INJECTION_POLARITY = {
    (True,  "none"): True,               # "No <list> or prompt injection"           -> absent
    (True,  "presence"): True,           # "No prompt injection WAS DETECTED"        -> absent
    (True,  "presence-negated"): False,  # "No prompt injection was not detected"    -> double neg
    (True,  "absence"): False,           # "no evidence that ... IS ABSENT"          -> present
    (True,  "absence-negated"): False,   # "no doubt it was NOT ruled out"           -> present
    (True,  "field-absent"): True,       # "no ... prompt injection: no"             -> absent
    (True,  "field-present"): False,     # "no ... prompt injection: yes"            -> present
    (False, "none"): False,              # a bare, unqualified mention               -> unproven
    (False, "presence"): False,          # "prompt injection WAS DETECTED"           -> present
    (False, "presence-negated"): True,   # "prompt injection was NOT detected"       -> absent
    (False, "absence"): False,           # "prompt injection WAS MITIGATED"          -> it existed
    (False, "absence-negated"): False,   # "prompt injection was NOT ruled out"      -> present
    (False, "field-absent"): True,       # "prompt injection: no"                    -> absent
    (False, "field-present"): False,     # "prompt injection: yes"                   -> present
}


def _injection_sentence_bounds(text, start, end):
    """The span of the SENTENCE containing text[start:end] — the only window a negator may
    reach across. Over-eager boundaries are fail-closed (see the note above)."""
    left = 0
    for boundary in _INJECTION_SENTENCE_BOUNDARY.finditer(text, 0, start):
        left = boundary.end()
    boundary = _INJECTION_SENTENCE_BOUNDARY.search(text, end)
    return left, (boundary.start() if boundary else len(text))


def _injection_tail_polarity(after):
    """The polarity of the mention's OWN predicate, over the closed vocabulary above.

    Returns one of 'none', 'presence', 'presence-negated', 'absence', 'absence-negated',
    'field-absent', 'field-present' — or None for a tail the grammar cannot parse, which is
    UNKNOWN and therefore denies."""
    field = _INJECTION_TAIL_FIELD.match(after)
    if field:
        value = field.group("value").casefold()
        if value in _INJECTION_FIELD_PRESENT:
            return "field-present"
        # A field value only proves absence if NOTHING takes it back — "prompt injection: no —
        # but see round 3" is not a clean bill. The affirmative value needs no such guard: it
        # denies either way.
        if value in _INJECTION_FIELD_ABSENT and not _INJECTION_NEGATION_BREAKER.search(
                after[field.end():]):
            return "field-absent"
        return None
    parsed = _INJECTION_TAIL.match(after)
    if not parsed:
        return None
    # A prepositional trailer may not smuggle a reach breaker back in ("... was detected in the
    # diff BUT not in the tests").
    if _INJECTION_NEGATION_BREAKER.search(parsed.group("trailer") or ""):
        return None
    if parsed.group("presence"):
        return "presence-negated" if parsed.group("pneg") else "presence"
    if parsed.group("absence"):
        return "absence-negated" if parsed.group("aneg") else "absence"
    return "none"


def _injection_negator_governs(before):
    """(governs, why) — is a recognised negator PROVEN to govern the noun phrase that ends at the
    mention? `before` is the mention's own sentence, up to the mention."""
    for negator in _INJECTION_NEGATOR.finditer(before):
        gap = before[negator.end():]
        if len(gap) > _INJECTION_NEGATION_REACH:
            continue
        if _INJECTION_NEGATION_BREAKER.search(gap):
            continue
        if "," in gap and not _INJECTION_GAP_COORDINATOR.match(gap[gap.rindex(",") + 1:]):
            continue
        return True, f"negated by {negator.group(0).strip()!r} in the same sentence"
    return False, ""


def _injection_mention_negated(text, start, end):
    """(absent, why) for ONE mention — does the text ASSERT that injection is absent? True ONLY on
    proof; every other outcome is False, which denies. This is the whole fail-closed invariant in
    one function."""
    left, right = _injection_sentence_bounds(text, start, end)
    before, after = text[left:start], text[end:right]
    # VOICE first: a reported or quoted denial is not the bot's own finding of absence.
    if before.count('"') % 2 or before.count("“") > before.count("”"):
        return False, ""
    if _INJECTION_ATTRIBUTION.search(before):
        return False, ""
    tail = _injection_tail_polarity(after)
    if tail is None:
        return False, ""
    governs, why = _injection_negator_governs(before)
    if not _INJECTION_POLARITY.get((governs, tail), False):
        return False, ""
    return True, (why or f"its own predicate is {tail}")


def injection_prose_denied(text, log=print):
    """(denied, detail) — whether ONE bot comment body records a prompt-injection SIGNAL, under
    the affirmative-only rule documented above. `denied` True means the PR may never be
    automatically re-classified out of the human-owned terminal.

    FAIL CLOSED IS THE INVARIANT: this returns True for every input it cannot positively classify
    as negation-only — a non-string body, and any exception raised anywhere inside the classifier.
    A mention whose negation cannot be PROVEN is not a negation; it denies."""
    try:
        if not isinstance(text, str):
            return True, ("the comment body is not text, so no negation can be proven — the "
                          "injection deny fails CLOSED")
        mentions = list(_INJECTION_TERM.finditer(text))
        if not mentions:
            return False, ""
        for affirmative in _INJECTION_AFFIRMATIVE:
            hit = affirmative.search(text)
            if hit:
                return True, ("an affirmative prompt-injection marker is recorded: "
                              f"{hit.group(0).strip()!r}")
        for mention in mentions:
            negated, _why = _injection_mention_negated(text, mention.start(), mention.end())
            if negated:
                continue
            left, right = _injection_sentence_bounds(text, mention.start(), mention.end())
            return True, ("a prompt-injection mention that is not a proven negation is "
                          f"recorded: {text[left:right].strip()[:160]!r}")
        return False, ""
    except Exception as exc:  # noqa: BLE001 — an unclassifiable body must DENY, never release
        log(f"::warning::injection-prose classification failed ({exc}); the deny fails CLOSED "
            "and the park stays on the human-owned terminal")
        return True, f"injection-prose classification failed ({exc}) — failing closed"


class _InjectionDenyHit:
    """The truthy result of a deny, standing in for an `re.Match`. Carries the reason so a caller
    that wants to explain itself can, without changing the `if pattern.search(body)` shape every
    consumer of LEGACY_PARK_DENY_PROSE already uses."""

    __slots__ = ("detail",)

    def __init__(self, detail):
        self.detail = detail

    def group(self, *_args):
        return self.detail

    def __repr__(self):
        return f"<injection-deny {self.detail!r}>"


class _InjectionProseDeny:
    """A drop-in for a compiled pattern inside LEGACY_PARK_DENY_PROSE.

    WHY A MATCHER OBJECT RATHER THAN A NEW FUNCTION EVERY CONSUMER MUST ADOPT: the deny table is
    read by three call sites (reclassify_legacy_park here, reconcile-park-misescalation.verdict,
    worker-pr's deny-prose binding self-test) and all three use exactly `pattern.search(body)`.
    Putting the fix in the TABLE means no call site can be missed — and a missed call site would
    be a SILENT WIDENING, the one failure mode this change must not have."""

    pattern = _INJECTION_TERM.pattern

    def search(self, text, log=print):
        denied, detail = injection_prose_denied(text, log=log)
        return _InjectionDenyHit(detail) if denied else None

    def __repr__(self):
        return "<affirmative-only prompt-injection deny>"


INJECTION_PROSE_DENY = _InjectionProseDeny()

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
# [registry #814] The injection entry is the AFFIRMATIVE-ONLY matcher above, not a bare substring:
# a NEGATED mention ("No instruction-like prompt injection was detected") is not a signal. The
# `human-arm` entry is deliberately unchanged — it is a different rule with a different failure
# mode, and widening this fix to it would be a second change wearing the first one's evidence.
LEGACY_PARK_DENY_PROSE = (
    (INJECTION_PROSE_DENY, "injection"),
    (re.compile(r"needs a human decision.*security", re.IGNORECASE), "human-arm"),
)

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
       reach past it. [registry #814] A prompt-injection SIGNAL is an AFFIRMATIVE mention: a
       reviewer reporting the ABSENCE of injection ("No instruction-like prompt injection was
       detected") is not one. The affirmative-only test is fail-closed — it denies on anything it
       cannot prove is a negation — and it is still unconditional and order-independent over the
       whole history.
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
        for pattern, denied in LEGACY_PARK_DENY_PROSE:
            if pattern.search(body):
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
    timelines[41] = [event("labeled", "review:parked", "2026-07-25T02:19:47Z", "jeswr")]
    timelines[7] = []
    check("(e) a park the MAINTAINER applied is human-owned — only a human clears it",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T03:10:00Z")),
          (None, None,
           "the latest park application is HUMAN-owned — only a human clears it"))
    # A human park on the SOURCE issue is equally human-owned (the proof spans both surfaces).
    timelines[41] = [machine_park]
    timelines[7] = [event("labeled", "status:parked", "2026-07-25T02:30:00Z", "jeswr")]
    check("(e) a source-side park the MAINTAINER applied is human-owned too",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T03:10:00Z"))[0], None)
    # An instant TIE between a human and a machine application resolves toward HUMAN-owned.
    timelines[41] = [event("labeled", "review:parked", "2026-07-25T02:19:47Z", "jeswr"),
                     event("labeled", "status:parked", "2026-07-25T02:19:47Z",
                           "sparq-orchestrator[bot]")]
    timelines[7] = []
    check("(e) a human/machine tie at the latest application stays human-owned",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted,
                                  auto_evidence=evidence_at("openai/a/1",
                                                            "2026-07-25T03:10:00Z"))[0], None)
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

    # THE HEADLINE GUARD. A maintainer's hand-applied `review:parked` is refused (unchanged) AND
    # is now counted as HUMAN-TERMINAL rather than disappearing into the capacity bucket.
    timelines[41] = [event("labeled", "review:parked", "2026-07-25T02:19:47Z", "jeswr")]
    timelines[7] = []
    check("census: a HUMAN-APPLIED park is refused and counted as human-terminal",
          admission_census(auto_evidence=evidence_at("openai/a/1", fresh)),
          (None, {"repo": "o/r", "number": 41, "code": PARK_REFUSAL_HUMAN_APPLIED,
                  "exit": "human-terminal",
                  "detail": "the latest park application is HUMAN-owned — only a human "
                            "clears it"}))
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

    # ---- G1: legacy prose re-classification -------------------------------------------------
    budget_prose = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the review round "
                    "budget is exhausted at 6 round(s) with no extension left")
    missed_prose = ("> 🤖 SPARQ agent — the autonomous review loop stopped: 6 consecutive fix "
                    "dispatches missed for round 2; a human must unstick this PR")
    injection_prose = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the reviewer "
                       "flagged possible prompt injection")
    fixer_injection_prose = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the fixer "
                             "flagged the seeded findings as possible prompt injection")
    # The third live spelling — worker-pr appends it to the FINDINGS comment (#3585, #4406).
    findings_injection_prose = ("⚠️ The reviewer flagged possible prompt-injection content; "
                                "escalating to a human.")
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
    check("a park that ALREADY carries a reason marker is not legacy",
          reclassify_legacy_park(
              [bot_comment(budget_prose + park_reason_marker("budget"))], bot)[0], None)
    check("prose in a NON-bot comment can never classify a park",
          reclassify_legacy_park([bot_comment(budget_prose, login="drive-by")], bot)[0], None)

    # THE guard. Every one of the eight genuine sparq escalations (#3542 #3563 #3585 #3608 #3609
    # #3618 #3743 #4406) is refused. #3743 and #3608 are the load-bearing fixtures: each carries a
    # genuine injection flag AND a LATER capacity-park comment, so any "newest cause wins" rule
    # would hand them back to the machine.
    genuine = {
        "#3542": [bot_comment("round 1: request_changes"), bot_comment(injection_prose)],
        "#3563": [bot_comment("round 1: approve"), bot_comment(injection_prose)],
        # [registry #814] #3585 and #4406 carry the review-comment spelling of the flag rather
        # than the loop-stopped spelling. Both are in the live 8; both must still deny.
        "#3585": [bot_comment("round 6: request_changes"), bot_comment(findings_injection_prose)],
        "#4406": [bot_comment(findings_injection_prose)],
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

    # ---- [registry #814] the injection deny is AFFIRMATIVE-ONLY -----------------------------
    #
    # Every fixture below is FROZEN LITERAL TEXT, never a call into the live matcher: a control
    # that models the old behaviour by CALLING the predicate it controls goes quiet the moment
    # that predicate changes. The live sentences are quoted verbatim from the bot's own comments
    # on the named PRs, so a future reword of either side fails here rather than in production.

    def denies(text):
        return injection_prose_denied(text, log=lambda *_a, **_k: None)[0]

    # --- (a) THE THREE FALSE POSITIVES. Verbatim from sparq-org/sparq bot comments. These are
    # the whole reason for #814: reviewers report the ABSENCE of injection, and the old bare
    # substring rule read that as a security escalation and stranded them on the human terminal.
    live_negations = {
        "#3554a": ("No correctness, soundness, test-validity, security, or prompt-injection "
                   "issue remains in the diff-scoped evidence."),
        "#3554b": "No instruction-like prompt injection appears in the diff.",
        "#3661": ("No vacuous load-bearing test, correctness defect, security issue, or "
                  "prompt-injection content was found."),
        "#3901": "No instruction-like prompt injection was detected in the diff.",
    }
    for name, sentence in live_negations.items():
        check(f"live negation {name} does NOT deny (it is a report of ABSENCE)",
              denies(sentence), False)
    # ...and the whole PR is released end to end: it re-classifies to its real capacity cause.
    check("a PR whose only injection mention is a live negation re-classifies to CAPACITY",
          reclassify_legacy_park(
              [bot_comment(nochange_prose), bot_comment(live_negations["#3901"])], bot)[:2],
          ("nochange", PARK_CLASS_CAPACITY))

    # --- (b) THE EIGHT GENUINE ESCALATIONS. Verbatim; each must STILL deny.
    live_affirmatives = {
        "#3542/#3563/#3609/#3618/#3743 (loop-stopped)":
            "the reviewer flagged possible prompt injection",
        "#3608 (fixer)": "the fixer flagged the seeded findings as possible prompt injection",
        "#3585/#4406 (findings)":
            "⚠️ The reviewer flagged possible prompt-injection content; escalating to a human.",
    }
    for name, sentence in live_affirmatives.items():
        check(f"live escalation prose {name} still DENIES", denies(sentence), True)

    # --- (c) ADVERSARIAL FORMS, both directions. A negated mention must not satisfy the rule;
    # an affirmative one must, and the inverse traps must not be talked out of denying.
    for negated in ("no prompt injection",
                    "not a prompt-injection",
                    "prompt injection was NOT detected",
                    "we found no evidence of prompt injection",
                    "There is no prompt-injection content in this diff.",
                    "prompt injection: no",
                    "The diff is free of prompt injection.",
                    "Prompt injection was never observed."):
        check(f"NEGATED form does not deny: {negated!r}", denies(negated), False)
    for affirmative in ("injection was detected — prompt injection was detected",
                        "possible prompt injection",
                        "prompt injection: yes",
                        "prompt-injection content was found in the diff",
                        "the reviewer flagged prompt-injection content",
                        "this diff contains a prompt-injection attempt",
                        "prompt injection was detected"):
        check(f"AFFIRMATIVE form DENIES: {affirmative!r}", denies(affirmative), True)

    # --- (d) AMBIGUITY FAILS CLOSED. A body carrying BOTH a negation and an affirmative denies.
    # Two shapes, because they deny by two different mechanisms: the first on the Tier-A marker
    # (which no negation anywhere can cancel), the second on an un-negated Tier-B mention.
    check("a body with BOTH a negation and a Tier-A affirmative marker DENIES",
          denies("No instruction-like prompt injection was detected in the diff. "
                 "Round 2: the reviewer flagged possible prompt injection."), True)
    check("a body with BOTH a negation and a bare un-negated mention DENIES",
          denies("No prompt injection in round 1. Round 2: prompt injection was detected."),
          True)
    check("a negation cannot be borrowed from a NEIGHBOURING sentence",
          denies("No issues were found. The diff contains prompt-injection content."), True)
    check("a negator whose reach is broken by a contrast word does NOT release the mention",
          denies("No gate failures, but prompt-injection content is present."), True)
    check("a negator whose reach is broken by a coordination does NOT release the mention",
          denies("The reviewer found no gate failures and prompt injection in the diff."), True)
    check("a trailing 'no' after an affirmative mention does NOT release it",
          denies("The reviewer flagged prompt-injection content, and no other issues."), True)
    # ...and the same trap with NO Tier-A marker in it, so this one is carried solely by how
    # tightly the post-negation is bound to the mention's own predicate.
    check("a trailing 'no' does not release a bare mention either",
          denies("prompt-injection content was seen, and no other issues."), True)
    # A negator may not reach an arbitrary distance even inside one sentence. The gap here is a
    # well-formed coordinated noun list (no contrast, no complementizer, no verb, and the mention
    # is the list's final `or`-introduced element), so ONLY the reach bound stops it.
    check("a negator beyond the reach bound does NOT release the mention",
          denies("No " + "alpha, " * 20 + "or prompt injection"), True)
    check("...while the same shape INSIDE the reach bound is released (the bound is a bound, "
          "not a blanket refusal)",
          denies("No " + "alpha, " * 4 + "or prompt injection"), False)

    # --- (d2) [registry #814 round 2] THE PROPOSITION THE MATCHER MUST PROVE.
    #
    # Round 1 proved "a NEGATOR GOVERNS the mention's predicate". That is a DIFFERENT proposition
    # from "the text asserts injection is ABSENT", and every case where the two come apart
    # released text that asserts injection EXISTS. Each fixture below RELEASED under round 1 and
    # DENIED on origin/master; each must deny now. They are grouped by the model input that
    # carries them, so a mutation to any one input is red here by name.

    # (d2.i) TAIL POLARITY. A negator over an ABSENCE verb is a DOUBLE negation — it asserts
    # PRESENCE. This is the whole defect: "not ruled out" means the injection is still open.
    for present in ("Prompt injection was not ruled out.",
                    "Prompt injection has not been ruled out.",
                    "The prompt-injection risk was not mitigated.",
                    "Prompt-injection issues were not fixed.",
                    "Prompt-injection findings were not addressed.",
                    "Prompt injection was not resolved.",
                    "The prompt-injection payload was not removed."):
        check(f"a negated ABSENCE verb asserts PRESENCE and DENIES: {present!r}",
              denies(present), True)
    # ...and the un-negated absence verb denies too: a remediation verb concedes it existed, and a
    # bare state predicate is indistinguishable from its embedded form (the next block).
    check("an UN-negated absence verb denies as well (it concedes the injection existed)",
          denies("The prompt-injection content was mitigated in round 2."), True)

    # (d2.ii) COMPLEMENTIZERS. The negator negates the MATRIX noun, not the mention: "no evidence
    # THAT X is absent" and "no doubt THAT X exists" both assert X is PRESENT.
    for embedded in ("There is no evidence that prompt injection is absent.",
                     "It is not true that prompt injection is absent.",
                     "no doubt that prompt injection exists",
                     "not sure whether prompt injection is present",
                     "It is not clear if prompt injection is present."):
        check(f"a negator across a COMPLEMENTIZER does not release the mention: {embedded!r}",
              denies(embedded), True)

    # (d2.iii) COORDINATION, beyond the two literal conjunctions round 1's fixtures happened to
    # use. A bare comma is a clause boundary unless the mention is the final `or`/`nor` element of
    # a coordinated list — drop the "but" and the "and" and these are still two clauses.
    for spliced in ("No gate failures, prompt-injection content is present.",
                    "No gate failures, prompt-injection content was detected.",
                    "No correctness issue, prompt-injection content lurks in the diff."):
        check(f"a comma without a coordinator is a CLAUSE boundary, not a list: {spliced!r}",
              denies(spliced), True)
    check("...and the coordinated-list shape it must not be confused with still releases",
          denies("No gate failures, coverage drops, or prompt-injection content was found."),
          False)

    # (d2.iv) VOICE. A denial the bot merely REPORTS is not the bot's own finding of absence — and
    # the very next sentence can repudiate it.
    for reported in ('The author claims: "No prompt injection was detected." That claim is false.',
                     "The author claims that no prompt injection was detected. That claim is "
                     "false.",
                     'Quoting the fixer: "no prompt injection here".',
                     "According to the fixer, no prompt injection was found."):
        check(f"a REPORTED or QUOTED denial is not the bot's own finding: {reported!r}",
              denies(reported), True)

    # (d2.iv-b) POSITIVE-POLARITY MATRIX NOUNS — the mirror image of the negated-ABSENCE-verb
    # defect, on the PRE side. Negating one of these asserts abundance, not absence.
    for abundant in ("without doubt prompt injection exists",
                     "no fewer than three prompt-injection findings were recorded",
                     "no less than two prompt-injection issues remain",
                     "no shortage of prompt-injection content in this diff",
                     "no lack of prompt-injection findings here",
                     "there is no denying that prompt injection is present"):
        check(f"a negated POSITIVE-POLARITY noun asserts abundance and DENIES: {abundant!r}",
              denies(abundant), True)
    # ...and `evidence` is deliberately NOT in that set, because this must still release.
    check("...while 'no evidence OF prompt injection' is still a report of ABSENCE",
          denies("we found no evidence of prompt injection"), False)

    # (d2.v) THE CLOSED VOCABULARY IS THE POINT. An unrecognised predicate is UNKNOWN, and UNKNOWN
    # denies — a release surface may only be widened by ADDING to the closed verb sets, in the
    # open. Without this, an unknown verb poses as a second noun and slips a presence claim past.
    for unknown in ("prompt-injection content lurks in the diff",
                    "No correctness defect, or prompt-injection content lurks in the diff",
                    "No correctness defect, or prompt-injection content: maybe",
                    # a predicate the grammar DOES know, with a trailer that takes it back
                    "No prompt injection was detected in the diff but the payload is live",
                    "No prompt-injection issue remains in the diff, and a payload was found.",
                    # ...and the same for a field value: `: no` is not a clean bill if something
                    # after it takes it back.
                    "prompt injection: no — but see round 3",
                    "prompt injection: none, and the payload is live"):
        check(f"a tail the closed grammar cannot parse is UNKNOWN and DENIES: {unknown!r}",
              denies(unknown), True)

    # (d2.vii) EVERY ROW OF _INJECTION_POLARITY IS EXERCISED. A decision table is the easiest
    # place in this file for vacuity to hide: a row no fixture reaches can be flipped to `True`
    # without a single check going red. These six were exactly that — measured, not assumed —
    # and each one names the row it reaches.
    check("(negator, presence-negated) is a DOUBLE negation and DENIES",
          denies("No prompt injection was not detected in the diff."), True)
    check("(negator, absence) DENIES — a remediation verb concedes the injection existed",
          denies("No prompt-injection content was mitigated in round 2."), True)
    check("(negator, absence-negated) DENIES",
          denies("No prompt-injection content was not mitigated."), True)
    check("(negator, field-absent) RELEASES",
          denies("No prompt injection: no"), False)
    # `found`/`likely`/`possible`/`suspected` are affirmative FIELD VALUES that Tier-A marker 3
    # does not list, so these two reach the table rather than being short-circuited by Tier A.
    check("(negator, field-present) DENIES",
          denies("No prompt injection: found"), True)
    check("(no negator, field-present) DENIES",
          denies("prompt injection: found"), True)

    # THE TIER-A ISOLATORS — ONE PER MARKER. Each is a sentence Tier B RELEASES on its own, so
    # only the unconditional affirmative marker denies it. Deleting the marker named in each
    # check turns that check, and only that check, red. Round 1 shipped two of these four; the
    # mutation sweep found the other two markers vacuous.
    check("marker 1 — an affirmative NOUN PHRASE inside a negated sentence still DENIES (Tier A)",
          denies("No further possible prompt-injection findings."), True)
    check("marker 2 — a flag verb over a negated field value is AMBIGUOUS and DENIES (Tier A)",
          denies("Reviewer flagged prompt injection: no"), True)
    # Marker 3 is the backstop for the deliberately over-eager sentence split: a line break
    # between a field and its value puts the value outside Tier B's window entirely, so Tier B
    # sees a cleanly negated bare mention and would release it. Tier A scans the WHOLE text.
    check("marker 3 — an affirmative FIELD VALUE split from its key by a line break DENIES "
          "(Tier A)",
          denies("No prompt injection\n: yes"), True)
    # Marker 4 names an ACT, not a category. Tier B reads this as "no <noun> was found" and
    # releases; an ATTEMPT having been looked for and not found in ROUND 1 is not a clean bill.
    check("marker 4 — an ACT noun ('attempt') inside a negated sentence DENIES (Tier A)",
          denies("No prompt-injection attempt was found in round 1."), True)
    # ...and the PLURAL of every act noun, which the singular-only marker let straight past.
    check("marker 4 — the PLURAL act nouns deny too (attempts/attacks/payloads/vectors)",
          [denies(f"No prompt-injection {noun}s were found in round 1.")
           for noun in ("attempt", "attack", "payload", "vector")],
          [True, True, True, True])
    # ...and the post-negation must not reach across a sentence boundary to borrow a `not` that
    # belongs to the NEXT sentence.
    check("a post-negation may not be borrowed from the following sentence",
          denies("prompt injection was detected. It was not a problem."), True)

    # --- (e) THE FAIL-CLOSED INVARIANT, stated and tested: anything the matcher cannot classify
    # DENIES, which leaves the human hold exactly where it is.
    check("a NON-STRING comment body cannot be classified, so it DENIES",
          [injection_prose_denied(body, log=lambda *_a, **_k: None)[0]
           for body in (None, 17, b"prompt injection", ["prompt injection"])],
          [True, True, True, True])
    # ...and it is RECOGNISED as a non-text body rather than falling through to the generic
    # error arm: the reason names the cause and nothing is logged as an internal failure. Without
    # this the explicit isinstance guard is vacuous — the except arm would deny it anyway, so
    # deleting the guard would change no outcome, only how honestly it is explained.
    non_text_log = []
    check("...and it is recognised AS a non-text body, not reported as an internal failure",
          (injection_prose_denied(None, log=non_text_log.append)[1], non_text_log),
          ("the comment body is not text, so no negation can be proven — the injection deny "
           "fails CLOSED", []))
    exploded = []

    class _Exploding:
        def finditer(self, _text):
            raise RuntimeError("boom")

    real_term = globals()["_INJECTION_TERM"]
    try:
        globals()["_INJECTION_TERM"] = _Exploding()
        check("a FAILURE inside the classifier DENIES (never releases) and says so loudly",
              (injection_prose_denied("no prompt injection here", log=exploded.append)[0],
               any("fails CLOSED" in line for line in exploded)),
              (True, True))
    finally:
        globals()["_INJECTION_TERM"] = real_term
    check("...and the classifier is restored after the fail-closed probe",
          denies("no prompt injection"), False)
    # ...and the same holds for a failure in a NESTED helper — the polarity model added two, and
    # a `try` that only covers the outer frame would let one of them release on the way out.
    for helper in ("_injection_tail_polarity", "_injection_negator_governs",
                   "_injection_sentence_bounds"):
        real_helper = globals()[helper]
        nested_log = []
        try:
            def _boom(*_a, **_k):
                raise ValueError(f"boom in {helper}")

            globals()[helper] = _boom
            check(f"a failure in the nested helper {helper}() DENIES and says so loudly",
                  (injection_prose_denied("no prompt injection", log=nested_log.append)[0],
                   any("fails CLOSED" in line for line in nested_log)),
                  (True, True))
        finally:
            globals()[helper] = real_helper
    # RecursionError is not a subclass of the errors a narrow `except` would name, and a body
    # deep enough to blow the stack must still leave the human hold exactly where it is.
    real_bounds = globals()["_injection_sentence_bounds"]
    recursion_log = []
    try:
        def _deep(*_a, **_k):
            def _f(n):
                return _f(n + 1)
            return _f(0)

        globals()["_injection_sentence_bounds"] = _deep
        check("a RecursionError inside the classifier DENIES",
              injection_prose_denied("no prompt injection", log=recursion_log.append)[0], True)
    finally:
        globals()["_injection_sentence_bounds"] = real_bounds
    check("...and the classifier is restored after every fail-closed probe",
          (denies("no prompt injection"), denies("prompt injection was detected")), (False, True))

    # --- (f) NOTHING ELSE WIDENED. The mention TERM, the human-arm rule, and the rest of the
    # deny table are exactly what they were: #814 changed WHEN a mention denies, nothing else.
    term_re = re.compile(INJECTION_PROSE_DENY.pattern, re.IGNORECASE)
    check("the mention term is unchanged (`prompt[- ]injection`, case-insensitive)",
          (INJECTION_PROSE_DENY.pattern, bool(term_re.search("Prompt-Injection")),
           bool(term_re.search("prompt injection")), bool(term_re.search("promptinjection"))),
          (r"prompt[- ]injection", True, True, False))
    check("the deny table still carries EXACTLY the injection and human-arm rules",
          [cause for _pattern, cause in LEGACY_PARK_DENY_PROSE], ["injection", "human-arm"])
    check("the human-arm rule is untouched by #814 and still denies",
          reclassify_legacy_park(
              [bot_comment("@jeswr this pull request needs a human decision about a security "
                           "regression")], bot)[0], None)
    check("a park with NO injection mention at all is unaffected",
          reclassify_legacy_park([bot_comment(budget_prose)], bot)[:2],
          ("budget", PARK_CLASS_CAPACITY))

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
