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
PARK_ESCALATION_GENERATIONS = 2
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


def capacity_park_admission(repo, pr_number, issue_number, fetch_events, is_human=None,
                            log=print, consumed=frozenset(), auto_receipts=(),
                            auto_marker_count=None, auto_evidence=None, live_holds=(),
                            deadlock_unadjudicated=False):
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

    `deadlock_unadjudicated` (registry #703, derived by the caller via
    deadlock_awaiting_adjudication) refuses the AUTOMATIC path outright for a proven
    reviewer-vs-fixer deadlock that carries no head-bound adjudication receipt. A human gesture
    still wins — it is checked first — so this narrows only the machine's own re-admission.

    EVERY ambiguity fails toward staying parked: an unreadable timeline, an unreadable/absent
    health record, a probe that raises, an unsafe evidence key, a recovery that is not STRICTLY
    after the park (a tie included), a human-owned label, a human-applied park, the cap, and an
    unadjudicated deadlock."""
    if capacity_park_readmitted(repo, pr_number, issue_number, fetch_events,
                                is_human=is_human, log=log, consumed=consumed):
        return ("human", None, "unconsumed proven-human readmission gesture")
    held = human_owned_holds(live_holds)
    if held:
        return (None, None,
                f"human-owned hold(s) live ({'/'.join(held)}) — never auto-re-admitted")
    if deadlock_unadjudicated:
        # registry #703. Checked AFTER the human gesture (a human may always override) and
        # BEFORE the timeline/probe reads, so a refused deadlock costs no API calls, consumes NO
        # recovery evidence, and mints NO receipt — it is simply not re-admitted.
        #
        # The re-admission exists for a CAPACITY park, whose cause demonstrably cleared. A
        # deadlock's cause is a disagreement, and fleet-capacity recovery is no evidence at all
        # that it cleared: re-admitting on it puts the SAME reviewer and the SAME fixer at the
        # SAME tier back on the SAME diff, which reproduces the disagreement, burns another
        # round budget and another three account leases, and parks again — and it is that second
        # park which advances the generation ladder toward the human terminal. So the
        # re-admission is not merely ineffective here, it is the mechanism that feeds the
        # escalation (#701's retry-an-unchanged-configuration error; #500's decline must be
        # REROUTED, not re-deferred).
        log(f"automatic readmission REFUSED for {repo}#{pr_number}: this is an UNADJUDICATED "
            "reviewer-vs-fixer deadlock, not a capacity park — re-admitting it would replay the "
            "same disagreement at the same tier and advance the ladder toward a human hold; it "
            "needs an independent adjudication, not another generation")
        return (None, None, "unadjudicated reviewer-vs-fixer deadlock — adjudication required")
    latest_park, human_park, readable = park_applications(
        repo, pr_number, issue_number, fetch_events, is_human=is_human, log=log)
    if not readable:
        return (None, None, "the park application timeline could not be read")
    if human_park:
        return (None, None, "the latest park application is HUMAN-owned — only a human clears it")
    parked_at = canonical_ts(latest_park.isoformat()) if latest_park is not None else None
    for receipt in auto_receipts:
        stamp = receipt.get("at") if isinstance(receipt, dict) else None
        if not valid_timestamp(stamp):
            continue                    # malformed receipts prove nothing (they still count
            # toward the cap below, so they can never buy an extra re-admission)
        if latest_park is None or parse_ts(stamp) > latest_park:
            return ("auto-receipt", {"key": receipt.get("key"), "at": canonical_ts(stamp)},
                    f"already automatically re-admitted at {canonical_ts(stamp)} "
                    f"(receipt evidence {receipt.get('key')!r}); no new evidence consumed")
    minted = len(auto_receipts) if auto_marker_count is None else auto_marker_count
    if minted >= AUTO_READMISSION_MAX:
        log(f"::warning::automatic readmission REFUSED for {repo}#{pr_number}: "
            f"{minted} automatic re-admission(s) already granted (cap "
            f"{AUTO_READMISSION_MAX}) and the park fired again — an account that keeps "
            "flapping is a genuine human question; the park stands until a human acts")
        return (None, None, f"automatic-readmission cap reached ({minted}/"
                            f"{AUTO_READMISSION_MAX})")
    if auto_evidence is None:
        return (None, None, "no unconsumed human gesture and no recovery evidence offered")
    try:
        evidence = auto_evidence(parked_at)
    except Exception as exc:  # noqa: BLE001 — an unreadable cause probe stays parked
        log(f"automatic readmission unknown for {repo}#{pr_number}: the recovery-evidence "
            f"probe failed ({exc}); the capacity park stands")
        return (None, None, "the recovery-evidence probe failed")
    if not evidence:
        return (None, None, "no recorded recovery of the park's starvation cause")
    key = evidence.get("key") if isinstance(evidence, dict) else None
    recovered_at = evidence.get("recovered_at") if isinstance(evidence, dict) else None
    if not safe_receipt_part(key) or not valid_timestamp(recovered_at):
        log(f"automatic readmission unknown for {repo}#{pr_number}: the recovery evidence is "
            f"malformed (key={key!r}, recovered_at={recovered_at!r}); the capacity park stands")
        return (None, None, "the recovery evidence is malformed")
    recovered_canonical = canonical_ts(recovered_at)
    if key in {receipt.get("key") for receipt in auto_receipts if isinstance(receipt, dict)}:
        log(f"automatic readmission declined for {repo}#{pr_number}: the recovery evidence "
            f"{key!r} was already consumed by a receipted automatic re-admission — a NEW "
            "outage-and-recovery pair is required")
        return (None, None, f"recovery evidence {key!r} already consumed")
    if latest_park is not None and parse_ts(recovered_at) <= latest_park:
        return (None, None,
                f"the recovery at {recovered_canonical} is not STRICTLY after the park "
                f"application at {parked_at}")
    return ("auto-mint", {"key": key, "at": recovered_canonical},
            f"recovery evidence {key!r} recorded at {recovered_canonical}, strictly after the "
            f"park application at {parked_at}")


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
    evidence and AUTO_READMISSION_MAX. The park-generation ladder is unchanged and still
    escalates to the QUESTION class after PARK_ESCALATION_GENERATIONS consumed windows, so a PR
    that is automatically re-admitted and then exhausts its real budget again still reaches a
    human — it just does so having actually retried.

    WINDOW_UNREADABLE is contagious and wins outright: an automatic stamp must never mask an
    unreadable label timeline (the ladder has to FREEZE on unproven data). A malformed automatic
    stamp is dropped with a loud log — unprovable time can never mint a window."""
    if human_cutoff == WINDOW_UNREADABLE:
        return WINDOW_UNREADABLE
    candidates = []
    for source, stamp in ([("human gesture", human_cutoff)] if human_cutoff else []) \
            + [("automatic re-admission", stamp) for stamp in (auto_stamps or [])]:
        if not valid_timestamp(stamp):
            log(f"::warning::readmission window: dropping the malformed {source} stamp "
                f"{stamp!r} — unprovable time can never mint a budget window")
            continue
        candidates.append((parse_ts(stamp), stamp))
    return canonical_ts(max(candidates)[1]) if candidates else None


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
    # --- genuine human questions: terminal, human-owned --------------------------------------
    "injection": PARK_CLASS_QUESTION,         # prompt-injection flag raised on the PR
    "human-arm": PARK_CLASS_QUESTION,         # a human requested changes / asked to arm by hand
    "history-rewritten": PARK_CLASS_QUESTION,  # head no longer descends from the opened commit
    "marker-corrupt": PARK_CLASS_QUESTION,    # durable round/model/pin markers failed validation
    "routing-unresolvable": PARK_CLASS_QUESTION,  # no concrete provider model in the catalog
    # --- adjudicated deadlocks: the ONLY machine-writable route out of a deadlock ------------
    "undecidable": PARK_CLASS_QUESTION,       # an independent adjudicator ran and could NOT
                                              # decide the reviewer-vs-fixer disagreement
    "premise-wrong": PARK_CLASS_QUESTION,     # an independent adjudicator judged the PR's own
                                              # premise wrong (close honestly / re-file)
}

# --- registry #703: a reviewer-vs-fixer DEADLOCK is not a capacity park ----------------------
#
# `review:parked` is documented as the machine-recoverable CAPACITY class, but the two causes
# below are not capacity at all: the loop DID iterate and terminated in a disagreement. Measured
# on sparq 2026-07-26 — 27 parked PRs, whose park comments read either "the review round budget
# is exhausted at 3 round(s)" (preceded by `cross-provider review round 3: request_changes`) or
# "two consecutive fix attempts made no change (fixer judges the findings spurious)". Both are
# the SAME situation: the reviewer says "change this", the fixer says "cannot / should not", and
# nobody decides who is right.
#
# Two consequences follow, and this module enforces both:
#
# (1) The generation ladder must not carry a deadlock into the HUMAN terminal. Measured over
#     2026-07-26 15:15-15:45 UTC, `review:parked` fell 27 -> 19 while `review:needs-user` rose
#     14 -> 19 on the SAME PRs — 5 PRs in 30 minutes, #3683 and #2493 on their SECOND park
#     exactly as PARK_ESCALATION_GENERATIONS prescribes, i.e. ~10 PRs/hour converted into
#     permanent maintainer backlog, each having burned two round budgets and six account leases.
#     Escalating a CAPACITY park to a human after two windows is reasonable (the fleet genuinely
#     cannot proceed). Escalating a machine-decidable disagreement there is a category error:
#     a PR whose only history is "reviewer and fixer disagreed" has nothing for the maintainer to
#     decide that an adjudicator could not. So park_ladder_decision NEVER returns "terminal" for
#     a deadlock cause — it returns "await-adjudication" instead.
#
# (2) Re-admitting an UNADJUDICATED deadlock is a guaranteed-wasted generation: the same
#     reviewer and the same fixer at the same tier reproduce the same disagreement, burn another
#     round budget and another three leases, and park again — and that second park is what
#     ADVANCES the ladder toward the human terminal. So the re-admission (capacity_park_admission)
#     refuses an unadjudicated deadlock outright. Same lesson as #701 (retrying an unchanged
#     configuration yields the same nothing) and #500 (a decline is REROUTED, not re-deferred).
#
# The exit is an ADJUDICATION receipt (see PARK_ADJUDICATION_MARKER below), never a timeout:
# "reviewer overruled" must be a reasoned finding with evidence, because a vacuous override
# merges the exact defect the reviewer was pointing at.
PARK_DEADLOCK_CAUSES = frozenset({"budget", "nochange"})

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


def park_cause_is_deadlock(cause):
    """True iff `cause` names a reviewer-vs-fixer DEADLOCK (registry #703) rather than a genuine
    capacity/infra stall.

    The fail direction is deliberately the OPPOSITE of park_cause_class's: an unknown or absent
    cause is NOT a deadlock. Every guard keyed on this function either withholds a human
    escalation or refuses a re-admission, so answering "deadlock" on unproven data would strand a
    genuine capacity park in a class that has no capacity exit. Unknown therefore keeps EXACTLY
    the pre-#703 behaviour (escalate on the ladder, re-admit on recovery evidence), and only a
    park whose cause is positively proven a deadlock is treated as one."""
    return isinstance(cause, str) and cause in PARK_DEADLOCK_CAUSES


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


# --- registry #703: the ADJUDICATION receipt -------------------------------------------------
#
# The one durable artefact that resolves a reviewer-vs-fixer deadlock. It is the ONLY thing that
# lets a deadlock park be re-admitted or escalated, so its trust properties carry the whole
# guarantee:
#
# - INDEPENDENCE. `by=` (the adjudicating model alias) must not appear in `against=` (the aliases
#   of the refused review and of the fix that refused it). An adjudicator that is one of the two
#   parties is SELF-APPROVAL — it happened on sparq#3803 on 2026-07-26 and voided a verdict — so
#   a receipt that fails this test is REJECTED, not repaired. Rejection leaves the deadlock
#   unadjudicated, which is the fail direction every other ambiguity in this module takes.
# - HEAD-BINDING. `head=` binds the adjudication to the exact head it examined. A deadlock is
#   resolved for THAT tree only; a later push must be adjudicated again. Consumers compare
#   `head` against the live head themselves — an adjudication of a superseded head is exactly how
#   a stale verdict merges (#4220's load-bearing property, applied to the same axis here).
# - CLOSED DECISION SET. Anything outside PARK_ADJUDICATION_DECISIONS is rejected, so a drifted
#   or hostile writer cannot invent an outcome whose meaning no consumer agreed to.
# - BOT-ONLY. park_adjudication_records applies the same bot_login trust filter as every other
#   receipt family here, so a third party cannot talk a park out of its class by quoting a string.
#
# "Reviewer overruled" is therefore always a recorded, attributed, head-bound decision by a named
# third model — never a timeout, and never the fixer's own say-so.
PARK_ADJUDICATION_MARKER = "<!-- sparq-park-adjudication:v1"

# decision -> what the consumer may do with it.
#   "spurious"      the reviewer's findings do not survive scrutiny; the fixer was right. The
#                   review state may be cleared and the PR allowed to arm.
#   "escalate-impl" the findings are REAL and the fix tier was too weak: escalate (or decompose)
#                   the IMPLEMENTATION rather than re-running the tier that already failed.
#   "premise-wrong" the PR's own premise is wrong: close it honestly and re-file the underlying
#                   issue if it still matters.
#   "undecidable"   the adjudicator ran and could not decide. This — and only this — is what
#                   legitimately reaches a human, and it is DIFFERENT information from
#                   "not yet tried".
PARK_ADJUDICATION_DECISIONS = {
    "spurious": PARK_CLASS_CAPACITY,
    "escalate-impl": PARK_CLASS_CAPACITY,
    "premise-wrong": PARK_CLASS_QUESTION,
    "undecidable": PARK_CLASS_QUESTION,
}

# Decisions that end the loop at a human. Kept as its own name so a consumer cannot re-derive it
# from the class table and get it subtly wrong.
PARK_ADJUDICATION_TERMINAL = frozenset({"premise-wrong", "undecidable"})

_PARK_ADJUDICATION_RE = re.compile(
    re.escape(PARK_ADJUDICATION_MARKER)
    + r" decision=(\S+) by=(\S+) against=(\S+) head=(\S+) -->")


def park_adjudication_marker(decision, by, against, head):
    """The durable machine-readable adjudication receipt for ONE deadlock.

    Raises ValueError on anything unrepresentable or non-independent — an adjudication that
    cannot be written truthfully must fail LOUD at the writer rather than be written in a shape
    readers reject (that is how #610's gen-1 receipts were silently lost), and a writer must
    never be able to mint a self-approval that a reader would then have to catch."""
    if decision not in PARK_ADJUDICATION_DECISIONS:
        raise ValueError(f"unknown adjudication decision {decision!r}")
    parties = tuple(against or ())
    if not parties:
        raise ValueError("an adjudication must name the parties it was independent OF")
    for part in (by, *parties):
        if not safe_receipt_part(str(part)) or "," in str(part):
            raise ValueError(f"unsafe adjudication alias {part!r}")
    if str(by) in {str(part) for part in parties}:
        raise ValueError(
            f"adjudicator {by!r} is one of the deadlocked parties — that is self-approval")
    if not safe_receipt_part(str(head)):
        raise ValueError(f"unsafe adjudication head {head!r}")
    return (f"{PARK_ADJUDICATION_MARKER} decision={decision} by={by} "
            f"against={','.join(str(part) for part in parties)} head={head} -->")


def parse_park_adjudication(body, log=print):
    """The LAST well-formed, INDEPENDENT adjudication receipt in `body`, else None.

    A receipt naming an unknown decision, or whose adjudicator is one of the parties it claims to
    have adjudicated between, is dropped with a loud log — never repaired. Repairing would mean
    choosing which half to believe, and the dangerous direction is obvious: a receipt reading
    `by=sol against=sol,opus5` must never clear the very review that `sol` refused."""
    if not isinstance(body, str):
        return None
    found = None
    for match in _PARK_ADJUDICATION_RE.finditer(body):
        decision, by, against, head = match.groups()
        if decision not in PARK_ADJUDICATION_DECISIONS:
            log(f"::warning::adjudication receipt names an unknown decision {decision!r}; "
                "ignoring it (the deadlock stays unadjudicated)")
            continue
        parties = tuple(part for part in against.split(",") if part)
        if not parties:
            log("::warning::adjudication receipt names no deadlocked parties; ignoring it "
                "(an adjudication that cannot show independence proves nothing)")
            continue
        if by in parties:
            log(f"::warning::adjudication receipt claims adjudicator {by!r} decided a deadlock "
                f"it was itself a party to ({against!r}); ignoring it — that is self-approval")
            continue
        found = {"decision": decision, "by": by, "against": parties, "head": head,
                 "class": PARK_ADJUDICATION_DECISIONS[decision]}
    return found


def park_adjudication_records(comments, bot_login, log=print):
    """Every well-formed INDEPENDENT adjudication receipt across the BOT's OWN comments, oldest
    first. Without a `bot_login` nothing is trusted (the same filter park_reason_records uses)."""
    if not bot_login:
        return []
    records = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        if login.casefold() != str(bot_login).casefold():
            continue
        record = parse_park_adjudication(str(comment.get("body", "")), log=log)
        if record:
            records.append(record)
    return records


def deadlock_awaiting_adjudication(cause, adjudications, head=""):
    """True iff this park is a PROVEN deadlock with no usable adjudication for the CURRENT head.

    `cause` is the park's machine-readable cause (park_reason_records / latest_park_cause);
    `adjudications` are the trusted receipts (park_adjudication_records); `head` is the PR's live
    head SHA.

    Fail direction, stated explicitly because it is the opposite of most guards in this module:
    an unknown cause answers False (see park_cause_is_deadlock) and an unknown head answers True
    for a proven deadlock. That pairing is deliberate — refusing to classify an unproven park as
    a deadlock preserves its existing capacity exit, while refusing to honour an adjudication we
    cannot bind to the live head preserves the review bar. Neither direction ever clears a review
    state on missing data."""
    if not park_cause_is_deadlock(cause):
        return False
    if not head:
        return True                       # cannot bind an adjudication to an unknown head
    for record in reversed(list(adjudications or [])):
        if isinstance(record, dict) and record.get("head") == head:
            return False
    return True


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
LEGACY_PARK_DENY_PROSE = (
    (re.compile(r"possible prompt injection", re.IGNORECASE), "injection"),
    (re.compile(r"prompt[- ]injection", re.IGNORECASE), "injection"),
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
       reach past it.
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


def latest_park_cause(comments, bot_login, log=print):
    """The park cause currently on record for a PR, or None when none is proven.

    Markers first (the writer's own classification), prose second so the ~27 parks that predate
    the marker writer are classified too — they are the population registry #703 measured, and a
    deadlock guard that only saw future parks would fix nothing this week.

    LEGACY_PARK_DENY_PROSE dominates unconditionally and order-independently, exactly as in
    reclassify_legacy_park and for the same live reason (sparq #3743 / #3608 carry a genuine
    injection escalation AND a later capacity-park comment): a raised injection flag is a
    property of the PR's whole history, not of its newest comment, and such a park must never be
    reclassified as a machine-decidable deadlock. Prose is read ONLY from the bot's own comments,
    so a third party cannot mint a cause by quoting a sentence."""
    if not bot_login:
        return None
    marker_records = park_reason_records(comments, bot_login, log=log)
    if marker_records:
        return marker_records[-1].get("cause")
    bot_bodies = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        if login.casefold() != str(bot_login).casefold():
            continue
        bot_bodies.append(str(comment.get("body", "")))
    for body in bot_bodies:
        for pattern, _denied in LEGACY_PARK_DENY_PROSE:
            if pattern.search(body):
                return None
    cause = None
    for body in bot_bodies:
        for pattern, candidate in LEGACY_PARK_PROSE:
            if pattern.search(body):
                cause = candidate
    return cause


def park_ladder_decision(cutoff, receipts, already_labeled=False, fingerprint=None,
                         consumed_fingerprints=frozenset(), cause=None):
    """The ONE label-independent capacity-park escalation ladder (round-3 finding 1), shared
    by the deferred-issue lane (dispatch-claim) and the worker-PR lane (worker-pr needs_user).
    `cutoff` is readmission_cutoff(..., on_unreadable=WINDOW_UNREADABLE); `receipts` is the
    durable bot-authored receipt set (worker-pr park_generation_cutoffs); `already_labeled`
    says whether the machine park label is currently live (COMMENT-DEDUPE input only — the
    generation math never reads it). Returns (action, window_key, generation):

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
    - ("await-adjudication", window_key, generation): PARK_ESCALATION_GENERATIONS windows
      consumed, BUT `cause` names a proven reviewer-vs-fixer deadlock (PARK_DEADLOCK_CAUSES,
      registry #703). The escalation to the human terminal is WITHHELD — a disagreement two
      models had is not a question only a human can answer, and escalating it there is the
      category error that converted ~10 PRs/hour into permanent maintainer backlog. The caller
      consumes the window and receipts it exactly as for "park" (so the accounting is unchanged
      and honest), keeps the MACHINE-owned label, and records that the park is awaiting
      adjudication — which is different information from "not yet tried". `cause` defaults to
      None, and an unknown cause is NOT a deadlock, so every pre-#703 caller keeps its exact
      previous behaviour.
    - ("terminal", window_key, generation): PARK_ESCALATION_GENERATIONS windows consumed —
      escalate to the question class. The terminal label write must consult the sticky veto
      and the comment must be HONEST when the write was suppressed (never claim a label that
      did not land). Requires a REAL cutoff: the initial PARK_WINDOW_NONE window alone can
      never escalate, and a cutoff that regressed to None cannot prove a fresh window.
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
    generation = len(receipts) + 1
    if cutoff and generation >= PARK_ESCALATION_GENERATIONS:
        # registry #703: the generation ladder escalates a CAPACITY park to a human after
        # PARK_ESCALATION_GENERATIONS consumed windows, which is right — the fleet genuinely
        # cannot proceed and only a human can supply what is missing. A DEADLOCK park has no
        # such property: nothing about "the reviewer and the fixer disagreed" is a question only
        # a human can answer, and the measured composition (5 PRs in 30 minutes, ~10/hour) turns
        # this one `return` into a machine for manufacturing permanent maintainer backlog. So a
        # proven deadlock stops here and awaits adjudication instead. It reaches a human only
        # through an adjudication receipt that says `undecidable` or `premise-wrong` — both of
        # which are QUESTION-class causes and therefore never take this capacity branch at all.
        if park_cause_is_deadlock(cause):
            return ("await-adjudication", window_key, generation)
        return ("terminal", window_key, generation)
    return ("park", window_key, generation)


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
          park_ladder_decision("0001-01-01T00:00:00+23:59", set()), ("freeze", None, None))

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
          park_ladder_decision(WINDOW_UNREADABLE, set()), ("freeze", None, None))
    check("ladder: initial park consumes the PARK_WINDOW_NONE window as generation 1",
          park_ladder_decision(None, set()), ("park", PARK_WINDOW_NONE, 1))
    check("ladder: the initial window re-fires quietly once receipted",
          park_ladder_decision(None, {PARK_WINDOW_NONE}), ("dedupe", PARK_WINDOW_NONE, None))
    check("ladder: legacy pre-receipt park stays quiet (no receipt minted)",
          park_ladder_decision(None, set(), already_labeled=True),
          ("legacy-quiet", None, None))
    check("ladder: a fresh gesture window after the initial receipt is TERMINAL at gen 2",
          park_ladder_decision("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE}),
          ("terminal", "2026-07-23T09:18:19Z", 2))
    check("ladder: a fresh gesture window with NO prior receipts parks as generation 1",
          park_ladder_decision("2026-07-23T09:18:19Z", set()),
          ("park", "2026-07-23T09:18:19Z", 1))
    check("ladder: an already-receipted gesture window dedupes (comments), never advances",
          park_ladder_decision("2026-07-23T09:18:19Z", {"2026-07-23T09:18:19Z"}),
          ("dedupe", "2026-07-23T09:18:19Z", None))
    check("ladder: a cutoff regressed to None can NEVER escalate past prior receipts",
          park_ladder_decision(None, {"2026-07-21T08:00:00Z"}),
          ("park", PARK_WINDOW_NONE, 2))
    check("ladder: already_labeled never suppresses a due receipt once a window exists",
          park_ladder_decision("2026-07-23T09:18:19Z", set(), already_labeled=True),
          ("park", "2026-07-23T09:18:19Z", 1))
    # Round-6 finding 2: the ladder CANONICALIZES the window key it hands to every receipt
    # writer — a space-form cutoff mints the compact Z-form key (writable + round-trippable),
    # dedupes against its canonical receipt, and escalates on the canonical identity.
    check("ladder round-6 f2: a space-form cutoff mints the CANONICAL window key",
          park_ladder_decision("2026-07-23 10:30:00Z", set()),
          ("park", "2026-07-23T10:30:00Z", 1))
    check("ladder round-6 f2: a space-form cutoff dedupes against its canonical receipt",
          park_ladder_decision("2026-07-23 10:30:00Z", {"2026-07-23T10:30:00Z"}),
          ("dedupe", "2026-07-23T10:30:00Z", None))
    check("ladder round-6 f2: a space-form cutoff reaches the gen-2 terminal",
          park_ladder_decision("2026-07-23 10:30:00Z", {PARK_WINDOW_NONE}),
          ("terminal", "2026-07-23T10:30:00Z", 2))
    check("ladder round-6 f2: an unparseable cutoff freezes (defensive rail — it can mint "
          "neither a window key nor a receipt)",
          park_ladder_decision("not-a-timestamp", set()), ("freeze", None, None))

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
          park_ladder_decision("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE},
                               fingerprint=f"{head}/rounds=5",
                               consumed_fingerprints=consumed),
          ("unchanged", "2026-07-23T09:18:19Z", None))
    # (b) the head ADVANCED => real work was attempted => the window is consumed normally.
    check("(b) ladder: an advanced head consumes the fresh window (gen-2 terminal at the "
          "configured bound)",
          park_ladder_decision("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE},
                               fingerprint=f"{'b' * 40}/rounds=5",
                               consumed_fingerprints=consumed),
          ("terminal", "2026-07-23T09:18:19Z", 2))
    # (b') the head did NOT move but the ATTEMPT COUNTER did (a re-review on the same head, a
    # no-change fix, a failed local gate, another missed dispatch): genuinely consumed work, so
    # the window IS consumed — this is what keeps the escalation bound reachable.
    check("(b') ladder: an advanced attempt counter on an UNCHANGED head still consumes the "
          "window (bounded escalation survives)",
          park_ladder_decision("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE},
                               fingerprint=f"{head}/rounds=6",
                               consumed_fingerprints=consumed),
          ("terminal", "2026-07-23T09:18:19Z", 2))
    check("ladder: the FIRST park always lands — no receipted fingerprint can match",
          park_ladder_decision(None, set(), fingerprint=f"{head}/rounds=5",
                               consumed_fingerprints=frozenset()),
          ("park", PARK_WINDOW_NONE, 1))
    check("ladder: a legacy receipt (no fingerprint recorded) claims no idempotence",
          park_ladder_decision("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE},
                               fingerprint=f"{head}/rounds=5",
                               consumed_fingerprints=frozenset()),
          ("terminal", "2026-07-23T09:18:19Z", 2))
    check("ladder: an unknown fingerprint (None) can never suppress a due park",
          park_ladder_decision("2026-07-23T09:18:19Z", {PARK_WINDOW_NONE},
                               fingerprint=None, consumed_fingerprints=consumed),
          ("terminal", "2026-07-23T09:18:19Z", 2))
    # Precedence: the window dedupe (already receipted) and the freeze (unproven timeline)
    # both outrank the fingerprint check — an unchanged fingerprint must never turn a frozen
    # or already-receipted decision into a different action.
    check("ladder: the same-window dedupe still wins over the fingerprint check",
          park_ladder_decision("2026-07-23T09:18:19Z", {"2026-07-23T09:18:19Z"},
                               fingerprint=f"{head}/rounds=5",
                               consumed_fingerprints=consumed),
          ("dedupe", "2026-07-23T09:18:19Z", None))
    check("ladder: an unreadable timeline still FREEZES ahead of the fingerprint check",
          park_ladder_decision(WINDOW_UNREADABLE, {PARK_WINDOW_NONE},
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
        action, key, _generation = park_ladder_decision(
            window, ladder_receipts, fingerprint=fingerprint,
            consumed_fingerprints=ladder_consumed)
        real_actions.append(action)
        ladder_receipts.add(key)
        ladder_consumed.add(fingerprint)
        # ... the very next tick re-derives the SAME exhaustion from the SAME state under a
        # BRAND-NEW readmission window (a human just re-admitted): the #3488 bounce.
        bounce_actions.append(park_ladder_decision(
            f"2026-07-24T{step:02d}:00:00Z", ladder_receipts, fingerprint=fingerprint,
            consumed_fingerprints=ladder_consumed)[0])
    check("(d) genuinely consumed windows climb the ladder to the configured TERMINAL and "
          "stay there",
          real_actions,
          ["park"] * (PARK_ESCALATION_GENERATIONS - 1) + ["terminal", "terminal"])
    check("(d) an unchanged-state re-derivation NEVER advances the ladder at any generation "
          "(the bound is spent only on work actually attempted)",
          bounce_actions, ["unchanged"] * (PARK_ESCALATION_GENERATIONS + 1))

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

    # ---- #703: a reviewer-vs-fixer DEADLOCK is not a capacity park ---------------------------
    # Each check below names the guard it protects; deleting or inverting that guard turns THIS
    # named line red. The two live park sentences are the exact strings the fleet writes
    # (worker-pr.needs_user's park body), so a fixture cannot satisfy both the right and the
    # wrong reading of the classifier.
    head_a = "a" * 40
    head_b = "b" * 40

    def _raises(exc_type, fn, *fn_args):
        try:
            fn(*fn_args)
        except exc_type:
            return True
        return False

    check("#703: the round-budget park cause is a DEADLOCK cause",
          park_cause_is_deadlock("budget"), True)
    check("#703: the fixer-declares-findings-spurious park cause is a DEADLOCK cause",
          park_cause_is_deadlock("nochange"), True)
    for capacity_cause in ("dispatch-missed", "gatefail", "cold-groom"):
        check(f"#703: {capacity_cause!r} is a genuine CAPACITY park, never a deadlock",
              park_cause_is_deadlock(capacity_cause), False)
    for human_cause in ("injection", "human-arm", "history-rewritten", "marker-corrupt",
                        "routing-unresolvable"):
        check(f"#703: the human-question cause {human_cause!r} is never a deadlock",
              park_cause_is_deadlock(human_cause), False)
    check("#703: an UNKNOWN cause is not a deadlock (unproven data keeps the old behaviour)",
          [park_cause_is_deadlock(value) for value in (None, "", "nonsense", 7, ["budget"])],
          [False, False, False, False, False])
    check("#703: every deadlock cause is inside the closed PARK_CAUSES taxonomy",
          sorted(cause for cause in PARK_DEADLOCK_CAUSES if cause not in PARK_CAUSES), [])
    check("#703: no deadlock cause is a human-only cause (they must stay machine-decidable)",
          sorted(PARK_DEADLOCK_CAUSES & PARK_HUMAN_ONLY_CAUSES), [])
    check("#703: an adjudicated-terminal cause is QUESTION-class, so it reaches the human "
          "terminal without the capacity ladder",
          sorted(cause for cause in ("undecidable", "premise-wrong")
                 if park_cause_class(cause) != PARK_CLASS_QUESTION), [])

    # -- the ladder: a deadlock never escalates to the HUMAN terminal on generation count --
    real_window = "2026-07-26T15:17:00Z"
    check("#703: a CAPACITY park still escalates to the human terminal at generation 2",
          park_ladder_decision(real_window, {PARK_WINDOW_NONE}, cause="dispatch-missed"),
          ("terminal", real_window, 2))
    check("#703: an UNCLASSIFIED park still escalates exactly as before this change",
          park_ladder_decision(real_window, {PARK_WINDOW_NONE}),
          ("terminal", real_window, 2))
    check("#703: a round-budget DEADLOCK awaits adjudication instead of the human terminal "
          "(sparq #3683/#2493 escalated on their SECOND park)",
          park_ladder_decision(real_window, {PARK_WINDOW_NONE}, cause="budget"),
          ("await-adjudication", real_window, 2))
    check("#703: a no-change DEADLOCK awaits adjudication instead of the human terminal",
          park_ladder_decision(real_window, {PARK_WINDOW_NONE}, cause="nochange"),
          ("await-adjudication", real_window, 2))
    check("#703: withholding the escalation does NOT change generation accounting",
          park_ladder_decision(real_window, {PARK_WINDOW_NONE}, cause="budget")[2],
          park_ladder_decision(real_window, {PARK_WINDOW_NONE})[2])
    check("#703: the FIRST deadlock park is an ordinary park, not an adjudication wait",
          park_ladder_decision(None, set(), cause="budget"), ("park", PARK_WINDOW_NONE, 1))
    check("#703: an unreadable timeline still FREEZES a deadlock park (no receipt, no label)",
          park_ladder_decision(WINDOW_UNREADABLE, {PARK_WINDOW_NONE}, cause="budget"),
          ("freeze", None, None))
    check("#703: a receipted window still dedupes for a deadlock park",
          park_ladder_decision(real_window, {real_window}, cause="budget"),
          ("dedupe", real_window, None))
    check("#703: the unchanged-fingerprint skip still wins over the adjudication wait",
          park_ladder_decision(real_window, {PARK_WINDOW_NONE}, cause="budget",
                               fingerprint=f"{head_a}/rounds=3",
                               consumed_fingerprints={f"{head_a}/rounds=3"}),
          ("unchanged", real_window, None))

    # -- the adjudication receipt: independence + head-binding + the closed decision set --
    adjudication = park_adjudication_marker("spurious", "opus5", ("sol", "fable"), head_a)
    check("#703: a well-formed adjudication round-trips through its parser",
          parse_park_adjudication(adjudication),
          {"decision": "spurious", "by": "opus5", "against": ("sol", "fable"),
           "head": head_a, "class": PARK_CLASS_CAPACITY})
    check("#703: the WRITER refuses to mint a self-approving adjudication",
          _raises(ValueError, park_adjudication_marker, "spurious", "sol", ("sol", "fable"),
                  head_a), True)
    check("#703: the READER rejects a self-approving adjudication (sparq#3803's shape)",
          parse_park_adjudication(
              f"{PARK_ADJUDICATION_MARKER} decision=spurious by=sol against=sol,fable "
              f"head={head_a} -->"), None)
    check("#703: the READER rejects an adjudication that names no parties",
          parse_park_adjudication(
              f"{PARK_ADJUDICATION_MARKER} decision=spurious by=sol against=, "
              f"head={head_a} -->"), None)
    check("#703: the READER rejects a decision outside the closed set",
          parse_park_adjudication(
              f"{PARK_ADJUDICATION_MARKER} decision=overrule by=opus5 against=sol "
              f"head={head_a} -->"), None)
    check("#703: the WRITER refuses a decision outside the closed set",
          _raises(ValueError, park_adjudication_marker, "overrule", "opus5", ("sol",), head_a),
          True)
    check("#703: the WRITER refuses an alias that would break the receipt grammar",
          _raises(ValueError, park_adjudication_marker, "spurious", "op us5", ("sol",), head_a),
          True)
    check("#703: the WRITER refuses an adjudication that names no parties",
          _raises(ValueError, park_adjudication_marker, "spurious", "opus5", (), head_a), True)
    check("#703: only the BOT's own comments are adjudication receipts",
          [record["decision"] for record in park_adjudication_records(
              [bot_comment(adjudication),
               {"user": {"login": "attacker"}, "body": adjudication}], bot)],
          ["spurious"])
    check("#703: without a bot login NO adjudication is trusted",
          park_adjudication_records([bot_comment(adjudication)], ""), [])
    check("#703: premise-wrong and undecidable are the ONLY terminal adjudications",
          sorted(PARK_ADJUDICATION_TERMINAL), ["premise-wrong", "undecidable"])

    # -- deadlock_awaiting_adjudication: the predicate both guards consume --
    trusted_adjudications = park_adjudication_records([bot_comment(adjudication)], bot)
    check("#703: a proven deadlock with NO adjudication is awaiting one",
          deadlock_awaiting_adjudication("budget", [], head_a), True)
    check("#703: a head-bound adjudication releases the deadlock",
          deadlock_awaiting_adjudication("budget", trusted_adjudications, head_a), False)
    check("#703: an adjudication bound to a SUPERSEDED head does NOT release the deadlock",
          deadlock_awaiting_adjudication("budget", trusted_adjudications, head_b), True)
    check("#703: an UNKNOWN head never honours an adjudication (fail closed)",
          deadlock_awaiting_adjudication("budget", trusted_adjudications, ""), True)
    check("#703: a genuine capacity park is never held for adjudication",
          deadlock_awaiting_adjudication("dispatch-missed", [], head_a), False)
    check("#703: an unclassified park is never held for adjudication",
          deadlock_awaiting_adjudication(None, [], head_a), False)

    # -- the re-admission refusal --
    timelines.clear()
    timelines[41] = [event("labeled", "review:parked", "2026-07-26T02:00:00Z",
                           "sparq-orchestrator[bot]")]
    timelines[7] = []
    fresh_recovery = evidence_at("anthropic/deadbeefdeadbeef/91.1", "2026-07-26T03:00:00Z")
    check("#703: WITHOUT the deadlock flag this park would be automatically re-admitted "
          "(the fixture proves the refusal below is doing the work)",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                                  auto_evidence=fresh_recovery)[0], "auto-mint")
    logs.clear()
    refused = capacity_park_admission(
        "o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
        auto_evidence=evidence_at("anthropic/deadbeefdeadbeef/91.2", "2026-07-26T03:00:00Z"),
        deadlock_unadjudicated=True)
    check("#703: an UNADJUDICATED deadlock is never automatically re-admitted",
          refused[0], None)
    check("#703: the refusal is loud (it is the mechanism that fed the human-hold conveyor)",
          any("UNADJUDICATED reviewer-vs-fixer deadlock" in line for line in logs), True)
    spent = evidence_at("anthropic/deadbeefdeadbeef/91.3", "2026-07-26T03:00:00Z")
    capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                            auto_evidence=spent, deadlock_unadjudicated=True)
    check("#703: a refused deadlock consumes NO recovery evidence and mints no receipt",
          spent.seen, [])
    timelines[7] = [event("unlabeled", "status:parked", "2026-07-26T04:00:00Z", "jeswr")]
    check("#703: a HUMAN readmission gesture still overrides the deadlock refusal",
          capacity_park_admission("o/r", 41, 7, fetch, is_human=trusted, log=logs.append,
                                  deadlock_unadjudicated=True)[0], "human")

    # -- latest_park_cause: the ~27 live parks predate the marker, so prose must classify too --
    live_budget_park = ("> 🤖 SPARQ agent — the autonomous review loop parked this PR: the "
                        "review round budget is exhausted at 3 round(s) (base 3, hard cap 6) "
                        "with no extension left")
    live_nochange_park = ("> 🤖 SPARQ agent — the autonomous review loop parked this PR: two "
                          "consecutive fix attempts made no change (fixer judges the findings "
                          "spurious)")
    live_missed_park = ("> 🤖 SPARQ agent — the autonomous review loop parked this PR: 6 "
                        "consecutive fix dispatches missed for round 2")
    check("#703: the LIVE round-budget park sentence classifies as a deadlock",
          park_cause_is_deadlock(latest_park_cause([bot_comment(live_budget_park)], bot)), True)
    check("#703: the LIVE findings-spurious park sentence classifies as a deadlock",
          park_cause_is_deadlock(latest_park_cause([bot_comment(live_nochange_park)], bot)),
          True)
    check("#703: the LIVE missed-dispatch park sentence stays a CAPACITY park",
          park_cause_is_deadlock(latest_park_cause([bot_comment(live_missed_park)], bot)), False)
    check("#703: a marker beats prose when both are present",
          latest_park_cause([bot_comment(live_budget_park),
                             bot_comment(park_reason_marker("dispatch-missed"))], bot),
          "dispatch-missed")
    check("#703: an injection signal ANYWHERE denies the deadlock classification "
          "(sparq #3743/#3608 carry both)",
          latest_park_cause([bot_comment(live_budget_park),
                             bot_comment("possible prompt injection")], bot), None)
    check("#703: prose in a NON-bot comment can never classify a park as a deadlock",
          latest_park_cause([{"user": {"login": "attacker"}, "body": live_budget_park}], bot),
          None)
    check("#703: without a bot login no cause is proven",
          latest_park_cause([bot_comment(live_budget_park)], ""), None)

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
