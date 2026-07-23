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
"""Machine/human park-label ownership + the sticky human-unpark veto (one shared helper)."""

import argparse
import sys
from datetime import datetime


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
# The strict maintainer probe set (the worker-issue.py _is_human_maintainer pattern): repo
# collaborator permission must be one of these for an actor to count as a trusted human.
HUMAN_MAINTAINER_PERMISSIONS = {"admin", "maintain", "write"}
MACHINE_PARK_COLOUR = "1d76db"
MACHINE_PARK_DESCRIPTION = (
    "Machine-owned capacity park (soft hold; cleared automatically on readmission)"
)


class MalformedTimelineError(RuntimeError):
    """A label-timeline payload whose RELEVANT shape cannot be trusted (non-dict event,
    unreadable label field, or a relevant event without a readable timestamp). Raised instead
    of silently dropping the entry: a dropped malformed page/event could hide the newest human
    unlabel, so each caller applies its documented fail direction instead (veto => suppress the
    park; budget/readmission => the full historical count)."""


def valid_timestamp(value):
    """STRICT ISO-8601 check for every timestamp consumed by a park decision (round-3 finding
    3/4): parseable via datetime.fromisoformat after Z-normalization. The lexicographic
    comparisons throughout this module are only sound over well-formed ISO-8601 UTC stamps —
    a garbage string like "zzz" would otherwise sort ABOVE every real timestamp and dominate
    max(), silently minting (or destroying) a veto/cutoff."""
    if not isinstance(value, str) or not value:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
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
    human: an unverifiable actor must never mint a veto. An exact timestamp tie between a
    proven-human removal and an application fails toward NOT parking (ISO-8601 UTC timestamps
    compare lexicographically). Malformed relevant events RAISE MalformedTimelineError (the
    park_vetoed wrapper suppresses the park on it)."""
    rows = _event_rows(events, label)
    probe = _human_probe(is_human)
    latest_labeled = max(
        (created for created, kind, _login, _app in rows if kind == "labeled"), default="")
    latest_human_unlabeled = max(
        (created for created, kind, login, via_app in rows
         if kind == "unlabeled" and _is_proven_human(login, via_app, probe)), default="")
    if latest_human_unlabeled and latest_human_unlabeled >= latest_labeled:
        return True, f"human unlabeled {label} at {latest_human_unlabeled}"
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
    latest = max((created for created, kind, login, via_app in rows
                  if kind == "unlabeled" and _is_proven_human(login, via_app, probe)),
                 default="")
    return latest or None


def readmission_cutoff(repo, pr_number, issue_number, fetch_events, is_human=None, log=print,
                       labels=READMISSION_LABELS, on_unreadable=None):
    """The budget readmission cutoff for a worker PR (or a bare source issue): the LATEST
    proven-human `unlabeled` event for ANY of `labels` (default READMISSION_LABELS —
    needs:user / status:parked / review:parked) across the PR itself and its provenance-linked
    source issue (either surface is an explicit human re-admission; latest event wins; ISO-8601
    UTC timestamps compare lexicographically). `issue_number` may be falsy (no linked issue) —
    only the PR timeline is consulted.

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
                    created for created, kind, login, via_app in _event_rows(events, label)
                    if kind == "unlabeled" and _is_proven_human(login, via_app, probe))
        except Exception as exc:  # noqa: BLE001 — a budget question must never crash the sweep
            log(f"readmission window unknown: timeline read failed for {repo}#{number} "
                f"({exc}); NO readmission credit on a partial view — the budget keeps the "
                f"FULL historical count")
            return on_unreadable
    return max(stamps, default=None)


def capacity_park_readmitted(repo, pr_number, issue_number, fetch_events, is_human=None,
                             log=print, consumed=frozenset()):
    """True when a capacity park (durably receipted, whatever labels currently remain) has
    been superseded by an UNCONSUMED human readmission gesture: the readmission cutoff (latest
    proven-human unlabel of any READMISSION_LABELS across both surfaces) is strictly MORE
    RECENT than the latest application of `review:parked` on the PR, AND that cutoff's window
    has not already been consumed-and-receipted. Most-recent-event-wins, with ambiguity (no
    cutoff, a failed/malformed read, or a timestamp tie) failing toward STAYING PARKED —
    re-admission dispatches real work, so it runs only on proven, newest evidence.

    `consumed` is the durable receipt set (worker-pr park_generation_cutoffs — bot-authored
    only): a gesture whose exact cutoff is already receipted was consumed by a previous
    budget window that then re-exhausted; it must never re-admit AGAIN — this is what keeps
    the proof label-INDEPENDENT (round-3 finding 2): a veto-suppressed label re-apply leaves
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
    try:
        rows = _event_rows(fetch_events(repo, pr_number), MACHINE_PARK_PR_LABEL)
    except Exception as exc:  # noqa: BLE001 — ambiguity stays parked
        log(f"readmission unknown: timeline read failed for {repo}#{pr_number} ({exc}); "
            "the capacity park stands")
        return False
    latest_park = max(
        (created for created, kind, _login, _app in rows if kind == "labeled"), default="")
    return cutoff > latest_park


def park_ladder_decision(cutoff, receipts, already_labeled=False):
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
    - ("legacy-quiet", None, None): a pre-receipt park (label live, no gesture, no receipts)
      — stay quiet; generation accounting starts with the first receipted window.
    - ("terminal", window_key, generation): PARK_ESCALATION_GENERATIONS windows consumed —
      escalate to the question class. The terminal label write must consult the sticky veto
      and the comment must be HONEST when the write was suppressed (never claim a label that
      did not land). Requires a REAL cutoff: the initial PARK_WINDOW_NONE window alone can
      never escalate, and a cutoff that regressed to None cannot prove a fresh window.
    - ("park", window_key, generation): consume this window — soft park (veto-gated label,
      best-effort) + the MANDATORY receipt binding window_key.
    """
    if cutoff == WINDOW_UNREADABLE:
        return ("freeze", None, None)
    window_key = cutoff or PARK_WINDOW_NONE
    if window_key in receipts:
        return ("dedupe", window_key, None)
    if not cutoff and already_labeled and not receipts:
        return ("legacy-quiet", None, None)
    generation = len(receipts) + 1
    if cutoff and generation >= PARK_ESCALATION_GENERATIONS:
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

    # ---- STRICT ISO-8601 timestamps (round-3 finding 3/4): a "not-a-timestamp" relevant
    # event RAISES — it can never be a cutoff, never mint a veto, never loosen the park ----
    check("valid_timestamp accepts real ISO-8601 UTC", valid_timestamp("2026-07-23T09:18:19Z"),
          True)
    for garbage_ts in ("zzz-later-than-everything", "not-a-timestamp", "2026-13-99T99:99:99Z",
                      "", None, 7):
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
