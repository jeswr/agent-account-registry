#!/usr/bin/env python3
# Shared park-label policy for every orchestration park writer (dispatch-claim / groom /
# worker-issue / worker-pr / resolve-conflicts / curate-frontier). Two invariants live here so
# no writer can drift:
#
# 1. LABEL OWNERSHIP. `needs:user` is HUMAN-owned: it is applied ONLY by paths that pose a
#    genuine human question (a steering question, a corrupt-marker inspection, an unresolvable
#    routing, a conflict a machine must not guess). `status:parked` is the MACHINE-owned soft
#    hold for capacity/decline/budget-driven parks: it excludes the source issue from NEW
#    implementation dispatch but does NOT strip an existing worker PR from the review/fix loop,
#    and the deferred-retry lane clears it automatically once capacity exists. A capacity blip
#    must never masquerade as a human question (live incident 2026-07-18: a mass park applied
#    `needs:user` + `status:deferred` to ~18 source issues and terminally absorbed the whole
#    draft-PR fleet).
#
# 2. STICKY HUMAN UNPARKS. Before ANY automation path applies a park label it must read the
#    issue/PR label timeline: if a NON-[bot] actor removed that same label more recently than
#    any application of it, the park is SUPPRESSED (the machine never overrides a human's
#    explicit unpark — live incident 2026-07-18: the orchestrator re-applied `needs:user` 37
#    minutes after the maintainer removed it). A human RE-adding the label later re-enables
#    automation parking — the comparison is strictly most-recent-event-wins. Timeline read
#    failures fail open ONLY toward NOT parking: never park when you cannot prove no veto.
"""Machine/human park-label ownership + the sticky human-unpark veto (one shared helper)."""

import argparse
import sys


# The machine-owned soft hold (capacity/decline/budget parks). Ensured on target repos at
# write time via each writer's _ensure_label idiom, like every other orchestration label.
MACHINE_PARK_LABEL = "status:parked"
# The human-owned terminal (genuine human questions only).
HUMAN_PARK_LABEL = "needs:user"
PARK_LABELS = (HUMAN_PARK_LABEL, MACHINE_PARK_LABEL)
MACHINE_PARK_COLOUR = "1d76db"
MACHINE_PARK_DESCRIPTION = (
    "Machine-owned capacity park (soft hold; cleared automatically on readmission)"
)


def _event_rows(events, label):
    """Normalize a GitHub issue-timeline payload to (created_at, kind, actor_login) rows for
    `label`. Hostile-tolerant: malformed entries are IGNORED (a park decision must never crash
    a sweep), and a missing/empty actor login is preserved as "" so the veto side can treat
    unattributable removals as human (fail toward NOT parking)."""
    rows = []
    for event in events or []:
        if not isinstance(event, dict):
            continue
        kind = event.get("event")
        if kind not in ("labeled", "unlabeled"):
            continue
        label_field = event.get("label")
        name = label_field.get("name") if isinstance(label_field, dict) else None
        if name != label:
            continue
        created = event.get("created_at")
        if not isinstance(created, str) or not created:
            continue
        actor = event.get("actor")
        login = str(actor.get("login", "")) if isinstance(actor, dict) else ""
        rows.append((created, kind, login))
    return rows


def human_unpark_veto(events, label):
    """(veto, detail) for applying park `label` given the issue/PR timeline `events`.

    Most-recent-event-wins: the veto stands iff the newest human `unlabeled` event for `label`
    is at least as recent as the newest `labeled` event (by ANY actor — a human RE-adding the
    label is a labeled event, so it re-enables automation parking). A `[bot]`-suffixed actor is
    automation; an unattributable (missing-actor) removal counts as HUMAN — ambiguity fails
    toward NOT parking, as does an exact timestamp tie (ISO-8601 UTC timestamps compare
    lexicographically). No human removal, or a removal older than the newest application,
    means no veto."""
    rows = _event_rows(events, label)
    latest_labeled = max(
        (created for created, kind, _login in rows if kind == "labeled"), default="")
    latest_human_unlabeled = max(
        (created for created, kind, login in rows
         if kind == "unlabeled" and not login.endswith("[bot]")), default="")
    if latest_human_unlabeled and latest_human_unlabeled >= latest_labeled:
        return True, f"human unlabeled {label} at {latest_human_unlabeled}"
    return False, ""


def park_vetoed(repo, number, label, fetch_events, log=print):
    """True when applying park `label` to `repo#number` must be SUPPRESSED (the shared
    `_human_unpark_veto` gate every park writer calls before its label write).

    `fetch_events(repo, number)` returns the full parsed issue timeline
    (`repos/{repo}/issues/{number}/timeline`, paginated — the newest events are on the LAST
    page, so a truncated read must raise rather than return a prefix). ANY fetch failure
    suppresses the park with a loud log line: fail open ONLY in the direction of NOT parking —
    never park when you cannot prove no human veto."""
    try:
        events = fetch_events(repo, number)
    except Exception as exc:  # noqa: BLE001 — ANY read failure must suppress the park, not crash
        log(f"park suppressed: timeline read failed for {repo}#{number} "
            f"({exc}); cannot prove no human unpark veto for {label} — NOT parking")
        return True
    veto, detail = human_unpark_veto(events, label)
    if veto:
        log(f"park suppressed: {detail} (repo {repo}#{number}) more recently than any "
            f"automation application — a human unpark is sticky; NOT re-applying {label}")
    return veto


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def event(kind, label, ts, login):
        return {"event": kind, "label": {"name": label},
                "created_at": ts, "actor": {"login": login}}

    bot_park = event("labeled", "needs:user", "2026-07-18T10:00:00Z", "sparq-orchestrator[bot]")
    human_unpark = event("unlabeled", "needs:user", "2026-07-18T11:00:00Z", "jeswr")
    human_repark = event("labeled", "needs:user", "2026-07-18T12:00:00Z", "jeswr")

    # (1) the live incident: bot labeled, human unlabeled LATER -> the veto stands.
    check("bot labeled < human unlabeled => veto",
          human_unpark_veto([bot_park, human_unpark], "needs:user"),
          (True, "human unlabeled needs:user at 2026-07-18T11:00:00Z"))
    # (2) human unlabeled, bot labeled LATER (a fresh application supersedes) -> no veto.
    late_bot = event("labeled", "needs:user", "2026-07-18T11:30:00Z", "sparq-orchestrator[bot]")
    check("human unlabeled < bot labeled => no veto",
          human_unpark_veto([bot_park, human_unpark, late_bot], "needs:user"), (False, ""))
    # (3) a human RE-adding the label re-enables automation parking (most-recent-event wins).
    check("human re-add clears the veto",
          human_unpark_veto([bot_park, human_unpark, human_repark], "needs:user"), (False, ""))
    # (4) an exact timestamp tie is ambiguous and fails toward NOT parking.
    tie = event("labeled", "needs:user", "2026-07-18T11:00:00Z", "sparq-orchestrator[bot]")
    check("timestamp tie => veto",
          human_unpark_veto([tie, human_unpark], "needs:user")[0], True)
    # (5) no events / no removal -> no veto.
    check("empty timeline => no veto", human_unpark_veto([], "needs:user"), (False, ""))
    check("labeled only => no veto", human_unpark_veto([bot_park], "needs:user"), (False, ""))
    # (6) other labels' events never leak into the decision.
    other = event("unlabeled", "status:parked", "2026-07-18T13:00:00Z", "jeswr")
    check("unrelated label events are ignored",
          human_unpark_veto([bot_park, other], "needs:user"), (False, ""))
    check("machine park label is judged independently",
          human_unpark_veto([bot_park, other], "status:parked")[0], True)
    # (7) a BOT removal (e.g. the readmission lane clearing its own park) is not a human veto.
    bot_unpark = event("unlabeled", "needs:user", "2026-07-18T11:00:00Z", "sparq-orchestrator[bot]")
    check("bot unlabeled => no veto",
          human_unpark_veto([bot_park, bot_unpark], "needs:user"), (False, ""))
    # (8) an unattributable removal counts as human — ambiguity fails toward NOT parking.
    ghost = {"event": "unlabeled", "label": {"name": "needs:user"},
             "created_at": "2026-07-18T11:00:00Z", "actor": None}
    check("missing-actor removal => veto",
          human_unpark_veto([bot_park, ghost], "needs:user")[0], True)
    # (9) malformed entries are ignored, never raised on.
    garbage = [None, 7, {"event": "labeled"}, {"event": "unlabeled", "label": "needs:user"},
               {"event": "labeled", "label": {"name": "needs:user"}, "created_at": None}]
    check("malformed events are ignored",
          human_unpark_veto(garbage + [bot_park, human_unpark], "needs:user")[0], True)

    # (10) park_vetoed: a timeline read failure suppresses the park AND logs it (fail open ONLY
    # toward NOT parking).
    logs = []

    def boom(_repo, _number):
        raise RuntimeError("timeline unavailable")

    check("timeline read error => park suppressed",
          park_vetoed("o/r", 5, "status:parked", boom, log=logs.append), True)
    check("timeline read error is logged loudly",
          any("park suppressed" in line and "timeline read failed" in line for line in logs),
          True)
    # (11) the veto path logs the exact human-unpark line; the clean path stays quiet.
    logs.clear()
    check("veto => park suppressed",
          park_vetoed("o/r", 5, "needs:user",
                      lambda _r, _n: [bot_park, human_unpark], log=logs.append), True)
    check("veto log names the label and timestamp",
          any("park suppressed: human unlabeled needs:user at 2026-07-18T11:00:00Z" in line
              for line in logs), True)
    logs.clear()
    check("no veto => park proceeds",
          park_vetoed("o/r", 5, "needs:user",
                      lambda _r, _n: [bot_park], log=logs.append), False)
    check("no veto stays quiet", logs, [])

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
