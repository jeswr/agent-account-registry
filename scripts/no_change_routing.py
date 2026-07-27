#!/usr/bin/env python3
# [OPUS-5] registry #701: the `no_change` routing decision, as ONE pure module.
"""no_change_routing.py — decide what to do with an issue whose worker produced NO diff.

WHY THIS EXISTS (registry #701, measured 2026-07-26). Of 196 completed `worker.yml` runs, 70
succeeded and 126 failed, and the dominant failure class was the structured `EXIT_CLASS: no_change`
— the model ran to a clean exit and produced no repository change. The SAME issue was then retried
up to 3x with the SAME model and NO record of why the previous attempt produced nothing (#3241
attempt 2/3, #2575 attempt 3/3). Retrying an unchanged configuration reproduces the unchanged
result, so three attempts burned three worker slots and three account leases to produce nothing.

Every sampled `no_change` target was a substantive, well-specified, genuinely hard task, so this is
NOT a stale-backlog or non-implementable-gating problem. It is a task-difficulty <-> execution-mode
mismatch, and the fix has two halves:

  1. WHY_NO_DIFF (`NO_CHANGE_REASONS` below) — the worker records, at exit, a short structured
     reason. Without it, choosing between "try another tier" and "decompose this" is guesswork.
  2. THE DECISION (`retry_decision` below) — a `no_change` never re-dispatches the tier that just
     produced it. It moves to an untried tier from the SAME resolved chain, or, when no untried
     tier remains (or the declared reason says another tier cannot help), routes the issue to
     decomposition. This is the sibling of #500's rule that a decline is REROUTED, not re-deferred.

FAIL-CLOSED, THE THREE DIRECTIONS THAT MATTER:

  * An ABSENT or UNREADABLE reason declaration is `unspecified` (index 0) — never inferred to be
    `too_large`/`underspecified`, which are the two values that skip straight to decomposition. A
    worker that crashes before writing the file therefore takes the ORDINARY ladder.
  * This module NEVER decides that a run WAS a `no_change`. It consumes rows the caller has already
    filtered on a VALIDATED `exit_class == no_change`; an unreadable exit class never reaches here,
    and dispatch's own guard leaves such an issue deferred with no escalation at all.
  * A record whose `model_alias` is absent or empty EXCLUDES NOTHING. An unattributable outcome
    cannot prove which tier already failed, so it must not silently retire a tier from the chain.
    Termination does not depend on it (see below). MEASURED CAVEAT: the guard inside
    `excluded_tiers` is not what binds this — `retry_decision`'s chain filter is (a junk alias can
    never match a well-formed chain entry). Mutating the `excluded_tiers` guard alone leaves
    `retry_decision` unchanged; both are asserted separately in the self-test, and the note is here
    rather than implied so nobody reads that guard as the load-bearing one.

TERMINATION (bounded escalation, machine-recoverable terminal). Two independent bounds:

  * `TIER_EXCLUSION_SECONDS` — a tier is excluded only while its own `no_change` evidence is
    younger than this. This is the machine exit for the narrowing itself: it cannot outlive the
    window even if the ledger keeps the record (model-health prunes at WINDOW_HOURS = 48, 8x
    longer). No human gesture is involved.
  * The caller's decline ladder (dispatch-claim `_escalate_repeated_declines`) still bounds the
    number of `no_change` outcomes an issue may accumulate before it is rerouted to decomposition
    and, once already on a non-implementation route, parked with the MACHINE-owned `status:parked`
    soft hold — never `needs:user` (registry #703: parks that need a human become a conveyor onto
    the maintainer's desk).

So the worst case is: tier A -> (untried tier B, or decomposition) -> park, with the park clearing
automatically once the evidence ages out.
"""
import json
import sys

# The declared reason a worker exited without a diff. ORDER IS THE WIRE FORMAT: worker-live.sh
# encodes the INDEX into the existing numeric-only `no-change-v1` health envelope, because that
# envelope is a protocol boundary whose grammar is deliberately ASCII-decimal only — a free-text
# reason there would be the one field in the record able to carry attacker-chosen text into a
# PUBLIC ledger and into maintainer-facing alert bodies. Append new reasons at the END; never
# reorder, and never renumber an existing one.
NO_CHANGE_REASONS = (
    "unspecified",          # 0 — DEFAULT. No declaration, or one that did not parse.
    "underspecified",       # 1 — the issue does not say enough to act on.
    "blocked_on_decision",  # 2 — needs a decision/answer that is not in the issue.
    "too_large",            # 3 — not completable in one session.
    "already_done",         # 4 — the model judged the work already present on the target.
    "other",                # 5 — a real reason the model could not fit the vocabulary.
)
UNSPECIFIED = NO_CHANGE_REASONS[0]
# The reasons for which trying a DIFFERENT model tier cannot help: the blocker is the TASK's shape,
# not the model's capability. These route straight to decomposition. Kept deliberately small —
# `blocked_on_decision` is NOT here (a stronger/second tier genuinely does sometimes find the
# decision already recorded in the repo), and `unspecified` is NOT here by construction (see the
# fail-closed note above: the default must take the ordinary ladder, not the terminal one).
DECOMPOSE_REASONS = frozenset({"underspecified", "too_large"})
# The machine exit for the tier narrowing (see TERMINATION above). 6h, i.e. the length of a couple
# of provider usage windows: long enough that a same-day retry never re-runs the failed tier,
# short enough that a narrowed chain whose remaining tier has no capacity cannot stall the issue
# for the full 48h health window.
TIER_EXCLUSION_SECONDS = 6 * 3600

# The decisions `retry_decision` can return.
PROCEED = "proceed"                  # no in-window no_change evidence: dispatch the full chain.
RETRY_OTHER_TIER = "retry-other-tier"  # dispatch, but only on tiers that have not already failed.
DECOMPOSE = "decompose"              # do not dispatch this route again; reroute to decomposition.


class ReasonError(ValueError):
    """A stored reason value outside the vocabulary. Raised at the READ boundary so a poisoned or
    hand-forged ledger row can never be silently folded into `unspecified` and then routed on."""


def reason_code(name):
    """Vocabulary name -> wire index. Anything unrecognised (including None/non-str) is 0.

    This is the WRITE side, where the input is a model-authored file: it must be total and must
    fail toward `unspecified`, because the alternative — refusing to record anything — throws away
    the routing signal the whole change exists to capture."""
    try:
        return NO_CHANGE_REASONS.index(name)
    except ValueError:
        return 0


def reason_name(code):
    """Wire index -> vocabulary name. RAISES on an out-of-range code.

    This is the READ side. Unlike `reason_code` it is NOT total: an index outside the vocabulary
    means the envelope was forged or the producer/consumer versions disagree, and folding that to
    `unspecified` would let a forged value pass validation as a legitimate record."""
    if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code < len(NO_CHANGE_REASONS):
        raise ReasonError(f"no_change reason code {code!r} is outside the vocabulary")
    return NO_CHANGE_REASONS[code]


def parse_declaration(text):
    """Decode a worker-written `.worker-no-diff.json` declaration into a vocabulary name.

    TOTAL, and total toward `unspecified`: malformed JSON, a non-object, a missing/non-string
    `why`, or a value outside the vocabulary all yield `unspecified`. The model authors this file,
    so it is UNTRUSTED input; nothing but the closed vocabulary index ever leaves this function.
    """
    try:
        document = json.loads(text)
    except (TypeError, ValueError):
        return UNSPECIFIED
    if not isinstance(document, dict):
        return UNSPECIFIED
    why = document.get("why")
    if not isinstance(why, str) or why not in NO_CHANGE_REASONS:
        return UNSPECIFIED
    return why


def excluded_tiers(records, now, horizon=TIER_EXCLUSION_SECONDS):
    """The model aliases that already produced a `no_change` for this issue RECENTLY.

    `records` are validated model-health rows the caller has already filtered to
    `exit_class == no_change` AND to this issue. A row with a missing/empty/non-string alias
    contributes NOTHING (it cannot prove which tier ran), and a row older than `horizon` contributes
    nothing either — that age bound IS the narrowing's machine exit.
    """
    cutoff = int(now) - int(horizon)
    tiers = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        ts = record.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, int) or ts < cutoff:
            continue
        alias = record.get("model_alias")
        if isinstance(alias, str) and alias:
            tiers.add(alias)
    return tiers


def declared_reasons(records):
    """The set of declared reasons across the given no_change rows (absent -> `unspecified`)."""
    reasons = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        why = record.get("why_no_diff")
        reasons.add(why if why in NO_CHANGE_REASONS else UNSPECIFIED)
    return reasons


def retry_decision(model_chain, records, now, horizon=TIER_EXCLUSION_SECONDS):
    """Return ``(decision, chain)`` for the next dispatch of an issue with `no_change` history.

    * ``(PROCEED, list(model_chain))`` — nothing in evidence; dispatch exactly as before.
    * ``(RETRY_OTHER_TIER, [...])`` — dispatch, but ONLY on the tiers that have not just failed.
      The returned chain is a strict, non-empty subsequence of `model_chain` in its original order,
      so the caller's "the claimed model must be inside the resolved chain" check still holds.
    * ``(DECOMPOSE, [])`` — do not dispatch this route again: either every tier in the chain has
      recent `no_change` evidence, or a declared reason says the task's SHAPE is the blocker.

    The reason check is FIRST and is deliberately narrow (`DECOMPOSE_REASONS`): "this task is too
    large for one session" is not made false by a different model, so spending a second lease to
    re-learn it is the same waste in a new coat.
    """
    chain = [alias for alias in (model_chain or []) if isinstance(alias, str) and alias]
    rows = [record for record in (records or []) if isinstance(record, dict)]
    if not rows:
        return PROCEED, list(chain)
    if declared_reasons(rows) & DECOMPOSE_REASONS:
        return DECOMPOSE, []
    excluded = excluded_tiers(rows, now, horizon=horizon)
    remaining = [alias for alias in chain if alias not in excluded]
    if not remaining:
        return DECOMPOSE, []
    if len(remaining) == len(chain):
        # Evidence exists but retires no tier from THIS chain (unattributable alias, aged-out
        # evidence, or a chain that no longer contains the failed tier). Dispatch normally — the
        # caller's decline ladder, not this narrowing, is what bounds the attempt count.
        return PROCEED, remaining
    return RETRY_OTHER_TIER, remaining


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def row(alias, ts, why=None, issue=7):
        record = {"exit_class": "no_change", "model_alias": alias, "ts": ts, "issue": issue}
        if why is not None:
            record["why_no_diff"] = why
        return record

    now = 1_800_000_000
    chain = ["opus5", "sol"]

    # ---- the vocabulary is a WIRE FORMAT: index 0 must stay `unspecified` and the order must not
    # drift, or every previously written envelope decodes to a different reason.
    chk("reason index 0 is the unspecified default", NO_CHANGE_REASONS[0], "unspecified")
    chk("vocabulary round-trips through the wire index",
        [reason_name(reason_code(name)) for name in NO_CHANGE_REASONS], list(NO_CHANGE_REASONS))
    chk("an unknown reason NAME degrades to the unspecified code", reason_code("wat"), 0)
    chk("a None reason name degrades to the unspecified code", reason_code(None), 0)
    # ...but the READ side refuses an out-of-vocabulary CODE instead of folding it to unspecified.
    for bad in (-1, len(NO_CHANGE_REASONS), True, "0", None, 1.0):
        try:
            reason_name(bad)
        except ReasonError:
            chk(f"reason code {bad!r} is REFUSED at the read boundary", True, True)
        else:
            chk(f"reason code {bad!r} is REFUSED at the read boundary", "accepted", "refused")

    # ---- GUARD: an absent/unreadable declaration is `unspecified`, NEVER a decompose reason.
    # Deleting the `why not in NO_CHANGE_REASONS` arm of parse_declaration turns these red.
    chk("a well-formed declaration parses", parse_declaration('{"why": "too_large"}'), "too_large")
    for hostile in ("", "not json", "[]", "null", '{"why": 3}', '{"why": "TOO_LARGE"}',
                    '{"why": "arbitrary"}', '{"detail": "no why key"}', None, b"{}"):
        chk(f"a malformed declaration {hostile!r} is unspecified",
            parse_declaration(hostile), UNSPECIFIED)
    chk("no malformed declaration can reach a decompose reason",
        sorted({parse_declaration(h) for h in ("", "x", "[]", '{"why": 3}')} & DECOMPOSE_REASONS),
        [])
    chk("unspecified is not a decompose reason", UNSPECIFIED in DECOMPOSE_REASONS, False)

    # ---- GUARD: a no_change does NOT re-dispatch the tier that produced it.
    chk("one no_change on opus5 -> retry on the untried tier only",
        retry_decision(chain, [row("opus5", now - 60)], now), (RETRY_OTHER_TIER, ["sol"]))
    chk("the retried chain never contains the failed tier",
        "opus5" in retry_decision(chain, [row("opus5", now - 60)], now)[1], False)
    chk("one no_change on sol -> retry on opus5 only",
        retry_decision(chain, [row("sol", now - 60)], now), (RETRY_OTHER_TIER, ["opus5"]))
    chk("the returned chain keeps the routing.toml ORDER (never a re-sorted set)",
        retry_decision(["opus5", "sol", "luna"], [row("sol", now - 60)], now),
        (RETRY_OTHER_TIER, ["opus5", "luna"]))

    # ---- GUARD: escalation TERMINATES. Both tiers spent -> decompose, never another dispatch.
    chk("both tiers spent -> decompose",
        retry_decision(chain, [row("opus5", now - 60), row("sol", now - 30)], now),
        (DECOMPOSE, []))
    chk("a single-rung chain decomposes after ONE no_change (nothing left to escalate to)",
        retry_decision(["opus5"], [row("opus5", now - 60)], now), (DECOMPOSE, []))
    # The strict-shrink property is what makes termination structural rather than incidental:
    # simulate the loop and require it to reach DECOMPOSE in at most len(chain) dispatches.
    long_chain = ["opus5", "sol", "luna", "terra"]
    spent, dispatches = [], 0
    while True:
        decision, remaining = retry_decision(long_chain, spent, now)
        if decision == DECOMPOSE:
            break
        dispatches += 1
        assert dispatches <= len(long_chain) + 1, "retry_decision did not terminate"
        spent.append(row(remaining[0], now - 10))
    chk("the ladder terminates in at most len(chain) dispatches",
        (decision, dispatches), (DECOMPOSE, len(long_chain)))

    # ---- GUARD: a declared shape-blocker skips the lateral retry entirely.
    chk("`too_large` decomposes even with an untried tier available",
        retry_decision(chain, [row("opus5", now - 60, why="too_large")], now), (DECOMPOSE, []))
    chk("`underspecified` decomposes even with an untried tier available",
        retry_decision(chain, [row("opus5", now - 60, why="underspecified")], now), (DECOMPOSE, []))
    chk("`blocked_on_decision` still takes the ORDINARY ladder (a second tier can find it)",
        retry_decision(chain, [row("opus5", now - 60, why="blocked_on_decision")], now),
        (RETRY_OTHER_TIER, ["sol"]))
    chk("an UNSPECIFIED reason takes the ordinary ladder, never the terminal one",
        retry_decision(chain, [row("opus5", now - 60, why="unspecified")], now),
        (RETRY_OTHER_TIER, ["sol"]))
    chk("a FORGED reason value takes the ordinary ladder",
        retry_decision(chain, [row("opus5", now - 60, why="too_large_ish")], now),
        (RETRY_OTHER_TIER, ["sol"]))

    # ---- GUARD: an UNATTRIBUTABLE outcome retires no tier (fail-closed direction). Model-health
    # allows an EMPTY model_alias, so this row shape is reachable in the live ledger.
    #
    # HONESTY NOTE, found by mutating this very guard: deleting `isinstance(alias, str) and alias`
    # from excluded_tiers leaves retry_decision's OUTPUT unchanged, because the chain filter at the
    # top of retry_decision already drops non-string/empty chain entries, so a junk alias in the
    # excluded set can never match a real one. TWO guards therefore assert one property, and the
    # CHAIN FILTER is the one that binds. Both are named below: the first pair pins the binding
    # guard, the second pins excluded_tiers' own exported contract (which would otherwise report a
    # tier that never ran).
    for alias in ("", None, 5, True):
        chk(f"a no_change with model_alias {alias!r} retires no tier",
            retry_decision(chain, [row(alias, now - 60)], now), (PROCEED, chain))
    chk("...and an unattributable row cannot empty the chain",
        retry_decision(["opus5"], [row("", now - 60)], now), (PROCEED, ["opus5"]))
    # THE BINDING GUARD: a malformed chain entry is dropped before it can be "excluded" or offered.
    chk("a malformed chain entry is never offered for dispatch",
        retry_decision(["opus5", "", None, 7, "sol"], [row("opus5", now - 60)], now),
        (RETRY_OTHER_TIER, ["sol"]))
    chk("...and an all-malformed chain decomposes rather than dispatching junk",
        retry_decision(["", None], [row("opus5", now - 60)], now), (DECOMPOSE, []))
    # THE EXPORTED CONTRACT of excluded_tiers: it names tiers PROVEN to have run, nothing else.
    chk("excluded_tiers reports only attributable aliases",
        excluded_tiers([row("", now - 60), row(None, now - 60), row(5, now - 60),
                        row(True, now - 60), row("sol", now - 60)], now), {"sol"})
    chk("excluded_tiers on wholly unattributable evidence is EMPTY, not a junk set",
        excluded_tiers([row("", now - 60), row(None, now - 60)], now), set())

    # ---- GUARD: the narrowing has a MACHINE EXIT — stale evidence stops excluding its tier.
    chk("evidence older than the horizon no longer excludes its tier",
        retry_decision(chain, [row("opus5", now - TIER_EXCLUSION_SECONDS - 1)], now),
        (PROCEED, chain))
    chk("evidence exactly at the horizon still excludes",
        retry_decision(chain, [row("opus5", now - TIER_EXCLUSION_SECONDS)], now),
        (RETRY_OTHER_TIER, ["sol"]))
    chk("the horizon is well inside model-health's 48h retention (it is the TIGHTER bound)",
        TIER_EXCLUSION_SECONDS < 48 * 3600, True)
    # A malformed ts is not evidence of recency: it must not exclude a tier.
    chk("a row with a malformed ts excludes nothing",
        retry_decision(chain, [row("opus5", "yesterday")], now), (PROCEED, chain))
    chk("a row with a boolean ts excludes nothing",
        retry_decision(chain, [row("opus5", True)], now), (PROCEED, chain))

    # ---- GUARD: no evidence at all is untouched behaviour.
    chk("no records -> proceed on the full chain", retry_decision(chain, [], now),
        (PROCEED, chain))
    chk("None records -> proceed on the full chain", retry_decision(chain, None, now),
        (PROCEED, chain))
    chk("non-dict rows are ignored, not crashed on",
        retry_decision(chain, [None, "x", 3], now), (PROCEED, chain))
    # A record for a tier that is no longer in the chain (routing.toml edited) must not empty it.
    chk("evidence for a retired alias does not empty the chain",
        retry_decision(chain, [row("fable", now - 60)], now), (PROCEED, chain))

    print("no_change_routing self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv:
        return _self_test()
    if len(sys.argv) > 2 and sys.argv[1] == "--reason-code":
        print(reason_code(parse_declaration(sys.argv[2])))
        return 0
    print(__doc__.strip().splitlines()[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
