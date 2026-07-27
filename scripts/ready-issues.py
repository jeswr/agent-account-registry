#!/usr/bin/env python3
# [OPUS-4.8] Registry self-management: the readiness engine for jeswr/agent-account-registry.
# A copy of the sparq target's scripts/ready-issues.py — the dispatch PLAN clones this repo and
# runs `scripts/ready-issues.py --self-test` + imports compute_ready(), exactly as it does for
# sparq. Kept behaviourally identical so the shared dispatcher treats both targets the same.
"""ready-issues.py — compute the dispatchable frontier from GitHub issues, FAIL-CLOSED.

Readiness requires POSITIVE, bot-attested state — never mere absence of a quarantine label. An
issue is READY iff, in priority order, ALL hold:
  * OPEN, and
  * carries `status:ready` (positive attestation the triage/trust pipeline set), and
  * carries exactly ONE valid `priority:P0..P4` (ambiguous/invalid priority -> excluded), and
  * carries exactly ONE `role:*` label (roleless -> excluded; MULTI-role -> excluded), and
  * carries NO gate label (`needs:*` — INCLUDING `needs:design` and `needs:user` —, or
    `trust:untrusted`) and is NOT busy
    (`status:in-progress|in-progress-review|blocked|deferred|untriaged`), and
  * has zero open blockers, and
  * none of its PACKAGES (`area:<section>`) is already taken by an in-progress issue or an
    earlier-selected ready issue. A no-package / cross-cutting issue reserves a **global
    partition** that serializes it against ALL other work.

`needs:design` (B2) is a DESIGN-HOLD gate: a `needs:*` label so an issue that still needs an
architect pass is NEVER ready while it is present, exactly like `needs:user`. The gate is the
prefix rule below — no design-heavy issue can be dispatched until a human clears the label.
"""
import argparse
import json
import os
import re
import subprocess
import sys

# Any `needs:*` (needs:user, needs:design, needs:area, ...) is a hard gate; `trust:untrusted` too.
GATE_LABELS = ("needs:", "trust:untrusted")
BUSY_STATUS = {"status:in-progress", "status:in-progress-review", "status:blocked",
               "status:deferred", "status:untriaged"}
# an epic is a tracking umbrella (its children are the work) — never dispatchable.
NON_DISPATCHABLE = "kind:epic"
GLOBAL = "__global__"  # the cross-cutting partition (serializes against everything)
_PRIO = re.compile(r"^priority:P([0-4])$")   # only P0..P4 are valid
_PKG = re.compile(r"^area:(.+)$")
_ROLE = re.compile(r"^role:.+$")
ROLE_PREFIX = "role:"


# --- open blockers: NATIVE GitHub dependencies UNIONED with the legacy body markers -------------
# [OPUS-5][sparq #4329] Kept behaviourally identical to the sparq target's copy of this file (see
# the header). Both readers of "is this issue blocked" used to derive `open_blockers` ONLY by
# regexing `Blocked-by: #NN` out of the issue BODY, so a dependency added through GitHub's native
# "blocked by" UI had ZERO effect on dispatch. The LIVE dispatcher's own copy of this rule lives in
# the registry's .github/workflows/dispatch.yml `blocker-union` block; this one serves the local
# `--self-test`/dry-run preview and must not drift from it.
#
# UNION, never replace — the fail-safe direction is one-way: `exclusion_reason` keys on
# `open_blockers > 0`, so MISSING an edge dispatches an issue that is genuinely blocked, while
# OVER-counting one only delays it.
_MARKER_BLOCKED_BY = re.compile(r"[Bb]locked-by:\s*#(\d+)")
# GitHub's REST list payload carries this per non-PR issue at no extra request. `blocked_by` counts
# only OPEN blockers (`total_blocked_by` counts closed ones too) — MEASURED over all 1368 open
# sparq issues: identical sets AND identical per-issue counts to GraphQL `blockedBy` filtered to
# state=OPEN, with 16 issues showing total_blocked_by > blocked_by. A CLOSED blocker never holds.
NATIVE_SUMMARY = "issue_dependencies_summary"
# A PRESENT-but-malformed summary is a schema change we cannot interpret. Reading it as "0
# blockers" is the fail-OPEN direction, so it counts as one unknown blocker instead: the issue is
# held, loudly, until a human looks.
MALFORMED_SUMMARY_BLOCKERS = 1


def native_open_blockers(issue, warn=None):
    """OPEN blockers from GitHub's NATIVE dependency edges (`issue_dependencies_summary`).

    ABSENT summary -> 0; the absence is NOT silent (see `native_channel_alarm`).
    PRESENT-but-malformed -> MALFORMED_SUMMARY_BLOCKERS (fail closed).
    """
    summary = issue.get(NATIVE_SUMMARY)
    if summary is None:
        return 0
    number = issue.get("number", "?")
    if not isinstance(summary, dict):
        if warn is not None:
            warn(f"#{number}: {NATIVE_SUMMARY} is not an object — holding the issue (fail-closed)")
        return MALFORMED_SUMMARY_BLOCKERS
    value = summary.get("blocked_by")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        if warn is not None:
            warn(f"#{number}: {NATIVE_SUMMARY}.blocked_by is {value!r}, not a non-negative int — "
                 "holding the issue (fail-closed)")
        return MALFORMED_SUMMARY_BLOCKERS
    return value


def marker_open_blockers(body, open_numbers):
    """OPEN blockers from validated `Blocked-by: #NN` BODY markers (the legacy channel)."""
    return sum(1 for n in _MARKER_BLOCKED_BY.findall(body or "") if int(n) in set(open_numbers))


def open_blocker_count(issue, open_numbers, warn=None):
    """The UNION of both blocker channels, as the count `exclusion_reason` consumes.

    `max` is the exact union for the only decision made from it — an issue is held iff
    `native > 0 or marker_open > 0`, which is precisely `max(...) > 0`. It is a LOWER BOUND on the
    cardinality of the union of the two blocker SETS (the native channel reports a count, not
    numbers), which can only understate a delay, never flip a held issue to ready.
    """
    return max(native_open_blockers(issue, warn),
               marker_open_blockers(issue.get("body"), open_numbers))


def native_channel_alarm(raw):
    """The GUARD against the native blocker channel going DARK without anyone noticing.

    An ABSENT summary reads as 0 — correct for an old snapshot, and indistinguishable from
    "GitHub renamed the field" if nobody checks. Returns the lines to print (pure, so the check
    itself is testable rather than a side effect nobody exercises).
    """
    rows = [i for i in raw if isinstance(i, dict)]
    if not rows or any(isinstance(i.get(NATIVE_SUMMARY), dict) for i in rows):
        return []
    return [f"::warning::NATIVE BLOCKER CHANNEL IS DARK: none of {len(rows)} open issues carries "
            f"`{NATIVE_SUMMARY}`. Native GitHub dependencies are being IGNORED and only "
            "`Blocked-by: #NN` body markers can hold an issue — a maintainer's native dependency "
            "edits have no effect on dispatch until this is fixed."]


def labels_of(issue):
    return {lb["name"] if isinstance(lb, dict) else lb for lb in issue.get("labels", [])}


def valid_priority(labels):
    """Exactly one valid priority:P0..P4 -> its int; zero or multiple or out-of-range -> None."""
    ps = {int(m.group(1)) for lb in labels for m in [_PRIO.match(lb)] if m}
    return next(iter(ps)) if len(ps) == 1 else None


def packages_of(labels):
    """The SET of all area:<section> packages; empty -> the serializing global partition."""
    pkgs = {m.group(1) for lb in labels for m in [_PKG.match(lb)] if m}
    return pkgs or {GLOBAL}


def has_role(labels):
    return any(_ROLE.match(lb) for lb in labels)


def roles_of(labels):
    """Every DISTINCT declared role VALUE, sorted (empty when roleless).

    PREFIX-matched (`role:` + anything, including the empty value), NOT `_ROLE`-matched
    (`role:` + at least one char). That is deliberate and load-bearing: this is the same rule
    `dispatch-plan._roles_of` uses to decide whether the PLANNER rejects an issue, and the
    readiness gate must never be LAXER than the stage downstream of it. Under the `_ROLE` regex
    the pair {`role:`, `role:impl`} counts as ONE role and would sail through the gate straight
    into the planner's rejection — precisely the hole this predicate exists to close. Prefix
    matching over-counts (a bare `role:` is not a usable role) only in the fail-closed direction:
    the roleless check below refuses that label set anyway.

    `has_role` keeps the `_ROLE` regex on purpose — it answers "is there a USABLE role label",
    which a bare `role:` does not satisfy. The two predicates answer different questions and the
    self-test pins both, including the label set where they disagree.
    """
    return sorted({lb[len(ROLE_PREFIX):] for lb in labels if lb.startswith(ROLE_PREFIX)})


def is_gated(labels):
    return any(lb == g or lb.startswith(g) for lb in labels for g in GATE_LABELS)


def is_busy(labels):
    return bool(labels & BUSY_STATUS)


def _defer_log(message):
    """Default sink for the readiness defer lines: STDERR, so the frontier this engine prints on
    stdout stays machine-readable while the reasons are still visible in a green CI run."""
    print(message, file=sys.stderr)


def exclusion_reason(labels, open_blockers=0):
    """The ONE label-side ENUMERABILITY predicate, as a REASON: None when the engine can enumerate
    an OPEN issue carrying these labels, else a short attributable string naming the FIRST failing
    condition (checked in the documented priority order above).

    Issue #586: `ready_candidates` used to drop a `status:ready` candidate with a bare `continue`
    — no log line, no counter — so an issue that lost its priority/role label while KEEPING the
    positive `status:ready` attestation left the frontier forever with zero emitted signal. The
    predicate is factored out here so (a) the drop is attributable and (b) the retriage re-park
    sweep can ask the readiness engine ITSELF whether an issue is enumerable rather than re-deriving
    enumerability from a private copy of these rules.

    SCOPE, precisely (#605 review finding 6). This is NOT the whole notion of triage-completeness,
    and the earlier wording overclaimed. It deliberately calls an AREA-LESS issue enumerable — a
    package-less issue reserves the serializing `__global__` partition, so the engine can still
    plan it — while `triage.triage()` calls that same issue triage-INCOMPLETE. Two predicates are
    therefore genuinely in play, answering different questions, and `retriage.plan()` composes both
    on purpose: this one decides "can the frontier see it", the classifier decides "is its label set
    complete", and an area regression is caught only by the second. What must never happen is a
    THIRD, divergent copy of either rule.

    `routing_refusal` (registry #122) is a genuinely different third question — "can the PLANNER
    build a row from it" — and is deliberately NOT folded in here, because `retriage.plan()` reads
    THIS predicate as "the issue is stranded, repair it". See that function's docstring for the
    measurement. `ready_candidates` composes both; anything asking "is this issue on the frontier"
    must ask `ready_candidates`, not this predicate alone.

    Package SERIALIZATION drops (compute_ready's one-per-package concurrency width) are
    deliberately NOT reported here: they are transient by design — the issue is still on the
    frontier next tick — and the assembler already names them (`assembler defer #N: crate ...`).
    """
    labels = set(labels)
    if "status:ready" not in labels:          # positive attestation required
        return "no status:ready attestation"
    if NON_DISPATCHABLE in labels:            # epics are tracking umbrellas, not work items
        return f"{NON_DISPATCHABLE} is a tracking umbrella, never dispatchable"
    gates = sorted(lb for lb in labels if any(lb == g or lb.startswith(g) for g in GATE_LABELS))
    if gates:
        return "gated by " + ",".join(gates)
    busy = sorted(labels & BUSY_STATUS)
    if busy:
        return "busy: " + ",".join(busy)
    if valid_priority(labels) is None:        # need exactly one valid priority
        seen = sorted(lb for lb in labels if lb.startswith("priority:"))
        return "no single valid priority:P0..P4 (have: " + (",".join(seen) or "none") + ")"
    if not has_role(labels):                  # need a role
        return "no role:* label"
    if int(open_blockers) > 0:
        return f"{int(open_blockers)} open blocker(s)"
    return None


def routing_refusal(labels):
    """The ROUTABILITY predicate: None when the PLANNER can turn this label set into a plan row,
    else a short attributable string naming why it refuses. Currently one condition — MORE THAN
    ONE `role:*` label (registry issue #122).

    THE PARTITION-KILLER. This rule already existed, in `dispatch-plan.plan_dispatch`, which runs
    AFTER `compute_ready` has serialized the candidate set down to one row per `area:` package. A
    malformed issue therefore WON its partition slot and was only THEN rejected, taking the whole
    partition down with it and offering no backfill: three such issues (each carrying `role:ci`
    AND `role:impl`) held the registry's plan rows at ZERO for 8 days while every individual run
    stayed green. `ready_candidates` applies this predicate alongside `exclusion_reason`, so
    (a) such an issue can never be a partition head — the next candidate in the package backfills
    — and (b) because it still holds `status:ready`, the drop emits an attributable
    `readiness defer #N:` line (the #586 idiom) and the outage is VISIBLE in a green run.

    It REFUSES; it never GUESSES. The pair is named, never collapsed to one role: no layer here
    can read which role a human meant, and silently picking one reroutes the work to a different
    model chain. `plan_dispatch`'s rejection STAYS as the fail-closed backstop — this is a
    layering correction (the one #113 applied to the trust/linked filters), not a move.

    WHY THIS IS NOT A BRANCH OF `exclusion_reason` (measured, not stylistic). That predicate has a
    SECOND consumer with a different question: `retriage.plan()` treats "not enumerable" as "this
    issue is STRANDED — repair or re-park it". Folding ambiguity in there was tried and measured:
    `retriage.plan()` flipped from `skip/ready-consistent` to `repair`, whose write STRIPS one of
    the two role labels — the classifier re-derives a role from `area:`, which on the three live
    heads kept `role:impl` and dropped the `role:ci` a human had applied deliberately. That is the
    auto-collapse this docstring refuses, arrived at through the back door, and retriage's own
    self-test ("an enumerable status:ready issue is left alone despite unrelated classifier
    drift") reds on it. Enumerability, triage-completeness and routability are three questions;
    `exclusion_reason`'s docstring already separates the first two. This is the third.
    """
    roles = roles_of(labels)
    if len(roles) > 1:
        # FULL label names (`role:ci, role:impl`), not the bare values the planner's skip line
        # prints: a bare `role:` has the EMPTY value, which `', '.join` renders as a leading comma
        # and nothing else — unreadable in the one line a human gets. The phrase "ambiguous role
        # labels" is kept verbatim so the gate and the planner grep as one class.
        return ("ambiguous role labels: "
                + ", ".join(ROLE_PREFIX + role for role in roles)
                + " — exactly one role:* required (registry issue #122)")
    return None


def ready_candidates(issues, log=None):
    """Every issue that passes the FAIL-CLOSED readiness LABEL gate (open + status:ready + exactly
    one priority + exactly one role + no gate/busy label + zero open blockers), priority-then-number
    ordered. THE gate is this function, not `exclusion_reason` alone: it composes that predicate
    with `routing_refusal` (registry #122), which the planner would otherwise apply too late.

    This is the DRAINABLE set — every issue a fleet could work through — BEFORE the conflict-free
    one-per-package concurrency serialization that compute_ready() layers on top. The two answer
    different questions: this is 'how much ready work exists'; compute_ready() is 'how many can be
    claimed RIGHT NOW without a package collision'. Throughput/backlog metrics want THIS count, not
    the concurrency width (see metrics.py issues_ready).

    Every dropped candidate that HOLDS the `status:ready` attestation emits one attributable
    `readiness defer #N: <reason>` line via `log` (default: stderr) — issue #586: a bare `continue`
    made a label-regressed issue invisible in a green run, recoverable only by noticing its absence
    from the frontier. Non-attested issues stay quiet (they are simply not candidates)."""
    log = _defer_log if log is None else log
    cands = []
    for it in issues:
        if str(it.get("state", "OPEN")).upper() != "OPEN":
            continue
        L = labels_of(it)
        # The label gate is the ENUMERABILITY predicate followed by the ROUTABILITY one, in that
        # order: a gated-AND-ambiguous issue reports the gate, which is the earlier and more
        # actionable condition. Both emit the same attributable defer line, so the caller cannot
        # tell — and must not care — which layer refused.
        reason = (exclusion_reason(L, it.get("open_blockers", 0)) or routing_refusal(L))
        if reason is not None:
            if "status:ready" in L:
                log(f"readiness defer #{it.get('number', 0)}: {reason}")
            continue
        cands.append((valid_priority(L), it.get("number", 0), it, packages_of(L)))
    cands.sort(key=lambda c: (c[0], c[1]))   # priority then number (deterministic)
    return cands


def _artifact_name(artifact):
    """How a package HOLDER is named in a conflict-attribution line. The readiness input carries
    issues only (PRs are filtered upstream); a pre-seeded `in_progress_packages` entry has no
    artifact behind it and says so rather than inventing one."""
    if artifact is None:
        return "preseeded occupancy"
    return f"issue#{artifact.get('number', '?')}"


def compute_ready(issues, in_progress_packages=None, log=None, conflict_log=None):
    """Conflict-free, priority-ordered, FAIL-CLOSED ready frontier (one-per-package concurrency
    width). This is NOT the count of drainable work — see ready_candidates() for that.

    `conflict_log`, when supplied, receives ONE attribution line per candidate the PACKAGE
    partition dropped: `conflict #N: area A held by issue#M`. Package serialization drops are
    transient by design, which is why `exclusion_reason` deliberately does not report them — but
    per-tick telemetry needs to know WHICH area is serialising the frontier and WHO holds it
    (`scripts/dispatch-telemetry.py`, Gate A of the crate-region-parallelism record). Same sink
    shape as the sparq target's readiness engine, so the shared dispatcher can attribute both
    targets identically. Supplying the sink NEVER changes the frontier — asserted by --self-test.
    """
    taken = set(in_progress_packages or ())
    holders = {pkg: None for pkg in taken}
    for it in issues:
        if str(it.get("state", "OPEN")).upper() != "OPEN":
            continue
        L = labels_of(it)
        if "status:in-progress" in L or "status:in-progress-review" in L:
            for pkg in packages_of(L):
                holders.setdefault(pkg, it)
                taken.add(pkg)

    def held_by(pkgs):
        """The (area, holder) blocking `pkgs`, or None. Mirrors the three conditions below exactly:
        a GLOBAL reservation blocks everything; an overlapping package blocks; and a cross-cutting
        candidate cannot co-run with ANY reserved package."""
        if GLOBAL in taken:
            return GLOBAL, holders.get(GLOBAL)
        overlap = pkgs & taken
        if overlap:
            area = sorted(overlap)[0]
            return area, holders.get(area)
        if GLOBAL in pkgs and taken:
            area = sorted(taken)[0]
            return area, holders.get(area)
        return None

    cands = ready_candidates(issues, log=log)
    ready = []
    for _p, _n, it, pkgs in cands:
        # The pre-fix loop `break`-ed once GLOBAL was taken. held_by() returns GLOBAL for every
        # remaining candidate in that state, so the frontier is byte-identical while each dropped
        # candidate still gets its attribution line (a `break` would have silently un-attributed
        # every candidate after the first cross-cutting reservation).
        blocker = held_by(pkgs)
        if blocker is not None:
            if conflict_log is not None:
                conflict_log(f"conflict #{it.get('number', '?')}: area {blocker[0]} held by "
                             f"{_artifact_name(blocker[1])}")
            continue
        for pkg in pkgs:
            holders.setdefault(pkg, it)
        taken |= pkgs
        ready.append(it)
    return ready


def _planner_role_rule():
    """(callable|None, bool): the PLANNER's role-counting rule, and whether it consumes ours.

    Returns `dispatch-plan._roles_of` compiled from its AST in an isolated namespace — importing
    the module itself would drag in route-resolve + routing.toml, which this engine's self-test
    has no business depending on. AST, not a source grep: only the function's actual BODY is
    executed, so a comment or a docstring naming the rule cannot satisfy the parity check.

    Second element is True when dispatch-plan has been collapsed onto `_ready.roles_of` (the
    end state this duplication should reach). The caller asserts one or the other; a file with
    NEITHER a private `_roles_of` NOR a reference to the shared one fails closed.
    """
    import ast
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dispatch-plan.py")
    if not os.path.exists(path):
        return None, False
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), path)
    uses_shared = any(isinstance(n, ast.Attribute) and n.attr == "roles_of"
                      and isinstance(n.value, ast.Name) and n.value.id == "_ready"
                      for n in ast.walk(tree))
    fn = next((n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name == "_roles_of"), None)
    if fn is None:
        return None, uses_shared
    namespace = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), path, "exec"), namespace)  # noqa: S102
    return namespace["_roles_of"], uses_shared


def _self_test():
    def iss(n, labels, blk=0, state="OPEN"):
        return {"number": n, "state": state, "labels": labels, "open_blockers": blk}

    R = ["status:ready", "role:impl"]
    F = [
        iss(1, R + ["priority:P2", "area:worker"]),
        iss(2, R + ["priority:P0", "area:worker"]),
        iss(3, R + ["priority:P1", "area:dispatch"]),
        iss(4, R + ["priority:P1", "area:dispatch", "needs:user"]),          # gated
        iss(40, R + ["priority:P1", "area:review-loop", "needs:design"]),    # DESIGN-HOLD gate (B2)
        iss(5, R + ["priority:P1", "area:usage"], blk=2),                    # blocked
        iss(6, R + ["priority:P0", "area:groom"], state="CLOSED"),           # closed
        iss(7, R + ["priority:P1", "trust:untrusted", "area:docs"]),         # untrusted
        iss(8, ["priority:P3", "role:impl", "area:worker"]),                 # not status:ready
        iss(9, R + ["priority:P1", "priority:P2", "area:usage"]),            # ambiguous priority
        iss(10, R + ["priority:P1", "area:set-up-account", "status:in-progress-review"]),  # busy
        iss(11, R + ["priority:P4"]),                                        # no package -> global
        iss(12, R + ["priority:P1", "area:groom"]),                          # groom (free)
        iss(13, R + ["priority:P0", "area:docs", "kind:epic"]),              # epic -> excluded
        iss(14, ["status:ready", "priority:P1", "area:usage"]),              # #586: lost its role
        # [#122] AMBIGUOUS ROLE. Deliberately given an otherwise-PERFECT ready label set on a FREE
        # package, so that deleting the ambiguity branch does not merely lose a defer line — it
        # puts #15 on the FRONTIER and changes `ready order`. That is a behaviour-kill of the
        # headline claim, not a helper-only kill.
        iss(15, R + ["role:ci", "priority:P1", "area:review-loop"]),
    ]
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    ready = compute_ready(F)
    # eligible: 2(P0 worker),3(P1 dispatch),12(P1 groom) then 11(P4 global blocked — board taken).
    check("ready order", [i["number"] for i in ready], [2, 3, 12])
    # DRAINABLE candidates: the label-gate set BEFORE package serialization — includes issue 1
    # (P2 worker) which compute_ready() drops only because 2 already took the `worker` package,
    # and 11 (global) which the frontier drops only because the board is taken. This is the count
    # the throughput metric wants — it must NOT collapse to the concurrency width.
    check("ready_candidates is the drainable set (not the concurrency width)",
          sorted(c[2]["number"] for c in ready_candidates(F)), [1, 2, 3, 11, 12])
    check("ready_candidates >= compute_ready (serialization only shrinks)",
          len(ready_candidates(F)) >= len(ready), True)
    # B2: a needs:design issue with an otherwise-perfect ready label-set is NEVER ready.
    check("needs:design gated (B2)", 40 in [i["number"] for i in ready], False)
    check("is_gated needs:design (B2)", is_gated({"needs:design", "status:ready"}), True)
    check("is_gated needs:user", is_gated({"needs:user"}), True)
    check("in-progress-review is busy", is_busy({"status:in-progress-review"}), True)
    check("epic excluded", 13 in [i["number"] for i in ready], False)
    check("lone global", [i["number"] for i in compute_ready([iss(11, R + ["priority:P4"])])], [11])
    g = compute_ready([iss(11, R + ["priority:P0"]), iss(12, R + ["priority:P1", "area:groom"])])
    check("global serializes", [i["number"] for i in g], [11])
    # ---------------------------------------------------------------------------------------
    # [sparq #4329] NATIVE dependency edges. Behaviour parity with the sparq target's copy AND
    # with the registry's own dispatch.yml `blocker-union` block (which is the LIVE path and is
    # separately executed by scripts/dispatch-plan.py --self-test). Every row runs END-TO-END
    # through the real `_fetch_rows` + compute_ready, so deleting the native read from the row
    # builder — the original bug's exact shape — reds this suite.
    # ---------------------------------------------------------------------------------------
    def raw_issue(n, labels, body="", summary=None):
        """A row in the SHAPE `_fetch` receives from `gh api repos/../issues`."""
        row = {"number": n, "state": "open", "labels": [{"name": lb} for lb in labels],
               "body": body}
        if summary is not None:
            row[NATIVE_SUMMARY] = summary
        return row

    def dep_summary(open_blockers, total=None):
        return {"blocked_by": open_blockers, "blocking": 0,
                "total_blocked_by": open_blockers if total is None else total, "total_blocking": 0}

    ready_labels = R + ["priority:P1", "area:usage"]
    check("[#4329] a NATIVE blocked_by edge with no body marker excludes from ready",
          [it["number"] for it in compute_ready(_fetch_rows(
              [raw_issue(40, ready_labels, body="no marker here", summary=dep_summary(1))]))], [])
    check("[#4329] ...and the same issue with the native edge cleared IS ready",
          [it["number"] for it in compute_ready(_fetch_rows(
              [raw_issue(40, ready_labels, body="no marker here", summary=dep_summary(0))]))], [40])
    check("[#4329] a MARKER-only edge (native says zero) still excludes from ready",
          [it["number"] for it in compute_ready(_fetch_rows(
              [raw_issue(41, ["role:impl"]),
               raw_issue(42, ready_labels, body="Blocked-by: #41", summary=dep_summary(0))]))], [])
    check("[#4329] an issue whose ONLY blocker is CLOSED is NOT excluded",
          [it["number"] for it in compute_ready(_fetch_rows(
              [raw_issue(44, ready_labels, body="Blocked-by: #43",
                         summary=dep_summary(0, total=2))]))], [44])
    check("[#4329] open_blocker_count unions both channels (never replaces either)",
          [open_blocker_count(raw_issue(1, [], body=b, summary=sm), {41})
           for b, sm in (("", None), ("", dep_summary(0)), ("", dep_summary(3)),
                         ("Blocked-by: #41", dep_summary(0)),
                         ("Blocked-by: #41", dep_summary(3)),
                         ("Blocked-by: #99", dep_summary(0)))],
          [0, 0, 3, 1, 3, 0])
    dep_warnings = []
    check("[#4329] a malformed native summary holds the issue and says so",
          ([native_open_blockers(raw_issue(45, [], summary=sm), dep_warnings.append)
            for sm in ({"blocked_by": -1}, {"blocked_by": "1"}, {"blocked_by": True},
                       {"blocked_by": None}, ["not", "a", "dict"])], len(dep_warnings)),
          ([MALFORMED_SUMMARY_BLOCKERS] * 5, 5))
    check("[#4329] ...and it is the FRONTIER that holds, not just the count",
          [it["number"] for it in compute_ready(_fetch_rows(
              [raw_issue(45, ready_labels, summary={"blocked_by": "1"})]))], [])
    check("[#4329] a native-channel-dark snapshot raises the alarm",
          [("DARK" in line, NATIVE_SUMMARY in line)
           for line in native_channel_alarm([raw_issue(50, []), raw_issue(51, [])])],
          [(True, True)])
    check("[#4329] one issue carrying the summary keeps the channel LIT",
          native_channel_alarm([raw_issue(50, []),
                                raw_issue(51, [], summary=dep_summary(0))]), [])
    check("[#4329] an empty snapshot never fabricates a dark alarm", native_channel_alarm([]), [])
    check("valid_priority single", valid_priority({"priority:P0"}), 0)
    check("valid_priority ambiguous", valid_priority({"priority:P1", "priority:P2"}), None)
    check("packages none->global", packages_of({"role:impl"}), {GLOBAL})
    # ---- #586: every dropped `status:ready` candidate is ATTRIBUTABLE (the silent `continue` is
    # what let a label-regressed issue leave the frontier forever with zero signal) ----
    lines = []
    compute_ready(F, log=lines.append)
    check("every dropped status:ready candidate emits one attributable defer line",
          sorted(int(re.search(r"#(\d+)", line).group(1)) for line in lines),
          [4, 5, 7, 9, 10, 13, 14, 15, 40])
    reasons = {int(re.search(r"#(\d+)", line).group(1)): line for line in lines}
    check("#586 lost-priority names the priority condition",
          "no single valid priority:P0..P4" in reasons[9], True)
    check("#586 lost-role names the role condition", "no role:* label" in reasons[14], True)
    # ---- [#122] the AMBIGUOUS-ROLE class: refused at the READINESS gate, not at the planner ----
    # Asserting only "#15 is absent from the frontier" is how #586 hid for months, so every claim
    # below is asserted positively: the frontier row, the DEFER LINE's content, and the backfill.
    check("[#122] an ambiguous-role issue is never a partition head",
          15 in [i["number"] for i in ready], False)
    check("[#122] the ambiguity defer line names the issue number AND both role labels",
          (reasons.get(15, "").startswith("readiness defer #15: "),
           "ambiguous role labels: role:ci, role:impl" in reasons.get(15, ""),
           "exactly one role:* required" in reasons.get(15, "")),
          (True, True, True))
    # THE OUTAGE, in one assertion. Pre-fix, #30 (P0, ambiguous) WON the `usage` partition and was
    # only then rejected by plan_dispatch — 0 plan rows, and #31 never got a turn, every tick, for
    # 8 days. The fix is not "#30 is excluded"; it is that its partition slot BACKFILLS.
    backfill = compute_ready([iss(30, R + ["role:ci", "priority:P0", "area:usage"]),
                              iss(31, R + ["priority:P1", "area:usage"])], log=lambda _line: None)
    check("[#122] the ambiguous head frees its partition — the next candidate backfills",
          [i["number"] for i in backfill], [31])
    check("gated defer names the gate", "gated by needs:design" in reasons[40], True)
    check("busy defer names the status", "busy: status:in-progress-review" in reasons[10], True)
    check("blocked defer names the blocker count", "2 open blocker(s)" in reasons[5], True)
    check("epic defer names the umbrella", "kind:epic" in reasons[13], True)
    # A NON-attested issue is not a candidate at all — it must stay quiet (no log flood).
    check("issue without status:ready stays quiet", 8 in reasons, False)
    # #605 review finding 5: "stays quiet" asserted only the ABSENCE of a defer line, which a
    # closed issue that wrongly reached the frontier would also satisfy. Assert both halves: no
    # log line AND not on the frontier (nor a candidate).
    check("closed issue stays quiet AND is not on the frontier",
          (6 in reasons, 6 in [i["number"] for i in compute_ready(F)],
           6 in [candidate[1] for candidate in ready_candidates(F, log=lambda _line: None)]),
          (False, False, False))
    quiet = []
    compute_ready([iss(20, R + ["priority:P1", "area:usage"])], log=quiet.append)
    check("an enumerable board emits NO defer line", quiet, [])
    # exclusion_reason is the single predicate ready_candidates and retriage's re-park both use.
    check("exclusion_reason: complete label set is enumerable",
          exclusion_reason({"status:ready", "priority:P1", "role:impl", "area:usage"}), None)
    check("exclusion_reason: no attestation",
          exclusion_reason({"priority:P1", "role:impl"}), "no status:ready attestation")
    check("exclusion_reason: an area-less set is still enumerable (it reserves __global__)",
          exclusion_reason({"status:ready", "priority:P1", "role:impl"}), None)
    # ---- Gate A telemetry: PACKAGE-serialization drops are ATTRIBUTABLE to the holding area ----
    # `exclusion_reason` deliberately omits these (they are transient), so without a sink the
    # dispatcher cannot say WHICH area is serialising the frontier — the exact quantity Gate A of
    # research/crate-region-parallelism.md asks for. Supplying the sink must not move the frontier.
    conflicts = []
    with_sink = compute_ready(F, conflict_log=conflicts.append)
    check("conflict_log NEVER changes the frontier (attribution is observation only)",
          [i["number"] for i in with_sink], [i["number"] for i in compute_ready(F)])
    # #1 is held by `worker` (#2 took it). #11 is CROSS-CUTTING: it cannot co-run with ANY reserved
    # package, so — as in the sparq engine — it is attributed to the deterministic first reserved
    # area rather than to a fabricated `__global__` holder.
    check("every package-serialized candidate gets ONE attribution line naming area + holder",
          sorted(conflicts),
          ["conflict #11: area dispatch held by issue#3",
           "conflict #1: area worker held by issue#2"])
    # NON-VACUOUS: #1 is dropped ONLY because #2 took `worker`; on a board where #2 is absent it is
    # on the frontier and emits nothing.
    solo = []
    check("a candidate with a free package emits no conflict line",
          ([i["number"] for i in compute_ready(
              [iss(1, R + ["priority:P2", "area:worker"])], conflict_log=solo.append)], solo),
          ([1], []))
    # The GLOBAL reservation must attribute EVERY later candidate, not just the first: the pre-fix
    # loop `break`-ed there, which would have left the rest silently un-attributed.
    after_global = []
    compute_ready([iss(30, R + ["priority:P0"]),
                   iss(31, R + ["priority:P1", "area:usage"]),
                   iss(32, R + ["priority:P2", "area:docs"])], conflict_log=after_global.append)
    check("a cross-cutting reservation attributes EVERY later candidate, not just the first",
          sorted(after_global),
          ["conflict #31: area __global__ held by issue#30",
           "conflict #32: area __global__ held by issue#30"])
    preseeded = []
    compute_ready([iss(33, R + ["priority:P1", "area:usage"])],
                  in_progress_packages={"usage"}, conflict_log=preseeded.append)
    check("a pre-seeded reservation with no artifact behind it says so, never invents a holder",
          preseeded, ["conflict #33: area usage held by preseeded occupancy"])

    # ---- [#122] the ROUTABILITY predicate itself ----
    check("routing_refusal: a routable single-role set is accepted",
          routing_refusal({"status:ready", "priority:P1", "role:impl", "area:usage"}), None)
    check("routing_refusal: an ambiguous role set is REFUSED and both roles are named",
          routing_refusal({"status:ready", "priority:P1", "area:usage", "role:ci", "role:impl"}),
          "ambiguous role labels: role:ci, role:impl — exactly one role:* required "
          "(registry issue #122)")
    check("routing_refusal: it REFUSES, it does not collapse — three roles are all named",
          routing_refusal({"status:ready", "priority:P1", "role:ci", "role:docs", "role:impl"}),
          "ambiguous role labels: role:ci, role:docs, role:impl — exactly one role:* required "
          "(registry issue #122)")
    # THE SEPARATION, asserted rather than merely commented. `retriage.plan()` reads
    # `exclusion_reason` as "this issue is STRANDED, repair it", and its repair STRIPS a role
    # label — measured: folding ambiguity into `exclusion_reason` flipped retriage from
    # skip/ready-consistent to repair/remove-a-role on the very fixture retriage's own self-test
    # pins ("an enumerable status:ready issue is left alone despite unrelated classifier drift").
    # An agent that "simplifies" the two predicates back into one must red HERE, next to the
    # reason, not three files away.
    AMBIG = {"status:ready", "priority:P1", "area:usage", "role:ci", "role:impl"}
    check("[#122] ambiguity is REFUSED by the frontier yet INVISIBLE to exclusion_reason — so "
          "retriage cannot 'repair' it by picking a role",
          (exclusion_reason(AMBIG), routing_refusal(AMBIG) is not None),
          (None, True))
    # The gate must not jump the DOCUMENTED priority order: a gated ambiguous issue reports the
    # GATE, which is the earlier and more actionable condition.
    gated_lines = []
    ready_candidates([iss(60, sorted(AMBIG | {"needs:user"}))], log=gated_lines.append)
    check("[#122] a GATED ambiguous issue reports the gate first (documented priority order)",
          gated_lines, ["readiness defer #60: gated by needs:user"])
    check("roles_of counts DISTINCT role values by PREFIX, sorted",
          (roles_of({"role:impl"}), roles_of({"role:impl", "role:ci"}), roles_of({"role:"}),
           roles_of({"area:usage", "status:ready"})),
          (["impl"], ["ci", "impl"], [""], []))
    # `has_role` (regex `role:` + at least one char) and `roles_of` (prefix) DISAGREE on a bare
    # `role:` — deliberately, and both fail closed. If `roles_of` were switched to the `_ROLE`
    # regex, this pair would count as ONE role, sail through the gate, and be rejected by the
    # planner exactly as before: the hole this unit closes, re-opened.
    check("[#122] a bare `role:` beside a real role is AMBIGUOUS (prefix rule, as CLAIM counts)",
          (has_role({"role:", "role:impl"}),
           routing_refusal({"status:ready", "priority:P1", "role:", "role:impl"})),
          (True, "ambiguous role labels: role:, role:impl — exactly one role:* required "
                 "(registry issue #122)"))
    check("[#122] a LONE bare `role:` is roleless, not ambiguous (one reason, the right one)",
          (has_role({"role:"}), exclusion_reason({"status:ready", "priority:P1", "role:"}),
           routing_refusal({"status:ready", "priority:P1", "role:"})),
          (False, "no role:* label", None))
    # ---- [#122] CROSS-FILE PARITY: the gate must never count roles more loosely than the stage
    # downstream of it. `dispatch-plan._roles_of` is the planner's copy of this rule; its BODY is
    # extracted by AST and executed here, so a textual re-word cannot satisfy the check and a
    # semantic divergence cannot pass it. (The rule belongs in this module — dispatch-plan already
    # imports it as `_ready` — but that file is owned by another change; see the PR body.)
    planner_roles_of, planner_uses_shared = _planner_role_rule()
    corpus = [set(), {"role:impl"}, {"role:ci", "role:impl"}, {"role:"}, {"role:", "role:impl"},
              {"area:usage", "status:ready"}, {"role:a", "role:b", "role:c"}, {"roles:impl"}]
    if planner_roles_of is not None:
        check("[#122] the readiness gate counts roles EXACTLY as dispatch-plan's planner does",
              [roles_of(labels) == planner_roles_of(labels) for labels in corpus],
              [True] * len(corpus))
    else:
        check("[#122] dispatch-plan dropped its private _roles_of — it must consume this module's",
              planner_uses_shared, True)
    check("flatten pages drops PRs", _flatten_pages(
        [[{"number": 1}, {"number": 2, "pull_request": {}}], [{"number": 3}], "junk", [None]]),
        [{"number": 1}, {"number": 3}])
    print("ready-issues self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _flatten_pages(pages):
    """Flatten `gh api --paginate --slurp` output (a list of pages) into issues, dropping PRs."""
    return [i for page in pages for i in (page if isinstance(page, list) else [])
            if isinstance(i, dict) and "pull_request" not in i]


def _fetch(repo, ceiling=10000):
    """Open-issue snapshot via REAL cursor pagination; the explicit ceiling fails closed."""
    out = subprocess.run(
        ["gh", "api", "--paginate", "--slurp",
         f"repos/{repo}/issues?state=open&per_page=100"],
        capture_output=True, text=True, check=True).stdout
    pages = json.loads(out or "[]")
    raw = _flatten_pages(pages)
    if len(raw) >= ceiling:
        raise SystemExit(f"refusing: fetched {len(raw)} >= ceiling {ceiling} — snapshot looks "
                         "runaway (fail-closed).")
    issues = _fetch_rows(raw, warn=lambda m: print(f"::warning::{m}", file=sys.stderr))
    for line in native_channel_alarm(raw):
        print(line, file=sys.stderr)
    return issues


def _fetch_rows(raw, warn=None):
    """The PURE half of `_fetch`: GitHub issue payloads -> readiness-engine rows.

    Split out so `--self-test` exercises the REAL row builder. Asserting on `open_blocker_count`
    alone would stay green with `_fetch` never calling it — which is exactly the shape of the bug
    being fixed (a correct blocker rule that no dispatcher consulted).
    """
    open_numbers = {i["number"] for i in raw}
    return [{"number": i["number"], "state": i["state"], "labels": i["labels"],
             "open_blockers": open_blocker_count(i, open_numbers, warn)} for i in raw]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="jeswr/agent-account-registry")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    for it in compute_ready(_fetch(args.repo)):
        L = labels_of(it)
        print(f"P{valid_priority(L)}  #{it['number']:5}  {sorted(packages_of(L))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
