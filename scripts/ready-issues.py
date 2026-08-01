#!/usr/bin/env python3
# Registry self-management: the readiness engine for jeswr/agent-account-registry.
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
  * none of its PACKAGES (`area:<section>`) is already taken by an OPEN PULL REQUEST, an
    in-progress issue, or an earlier-selected ready issue. A no-package / cross-cutting ISSUE
    reserves a **global partition** that serializes it against ALL other work.

A PULL REQUEST row is OCCUPANCY, never a candidate (issue #768/#773). `/issues?state=open`
returns PR rows too, and this engine used to have no `pull_request` guard anywhere: handed one it
would have treated it as a dispatch CANDIDATE and launched an impl worker against a pull-request
number. The shared dispatcher therefore PROBES each target's planner by execution and refused to
give this one the PR half of any unit of work, so an `area:` an open PR held read as FREE. Both
halves are fixed here — see `ready_candidates` (safety) and `_own_reservation` (effect).

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
# The statuses that make an OPEN ISSUE in-flight work OCCUPYING its area (not merely excluded).
IN_FLIGHT_STATUS = {"status:in-progress", "status:in-progress-review"}
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

    [OPUS-5 #768] Counted over NON-PR rows only. `_flatten_pages` retains PR rows now, and a PR
    row never carries `issue_dependencies_summary`, so counting them would both inflate the "none
    of N open issues" denominator and — on a repository whose snapshot happened to be all PRs —
    fire a DARK alarm about a population that has no dependency summaries by construction.
    """
    rows = [i for i in raw if isinstance(i, dict) and "pull_request" not in i]
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


def declared_packages(labels):
    """The SET of area:<section> packages ACTUALLY declared — empty when none are, no fallback."""
    return {m.group(1) for lb in labels for m in [_PKG.match(lb)] if m}


def packages_of(labels):
    """The SET of all area:<section> packages; empty -> the serializing global partition.

    CANDIDATE-side rule (fail-closed): an unlabelled issue is cross-cutting work that must
    serialize against everything. Also the ISSUE-side occupancy rule, unchanged by #768 — see
    `_own_reservation` for why the PR side deliberately differs.
    """
    return declared_packages(labels) or {GLOBAL}


def _pr_reserving_packages(labels):
    """OCCUPANCY-side rule for an open PULL REQUEST: ONLY the areas it declares, no fallback.

    [OPUS-5 #768] The deliberate asymmetry with `packages_of`, and it is NOT a style choice —
    the `or {GLOBAL}` form has taken this pipeline down twice and both outages are recorded:
    registry #772 (one unprovenanced open PR reserved `__global__` and the impl lane realised 0
    dispatches against 10) and registry #75 (4 no-area issues froze the entire sparq frontier,
    48 planned -> 0 launched every tick). Fail-closed on a CANDIDATE costs one dispatch; fail-
    closed on an OCCUPANT costs the whole fleet, because an occupant nobody can attribute to a
    section would seize every section at once.

    MEASURED on the live registry board (2026-07-27, `/issues?state=open`: 338 issues + 40 PR
    rows): 40 of 40 open PRs declare NO `area:` label — this repository has no PR-area deriver at
    all, unlike the sparq target's `scripts/pr-area-labels.py`. So adopting CLAIM's
    `areas |= issue_areas or {GLOBAL_PACKAGE}` here would hand `__global__` to all 40 and take
    this target's frontier to 0 on the very next tick. The two sides are NOT unified, and if they
    ever are, CLAIM is the side that moves — #772 and #781 are already moving it.
    """
    return declared_packages(labels)


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


# The two line families this engine emits through `log`, both greppable by prefix: one PER-ISSUE
# attribution for a label-gate refusal, and one PER-RUN census of the conflict stage.
DEFER_PREFIX = "readiness defer #"
CENSUS_PREFIX = "readiness census:"
CENSUS_TOP_CONTENDED = 8   # reserved areas named in the census line, ranked by blocked demand


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
    Not reported here is not the same as unreported (#1478): `frontier_census` counts them in
    AGGREGATE, per reserved area, on every run, because at the measured population they are almost
    the entire candidate set and their silence hid a width-exhausted frontier.
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
    from the frontier. Non-attested issues stay quiet (they are simply not candidates).

    [OPUS-5 #768] A row carrying `pull_request` is skipped BEFORE `exclusion_reason` and therefore
    also before the defer log: it is not a candidate that was rejected, it is not a candidate at
    all. Silently, on purpose — a PR row is normal, expected occupancy and logging one as a
    "readiness defer" would be a per-tick line per open PR that names no actionable condition."""
    log = _defer_log if log is None else log
    cands = []
    for it in issues:
        if str(it.get("state", "OPEN")).upper() != "OPEN":
            continue
        if "pull_request" in it:   # PRs reserve work; they are NEVER issue candidates
            continue
        L = labels_of(it)
        # The label gate is the ENUMERABILITY predicate followed by the ROUTABILITY one, in that
        # order: a gated-AND-ambiguous issue reports the gate, which is the earlier and more
        # actionable condition. Both emit the same attributable defer line, so the caller cannot
        # tell — and must not care — which layer refused.
        reason = (exclusion_reason(L, it.get("open_blockers", 0)) or routing_refusal(L))
        if reason is not None:
            if "status:ready" in L:
                log(f"{DEFER_PREFIX}{it.get('number', 0)}: {reason}")
            continue
        cands.append((valid_priority(L), it.get("number", 0), it, packages_of(L)))
    cands.sort(key=lambda c: (c[0], c[1]))   # priority then number (deterministic)
    return cands


def _own_reservation(row):
    """What ONE snapshot row reserves BY ITSELF. The single definition of per-row occupancy.

    [OPUS-5 #768] Every active OPEN PR is in flight, drafts included, and reserves the areas it
    DECLARES (`_pr_reserving_packages` — no `__global__` fallback, measured). An open ISSUE
    occupies only while `status:in-progress*`, and its rule is UNCHANGED: `packages_of`, global
    fallback included. That asymmetry is deliberate and this change is deliberately ADD-ONLY —
    switching the issue side to the declared-areas rule too would RELEASE `__global__` from every
    area-less in-progress issue, and releasing a key is the under-serialising, silently-corrupting
    direction. Widening occupancy can only delay; narrowing it double-dispatches.

    Parked artifacts are NOT carved out here on purpose: registry PR #683 owns that axis
    (`a parked PR reserves no crates — release on parked alone`, issue #677). PLAN also cannot
    mirror CLAIM's park rule from labels alone — `busy_packages_of_pulls` frees a parked PR only
    when it is a PROVABLY-INERT DRAFT, and the occupancy rows PLAN receives carry no draft bit —
    so releasing on a park label here would make PLAN offer rows CLAIM then drops with no
    backfill, which is the exact defect class #773 exists to prevent.
    """
    if str(row.get("state", "OPEN")).upper() != "OPEN":
        return set()
    labels = labels_of(row)
    if "pull_request" in row:
        return _pr_reserving_packages(labels)
    if labels & IN_FLIGHT_STATUS:
        return packages_of(labels)
    return set()


def unit_reservations(issues, source_links=None):
    """Occupancy as ONE reservation per UNIT OF WORK — a PR together with the issues it closes.

    [OPUS-5 #768] A worker PR and its source issue are the SAME unit of work. `source_links`
    (a PR-number -> source-issue-numbers map) folds each pair into ONE reservation of the UNION,
    attributed to the PR. Mirrors the sparq target's engine so the shared dispatcher can treat
    both targets identically.

    Two things this deliberately is NOT:

    * It is NOT a frontier lever by itself. The frontier tests MEMBERSHIP in the set of held keys,
      so a second occupant on an already-held key is a no-op: `⋃ units == ⋃ members` always. What
      it buys is the case where only ONE half reserves on its own — a PR whose source issue is not
      `status:in-progress*`. MEASURED on the live registry board (2026-07-27): 20 of 40 open PRs
      link a source issue, and folding them adds 4 keys (`dispatch`, `groom`, `set-up-account`,
      `worker`) that NOTHING holds today — held keys 2 -> 6.
    * It is NOT permission to drop either half. sparq #4539 measured 94 open PR/issue pairs: 13
      have PR ⊊ issue and 26 are INCOMPARABLE, so in 39/94 = 41% the PR's key set is not a
      superset and dropping the issue's reservation frees a key the unit really occupies.

    MONOTONE BY CONSTRUCTION: a unit reserves `⋃ _own_reservation(member)`, a superset of every
    member's own reservation, so the fold can never under-serialise relative to the per-row loop.

    `source_links=None` (the default, and what `dispatch.yml` passes today) yields exactly the
    legacy per-row reservations in the legacy order — pinned by --self-test.
    """
    links = source_links or {}
    by_number = {}
    for row in issues:
        by_number.setdefault(row.get("number"), row)

    def sources_of(pr_number):
        for number in sorted(links.get(pr_number) or ()):
            row = by_number.get(number)
            if row is not None and "pull_request" not in row:
                yield number, row

    consumed = {number for row in issues if "pull_request" in row
                for number, _row in sources_of(row.get("number"))}
    out = []
    for row in issues:              # input order preserved: attribution is order-sensitive
        number = row.get("number")
        if "pull_request" not in row:
            if number in consumed:  # already reserved as part of its PR's unit
                continue
            areas = _own_reservation(row)
        else:
            areas = set(_own_reservation(row))
            for _number, source in sources_of(number):
                areas |= _own_reservation(source)
        if areas:
            out.append((areas, row))
    return out


def frontier_census(cands, held, ready, limit=CENSUS_TOP_CONTENDED):
    """The ONE-LINE, per-run WIDTH census of the CONFLICT stage. Pure — returns the lines to print,
    so the check is testable rather than a side effect nobody exercises (`native_channel_alarm`'s
    idiom). `held` is occupancy BEFORE selection; `cands` is `ready_candidates`' output.

    Issue #1478: `ready_candidates` logs its own label-gate refusals faithfully (the #586 idiom),
    but `compute_ready`'s three conflict rules dropped candidates with a bare `continue` — and that
    is where almost the entire population dies. MEASURED on the live registry 2026-07-31: 413
    candidates entered the conflict filter, ONE survived, and 412 printed NOTHING. The observable
    signal was an empty frontier plus 25 unrelated label-gate defer lines, so a frontier that was
    WIDTH-EXHAUSTED (45 in-flight PRs holding 8 of the 9 demanded areas; the single dispatchable
    item was the lowest-priority P4 on the one free area while 30+ P1s waited) was indistinguishable
    from a backlog that had simply run dry. A tick spent clearing `needs:user` holds on six P1s
    delivered exactly zero, because every one of them was in a reserved area, and nothing in the
    engine's output said so before or after.

    AGGREGATE, deliberately, and this is the one judgement call in the fix. The issue also proposed
    a defer line per conflict-dropped candidate; at the measured population that is 412 lines per
    tick naming a condition that is transient by design (the issue is still on the frontier next
    tick, and `exclusion_reason`'s docstring records why serialization drops are not label-gate
    refusals). `413 -> 1, 8 areas held` is the sentence that makes width exhaustion visible, and the
    per-area demand breakdown attributes every one of the 412 to the area that is holding it.

    ALWAYS printed, ZERO INCLUDED — the standing rule for every cap in this fleet: a limit must name
    itself on every tick, including a tick on which it refused nothing, so a quiet tick is
    distinguishable from an uninstrumented one.

    Counts, precisely:
      * `candidates` / `frontier` — the drainable set and the concurrency width it collapsed to.
        Every candidate that is not on the frontier was dropped by a conflict rule (the label gate
        ran upstream, in `ready_candidates`), so `conflict-deferred` is exact, not a residual.
      * `reserved_areas` — keys held by IN-FLIGHT work (open PRs, in-progress issues, and any
        `in_progress_packages` seed) BEFORE selection. Keys that the frontier's own earlier heads
        take are NOT counted: those are the engine working as designed, and folding them in would
        report a healthy tick as a held one.
      * `free_areas` — demanded-by-a-candidate and NOT reserved. The 9th area in `8 reserved / 1
        free` is the whole finding, so the denominator is the areas candidates actually want, not
        every area label that exists.
      * `cross-cutting-blocked` — deferred CROSS-CUTTING candidates (`{GLOBAL}` packages, i.e. no
        `area:` label) that collide with NO reserved key yet cannot run, because the third conflict
        rule refuses to co-run cross-cutting work with ANY reservation. `blocked-by-reserved` is
        structurally blind to these: `{GLOBAL}` intersects an area-specific held set emptily, so
        pre-#1478-review such a tick read `frontier=0 ... blocked-by-reserved: none` — occupancy
        stopped the frontier while the census denied any reservation was costing demand. Counted
        HERE and not there, EXCLUSIVELY (`elif`): a candidate already attributed to a colliding key
        is never re-counted, so the two fields never double-count one deferral. A candidate stopped
        only by a key the frontier's OWN head took is in neither — `held` is in-flight occupancy,
        and that tick is the engine working as designed.
      * `blocked-by-reserved` — for each RESERVED key, how many deferred candidates collide with
        it, ranked by count then key and capped at `limit`. A reserved key that blocks nothing is
        not named (it is costing nothing); the count above still counts it.
    """
    held = set(held)
    demanded = set().union(set(), *(pkgs for _p, _n, _it, pkgs in cands))
    selected = {it.get("number") for it in ready}
    blocked = {}
    cross_cutting = 0
    for _p, number, _it, pkgs in cands:
        if number in selected:
            continue
        collisions = pkgs & held
        if collisions:
            for pkg in collisions:
                blocked[pkg] = blocked.get(pkg, 0) + 1
        elif GLOBAL in pkgs and held:        # refused by ANY reservation, collides with no key
            cross_cutting += 1
    ranked = sorted(blocked.items(), key=lambda kv: (-kv[1], kv[0]))
    shown = ", ".join(f"{pkg}={n}" for pkg, n in ranked[:limit]) or "none"
    more = f" (+{len(ranked) - limit} more)" if len(ranked) > limit else ""
    line = (f"{CENSUS_PREFIX} candidates={len(cands)} frontier={len(ready)} "
            f"conflict-deferred={len(cands) - len(ready)} "
            f"reserved_areas={len(held)} free_areas={len(demanded - held)} "
            f"cross-cutting-blocked={cross_cutting} "
            f"blocked-by-reserved: {shown}{more}")
    if GLOBAL in held:
        # `blocked-by-reserved` cannot see this one: a cross-cutting occupant collides with no
        # `area:` key, it simply stops the loop. Unnamed, the census would read as a wide-open
        # board (free areas, nothing contended) on the tick where NOTHING can run.
        line += f" — {GLOBAL} is held: NO other work can co-run this tick"
    return [line]


def compute_ready(issues, in_progress_packages=None, log=None, source_links=None):
    """Conflict-free, priority-ordered, FAIL-CLOSED ready frontier (one-per-package concurrency
    width). This is NOT the count of drainable work — see ready_candidates() for that.

    [OPUS-5 #768] `issues` may carry PULL-REQUEST rows (any row with a `pull_request` key). They
    are pure OCCUPANCY: they reserve, and they are never selected. `source_links`, when supplied,
    additionally folds a PR and the issues it closes into one unit reserving the union ONCE.

    [#1478] Emits ONE `readiness census:` line through the same `log` sink, every run, after the
    per-issue `readiness defer #N:` lines the label gate emitted — the conflict stage below used to
    discard most of the population with a bare `continue` and no signal at all. See
    `frontier_census`.
    """
    log = _defer_log if log is None else log
    taken = set(in_progress_packages or ())
    for areas, _artifact in unit_reservations(issues, source_links):
        taken |= areas
    # Snapshot BEFORE the selection loop mutates `taken`: the census must report what IN-FLIGHT
    # work holds, not what the frontier's own heads went on to take.
    held = frozenset(taken)
    cands = ready_candidates(issues, log=log)
    ready = []
    for _p, _n, it, pkgs in cands:
        if GLOBAL in taken:                  # cross-cutting work in flight -> nothing else co-runs
            break
        if pkgs & taken:                     # package conflict
            continue
        if GLOBAL in pkgs and taken:         # cross-cutting can't co-run with any package in flight
            continue
        taken |= pkgs
        ready.append(it)
    for line in frontier_census(cands, held, ready):
        log(line)
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
    emitted = []
    compute_ready(F, log=emitted.append)
    # [#1478] `log` now carries TWO line families. Split by prefix rather than relaxing any
    # assertion below: the per-issue set is still asserted EXACTLY, and the census lines it
    # separates out are asserted just as exactly, further down.
    lines = [line for line in emitted if line.startswith(DEFER_PREFIX)]
    census = [line for line in emitted if line.startswith(CENSUS_PREFIX)]
    check("[#1478] the log carries the 9 defer lines AND exactly ONE census line, nothing else",
          (len(lines), len(census), len(emitted)), (9, 1, 10))
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
    check("an enumerable board emits NO defer line",
          [line for line in quiet if line.startswith(DEFER_PREFIX)], [])
    # ...and the census is NOT suppressed on that tick — ZERO INCLUDED, so a tick that refused
    # nothing is distinguishable from a tick nobody instrumented. `if conflict_deferred:` is the
    # mutant this kills.
    check("[#1478] a tick that deferred NOTHING still prints its census (zero included)",
          [line for line in quiet if line.startswith(CENSUS_PREFIX)],
          [f"{CENSUS_PREFIX} candidates=1 frontier=1 conflict-deferred=0 reserved_areas=0 "
           "free_areas=1 cross-cutting-blocked=0 blocked-by-reserved: none"])
    # exclusion_reason is the single predicate ready_candidates and retriage's re-park both use.
    check("exclusion_reason: complete label set is enumerable",
          exclusion_reason({"status:ready", "priority:P1", "role:impl", "area:usage"}), None)
    check("exclusion_reason: no attestation",
          exclusion_reason({"priority:P1", "role:impl"}), "no status:ready attestation")
    check("exclusion_reason: an area-less set is still enumerable (it reserves __global__)",
          exclusion_reason({"status:ready", "priority:P1", "role:impl"}), None)
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
    check("flatten pages RETAINS PRs as occupancy artifacts", _flatten_pages(
        [[{"number": 1}, {"number": 2, "pull_request": {}}], [{"number": 3}], "junk", [None]]),
        [{"number": 1}, {"number": 2, "pull_request": {}}, {"number": 3}])
    # ------------------------------------------------------------------------------------------
    # [#768/#773] THE PULL-REQUEST HALF OF EVERY UNIT OF WORK.
    #
    # The shared dispatcher PROBES this engine by execution before it will hand it a PR row
    # (dispatch.yml `pr_row_aware`). Both obligations it checks are pinned here, plus the two
    # rules whose naive form is a measured OUTAGE (`or {GLOBAL}`) and a measured UNDER-
    # SERIALISATION (releasing the issue side's global fallback). Every check names the ONE guard
    # it kills, so a deleted guard reds a line whose text says what was deleted.
    # ------------------------------------------------------------------------------------------
    def pr(n, labels, state="OPEN"):
        return {"number": n, "state": state, "labels": labels, "open_blockers": 0,
                "pull_request": {"url": "u"}}

    probe = ["status:ready", "priority:P0", "role:impl", "area:__pr_probe__"]
    # SAFETY (probe obligation 1) — kills `if "pull_request" in it: continue` in ready_candidates.
    check("[#768] a PR row is NEVER a dispatch candidate, even with a perfect ready label set",
          ([it["number"] for it in compute_ready([pr(999000001, list(probe))])],
           [c[1] for c in ready_candidates([pr(999000001, list(probe))])]),
          ([], []))
    # EFFECT (probe obligation 2) — kills the `"pull_request" in row` branch of _own_reservation.
    # The free-area sibling must still be offered, so an engine that merely stopped emitting
    # anything cannot satisfy this line.
    check("[#768] an open PR RESERVES its declared areas; the free-area sibling is still offered",
          [it["number"] for it in compute_ready([
              pr(700, ["area:worker"]),
              iss(701, R + ["priority:P1", "area:worker"]),
              iss(702, R + ["priority:P1", "area:docs"])])],
          [702])
    # The whole probe, run EXACTLY as dispatch.yml runs it, against this module. This is the
    # acceptance test: the interlock opens iff these three lines hold.
    _alone = [it.get("number") for it in compute_ready([pr(999000001, list(probe))])]
    _paired = [it.get("number") for it in compute_ready(
        [pr(999000001, list(probe)),
         {"number": 999000002, "state": "OPEN", "labels": list(probe), "open_blockers": 0}])]
    check("[#773] dispatch.yml's pr_row_aware probe PASSES against this engine",
          (_alone, 999000001 in _paired, _paired), ([], False, []))
    # THE GLOBAL-FALLBACK DECISION, PINNED. Kills `_pr_reserving_packages` gaining `or {GLOBAL}`.
    # MEASURED: 40 of 40 open registry PRs declare no `area:`, so the fallback takes the frontier
    # to 0. CLAIM's `areas |= issue_areas or {GLOBAL_PACKAGE}` is deliberately NOT mirrored.
    check("[#768] an area-less open PR reserves NOTHING — CLAIM's `or {GLOBAL}` is NOT adopted",
          [it["number"] for it in compute_ready([
              pr(710, []), iss(711, R + ["priority:P1", "area:worker"])])],
          [711])
    check("[#768] ...and an area-less PR does not seize the GLOBAL partition either",
          [it["number"] for it in compute_ready([pr(712, []), iss(713, R + ["priority:P4"])])],
          [713])
    # THE ISSUE SIDE IS UNCHANGED. Kills a "tidy-up" that gives the in-flight ISSUE branch the
    # declared-areas rule too — that RELEASES __global__ from every area-less in-progress issue,
    # which is the under-serialising direction.
    check("[#768] an area-less IN-PROGRESS ISSUE still seizes __global__ (issue rule unchanged)",
          [it["number"] for it in compute_ready([
              iss(720, ["status:in-progress", "role:impl"]),
              iss(721, R + ["priority:P1", "area:worker"])])],
          [])
    # A CLOSED PR reserves nothing — kills the state guard in _own_reservation.
    check("[#768] a CLOSED PR row reserves nothing",
          [it["number"] for it in compute_ready([
              pr(730, ["area:worker"], state="CLOSED"),
              iss(731, R + ["priority:P1", "area:worker"])])],
          [731])
    # A PR row is not a "readiness defer" — kills moving the pull_request guard BELOW the
    # exclusion_reason call (which would log one line per open PR, every tick, naming nothing).
    _pr_lines = []
    compute_ready([pr(740, ["status:ready", "area:worker"])], log=_pr_lines.append)
    check("[#768] a PR row emits NO readiness-defer line (it is not a rejected candidate)",
          [line for line in _pr_lines if line.startswith(DEFER_PREFIX)], [])
    # UNIT RESERVATIONS. `source_links=None` must be byte-identical to the legacy per-row loop —
    # this is what lets dispatch.yml keep calling compute_ready(rows) unchanged.
    _board = [pr(750, ["area:worker"]), iss(751, ["status:in-progress", "role:impl", "area:docs"]),
              iss(752, R + ["priority:P1", "area:usage"])]
    check("[#768] source_links=None is EXACTLY the legacy per-row reservation set",
          [(sorted(a), r["number"]) for a, r in unit_reservations(_board)],
          [(["worker"], 750), (["docs"], 751)])
    # THE UNION, ONCE. Both directions of non-superset are covered: the PR declares a key the
    # issue lacks AND the issue declares a key the PR lacks. Dropping EITHER half frees a key the
    # unit really occupies (sparq #4539: 41% of live pairs are not supersets).
    _pair = [pr(760, ["area:worker"]),
             iss(761, ["status:in-progress", "role:impl", "area:docs", "area:usage"])]
    check("[#768] a PR and its source issue reserve the UNION, as ONE reservation",
          [(sorted(a), r["number"]) for a, r in unit_reservations(_pair, {760: [761]})],
          [(["docs", "usage", "worker"], 760)])
    check("[#768] ...and union-over-UNITS == union-over-MEMBERS (folding is not a frontier lever)",
          (sorted(set().union(*(a for a, _ in unit_reservations(_pair, {760: [761]})))),
           sorted(set().union(*(a for a, _ in unit_reservations(_pair))))),
          (["docs", "usage", "worker"], ["docs", "usage", "worker"]))
    # WHAT THE FOLD IS NOT. A source issue that reserves NOTHING on its own (it is not
    # `status:in-progress*`) contributes nothing to its PR's unit — the union is over what each
    # member RESERVES, never over what it merely DECLARES. Pinned because the opposite reading is
    # attractive and would be a silent WIDENING: on the live registry board 20 of 40 open PRs link
    # a source issue and 18 of those issues are not in flight, so a declares-based union would add
    # 4 keys (`dispatch`, `groom`, `set-up-account`, `worker`) that nothing holds today. That may
    # well be the right rule, but it is a different change with its own measurement and it is NOT
    # what the sparq target's engine does — the two must not silently diverge (issue filed).
    _idle_src = [pr(770, []), iss(771, R + ["priority:P1", "area:groom"]),
                 iss(772, R + ["priority:P2", "area:groom"])]
    check("[#768] the fold unions what members RESERVE, not what they DECLARE (no silent widening)",
          ([it["number"] for it in compute_ready(_idle_src, source_links={770: [771]})],
           [it["number"] for it in compute_ready(_idle_src)]),
          ([771], [771]))
    # A source issue folded into its PR's unit must not ALSO appear as its own reservation.
    check("[#768] a folded source issue is consumed — the unit reserves once, not twice",
          len(unit_reservations([pr(780, ["area:worker"]),
                                 iss(781, ["status:in-progress", "role:impl", "area:worker"])],
                                {780: [781]})),
          1)
    # THE CALL SITE, not the helper. Mutation found this hole: truncating compute_ready's
    # occupancy loop to `unit_reservations(...)[:1]` — six characters, at the call site — left
    # EVERY check above green, because no board above had more than ONE reserving unit on it.
    # That is the exact shape this repo has been burned by, so the fix is a board where the
    # SECOND unit is the one that matters: both areas must be held, and dropping any unit after
    # the first offers #822 again.
    check("[#768] EVERY reserving unit is applied, not just the first (call-site truncation)",
          [it["number"] for it in compute_ready([
              pr(820, ["area:worker"]), pr(821, ["area:docs"]),
              iss(822, R + ["priority:P1", "area:docs"]),
              iss(823, R + ["priority:P1", "area:worker"]),
              iss(824, R + ["priority:P1", "area:usage"])])],
          [824])
    # THE FETCH PATH, END-TO-END. Mutation found this too: dropping the `pull_request`
    # carry-through in `_fetch_rows` left everything green, because every check above hand-builds
    # its rows. `--repo` builds them with `_fetch_rows`, so without this the local preview could
    # silently lose PR occupancy while the engine kept it. Runs the REAL row builder.
    _raw_mixed = [raw_issue(830, ["area:usage"], summary=dep_summary(0)),
                  raw_issue(831, ready_labels, summary=dep_summary(0))]
    _raw_mixed[0]["pull_request"] = {"url": "u"}
    _raw_mixed[0].pop(NATIVE_SUMMARY, None)
    check("[#768] _fetch_rows carries PR rows through, and they RESERVE end-to-end",
          ([("pull_request" in row) for row in _fetch_rows(_raw_mixed)],
           [it["number"] for it in compute_ready(_fetch_rows(_raw_mixed))]),
          ([True, False], []))
    check("[#768] ...and the same board without the PR row IS offered (not a stopped engine)",
          [it["number"] for it in compute_ready(_fetch_rows(_raw_mixed[1:]))], [831])
    # THE ALARM DENOMINATOR. Also a mutation survivor: counting PR rows again left every alarm
    # check green, because none of them mixed the two row kinds.
    _pr_raw = raw_issue(840, ["area:worker"])
    _pr_raw["pull_request"] = {"url": "u"}
    _pr_raw.pop(NATIVE_SUMMARY, None)
    check("[#768] the DARK alarm counts open ISSUES, never PR rows, in its denominator",
          [line.split("none of ")[1].split(" open")[0]
           for line in native_channel_alarm([_pr_raw, raw_issue(841, []), raw_issue(842, [])])],
          ["2"])
    check("[#768] ...and an all-PR snapshot never fabricates a DARK alarm",
          native_channel_alarm([_pr_raw]), [])
    # A DEFECT CLASS MUTATION CANNOT REACH (found elsewhere in this repo by AST scan): a duplicated
    # top-level `def` silently SHADOWS the earlier one, so both bodies parse, the suite passes, and
    # mutating the shadowed copy changes nothing at all. Scan this module's own source.
    import ast as _ast
    _tree = _ast.parse(open(__file__, encoding="utf-8").read())
    _tops = [node.name for node in _tree.body
             if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef))]
    check("[#768] no top-level def is defined twice (a shadowed copy is unmutatable dead code)",
          sorted(name for name in set(_tops) if _tops.count(name) > 1), [])
    # ------------------------------------------------------------------------------------------
    # [#1478] THE WIDTH CENSUS. The conflict stage used to discard its population with a bare
    # `continue`: 413 candidates in, 1 out, 412 silent. Every check below asserts the census TEXT,
    # never merely that some line was emitted — an engine that printed `readiness census: ok` would
    # satisfy "a line exists" and report nothing at all.
    # ------------------------------------------------------------------------------------------
    # THE LIVE SHAPE, in miniature: in-flight PRs hold 3 of the 4 areas candidates want, so the ONE
    # dispatchable row is the lowest-priority item on the only free area while four P1s wait. This
    # is the tick the issue describes; pre-fix its entire output was `[914]` and nothing else.
    _wide = [pr(900, ["area:dispatch"]), pr(901, ["area:worker"]), pr(902, ["area:review-loop"]),
             iss(910, R + ["priority:P1", "area:dispatch"]),
             iss(911, R + ["priority:P1", "area:dispatch"]),
             iss(912, R + ["priority:P1", "area:worker"]),
             iss(913, R + ["priority:P1", "area:review-loop"]),
             iss(914, R + ["priority:P4", "area:usage"])]
    _wide_lines = []
    _wide_ready = compute_ready(_wide, log=_wide_lines.append)
    check("[#1478] a width-exhausted frontier NAMES itself: candidates, width, held vs free areas, "
          "and the demand each reserved area is holding",
          ([it["number"] for it in _wide_ready], _wide_lines),
          ([914],
           [f"{CENSUS_PREFIX} candidates=5 frontier=1 conflict-deferred=4 reserved_areas=3 "
            "free_areas=1 cross-cutting-blocked=0 "
            "blocked-by-reserved: dispatch=2, review-loop=1, worker=1"]))
    # RESERVED means HELD BY IN-FLIGHT WORK, not "taken by the time the loop ended". Two candidates
    # on one area with NO occupancy at all is a healthy tick: one is offered, one waits for it, and
    # the census must say `reserved_areas=0`. Reading the post-selection `taken` (or seeding the
    # census from `ready`'s own packages) reports that tick as area-starved — the false alarm that
    # would make the real one, above, unreadable.
    _healthy = []
    compute_ready([iss(920, R + ["priority:P1", "area:usage"]),
                   iss(921, R + ["priority:P2", "area:usage"])], log=_healthy.append)
    check("[#1478] a key the frontier's OWN head took is not a reserved area (no false alarm)",
          _healthy,
          [f"{CENSUS_PREFIX} candidates=2 frontier=1 conflict-deferred=1 reserved_areas=0 "
           "free_areas=1 cross-cutting-blocked=0 blocked-by-reserved: none"])
    # The GLOBAL occupant collides with no `area:` key — it stops the loop. Unnamed, this tick
    # reads as a wide-open board (free areas, nothing contended) while NOTHING can run.
    _global_lines = []
    compute_ready([iss(930, ["status:in-progress", "role:impl"]),
                   iss(931, R + ["priority:P1", "area:worker"])], log=_global_lines.append)
    check("[#1478] a held GLOBAL partition is named — the census never reads as open on a tick "
          "where nothing can co-run",
          _global_lines,
          [f"{CENSUS_PREFIX} candidates=1 frontier=0 conflict-deferred=1 reserved_areas=1 "
           "free_areas=1 cross-cutting-blocked=0 blocked-by-reserved: none "
           f"— {GLOBAL} is held: NO other work can co-run this tick"])
    # ...and the INVERSE of that occupant, which is the third conflict rule and the branch whose
    # census evidence was missing: the CANDIDATE is cross-cutting and an AREA is reserved. `{GLOBAL}`
    # intersects an area-specific held set emptily, so `blocked-by-reserved` is structurally blind
    # to it — this tick used to read `frontier=0 reserved_areas=1 ... blocked-by-reserved: none`,
    # denying that any reservation was costing demand while a reservation was stopping the frontier
    # dead. `cross-cutting-blocked` is the only field that can carry it.
    _xcut_lines = []
    _xcut_ready = compute_ready([pr(960, ["area:worker"]),
                                 iss(961, R + ["priority:P1"])], log=_xcut_lines.append)
    check("[#1478] a cross-cutting candidate refused by an AREA reservation is attributed, so a "
          "held-and-stopped tick cannot report that nothing is blocked",
          ([it["number"] for it in _xcut_ready], _xcut_lines),
          ([],
           [f"{CENSUS_PREFIX} candidates=1 frontier=0 conflict-deferred=1 reserved_areas=1 "
            "free_areas=1 cross-cutting-blocked=1 blocked-by-reserved: none"]))
    # The OTHER direction, twice over — the field must stay 0 when no RESERVATION is the cause:
    #   (i) dropping the `held` conjunct would report the healthy tick below (a cross-cutting
    #       candidate waiting on the frontier's OWN P1 head, zero in-flight work) as reservation-
    #       blocked — the false alarm that makes the real one above unreadable.
    _xcut_head = []
    compute_ready([iss(970, R + ["priority:P1", "area:usage"]),
                   iss(971, R + ["priority:P2"])], log=_xcut_head.append)
    check("[#1478] a cross-cutting candidate waiting on the frontier's OWN head is NOT counted as "
          "reservation-blocked (reserved means in-flight)",
          _xcut_head,
          [f"{CENSUS_PREFIX} candidates=2 frontier=1 conflict-deferred=1 reserved_areas=0 "
           "free_areas=2 cross-cutting-blocked=0 blocked-by-reserved: none"])
    #   (ii) relaxing the `elif` to `if` would count a cross-cutting candidate that ALREADY named
    #        its colliding key in `blocked-by-reserved` a second time, so one deferral would show up
    #        in two fields and the census would over-report its own population.
    _xcut_both = []
    compute_ready([iss(980, ["status:in-progress", "role:impl"]),
                   iss(981, R + ["priority:P1"])], log=_xcut_both.append)
    check("[#1478] a deferral attributed to a colliding key is NOT also counted as cross-cutting "
          "(the two fields never double-count one candidate)",
          _xcut_both,
          [f"{CENSUS_PREFIX} candidates=1 frontier=0 conflict-deferred=1 reserved_areas=1 "
           f"free_areas=0 cross-cutting-blocked=0 blocked-by-reserved: {GLOBAL}=1 "
           f"— {GLOBAL} is held: NO other work can co-run this tick"])
    # The census for board F, asserted whole (it was split out of `emitted` above). `held` there is
    # the in-progress issue #10's `set-up-account`, which no candidate NAMES: a reserved area that
    # contends with no `area:` label is counted, not named. It is not costing nothing, though —
    # board F's #11 is the cross-cutting P4, and `set-up-account` being in flight is on its own
    # sufficient to refuse it. That `cross-cutting-blocked=1` is the headline fixture carrying the
    # very case the field exists for; it read 0-shaped (`blocked-by-reserved: none`, no field at
    # all) before, which is how the branch stayed invisible in the engine's own reference board.
    check("[#1478] the census counts a reserved area that names no candidate, and still attributes "
          "the cross-cutting demand that area refuses", census,
          [f"{CENSUS_PREFIX} candidates=5 frontier=3 conflict-deferred=2 reserved_areas=1 "
           "free_areas=4 cross-cutting-blocked=1 blocked-by-reserved: none"])
    # Ranking (count desc, then key) and the cap. Ten reserved areas each blocking one candidate:
    # a dropped bound prints all ten, an ascending sort or a missing `+N more` changes this text.
    _many = [pr(940 + i, [f"area:a{i}"]) for i in range(10)]
    _many += [iss(950 + i, R + ["priority:P1", f"area:a{i}"]) for i in range(10)]
    _many_lines = []
    compute_ready(_many, log=_many_lines.append)
    check("[#1478] the named areas are ranked and BOUNDED, and the overflow is declared",
          _many_lines,
          [f"{CENSUS_PREFIX} candidates=10 frontier=0 conflict-deferred=10 reserved_areas=10 "
           "free_areas=0 cross-cutting-blocked=0 "
           "blocked-by-reserved: a0=1, a1=1, a2=1, a3=1, a4=1, a5=1, a6=1, a7=1 (+2 more)"])
    # `frontier_census` is PURE and the numbers are DERIVED, not passed through: hand it a
    # candidate set and a held set directly, with no engine in the loop.
    _c = [(1, 11, {"number": 11}, {"worker"}), (1, 12, {"number": 12}, {"docs", "worker"}),
          (2, 13, {"number": 13}, {"usage"})]
    check("[#1478] frontier_census is pure and derives every number from its inputs",
          frontier_census(_c, {"worker", "groom"}, [{"number": 13}]),
          [f"{CENSUS_PREFIX} candidates=3 frontier=1 conflict-deferred=2 reserved_areas=2 "
           "free_areas=2 cross-cutting-blocked=0 blocked-by-reserved: worker=2"])
    # An EMPTY board still reports, and reports zeroes — not a crash, not silence.
    check("[#1478] an empty board reports zeroes rather than nothing", frontier_census([], (), []),
          [f"{CENSUS_PREFIX} candidates=0 frontier=0 conflict-deferred=0 reserved_areas=0 "
           "free_areas=0 cross-cutting-blocked=0 blocked-by-reserved: none"])
    # ADD-ONLY RESERVATIONS + CONFLICT-FREEDOM, BY EXECUTION over every subset of a PR-bearing
    # board. These are the two universals this change actually has, and both pin the SIGN of it:
    #
    #   (i)  ADD-ONLY — folding a unit (`source_links`) is a SUPERSET of the unfolded per-row
    #        loop, so the fold can never RELEASE a key. This is `unit_reservations`' "MONOTONE BY
    #        CONSTRUCTION" docstring claim, EXECUTED rather than asserted in prose; dropping
    #        either half of a unit (sparq #4539: 41% of live pairs are not supersets) reds it.
    #   (ii) CONFLICT-FREEDOM — no offered row sits on a held key and no two offered rows collide,
    #        re-derived here independently of `compute_ready`'s own selection loop. This is the
    #        SAFETY property; `[:1]`-truncating the occupancy loop reds it.
    #
    # WHAT THIS DELIBERATELY NO LONGER CLAIMS. It read "MONOTONE: no subset of PR rows ever ADDS a
    # frontier row (0 violations)". That universal is FALSE, and false for a reason that has
    # nothing to do with PR rows: selection is greedy in (priority, number) order, so a held key
    # can knock out a multi-area contender and let a lower-priority issue on a DIFFERENT area take
    # a slot it would otherwise never reach. MEASURED with a seeded generator (3 occupancy rows x
    # 5 ready issues declaring 1-2 areas each, all 8 subsets, 4000 boards = 32000 trials): 4739
    # trials violate frontier-monotonicity on THIS engine — and 5582 violate it on `origin/master`
    # through in-flight ISSUE occupancy, with no PR row on the board at all. It is pre-existing
    # greedy-selection behaviour that this check mislabelled as a property of PR occupancy, and 0
    # of the violating trials was UNSAFE — which is why (ii) is the check that belongs here. The
    # old fixed board could not see any of it: every issue on it declared exactly ONE area.
    import itertools
    _mono_prs = [pr(800, ["area:worker"]), pr(801, []), pr(802, ["area:docs", "area:usage"])]
    _mono_iss = [iss(810, R + ["priority:P1", "area:docs", "area:usage"]),
                 iss(811, R + ["priority:P1", "area:docs"]),
                 iss(812, R + ["priority:P2", "area:usage"]),
                 iss(813, R + ["priority:P3"]),
                 iss(814, ["status:in-progress", "role:impl", "area:groom"])]
    _links = {800: [814]}          # PR #800 and the in-flight issue it closes are ONE unit

    def _held(rows, links=None):
        return set().union(set(), *(areas for areas, _row in unit_reservations(rows, links)))

    _subsets = [list(s) for _k in range(len(_mono_prs) + 1)
                for s in itertools.combinations(_mono_prs, _k)]
    _released, _unsafe = [], []
    for _subset in _subsets:
        _board = _subset + _mono_iss
        if not _held(_board) <= _held(_board, _links):
            _released.append(sorted(p["number"] for p in _subset))
        _seen = set(_held(_board))
        for _it in compute_ready(_board, log=lambda _line: None):
            _pkgs = packages_of(labels_of(_it))
            if (GLOBAL in _seen) or (_pkgs & _seen) or (GLOBAL in _pkgs and _seen):
                _unsafe.append((sorted(p["number"] for p in _subset), _it["number"]))
            _seen |= _pkgs
    check("[#768] ADD-ONLY: the fold never RELEASES a key, and the offered frontier is "
          "CONFLICT-FREE, over every subset of a PR-bearing board",
          (_released, _unsafe, len(_subsets)), ([], [], 8))
    print("ready-issues self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _flatten_pages(pages):
    """Flatten `gh api --paginate --slurp` output (a list of pages), RETAINING PRs.

    [OPUS-5 #768] PR rows used to be dropped here, which made the local `--repo` preview
    structurally unable to show a PR holding an area — the preview would have disagreed with the
    live dispatcher the moment the planner became PR-aware. They are occupancy artifacts now;
    `ready_candidates` is what keeps them out of the frontier.
    """
    return [i for page in pages for i in (page if isinstance(page, list) else [])
            if isinstance(i, dict)]


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

    [OPUS-5 #768] PR rows are carried through as occupancy, marked by the `pull_request` key.
    They are excluded from `open_numbers` (a `Blocked-by: #NN` marker naming a PR number is not
    an open-ISSUE blocker) and never get a blocker count of their own — nothing reads it, and the
    native dependency summary does not exist on a PR row.
    """
    open_numbers = {i["number"] for i in raw if "pull_request" not in i}
    rows = []
    for i in raw:
        row = {"number": i["number"], "state": i["state"], "labels": i["labels"],
               "open_blockers": 0}
        if "pull_request" in i:
            row["pull_request"] = i["pull_request"]
        else:
            row["open_blockers"] = open_blocker_count(i, open_numbers, warn)
        rows.append(row)
    return rows


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
