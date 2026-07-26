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
  * carries a `role:*` label, and
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
# [OPUS-5 issue #688] Historical, behaviour-preserving frontier width: exactly one in-flight issue
# per `area:` package. Also the fail-closed floor for a policy-supplied width.
DEFAULT_PACKAGE_WIDTH = 1
_PRIO = re.compile(r"^priority:P([0-4])$")   # only P0..P4 are valid
_PKG = re.compile(r"^area:(.+)$")
_ROLE = re.compile(r"^role:.+$")


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


def ready_candidates(issues, log=None):
    """Every issue that passes the FAIL-CLOSED readiness LABEL gate (open + status:ready + exactly
    one priority + a role + no gate/busy label + zero open blockers), priority-then-number ordered.

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
        reason = exclusion_reason(L, it.get("open_blockers", 0))
        if reason is not None:
            if "status:ready" in L:
                log(f"readiness defer #{it.get('number', 0)}: {reason}")
            continue
        cands.append((valid_priority(L), it.get("number", 0), it, packages_of(L)))
    cands.sort(key=lambda c: (c[0], c[1]))   # priority then number (deterministic)
    return cands


def compute_ready(issues, in_progress_packages=None, log=None, package_width=DEFAULT_PACKAGE_WIDTH):
    """Conflict-free, priority-ordered, FAIL-CLOSED ready frontier. This is NOT the count of
    drainable work — see ready_candidates() for that.

    [OPUS-5 issue #688] `package_width` is the number of issues that may be in flight PER
    `area:<section>` package. It defaults to 1, which is the historical exactly-one-per-package
    serialization, byte-for-byte — so an unset width changes nothing anywhere.

    WHY THIS KNOB EXISTS, and — precisely — WHAT IT DOES NOT DO. Measured on the registry: 12
    drainable candidates spread over only 3 distinct areas collapse to a frontier of 3, so
    `max_concurrent` was never the limiter and raising it alone is inert. Width widens THIS layer,
    the PLAN frontier, and nothing else.

    IT IS NOT, ON ITS OWN, A THROUGHPUT LEVER (review finding F2 — an earlier version of this
    docstring claimed it converted drainable backlog into concurrent work; that was wrong). The
    binding constraint sits one layer DOWN, at the lease layer: `select-and-claim.partition_available`
    refuses a second live lease on the same package, and `dispatch-claim.filter_busy_area_items`
    drops any item whose package already has an in-flight worker PR or live lease. With width 2 the
    frontier grows from 3 to 6 and the three extra rows are then refused with `package-single-flight`
    — a MEASURED net gain of ZERO additional concurrent workers. Width only becomes a throughput
    lever once the lease-layer partition is widened by the same bound (tracked in #692); until then
    every target is deliberately configured at width 1 and this parameter is prepared, not enabled.

    THE COST, honestly. One-per-package exists because two agents in the same area tend to edit the
    same file, and this repo's areas map onto very large single scripts. Width > 1 therefore trades
    merge conflicts for throughput; it is deliberately a per-target policy knob (see
    `policy/repos.toml`) rather than a raised default, and the repo already runs a conflict
    resolver for the collisions it does produce. The GLOBAL (cross-cutting, area-less) partition is
    NEVER widened — it exists precisely to serialize against everything, so widening it would be
    incoherent regardless of policy.
    """
    try:
        width = int(package_width)
    except (TypeError, ValueError):
        width = DEFAULT_PACKAGE_WIDTH        # unparseable policy -> the SAFE historical behaviour
    width = max(DEFAULT_PACKAGE_WIDTH, width)  # fail-closed floor: never narrower than 1
    counts = {}
    for it in issues:
        if str(it.get("state", "OPEN")).upper() != "OPEN":
            continue
        L = labels_of(it)
        if "status:in-progress" in L or "status:in-progress-review" in L:
            for pkg in packages_of(L):
                counts[pkg] = counts.get(pkg, 0) + 1
    for pkg in (in_progress_packages or ()):
        counts[pkg] = counts.get(pkg, 0) + 1

    def full(pkg):
        """A package is closed to new work at its width — the GLOBAL partition always at 1."""
        return counts.get(pkg, 0) >= (DEFAULT_PACKAGE_WIDTH if pkg == GLOBAL else width)

    cands = ready_candidates(issues, log=log)
    ready = []
    for _p, _n, it, pkgs in cands:
        if full(GLOBAL) and counts.get(GLOBAL, 0):  # cross-cutting in flight -> nothing else co-runs
            break
        if any(full(pkg) for pkg in pkgs):   # package conflict (at width)
            continue
        if GLOBAL in pkgs and counts:        # cross-cutting can't co-run with any package in flight
            continue
        for pkg in pkgs:
            counts[pkg] = counts.get(pkg, 0) + 1
        ready.append(it)
    return ready


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
    check("valid_priority single", valid_priority({"priority:P0"}), 0)
    check("valid_priority ambiguous", valid_priority({"priority:P1", "priority:P2"}), None)
    check("packages none->global", packages_of({"role:impl"}), {GLOBAL})
    # ---- #586: every dropped `status:ready` candidate is ATTRIBUTABLE (the silent `continue` is
    # what let a label-regressed issue leave the frontier forever with zero signal) ----
    lines = []
    compute_ready(F, log=lines.append)
    check("every dropped status:ready candidate emits one attributable defer line",
          sorted(int(re.search(r"#(\d+)", line).group(1)) for line in lines),
          [4, 5, 7, 9, 10, 13, 14, 40])
    reasons = {int(re.search(r"#(\d+)", line).group(1)): line for line in lines}
    check("#586 lost-priority names the priority condition",
          "no single valid priority:P0..P4" in reasons[9], True)
    check("#586 lost-role names the role condition", "no role:* label" in reasons[14], True)
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
    # ---- [OPUS-5 issue #688] PACKAGE WIDTH: the frontier lever ------------------------------------
    # The default MUST be byte-for-byte the historical one-per-package serialization, and a widened
    # package MUST actually admit more work — otherwise "raise the ceiling" is inert on a
    # package-clustered backlog. Deleting the width plumbing collapses the first two to the same
    # list; widening GLOBAL breaks the serialization guarantee the partition exists to provide.
    check("default width is exactly the historical one-per-package frontier",
          [i["number"] for i in compute_ready(F)], [i["number"] for i in compute_ready(F, package_width=1)])
    check("width=2 admits a SECOND issue from the same package (1 joins 2 on `worker`)",
          [i["number"] for i in compute_ready(F, package_width=2)], [2, 3, 12, 1])
    check("width only ever GROWS the frontier (it is a superset of width=1)",
          set(i["number"] for i in compute_ready(F)) <=
          set(i["number"] for i in compute_ready(F, package_width=3)), True)
    check("width never exceeds the drainable candidate set",
          len(compute_ready(F, package_width=99)) <= len(ready_candidates(F, log=lambda _l: None)),
          True)
    # The GLOBAL partition is the cross-cutting serializer — widening it would be incoherent.
    wide_global = [iss(11, R + ["priority:P0"]), iss(12, R + ["priority:P1", "area:groom"])]
    check("GLOBAL partition is NEVER widened, whatever the policy says",
          [i["number"] for i in compute_ready(wide_global, package_width=9)], [11])
    check("two area-less issues never co-run even at a wide width",
          [i["number"] for i in compute_ready(
              [iss(30, R + ["priority:P0"]), iss(31, R + ["priority:P1"])], package_width=9)], [30])
    # An in-progress issue consumes width, so a widened package still respects live work.
    busy = [iss(40, R + ["priority:P1", "area:worker", "status:in-progress"]),
            iss(41, R + ["priority:P1", "area:worker"]),
            iss(42, R + ["priority:P2", "area:worker"])]
    check("in-progress work CONSUMES width (width=2 leaves room for exactly one more)",
          [i["number"] for i in compute_ready(busy, package_width=2)], [41])
    check("in_progress_packages argument consumes width too",
          [i["number"] for i in compute_ready(
              [iss(43, R + ["priority:P1", "area:worker"]), iss(44, R + ["priority:P2", "area:worker"])],
              in_progress_packages=["worker"], package_width=2)], [43])
    # FAIL-CLOSED: junk policy must degrade to the SAFE narrow default, never to an unbounded width.
    check("a junk / zero / negative width fails closed to the historical width of 1",
          [[i["number"] for i in compute_ready(F, package_width=w)]
           for w in (0, -5, "nonsense", None, 1.9)],
          [[2, 3, 12]] * 5)
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
    open_numbers = {i["number"] for i in raw}
    issues = []
    for i in raw:
        blockers = re.findall(r"[Bb]locked-by:\s*#(\d+)", i.get("body") or "")
        open_blk = sum(1 for b in blockers if int(b) in open_numbers)
        issues.append({"number": i["number"], "state": i["state"],
                       "labels": i["labels"], "open_blockers": open_blk})
    return issues


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
