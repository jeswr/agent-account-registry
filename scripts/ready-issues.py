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
_PRIO = re.compile(r"^priority:P([0-4])$")   # only P0..P4 are valid
_PKG = re.compile(r"^area:(.+)$")
_ROLE = re.compile(r"^role:.+$")


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


def compute_ready(issues, in_progress_packages=None, log=None):
    """Conflict-free, priority-ordered, FAIL-CLOSED ready frontier (one-per-package concurrency
    width). This is NOT the count of drainable work — see ready_candidates() for that."""
    taken = set(in_progress_packages or ())
    for it in issues:
        if str(it.get("state", "OPEN")).upper() != "OPEN":
            continue
        L = labels_of(it)
        if "status:in-progress" in L or "status:in-progress-review" in L:
            taken |= packages_of(L)
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
