#!/usr/bin/env python3
# [OPUS-4.8] Registry self-management: the pure dispatch PLANNER for jeswr/agent-account-registry.
# A copy of the sparq target's scripts/dispatch-plan.py. The shared dispatch.yml PLAN job clones
# this repo (as a target), runs `scripts/dispatch-plan.py --self-test`, and imports compute_ready
# / plan_dispatch / packages_of / labels_of / _routing_doc — exactly as it does for sparq.
"""dispatch-plan.py — compose the readiness engine + route resolver into a dispatch plan.

PURE, read-only planner: walks the conflict-free, priority-ordered ready frontier from
`ready-issues.compute_ready`, resolves each issue's route via `route-resolve.resolve` against
`orchestration/routing.toml`, and emits a plan row per issue:
{number, priority, package, role, model_chain, agent, escalate}. It never claims an account or
triggers a worker (the credential-gated seam lives in the registry's dispatch-claim.py).
"""
import argparse
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util


def _load(modname, filename):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ready = _load("ready_issues", "ready-issues.py")
_route = _load("route_resolve", "route-resolve.py")

compute_ready = _ready.compute_ready
packages_of = _ready.packages_of
labels_of = _ready.labels_of
valid_priority = _ready.valid_priority
GLOBAL = _ready.GLOBAL
resolve = _route.resolve

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


def _roles_of(labels):
    """All DISTINCT declared roles, sorted for determinism (empty when roleless). The planner
    requires EXACTLY ONE (registry issue #122): CLAIM (policy-resolve.resolve) rejects a multi-role
    issue, so the old `sorted(labels)` first-role pick built a plan row CLAIM would reject."""
    return sorted({lb[5:] for lb in labels if lb.startswith("role:")})


def _plan_package(labels):
    """The single conflict partition a plan row reserves (registry issue #112). A one-area
    issue reserves that area; a NO-area OR MULTI-area issue reserves the serializing global
    partition, so it can never co-run with in-flight work in ANY of its areas. The old
    `sorted(packages_of(labels))[0]` kept only the alphabetically-first area, silently
    dropping every secondary area — an A+B issue could dispatch while B was busy. This mirrors
    packages_of's empty->global rule and extends it to the multi-area case (fail-closed:
    over-serialize a multi-area row rather than free a busy sibling crate)."""
    pkgs = packages_of(labels)
    return next(iter(pkgs)) if len(pkgs) == 1 else GLOBAL


def roleless_ready(issues):
    """The SILENT-INVISIBILITY class (registry issue #225): open issues that carry `status:ready`,
    are not epics, not gated, not busy and not blocked — and yet carry NO `role:*` label.

    `ready_candidates` requires a role, so the readiness engine drops these BEFORE any plan row
    exists: they appear in no plan, in no diagnostic, and drain never. 117 of them accumulated
    before a human noticed the backlog was not moving. PURE (returns sorted issue numbers); the
    planner still never GUESSES a role — the fail-closed drop is correct, its SILENCE was not, so
    callers report this count LOUDLY on every plan. Deliberately does NOT require a valid priority:
    a roleless issue must be reported whether or not it is also mis-prioritized."""
    numbers = []
    for it in issues:
        if str(it.get("state", "OPEN")).upper() != "OPEN":
            continue
        labels = labels_of(it)
        if "status:ready" not in labels or _ready.NON_DISPATCHABLE in labels:
            continue
        if _ready.is_gated(labels) or _ready.is_busy(labels):
            continue
        if int(it.get("open_blockers", 0)) > 0:
            continue
        if _ready.has_role(labels):
            continue
        numbers.append(it.get("number", 0))
    return sorted(numbers)


def plan_dispatch(ready_issues, routing_doc):
    """Compose the ready frontier + routing into a dispatch plan. PURE apart from a stderr
    diagnostic when it REJECTS an ambiguous-role issue (below). A roleless issue is flagged
    unresolved (role=None, agent=None) — never guessed (fail-closed)."""
    plan = []
    for it in ready_issues:
        labels = labels_of(it)
        roles = _roles_of(labels)
        if len(roles) > 1:
            # registry issue #122: CLAIM (policy-resolve.resolve) REJECTS an issue carrying more
            # than one role:* label. The planner must therefore NOT pick one arbitrarily (the old
            # `sorted(labels)` first-role) and build a plan row CLAIM will reject — that resolved
            # the role nondeterministically and then stranded the malformed issue every tick.
            # Reject it DETERMINISTICALLY here, BEFORE its plan row is constructed, with a
            # diagnostic; the tick stays healthy (the other ready issues still plan). NOT emitted
            # as a role=None row: dispatch.yml treats an unresolved planner row as a fatal
            # invariant breach (SystemExit) — that would abort the whole tick, not just this issue.
            print(f"skip #{it.get('number', 0)}: ambiguous role labels "
                  f"{', '.join(roles)} — exactly one role:* required (registry issue #122)",
                  file=sys.stderr)
            continue
        role = roles[0] if roles else None
        package = _plan_package(labels)
        try:
            model_chain, agent, escalate = resolve(labels, routing_doc)
        except _route.RoleResolutionError as exc:
            # registry issue #122 (round 2): a bare `role:` (empty value) or an UNCONFIGURED
            # `role:<name>` is likewise rejected by CLAIM (policy-resolve.resolve raises on an empty
            # role value and on a role absent from role_routes). resolve() now fails closed on both
            # BEFORE routing, so — as with the ambiguous case above — reject the issue here rather
            # than let the raise abort the tick OR (pre-fix) build a default-routed row CLAIM would
            # strand. Per-issue skip + diagnostic; the other ready issues still plan.
            print(f"skip #{it.get('number', 0)}: {exc} (registry issue #122)", file=sys.stderr)
            continue
        if role is None:
            row = {
                "number": it.get("number", 0),
                "priority": valid_priority(labels),
                "package": package,
                "role": None,
                "model_chain": [],
                "agent": None,
                "escalate": False,
            }
        else:
            row = {
                "number": it.get("number", 0),
                "priority": valid_priority(labels),
                "package": package,
                "role": role,
                "model_chain": list(model_chain),
                "agent": agent,
                "escalate": bool(escalate),
            }
        plan.append(row)
    return plan


def _routing_doc():
    here = os.path.dirname(os.path.abspath(__file__))
    toml = os.path.join(os.path.dirname(here), "orchestration", "routing.toml")
    with open(toml, "rb") as fh:
        return tomllib.load(fh)


def _self_test():
    doc = _routing_doc()
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    def iss(n, labels, blk=0, state="OPEN"):
        return {"number": n, "state": state, "labels": labels, "open_blockers": blk}

    R = ["status:ready"]

    # a non-trust impl issue (area:usage) -> sol-led chain (sol-first routing, 2026-07-18),
    # no escalate.
    impl = compute_ready([iss(1, R + ["priority:P1", "role:impl", "area:usage"])])
    p_impl = plan_dispatch(impl, doc)
    chk("impl -> single row", len(p_impl), 1)
    row = p_impl[0]
    chk("impl row", (row["role"], row["model_chain"][0], row["agent"], row["escalate"]),
        ("impl", "opus5", "registry-impl", False))
    chk("impl package", row["package"], "usage")

    # a TRUST-SURFACE issue (area:worker) -> opus5-led (opus tail fallback, 2026-07-24) +
    # escalate (security override beats role).
    sec = compute_ready([iss(2, R + ["priority:P0", "role:impl", "area:worker"])])
    row = plan_dispatch(sec, doc)[0]
    chk("worker -> opus5 only", row["model_chain"], ["opus5"])
    chk("worker -> reviewer/escalate", (row["agent"], row["escalate"]),
        ("registry-reviewer", True))
    chk("worker role stays declared", row["role"], "impl")

    # a docs issue -> its route (haiku-led).
    docs = compute_ready([iss(3, R + ["priority:P2", "role:docs", "area:docs"])])
    row = plan_dispatch(docs, doc)[0]
    chk("docs -> sol", row["model_chain"][0], "sol")
    chk("docs row has no cheap anthropic tier",
        sorted(set(row["model_chain"]) & {"haiku", "sonnet"}), [])

    # package-conflict pair -> only the higher-priority one is planned.
    pair = compute_ready([
        iss(4, R + ["priority:P2", "role:impl", "area:usage"]),
        iss(5, R + ["priority:P0", "role:impl", "area:usage"]),
    ])
    p_pair = plan_dispatch(pair, doc)
    chk("conflict -> one row", len(p_pair), 1)
    chk("conflict -> higher prio kept", p_pair[0]["number"], 5)

    chk("empty frontier -> empty plan", plan_dispatch([], doc), [])

    # no declared role -> fail-closed (role/agent None), never guessed.
    p_norole = plan_dispatch([iss(7, ["priority:P1", "area:usage"])], doc)
    row = p_norole[0]
    chk("no-role -> flagged", (row["role"], row["agent"], row["model_chain"]), (None, None, []))

    # issue #122: an AMBIGUOUS multi-role ready issue is REJECTED deterministically and produces
    # NO plan row — CLAIM (policy-resolve) rejects multiple roles, so a row with an arbitrarily
    # picked role (the pre-fix `sorted(labels)` first-role -> "docs" here) would strand the issue
    # every tick. The check flips red on the pre-fix code (which returned a one-row docs plan).
    p_ambig = plan_dispatch(
        compute_ready([iss(10, R + ["priority:P1", "role:docs", "role:impl", "area:usage"])]), doc)
    chk("ambiguous roles -> no row (rejected)", p_ambig, [])
    # per-issue rejection: a valid single-role issue alongside an ambiguous one still plans — only
    # the malformed one is dropped, so one mislabeled issue never aborts the whole tick.
    p_mix = plan_dispatch(compute_ready([
        iss(11, R + ["priority:P0", "role:impl", "area:usage"]),
        iss(12, R + ["priority:P1", "role:impl", "role:docs", "area:worker"]),
    ]), doc)
    chk("ambiguous dropped, valid kept", [r["number"] for r in p_mix], [11])

    # issue #122 (round 2): a bare `role:` (EMPTY value) and an UNCONFIGURED `role:<name>` are
    # ALSO rejected — CLAIM (policy-resolve) rejects an empty role value and a role absent from
    # role_routes, so a default-routed plan row would strand the issue every tick. resolve() raises
    # a RoleResolutionError and plan_dispatch drops the issue (no row), rather than crashing the
    # tick or emitting a permissive default row. An UNCONFIGURED role (`role:bogus`) reaches the
    # planner through readiness (has_role matches any `role:.+`) and is rejected here — non-vacuous:
    # the pre-fix planner built a one-row default-agent plan for it.
    chk("unknown role -> no row (rejected)", plan_dispatch(
        compute_ready([iss(14, R + ["priority:P1", "role:bogus", "area:usage"])]), doc), [])
    # A bare `role:` (empty value) is normally filtered EARLIER by readiness (has_role requires
    # `role:.+`), so feed plan_dispatch directly to exercise its own fail-closed guard (defense in
    # depth): even handed a malformed empty-role issue it drops it rather than emit a default row.
    # Non-vacuous: pre-fix resolve returned defaults and plan_dispatch built a role="" default row.
    chk("empty role -> no row (planner guard, defense in depth)",
        plan_dispatch([iss(13, R + ["priority:P1", "role:", "area:usage"])], doc), [])
    # per-issue rejection holds: a valid issue alongside a malformed-role one still plans. DIFFERENT
    # areas (usage vs docs) so both survive readiness — the drop is the role rejection, NOT a
    # package conflict filtering the second issue out before plan_dispatch sees it.
    p_mix2 = plan_dispatch(compute_ready([
        iss(15, R + ["priority:P0", "role:impl", "area:usage"]),
        iss(16, R + ["priority:P1", "role:bogus", "area:docs"]),
    ]), doc)
    chk("malformed single-role dropped, valid kept", [r["number"] for r in p_mix2], [15])

    # issue #225: a `status:ready` issue with NO role:* label is INVISIBLE to the enumerator
    # (ready_candidates' has_role gate drops it) — it must be REPORTED, never silently dropped.
    invisible = [
        iss(20, R + ["priority:P1", "area:usage"]),                        # ready but ROLELESS
        iss(21, R + ["priority:P1", "role:impl", "area:docs"]),            # has a role -> visible
        iss(22, R + ["priority:P1", "area:groom", "needs:design"]),        # gated (human-held)
        iss(23, R + ["priority:P1", "area:worker", "status:in-progress"]),  # busy
        iss(24, R + ["priority:P1", "area:ci", "kind:epic"]),              # epic (never work)
        iss(25, R + ["priority:P1", "area:dispatch"], state="CLOSED"),     # closed
        iss(26, R + ["priority:P1", "area:review-loop"], blk=1),           # open blocker
    ]
    chk("roleless-ready computes the invisible set", roleless_ready(invisible), [20])
    # non-vacuous pairing: #20 is EXACTLY the issue the frontier cannot see for want of a role —
    # the only ready row it plans is the role-carrying #21.
    chk("roleless-ready is the frontier's blind spot",
        [i["number"] for i in compute_ready(invisible)], [21])
    # a fully-labelled ready frontier reports NOTHING (no false alarm on a healthy tick).
    chk("healthy frontier -> no roleless", roleless_ready(
        [iss(27, R + ["priority:P1", "role:impl", "area:usage"])]), [])

    # #597 review finding 2: the LOUD half of this fix — the half issue #225 actually asks for —
    # had NO coverage. `roleless_ready(invisible) == [20]` tests the PURE computation; delete the
    # `::warning::` block from dispatch.yml and `_print_roleless(...)` from main() and every check
    # above stays green while the silent-invisibility failure is fully restored. So assert the
    # REPORTING: the rendered text, at a nonzero AND a zero count, through the real main()
    # entrypoint, plus the workflow-side wiring.
    def _captured(fn, *args):
        buffer, saved = io.StringIO(), sys.stdout
        try:
            sys.stdout = buffer
            fn(*args)
        finally:
            sys.stdout = saved
        return buffer.getvalue()

    loud = _captured(_print_roleless, [20, 26])
    chk("[#225] the roleless report NAMES the count, the issues and the consequence",
        ("2 status:ready issue(s) carry NO role:* label" in loud, "#20" in loud, "#26" in loud,
         "INVISIBLE" in loud, "role:* label" in loud),
        (True, True, True, True, True))
    quiet = _captured(_print_roleless, [])
    chk("[#225] the roleless report is printed even at ZERO (never a silent healthy tick)",
        ("ready-but-roleless issues: 0" in quiet, quiet.strip() != ""), (True, True))
    # #597 review round 2 (F-class): the zero line claimed "every status:ready issue is
    # enumerable", but roleless_ready() excludes gated/busy/blocked/epic/closed rows — this suite's
    # own fixture #22 (status:ready + area:groom + needs:design, roleless) is a counterexample
    # sitting behind that printed zero. Pin the SCOPED wording so the over-claim cannot come back,
    # and pin the fixture that disproves the old one.
    chk("[#597 r2] the zero line scopes its claim to the missing-role class only",
        ("every status:ready issue is enumerable" in quiet,
         "missing a role:* label" in quiet, "excluded by design" in quiet),
        (False, True, True))
    chk("[#597 r2] ...and #22 (status:ready + needs:design, roleless) is that counterexample",
        (roleless_ready([iss(22, R + ["priority:P1", "area:groom", "needs:design"])]),
         [i["number"] for i in compute_ready(
             [iss(22, R + ["priority:P1", "area:groom", "needs:design"])])]),
        ([], []))
    chk("[#597 r2] the remediation line does not claim a role alone is always sufficient",
        ("priority:P0..P4" in loud, "role:* label" in loud), (True, True))

    # ...and through main() --dry-run itself, so "the planner can compute it" can never stand in for
    # "the plan EMITS it". The two live reads (`gh` issue fetch, routing.toml) are the only things
    # stubbed; main()'s own code path is the real one.
    def _main_dry_run(issues):
        saved = (sys.argv, _ready._fetch, globals()["_routing_doc"])
        try:
            sys.argv = ["dispatch-plan.py", "--dry-run"]
            _ready._fetch = lambda repo, *a, **k: list(issues)
            globals()["_routing_doc"] = lambda: doc
            return _captured(main)
        finally:
            sys.argv, _ready._fetch, globals()["_routing_doc"] = saved

    reported = _main_dry_run(invisible)
    chk("[#225] main() --dry-run REPORTS the invisible issues alongside the plan",
        ("1 status:ready issue(s) carry NO role:* label" in reported, "#20" in reported,
         "would be dispatched" in reported), (True, True, True))
    healthy = _main_dry_run([iss(28, R + ["priority:P1", "role:impl", "area:usage"])])
    chk("[#225] main() --dry-run prints the zero line on a healthy board",
        "ready-but-roleless issues: 0" in healthy, True)

    # The scheduled path is dispatch.yml's PLAN job, not main(): assert IT calls the planner's
    # roleless enumeration and emits the loud annotation. Comments are stripped first — this file's
    # own prose mentions `roleless_ready`, and a claim in a comment must never satisfy a wiring
    # check (the same vacuity class as #616 findings 3-4).
    workflow = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            ".github", "workflows", "dispatch.yml")
    with open(workflow, encoding="utf-8") as fh:
        executable = "\n".join(line for line in fh.read().splitlines()
                               if not line.lstrip().startswith("#"))
    # STATIC SHAPE ONLY, and #597 review round 2 was right that on its own it is vacuous: every
    # searched substring survives flipping `if roleless_fn is None:` to `is not None:` or
    # `if roleless:` to `if not roleless:`, each of which fully restores silent invisibility. Kept
    # as cheap drift detection; the block's BEHAVIOUR is covered by the executed rows below.
    chk("[#225] the PLAN job calls the planner's roleless enumeration and reports it LOUDLY",
        ('getattr(dispatch, "roleless_ready"' in executable,
         "roleless_fn(readiness_input)" in executable,
         "are INVISIBLE to dispatch" in executable,
         "ready-but-roleless issues: 0" in executable),
        (True, True, True, True))

    # ------------------------------------------------------------------------------------------
    # [#597 review ROUND 2, MAJOR] THE WORKFLOW BLOCK IS EXECUTED, not pattern-matched. It is the
    # SCHEDULED path — main() is not — and its two `if` conditions are workflow python that no test
    # ran: `if roleless_fn is None:` -> `is not None:` makes every target report "planner has no
    # roleless_ready()" so enumeration never runs, and `if roleless:` -> `if not roleless:` reports
    # zero precisely when invisible issues exist. Both left all four substring assertions green.
    # The block is extracted between its sentinels (fail-closed if either is gone), dedented, and
    # run against a stub planner in a controlled namespace, so each row below dies on a one-token
    # flip. Its only inputs are `dispatch`, `readiness_input` and `repo`.
    # ------------------------------------------------------------------------------------------
    def _workflow_block(path, step_id, marker):
        """The dedented python between `# >>> <marker>` and `# <<< <marker>` inside the ONE
        workflow step whose `id:` is `step_id`. Raises on anything it cannot resolve uniquely — an
        assertion that cannot find its target must fail, never pass vacuously."""
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().split("\n")
        ids = [i for i, line in enumerate(lines) if line.strip() == f"id: {step_id}"]
        if len(ids) != 1:
            raise AssertionError(f"expected one workflow step `id: {step_id}`, found {len(ids)}")
        starts = [i for i in range(ids[0], -1, -1) if lines[i].lstrip().startswith("- ")]
        indent = len(lines[starts[0]]) - len(lines[starts[0]].lstrip())
        end = len(lines)
        for i in range(starts[0] + 1, len(lines)):
            if not lines[i].strip():
                continue
            here = len(lines[i]) - len(lines[i].lstrip())
            if here < indent or (here == indent and lines[i].lstrip().startswith("- ")):
                end = i
                break
        block = lines[starts[0]:end]
        opens = [i for i, line in enumerate(block) if line.strip().startswith(f"# >>> {marker}")]
        closes = [i for i, line in enumerate(block) if line.strip() == f"# <<< {marker}"]
        if len(opens) != 1 or len(closes) != 1 or closes[0] <= opens[0]:
            raise AssertionError(
                f"step `id: {step_id}` must contain exactly one `# >>> {marker}` ... "
                f"`# <<< {marker}` pair, found {len(opens)}/{len(closes)} — refusing")
        body = [line for line in block[opens[0] + 1:closes[0]]
                if line.strip() and not line.lstrip().startswith("#")]
        if not body:
            raise AssertionError(f"the `{marker}` block extracted to nothing — refusing")
        pad = min(len(line) - len(line.lstrip()) for line in body)
        source = "\n".join(line[pad:] for line in body)
        compile(source, f"<{marker}>", "exec")   # a block that will not compile is a defect here
        return source

    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    roleless_block = _workflow_block(
        os.path.join(_root, ".github", "workflows", "dispatch.yml"), "readiness",
        "roleless-report")

    class _StubPlanner:
        """Stands in for the target's `dispatch` module. `enumerate_roleless=False` models a target
        whose planner PREDATES roleless_ready (the compatibility branch)."""

        def __init__(self, result, enumerate_roleless=True):
            self.seen = []
            if enumerate_roleless:
                self.roleless_ready = self._roleless
            self._result = result

        def _roleless(self, issues):
            self.seen.append(list(issues))
            return list(self._result)

    def _run_block(result, enumerate_roleless=True):
        planner = _StubPlanner(result, enumerate_roleless)
        namespace = {"dispatch": planner, "readiness_input": [{"number": 20}, {"number": 26}],
                     "repo": "o/t"}
        text = _captured(lambda: exec(roleless_block, namespace))  # noqa: S102 — workflow block
        return text, planner.seen

    _loudly, _seen = _run_block([20, 26])
    chk("[#597 r2] the EXECUTED workflow block enumerates and warns when issues are invisible",
        ("::warning::o/t: 2 status:ready issue(s) carry no role:* label and are INVISIBLE to "
         "dispatch: #20, #26" in _loudly,
         _seen == [[{"number": 20}, {"number": 26}]]),
        (True, True))
    _quietly, _seen = _run_block([])
    chk("[#597 r2] ...and prints the ZERO line — never the warning — when there are none",
        (_quietly.strip(), "INVISIBLE" in _quietly, _seen != []),
        ("o/t: ready-but-roleless issues: 0", False, True))
    _degraded, _seen = _run_block([20], enumerate_roleless=False)
    chk("[#597 r2] a planner WITHOUT roleless_ready says so, and reports no fabricated zero",
        ("target planner has no roleless_ready()" in _degraded,
         "ready-but-roleless issues: 0" in _degraded, _seen),
        (True, False, []))
    _truncated, _seen = _run_block(list(range(1, 31)))
    chk("[#597 r2] a large invisible set is summarized, not truncated silently",
        ("30 status:ready issue(s)" in _truncated,
         "#19, #20 (+10 more)" in _truncated, "#21" in _truncated),
        (True, True, False))

    # issue #112: a MULTI-area issue reserves the serializing GLOBAL partition, NOT the
    # alphabetically-first area — else a busy secondary area (here 'worker') could not exclude
    # it and it would double-dispatch. A single-area issue still reserves just that area.
    p_multi = plan_dispatch(
        compute_ready([iss(8, R + ["priority:P1", "role:impl", "area:usage", "area:worker"])]), doc)
    chk("multi-area -> global package", p_multi[0]["package"], GLOBAL)
    chk("single-area -> that package", plan_dispatch(
        compute_ready([iss(9, R + ["priority:P1", "role:impl", "area:usage"])]), doc)[0]["package"],
        "usage")

    print("dispatch-plan self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _print_table(plan):
    if not plan:
        print("(no ready issues — the dispatch plan is empty; nothing to dispatch)")
        return
    cols = ["number", "priority", "package", "role", "model_chain", "agent", "escalate"]

    def cell(row, c):
        v = row[c]
        if c == "number":
            return f"#{v}"
        if c == "priority":
            return f"P{v}" if v is not None else "P?"
        if c == "model_chain":
            return ">".join(v) if v else "-"
        return str(v) if v is not None else "-"

    widths = {c: max(len(c), *(len(cell(r, c)) for r in plan)) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    print("  ".join("-" * widths[c] for c in cols))
    for r in plan:
        print("  ".join(cell(r, c).ljust(widths[c]) for c in cols))
    print(f"\n{len(plan)} issue(s) would be dispatched (dry-run).")


def _print_roleless(numbers):
    """ONE aggregate line on EVERY plan — printed even when the count is zero, the same
    always-printed shape as dispatch.yml's review-enumeration exclusion line. A plan showing N
    rows must never silently coexist with ready issues no enumerator can see (issue #225).

    #597 review round 2 (F-class): the zero line used to read "every `status:ready` issue is
    enumerable", which is FALSE — `roleless_ready()` deliberately excludes gated, busy, blocked,
    epic and closed issues, so a `status:ready` + `needs:design` issue is un-enumerable AND behind
    a printed zero. This line reports ONE class (missing `role:*`) and now says so. The remediation
    is likewise scoped honestly: a role is necessary, not always sufficient."""
    if not numbers:
        print("ready-but-roleless issues: 0 (no OPEN status:ready issue is missing a role:* label; "
              "issues held by needs:*/trust:untrusted, an open blocker, kind:epic or an "
              "in-progress claim are excluded by design and are NOT covered by this count).")
        return
    print(f"WARNING: {len(numbers)} status:ready issue(s) carry NO role:* label and are INVISIBLE "
          "to dispatch — they can never be planned: "
          + ", ".join(f"#{n}" for n in numbers))
    print("  fix: give each one a role:* label (scripts/triage.py derives one from its area:*); an "
          "issue that also lacks a valid priority:P0..P4 needs that too before it can be planned.")


def main():
    ap = argparse.ArgumentParser(description="Pure dispatch planner (dry-run) for the registry.")
    ap.add_argument("--repo", default="jeswr/agent-account-registry")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if args.dry_run:
        issues = _ready._fetch(args.repo)
        ready = compute_ready(issues)
        plan = plan_dispatch(ready, _routing_doc())
        _print_table(plan)
        _print_roleless(roleless_ready(issues))
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
