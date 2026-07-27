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
import re
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

    # [OPUS-5] a non-trust impl issue (area:usage) -> OPUS5-ONLY + escalate (maintainer decision
    # 2026-07-26, registry #738: "Remove sol from impl fallback"). The WHOLE chain is asserted, not
    # its head: the planner row is what CLAIM compares for exact equality, so a demoted-not-removed
    # sol must red here too.
    impl = compute_ready([iss(1, R + ["priority:P1", "role:impl", "area:usage"])])
    p_impl = plan_dispatch(impl, doc)
    chk("impl -> single row", len(p_impl), 1)
    row = p_impl[0]
    chk("impl row", (row["role"], row["model_chain"], row["agent"], row["escalate"]),
        ("impl", ["opus5"], "registry-impl", True))
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
        assertion that cannot find its target must fail, never pass vacuously.

        [sparq #4329] It ALSO refuses when the step, or the job containing it, carries an `if:`.
        Extraction-by-sentinel reads the source text, so `if: false` on the step would disable the
        block in production with every executed assertion below still green — the precise
        never-runs-in-anger vacuity the sentinel harness exists to prevent. There is no legitimate
        conditional on the readiness step (PLAN runs it every tick), so ANY `if:` is refused rather
        than evaluated; a future conditional must be declared here deliberately.
        """
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
        # the STEP's own keys sit one level in from its `- ` marker
        step_if = [line for line in block
                   if line.startswith(" " * (indent + 2) + "if:")]
        if step_if:
            raise AssertionError(
                f"workflow step `id: {step_id}` carries {step_if[0].strip()!r} — this block is "
                "EXECUTED by this self-test from its source text, so a conditional step would "
                "pass every assertion while never running. Refusing.")
        # ...and the JOB that owns it: `jobs:` entries at indent 2, their keys at indent 4.
        jobs = [i for i in range(starts[0], -1, -1)
                if re.fullmatch(r"  [A-Za-z0-9_-]+:\s*", lines[i])]
        if not jobs:
            raise AssertionError(f"cannot locate the job owning step `id: {step_id}` — refusing")
        job_end = next((i for i in range(jobs[0] + 1, len(lines))
                        if re.fullmatch(r"  [A-Za-z0-9_-]+:\s*", lines[i])), len(lines))
        job_if = [line for line in lines[jobs[0]:job_end] if line.startswith("    if:")]
        if job_if:
            # ONE modelled exception, and it is an allowlist of a single exact expression, not a
            # loosening (issue #819). The worry this guard encodes is a PERMANENTLY disabled job
            # leaving every executed assertion below green. The #819 tick floor is a TEMPORAL rate
            # gate: it is false only for ticks arriving inside the minimum interval, and the very
            # next tick past the floor runs the job. Admitting it costs nothing here; admitting
            # "any `if:`" would give back the whole guard, so anything that is not this exact
            # string still refuses — including a rewrite of the same gate into a different form,
            # which must be re-reviewed rather than pattern-matched.
            floor_gate = "if: ${{ needs.tick-floor.outputs.proceed == 'true' }}"
            declares_floor_job = any(re.fullmatch(r"  tick-floor:\s*", line) for line in lines)
            if not (len(job_if) == 1 and job_if[0].strip() == floor_gate and declares_floor_job):
                raise AssertionError(
                    f"the job owning step `id: {step_id}` carries {job_if[0].strip()!r} — a "
                    "disabled job would leave every executed assertion below green. Only the "
                    f"#819 tick-floor gate ({floor_gate!r}, with a `tick-floor:` job present in "
                    "the same file) is modelled here. Refusing.")
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

    # ------------------------------------------------------------------------------------------
    # [sparq #4329] NATIVE GitHub dependency edges. The dispatcher derived `open_blockers` ONLY
    # from a `Blocked-by: #NN` BODY regex, so a dependency the maintainer added through GitHub's
    # native UI had ZERO effect on dispatch. The fix unions the native
    # `issue_dependencies_summary.blocked_by` count with the marker count, and it lives ENTIRELY
    # in workflow python — the exact seam where every uncaught mutant in this repo has lived.
    # So the block is EXTRACTED and EXECUTED here, not pattern-matched: each row below dies on a
    # one-token flip (delete the native read, turn the union into a replacement either way, read
    # `total_blocked_by` instead, admit a malformed summary as zero, invert the dark alarm).
    # Its only inputs are `raw`, `repo`, `label_names` and `re`.
    # ------------------------------------------------------------------------------------------
    _dispatch_yml = os.path.join(_root, ".github", "workflows", "dispatch.yml")
    blocker_block = _workflow_block(_dispatch_yml, "readiness", "blocker-union")

    # THE YAML SEAM ITSELF. Extraction reads SOURCE TEXT, so `if: false` on the readiness step (or
    # on the PLAN job) disables both sentinel blocks in production while every executed row below
    # stays green — a substring or `count(...) == N` assertion cannot see it either. Prove the
    # harness refuses both, by injecting each conditional into a real copy of the workflow.
    def _with_line(after_pattern, inserted):
        with open(_dispatch_yml, encoding="utf-8") as handle:
            lines = handle.read().split("\n")
        hits = [i for i, line in enumerate(lines) if line.rstrip() == after_pattern]
        if len(hits) != 1:
            raise AssertionError(f"expected one {after_pattern!r} line, found {len(hits)}")
        lines.insert(hits[0] + 1, inserted)
        handle_dir = os.path.join(_root, ".github", "workflows")
        path = os.path.join(handle_dir, ".dispatch-seam-probe.yml")
        with open(path, "w", encoding="utf-8") as out:
            out.write("\n".join(lines))
        return path

    def _refusal(path):
        try:
            _workflow_block(path, "readiness", "blocker-union")
        except AssertionError as exc:
            return str(exc)
        finally:
            os.remove(path)
        return ""

    _step_off = _refusal(_with_line("        id: readiness", "        if: false"))
    chk("[#4329][YAML seam] `if: false` on the readiness STEP is REFUSED, not silently accepted",
        ("carries 'if: false'" in _step_off, "never running" in _step_off), (True, True))
    _job_off = _refusal(_with_line(
        "    name: PLAN (unprivileged, secret-free target half)", "    if: false"))
    chk("[#4329][YAML seam] `if: false` on the PLAN JOB is REFUSED too",
        ("job owning step" in _job_off, "if: false" in _job_off), (True, True))

    def _blockers(rows, repo="o/t"):
        """Run the REAL workflow block over REST-shaped issue rows; return (rows, printed)."""
        namespace = {
            "raw": rows, "repo": repo, "re": re,
            "label_names": lambda issue: sorted(
                label["name"] for label in issue.get("labels", [])),
        }
        text = _captured(lambda: exec(blocker_block, namespace))  # noqa: S102 — workflow block
        return namespace["readiness_input"], text

    def _rest(number, body="", summary=..., labels=()):
        """A row in the SHAPE the authenticated snapshot writes (`GET /repos/../issues`)."""
        row = {"number": number, "body": body,
               "labels": [{"name": name} for name in labels]}
        if summary is not ...:
            row["issue_dependencies_summary"] = summary
        return row

    def _sum(open_blockers, total=None):
        return {"blocked_by": open_blockers, "blocking": 0,
                "total_blocked_by": open_blockers if total is None else total, "total_blocking": 0}

    # (1) THE REGRESSION THIS EXISTS FOR — a native edge with NO body marker must hold the issue.
    _rows, _ = _blockers([_rest(40, body="no marker here", summary=_sum(1))])
    chk("[#4329] a NATIVE blocked_by edge with no body marker holds the issue",
        [row["open_blockers"] for row in _rows], [1])
    # ...and it reaches the FRONTIER, not merely the row dict: a correct count nothing consults
    # is precisely the bug being fixed.
    _ready_labels = ("status:ready", "role:impl", "priority:P1", "area:usage")
    _rows, _ = _blockers([_rest(40, body="", summary=_sum(1), labels=_ready_labels)])
    chk("[#4329] ...and compute_ready() HOLDS it end-to-end",
        [it["number"] for it in compute_ready(_rows)], [])
    _rows, _ = _blockers([_rest(40, body="", summary=_sum(0), labels=_ready_labels)])
    chk("[#4329] ...while the same issue with no native edge IS dispatched",
        [it["number"] for it in compute_ready(_rows)], [40])
    # (2) UNION, never replace: 3 live sparq issues are marker-only, so a replacement drops them.
    _rows, _ = _blockers([_rest(41, labels=("role:impl",)),
                          _rest(42, body="Blocked-by: #41", summary=_sum(0),
                                labels=_ready_labels)])
    chk("[#4329] a MARKER-only edge (native says zero) still holds the issue",
        ([row["open_blockers"] for row in _rows], [it["number"] for it in compute_ready(_rows)]),
        ([0, 1], []))
    # (3) a CLOSED blocker must NOT hold the child on either channel. Native: `blocked_by` counts
    # only open blockers while `total_blocked_by` counts the closed one (MEASURED on 16 live
    # sparq issues, e.g. #3264 blocked_by=0 total_blocked_by=1). Marker: #43 is not in the snapshot.
    _rows, _ = _blockers([_rest(44, body="Blocked-by: #43", summary=_sum(0, total=2),
                                labels=_ready_labels)])
    chk("[#4329] an issue whose ONLY blocker is CLOSED is NOT held",
        ([row["open_blockers"] for row in _rows], [it["number"] for it in compute_ready(_rows)]),
        ([0], [44]))
    # (4) union arithmetic over every channel combination, through the workflow block itself.
    _rows, _ = _blockers([_rest(50, body="", summary=...),
                          _rest(51, body="", summary=_sum(0)),
                          _rest(52, body="", summary=_sum(3)),
                          _rest(53, body="Blocked-by: #50", summary=_sum(0)),
                          _rest(54, body="Blocked-by: #50", summary=_sum(3)),
                          _rest(55, body="Blocked-by: #99999", summary=_sum(0))])
    chk("[#4329] the block unions both channels and never replaces either",
        [row["open_blockers"] for row in _rows], [0, 0, 3, 1, 3, 0])
    # (5) a PRESENT-but-malformed summary FAILS CLOSED (holds), and says why.
    _rows, _text = _blockers([_rest(60, summary={"blocked_by": -1}, labels=_ready_labels),
                              _rest(61, summary={"blocked_by": "1"}, labels=_ready_labels),
                              _rest(62, summary={"blocked_by": True}, labels=_ready_labels),
                              _rest(63, summary=["not", "a", "dict"], labels=_ready_labels)])
    chk("[#4329] a malformed native summary holds the issue instead of admitting it",
        ([row["open_blockers"] for row in _rows],
         [it["number"] for it in compute_ready(_rows)],
         _text.count("fail-closed"), "o/t#63" in _text),
        ([1, 1, 1, 1], [], 4, True))
    # (6) the DARK-CHANNEL alarm — absent on EVERY row is a schema regression, not a quiet repo.
    _, _dark = _blockers([_rest(70, summary=...), _rest(71, summary=...)])
    chk("[#4329] a snapshot with no native-dependency data raises the DARK alarm",
        ("::warning::o/t: NATIVE BLOCKER CHANNEL IS DARK" in _dark, "none of 2 open" in _dark,
         "LIT" in _dark),
        (True, True, False))
    _, _lit = _blockers([_rest(70, summary=...), _rest(71, summary=_sum(1))])
    chk("[#4329] one row carrying the summary keeps the channel LIT, and it is reported at ZERO",
        ("DARK" in _lit,
         "o/t: native blocker channel: LIT (1 of 2 open issue(s) held by a blocker)" in _lit),
        (False, True))
    _, _empty = _blockers([])
    chk("[#4329] an empty snapshot never fabricates a DARK alarm", "DARK" in _empty, False)
    # (7) the fail-closed field validation the block inherited must survive the rewrite.
    _malformed = ""
    try:
        _blockers([{"number": 0, "body": "", "labels": []}])
    except SystemExit as exc:
        _malformed = str(exc)
    chk("[#4329] a malformed issue number still kills the sweep, fail-closed",
        _malformed, "target issue fields are malformed")

    # ------------------------------------------------------------------------------------------
    # [#768] PLAN'S OCCUPANCY MUST CARRY THE PR HALF OF EVERY UNIT OF WORK.
    #
    # These run the ENTIRE readiness step, not a sentinel block. The defect this fixes lives at a
    # CALL SITE (`ready_input = occupancy_input + [...]`, and the deferred lane's argument list),
    # and a call site is exactly what a block-scoped harness cannot see: deleting six characters
    # there restores the bug with every block-level assertion still green. So the step's whole
    # python heredoc is extracted and EXECUTED against a synthetic two-target fixture, and the
    # assertions are made on the PLAN ROWS it emits — the artifact CLAIM actually consumes.
    #
    # Target 0 is a PR-AWARE planner (sparq's occupancy semantics: a PR row reserves its declared
    # areas and is never a candidate). Target 1 is THIS REPOSITORY'S OWN planner, unmodified, so
    # the interlock is tested against the real engine it exists to protect rather than a mock of
    # it — `scripts/ready-issues.py` here has no `pull_request` guard at all.
    # ------------------------------------------------------------------------------------------
    def _is_modelled_tick_floor_gate(scope, mapping, document):
        """The ONE `if:` the two guards below admit: the #819 tick floor on the PLAN job.

        This is an allowlist of a single exact expression, not a loosening. What those guards
        encode is a worry about a PERMANENTLY disabled job leaving every executed assertion green.
        The tick floor is a TEMPORAL rate gate — false only for a tick arriving inside the minimum
        interval between EXECUTED ticks, and the next tick past the floor runs the job — so it
        cannot hide a broken planner for more than one interval. Three conditions, all required:
        it is the JOB (never a step), the expression is byte-exact, and the job it names actually
        exists in the same document. A rewrite of the same gate into a different form still
        refuses, deliberately: that is a re-review, not a pattern match."""
        if not scope.startswith("job "):
            return False
        gate = "${{ needs.tick-floor.outputs.proceed == 'true' }}"
        return (str(mapping.get("if")).strip() == gate
                and "tick-floor" in ((document.get("jobs") or {})))

    def _refuse_exit_zero_swallow(path, step_id):
        """Refuse any way the `id: step_id` step can FAIL while its job stays green.

        [#773 adversarial review, BLOCKING] The first cut of this check scanned the raw LINES
        BEFORE the heredoc-open. `continue-on-error: true` placed AFTER `run:` is equally valid
        YAML and was not in that range, so the mutant survived with the whole suite green and
        `rc = 0` — a guard that claimed a ban it did not enforce. That is precisely why the
        `>>> ... <<<` sentinels were deleted from this same change, so it is fixed the same way
        rather than excused: walk the PARSED step MAPPING, where key order cannot hide anything.

        Three distinct swallows, because they are independent:
          1. `continue-on-error` (truthy) or `if:` on the STEP or its JOB — the step's failure,
             or the step itself, disappears.
          2. `set -euo pipefail` missing from the step's `run:` — a shell script's exit status is
             its LAST command, so without `-e` a failing python is masked by anything after it.
          3. anything after the heredoc terminator — even WITH `-e`, a trailing successful
             command is the step's exit status if the heredoc is not last.
        """
        import yaml  # lazy: same shape as dispatch-secrets-guard's parsed step-level ban
        with open(path, encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        found = []
        for job_name, job in (document.get("jobs") or {}).items():
            for step in (job or {}).get("steps") or []:
                if isinstance(step, dict) and step.get("id") == step_id:
                    found.append((job_name, job, step))
        if len(found) != 1:
            raise AssertionError(
                f"expected exactly one step `id: {step_id}` in the parsed workflow, "
                f"found {len(found)} — refusing")
        job_name, job, step = found[0]
        for scope, mapping in (("step", step), (f"job `{job_name}`", job)):
            if mapping.get("continue-on-error"):
                raise AssertionError(
                    f"{scope} owning `id: {step_id}` carries a truthy `continue-on-error` — it "
                    "could fail while the job stays green, making every assertion over its "
                    "output vacuous. Refusing.")
            if "if" in mapping and not _is_modelled_tick_floor_gate(scope, mapping, document):
                raise AssertionError(
                    f"{scope} owning `id: {step_id}` carries an `if:` condition — this block is "
                    "EXECUTED by this self-test from its source text, so a conditional would "
                    "pass every assertion while never running. Refusing.")
        run = step.get("run")
        if not isinstance(run, str):
            raise AssertionError(f"step `id: {step_id}` has no `run:` script — refusing")
        commands = [line for line in run.split("\n")
                    if line.strip() and not line.lstrip().startswith("#")]
        if not any(line.strip() == "set -euo pipefail" for line in commands):
            raise AssertionError(
                f"step `id: {step_id}`'s `run:` does not `set -euo pipefail` — a shell script "
                "exits with its LAST command's status, so the planner could raise and the step "
                "still succeed. Refusing.")
        # `|| true` anywhere in the script, INCLUDING across a backslash continuation (a sibling
        # seam check was found to miss exactly that), and any command after the heredoc closes.
        flattened = run.replace("\\\n", " ")
        if "|| true" in "\n".join(line for line in flattened.split("\n")
                                  if not line.lstrip().startswith("#")):
            raise AssertionError(
                f"step `id: {step_id}` neutralises a command with `|| true` — refusing")
        terminators = [i for i, line in enumerate(commands) if line.strip() == "PY"]
        if not terminators:
            raise AssertionError(f"step `id: {step_id}`'s heredoc is unterminated — refusing")
        trailing = commands[terminators[-1] + 1:]
        if trailing:
            raise AssertionError(
                f"step `id: {step_id}` runs {len(trailing)} command(s) AFTER its heredoc "
                f"({trailing[0].strip()!r}) — that command's exit status becomes the step's, so a "
                "failing planner would be swallowed. Refusing.")

    def _workflow_heredoc(path, step_id):
        """The dedented python heredoc of the ONE workflow step whose `id:` is `step_id`.

        Fail-closed in the same way `_workflow_block` is: anything it cannot resolve uniquely
        raises, because an assertion that cannot find its target must never pass vacuously. The
        `if: false` refusals above already cover a disabled step/job, and they read the same file.
        """
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
        opens = [i for i, line in enumerate(block) if line.rstrip().endswith("<<'PY'")]
        if len(opens) != 1:
            raise AssertionError(
                f"step `id: {step_id}` must run exactly one `<<'PY'` heredoc, found {len(opens)}")
        body = block[opens[0] + 1:]
        closes = [i for i, line in enumerate(body) if line.strip() == "PY"]
        if not closes:
            raise AssertionError(f"step `id: {step_id}`'s heredoc is unterminated — refusing")
        body = body[:closes[0]]
        _refuse_exit_zero_swallow(path, step_id)
        pad = min(len(line) - len(line.lstrip()) for line in body if line.strip())
        source = "\n".join(line[pad:] if line.strip() else "" for line in body)
        compile(source, f"<{step_id}>", "exec")
        return source

    _readiness_source = _workflow_heredoc(
        os.path.join(_root, ".github", "workflows", "dispatch.yml"), "readiness")

    # A PR-AWARE planner, written to sparq's contract: an OPEN PR row reserves the `area:` keys it
    # declares (and NOTHING when it declares none — the occupancy-side rule, see the GLOBAL
    # decision pinned below) and is never a dispatch candidate; an in-flight issue reserves the
    # same way. Deliberately a separate implementation rather than an import: it is the CONTRACT
    # `dispatch.yml` depends on, and a copy of this repo's engine could not express it.
    _PR_AWARE_PLANNER = '''
GLOBAL = "__global__"
IN_FLIGHT = {"status:in-progress", "status:in-progress-review"}
PARKED = {"needs:user", "review:needs-user", "status:blocked"}


def labels_of(issue):
    return {lb["name"] if isinstance(lb, dict) else lb for lb in issue.get("labels", [])}


def declared(labels):
    return {lb[5:] for lb in labels if lb.startswith("area:")}


def packages_of(labels):
    return declared(labels) or {GLOBAL}


def roleless_ready(issues):
    return sorted(it.get("number") for it in issues
                  if "pull_request" not in it and "status:ready" in labels_of(it)
                  and not any(lb.startswith("role:") for lb in labels_of(it)))


def compute_ready(issues, in_progress_packages=None):
    taken = set(in_progress_packages or ())
    for it in issues:
        L = labels_of(it)
        if L & PARKED:
            continue
        if "pull_request" in it or (L & IN_FLIGHT):
            taken |= declared(L)          # OCCUPANCY: declared areas only, no global fallback
    ready = []
    cands = [it for it in issues if "pull_request" not in it
             and "status:ready" in labels_of(it)
             and not (labels_of(it) & IN_FLIGHT)
             and not (labels_of(it) & PARKED)
             and any(lb.startswith("role:") for lb in labels_of(it))
             and int(it.get("open_blockers", 0)) == 0]
    for it in sorted(cands, key=lambda i: i.get("number")):
        pkgs = packages_of(labels_of(it))
        if GLOBAL in taken or (pkgs & taken) or (GLOBAL in pkgs and taken):
            continue
        taken |= pkgs
        ready.append(it)
    return ready


def plan_dispatch(ready_issues, routing_doc):
    rows = []
    for it in ready_issues:
        pkgs = packages_of(labels_of(it))
        rows.append({"number": it["number"], "priority": 1,
                     "package": next(iter(pkgs)) if len(pkgs) == 1 else GLOBAL,
                     "role": "impl", "agent": "a", "model_chain": ["m"], "escalate": False})
    return rows


def _routing_doc():
    return {}
'''

    def _run_readiness(rows_by_target, planners):
        """EXECUTE the real readiness step over a synthetic snapshot; return (plan, printed).

        `rows_by_target[i]` is the `/issues?state=open` listing for target i (PR rows included,
        exactly as GitHub returns them). `planners[i]` is either the PR-aware source above or
        None, meaning "use THIS repository's own scripts/ unmodified".
        """
        import json as _json
        import shutil
        import tempfile
        workdir = tempfile.mkdtemp(prefix="readiness-768-")
        try:
            root = os.path.join(workdir, "targets")
            os.makedirs(root)
            names = []
            for index, source in enumerate(planners):
                names.append(f"o/t{index}")
                target = os.path.join(root, str(index))
                if source is None:
                    shutil.copytree(os.path.join(_root, "scripts"),
                                    os.path.join(target, "scripts"))
                    shutil.copytree(os.path.join(_root, "orchestration"),
                                    os.path.join(target, "orchestration"),
                                    ignore=shutil.ignore_patterns("provenance", "review-verdicts"))
                else:
                    os.makedirs(os.path.join(target, "scripts"))
                    with open(os.path.join(target, "scripts", "dispatch-plan.py"), "w",
                              encoding="utf-8") as handle:
                        handle.write(source)
            # `git rev-parse HEAD` must return a 40-hex sha; a stub on PATH keeps the fixture
            # free of a real repository (and of any git identity configuration).
            bindir = os.path.join(workdir, "bin")
            os.makedirs(bindir)
            with open(os.path.join(bindir, "git"), "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\necho 00112233445566778899aabbccddeeff00112233\n")
            os.chmod(os.path.join(bindir, "git"), 0o755)
            repos_path = os.path.join(root, "repos.txt")
            with open(repos_path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(names) + "\n")
            for index, rows in enumerate(rows_by_target):
                pulls = [{"number": r["number"], "state": "open", "body": r.get("body", ""),
                          "author_association": "OWNER",
                          "head": {"ref": "sparq-agent/x", "sha": "0" * 40,
                                   "repo": {"full_name": names[index]}},
                          "user": {"login": "u", "type": "User"},
                          "labels": r.get("labels", [])}
                         for r in rows if "pull_request" in r]
                for kind, items in (("issues", rows), ("pulls", pulls)):
                    with open(os.path.join(workdir, f"raw-{kind}-{index}.json"), "w",
                              encoding="utf-8") as handle:
                        _json.dump({"complete": True, "items": items}, handle)
            with open(os.path.join(workdir, "trusted-bots.json"), "w", encoding="utf-8") as handle:
                _json.dump({name: [] for name in names}, handle)
            # [issue #688] The readiness step reads the per-target frontier width from the same
            # registry-code extraction step that writes `trusted-bots.json`, and that step does not
            # run here. Staged EMPTY on purpose rather than with a width fixture: the consumer is
            # `frontier_width.get(repo, 1)`, so an empty map is exactly width 1 per target — the
            # pre-#688 behaviour these readiness assertions (#768 / #122) were written against.
            # A non-empty fixture would silently change WHICH frontier they exercise, i.e. leave
            # them green while testing something else. Width itself is covered by the extraction
            # step's own `width-validate` block, which this suite executes separately.
            with open(os.path.join(workdir, "frontier-width.json"), "w", encoding="utf-8") as handle:
                _json.dump({}, handle)
            saved = (sys.argv[:], os.environ.get("TARGET_ROOT"), os.environ.get("PATH"))
            os.environ["TARGET_ROOT"] = root
            os.environ["PATH"] = bindir + os.pathsep + (saved[2] or "")
            sys.argv = ["-", repos_path, workdir]
            try:
                printed = _captured(
                    lambda: exec(_readiness_source,                     # noqa: S102 — the step
                                 {"__name__": "__main__"}))
            finally:
                sys.argv = saved[0]
                os.environ["PATH"] = saved[2] or ""
                if saved[1] is None:
                    os.environ.pop("TARGET_ROOT", None)
                else:
                    os.environ["TARGET_ROOT"] = saved[1]
            with open(os.path.join(workdir, "issue-plan.json"), encoding="utf-8") as handle:
                return _json.load(handle), printed
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def _issue(number, labels, pr=False, body=""):
        row = {"number": number, "body": body, "state": "open",
               "author_association": "OWNER", "user": {"login": "u", "type": "User"},
               "issue_dependencies_summary": {"blocked_by": 0, "blocking": 0,
                                              "total_blocked_by": 0, "total_blocking": 0},
               "labels": [{"name": name} for name in labels]}
        if pr:
            row["pull_request"] = {"url": "u"}
            row.pop("issue_dependencies_summary")
        return row

    def _planned(plan, index=0):
        return sorted(item["number"] for item in plan["repositories"][index]["items"])

    _READY = ["status:ready", "role:impl", "priority:P1"]

    # (1) THE REGRESSION. An open PR holds `area:usage`; a ready issue wants it. PLAN must NOT
    # offer that issue — CLAIM would drop it, AFTER the frontier committed, with no backfill.
    # The sibling on the free `area:docs` must still be offered, so the assertion cannot be
    # satisfied by an engine that simply stopped emitting anything.
    _rows = [_issue(500, ["area:usage"], pr=True),
             _issue(501, _READY + ["area:usage"]),
             _issue(502, _READY + ["area:docs"])]
    _plan, _out = _run_readiness([_rows], [_PR_AWARE_PLANNER])
    chk("[#768] a row whose area an open PR HOLDS is not offered; its free sibling still is",
        _planned(_plan), [502])
    chk("[#768] ...and PLAN says how many PR rows entered its occupancy",
        ("PLAN occupancy carries 1 open pull-request row(s)" in _out,
         "NOT pull-request-aware" in _out),
        (True, False))

    # (2) MONOTONICITY, by execution: the SAME board with the PR removed must offer BOTH rows.
    # Widening occupancy can only ADD holds, so #502 can never be lost by adding the PR half —
    # under-serialisation is the corrupting direction and this pins the sign of the change.
    _plan_free, _ = _run_readiness([[r for r in _rows if "pull_request" not in r]],
                                   [_PR_AWARE_PLANNER])
    chk("[#768] monotonicity: removing the PR row can only ADD offers, never remove one",
        (_planned(_plan_free), set(_planned(_plan)) <= set(_planned(_plan_free))),
        ([501, 502], True))

    # (3) THE PARKED PR. A parked PR reserves nothing (`occupies_area`), so its area is offered
    # again. Without this the fix would be a one-way ratchet that never releases a crate.
    _plan_parked, _ = _run_readiness(
        [[_issue(500, ["area:usage", "review:needs-user"], pr=True),
          _issue(501, _READY + ["area:usage"])]], [_PR_AWARE_PLANNER])
    chk("[#768] a PARKED PR reserves nothing, so its area is offered again",
        _planned(_plan_parked), [501])

    # (4) THE GLOBAL-FALLBACK DECISION, PINNED. CLAIM does `areas |= issue_areas or
    # {GLOBAL_PACKAGE}`; this side deliberately does NOT mirror it on the occupancy input.
    # MEASURED on the live sparq snapshot (2026-07-27, 1473 issues / 119 PRs, list counts ==
    # search total_count): 14 of 119 open PRs declare no `area:`, and making each seize
    # `__global__` takes PLAN's frontier from 3 ready + 5 deferred rows to 0 + 0 — the
    # whole-fleet seizure `_reserving_packages` exists to prevent. An area-less PR must
    # therefore NOT suppress an unrelated ready issue. If the two sides are ever unified,
    # CLAIM is the side that moves.
    _plan_noarea, _ = _run_readiness(
        [[_issue(500, [], pr=True), _issue(501, _READY + ["area:usage"])]], [_PR_AWARE_PLANNER])
    chk("[#768] an area-less open PR reserves NOTHING — CLAIM's `or {GLOBAL}` is NOT adopted",
        _planned(_plan_noarea), [501])

    # (5) THE INTERLOCK, against THIS repository's own planner, unmodified. `ready_candidates`
    # here has no `pull_request` guard, so a PR row carrying the readiness labels would be
    # DISPATCHED as though it were an issue — an impl worker launched against a pull-request
    # number. The probe must refuse it, say why, and leave today's behaviour exactly in place.
    _own_rows = [_issue(500, _READY + ["area:usage"], pr=True),
                 _issue(502, _READY + ["area:docs"])]
    _plan_own, _out_own = _run_readiness([_own_rows], [None])
    chk("[#768] this repo's OWN planner is refused PR rows — and never plans one as an issue",
        (500 in _planned(_plan_own), _planned(_plan_own)), (False, [502]))
    chk("[#768] ...and the refusal is LOUD, naming the reason and the unreserved count",
        ("::warning::" in _out_own, "NOT pull-request-aware" in _out_own,
         "DISPATCHES a pull-request row" in _out_own,
         "1 open PR row(s) were NOT reserved" in _out_own),
        (True, True, True, True))

    # (6) THE PROBE'S SECOND OBLIGATION, on its own. Mutation found this hole: dropping the
    # EFFECT check left every other assertion green, because the only non-PR-aware planner in
    # this suite (this repo's own) fails the SAFETY check FIRST, so EFFECT never decided
    # anything. A planner that is SAFE — it skips PR rows as candidates — but silently ignores
    # them as occupants is the case that matters: it makes the whole change an expensive no-op,
    # and passing it PR rows would let PLAN offer a row an open PR holds while reporting success.
    _INERT_PLANNER = _PR_AWARE_PLANNER.replace(
        'if "pull_request" in it or (L & IN_FLIGHT):', "if L & IN_FLIGHT:")
    _plan_inert, _out_inert = _run_readiness(
        [[_issue(500, ["area:usage"], pr=True), _issue(501, _READY + ["area:usage"])]],
        [_INERT_PLANNER])
    chk("[#768] a planner that IGNORES PR occupancy is refused too, naming that reason",
        ("does not RESERVE a pull request's declared area" in _out_inert,
         "NOT pull-request-aware" in _out_inert,
         "PLAN occupancy carries" in _out_inert),
        (True, True, False))

    # (7) THE PROBE'S FAIL-CLOSED PATH. [#773 adversarial review, BLOCKING] The code claims
    # "a probe that raises is a planner we cannot characterise, so it gets no PR rows", and
    # flipping that handler's `return False` to `return True` left the ENTIRE suite green — a
    # fail-OPEN predicate on the one interlock whose whole job is preventing the outage. A
    # planner whose `compute_ready` raises is exactly the hostile/incompatible target the probe
    # exists for, and it must be refused, not admitted on the strength of an exception.
    _RAISING_PLANNER = _PR_AWARE_PLANNER.replace(
        "def compute_ready(issues, in_progress_packages=None):",
        "def compute_ready(issues, in_progress_packages=None):\n"
        "    if any('pull_request' in it for it in issues):\n"
        "        raise RuntimeError('planner cannot handle PR rows')")
    # Caught rather than allowed to propagate ON PURPOSE. When the probe fails open, the planner's
    # exception escapes the readiness step and kills the whole sweep for EVERY target — a real
    # traceback, but a crash-kill reads as "the harness broke", and the fact under test is that
    # PLAN must survive this planner and refuse it. Catching turns it into a NAMED red row.
    try:
        _plan_raise, _out_raise = _run_readiness(
            [[_issue(500, ["area:usage"], pr=True), _issue(501, _READY + ["area:usage"])]],
            [_RAISING_PLANNER])
        _raise_outcome = (
            "probe raised RuntimeError" in _out_raise, "NOT pull-request-aware" in _out_raise,
            "PLAN occupancy carries" in _out_raise, _planned(_plan_raise))
    except Exception as exc:                                       # noqa: BLE001
        _raise_outcome = f"the sweep DIED for every target: {type(exc).__name__}: {exc}"
    chk("[#768] a planner whose compute_ready RAISES is refused — the probe fails CLOSED",
        _raise_outcome, (True, True, False, [501]))

    # (8) THE DEFERRED LANE. It used to be handed `deferred_input` ALONE — a list `retry_gated`
    # filters to `status:deferred` rows, so it contained no occupant of any kind and reserved
    # ZERO keys (MEASURED on the live snapshot: 0 keys held, against 48 in the ready lane). A
    # deferred retry therefore launched onto a crate an in-flight issue owned, which CLAIM's
    # busy union CANNOT catch — it enumerates `sparq-agent/*` PR heads, not in-progress issues.
    # MEASURED: 3 such rows on the live board (#2767 `upstream`, #2951 `workspace`, #4423
    # `sparq-zk-compose`), each with no PR holder at all.
    _def = ["status:deferred", "role:impl", "priority:P1"]
    _plan_def, _ = _run_readiness(
        [[_issue(600, ["area:usage"], pr=True),
          _issue(601, ["status:in-progress", "role:impl", "priority:P1", "area:docs"]),
          _issue(602, _def + ["area:usage"]),
          _issue(603, _def + ["area:docs"]),
          _issue(604, _def + ["area:free"])]], [_PR_AWARE_PLANNER])
    chk("[#768] the DEFERRED lane reserves the PR half and the in-flight issue half too",
        _planned(_plan_def), [604])

    # ---- [OPUS-5 issue #688] THE FRONTIER-WIDTH CALL SITE, EXECUTED ------------------------------
    # This is the YAML seam, and it is where vacuity lives: the width branch and the TypeError
    # fallback are workflow python that no unit test would otherwise reach. Deleting `package_width`
    # from the call, inverting `if width > 1`, or dropping the except-TypeError arm each makes a
    # NAMED row below go red — none of them would disturb a substring assertion.
    width_block = _workflow_block(
        os.path.join(_root, ".github", "workflows", "dispatch.yml"), "readiness", "frontier-width")

    class _WidthPlanner:
        """Stub target planner. `supports_width=False` models a target whose readiness engine
        PREDATES the parameter — the real cross-repo hazard, since each target carries its own copy
        and passing an unsupported kwarg would TypeError out of that target's whole dispatch."""

        def __init__(self, supports_width=True):
            self.calls = []
            self._supports = supports_width

        def compute_ready(self, issues, package_width=None):
            if package_width is not None and not self._supports:
                raise TypeError("compute_ready() got an unexpected keyword argument 'package_width'")
            self.calls.append(package_width)
            return list(issues)

    def _run_width(width, supports_width=True):
        planner = _WidthPlanner(supports_width)
        namespace = {"dispatch": planner, "readiness_input": [{"number": 1}],
                     "ready_input": [{"number": 1}], "repo": "o/t",
                     "frontier_width": {"o/t": width}}
        text = _captured(lambda: exec(width_block, namespace))  # noqa: S102 — workflow block
        return text, planner.calls, namespace.get("ready")

    _text, _calls, _frontier = _run_width(3)
    chk("[#688] a widened target PASSES package_width through to the readiness engine",
        (_calls, _frontier, _text.strip()), ([3], [{"number": 1}], ""))
    _text, _calls, _frontier = _run_width(1)
    chk("[#688] width 1 takes the ORIGINAL call path (no kwarg at all — byte-for-byte unchanged)",
        (_calls, _text.strip()), ([None], ""))
    # The cross-repo compatibility hazard: an older target engine must DEGRADE to the narrow
    # frontier with a warning, never take that target's dispatch down.
    _text, _calls, _frontier = _run_width(3, supports_width=False)
    chk("[#688] an older target engine falls back to the narrow frontier and says so LOUDLY",
        ("::warning::o/t: readiness engine does not support package_width" in _text,
         _calls, _frontier),
        (True, [None], [{"number": 1}]))
    # A target absent from the width map is width 1 — the safe default, never an unbounded frontier.
    planner = _WidthPlanner()
    _captured(lambda: exec(width_block, {"dispatch": planner, "ready_input": [], "repo": "o/absent",
                                         "frontier_width": {}}))  # noqa: S102
    chk("[#688] a target with no policy width defaults to the one-per-package frontier",
        planner.calls, [None])

    # The REGISTRY-CODE width validation that runs BEFORE any target code sees the value. Review
    # flagged it as defence-in-depth that survived being replaced with `if False:` — so execute it.
    validate_block = _workflow_block(
        os.path.join(_root, ".github", "workflows", "dispatch.yml"), "policy-extract",
        "width-validate")

    def _validate(row):
        ns = {"row": row, "repo": "o/t", "MAX_WIDTH": 8, "widths": {}}
        try:
            exec(validate_block, ns)  # noqa: S102 — workflow block
        except SystemExit as exc:
            return f"REFUSED: {exc}"
        return ns["widths"].get("o/t")

    chk("[#688] the workflow width validation ACCEPTS the in-range values",
        [_validate(r) for r in ({}, {"package_width": 1}, {"package_width": 8}, "not-a-table")],
        [1, 1, 8, 1])
    chk("[#688] ...and REFUSES every out-of-range or wrong-typed value (bounded BOTH sides)",
        [str(_validate({"package_width": bad})).startswith("REFUSED")
         for bad in (0, -1, 9, 1000, "2", True, 1.5, None)],
        [True] * 8)

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
