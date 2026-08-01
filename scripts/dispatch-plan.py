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
# [OPUS-5] The partition census in dispatch.yml's readiness step reads the planner's OWN candidate
# set as the frontier's denominator. sparq's copy of this file already re-exports it (its line 51);
# this copy had drifted, so the shared step would have reported the registry target as
# UNMEASURABLE while measuring sparq — the "kept behaviourally identical" promise in this file's
# header is exactly what stops one target silently losing an instrument the other has.
ready_candidates = _ready.ready_candidates
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
    """The conflict partition KEY a plan row reserves (registry issue #112). A partition key names
    a SET of areas: a one-area issue reserves that area, a MULTI-area issue reserves EXACTLY its
    own areas as the canonical sorted `,`-joined key, and a NO-area issue reserves the serializing
    global partition because its footprint is unknown. The old `sorted(packages_of(labels))[0]`
    kept only the alphabetically-first area, silently dropping every secondary area — an A+B issue
    could dispatch while B was busy — and its replacement over-corrected the other way, sending
    every multi-area row to `__global__` so that "touches A and B" meant "touches everything".
    Two rows now conflict iff their area sets INTERSECT (lease_schema.packages_conflict), which is
    narrower than `__global__` exactly where the LABELS prove the footprint and never elsewhere:
    `packages_of` still maps the no-area case to `{GLOBAL}`, so a zero-label row is unchanged.

    Byte-identical to `lease_schema.plan_package` over the same area set, and dispatch-claim's
    `_plan_package_agreement()` self-test EXECUTES both to prove it — this copy exists only
    because dispatch-plan.py ships inside the target repos, which have no lease_schema.py."""
    pkgs = packages_of(labels)
    if pkgs == {GLOBAL}:
        return GLOBAL
    return ",".join(sorted(pkgs))


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
    #
    # [#1397] The PERSONA, though, comes from the `role = "impl"` row: the override declares
    # `agent_from_role = true`, so a trust-surface IMPLEMENTATION row is planned with the
    # implementer's brief instead of the verdict-only reviewer's (which told the model not to write
    # code). The chain and `escalate` — the soundness posture CLAIM compares for exact equality —
    # are the override's, unchanged.
    sec = compute_ready([iss(2, R + ["priority:P0", "role:impl", "area:worker"])])
    row = plan_dispatch(sec, doc)[0]
    chk("worker -> opus5 only", row["model_chain"], ["opus5"])
    chk("worker -> implementer persona on the soundness chain/escalate",
        (row["agent"], row["escalate"]), ("registry-impl", True))
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
    # [OPUS-5] PARTITION CENSUS. The conflict partition is the dispatcher's LARGEST refusal and it
    # emitted no census row at all: MEASURED 2026-07-28 on live sparq, 452 drainable candidates
    # collapsed to a frontier of 7, and the per-lane summary's `planned` is already the
    # POST-frontier number, so 445 refusals/tick were invisible and the capacity question kept
    # being answered with account arithmetic. Like every other block in that step this one lives
    # in workflow python — the seam where every uncaught mutant in this repo has lived — so it is
    # EXTRACTED and EXECUTED here, not pattern-matched. Each row below dies on a one-token flip:
    # dropping the selected-row skip, inverting the `is None` compatibility branch, guarding the
    # print behind a truthy `_contended`, reversing the rank order, removing the `[:8]` bound, or
    # dropping the `log=` stub.
    # ------------------------------------------------------------------------------------------
    partition_block = _workflow_block(
        os.path.join(_root, ".github", "workflows", "dispatch.yml"), "readiness",
        "partition-census")

    class _StubCandidatePlanner:
        """Stands in for the target's `dispatch` module. `enumerate_candidates=False` models a
        planner that PREDATES ready_candidates (the compatibility branch)."""

        def __init__(self, cands, enumerate_candidates=True):
            self.seen = []
            self.log_supplied = None
            self._cands = list(cands)
            if enumerate_candidates:
                self.ready_candidates = self._enumerate

        def _enumerate(self, issues, log=None):
            self.seen.append(list(issues))
            self.log_supplied = log is not None
            return list(self._cands)

    def _cand(number, pkgs):
        """One `ready_candidates` row in the engine's shape: (priority, number, item, packages)."""
        return (1, number, {"number": number}, set(pkgs))

    def _run_partition_block(cands, ready_rows, enumerate_candidates=True):
        planner = _StubCandidatePlanner(cands, enumerate_candidates)
        namespace = {"dispatch": planner, "ready_input": [{"number": 1}],
                     "ready": [{"number": n} for n in ready_rows], "repo": "o/t"}
        text = _captured(lambda: exec(partition_block, namespace))  # noqa: S102 — workflow block
        return text.strip(), planner

    # #1/#4 were SELECTED, so only #2/#3 (package a) and #5 (package b) are still contending.
    # Counting the selected rows too would print `a=3, b=2`; that is the mutant this row kills.
    _five = [_cand(1, "a"), _cand(2, "a"), _cand(3, "a"), _cand(4, "b"), _cand(5, "b")]
    _busy, _planner = _run_partition_block(_five, [1, 4])
    chk("[OPUS-5] the EXECUTED workflow block names the frontier's denominators and contention",
        _busy,
        "partition census o/t: candidates=5 frontier=2 partition-deferred=3 "
        "top-contended: a=2, b=1")
    chk("[OPUS-5] ...and stubs `log` so the re-walk does not double the readiness attributions",
        (_planner.log_supplied, _planner.seen), (True, [[{"number": 1}]]))
    # The brief's standing rule: a cap must name itself EVERY tick it holds, including a tick on
    # which it refused nothing. Guarding the print behind `if _contended:` is the mutant here.
    _quiet, _ = _run_partition_block([_cand(1, "a"), _cand(2, "b")], [1, 2])
    chk("[OPUS-5] ...and still prints on a tick that deferred NOTHING (zero included)",
        _quiet,
        "partition census o/t: candidates=2 frontier=2 partition-deferred=0 "
        "top-contended: none")
    _degraded, _planner = _run_partition_block([_cand(1, "a")], [], False)
    chk("[OPUS-5] a planner without ready_candidates() says so and fabricates no census",
        ("partition attrition is UNMEASURABLE" in _degraded,
         "partition census" in _degraded, _planner.seen), (True, False, []))
    # Rank by COUNT descending, then key — and cap at 8. An ascending sort or a dropped bound
    # both change this line; `z` (the single smallest) is the row that must fall off the end.
    _many = [_cand(100 + i, chr(ord("a") + i)) for i in range(8) for _ in range(8 - i)]
    _many += [_cand(999, "z")]
    _ranked_text, _ = _run_partition_block(_many, [])
    chk("[OPUS-5] contention is ranked by count (desc) and bounded to the top 8",
        (_ranked_text.split("top-contended: ")[1], "z=1" in _ranked_text),
        ("a=8, b=7, c=6, d=5, e=4, f=3, g=2, h=1", False))

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

    def _without_line(pattern):
        """The workflow with the ONE line matching `pattern` DELETED. Insertion-only probes can
        express "someone added a neutraliser" but not "someone removed the wiring", which is the
        mutation the #1207 seam is most exposed to — a deleted env line leaves every other
        assertion in this file green."""
        with open(_dispatch_yml, encoding="utf-8") as handle:
            lines = handle.read().split("\n")
        hits = [i for i, line in enumerate(lines) if line.rstrip() == pattern]
        if len(hits) != 1:
            raise AssertionError(f"expected one {pattern!r} line, found {len(hits)}")
        del lines[hits[0]]
        path = os.path.join(_root, ".github", "workflows", ".dispatch-seam-probe.yml")
        with open(path, "w", encoding="utf-8") as out:
            out.write("\n".join(lines))
        return path

    def _replacing_line(pattern, replacement, occurrence=None):
        """The workflow with a line matching `pattern` REPLACED. `occurrence` selects which hit
        when the line legitimately appears more than once (the cached `path:` appears on both the
        restore and the save); None demands exactly one."""
        with open(_dispatch_yml, encoding="utf-8") as handle:
            lines = handle.read().split("\n")
        hits = [i for i, line in enumerate(lines) if line.rstrip() == pattern]
        if occurrence is None:
            if len(hits) != 1:
                raise AssertionError(f"expected one {pattern!r} line, found {len(hits)}")
            target = hits[0]
        else:
            if len(hits) <= occurrence:
                raise AssertionError(
                    f"expected >{occurrence} {pattern!r} lines, found {len(hits)}")
            target = hits[occurrence]
        lines[target] = replacement
        path = os.path.join(_root, ".github", "workflows", ".dispatch-seam-probe.yml")
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

    def _refuse_producer_swallow(path, step_id, invocation):
        """Refuse any way the PRODUCER step can stop producing while the run stays green.

        [sparq#4819 round 2, BLOCKING] `_refuse_exit_zero_swallow` pins the CONSUMER (`readiness`)
        seam and cannot be reused here: it requires a `PY` heredoc terminator, and this step runs a
        checked-in script. So the producer seam had NO refusal at all, and the round-1 review
        measured three survivors on it — `if: false` on the step, `continue-on-error: true` on the
        step, `|| true` on the invocation. Every one of them degrades to the fail-safe
        every-PR-reserves path WITH a `::warning::`, so this is throughput loss with a detector
        rather than a correctness hole; it is pinned anyway, because "the answer is computed and
        discarded" with a warning nobody reads is precisely how round 1 shipped as a no-op.

        Same three independent swallows as the consumer's, plus one this step has and that one
        does not: the `plan-snapshot.py` INVOCATION must be the script's last command, because a
        shell exits with its last command's status.
        """
        import yaml  # lazy, same as _refuse_exit_zero_swallow
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
                    f"{scope} owning `id: {step_id}` carries a truthy `continue-on-error` — the "
                    "producer could fail while the job stays green, and PLAN would silently plan "
                    "with no inertness attestation. Refusing.")
            if "if" in mapping and not _is_modelled_tick_floor_gate(scope, mapping, document):
                raise AssertionError(
                    f"{scope} owning `id: {step_id}` carries an `if:` condition — the producer "
                    "would never run while every assertion over its output stayed green. "
                    "Refusing.")
        run = step.get("run")
        if not isinstance(run, str):
            raise AssertionError(f"step `id: {step_id}` has no `run:` script — refusing")
        flattened = run.replace("\\\n", " ")
        commands = [line for line in flattened.split("\n")
                    if line.strip() and not line.lstrip().startswith("#")]
        if not any(line.strip() == "set -euo pipefail" for line in commands):
            raise AssertionError(
                f"step `id: {step_id}`'s `run:` does not `set -euo pipefail` — refusing")
        if "|| true" in "\n".join(commands):
            raise AssertionError(
                f"step `id: {step_id}` neutralises a command with `|| true` — the snapshot would "
                "produce nothing and the step would still succeed. Refusing.")
        last = commands[-1] if commands else "<none>"
        # `--self-test` is excluded deliberately: it also matches `invocation`, so without this a
        # reordering that left the SELF-TEST last — producing no snapshot at all — would pass.
        if invocation not in last or "--self-test" in last:
            raise AssertionError(
                f"step `id: {step_id}`'s LAST command is {last.strip()!r}, not the `{invocation}` "
                "snapshot invocation — a shell exits with its last command's status, so a failing "
                "producer would be swallowed. Refusing.")
        return step

    def _refuse_unwired_etag_store(path):
        """THE #1207 CONDITIONAL-READ SEAM: `snapshot` -> `etag-save`, with the publish strictly
        BEFORE the first step that executes target code, and NO extracting action anywhere in the
        job.

        Every fact below is a SILENT one. The mechanism has no output of its own that anything
        else asserts on, so each of these mutations leaves a dispatcher that still plans, still
        dispatches, still goes green — and quietly pays full price for every read again, or (the
        ordering and transport rules) reopens the write primitive the adversarial review of PR
        #1218 found:

          * the `SNAPSHOT_ETAG_STORE` env line deleted    -> unconditional sweep, no signal
          * the publish step deleted or reordered         -> cold store every tick, no signal
          * the published `path:` and the store path diverge -> publishes nothing, forever
          * ANY cache/artifact RESTORE action in this job -> `@actions/toolkit` extracts with
            `tar -xf ... -P` (--absolute-names), i.e. an ARBITRARY FILE WRITE, in a job that
            subsequently holds `github.token`. This is the finding that failed review round 1
            and it is refused STRUCTURALLY here, not by ordering — the runner populates
            `_actions/` before any step runs, so no placement of a restore is safe.

        Fail-closed like its neighbours: anything it cannot resolve raises rather than passes.
        """
        import yaml  # lazy, same as _refuse_exit_zero_swallow
        # The artifact name is read from the PRODUCT, never restated here: a literal copy is a
        # second place for the workflow and the reader to drift apart silently.
        _STORE_ARTIFACT = _load("registry_plan_snapshot_seam", "plan-snapshot.py").STORE_ARTIFACT
        with open(path, encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        steps = ((document.get("jobs") or {}).get("plan") or {}).get("steps")
        if not isinstance(steps, list) or not steps:
            raise AssertionError("dispatch.yml `plan` job has no steps — refusing")
        index = {}
        for position, step in enumerate(steps):
            if isinstance(step, dict) and step.get("id"):
                index.setdefault(step["id"], position)
        for required in ("snapshot", "etag-save"):
            if required not in index:
                raise AssertionError(
                    f"dispatch.yml `plan` has no step `id: {required}` — the #1207 conditional-"
                    "read seam is not wired, so every check-runs read is billable again and "
                    "nothing reports it. Refusing.")
        if not index["snapshot"] < index["etag-save"]:
            raise AssertionError(
                "the #1207 seam is out of order: the ETag store must be PUBLISHED after the "
                "snapshot writes it — refusing.")
        # THE TRANSPORT RULE. No step in this job may RESTORE a cache or an artifact: those
        # actions extract a tarball with `tar -P` (--absolute-names), which is an arbitrary file
        # write landing in a job that subsequently holds `github.token`. Refused by SHAPE rather
        # than by position, because `_actions/` is populated before the first step runs and no
        # placement of a restore is safe. (Adversarial review of PR #1218.)
        for position, step in enumerate(steps):
            uses = str((step or {}).get("uses") or "") if isinstance(step, dict) else ""
            bare = uses.split("@", 1)[0]
            if bare in ("actions/cache", "actions/cache/restore", "actions/download-artifact"):
                raise AssertionError(
                    f"dispatch.yml `plan` step {position} uses `{bare}`, which EXTRACTS a "
                    "tarball with `tar -P` (--absolute-names) — an arbitrary file write in a "
                    "job that holds github.token. The store is read through the API into "
                    "memory instead; see plan-snapshot.load_store_from_artifact. Refusing.")
        # The first step that can execute anything from a target repository. The clone step is
        # that boundary (it runs the target's own `--self-test`s), and the save must precede it.
        clone = [position for position, step in enumerate(steps)
                 if isinstance(step, dict) and "git clone" in str(step.get("run") or "")]
        if not clone:
            raise AssertionError(
                "cannot locate the target-clone step in dispatch.yml `plan` — refusing to "
                "assert the #1207 store is published before target code without finding it.")
        if index["etag-save"] > min(clone):
            raise AssertionError(
                "the ETag store is published AFTER target code runs — a store written past the "
                "target-clone step is one the hostile planner half was in a position to shape. "
                "Refusing.")
        for step_id, prefix in (("etag-save", "actions/upload-artifact@"),):
            step = steps[index[step_id]]
            uses = str(step.get("uses") or "")
            if not uses.startswith(prefix):
                raise AssertionError(
                    f"step `id: {step_id}` must use `{prefix}...`, not {uses!r} — publishing the "
                    "store must be an UPLOAD, which writes nothing locally. Refusing.")
            if step.get("continue-on-error"):
                raise AssertionError(
                    f"step `id: {step_id}` carries a truthy `continue-on-error` — refusing.")
            if "if" in step:
                raise AssertionError(
                    f"step `id: {step_id}` carries an `if:` condition — the seam would go quiet "
                    "while every assertion over it stayed green. Refusing.")
        store_path = (steps[index["snapshot"]].get("env") or {}).get("SNAPSHOT_ETAG_STORE")
        if not isinstance(store_path, str) or not store_path.strip():
            raise AssertionError(
                "the `snapshot` step does not pass `SNAPSHOT_ETAG_STORE` — plan-snapshot.py "
                "defaults to NO store and sweeps unconditionally, at full price, silently. "
                "Refusing.")
        published = str((steps[index["etag-save"]].get("with") or {}).get("path") or "")
        if published != store_path:
            raise AssertionError(
                f"the snapshot writes its store to {store_path!r} but the publish step uploads "
                f"{published!r} — the store would never survive a tick while every assertion "
                "stayed green. Refusing.")
        # The artifact NAME is what the reader looks up by equality; a drift here is a
        # permanently cold store with nothing red.
        published_name = str((steps[index["etag-save"]].get("with") or {}).get("name") or "")
        if published_name != _STORE_ARTIFACT:
            raise AssertionError(
                f"the publish step uploads artifact {published_name!r}, but plan-snapshot.py "
                f"reads {_STORE_ARTIFACT!r} — refusing.")
        return steps[index["snapshot"]]

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
    # [sparq#4819 round 2] ...and the PRODUCER seam, refused the same way. Called at extraction
    # time (not inside a `chk`) so a disabled/swallowed producer aborts this self-test outright
    # rather than reporting one red row among the greens — the same posture `_workflow_heredoc`
    # takes for the consumer.
    _refuse_producer_swallow(
        os.path.join(_root, ".github", "workflows", "dispatch.yml"), "snapshot",
        "plan-snapshot.py")
    # [#1207] ...and the conditional-read seam around that same step, for the same reason: it is
    # pure throughput with no consumer that would notice its absence.
    _refuse_unwired_etag_store(os.path.join(_root, ".github", "workflows", "dispatch.yml"))

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

    # [sparq#4819] The SAME contract with the machine-park carve-out sparq's engine ships: a
    # `review:parked` PR releases its declared areas iff the row carries a positively-attested
    # `inert` bit. Deliberately a separate implementation from sparq's, for the reason the
    # PR-aware planner above is: this is the CONTRACT dispatch.yml depends on, and the interlock
    # must be tested against a written statement of it rather than against a copy of one side.
    _INERT_AWARE_PLANNER = _PR_AWARE_PLANNER.replace(
        '''        if L & PARKED:
            continue''',
        '''        if L & PARKED:
            continue
        if ("review:parked" in L and "pull_request" in it
                and it.get("inert") is True):
            continue''').replace(
        "def _routing_doc():",
        'INERT_FIELD = "inert"\nMACHINE_PARK_PR_LABEL = "review:parked"\n\n\ndef _routing_doc():')
    # ...an engine that DECLARES the contract but never consults the field. Without this the
    # `if freed != [...]` half of `inert_aware` has no coverage: deleting it would hand
    # attestations to an engine that ignores them, and PLAN would keep reserving the crates it
    # believes it released — the defect, restored, with a log line claiming otherwise.
    _INERT_DECLARING_ONLY_PLANNER = _PR_AWARE_PLANNER.replace(
        "def _routing_doc():",
        'INERT_FIELD = "inert"\nMACHINE_PARK_PR_LABEL = "review:parked"\n\n\ndef _routing_doc():')
    # ...and the FORBIDDEN engine: it releases a machine park on the LABEL ALONE. The interlock
    # must refuse to hand it attestations, or the workflow would be sanctioning exactly the
    # unconditional release sparq#4819 rules out.
    _UNCONDITIONAL_PARK_PLANNER = _PR_AWARE_PLANNER.replace(
        'PARKED = {"needs:user", "review:needs-user", "status:blocked"}',
        'PARKED = {"needs:user", "review:needs-user", "status:blocked", "review:parked"}').replace(
        "def _routing_doc():",
        'INERT_FIELD = "inert"\nMACHINE_PARK_PR_LABEL = "review:parked"\n\n\ndef _routing_doc():')

    def _run_readiness(rows_by_target, planners, attest=True, produce=None, catch=False):
        """EXECUTE the real readiness step over a synthetic snapshot; return (plan, printed).

        `rows_by_target[i]` is the `/issues?state=open` listing for target i (PR rows included,
        exactly as GitHub returns them). `planners[i]` is either the PR-aware source above or
        None, meaning "use THIS repository's own scripts/ unmodified".

        [sparq#4819] A PR fixture row carrying `"_inert": True` is attested provably-inert in the
        `raw-inertness-<i>.json` the snapshot step writes. `attest=False` omits that file entirely
        (the PRODUCER-DELETED case); a DICT is written verbatim as the document, so a malformed or
        hostile attestation can be handed to the consumer. All three are asserted below.

        [sparq#4819 round 2] `produce` replaces ALL of that with the REAL producer. Called as
        `produce(workdir, index, repo, rows)`, it is then solely responsible for writing every
        `raw-*.json` this target needs. That closes the round-1 gap where THIS HARNESS wrote
        `raw-inertness-<i>.json` itself: the producer could rename the file (and its own
        assertion) and both self-tests stayed green while production silently lost the carve-out.

        `catch=True` returns the STRING `"STEP ABORTED: <ExceptionType>"` in place of the plan
        instead of letting the exception escape. OPT-IN, and used by exactly the rows whose
        mutants kill the step outright (a Unicode key, a truncated document): without it those
        mutants surface as a bare traceback with no verdict line, and a crash is not a kill — the
        mutant has to red a row that NAMES what it broke. It is deliberately not the default,
        because swallowing an abort everywhere would let a step that dies mid-way report an empty
        plan and satisfy any assertion expecting nothing.
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
                if produce is not None:
                    # THE REAL PRODUCER writes every raw-*.json for this target, including the
                    # attestation, at whatever path IT chooses. See the R1 row below.
                    produce(workdir, index, names[index], rows)
                    continue
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
                if attest is not False:
                    path = os.path.join(workdir, f"raw-inertness-{index}.json")
                    if isinstance(attest, str):
                        # RAW BYTES, unserialised — the only way to write a document that is not
                        # valid JSON at all (truncated / empty / half-flushed).
                        with open(path, "w", encoding="utf-8") as handle:
                            handle.write(attest)
                    else:
                        document = (attest if isinstance(attest, dict) else
                                    {"complete": True,
                                     "items": {str(r["number"]): bool(r.get("_inert"))
                                               for r in rows if "pull_request" in r},
                                     "reasons": {}})
                        with open(path, "w", encoding="utf-8") as handle:
                            _json.dump(document, handle)
            with open(os.path.join(workdir, "trusted-bots.json"), "w", encoding="utf-8") as handle:
                _json.dump({name: [] for name in names}, handle)
            saved = (sys.argv[:], os.environ.get("TARGET_ROOT"), os.environ.get("PATH"))
            os.environ["TARGET_ROOT"] = root
            os.environ["PATH"] = bindir + os.pathsep + (saved[2] or "")
            sys.argv = ["-", repos_path, workdir]
            aborted = None
            try:
                printed = _captured(
                    lambda: exec(_readiness_source,                     # noqa: S102 — the step
                                 {"__name__": "__main__"}))
            except BaseException as exc:                # noqa: BLE001 — see `catch` below
                if not catch:
                    raise
                aborted, printed = f"STEP ABORTED: {type(exc).__name__}", ""
            finally:
                sys.argv = saved[0]
                os.environ["PATH"] = saved[2] or ""
                if saved[1] is None:
                    os.environ.pop("TARGET_ROOT", None)
                else:
                    os.environ["TARGET_ROOT"] = saved[1]
            if aborted is not None:
                return aborted, printed
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

    def _planned_or_abort(plan, index=0):
        """`_planned`, except a `catch=True` abort reports itself BY NAME instead of raising.

        [sparq#4819 round 2] The two rows that use this exist to prove the step SURVIVES a hostile
        document. Their mutants (`isdigit()` back for `isdecimal()`; a bare `json.loads`) kill the
        step outright, and without this the suite ends in a traceback with no verdict line — a
        crash, not a kill. Returning `"STEP ABORTED: ValueError"` makes the mutant red a NAMED row
        that says exactly what it broke."""
        return plan if isinstance(plan, str) else _planned(plan, index)

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

    # (5) THE INTERLOCK, against THIS repository's own planner, unmodified. It used to FAIL the
    # probe — `scripts/ready-issues.py` had no `pull_request` guard anywhere, so a PR row carrying
    # the readiness labels would have been DISPATCHED as though it were an issue (an impl worker
    # launched against a pull-request number) and the interlock refused it PR rows, loudly. Since
    # the engine gained both halves it PASSES, and the assertions below are the acceptance test:
    # the probe opens, and the PR's area is genuinely HELD.
    #
    # The old first assertion was `(500 in _planned, _planned) == (False, [502])`, which the
    # REFUSED and the ACCEPTED planner both satisfy — #500 is dropped as a PR row in one case and
    # as an unready row in the other, and #502 sits on a free area either way. It could not
    # witness this change in either direction, so a THIRD row is added on the PR's own area: it is
    # planned iff the PR reserved nothing, which is exactly the property under test.
    _own_rows = [_issue(500, _READY + ["area:usage"], pr=True),
                 _issue(501, _READY + ["area:usage"]),
                 _issue(502, _READY + ["area:docs"])]
    _plan_own, _out_own = _run_readiness([_own_rows], [None])
    chk("[#768] this repo's OWN planner PASSES the probe — it holds the PR's area, plans no PR",
        (500 in _planned(_plan_own), _planned(_plan_own)), (False, [502]))
    # [sparq#4819 round 2] The first element USED to be `"::warning::" in _out_own` -> False,
    # i.e. "no annotation of any kind fired". That is the blanket shape this file warns about
    # elsewhere — it is satisfied by the absence of ANY warning, including ones it does not mean —
    # and it went red the moment the planner-side inertness degradation gained the `::warning::`
    # it should always have had. It is REPLACED, not relaxed: the row now asserts the specific
    # PR-awareness warning is absent (which is what its name claims) AND that the inertness
    # warning IS present with its reason. This repository's own readiness engine has no
    # `INERT_FIELD` — it does not implement the machine-park carve-out — so the honest state for
    # it is exactly "attestation computed and discarded", loudly.
    chk("[#768] ...and the interlock OPENS for it, naming the capability and the reserved count",
        ("NOT pull-request-aware" in _out_own,
         "PLAN occupancy carries 1 open pull-request row(s)" in _out_own,
         "reserves PR areas and never dispatches a PR row" in _out_own,
         "::warning::o/t0: PLAN computed an inertness attestation" in _out_own,
         "planner declares no inertness contract" in _out_own),
        (False, True, True, True, True))

    # (5b) THE SAFETY REFUSAL, which (5) no longer exercises now that this repo's planner passes.
    # Without this the `planner DISPATCHES a pull-request row` branch of `pr_row_aware` would have
    # NO live coverage at all and could be deleted with the suite green — the probe would then
    # hand PR rows to an engine that plans them as issues, which is the outage it exists to
    # prevent. A synthetic planner with ONLY the candidate guard removed isolates that one branch
    # (the inert planner in (6) isolates the other).
    _UNGUARDED_PLANNER = _PR_AWARE_PLANNER.replace(
        '    cands = [it for it in issues if "pull_request" not in it\n',
        "    cands = [it for it in issues if True\n")
    assert _UNGUARDED_PLANNER != _PR_AWARE_PLANNER, "the unguarded-planner mutation did not apply"
    _plan_unguarded, _out_unguarded = _run_readiness(
        [[_issue(500, _READY + ["area:usage"], pr=True)]], [_UNGUARDED_PLANNER])
    chk("[#768] a planner that would PLAN a PR row is refused, and plans no PR row",
        ("DISPATCHES a pull-request row" in _out_unguarded,
         "NOT pull-request-aware" in _out_unguarded,
         "PLAN occupancy carries" in _out_unguarded,
         500 in _planned(_plan_unguarded)),
        (True, True, False, False))

    # (5c) [#786] THE PROBE'S FAIL-OPEN HOLE, pinned by the shape that exposed it. `_UNGUARDED_
    # PLANNER` above still RESERVES a PR's declared areas, so the area-declaring probe row shields
    # ITSELF: it reserves `__pr_probe__`, then its own reservation drops it from selection, and
    # `alone`/`paired` are both empty however broken the candidate guard is. Before the area-LESS
    # probe row was added, SAFETY therefore admitted that planner (MEASURED against this repo's
    # own engine with the guard deleted: alone=[], paired=[], verdict ACCEPT) — and it plans an
    # area-less PR row as an issue, which is the ONLY shape 40 of 40 open PRs here have. This row
    # asserts the refusal happens on a board with NO area-declaring row to shield the PR.
    #
    # It does NOT isolate `bare_alone` from (5b) — an earlier revision of this comment claimed
    # "deleting `bare_alone` reds it while (5b) stays green", and that is measurably wrong. Delete
    # `bare_alone` from `pr_row_aware`'s refusal condition in `dispatch.yml` and re-run: BOTH rows
    # red, (5b) with (False, False, True, False) and this one with `PLAN DIED on the admitted
    # planner: KeyError: 500`. Both refusals come from the same probe, so both stop printing at
    # once. What separates them is what the board then DOES: on (5b)'s area-declaring board the
    # admitted planner is still harmless (`500 in _planned` stays False — the PR self-shields), so
    # (5b) witnesses only that the refusal text vanished. This row is the one whose board realises
    # the outage: the admitted planner emits a plan row whose `number` is a PULL REQUEST and the
    # downstream assembly dies on it. Two rows, one probe, two different consequences.
    # Caught for the same reason case (7) catches: when SAFETY admits this planner, PLAN goes on
    # to emit a plan row whose `number` is a PR and the downstream assembly dies on it. A crash
    # reads as "the harness broke"; the fact under test is that the probe must REFUSE, so the
    # exception is turned into a NAMED red row instead of an abort that hides every later check.
    try:
        _plan_bare, _out_bare = _run_readiness(
            [[_issue(500, _READY, pr=True), _issue(501, _READY + ["area:usage"])]],
            [_UNGUARDED_PLANNER])
        _bare_outcome = ("DISPATCHES a pull-request row" in _out_bare,
                         "PLAN occupancy carries" in _out_bare, _planned(_plan_bare))
    except Exception as exc:                                       # noqa: BLE001
        _bare_outcome = f"PLAN DIED on the admitted planner: {type(exc).__name__}: {exc}"
    chk("[#786] an AREA-LESS PR row cannot shield itself — SAFETY still refuses, and plans no PR",
        _bare_outcome, (True, False, [501]))

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
    # [sparq#4819] ...and it now SAYS SO. The ready lane has printed its partition attrition every
    # tick since #708; this lane printed nothing, so "offered 1" was indistinguishable from "had 1
    # candidate" and from "is broken". Asserted on the executed step's real output, at a fixture
    # where the three numbers genuinely differ (3 candidates, 1 offered, 2 partition-deferred) —
    # a fixture where they coincided would pass for a line that printed any one of them thrice.
    chk("[sparq#4819] the deferred lane names its own partition attrition, always",
        [line for line in _.split("\n") if line.startswith("deferred census")],
        ["deferred census o/t0: candidates=3 frontier=1 partition-deferred=2 "
         "ready-lane-keys-held=0 top-contended: docs=1, usage=1"])
    _, _def_zero = _run_readiness([[_issue(605, ["area:usage"], pr=True)]], [_PR_AWARE_PLANNER])
    chk("[sparq#4819] ...printed at ZERO too — an absent bucket must not look like an empty one",
        "deferred census o/t0: candidates=0 frontier=0 partition-deferred=0" in _def_zero, True)

    # ------------------------------------------------------------------------------------------
    # [sparq#4819] THE MACHINE-PARK ATTESTATION INTERLOCK.
    #
    # CLAIM frees a `review:parked` provably-inert draft's crates and logs it 142 times a tick;
    # PLAN reserved those same crates and committed the frontier FIRST, because `occupancy_input`
    # carried no `draft`/`auto_merge` and so could not evaluate the predicate. These run the WHOLE
    # readiness step, so they cover the CALL SITE (`row[inert_field] = ...`) that a block-scoped
    # or attribute-level assertion cannot see, in both directions and in the producer-deleted and
    # planner-does-not-consume degradations.
    # ------------------------------------------------------------------------------------------
    _park_rows = [_issue(700, ["area:usage", "review:parked"], pr=True),
                  _issue(701, _READY + ["area:usage"]),
                  _issue(702, _READY + ["area:docs"])]
    _plan_hold, _out_hold = _run_readiness([_park_rows], [_INERT_AWARE_PLANNER])
    chk("[sparq#4819] an UNATTESTED machine-parked PR keeps its crate (the forbidden fix stays out)",
        _planned(_plan_hold), [702])
    _plan_free, _out_free = _run_readiness(
        [[dict(_park_rows[0], _inert=True)] + _park_rows[1:]], [_INERT_AWARE_PLANNER])
    chk("[sparq#4819] ...and an ATTESTED one releases it, so the waiting sibling is offered",
        _planned(_plan_free), [701, 702])
    # The two degradation warnings must be ABSENT on the healthy path. Deliberately NOT
    # `"::warning::" not in _out_free`: this fixture planner has no `ready_candidates`, so it
    # legitimately raises an unrelated warning, and the broad assertion would be satisfied by the
    # wrong absence — the "right answer, wrong reason" class.
    chk("[sparq#4819] the release census names the PR and the crate it released, and opens clean",
        ("parked-release census o/t0: stamped" in _out_free,
         "1 machine-parked row(s) release their areas: pr#700:usage" in _out_free,
         "no inertness attestation" in _out_free, "NOT STAMPED" in _out_free),
        (True, True, False, False))
    chk("[sparq#4819] ...and the census prints at ZERO releases too",
        "0 machine-parked row(s) release their areas: none" in _out_hold, True)
    # PRODUCER DELETED. The consumer must fall back to every-PR-reserves and SAY SO — a silent
    # fallback is a carve-out that stops firing with no signal, the #753/#762 class.
    _plan_noattest, _out_noattest = _run_readiness(
        [[dict(_park_rows[0], _inert=True)] + _park_rows[1:]], [_INERT_AWARE_PLANNER],
        attest=False)
    # The warning is asserted with its `::warning::` PREFIX ATTACHED. A bare
    # `"::warning::" in out` passes for the wrong reason here — this fixture planner has no
    # `ready_candidates`, so an unrelated warning is present either way, and downgrading THIS
    # message to a plain print left the pair green (measured: mutant C7 survived it).
    chk("[sparq#4819] with NO attestation file the park holds again, loudly",
        (_planned(_plan_noattest),
         "::warning::o/t0: no inertness attestation" in _out_noattest),
        ([702], True))
    # A truthy-but-not-True value in the map is NOT a proof. The consumer normalises with
    # `is True`; relaxing it to `bool(...)` would read a producer's string or int as an
    # attestation (measured: mutant C2 survived a boolean-only fixture).
    _plan_truthy, _ = _run_readiness(
        [_park_rows], [_INERT_AWARE_PLANNER],
        attest={"complete": True, "items": {"700": "yes"}, "reasons": {}})
    chk("[sparq#4819] a truthy-but-not-True attestation releases nothing",
        _planned(_plan_truthy), [702])
    # A document that never says `complete` is an INCOMPLETE read, not an empty one; accepting it
    # would consume a half-written snapshot as authoritative.
    _plan_incomplete, _out_incomplete = _run_readiness(
        [_park_rows], [_INERT_AWARE_PLANNER],
        attest={"items": {"700": True}})
    chk("[sparq#4819] an INCOMPLETE attestation document is refused, loudly",
        (_planned(_plan_incomplete),
         "::warning::o/t0: inertness attestation is malformed or incomplete" in _out_incomplete),
        ([702], True))
    # A UNICODE DIGIT-BUT-NOT-DECIMAL KEY. Round-1 review, real crash: the guard was
    # `str(number).isdigit()`, which answers True for "²" (SUPERSCRIPT TWO) and every other
    # superscript/circled digit, while `int()` accepts only DECIMALS — so one such key raised
    # ValueError out of the comprehension and killed the readiness step for EVERY target repo,
    # not just this one. The key is a JSON object key, i.e. reachable by any producer. Asserted
    # as "the tick survives AND the good row still works", because a mutant that dropped the
    # whole document would also stop the crash while losing every attestation with it.
    _plan_uni, _out_uni = _run_readiness(
        [_park_rows], [_INERT_AWARE_PLANNER], catch=True,
        attest={"complete": True, "items": {"²": True, "700": True, "7e2": True, "-700": True},
                "reasons": {}})
    chk("[sparq#4819] a Unicode digit-but-not-decimal key drops its row, it does not kill the tick",
        (_planned_or_abort(_plan_uni),
         "1 machine-parked row(s) release their areas: pr#700:usage" in _out_uni),
        ([701, 702], True))
    # TRUNCATED/UNREADABLE degrades, it does not abort. Round-1 review: `json.loads` raised
    # straight out of the step, so a half-written document was a total PLAN outage for every
    # target — while an ABSENT document (the same accident one fsync earlier) degraded cleanly.
    # The words claimed fail-closed-at-every-seam; now the behaviour matches them.
    _plan_trunc, _out_trunc = _run_readiness(
        [_park_rows], [_INERT_AWARE_PLANNER], catch=True,
        attest="{\"complete\": true, \"items\": {\"700\":")
    chk("[sparq#4819] a TRUNCATED attestation degrades to every-PR-reserves, loudly",
        (_planned_or_abort(_plan_trunc),
         "::warning::o/t0: inertness attestation is unreadable (JSONDecodeError)" in _out_trunc),
        ([702], True))
    # An engine that declares the contract but never consults it must NOT be fed attestations.
    _plan_ignoring, _out_ignoring = _run_readiness(
        [[dict(_park_rows[0], _inert=True)] + _park_rows[1:]], [_INERT_DECLARING_ONLY_PLANNER])
    chk("[sparq#4819] a planner that declares the field but ignores it is refused, by name",
        ("planner ignores the inertness attestation" in _out_ignoring,
         "NOT STAMPED" in _out_ignoring, _planned(_plan_ignoring)),
        (True, True, [702]))
    # PLANNER DOES NOT CONSUME IT. Today's behaviour exactly, and the field is never stamped.
    _plan_legacy, _out_legacy = _run_readiness(
        [[dict(_park_rows[0], _inert=True)] + _park_rows[1:]], [_PR_AWARE_PLANNER])
    chk("[sparq#4819] a planner with no inertness contract is byte-identical to today",
        (_planned(_plan_legacy), "NOT STAMPED" in _out_legacy,
         "declares no inertness contract" in _out_legacy),
        ([702], True, True))
    # THE REFUSAL THAT MATTERS. An engine that releases a machine park on the LABEL ALONE is the
    # fix the issue forbids; the interlock must refuse to feed it, naming that reason. Without
    # this row the `if held:` branch of `inert_aware` has NO coverage and could be deleted with
    # every other assertion green.
    _plan_uncond, _out_uncond = _run_readiness(
        [_park_rows], [_UNCONDITIONAL_PARK_PLANNER])
    chk("[sparq#4819] an engine that releases a park with NO attestation is refused, by name",
        ("RELEASES a machine-parked area with no attestation" in _out_uncond,
         "NOT STAMPED" in _out_uncond, _planned(_plan_uncond)),
        (True, True, [701, 702]))
    # THE PLANNER-SIDE DEGRADATION IS ANNOTATED. Round 1 printed `NOT STAMPED` as a plain `print`
    # inside the census line while both FILE seams carried `::warning::` — so the only degradation
    # that actually fired in production (sparq's dispatch-plan.py exported neither name) was the
    # one with no annotation, and the pair shipped as a measured no-op under a green run. The
    # `::warning::` PREFIX is asserted ATTACHED, for the reason the neighbouring rows already are:
    # this fixture raises an unrelated warning either way, so a bare `"::warning::" in out` is
    # satisfied by the wrong absence (mutant C7's lesson).
    chk("[sparq#4819] a planner that cannot consume the attestation is ANNOTATED, not just printed",
        (f"::warning::o/t0: PLAN computed an inertness attestation (1 of 1 open PR(s) provably "
         f"inert) and DISCARDED it" in _out_legacy,
         "planner declares no inertness contract" in _out_legacy,
         # ...and the healthy path does NOT raise it, so this cannot be passing unconditionally.
         "and DISCARDED it" in _out_free),
        (True, True, False))

    # ------------------------------------------------------------------------------------------
    # [sparq#4819 round 2] THE PRODUCER SEAM. Round 1's YAML pins covered only the CONSUMER
    # (`readiness`). The round-1 review measured four survivors on the producer, all of which
    # degrade to the fail-safe every-PR-reserves path WITH a warning — throughput loss with a
    # detector, not a correctness hole, and unpinned either way. Pinned here the same way the
    # consumer seam is: by injecting each mutation into a real copy of the workflow and asserting
    # the refusal FIRES, so these rows cannot be green because the refusal is unreachable.
    # ------------------------------------------------------------------------------------------
    def _producer_refusal(path):
        try:
            _refuse_producer_swallow(path, "snapshot", "plan-snapshot.py")
        except AssertionError as exc:
            return str(exc)
        finally:
            os.remove(path)
        return ""

    _prod_off = _producer_refusal(_with_line("        id: snapshot", "        if: false"))
    chk("[sparq#4819][YAML seam] `if: false` on the PRODUCER step is REFUSED",
        ("step owning `id: snapshot`" in _prod_off, "never run" in _prod_off), (True, True))
    _prod_coe = _producer_refusal(
        _with_line("        id: snapshot", "        continue-on-error: true"))
    chk("[sparq#4819][YAML seam] `continue-on-error: true` on the PRODUCER step is REFUSED",
        ("truthy `continue-on-error`" in _prod_coe,
         "no inertness attestation" in _prod_coe), (True, True))
    _prod_or_true = _producer_refusal(_with_line(
        '            "$RUNNER_TEMP/dispatch-targets/repos.txt" "$RUNNER_TEMP"',
        "          true"))
    chk("[sparq#4819][YAML seam] a command AFTER the producer invocation is REFUSED",
        ("LAST command is 'true'" in _prod_or_true,
         "exits with its last command's status" in _prod_or_true), (True, True))
    # ...and the refusal is not passing because it refuses everything: the REAL workflow passes.
    chk("[sparq#4819][YAML seam] ...and the real producer step passes the same refusal",
        _producer_refusal(_with_line("        id: snapshot", "        # a harmless comment")), "")

    # ------------------------------------------------------------------------------------------
    # [#1207] THE CONDITIONAL-READ SEAM. Mutated at all three places the estate's uncaught
    # mutants live: the `if:`, the STEP, and the CALL SITE. Each mutation is injected into a real
    # copy of the workflow and the refusal must FIRE, so none of these rows can be green because
    # the assertion is unreachable — and the last row proves the real file still passes, so none
    # of them is green because the guard refuses everything.
    # ------------------------------------------------------------------------------------------
    def _etag_refusal(path):
        try:
            _refuse_unwired_etag_store(path)
        except AssertionError as exc:
            return str(exc)
        finally:
            os.remove(path)
        return ""

    # THE CALL SITE. Delete the one env line and the mechanism is gone: plan-snapshot.py defaults
    # to no store, sweeps unconditionally at full price, and every other assertion stays green.
    _etag_callsite = _etag_refusal(_without_line(
        "          SNAPSHOT_ETAG_STORE: ${{ runner.temp }}/etag-store/etags.json"))
    chk("[#1207][YAML seam] deleting the SNAPSHOT_ETAG_STORE call site is REFUSED",
        ("does not pass `SNAPSHOT_ETAG_STORE`" in _etag_callsite,
         "at full price, silently" in _etag_callsite), (True, True))

    # THE STEP. Delete the publish step's id and the seam cannot be found at all.
    _etag_step = _etag_refusal(_without_line("        id: etag-save"))
    chk("[#1207][YAML seam] removing the store-publishing STEP is REFUSED",
        ("no step `id: etag-save`" in _etag_step, "billable again" in _etag_step), (True, True))

    # THE `if:`. A condition on the publish step silences the seam without failing anything.
    _etag_if = _etag_refusal(_with_line("        id: etag-save", "        if: false"))
    chk("[#1207][YAML seam] an `if:` on the store-publishing step is REFUSED",
        ("carries an `if:` condition" in _etag_if, "stayed green" in _etag_if), (True, True))

    # THE TRANSPORT, which is a SECURITY property and not a throughput one: any RESTORE action
    # in this job extracts a tarball with `tar -P` (--absolute-names) — an arbitrary file write
    # in a job that goes on to hold github.token. This is the finding that failed review round 1.
    # Injected as a WHOLE, well-formed step (not a line spliced into another step's body, which
    # only produced malformed YAML and a vacuously-passing row).
    _SNAPSHOT_NAME_LINE = ("      - name: Snapshot target issues and pull requests "
                           "(authenticated, registry-inline only)")
    for _label, _action in (("actions/cache/restore", "actions/cache/restore"),
                            ("the combined actions/cache", "actions/cache"),
                            ("actions/download-artifact", "actions/download-artifact")):
        _etag_restore = _etag_refusal(_replacing_line(
            _SNAPSHOT_NAME_LINE,
            f"      - uses: {_action}@1bd1e32a3bdc45362d1e726936510720a7c30a57\n"
            "        with:\n"
            "          path: ${{ runner.temp }}/etag-store\n"
            "          key: dispatch-etags-\n"
            + _SNAPSHOT_NAME_LINE))
        chk(f"[#1207][YAML seam][SECURITY] re-introducing {_label} into the PLAN job is REFUSED",
            ("--absolute-names" in _etag_restore, "arbitrary file write" in _etag_restore),
            (True, True))

    # THE ORDERING. If target code can run before the publish, the store is one the hostile half
    # was in a position to shape. Injecting a `git clone` into the SNAPSHOT step makes the
    # first target-code step precede `etag-save`, and the refusal must fire.
    _etag_order = _etag_refusal(_replacing_line(
        "          python3 registry-snapshot/scripts/plan-snapshot.py --self-test",
        "          git clone https://example.invalid/decoy\n"
        "          python3 registry-snapshot/scripts/plan-snapshot.py --self-test"))
    chk("[#1207][YAML seam][SECURITY] publishing the store AFTER target code is REFUSED",
        ("AFTER target code runs" in _etag_order,
         "in a position to shape" in _etag_order), (True, True))

    # THE PATH CHAIN. Publish a path the snapshot never writes and the store is cold forever.
    _etag_path = _etag_refusal(_replacing_line(
        "          path: ${{ runner.temp }}/etag-store/etags.json",
        "          path: ${{ runner.temp }}/etag-store/elsewhere.json", occurrence=0))
    chk("[#1207][YAML seam] publishing a path the store is not written to is REFUSED",
        ("but the publish step uploads" in _etag_path), True)

    # THE ARTIFACT NAME, read from plan-snapshot.py itself so the two cannot drift.
    _etag_name = _etag_refusal(_replacing_line(
        "          name: dispatch-etags", "          name: dispatch-etags-renamed"))
    chk("[#1207][YAML seam] a publish/read artifact-name drift is REFUSED",
        ("uploads artifact" in _etag_name), True)

    chk("[#1207][YAML seam] ...and the real workflow passes the same refusal",
        _etag_refusal(_with_line("        id: snapshot", "        # a harmless comment")), "")

    # THE FILENAME CHAIN, END TO END. Round 1's rows all fed the consumer an attestation THIS
    # HARNESS wrote, so the producer could rename `raw-inertness-<i>.json` — and rename its own
    # assertion with it — and both self-tests stayed green while PLAN silently stopped seeing
    # attestations. Here the REAL `plan-snapshot.snapshot_targets` writes every file, over a stub
    # fetch, and the REAL readiness step then consumes that same directory. Nothing in between
    # names the file, so the two sides have to agree by construction.
    def _real_producer(workdir, index, repo, rows):
        import json as _json
        snapshot = _load("registry_plan_snapshot_e2e", "plan-snapshot.py")
        # A GENUINELY inert PR: draft + the `auto_merge` key PRESENT and null is the atomic
        # single-read proof `_pull_inactivity_decision` accepts. The head ref is deliberately NOT
        # worker-prefixed so `_pr_status_snapshot` issues no per-PR detail read and the stub fetch
        # stays two endpoints; that is also the dominant live shape.
        pulls = [{"number": r["number"], "state": "open", "body": "",
                  "author_association": "OWNER", "draft": True, "auto_merge": None,
                  "head": {"ref": "feature/x", "sha": "a" * 40, "repo": {"full_name": repo}},
                  "user": {"login": "u", "type": "User"}, "labels": r.get("labels", [])}
                 for r in rows if "pull_request" in r]

        def fetch(url):
            if "/issues?" in url:
                return rows if "page=1" in url else []
            if "/pulls?" in url:
                return pulls if "page=1" in url else []
            raise AssertionError(f"stub fetch got an unexpected URL: {url}")

        snapshot.snapshot_targets(fetch, snapshot._load_claim(), [repo], workdir)
        # Observed, NEVER asserted here: an `assert`/open() in this hook would abort the suite
        # with a traceback, and a crash is not a kill — the mutant has to red a NAMED row. The
        # producer's own count rides out so the row below can also prove it PROVED something,
        # which is how "the consumer released" could otherwise pass for the wrong reason.
        try:
            with open(os.path.join(workdir, f"raw-inertness-{index}.json"),
                      encoding="utf-8") as handle:
                _e2e_seen["attested"] = sum(_json.load(handle)["items"].values())
        except (OSError, ValueError, KeyError, TypeError):
            _e2e_seen["attested"] = None
        _e2e_seen["files"] = sorted(name for name in os.listdir(workdir)
                                    if name.startswith("raw-"))

    _e2e_seen = {}
    _plan_e2e, _out_e2e = _run_readiness(
        [_park_rows], [_INERT_AWARE_PLANNER], produce=_real_producer)
    chk("[sparq#4819] the REAL producer's file is the one the REAL consumer reads (rename => red)",
        (_planned(_plan_e2e),
         "1 machine-parked row(s) release their areas: pr#700:usage" in _out_e2e,
         "no inertness attestation" in _out_e2e,
         _e2e_seen["attested"],
         "raw-inertness-0.json" in _e2e_seen["files"]),
        ([701, 702], True, False, 1, True))

    # issue #112: a MULTI-area issue reserves BOTH its areas, NOT the alphabetically-first one —
    # else a busy secondary area (here 'worker') could not exclude it and it would double-dispatch.
    # It does NOT reserve the serializing global partition either: that made "touches usage and
    # worker" mean "touches everything" and self-blocked 13.9% of the ready board. A single-area
    # issue still reserves just that area; a NO-area issue still reserves everything.
    p_multi = plan_dispatch(
        compute_ready([iss(8, R + ["priority:P1", "role:impl", "area:usage", "area:worker"])]), doc)
    chk("multi-area -> the canonical BOTH-areas key (never the first area, never global)",
        p_multi[0]["package"], "usage,worker")
    chk("multi-area key is order-independent", plan_dispatch(
        compute_ready([iss(88, R + ["priority:P1", "role:impl", "area:worker", "area:usage"])]),
        doc)[0]["package"], "usage,worker")
    chk("single-area -> that package", plan_dispatch(
        compute_ready([iss(9, R + ["priority:P1", "role:impl", "area:usage"])]), doc)[0]["package"],
        "usage")
    # [CONTROL] the fail-closed direction is untouched: a row with NO area label still reserves
    # every partition. Narrowing this one is the reckless inversion of the change above.
    chk("[CONTROL] no-area -> the serializing global partition", _plan_package(
        ["status:ready", "priority:P1", "role:impl"]), GLOBAL)

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
