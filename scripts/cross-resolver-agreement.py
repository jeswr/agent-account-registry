#!/usr/bin/env python3
# [OPUS-5] PLAN-vs-CLAIM agreement harness. Pure + offline; no network, no secrets, no writes.
"""cross-resolver-agreement.py — assert the PLAN resolver and the CLAIM resolver agree.

THE GAP THIS CLOSES
-------------------
A dispatchable item's route is derived TWICE:

  PLAN   `dispatch.yml` clones the target repository and runs the TARGET's
         `scripts/dispatch-plan.py` -> the TARGET's `scripts/route-resolve.py`.
  CLAIM  `dispatch-claim.dispatch()` loads REGISTRY-owned `scripts/policy-resolve.py` and
         re-derives the route from the target's routing table read at its PROTECTED default tip.

`dispatch-claim._route_matches` then requires EXACT equality of `model_chain`, `agent` and
`escalate`. A rule one resolver implements and the other does not is therefore not a preference
that half-applies — it raises `DispatchError`, the item is counted `route-policy-failed` and
skipped, and because the comparison is a pure function of the item's labels and the routing table
the SAME skip repeats on every subsequent tick. The item never dispatches again, and the only
symptom is a generic defer counter.

Until this harness existed, NO test in either repository asserted that the two resolvers derive the
same chain. That absence is why sparq PR #4211 round 1 passed review with an inert carve-out and
round 2 passed review with a carve-out that would have stopped 34 issues from dispatching at all:
every assertion on both sides drove ONE resolver.

WHAT IT COMPARES
----------------
For each label set in `AGREEMENT_MATRIX`, both resolvers are driven over the SAME routing document
and their full route decisions are compared. A REFUSAL is a first-class outcome: the two resolvers
must also agree about which label sets never route at all (registry #122), so "PLAN routes it,
CLAIM refuses it" is reported as a disagreement rather than passing because one side raised.

MODES
-----
  --self-test                 offline fixtures: a sparq-shaped table with and without a
                              `[[chain_preference]]` declaration, plus the non-vacuity mutants.
  --routing-file F            run the matrix over a real routing table, using the REGISTRY's own
                              `route-resolve.py` as the PLAN resolver (it is a copy of the
                              target-side resolver and shares the same consumer contract).
  --target-root DIR           the REAL cross-repository check: use DIR/scripts/route-resolve.py —
                              the target's OWN planner code — as the PLAN resolver, and
                              DIR/<routing pointer> as the table. This executes target-authored
                              code, so it is a DEVELOPMENT / CI-in-the-target's-own-repo tool and
                              deliberately NOT wired into the privileged claim step (registry
                              #119: CLAIM trusts the target's protected DATA, never its CODE).
"""
import argparse
import copy
import importlib.util
import json
import sys
import tomllib
from pathlib import Path


def _load(module_name, path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_HERE = Path(__file__).resolve().parent
_POLICY = _load("registry_policy_resolve_agreement", _HERE / "policy-resolve.py")
_ROUTE = _load("registry_route_resolve_agreement", _HERE / "route-resolve.py")

# A synthetic, minimal policy row. The agreement question is about ROUTING, and every non-routing
# field policy-resolve validates is target policy the PLAN resolver never sees; synthesising it
# keeps this harness runnable against any routing table with no access to the private policy file.
PROBE_REPO = "probe/target"
PROBE_POLICY = {"repos": {PROBE_REPO: {
    "enabled": True, "routing": "orchestration/routing.toml", "account_pool": ["acct01"],
    "max_concurrent": 1, "worker_timeout_minutes": 30, "gate_profile": "lint-only",
    "arm_auto_merge": False, "max_attempts": 1, "trust": "collaborators"}}}

# THE AGREEMENT MATRIX. Each row is a label set both resolvers must decide identically.
#
# Rows are chosen to cover every branch a chain-order preference can reach, and every branch it
# must NOT reach. `role:*` values are restricted to roles a real table declares, because an
# UNDECLARED role is a separate, pre-existing PLAN/CLAIM question (registry #122) that this harness
# is not the place to relitigate.
AGREEMENT_MATRIX = (
    # -- the carve-out's own surface: the exact shapes of sparq's live area:gui backlog.
    ("area:gui + role:impl (33 of the 35 live sparq issues)", ("area:gui", "role:impl")),
    ("area:gui + role:impl + priority", ("area:gui", "role:impl", "priority:P2")),
    ("area:gui + role:perf (the 34th)", ("area:gui", "role:perf")),
    ("area:gui + role:research (the 35th — must NOT be re-ordered)",
     ("area:gui", "role:research")),
    ("area:gui with no role at all (the [defaults] branch)", ("area:gui",)),
    ("area:gui + role:docs", ("area:gui", "role:docs")),
    ("area:gui + role:ci", ("area:gui", "role:ci")),
    ("area:gui + role:site", ("area:gui", "role:site")),
    # -- security surfaces: never re-ordered, on either side.
    ("area:gui + a security surface (ZK wins)", ("area:gui", "area:sparq-zk", "role:impl")),
    ("a security surface alone", ("area:sparq-zk", "role:impl")),
    # -- [#1397] the security override's PERSONA branch. Under `agent_from_role` the agent is taken
    # from the issue's own role row, so each role must be decided identically by both resolvers,
    # and a ROLELESS security issue (no row to direct from) must keep the override's own persona.
    ("a security surface + role:docs (a DIFFERENT role row supplies the persona)",
     ("area:sparq-zk", "role:docs")),
    ("a security surface + role:research", ("area:sparq-zk", "role:research")),
    ("a security surface with NO role (the persona cannot be role-directed)", ("area:sparq-zk",)),
    # -- the exclusions. site* is NOT gui; `guide`/`guidance` must not substring-match.
    ("area:site + role:impl", ("area:site", "role:impl")),
    ("area:site-specs + role:impl", ("area:site-specs", "role:impl")),
    ("area:site-papers + role:impl", ("area:site-papers", "role:impl")),
    ("area:sitemap + role:impl", ("area:sitemap", "role:impl")),
    ("surface:frontend + role:impl", ("surface:frontend", "role:impl")),
    ("dashboard + role:impl", ("dashboard", "role:impl")),
    ("area:guide + role:impl (substring trap)", ("area:guide", "role:impl")),
    ("area:guidance + role:impl (substring trap)", ("area:guidance", "role:impl")),
    # -- plain, unremarkable work: the regression surface for the whole rest of the backlog.
    ("a plain crate area + role:impl", ("area:sparq-core", "role:impl")),
    ("a plain crate area + role:docs", ("area:sparq-core", "role:docs")),
    ("a plain crate area, role-less", ("area:sparq-core",)),
    ("no labels at all", ()),
)


def _plan(resolver, labels, routing_doc):
    try:
        chain, agent, escalate = resolver(list(labels), copy.deepcopy(routing_doc))
    except ValueError:
        # A REFUSAL, compared by outcome and not by message: the two resolvers word their
        # fail-closed diagnostics differently, but they must agree on WHICH label sets never route.
        return ("refused", "")
    return ("routed", (list(chain), agent, bool(escalate)))


def _claim(labels, routing_doc, policy_doc=None, repo=PROBE_REPO):
    try:
        resolved = _POLICY.resolve(repo, list(labels), policy_doc or PROBE_POLICY,
                                   copy.deepcopy(routing_doc))
    except ValueError:
        return ("refused", "")
    return ("routed", (list(resolved["model_chain"]), resolved["agent"],
                       bool(resolved["escalate"])))


def compare(routing_doc, plan_resolver=None, policy_doc=None, repo=PROBE_REPO,
            matrix=AGREEMENT_MATRIX):
    """Return [(name, labels, plan_outcome, claim_outcome)] for every DISAGREEING row."""
    plan_resolver = plan_resolver or _ROUTE.resolve
    bad = []
    for name, labels in matrix:
        plan = _plan(plan_resolver, labels, routing_doc)
        claim = _claim(labels, routing_doc, policy_doc, repo)
        if plan != claim:
            bad.append((name, labels, plan, claim))
    return bad


def target_resolver(target_root):
    """Load the TARGET repository's own `scripts/route-resolve.py` — the module the PLAN job runs."""
    path = Path(target_root).resolve() / "scripts" / "route-resolve.py"
    if not path.is_file():
        raise FileNotFoundError(f"no target-side resolver at {path}")
    return _load("target_route_resolve", path).resolve


# ---------------------------------------------------------------------------------------------
# Fixtures. A sparq-SHAPED routing table: the same catalog, the same precedence, the same role set.
# ---------------------------------------------------------------------------------------------
SPARQ_SHAPED = """
[models.opus5]
provider = "anthropic"
provider_model = "claude-opus-5"
[models.sol]
provider = "openai"
provider_model = "gpt-5.6-sol"
[models.luna]
provider = "openai"
[models.terra]
provider = "openai"
[models.haiku]
provider = "anthropic"
[models.sonnet]
provider = "anthropic"

[defaults]
model_chain = ["opus5", "sol"]
agent = "sparq-rust-impl"

[[route]]
match_labels = ["zk", "mpc", "crypto", "auth", "e2ee", "security"]
model_chain = ["opus5"]
agent = "sparq-reviewer"
escalate = true

[[route]]
role = "impl"
model_chain = ["opus5", "sol"]
agent = "sparq-rust-impl"

[[route]]
role = "perf"
model_chain = ["opus5", "sol"]
agent = "sparq-perf-engineer"

[[route]]
role = "site"
model_chain = ["opus5", "sol"]
agent = "sparq-site"

[[route]]
role = "gui"
model_chain = ["sol", "opus5"]
agent = "sparq-site"

[[route]]
role = "ci"
model_chain = ["opus5", "sol"]
agent = "sparq-ci-infra"

[[route]]
role = "research"
model_chain = ["opus5"]
agent = "sparq-researcher"
escalate = true

[[route]]
role = "docs"
model_chain = ["sol", "terra", "opus5"]
agent = "sparq-docs"
"""

GUI_DECLARATION = """
[[chain_preference]]
labels   = ["area:gui"]
lead     = "sol"
requires = ["sol", "opus5"]
"""

# [OPUS-5] registry #738 / the OPUS5-ONLY `role:impl` chain. `role = "impl"` moved from
# `["opus5", "sol"]` to `["opus5"]` + `escalate = true` (measured: sol 18% vs opus5 86% in-cell
# first-attempt yield, n=74). That edit DISARMS the re-order-only carve-out — a `["opus5"]` chain
# does not contain `sol`, so the `requires` condition declines and GUI impl work silently becomes
# opus5-only, the exact inversion PR #4211 fixed. The fixtures below pin BOTH halves: that the
# collision is real, and that `inject_roles` closes it identically on both resolvers.
SPARQ_IMPL_TWO_RUNG = 'role = "impl"\nmodel_chain = ["opus5", "sol"]\nagent = "sparq-rust-impl"'
SPARQ_IMPL_OPUS5_ONLY = ('role = "impl"\nmodel_chain = ["opus5"]\n'
                         'agent = "sparq-rust-impl"\nescalate = true')
GUI_DECLARATION_INJECT = """
[[chain_preference]]
labels       = ["area:gui"]
lead         = "sol"
requires     = ["sol", "opus5"]
inject_roles = ["impl"]
"""

# The security-route exemption is UNOBSERVABLE while the soundness chain is single-model: the
# `requires` condition declines it for an unrelated reason, so applying the preference to the
# security branch is a mutation no assertion can see. This variant makes the soundness chain
# CROSS-PROVIDER, which is the only shape in which the exemption is a real, testable rule.
SECURITY_CROSS_PROVIDER = 'model_chain = ["opus5"]\nagent = "sparq-reviewer"'
SECURITY_CROSS_PROVIDER_FIXED = 'model_chain = ["opus5", "sol"]\nagent = "sparq-reviewer"'

# [#1397] `agent_from_role`: the security override supplies the chain + escalate, the issue's own
# role row supplies the PERSONA. It is a two-resolver rule like every other rule in this file — a
# redirect CLAIM implements and PLAN does not is a permanent per-item `route-policy-failed` defer
# for every trust-surface issue, which on the registry itself is most of the backlog.
SECURITY_ROLE_DIRECTED = ('agent = "sparq-reviewer"\nescalate = true',
                          'agent = "sparq-reviewer"\nagent_from_role = true\nescalate = true')


def _self_test():  # noqa: C901 — a flat sequence of assertions
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    undeclared = tomllib.loads(SPARQ_SHAPED)
    declared = tomllib.loads(SPARQ_SHAPED + GUI_DECLARATION)

    # (1) THE HEADLINE. Both resolvers implement the mechanism, so a table that declares the
    # carve-out is decided identically by PLAN and CLAIM on every row of the matrix.
    chk("PLAN and CLAIM agree on EVERY matrix row for a table that DECLARES the carve-out",
        compare(declared), [])
    # (2) ...and on every row for a table that declares nothing. This is the property that makes
    # landing the registry side FIRST a strict no-op.
    chk("PLAN and CLAIM agree on every matrix row for a table with NO declaration",
        compare(undeclared), [])
    # (3) The declaration must actually CHANGE something, or (1) is satisfied vacuously by two
    # resolvers that both ignore it.
    def chain(doc, labels):
        return _claim(labels, doc)[1][0]

    chk("the declaration MOVES the 33-issue case (so agreement above is not vacuous)",
        (chain(undeclared, ("area:gui", "role:impl")),
         chain(declared, ("area:gui", "role:impl"))),
        (["opus5", "sol"], ["sol", "opus5"]))
    chk("...and the role:perf case", (chain(undeclared, ("area:gui", "role:perf")),
                                      chain(declared, ("area:gui", "role:perf"))),
        (["opus5", "sol"], ["sol", "opus5"]))
    chk("...and the role-less case", (chain(undeclared, ("area:gui",)),
                                      chain(declared, ("area:gui",))),
        (["opus5", "sol"], ["sol", "opus5"]))
    chk("...but NOT role:research (the both-implementors condition)",
        (chain(undeclared, ("area:gui", "role:research")),
         chain(declared, ("area:gui", "role:research"))), (["opus5"], ["opus5"]))
    chk("...and NOT a security surface",
        (chain(undeclared, ("area:gui", "area:sparq-zk", "role:impl")),
         chain(declared, ("area:gui", "area:sparq-zk", "role:impl"))), (["opus5"], ["opus5"]))
    chk("...and NOT area:site", (chain(undeclared, ("area:site", "role:impl")),
                                 chain(declared, ("area:site", "role:impl"))),
        (["opus5", "sol"], ["opus5", "sol"]))

    # (3b) THE SECURITY EXEMPTION, made observable. Against the shipped single-model soundness
    # chain the `requires` condition declines for an unrelated reason, so "the security route is
    # exempt" is not testable at all — mutation found that applying the preference to the security
    # branch survives every assertion. With a CROSS-PROVIDER soundness chain the exemption becomes
    # a real rule, on both resolvers, and both must still return it unmodified.
    xsec = tomllib.loads((SPARQ_SHAPED + GUI_DECLARATION)
                         .replace(SECURITY_CROSS_PROVIDER, SECURITY_CROSS_PROVIDER_FIXED, 1))
    assert xsec["route"][0]["model_chain"] == ["opus5", "sol"], \
        "the cross-provider security fixture is stale — it no longer edits the security route"
    chk("a CROSS-PROVIDER security route is returned UNMODIFIED by CLAIM under area:gui",
        chain(xsec, ("area:gui", "area:sparq-zk", "role:impl")), ["opus5", "sol"])
    chk("...and by PLAN", _plan(_ROUTE.resolve, ("area:gui", "area:sparq-zk", "role:impl"),
                                xsec)[1][0], ["opus5", "sol"])
    chk("...while the SAME table still re-orders the role branch (so the two rows above are an "
        "exemption, not a dead fixture)",
        chain(xsec, ("area:gui", "role:impl")), ["sol", "opus5"])
    chk("PLAN and CLAIM agree on every matrix row for the cross-provider-security table",
        compare(xsec), [])

    # (3c) [OPUS-5] THE OPUS5-ONLY `role:impl` CHAIN (registry #738) AND ITS COLLISION WITH THE
    # CARVE-OUT. Both halves are asserted, because the first is the defect and the second is the fix
    # and a table can only ship one of them.
    assert SPARQ_IMPL_TWO_RUNG in SPARQ_SHAPED, \
        "the impl-route fixture is stale — it no longer edits the impl route"
    _single = SPARQ_SHAPED.replace(SPARQ_IMPL_TWO_RUNG, SPARQ_IMPL_OPUS5_ONLY, 1)
    single_reorder = tomllib.loads(_single + GUI_DECLARATION)
    single_inject = tomllib.loads(_single + GUI_DECLARATION_INJECT)
    chk("the fixture edit really produced a single-rung escalating impl route",
        [(r.get("model_chain"), r.get("escalate")) for r in single_reorder["route"]
         if r.get("role") == "impl"], [(["opus5"], True)])
    # THE COLLISION, as a test rather than as prose: with the re-order-only declaration the carve-out
    # goes INERT and GUI impl work resolves opus5-only. Both resolvers agree — which is exactly why
    # nothing in the pipeline would have reported it.
    chk("re-order-only declaration + a ['opus5'] impl chain DISARMS the carve-out (both sides "
        "agree on the WRONG answer, so agreement alone could never have caught this)",
        (chain(single_reorder, ("area:gui", "role:impl")),
         _plan(_ROUTE.resolve, ("area:gui", "role:impl"), single_reorder)[1][0]),
        (["opus5"], ["opus5"]))
    # THE FIX: `inject_roles` restores sol-first for GUI impl work, on BOTH resolvers.
    chk("inject_roles restores SOL-FIRST for area:gui + role:impl at CLAIM",
        chain(single_inject, ("area:gui", "role:impl")), ["sol", "opus5"])
    chk("...and at PLAN", _plan(_ROUTE.resolve, ("area:gui", "role:impl"),
                                single_inject)[1][0], ["sol", "opus5"])
    chk("...and opus5 stays reachable behind sol (preference, not exclusion)",
        "opus5" in chain(single_inject, ("area:gui", "role:impl")), True)
    chk("...and the carve-out still never re-routes the AGENT",
        _claim(("area:gui", "role:impl"), single_inject)[1][1], "sparq-rust-impl")
    chk("PLAN and CLAIM agree on EVERY matrix row for the single-rung + inject_roles table",
        compare(single_inject), [])
    chk("PLAN and CLAIM agree on every matrix row for the single-rung re-order-only table too "
        "(the collision is a WRONG answer, not a divergence)", compare(single_reorder), [])
    # The injection is scoped to `role:impl` and to `area:gui`: nothing else may grow a rung.
    chk("role:research keeps its single-provider escalating chain under the inject declaration",
        (chain(single_inject, ("area:gui", "role:research")),
         _claim(("area:gui", "role:research"), single_inject)[1][2]), (["opus5"], True))
    chk("a plain (non-gui) role:impl issue is NOT given sol back",
        chain(single_inject, ("area:sparq-core", "role:impl")), ["opus5"])
    for _near in (("area:guide", "role:impl"), ("area:guidance", "role:impl"),
                  ("area:site", "role:impl"), ("dashboard", "role:impl")):
        chk(f"{_near[0]} + role:impl is NOT given sol back (exact selector, under injection too)",
            chain(single_inject, _near), ["opus5"])
    chk("a security surface under area:gui is still returned unmodified",
        chain(single_inject, ("area:gui", "area:sparq-zk", "role:impl")), ["opus5"])
    # (3d) [#1397] THE ROLE-DIRECTED SECURITY PERSONA. Same shape as (3b)/(3c): assert the rule
    # MOVES something, that both resolvers move it identically, and that a malformed declaration is
    # refused by both — a one-sided redirect would be invisible to every per-resolver assertion.
    assert SECURITY_ROLE_DIRECTED[0] in SPARQ_SHAPED, \
        "the agent_from_role fixture is stale — it no longer edits the security route"
    directed = tomllib.loads(SPARQ_SHAPED.replace(*SECURITY_ROLE_DIRECTED, 1))

    def persona(doc, labels):
        return _claim(labels, doc)[1][1]

    chk("the declaration MOVES the trust-surface implementation persona off the verdict-only "
        "reviewer (so the agreement rows below are not vacuous)",
        (persona(undeclared, ("area:sparq-zk", "role:impl")),
         persona(directed, ("area:sparq-zk", "role:impl"))),
        ("sparq-reviewer", "sparq-rust-impl"))
    chk("...and PLAN moves it to exactly the same persona",
        _plan(_ROUTE.resolve, ("area:sparq-zk", "role:impl"), directed)[1][1], "sparq-rust-impl")
    chk("...while the CHAIN and ESCALATE stay the security override's on both sides (the "
        "soundness posture is not what moved)",
        (_claim(("area:sparq-zk", "role:impl"), directed)[1][0::2],
         _plan(_ROUTE.resolve, ("area:sparq-zk", "role:impl"), directed)[1][0::2]),
        ((["opus5"], True), (["opus5"], True)))
    chk("...a ROLELESS security issue keeps the override's own persona on both sides",
        (persona(directed, ("area:sparq-zk",)),
         _plan(_ROUTE.resolve, ("area:sparq-zk",), directed)[1][1]),
        ("sparq-reviewer", "sparq-reviewer"))
    chk("PLAN and CLAIM agree on EVERY matrix row for the role-directed-persona table",
        compare(directed), [])
    for _label, _bad_toml in (
            ("a non-boolean value", SPARQ_SHAPED.replace(
                SECURITY_ROLE_DIRECTED[0],
                'agent = "sparq-reviewer"\nagent_from_role = "true"\nescalate = true', 1)),
            ("a ROLE route", SPARQ_SHAPED.replace(
                'role = "impl"\nmodel_chain = ["opus5", "sol"]\nagent = "sparq-rust-impl"',
                'role = "impl"\nmodel_chain = ["opus5", "sol"]\nagent = "sparq-rust-impl"\n'
                "agent_from_role = true", 1))):
        _bad_doc = tomllib.loads(_bad_toml)
        chk(f"agent_from_role on {_label} is REFUSED by BOTH resolvers (a rule only one side "
            "refuses is a table PLAN plans and CLAIM rejects, every tick, forever)",
            (_plan(_ROUTE.resolve, ("area:sparq-zk", "role:impl"), _bad_doc)[0],
             _claim(("area:sparq-zk", "role:impl"), _bad_doc)[0]), ("refused", "refused"))
    # A declaration that tried to inject into an authorship-pinned escalating role is REFUSED, and
    # refused IDENTICALLY by both resolvers — so the prohibition cannot become a one-sided rule.
    banned = tomllib.loads(_single + GUI_DECLARATION_INJECT.replace(
        'inject_roles = ["impl"]', 'inject_roles = ["impl", "research"]', 1))
    chk("inject_roles naming an authorship-pinned role makes CLAIM refuse",
        _claim(("area:gui", "role:impl"), banned)[0], "refused")
    chk("...and PLAN refuse identically, so the two still AGREE (fail-closed on BOTH sides)",
        compare(banned), [])

    # (3d) [OPUS-5] THE DOCS-ONLY BOUND ON INJECTION, AND — the load-bearing half — ITS SYMMETRY.
    #
    # `policy-resolve._reject_docs_only` enforces the 2026-07-18 docs-only directive over
    # STATICALLY DECLARED chains. `inject_roles` writes the lead into the chain AFTER that, so
    # before the parse-time bound a table could lead `role:impl` with `terra` and BOTH resolvers
    # would return `['terra', 'opus5']` — agreeing, so every check in this file passed. The bound
    # lives in the SHARED `chain_preference` module for exactly that reason: PLAN
    # (`route-resolve.py`) has no docs-only rule of its own, so a CLAIM-only fix would trade a
    # silent bypass for a permanent `route-policy-failed` defer.
    docs_attack = tomllib.loads(_single + GUI_DECLARATION_INJECT.replace(
        'lead         = "sol"\nrequires     = ["sol", "opus5"]',
        'lead         = "terra"\nrequires     = ["terra", "opus5"]', 1))
    assert docs_attack["chain_preference"][0]["lead"] == "terra", \
        "the docs-only attack fixture is stale — it no longer declares a docs-only lead"
    chk("a docs-only lead injected into role:impl makes CLAIM refuse",
        _claim(("area:gui", "role:impl"), docs_attack)[0], "refused")
    chk("...and makes PLAN refuse", _plan(_ROUTE.resolve, ("area:gui", "role:impl"),
                                          docs_attack)[0], "refused")
    chk("...so PLAN and CLAIM still AGREE on EVERY matrix row (a one-sided refusal here would be "
        "a permanent per-tick route-policy-failed defer, not a closed hole)",
        compare(docs_attack), [])
    # WHY a one-sided refusal is unconstructible, asserted rather than left to inspection: BOTH
    # sides' refusal is raised by the SAME `ChainPreferenceError` from the SAME shared module —
    # PLAN propagates it, CLAIM re-raises it as a PolicyError whose `__cause__` is that very error.
    def _refusal_origin():
        try:
            _ROUTE.resolve(["area:gui", "role:impl"], copy.deepcopy(docs_attack))
        except Exception as exc:  # noqa: BLE001 — the TYPE is the assertion
            plan_origin = type(exc).__name__
        else:
            plan_origin = "ROUTED"
        try:
            _POLICY.resolve(PROBE_REPO, ["area:gui", "role:impl"], PROBE_POLICY,
                            copy.deepcopy(docs_attack))
        except Exception as exc:  # noqa: BLE001
            claim_origin = type(exc.__cause__).__name__ if exc.__cause__ else type(exc).__name__
        else:
            claim_origin = "ROUTED"
        return plan_origin, claim_origin

    chk("both refusals originate in the SHARED parse-time module — which is WHY a split is "
        "unconstructible, rather than merely absent from today's fixtures",
        _refusal_origin(), ("ChainPreferenceError", "ChainPreferenceError"))
    # THE SWEEP. Every (lead, inject_roles) shape, decided by BOTH resolvers. The first row is the
    # symmetry property; the second pins WHICH shapes are refused, so a mutant that deletes the
    # bound reds here (the docs-only-into-non-docs rows become "routed") instead of passing because
    # both sides agreed on the wrong answer.
    def _both(lead, requires, inject_roles):
        decl = f'\n[[chain_preference]]\nlabels = ["area:gui"]\nlead = "{lead}"\n' \
               f'requires = {json.dumps(requires)}\n'
        if inject_roles is not None:
            decl += f'inject_roles = {json.dumps(inject_roles)}\n'
        doc = tomllib.loads(_single + decl)
        role_labels = ("area:gui", "role:docs") if inject_roles == ["docs"] \
            else ("area:gui", "role:impl")
        return (_plan(_ROUTE.resolve, role_labels, doc)[0], _claim(role_labels, doc)[0],
                compare(doc))

    sweep = {
        "terra lead -> role:impl": ("terra", ["terra", "opus5"], ["impl"]),
        "sonnet lead -> role:impl": ("sonnet", ["sonnet", "opus5"], ["impl"]),
        "terra lead -> role:impl AND role:docs": ("terra", ["terra", "opus5"], ["docs", "impl"]),
        "terra lead -> role:docs only": ("terra", ["terra", "opus5"], ["docs"]),
        "terra lead, NO inject_roles (re-order only)": ("terra", ["terra", "opus5"], None),
        "sol lead -> role:impl (THE LIVE SHAPE)": ("sol", ["sol", "opus5"], ["impl"]),
        "sol lead, NO inject_roles": ("sol", ["sol", "opus5"], None),
    }
    outcomes = {name: _both(*args) for name, args in sweep.items()}
    chk("SYMMETRY: for every (lead, inject_roles) shape, PLAN and CLAIM reach the SAME outcome — "
        "one resolver refusing while the other accepts is not merely absent, it is impossible "
        "because the refusal is decided by the one module they share",
        sorted(name for name, (plan, claim, _rows) in outcomes.items() if plan != claim), [])
    chk("...and no shape produces a matrix disagreement on any other row either",
        sorted(name for name, (_p, _c, rows) in outcomes.items() if rows), [])
    chk("...and the REFUSED set is exactly the docs-only-lead-into-a-non-docs-role shapes (this is "
        "the row that reds if the parse-time bound is deleted)",
        sorted(name for name, (plan, _c, _r) in outcomes.items() if plan == "refused"),
        sorted(["terra lead -> role:impl", "sonnet lead -> role:impl",
                "terra lead -> role:impl AND role:docs"]))
    # NON-VACUITY of the accepted rows: they must actually ROUTE, and route to the intended chain.
    chk("the LIVE sol declaration is untouched by the bound — still sol-first at CLAIM and PLAN",
        (chain(single_inject, ("area:gui", "role:impl")),
         _plan(_ROUTE.resolve, ("area:gui", "role:impl"), single_inject)[1][0]),
        (["sol", "opus5"], ["sol", "opus5"]))
    docs_legit = tomllib.loads(_single + GUI_DECLARATION_INJECT.replace(
        'lead         = "sol"\nrequires     = ["sol", "opus5"]\ninject_roles = ["impl"]',
        'lead         = "terra"\nrequires     = ["terra", "opus5"]\ninject_roles = ["docs"]', 1))
    docs_legit["route"] = [({**r, "model_chain": ["opus5"]} if r.get("role") == "docs" else r)
                           for r in docs_legit["route"]]
    chk("a docs-only lead injected into role:docs ROUTES, identically on both sides (the bound is "
        "the _reject_docs_only exemption mirrored, not a ban on docs-only leads)",
        (chain(docs_legit, ("area:gui", "role:docs")),
         _plan(_ROUTE.resolve, ("area:gui", "role:docs"), docs_legit)[1][0]),
        (["terra", "opus5"], ["terra", "opus5"]))

    # (4) NON-VACUITY OF THE HARNESS ITSELF. Give PLAN a resolver that knows a rule CLAIM does not
    # — the exact sparq #4211 shape, a carve-out implemented only in the target's Python — and the
    # comparison MUST report it. Without this the whole harness could be a function that returns
    # [] unconditionally.
    def plan_with_private_rule(labels, doc):
        chain_, agent, escalate = _ROUTE.resolve(labels, doc)
        if "area:gui" in set(labels) and {"sol", "opus5"} <= set(chain_):
            chain_ = ["sol"] + [m for m in chain_ if m != "sol"]
        return chain_, agent, escalate

    private = compare(undeclared, plan_resolver=plan_with_private_rule)
    chk("a PLAN-only carve-out (the #4211 defect, reproduced) is REPORTED, not silently tolerated",
        sorted(labels for _n, labels, _p, _c in private),
        sorted([("area:gui",), ("area:gui", "role:ci"), ("area:gui", "role:impl"),
                ("area:gui", "role:impl", "priority:P2"), ("area:gui", "role:perf"),
                ("area:gui", "role:site")]))
    chk("the reported rows name BOTH chains, so the diagnostic is actionable",
        [(p[1][0], c[1][0]) for _n, labels, p, c in private
         if labels == ("area:gui", "role:impl")],
        [(["sol", "opus5"], ["opus5", "sol"])])
    # (5) ...and the mirror image: a CLAIM-only rule (this registry PR merging while the target
    # still declares nothing, had the rule been hard-coded here) is reported too.
    claim_only = compare(undeclared, policy_doc=PROBE_POLICY,
                         plan_resolver=lambda labels, doc: _ROUTE.resolve(labels, undeclared))
    chk("a table with no declaration produces no CLAIM-only drift either", claim_only, [])
    hard_coded = compare(declared,
                         plan_resolver=lambda labels, _doc: _ROUTE.resolve(labels, undeclared))
    chk("a CLAIM-only carve-out (registry ahead of the target) is REPORTED",
        sorted({labels for _n, labels, _p, _c in hard_coded}),
        sorted([("area:gui",), ("area:gui", "role:ci"), ("area:gui", "role:impl"),
                ("area:gui", "role:impl", "priority:P2"), ("area:gui", "role:perf"),
                ("area:gui", "role:site")]))

    # (6) A REFUSAL is a first-class outcome: the two resolvers must agree about which label sets
    # never route. A PLAN resolver that routes where CLAIM refuses is a disagreement.
    broken = copy.deepcopy(declared)
    broken["chain_preference"] = [{"labels": ["area:gui"], "lead": "sol", "requires": ["opus5"]}]
    chk("a malformed declaration makes CLAIM refuse", _claim(("area:gui", "role:impl"), broken)[0],
        "refused")
    chk("...and PLAN refuse identically, so the two still AGREE (fail-closed on BOTH sides, "
        "which is what stops a malformed table from routing on one side only)",
        compare(broken), [])
    chk("a PLAN resolver that routes where CLAIM refuses is REPORTED",
        [labels for _n, labels, _p, _c in compare(
            broken, plan_resolver=lambda labels, _doc: _ROUTE.resolve(labels, declared))][:1],
        [("area:gui", "role:impl")])

    # (7) The matrix itself must not silently shrink — an emptied matrix makes every check above
    # pass vacuously (the registry has been bitten by exactly this shape before).
    chk("the matrix covers the rows the maintainer directive turns on",
        sorted({labels for _n, labels in AGREEMENT_MATRIX} & {
            ("area:gui", "role:impl"), ("area:gui", "role:perf"), ("area:gui",),
            ("area:gui", "role:research"), ("area:site", "role:impl"),
            ("area:sparq-zk", "role:impl"), ("area:sparq-core", "role:impl")}),
        sorted([("area:gui",), ("area:gui", "role:impl"), ("area:gui", "role:perf"),
                ("area:gui", "role:research"), ("area:site", "role:impl"),
                ("area:sparq-core", "role:impl"), ("area:sparq-zk", "role:impl")]))
    chk("every matrix row is distinct", len({labels for _n, labels in AGREEMENT_MATRIX}),
        len(AGREEMENT_MATRIX))

    # (8) The registry's OWN live routing table: PLAN and CLAIM must agree on it too. It declares
    # no preference (this repo has no `area:gui`), so this pins the no-op end to end on real data.
    live_path = _HERE.parent / "orchestration" / "routing.toml"
    with open(live_path, "rb") as handle:
        live = tomllib.load(handle)
    live_matrix = tuple((n, lb) for n, lb in AGREEMENT_MATRIX
                        if not ({x for x in lb if x.startswith("role:")}
                                - {"role:impl", "role:site", "role:ci", "role:research",
                                   "role:docs"}))
    chk("PLAN and CLAIM agree on the registry's OWN live routing table",
        compare(live, matrix=live_matrix), [])
    chk("the live-table matrix is not empty", len(live_matrix) > 10, True)

    print("cross-resolver-agreement self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="Assert the PLAN and CLAIM resolvers derive identical routes.")
    ap.add_argument("--self-test", action="store_true", help="run offline fixture tests")
    ap.add_argument("--routing-file", help="routing TOML to check")
    ap.add_argument("--target-root",
                    help="a target repository checkout: use ITS scripts/route-resolve.py as PLAN")
    ap.add_argument("--json", action="store_true", help="emit the disagreement report as JSON")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if not args.routing_file and not args.target_root:
        ap.error("one of --self-test, --routing-file or --target-root is required")

    plan_resolver = None
    routing_file = args.routing_file
    if args.target_root:
        plan_resolver = target_resolver(args.target_root)
        if not routing_file:
            routing_file = Path(args.target_root) / "orchestration" / "routing.toml"
    with open(routing_file, "rb") as handle:
        routing_doc = tomllib.load(handle)

    bad = compare(routing_doc, plan_resolver=plan_resolver)
    if args.json:
        print(json.dumps([{"case": n, "labels": list(lb), "plan": p[0],
                           "plan_route": p[1] if p[0] == "routed" else None, "claim": c[0],
                           "claim_route": c[1] if c[0] == "routed" else None}
                          for n, lb, p, c in bad], sort_keys=True))
    else:
        for name, labels, plan, claim in bad:
            print(f"DISAGREE {name} {sorted(labels)}\n  PLAN : {plan}\n  CLAIM: {claim}")
    if bad:
        print(f"::error::PLAN and CLAIM disagree on {len(bad)} of {len(AGREEMENT_MATRIX)} routing "
              f"cases for {routing_file} — every affected issue would defer "
              f"`route-policy-failed` on EVERY tick", file=sys.stderr)
        return 1
    print(f"agreement OK: PLAN and CLAIM derive identical routes for all "
          f"{len(AGREEMENT_MATRIX)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
