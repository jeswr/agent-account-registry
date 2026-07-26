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
