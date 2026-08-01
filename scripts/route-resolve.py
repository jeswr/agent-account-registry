#!/usr/bin/env python3
# Registry self-management: the routing resolver for jeswr/agent-account-registry.
# A copy of the sparq target's scripts/route-resolve.py; dispatch-plan.py imports resolve().
"""route-resolve.py — resolve an issue's labels to (model_chain, agent, escalate).

PRECEDENCE: security-label override > explicit role > [defaults]. This MUST match the CLAIM-side
resolver (policy-resolve.resolve) exactly, or a plan the PLANNER computes is rejected by CLAIM. The
resolution is TWO-PHASE and ORDER-INDEPENDENT: EVERY security-label rule (`match_labels`) is
evaluated before ANY role rule, so a security surface wins even when a role block happens to be
listed before it in routing.toml. Within each phase the first match wins. `match_labels` rules match
if any listed keyword is a SUBSTRING of any issue label (so `worker` matches `area:worker`,
`dispatch` matches `area:dispatch`, etc.). An `impl` issue that also touches `area:worker` therefore
routes to Opus (soundness), not Fable, regardless of where the security block sits in the file.
"""
import copy
import importlib.util
from pathlib import Path
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


def _sibling(module_name, filename):
    """Import a sibling script by path — these scripts are invoked standalone, so there is no
    package to import from, but a SHARED rule must still be imported rather than re-declared."""
    path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_DEP = _sibling("registry_deprecated_models", "deprecated_models.py")
# [OPUS-5] The chain-order preference MECHANISM — the identical module policy-resolve.py (the CLAIM
# side) imports. The rule itself is DATA in this routing table's `[[chain_preference]]` block, so
# PLAN and CLAIM read one declaration and cannot drift apart about what it says.
_PREF = _sibling("registry_chain_preference", "chain_preference.py")


def validate_catalog(doc):
    """[OPUS-5] FAIL CLOSED on a retired model in the [models] CATALOG.

    Found by mutation-testing this very change: re-adding `[models.fable]` to
    orchestration/routing.toml SURVIVED every registry self-test. policy-resolve rejects an unknown
    model in a CHAIN, and the shared register guards REVIEW_CHAIN/FIX_CHAIN/ESCALATION_LADDERS —
    but nothing guarded the catalog itself. A resurrected catalog entry is the first half of a
    resurrected route: it makes `fable` resolvable again, so the next edit that adds it to a chain
    passes every check. Guard the catalog, not only the chains.
    """
    _DEP.assert_catalog_clean(doc.get("models", {}))


class RoleResolutionError(ValueError):
    """Base for a fail-closed role-validation failure: a malformed role:* set must DEFER/DIE, never
    resolve to a permissive default. resolve() raises a SUBCLASS so a caller (dispatch-plan) can
    reject the issue as one class. Mirrors policy-resolve.resolve (the CLAIM-side resolver), which
    raises PolicyError on the SAME three malformed-role cases — empty value, ambiguous set, unknown
    role — all BEFORE any route match, so PLAN and CLAIM agree on which issues never route (#122).
    """


class AmbiguousRoleError(RoleResolutionError):
    """More than one distinct role:* label — reject, never guess. Mirrors policy-resolve's
    ``len(roles) > 1`` check. resolve() distinguishes this from a ROLELESS issue (which legitimately
    routes to security/defaults) so ambiguous input can never fall to a permissive default (#122).
    """


class EmptyRoleError(RoleResolutionError):
    """A role:* label with an EMPTY value (a bare ``role:``). Mirrors policy-resolve's
    ``any(not role ...)`` check. Without it ``role`` became "" and, matching no role route, fell
    through to Phase-3 defaults — a permissive route CLAIM rejects (empty role value).
    """


class UnknownRoleError(RoleResolutionError):
    """A single role with NO explicit role route in routing.toml. Mirrors policy-resolve's
    ``role not in role_routes`` check. Without it an unconfigured role fell through to Phase-3
    defaults (or became a default-routed planner row), only to be rejected downstream at CLAIM —
    the exact PLAN/CLAIM divergence this resolver exists to prevent. Must DIE here, not route.
    """


# [#1397] The ROLE-DIRECTED PERSONA flag, mirrored from the CLAIM-side resolver
# (policy-resolve.AGENT_FROM_ROLE_KEY — read its comment for the why). A `match_labels` override
# that declares `agent_from_role = true` supplies the model_chain + escalate, while the PERSONA
# comes from the issue's own `role = "<role>"` row: the security keywords on this repo
# (worker/dispatch/review-loop/...) match the surfaces most in need of IMPLEMENTATION, and the
# override named the VERDICT-ONLY reviewer, so every implementation run on a trust-surface issue was
# handed a brief that forbids editing. The keyword list, the chain and `escalate` are untouched, so
# the arm-side security classifier and the escalation posture are exactly as before.
AGENT_FROM_ROLE_KEY = "agent_from_role"


def validate_agent_from_role(doc):
    """FAIL CLOSED on a malformed / misplaced `agent_from_role`, exactly as CLAIM does.

    Validated over EVERY route (and `[defaults]`), not only the matched one, so PLAN and CLAIM
    refuse the SAME tables: a declaration CLAIM raises on and PLAN silently ignores is a route PLAN
    plans and CLAIM rejects — a permanent per-item `route-policy-failed` defer, not a lost setting.
    """
    tables = [("routing defaults", doc.get("defaults", {}), False)]
    for index, route in enumerate(doc.get("route", [])):
        if isinstance(route, dict):
            tables.append((f"routing route #{index + 1}", route, "match_labels" in route))
    for where, table, allowed in tables:
        if not isinstance(table, dict):
            continue
        if AGENT_FROM_ROLE_KEY in table and not allowed:
            raise ValueError(
                f"{where} may not set {AGENT_FROM_ROLE_KEY}: it directs a SECURITY override's "
                "persona at the issue's own role route, so it is meaningful only on a "
                "match_labels route")
        # PRESENT means OPT-IN, so the only accepted value is the boolean `true`. An explicit
        # `false` is value-identical to omitting the key — the same inert declaration refused above
        # on a role row / in [defaults] — and being value-identical, no agreement row could catch
        # it. Omit the key to get the undeclared behaviour.
        if AGENT_FROM_ROLE_KEY in table and table[AGENT_FROM_ROLE_KEY] is not True:
            raise ValueError(
                f"{where} {AGENT_FROM_ROLE_KEY} must be the boolean true when declared: it is an "
                "explicit opt-in, so any other value (including false) is an inert declaration — "
                "omit the key instead")


def resolve(labels, doc):
    """Return (model_chain, agent, escalate). `labels`: iterable of the issue's labels.

    Two-phase precedence, identical to policy-resolve.resolve (the CLAIM-side resolver) so PLAN and
    CLAIM never diverge on a reordered routing.toml (#121): ALL security-label rules are evaluated
    before ANY role rule; within each phase the first match wins. The old single-pass first-match
    let a role block that preceded a matching security block win, planning a chain CLAIM rejects.

    RAISES a RoleResolutionError subclass for a MALFORMED role:* set — more than one distinct role
    (AmbiguousRoleError), an empty value like a bare ``role:`` (EmptyRoleError), or a single role
    with no explicit role route (UnknownRoleError). All three checks precede route matching (exactly
    as in policy-resolve.resolve: empty > ambiguous > unknown, then routing), so a malformed issue
    can never resolve to a security/role/defaults route regardless of a caller's own precheck.
    """
    validate_catalog(doc)   # [OPUS-5] a retired model must not even be RESOLVABLE
    # [OPUS-5] Parsed BEFORE any route match, so a malformed declaration refuses to resolve rather
    # than resolving to a chain CLAIM would reject. ChainPreferenceError is a ValueError, the same
    # fail-closed class dispatch-plan already handles.
    preferences = _PREF.parse_preferences(doc, set(doc.get("models", {})))
    validate_agent_from_role(doc)   # [#1397] refuse the same tables CLAIM refuses
    labels = set(labels)
    routes = doc.get("route", [])
    # The explicit role routes declared in routing.toml (role blocks, never security blocks); the
    # unknown-role guard rejects any role absent from this set, mirroring policy-resolve's role_routes.
    role_routes = {r.get("role") for r in routes if "match_labels" not in r and "role" in r}

    # SINGLE declared role, or None when ROLELESS. A malformed set fails closed here, BEFORE any
    # route match (same order as policy-resolve.resolve), so it can never slip into a security/role/
    # defaults route: returning None collapsed ambiguity/empty/unknown into the roleless case and let
    # a malformed issue fall to a permissive default — a chain CLAIM rejects, stranding the issue.
    roles = {lb[5:] for lb in labels if lb.startswith("role:")}
    if any(not r for r in roles):
        raise EmptyRoleError("empty role:* value — exactly one non-empty role:* required")
    if len(roles) > 1:
        raise AmbiguousRoleError(
            f"ambiguous role labels: {', '.join(sorted(roles))} — exactly one role:* required")
    role = next(iter(roles)) if roles else None
    if role is not None and role not in role_routes:
        raise UnknownRoleError(
            f"unknown role {role!r} — no matching role route in routing.toml")

    # Phase 1 — security-label overrides: any keyword is a substring of any label; first match wins.
    # Returned UNMODIFIED: a chain-order preference expresses which IMPLEMENTOR is preferred and
    # must never re-order a soundness chain. policy-resolve (CLAIM) makes the same exemption.
    for r in routes:
        kws = r.get("match_labels")
        if kws and any(k in lb for lb in labels for k in kws):
            agent = r["agent"]
            # [#1397] The persona — and ONLY the persona — may be directed at the issue's own role
            # row. `role` is a declared role route by construction (the unknown-role guard above),
            # and a ROLELESS issue has no row to direct from, so it keeps the override's own agent.
            if r.get(AGENT_FROM_ROLE_KEY) is True and role is not None:
                agent = next(rr["agent"] for rr in routes
                             if "match_labels" not in rr and rr.get("role") == role)
            return r["model_chain"], agent, bool(r.get("escalate"))
    # Phase 2 — explicit role route (only role blocks, never a security block).
    if role is not None:
        for r in routes:
            if "match_labels" not in r and r.get("role") == role:
                # `role=` is what lets a preference's `inject_roles` allow-list be evaluated (adding
                # the lead to a chain that lacks it is legal only for the roles the DECLARATION
                # names). policy-resolve passes the same value at the same point.
                return (_PREF.apply_preferences(labels, r["model_chain"], preferences, role=role),
                        r["agent"], bool(r.get("escalate")))
    # Phase 3 — defaults (no security match and no role). role is None here BY CONSTRUCTION, so a
    # roleless issue can never be injected into — passed explicitly rather than left to the default.
    d = doc.get("defaults", {})
    return (_PREF.apply_preferences(labels, d.get("model_chain", []), preferences, role=None),
            d.get("agent"), False)


def _self_test():
    doc = tomllib.load(open("orchestration/routing.toml", "rb"))
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    def raises(n, exc_type, fn):
        nonlocal ok
        try:
            fn()
        except exc_type as exc:
            good, detail = True, f"raised {exc_type.__name__}: {exc}"
        except Exception as exc:  # a DIFFERENT exception is still a failure (wrong fail-closed class)
            good, detail = False, f"raised {type(exc).__name__} (want {exc_type.__name__})"
        else:
            good, detail = False, "did NOT raise (routed instead)"
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {detail}")

    # impl + a trust surface (area:worker) -> security rule wins over role -> Opus-5-led
    # (opus tail fallback, 2026-07-24), escalate.
    #
    # [#1397] ...and since the override DECLARES `agent_from_role = true`, the PERSONA comes from
    # the `role = "impl"` row: the chain and escalate are the security override's (unchanged), the
    # brief is the IMPLEMENTER's. Before that declaration this row read `registry-reviewer` — a
    # verdict-only brief ("never a fix", Read/Glob/Grep, byte-identical tree) handed to an
    # IMPLEMENTATION run, which is the whole defect.
    mc, ag, esc = resolve(["role:impl", "area:worker"], doc)
    chk("impl+worker -> opus5-led/escalate, IMPLEMENTER persona", (mc, ag, esc),
        (["opus5"], "registry-impl", True))
    # dispatch is a trust surface too.
    mc, ag, esc = resolve(["role:impl", "area:dispatch"], doc)
    chk("impl+dispatch -> opus5/escalate", (mc, esc), (["opus5"], True))
    # [#1397] BOTH DIRECTIONS at the seam, on the LIVE table: an implementation lane on a trust
    # surface gets a persona whose real brief authorises editing, a review lane still gets the
    # verdict-only reviewer. The briefs are read, not assumed — this is the file worker-live.sh
    # loads with --append-system-prompt-file.
    _briefs = Path(__file__).resolve().parents[1] / ".claude" / "agents"
    _MUTATES = "edits the current checkout only"
    for _labels, _want_agent, _want_mutates in (
            (["role:impl", "area:review-loop"], "registry-impl", True),
            (["role:impl", "area:groom"], "registry-impl", True),
            (["role:docs", "area:worker"], "registry-docs", True),
            (["role:review", "area:review-loop"], "registry-reviewer", False),
            (["area:review-loop"], "registry-reviewer", False)):   # ROLELESS: no row to direct from
        _agent = resolve(_labels, doc)[1]
        _text = (_briefs / f"{_agent}.md").read_text(encoding="utf-8").lower()
        chk(f"[#1397] {_labels} -> a persona whose REAL brief matches the lane",
            (_agent, _MUTATES in _text), (_want_agent, _want_mutates))
    # NON-VACUOUS: strip the declaration and the implementation lane resolves the verdict-only
    # reviewer again, so the rows above pin the declaration and not merely the table's shape.
    _stripped = copy.deepcopy(doc)
    for _row in _stripped["route"]:
        _row.pop(AGENT_FROM_ROLE_KEY, None)
    chk("[#1397] RED: without the declaration an IMPLEMENTATION lane is handed the verdict-only "
        "persona again", resolve(["role:impl", "area:review-loop"], _stripped)[1],
        "registry-reviewer")
    chk("[#1397] ...and the declaration changes ONLY the persona (chain + escalate identical)",
        resolve(["role:impl", "area:review-loop"], _stripped)[0::2],
        resolve(["role:impl", "area:review-loop"], doc)[0::2])
    # A malformed / misplaced declaration must REFUSE here exactly as it does at CLAIM, or PLAN
    # plans a route CLAIM rejects on every tick.
    for _where, _mutate in (
            ("a non-boolean value", lambda d: d["route"][0].update({AGENT_FROM_ROLE_KEY: "true"})),
            # an explicit `false` is the one bad value that RESOLVES identically to the absent key,
            # so only refusing it — on both sides — can surface the typo at all.
            ("an explicit FALSE (an inert declaration)",
             lambda d: d["route"][0].update({AGENT_FROM_ROLE_KEY: False})),
            ("a ROLE route", lambda d: d["route"][2].update({AGENT_FROM_ROLE_KEY: True})),
            ("[defaults]", lambda d: d["defaults"].update({AGENT_FROM_ROLE_KEY: True}))):
        _bad = copy.deepcopy(doc)
        _mutate(_bad)
        raises(f"[#1397] agent_from_role on {_where} refuses to resolve (PLAN must refuse the "
               "tables CLAIM refuses)", ValueError,
               lambda d=_bad: resolve(["role:impl", "area:usage"], d))
    # [OPUS-5] a NON-trust area (usage) -> plain impl -> OPUS5-ONLY + escalate (maintainer decision
    # 2026-07-26 on the registry #738 measurement: "Remove sol from impl fallback"; sol converted
    # 18% vs opus5 86% in-cell, n=74). The FULL tuple is asserted, not just the head, so demoting
    # sol back to a second rung reds this instead of passing on `mc[0] == "opus5"`.
    mc, ag, esc = resolve(["role:impl", "area:usage"], doc)
    chk("impl+usage -> OPUS5-ONLY, escalating", (mc, ag, esc),
        (["opus5"], "registry-impl", True))
    chk("role:impl names NO openai tier at all (exclusion, not a demotion)",
        sorted({doc["models"][m]["provider"] for m in mc}), ["anthropic"])
    chk("role:impl ESCALATES, so a single-rung chain has a machine exit rather than deferring "
        "forever with nobody notified", esc, True)
    # [OPUS-5] docs -> SOL-led (maintainer 2026-07-26: "deprecate sonnet and haiku for docs
    # writing in favor of gpt 5.6 sol"). The second assertion is the one that reds if either
    # cheap anthropic tier is put back into the docs chain.
    chk("docs -> sol", resolve(["role:docs", "area:docs"], doc)[0][0], "sol")
    chk("docs chain has no cheap anthropic tier",
        sorted(set(resolve(["role:docs", "area:docs"], doc)[0]) & {"haiku", "sonnet"}), [])
    # [FABLE-5] frontier-tier infra authorship (standing rule 2026-07-17): ci -> sol-led
    # (sol/opus5/fable — opus5 primary anthropic tier since 2026-07-24, fable its tail
    # fallback), FRONTIER-ONLY chain — no sub-frontier model (sonnet/haiku), so
    # chain exhaustion DEFERS at the claim step (defer-not-fallback) instead of degrading tier.
    mc, ag, esc = resolve(["role:ci", "area:ci"], doc)
    chk("ci -> frontier-only opus5-first (terra is docs-only)", (mc, ag, esc),
        (["opus5", "sol"], "registry-ci", False))
    chk("ci chain has no sub-frontier tier", sorted(set(mc) & {"sonnet", "haiku"}), [])
    # [OPUS-5] no role -> defaults, now OPUS5-led (maintainer 2026-07-26: opus5 is preferred over
    # sol wherever both are viable implementors). This repo has no `area:gui`, so it carries no
    # sol carve-out — every implementor route here takes the opus5-first default.
    chk("no role -> defaults", resolve(["area:usage"], doc)[0][0], "opus5")
    # `role:impl` is deliberately NOT in this loop since 2026-07-26 — it is the one implementor
    # route where sol was REMOVED rather than demoted, and it is asserted separately above. Every
    # OTHER implementor route keeps sol as a reachable fallback (preference, not exclusion).
    for _role in ("site", "ci"):
        _mc = resolve([f"role:{_role}"], doc)[0]
        chk(f"role:{_role} prefers opus5 over sol", _mc[0], "opus5")
        chk(f"role:{_role} keeps sol reachable (preference, not exclusion)", "sol" in _mc, True)
        chk(f"role:{_role} chain is cross-provider (terminates under either outage)",
            sorted({doc["models"][m]["provider"] for m in _mc}), ["anthropic", "openai"])
    # ...and the exclusion is EXACTLY role:impl. This is the guard that reds if a future edit
    # copies the exclusion onto a route the maintainer did not scope it to.
    chk("the ONLY route with no openai rung among the implementor routes is role:impl",
        sorted(r for r in ("impl", "site", "ci", "docs")
               if not any(doc["models"][m]["provider"] == "openai"
                          for m in resolve([f"role:{r}"], doc)[0])),
        ["impl"])
    chk("docs KEEPS its sol lead (the separate docs-writing directive)",
        resolve(["role:docs"], doc)[0][0], "sol")

    # [OPUS-5] THE CATALOG GUARD, mutation-found. Re-adding [models.fable] to the LIVE routing
    # table survived every registry self-test before this assertion existed.
    import copy as _copy
    _resurrected = _copy.deepcopy(doc)
    _resurrected["models"]["fable"] = {"provider": "anthropic", "harness": "claude",
                                       "provider_model": "claude-fable-5",
                                       "credential_format": "claude-oauth-token"}
    try:
        resolve(["role:impl"], _resurrected)
    except _DEP.DeprecatedModelError as exc:
        chk("a resurrected [models.fable] catalog entry REFUSES to resolve",
            "retired alias" in str(exc), True)
    else:
        chk("a resurrected [models.fable] catalog entry REFUSES to resolve", "resolved", "refused")
    _smuggled = _copy.deepcopy(doc)
    _smuggled["models"]["legacy"] = {"provider": "anthropic", "harness": "claude",
                                     "provider_model": "claude-opus-4-8",
                                     "credential_format": "claude-oauth-token"}
    try:
        resolve(["role:impl"], _smuggled)
    except _DEP.DeprecatedModelError as exc:
        chk("a retired provider id under a fresh alias REFUSES to resolve",
            "retired provider_model" in str(exc), True)
    else:
        chk("a retired provider id under a fresh alias REFUSES to resolve", "resolved", "refused")
    chk("the LIVE catalog defines no retired alias",
        sorted(set(doc["models"]) & _DEP.DEPRECATED_ALIASES), [])
    # [#122] an AMBIGUOUS multi-role set is REJECTED, never silently routed. An earlier resolver
    # returned None for >1 role, collapsing ambiguity into the roleless case so the set fell to a
    # security/defaults route (a default-allow path for any caller that skips the planner precheck).
    # resolve now RAISES AmbiguousRoleError, mirroring policy-resolve.resolve (CLAIM), which raises
    # PolicyError on multiple roles. Non-vacuous: the pre-fix code returned ("sol", ...) here.
    raises("ambiguous roles rejected, not routed to a default", AmbiguousRoleError,
           lambda: resolve(["role:impl", "role:docs", "area:usage"], doc))
    # the guard precedes route matching (as in policy-resolve), so a security label present on the
    # malformed issue does NOT let it slip past the ambiguity check into a security route.
    raises("ambiguous roles rejected even with a security label present", AmbiguousRoleError,
           lambda: resolve(["role:impl", "role:docs", "area:worker"], doc))
    # [#122 r2] a bare `role:` (EMPTY value) and an UNCONFIGURED `role:<name>` are ALSO rejected,
    # not routed to Phase-3 defaults — the CLAIM-side policy-resolve.resolve rejects an empty role
    # value and a role absent from role_routes, so PLAN must too or the two diverge. Non-vacuous:
    # the pre-fix resolver returned the permissive defaults chain (("sol", ...)) for BOTH inputs.
    raises("empty role value rejected, not routed to defaults", EmptyRoleError,
           lambda: resolve(["role:", "area:usage"], doc))
    raises("unknown role rejected, not routed to defaults", UnknownRoleError,
           lambda: resolve(["role:unknown", "area:usage"], doc))
    # like ambiguity, both malformed-single-role guards PRECEDE route matching, so a security label
    # on the malformed issue cannot let it slip into a security route (matches policy-resolve order).
    raises("empty role rejected even with a security label present", EmptyRoleError,
           lambda: resolve(["role:", "area:worker"], doc))
    raises("unknown role rejected even with a security label present", UnknownRoleError,
           lambda: resolve(["role:unknown", "area:worker"], doc))
    # a CONFIGURED single role with a matching route still resolves (guards do not over-reject).
    chk("configured role still routes", resolve(["role:research"], doc)[1], "registry-researcher")
    # review role -> opus + escalate.
    chk("review -> opus/escalate", resolve(["role:review"], doc)[1:], ("registry-reviewer", True))

    # [#121] ORDER-INDEPENDENCE: security beats a role block listed BEFORE it. This is the exact
    # PLAN/CLAIM divergence — policy-resolve is two-phase, so route-resolve MUST be too. The fixture
    # deliberately puts the role route first: the old single-pass first-match returned the ROLE
    # chain here (would FAIL), the two-phase resolver returns the SECURITY chain. Non-vacuous: the
    # first check flips red on the pre-fix code.
    reordered = tomllib.loads('''
[defaults]
model_chain = ["fable"]
agent = "default-agent"

[[route]]
role = "impl"
model_chain = ["fable", "haiku"]
agent = "impl-agent"

[[route]]
match_labels = ["worker", "dispatch"]
model_chain = ["opus"]
agent = "security-agent"
escalate = true
''')
    chk("security beats a role listed before it (order-independent)",
        resolve(["role:impl", "area:worker"], reordered), (["opus"], "security-agent", True))
    chk("role still resolves when no security label matches",
        resolve(["role:impl", "area:usage"], reordered), (["fable", "haiku"], "impl-agent", False))
    chk("no security + no matching role -> defaults",
        resolve(["area:usage"], reordered), (["fable"], "default-agent", False))

    # ---- [OPUS-5] THE DOCS-ONLY BOUND ON `inject_roles`, ON THE PLAN SIDE.
    # THIS resolver has NO docs-only rule of its own: `_reject_docs_only` is a CLAIM-side
    # (policy-resolve) control over statically declared chains. That is precisely why the bound on
    # the INJECTED lead lives in the SHARED `chain_preference` module — enforcing it only on the
    # CLAIM side would make CLAIM refuse while PLAN routed, which `_route_matches` turns into a
    # permanent per-tick `route-policy-failed` defer rather than a closed hole. These rows assert
    # PLAN refuses the identical declaration, so the two sides cannot split.
    _pref_doc = _copy.deepcopy(doc)
    _pref_doc["route"] = [r for r in _pref_doc["route"] if "match_labels" not in r]
    _attack = _copy.deepcopy(_pref_doc)
    _attack["chain_preference"] = [{"labels": ["area:gui"], "lead": "terra",
                                    "requires": ["terra", "opus5"], "inject_roles": ["impl"]}]
    raises("PLAN refuses a DOCS-ONLY lead injected into role:impl, at parse time — the same "
           "refusal the CLAIM-side resolver gives, from the same shared module",
           _PREF.ChainPreferenceError,
           lambda: resolve(["area:gui", "role:impl"], _attack))
    raises("...and refuses it for an issue the selector does NOT even match, because a bad "
           "DECLARATION is refused when the table is READ, not when an issue happens to select it",
           _PREF.ChainPreferenceError,
           lambda: resolve(["area:usage", "role:impl"], _attack))
    _docs_ok = _copy.deepcopy(_pref_doc)
    _docs_ok["chain_preference"] = [{"labels": ["area:gui"], "lead": "terra",
                                     "requires": ["terra", "opus5"], "inject_roles": ["docs"]}]
    _docs_ok["route"] = [({**r, "model_chain": ["opus5"]} if r.get("role") == "docs" else r)
                         for r in _docs_ok["route"]]
    chk("...but a docs-only lead injected into role:docs still RESOLVES at PLAN (the bound mirrors "
        "the _reject_docs_only EXEMPTION, so it is not a blanket ban)",
        resolve(["area:gui", "role:docs"], _docs_ok)[0], ["terra", "opus5"])
    # THE LIVE SHAPE sparq SHIPS: `lead = "sol"` + `inject_roles = ["impl"]`. Unchanged by the
    # bound.
    _live_shape = _copy.deepcopy(_pref_doc)
    _live_shape["chain_preference"] = [{"labels": ["area:gui"], "lead": "sol",
                                        "requires": ["sol", "opus5"], "inject_roles": ["impl"]}]
    chk("the LIVE area:gui carve-out (lead = sol, inject_roles = [impl]) still injects sol-first "
        "into the single-rung impl chain at PLAN",
        resolve(["area:gui", "role:impl"], _live_shape)[0], ["sol", "opus5"])
    chk("...and a non-gui impl issue is still OPUS5-ONLY under that same declaration",
        resolve(["area:usage", "role:impl"], _live_shape)[0], ["opus5"])

    print("route-resolve self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv:
        return _self_test()
    if len(sys.argv) > 1:
        doc = tomllib.load(open("orchestration/routing.toml", "rb"))
        mc, ag, esc = resolve(sys.argv[1].split(","), doc)
        print(f"model_chain={mc} agent={ag} escalate={esc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
