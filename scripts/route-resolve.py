#!/usr/bin/env python3
# [OPUS-4.8] Registry self-management: the routing resolver for jeswr/agent-account-registry.
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
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


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
    for r in routes:
        kws = r.get("match_labels")
        if kws and any(k in lb for lb in labels for k in kws):
            return r["model_chain"], r["agent"], bool(r.get("escalate"))
    # Phase 2 — explicit role route (only role blocks, never a security block).
    if role is not None:
        for r in routes:
            if "match_labels" not in r and r.get("role") == role:
                return r["model_chain"], r["agent"], bool(r.get("escalate"))
    # Phase 3 — defaults (no security match and no role).
    d = doc.get("defaults", {})
    return d.get("model_chain", []), d.get("agent"), False


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

    # impl + a trust surface (area:worker) -> security rule wins over role -> Opus, escalate.
    mc, ag, esc = resolve(["role:impl", "area:worker"], doc)
    chk("impl+worker -> opus/escalate", (mc, ag, esc), (["opus"], "registry-reviewer", True))
    # dispatch is a trust surface too.
    mc, ag, esc = resolve(["role:impl", "area:dispatch"], doc)
    chk("impl+dispatch -> opus/escalate", (mc, esc), (["opus"], True))
    # a NON-trust area (usage) -> plain impl -> sol-led chain (sol-first routing, 2026-07-18).
    mc, ag, esc = resolve(["role:impl", "area:usage"], doc)
    chk("impl+usage -> sol-led", (mc[0], ag, esc), ("sol", "registry-impl", False))
    # docs -> haiku-led.
    chk("docs -> haiku", resolve(["role:docs", "area:docs"], doc)[0][0], "haiku")
    # [FABLE-5] frontier-tier infra authorship (standing rule 2026-07-17): ci -> sol-led
    # (sol/fable, 2026-07-18), FRONTIER-ONLY chain — no sub-frontier model (sonnet/haiku), so
    # chain exhaustion DEFERS at the claim step (defer-not-fallback) instead of degrading tier.
    mc, ag, esc = resolve(["role:ci", "area:ci"], doc)
    chk("ci -> frontier-only sol-first (terra is docs-only)", (mc, ag, esc), (["sol", "fable"], "registry-ci", False))
    chk("ci chain has no sub-frontier tier", sorted(set(mc) & {"sonnet", "haiku"}), [])
    # no role -> defaults (sol-led, 2026-07-18).
    chk("no role -> defaults", resolve(["area:usage"], doc)[0][0], "sol")
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
