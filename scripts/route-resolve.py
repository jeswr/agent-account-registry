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


class AmbiguousRoleError(ValueError):
    """A malformed issue carries more than one role:* label — reject, never guess (fail-closed).

    Mirrors policy-resolve.resolve (the CLAIM-side resolver), which raises PolicyError on multiple
    roles. resolve() distinguishes this from a ROLELESS issue (which legitimately routes to
    security/defaults) so ambiguous input can never fall through to a permissive default (#122).
    """


def resolve(labels, doc):
    """Return (model_chain, agent, escalate). `labels`: iterable of the issue's labels.

    Two-phase precedence, identical to policy-resolve.resolve (the CLAIM-side resolver) so PLAN and
    CLAIM never diverge on a reordered routing.toml (#121): ALL security-label rules are evaluated
    before ANY role rule; within each phase the first match wins. The old single-pass first-match
    let a role block that preceded a matching security block win, planning a chain CLAIM rejects.

    RAISES AmbiguousRoleError when the issue carries more than one distinct role:* label — the
    ambiguity guard precedes route matching (as in policy-resolve.resolve), so a malformed issue
    can never resolve to a security/defaults route regardless of a caller's own precheck.
    """
    labels = set(labels)

    def role_of(lbs):
        # The SINGLE declared role, or None when ROLELESS. RAISES on an AMBIGUOUS set (>1 distinct
        # role:*) rather than silently returning None: returning None collapsed ambiguity into the
        # roleless case and let a multi-role issue fall to a security/defaults route (default-allow)
        # for any caller that skips the planner precheck. This matches policy-resolve.resolve, which
        # REJECTS multiple roles, and complements the planner (dispatch-plan.plan_dispatch), which
        # skips an ambiguous issue before it reaches here (#122). Never picks one of several roles.
        roles = {lb[5:] for lb in lbs if lb.startswith("role:")}
        if len(roles) > 1:
            raise AmbiguousRoleError(
                f"ambiguous role labels: {', '.join(sorted(roles))} — exactly one role:* required")
        return next(iter(roles)) if roles else None

    role = role_of(labels)
    routes = doc.get("route", [])
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

    def raises_ambiguous(n, fn):
        nonlocal ok
        try:
            fn()
        except AmbiguousRoleError:
            good, detail = True, "raised AmbiguousRoleError"
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
    # [#122] an AMBIGUOUS multi-role set is REJECTED, never silently routed. The pre-fix role_of
    # returned None for >1 role, collapsing ambiguity into the roleless case so the set fell to a
    # security/defaults route (a default-allow path for any caller that skips the planner precheck).
    # resolve now RAISES AmbiguousRoleError, mirroring policy-resolve.resolve (CLAIM), which raises
    # PolicyError on multiple roles. Non-vacuous: the pre-fix code returned ("sol", ...) here.
    raises_ambiguous("ambiguous roles rejected, not routed to a default",
                     lambda: resolve(["role:impl", "role:docs", "area:usage"], doc))
    # the guard precedes route matching (as in policy-resolve), so a security label present on the
    # malformed issue does NOT let it slip past the ambiguity check into a security route.
    raises_ambiguous("ambiguous roles rejected even with a security label present",
                     lambda: resolve(["role:impl", "role:docs", "area:worker"], doc))
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
