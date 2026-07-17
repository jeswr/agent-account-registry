#!/usr/bin/env python3
# [OPUS-4.8] Registry self-management: the routing resolver for jeswr/agent-account-registry.
# A copy of the sparq target's scripts/route-resolve.py; dispatch-plan.py imports resolve().
"""route-resolve.py — resolve an issue's labels to (model_chain, agent, escalate).

PRECEDENCE: security-label override > explicit role > [defaults], FIRST MATCH WINS. `match_labels`
rules match if any listed keyword is a SUBSTRING of any issue label (so `worker` matches
`area:worker`, `dispatch` matches `area:dispatch`, etc.). Because the registry's routing.toml
lists its trust-surface security rule first, an `impl` issue that also touches `area:worker`
routes to Opus (soundness), not Fable.
"""
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


def resolve(labels, doc):
    """Return (model_chain, agent, escalate). `labels`: iterable of the issue's labels."""
    labels = set(labels)

    def role_of(lbs):
        for lb in lbs:
            if lb.startswith("role:"):
                return lb[5:]
        return None

    role = role_of(labels)
    for r in doc.get("route", []):
        kws = r.get("match_labels")
        if kws:  # security-label rule: any keyword is a substring of any label
            if any(k in lb for lb in labels for k in kws):
                return r["model_chain"], r["agent"], bool(r.get("escalate"))
        elif "role" in r and role is not None and r["role"] == role:
            return r["model_chain"], r["agent"], bool(r.get("escalate"))
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

    # impl + a trust surface (area:worker) -> security rule wins over role -> Opus, escalate.
    mc, ag, esc = resolve(["role:impl", "area:worker"], doc)
    chk("impl+worker -> opus/escalate", (mc, ag, esc), (["opus"], "registry-reviewer", True))
    # dispatch is a trust surface too.
    mc, ag, esc = resolve(["role:impl", "area:dispatch"], doc)
    chk("impl+dispatch -> opus/escalate", (mc, esc), (["opus"], True))
    # a NON-trust area (usage) -> plain impl -> Fable-led chain.
    mc, ag, esc = resolve(["role:impl", "area:usage"], doc)
    chk("impl+usage -> fable-led", (mc[0], ag, esc), ("fable", "registry-impl", False))
    # docs -> haiku-led.
    chk("docs -> haiku", resolve(["role:docs", "area:docs"], doc)[0][0], "haiku")
    # [FABLE-5] frontier-tier infra authorship (standing rule 2026-07-17): ci -> fable-first,
    # FRONTIER-ONLY chain — no sub-frontier model (sonnet/haiku), so chain exhaustion DEFERS at
    # the claim step (defer-not-fallback) instead of degrading tier.
    mc, ag, esc = resolve(["role:ci", "area:ci"], doc)
    chk("ci -> frontier-only fable-first", (mc, ag, esc), (["fable", "terra"], "registry-ci", False))
    chk("ci chain has no sub-frontier tier", sorted(set(mc) & {"sonnet", "haiku"}), [])
    # no role -> defaults (fable-led).
    chk("no role -> defaults", resolve(["area:usage"], doc)[0][0], "fable")
    # review role -> opus + escalate.
    chk("review -> opus/escalate", resolve(["role:review"], doc)[1:], ("registry-reviewer", True))
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
