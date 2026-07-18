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


def validate_routing(doc):
    """Structural invariants a routing table must satisfy before ANY resolution — enforced in
    resolve() so a violating table fails LOUDLY at PLAN time instead of silently routing.
    Maintainer rule 2026-07-18: the cheap tiers `sonnet` and `terra` author NOTHING but docs —
    they may appear only in the model_chain of a route whose role == "docs" (never in defaults,
    a match_labels security rule, or any other role's chain)."""
    docs_only = {"sonnet", "terra"}
    offenders = []
    if docs_only & set(doc.get("defaults", {}).get("model_chain", [])):
        offenders.append("defaults")
    for r in doc.get("route", []):
        if docs_only & set(r.get("model_chain", [])) and r.get("role") != "docs":
            offenders.append(r.get("role") or ",".join(r.get("match_labels", [])) or "<unnamed>")
    if offenders:
        raise ValueError("routing violates the docs-only rule for sonnet/terra (maintainer "
                         "2026-07-18) in: " + "; ".join(offenders))


def resolve(labels, doc):
    """Return (model_chain, agent, escalate). `labels`: iterable of the issue's labels."""
    validate_routing(doc)
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
    chk("ci -> frontier-only fable-first", (mc, ag, esc), (["fable", "sol"], "registry-ci", False))
    chk("ci chain has no sub-frontier tier", sorted(set(mc) & {"sonnet", "haiku"}), [])
    # no role -> defaults (fable-led).
    chk("no role -> defaults", resolve(["area:usage"], doc)[0][0], "fable")
    # review role -> opus + escalate.
    chk("review -> opus/escalate", resolve(["role:review"], doc)[1:], ("registry-reviewer", True))
    # sonnet-docs-only (maintainer 2026-07-18): the shipped table must carry sonnet in no
    # non-docs chain, and a violating table must be REJECTED at resolve time.
    non_docs = [r for r in doc.get("route", []) if r.get("role") != "docs"]
    chk("sonnet/terra absent from all non-docs chains",
        [bool({"sonnet", "terra"} & set(r.get("model_chain", []))) for r in non_docs].count(True)
        + bool({"sonnet", "terra"} & set(doc.get("defaults", {}).get("model_chain", []))), 0)
    try:
        resolve(["role:impl"], {"defaults": {"model_chain": ["fable", "sonnet"], "agent": "x"}})
        chk("violating table rejected", "no error", "ValueError")
    except ValueError:
        chk("violating table rejected", "ValueError", "ValueError")
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
