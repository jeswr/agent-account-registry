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
resolve = _route.resolve

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


def _role_of(labels):
    for lb in sorted(labels):
        if lb.startswith("role:"):
            return lb[5:]
    return None


def plan_dispatch(ready_issues, routing_doc):
    """Compose the ready frontier + routing into a dispatch plan. PURE — no I/O, no side effects.
    A roleless issue is flagged unresolved (role=None, agent=None) — never guessed (fail-closed)."""
    plan = []
    for it in ready_issues:
        labels = labels_of(it)
        role = _role_of(labels)
        package = sorted(packages_of(labels))[0]
        model_chain, agent, escalate = resolve(labels, routing_doc)
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

    # a non-trust impl issue (area:usage) -> fable-led chain, no escalate.
    impl = compute_ready([iss(1, R + ["priority:P1", "role:impl", "area:usage"])])
    p_impl = plan_dispatch(impl, doc)
    chk("impl -> single row", len(p_impl), 1)
    row = p_impl[0]
    chk("impl row", (row["role"], row["model_chain"][0], row["agent"], row["escalate"]),
        ("impl", "fable", "registry-impl", False))
    chk("impl package", row["package"], "usage")

    # a TRUST-SURFACE issue (area:worker) -> opus + escalate (security override beats role).
    sec = compute_ready([iss(2, R + ["priority:P0", "role:impl", "area:worker"])])
    row = plan_dispatch(sec, doc)[0]
    chk("worker -> opus", row["model_chain"], ["opus"])
    chk("worker -> reviewer/escalate", (row["agent"], row["escalate"]),
        ("registry-reviewer", True))
    chk("worker role stays declared", row["role"], "impl")

    # a docs issue -> its route (haiku-led).
    docs = compute_ready([iss(3, R + ["priority:P2", "role:docs", "area:docs"])])
    row = plan_dispatch(docs, doc)[0]
    chk("docs -> haiku", row["model_chain"][0], "haiku")

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
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
