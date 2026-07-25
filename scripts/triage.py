#!/usr/bin/env python3
# [OPUS-4.8] Registry self-management: static (no-LLM) issue triage for jeswr/agent-account-registry.
# Modeled on the sparq target's scripts/triage.py, adjusted for the registry's area:* sections and
# its trust-surface soundness lane. Applied by .github/workflows/triage-issue.yml.
"""triage.py — the deterministic, no-LLM part of issue triage.

Given an issue's labels + type, decide the labels to ADD/REMOVE and whether it is triage-complete:
  * role     — from a `kind:*` label, the issue type, or (last resort, issue #225) the issue's
               `area:*` default; a trust-surface area forces `soundness`.
  * priority — kept if a valid single `priority:P0..P4` is present; else triage is incomplete.
  * package  — the existing `area:<section>` labels are the package. A NO-area issue is parked
               `needs:area` (it would otherwise reserve the serializing __global__ partition).
  * ready    — `status:ready` iff a valid single priority AND a role AND an `area:<section>` AND
               NOT gated (`needs:*` incl. `needs:design`/`needs:user`, `trust:untrusted`) and not
               an epic. Otherwise `status:untriaged` (or `needs:area`-parked).

Fail-closed: ambiguity, missing role/priority, or ANY `needs:*` gate (INCLUDING `needs:design`,
the B2 design-hold) yields NOT-ready. `needs:design` is never auto-cleared here — a human/architect
removes it after the design pass, then the retriage path promotes.
"""
import re
import sys

ROLE_BY_KIND = {"docs": "docs", "research": "research", "ci": "ci", "site": "site",
                "security": "soundness"}
ROLE_BY_TYPE = {"feature": "impl", "bug": "impl", "task": "impl", "chore": "ci",
                "spike": "research", "epic": "impl"}
# The registry IS the orchestration trust plane: an issue touching these sections is a soundness
# surface (mirrors orchestration/routing.toml's match_labels). A substring match forces the
# soundness lane so the review of its eventual PR is human-armed, never auto-armed.
SEC_KEYWORDS = ("dispatch", "worker", "set-up-account", "review-loop", "groom",
                "zk", "mpc", "crypto", "auth", "e2ee")
# [FABLE-5] STANDING RULE (maintainer decision 2026-07-17): UI/front-end surfaces route role:site
# -> the openai/codex chain in orchestration/routing.toml (original-builder ownership: GPT-5.6
# codex built the registry dashboard, e4098b9). EXACT labels, not substrings — UI keywords must
# not enter SEC_KEYWORDS/match_labels semantics (that would human-arm every UI PR).
UI_SURFACE_LABELS = ("area:dashboard", "dashboard", "surface:frontend")
# [FABLE-5] STANDING RULE — frontier-tier CI/infrastructure authorship (maintainer decision
# 2026-07-17, same pattern as the UI rule above): infra-surface labels derive role:ci so CI
# plumbing reaches the FRONTIER-ONLY sol-led ci chain in orchestration/routing.toml (sol/fable —
# terra and sonnet are docs-only, 2026-07-18; sonnet/haiku no longer author infra). EXACT labels, not substrings, and NOT routing match_labels
# (the arm-side security classifier unions those keywords). NOTE the trust-plane infra surfaces
# (dispatch/worker/set-up-account/review-loop/groom — incl. scripts/dispatch*, scripts/worker*,
# scripts/groom*, scripts/select-and-claim* issues, which carry those area labels) are ALREADY
# forced to the soundness lane by SEC_KEYWORDS above, which WINS — opus + human arm is stricter
# than the frontier floor. role:ci covers the residual: .github/workflows + non-trust CI plumbing.
INFRA_SURFACE_LABELS = ("area:ci", "area:workflows")
# [OPUS-5] issue #225 — the DEFAULT role for each of the registry's OWN areas: the LAST fallback
# in _role(), consulted only when the security/UI/infra lanes, an explicit `role:*`, a `kind:*` AND
# the type map have all come up empty. `ROLE_BY_TYPE.get()` returns None for an issue with no
# GitHub type or a type outside its keys, and a ROLELESS issue is INVISIBLE to the dispatch
# enumerator (ready-issues.has_role requires `role:.+`, so the frontier drops it with no signal):
# 117 `status:ready` issues sat silently undrainable. Keys are area VALUES matched EXACTLY — never
# substrings; substring semantics belong to SEC_KEYWORDS / routing match_labels, which human-arm
# whatever they match. Every value MUST be a role configured in orchestration/routing.toml, else
# the row this enables is rejected by the planner (route-resolve.RoleResolutionError).
# The first three groups are REDUNDANT today — an earlier lane short-circuits before the fallback
# is reached — and are listed anyway so this table is the one complete registry-area map, and so a
# future narrowing of SEC_KEYWORDS/UI/INFRA cannot silently reopen the roleless hole. `_self_test`
# asserts each entry AGREES with the lane that actually wins, so the redundancy can never drift.
AREA_ROLE_DEFAULT = {
    # trust-plane script surfaces — SEC_KEYWORDS already forces `soundness` (stricter, and it wins)
    "dispatch": "soundness", "worker": "soundness", "groom": "soundness",
    "review-loop": "soundness", "set-up-account": "soundness",
    # workflow/CI plumbing — INFRA_SURFACE_LABELS already derives `ci`
    "ci": "ci", "workflows": "ci",
    # the UI surface — UI_SURFACE_LABELS already derives `site`
    "dashboard": "site",
    # the residual registry surfaces, reachable ONLY through this table
    "usage": "impl", "docs": "docs",
}
_PRIO = re.compile(r"^priority:P([0-4])$")


def _valid_priority(labels):
    ps = {m.group(1) for lb in labels for m in [_PRIO.match(lb)] if m}
    return len(ps) == 1


def _area_default(labels):
    """The role ALL of the issue's known `area:<value>` labels agree on; None when they disagree
    (fail-closed: never an arbitrary pick — an ambiguous issue stays `status:untriaged` for a
    human) or when no area is in the table."""
    roles = {AREA_ROLE_DEFAULT[lb[5:]] for lb in labels
             if lb.startswith("area:") and lb[5:] in AREA_ROLE_DEFAULT}
    return next(iter(roles)) if len(roles) == 1 else None


def _role(labels, issue_type):
    # a trust-surface keyword forces the soundness lane regardless of kind/type/explicit role.
    if any(k in lb for lb in labels for k in SEC_KEYWORDS):
        return "soundness"
    # respect an EXPLICIT single role:* label (a seeded/migrated issue already carrying its role).
    explicit = sorted(lb[5:] for lb in labels if lb.startswith("role:"))
    if len(explicit) == 1:
        return explicit[0]
    for lb in labels:
        if lb.startswith("kind:") and lb[5:] in ROLE_BY_KIND:
            return ROLE_BY_KIND[lb[5:]]
    # [FABLE-5] UI-surface labels derive role:site (codex-led chain) before the generic type map,
    # after kind (docs about the dashboard stay docs) and after an explicit role:* label.
    if any(lb in UI_SURFACE_LABELS for lb in labels):
        return "site"
    # [FABLE-5] infra-surface labels derive role:ci (the frontier-only sol/fable chain) in the
    # same precedence slot: after security (soundness wins), explicit role:*, and kind.
    if any(lb in INFRA_SURFACE_LABELS for lb in labels):
        return "ci"
    # [OPUS-5] issue #225: the area-derived default is the LAST resort, so an issue with no GitHub
    # type (or a type outside ROLE_BY_TYPE) still derives a role instead of silently becoming
    # undispatchable. Strictly a WIDENING — it fires only where the type map returned None, so no
    # existing derivation changes.
    return ROLE_BY_TYPE.get(issue_type) or _area_default(labels)


def triage(labels, issue_type="task", trusted=True):
    """Return {add:set, remove:set, ready:bool, role:str|None}. Untrusted -> a no-op (the trust
    layer quarantines/notifies; content is never inspected here)."""
    labels = set(labels)
    if not trusted or "trust:untrusted" in labels:
        return {"add": set(), "remove": set(), "ready": False, "role": None}
    role = _role(labels, issue_type)
    add, remove = set(), set()
    if role:
        add.add(f"role:{role}")
        # single-role invariant: strip any OTHER role:* so resolve() never sees an ambiguous set.
        remove |= {lb for lb in labels if lb.startswith("role:") and lb != f"role:{role}"}
    has_area = any(lb.startswith("area:") for lb in labels)
    # ANY needs:* gate (needs:design B2, needs:user, needs:area) blocks ready. kind:epic too.
    gated = any(lb.startswith("needs:") for lb in labels)
    ready = (bool(role) and _valid_priority(labels) and has_area and not gated
             and "kind:epic" not in labels)
    if ready:
        add.add("status:ready")
        remove.add("status:untriaged")
        remove.add("needs:area")
    else:
        add.add("status:untriaged")
        remove.add("status:ready")
        # a triage-complete-but-no-area, non-gated, non-epic issue parks needs:area (actionable).
        if (bool(role) and _valid_priority(labels) and not has_area
                and "kind:epic" not in labels and not gated):
            add.add("needs:area")
    return {"add": add - labels, "remove": remove & labels, "ready": ready, "role": role}


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    # complete NON-trust issue: priority + derivable role + area -> ready.
    r = triage(["priority:P2", "kind:docs", "area:docs"], "task")
    chk("docs ready", (r["ready"], "role:docs" in r["add"], "status:ready" in r["add"]),
        (True, True, True))
    # missing priority -> untriaged.
    r = triage(["area:usage"], "feature")
    chk("no priority -> untriaged", (r["ready"], "status:untriaged" in r["add"]), (False, True))
    # ambiguous priority -> untriaged.
    chk("ambiguous priority", triage(["priority:P1", "priority:P2"], "feature")["ready"], False)
    # trust-surface area forces soundness role.
    chk("trust surface -> soundness", triage(["priority:P1", "area:worker"], "feature")["role"],
        "soundness")
    chk("dispatch -> soundness", triage(["priority:P1", "area:dispatch"], "feature")["role"],
        "soundness")
    # [FABLE-5] UI-surface ownership: dashboard work derives role:site (codex-led chain, e4098b9);
    # kind:docs about the dashboard stays docs.
    chk("dashboard -> site", triage(["priority:P2", "area:dashboard"], "feature")["role"], "site")
    chk("dashboard docs stay docs",
        triage(["priority:P3", "kind:docs", "area:dashboard"], "task")["role"], "docs")
    # [FABLE-5] frontier-tier infra authorship: an infra-surface label derives role:ci (the
    # frontier-only sol/fable chain); kind (docs) and trust-surface keywords still win.
    chk("infra surface -> ci", triage(["priority:P2", "area:ci"], "feature")["role"], "ci")
    chk("workflows surface -> ci", triage(["priority:P2", "area:workflows"], "task")["role"], "ci")
    chk("infra docs stay docs",
        triage(["priority:P3", "kind:docs", "area:ci"], "task")["role"], "docs")
    chk("infra+trust surface -> soundness",
        triage(["priority:P1", "area:ci", "area:dispatch"], "feature")["role"], "soundness")
    # [OPUS-5] issue #225: EVERY registry area derives a role even when the issue TYPE is unknown
    # (an untyped issue fell through `ROLE_BY_TYPE.get(...)` to None, and a roleless issue is
    # invisible to the dispatch enumerator). Each check ALSO asserts the table agrees with the lane
    # that actually wins for that area — SEC_KEYWORDS/INFRA/UI short-circuit before the fallback,
    # so a divergent entry here would flip the check red rather than sit unnoticed. Non-vacuous:
    # pre-fix, area:usage/area:docs returned None for an unknown type.
    for _area, _want in sorted(AREA_ROLE_DEFAULT.items()):
        chk(f"area:{_area} derives a role when untyped",
            triage(["priority:P2", f"area:{_area}"], "")["role"], _want)
    # the consequence that matters: such an issue is now READY (it was parked status:untriaged and
    # never entered any dispatch plan).
    r = triage(["priority:P2", "area:usage"], "")
    chk("untyped registry issue becomes ready", (r["ready"], "role:impl" in r["add"]), (True, True))
    # AMBIGUOUS area defaults -> no role at all (fail closed), never an arbitrary pick.
    chk("conflicting area defaults -> no role",
        triage(["priority:P2", "area:usage", "area:docs"], "")["role"], None)
    # the area default is LAST: an explicit role, a kind, the UI/infra lanes and the type map win.
    chk("type map wins over area default",
        triage(["priority:P3", "area:usage"], "spike")["role"], "research")
    chk("explicit role wins over area default",
        triage(["priority:P2", "role:research", "area:usage"], "")["role"], "research")
    chk("kind wins over area default",
        triage(["priority:P2", "kind:docs", "area:usage"], "")["role"], "docs")
    # an unknown area is NOT invented into a role — an untyped, unmapped issue stays untriaged.
    chk("unknown area derives nothing", triage(["priority:P2", "area:mystery"], "")["role"], None)
    # B2: a needs:design issue is NOT ready even with a full role+priority+area label-set.
    r = triage(["priority:P2", "role:impl", "area:review-loop", "needs:design"], "task")
    chk("needs:design not ready (B2)", r["ready"], False)
    chk("needs:design not promoted (B2)", "status:ready" in r["add"], False)
    # needs:user -> not ready.
    chk("needs:user gated", triage(["priority:P1", "kind:docs", "needs:user"], "task")["ready"],
        False)
    # untrusted -> no-op.
    chk("untrusted no-op", triage(["priority:P1", "trust:untrusted"], "feature"),
        {"add": set(), "remove": set(), "ready": False, "role": None})
    # respect an explicit role:* on a NON-trust area — do NOT derive a second (ambiguity broke
    # autonomous dispatch upstream).
    r = triage(["priority:P2", "role:research", "area:usage"], "feature")
    chk("explicit role respected", (r["role"], "role:impl" in r["add"]), ("research", False))
    # an epic is never dispatchable even with a full label-set.
    chk("epic not ready", triage(["priority:P1", "role:impl", "kind:epic", "area:usage"],
                                 "epic")["ready"], False)
    # no-area guard: parks needs:area.
    r = triage(["priority:P1", "kind:docs"], "task")
    chk("no-area not ready", r["ready"], False)
    chk("no-area parks needs:area", "needs:area" in r["add"], True)
    # a needs:design no-area issue is not double-parked with needs:area (already gated).
    chk("gated no-area no needs:area",
        "needs:area" in triage(["priority:P1", "role:impl", "needs:design"], "task")["add"], False)
    print("triage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--labels", default="", help="comma-separated current labels")
    ap.add_argument("--type", default="task")
    ap.add_argument("--untrusted", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    labels = [x for x in a.labels.split(",") if x.strip()]
    r = triage(labels, a.type, trusted=not a.untrusted)
    print("ADD: " + " ".join(sorted(r["add"])))
    print("REMOVE: " + " ".join(sorted(r["remove"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
