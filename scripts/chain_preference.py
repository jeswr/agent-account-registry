#!/usr/bin/env python3
# [OPUS-5] Shared CHAIN-ORDER PREFERENCE mechanism — ONE implementation, imported (never
# re-declared) by BOTH registry resolvers: scripts/policy-resolve.py (the CLAIM side) and
# scripts/route-resolve.py (the registry-as-target PLAN side).
"""chain_preference.py — re-order a resolved model chain from a DECLARATION in the routing table.

WHY THIS EXISTS
---------------
A dispatch decision is made TWICE. PLAN clones the target repository and runs the TARGET's
`scripts/route-resolve.py`; CLAIM re-derives the same route with REGISTRY-owned
`scripts/policy-resolve.py` against the target's routing table fetched from its PROTECTED default
tip (`dispatch-claim._protected_routing`), and `dispatch-claim._route_matches` demands EXACT
equality of `model_chain` / `agent` / `escalate`. A rule one side knows and the other does not is
not a preference that half-applies — it is a `DispatchError`, a `route-policy-failed` defer, and,
because the comparison is a pure function of the labels and the table, the SAME defer on every
subsequent tick. The item never dispatches again.

sparq PR #4211 is the live instance: an `area:gui` carve-out ("sol stays first for GUI work",
maintainer 2026-07-26) implemented only in sparq's `route-resolve.gui_carve_out()` would have
stopped all 34 open `area:gui` `role:impl`/`role:perf` issues from dispatching at all.

WHY THE RULE IS *DATA*, NOT A SECOND COPY OF THE CODE
-----------------------------------------------------
The obvious fix — hand-write the same `area:gui` rule in `policy-resolve.py` — recreates exactly
the drift class registry #707/#712 exist to prevent: two hand-maintained copies of one rule, with
the failure mode of a divergence being an invisible per-item defer counter.

CLAIM cannot import the target's resolver: running target-authored CODE in the privileged claim
step is the escalation `_protected_routing` was written to close (registry #119). But CLAIM already
trusts one artefact from the target — the PROTECTED routing TOML itself, which is where
`model_chain` comes from in the first place. So the rule crosses the repository boundary through
that same channel, as DATA:

    [[chain_preference]]
    labels   = ["area:gui"]        # EXACT labels; ANY one of them selects
    lead     = "sol"               # moved to the FRONT of the chain
    requires = ["sol", "opus5"]    # fires ONLY when the chain already contains ALL of these

Both resolvers read that declaration from the same bytes, so they cannot disagree about the rule.
This module is the shared MECHANISM; it hard-codes no selector, no lead, and no label.

THE INVARIANTS, AND WHY EACH ONE IS STRUCTURAL
----------------------------------------------
* `lead` MUST appear in `requires`. Consequence: a preference applied to a chain that already
  contains `lead` can only ever RE-ORDER it. Without this, `lead = "sol"` on a `["opus5"]` research
  chain would silently turn a deliberately single-provider, escalating route cross-provider.
* `requires` is the directive's own "tasks for which they are BOTH possible implementors"
  qualifier, encoded literally rather than as prose.
* Preference is NOT exclusion: every other model keeps its relative order behind `lead`, so the
  chain still terminates through the same fallbacks.
* A SECURITY-override route is never offered to this module by either resolver — a soundness chain
  is not a matter of implementor preference.
* Malformed declarations RAISE. A silently dropped preference is a PLAN/CLAIM divergence, i.e. the
  exact failure this module exists to prevent, so degrading to "no preference" is not available.

`inject_roles` — WHY ADDING THE LEAD BACK IS SOMETIMES THE ONLY HONEST ANSWER
----------------------------------------------------------------------------
Re-ordering is sufficient only while every affected route's chain still CONTAINS the lead. The
2026-07-26 measurement (registry #738: `role:impl` first-attempt yield sol 18% vs opus5 86%, n=74,
4/4 same-issue crossovers) moved `role:impl` to a single-rung `["opus5"]` chain — and that silently
DISARMED the `area:gui` carve-out, because a chain of `["opus5"]` does not contain `sol`, so the
`requires` condition declines and GUI work would have gone opus5-only. That is the exact inversion
of the maintainer's one stated exception ("except GUI work where sol should remain prioritised")
that sparq PR #4211 was written to fix, re-created by an unrelated edit two directives later.

So a preference may OPT IN, per preference and per ROLE, to adding its `lead` to a chain that lacks
it:

    inject_roles = ["impl"]        # EXACT role names; injection is legal ONLY for these

The narrowing is deliberate and it is what keeps the original invariant's PURPOSE intact:

* Injection is OFF by default. An absent `inject_roles` is `()`, i.e. byte-for-byte the previous
  re-order-only behaviour — which is what makes deploying this mechanism ahead of any declaration a
  strict no-op, exactly as the `chain_preference` rollout itself was.
* The allow-list is EXACT role names, closed, and declared in the same protected DATA both
  resolvers read — so PLAN and CLAIM cannot disagree about where injection is legal.
* `INJECT_FORBIDDEN_ROLES` (research / review / soundness) may never appear in it. Those are the
  routes that are single-provider for AUTHORSHIP reasons and that escalate on exhaustion; making
  one cross-provider is precisely what the no-injection invariant existed to prevent, so it stays
  structurally impossible rather than merely undeclared.
* A ROLELESS issue (the `[defaults]` branch, `role=None`) can never be injected into: with no role
  there is nothing to check against the allow-list, and fail-closed means decline.
* `requires` is still enforced, minus the lead itself — so a route must still offer everything else
  the preference depends on before its lead is added.
"""

# The REQUIRED key set of a `[[chain_preference]]` table.
PREFERENCE_FIELDS = frozenset({"labels", "lead", "requires"})
# Keys that may be present. Absent -> the documented default, which is always the pre-existing
# behaviour. Anything outside REQUIRED|OPTIONAL is a typo or a newer schema this resolver does not
# implement; either way the two sides would disagree about what the table means, so it is refused
# rather than ignored.
OPTIONAL_PREFERENCE_FIELDS = frozenset({"inject_roles"})
# Roles whose chain a preference may NEVER extend. These are pinned to one provider for AUTHORSHIP
# reasons and `escalate = true` on exhaustion (a visible stall is the intended outcome); quietly
# adding a cross-provider rung would convert that visible stall into a silent hop to another
# provider. Refused at PARSE time, so the prohibition cannot be bypassed by declaring it.
INJECT_FORBIDDEN_ROLES = frozenset({"research", "review", "soundness"})


class ChainPreferenceError(ValueError):
    """A malformed `[[chain_preference]]` declaration. Fail-closed: never resolve past one."""


def _string_list(value, where, field):
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, str) or not item.strip() or item != item.strip()
                   for item in value)):
        raise ChainPreferenceError(
            f"{where}: {field} must be a non-empty list of non-empty, unpadded strings")
    if len(set(value)) != len(value):
        raise ChainPreferenceError(f"{where}: {field} contains duplicates")
    return tuple(value)


def parse_preferences(routing_doc, model_catalog):
    """Validate `[[chain_preference]]` and return an immutable tuple of
    (labels, lead, requires, inject_roles).

    `model_catalog` is the routing table's `[models]` key set; `lead` and every `requires` entry
    must name a catalogued model, so a preference can never reference a rung that does not exist.
    An ABSENT `chain_preference` key is legal and yields `()` — that is what makes this mechanism
    safe to deploy to the registry BEFORE any target declares one: with no declaration, both
    resolvers behave exactly as they did before.
    """
    if not isinstance(routing_doc, dict):
        raise ChainPreferenceError("routing document must be a table")
    raw = routing_doc.get("chain_preference", [])
    if not isinstance(raw, list):
        raise ChainPreferenceError("chain_preference must be an ARRAY of tables")
    parsed = []
    seen_labels = set()
    for index, entry in enumerate(raw):
        where = f"chain_preference #{index + 1}"
        if not isinstance(entry, dict):
            raise ChainPreferenceError(f"{where} must be a table")
        unknown = sorted(entry.keys() - PREFERENCE_FIELDS - OPTIONAL_PREFERENCE_FIELDS)
        missing = sorted(PREFERENCE_FIELDS - entry.keys())
        if missing:
            raise ChainPreferenceError(f"{where} is missing fields: {', '.join(missing)}")
        if unknown:
            raise ChainPreferenceError(f"{where} has unknown fields: {', '.join(unknown)}")
        labels = _string_list(entry["labels"], where, "labels")
        requires = _string_list(entry["requires"], where, "requires")
        inject_roles = ()
        if "inject_roles" in entry:
            inject_roles = _string_list(entry["inject_roles"], where, "inject_roles")
            forbidden = sorted(set(inject_roles) & INJECT_FORBIDDEN_ROLES)
            if forbidden:
                raise ChainPreferenceError(
                    f"{where}: inject_roles may not name {', '.join(forbidden)} — those routes are "
                    f"single-provider for authorship reasons and escalate on exhaustion, so adding "
                    f"a rung to them would turn an intended visible stall into a silent "
                    f"cross-provider hop")
        lead = entry["lead"]
        if not isinstance(lead, str) or not lead.strip() or lead != lead.strip():
            raise ChainPreferenceError(f"{where}: lead must be a non-empty, unpadded string")
        if lead not in requires:
            # `requires` is checked against the chain before the re-order, so `lead in requires` is
            # what makes "re-order" the only effect reachable WITHOUT an explicit `inject_roles`
            # opt-in. Adding the lead back is available only to the roles that declaration names,
            # and never to INJECT_FORBIDDEN_ROLES.
            raise ChainPreferenceError(
                f"{where}: lead {lead!r} must also appear in requires — otherwise the preference "
                f"could INJECT {lead!r} into a chain that deliberately excludes it (e.g. turning a "
                f"single-provider escalating route into a cross-provider one) for EVERY role, "
                f"instead of only the roles `inject_roles` names")
        unknown_models = sorted({lead, *requires} - set(model_catalog))
        if unknown_models:
            raise ChainPreferenceError(
                f"{where} references models absent from the [models] catalog: "
                f"{', '.join(unknown_models)}")
        overlap = sorted(seen_labels & set(labels))
        if overlap:
            # First match wins, so two preferences selecting the same label make the outcome depend
            # on declaration order — readable to neither reviewer nor resolver. Refuse.
            raise ChainPreferenceError(
                f"{where}: label(s) {', '.join(overlap)} are already selected by an earlier "
                f"chain_preference; a label must be claimed by at most one preference")
        seen_labels |= set(labels)
        parsed.append((frozenset(labels), lead, frozenset(requires), frozenset(inject_roles)))
    return tuple(parsed)


def apply_preferences(labels, chain, preferences, role=None):
    """Return `chain` re-ordered (or led) by the FIRST matching preference, or `chain` unchanged.

    A preference matches when the issue carries at least one of its EXACT `labels` — exact, never
    substring: a substring selector on `"gui"` would sweep `area:guide` / `area:guidance` into the
    carve-out — AND the chain satisfies the `requires` condition:

    * `lead` ALREADY in the chain -> the chain must contain EVERY model in `requires`; the result is
      a strict PERMUTATION of the input (re-order only).
    * `lead` ABSENT -> the preference must name `role` in its `inject_roles`, and the chain must
      contain every model in `requires` EXCEPT the lead itself; the result is the input with `lead`
      prepended. `role=None` (a ROLELESS issue, i.e. the `[defaults]` branch) can never inject:
      there is no role to check against the allow-list, and fail-closed means decline.

    Idempotent in both modes. The permutation / single-addition property is ASSERTED, not assumed.
    """
    chain = list(chain)
    label_set = set(labels)
    for wanted, lead, requires, inject_roles in preferences:
        if not (label_set & wanted):
            continue
        if lead in chain:
            if not requires <= set(chain):
                # "for which they are BOTH possible implementors" — the chain does not offer this
                # preference's models, so the route is left exactly as the table wrote it.
                continue
            reordered = [lead] + [model for model in chain if model != lead]
            expected = sorted(chain)
        else:
            # ADDING the lead is a strictly larger effect than re-ordering, so it is opt-in per
            # preference AND per role (see `inject_roles` in the module docstring). Without the
            # opt-in this declines exactly as it did before the field existed.
            if role is None or role not in inject_roles:
                continue
            if not (requires - {lead}) <= set(chain):
                continue
            reordered = [lead] + list(chain)
            expected = sorted(chain + [lead])
        if sorted(reordered) != expected:  # pragma: no cover — structurally unreachable
            raise ChainPreferenceError(
                f"chain preference for lead {lead!r} did not preserve the chain: "
                f"{chain} -> {reordered}")
        return reordered
    return chain


def preference_labels(preferences):
    """The union of every selector label — the audit surface for "what does this table carve out"."""
    return sorted({label for labels, _lead, _requires, _inject in preferences for label in labels})


def preference_inject_roles(preferences):
    """The union of every `inject_roles` entry — the audit surface for "where may a chain GROW".

    Consumers assert this against the routing table's declared role routes, so an `inject_roles`
    naming a role that does not exist is caught as the typo it is rather than silently never firing.
    """
    return sorted({role for _labels, _lead, _requires, inject in preferences for role in inject})


def _self_test():  # noqa: C901 — a flat sequence of assertions, deliberately not factored
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def rejects(name, needle, fn):
        nonlocal ok
        try:
            fn()
        except ChainPreferenceError as exc:
            good, detail = needle in str(exc), str(exc)
        else:
            good, detail = False, "ACCEPTED (want a refusal)"
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {detail}")

    catalog = {"opus5", "sol", "luna", "terra", "haiku", "sonnet"}
    gui_doc = {"chain_preference": [
        {"labels": ["area:gui"], "lead": "sol", "requires": ["sol", "opus5"]}]}
    gui = parse_preferences(gui_doc, catalog)
    chk("a declaration parses to (labels, lead, requires, inject_roles)",
        [(sorted(a), b, sorted(c), sorted(d)) for a, b, c, d in gui],
        [(["area:gui"], "sol", ["opus5", "sol"], [])])
    chk("the audit surface is the union of the selectors", preference_labels(gui), ["area:gui"])
    chk("an inject_roles-less declaration injects NOWHERE", preference_inject_roles(gui), [])

    # ---- THE LIVE sparq CASES. Each row is a real open-backlog shape from sparq PR #4211.
    chk("area:gui + role:impl -> sol first (the 33-issue case)",
        apply_preferences({"area:gui", "role:impl"}, ["opus5", "sol"], gui), ["sol", "opus5"])
    chk("area:gui + role:perf -> sol first (the 34th issue)",
        apply_preferences({"area:gui", "role:perf"}, ["opus5", "sol"], gui), ["sol", "opus5"])
    chk("area:gui with NO role (the [defaults] chain) -> sol first",
        apply_preferences({"area:gui"}, ["opus5", "sol"], gui), ["sol", "opus5"])
    chk("PREFERENCE, NOT EXCLUSION: opus5 stays reachable behind sol",
        "opus5" in apply_preferences({"area:gui"}, ["opus5", "sol"], gui), True)
    chk("area:gui + role:research is UNTOUCHED (sol is not an implementor there, so the "
        "requires-condition declines rather than making a single-provider route cross-provider)",
        apply_preferences({"area:gui", "role:research"}, ["opus5"], gui), ["opus5"])
    chk("a longer chain keeps every other rung in its original relative order",
        apply_preferences({"area:gui"}, ["opus5", "luna", "sol"], gui),
        ["sol", "opus5", "luna"])
    chk("the docs chain is already sol-led, so the preference is a no-op there",
        apply_preferences({"area:gui", "role:docs"}, ["sol", "terra", "opus5"], gui),
        ["sol", "terra", "opus5"])
    chk("idempotent", apply_preferences({"area:gui"},
                                        apply_preferences({"area:gui"}, ["opus5", "sol"], gui),
                                        gui), ["sol", "opus5"])
    # EXACT LABEL, never a substring — the whole site*/guide family must stay outside.
    for outside in ("area:site", "area:site-specs", "area:site-papers", "area:sitemap",
                    "surface:frontend", "dashboard", "area:guide", "area:guidance", "xarea:gui",
                    "area:gui-toolkit", "gui"):
        chk(f"{outside} does NOT match the area:gui selector",
            apply_preferences({outside, "role:impl"}, ["opus5", "sol"], gui), ["opus5", "sol"])
    chk("NO preferences declared -> the chain is returned verbatim (the safe-to-deploy-first "
        "property: a registry that knows the mechanism but reads a table without a declaration "
        "resolves exactly as it did before)",
        apply_preferences({"area:gui", "role:impl"}, ["opus5", "sol"], ()), ["opus5", "sol"])
    chk("an absent chain_preference key parses to no preferences",
        parse_preferences({"models": {}}, catalog), ())

    # ---- [OPUS-5] `inject_roles` (registry #738 / the single-rung `role:impl` chain).
    def one(entry, cat=catalog):
        return lambda: parse_preferences({"chain_preference": [entry]}, cat)

    # THE COLLISION THIS FIELD EXISTS FOR, asserted first so the field cannot be read as optional
    # polish: with `role:impl` at `["opus5"]`, the re-order-only rule DECLINES and GUI impl work
    # goes opus5-only — the exact inversion of the maintainer's one stated exception.
    chk("WITHOUT inject_roles, a single-rung ['opus5'] impl chain DISARMS the carve-out",
        apply_preferences({"area:gui", "role:impl"}, ["opus5"], gui, role="impl"), ["opus5"])
    inj_doc = {"chain_preference": [{"labels": ["area:gui"], "lead": "sol",
                                     "requires": ["sol", "opus5"], "inject_roles": ["impl"]}]}
    inj = parse_preferences(inj_doc, catalog)
    chk("the audit surface names where a chain may GROW", preference_inject_roles(inj), ["impl"])
    chk("WITH inject_roles, area:gui + role:impl on a ['opus5'] chain is SOL-FIRST again",
        apply_preferences({"area:gui", "role:impl"}, ["opus5"], inj, role="impl"),
        ["sol", "opus5"])
    chk("...and opus5 stays reachable behind sol (preference, not exclusion)",
        "opus5" in apply_preferences({"area:gui", "role:impl"}, ["opus5"], inj, role="impl"), True)
    chk("injection is IDEMPOTENT (the lead is never duplicated)",
        apply_preferences({"area:gui", "role:impl"},
                          apply_preferences({"area:gui", "role:impl"}, ["opus5"], inj, role="impl"),
                          inj, role="impl"), ["sol", "opus5"])
    chk("a two-rung chain still takes the RE-ORDER path (injection changes nothing there)",
        apply_preferences({"area:gui", "role:impl"}, ["opus5", "sol"], inj, role="impl"),
        ["sol", "opus5"])
    # THE ALLOW-LIST IS THE GUARD. A role the declaration does not name is left alone even though
    # every other condition holds — this is the check that reds if the `role not in inject_roles`
    # test is deleted.
    for other in ("perf", "site", "ci", "docs", "gui"):
        chk(f"role:{other} is NOT in inject_roles, so its ['opus5'] chain is untouched",
            apply_preferences({"area:gui", f"role:{other}"}, ["opus5"], inj, role=other), ["opus5"])
    # A ROLELESS issue can never inject: no role, nothing to authorise it. Reds if `role is None`
    # is dropped from the guard.
    chk("a ROLELESS issue (the [defaults] branch) can never be injected into",
        apply_preferences({"area:gui"}, ["opus5"], inj, role=None), ["opus5"])
    # `requires` MINUS the lead is still enforced: a chain missing the other required model does
    # not get the lead added. Reds if the `(requires - {lead}) <= set(chain)` check is deleted.
    chk("injection still requires the REST of `requires` to be in the chain",
        apply_preferences({"area:gui", "role:impl"}, ["luna"], inj, role="impl"), ["luna"])
    chk("...and an EMPTY chain is never given a lead",
        apply_preferences({"area:gui", "role:impl"}, [], inj, role="impl"), [])
    # The selector is still EXACT under injection — a substring near-miss must not inject either.
    for outside in ("area:guide", "area:guidance", "area:site", "gui", "area:gui-toolkit"):
        chk(f"{outside} does not inject sol into a single-rung impl chain",
            apply_preferences({outside, "role:impl"}, ["opus5"], inj, role="impl"), ["opus5"])
    # THE STRUCTURAL PROHIBITION: the authorship-pinned escalating roles can never be declared.
    chk("the forbidden set is exactly the authorship-pinned escalating roles",
        sorted(INJECT_FORBIDDEN_ROLES), ["research", "review", "soundness"])
    for banned in sorted(INJECT_FORBIDDEN_ROLES):
        rejects(f"inject_roles naming {banned!r} is REFUSED at parse time (it would turn an "
                f"intended visible stall into a silent cross-provider hop)",
                "inject_roles may not name",
                one({"labels": ["area:gui"], "lead": "sol", "requires": ["sol", "opus5"],
                        "inject_roles": [banned]}))
    rejects("a malformed inject_roles list is REFUSED", "inject_roles must be",
            one({"labels": ["area:gui"], "lead": "sol", "requires": ["sol", "opus5"],
                    "inject_roles": ["impl", ""]}))
    rejects("a duplicated inject_roles entry is REFUSED", "inject_roles contains duplicates",
            one({"labels": ["area:gui"], "lead": "sol", "requires": ["sol", "opus5"],
                    "inject_roles": ["impl", "impl"]}))
    rejects("a padded inject_roles entry is REFUSED (it could never match a real role)",
            "inject_roles must be",
            one({"labels": ["area:gui"], "lead": "sol", "requires": ["sol", "opus5"],
                    "inject_roles": [" impl"]}))
    rejects("a non-list inject_roles is REFUSED", "inject_roles must be",
            one({"labels": ["area:gui"], "lead": "sol", "requires": ["sol", "opus5"],
                    "inject_roles": "impl"}))
    # `lead in requires` is STILL required even with the opt-in, so the declaration always states
    # which models the rule is about.
    rejects("lead outside requires is refused even WITH inject_roles",
            "must also appear in requires",
            one({"labels": ["area:gui"], "lead": "sol", "requires": ["opus5"],
                    "inject_roles": ["impl"]}))

    # ---- FAIL-CLOSED VALIDATION. Every one of these would otherwise be a silent PLAN/CLAIM split.
    def parsed(entry, cat=catalog):
        return lambda: parse_preferences({"chain_preference": [entry]}, cat)

    rejects("lead outside requires is REFUSED (the no-injection invariant)",
            "must also appear in requires",
            parsed({"labels": ["area:gui"], "lead": "sol", "requires": ["opus5"]}))
    rejects("an uncatalogued lead is REFUSED", "absent from the [models] catalog",
            parsed({"labels": ["area:gui"], "lead": "ghost", "requires": ["ghost"]}))
    rejects("an uncatalogued requires entry is REFUSED", "absent from the [models] catalog",
            parsed({"labels": ["area:gui"], "lead": "sol", "requires": ["sol", "ghost"]}))
    rejects("an unknown field is REFUSED (a newer schema must not resolve as a weaker one)",
            "unknown fields",
            parsed({"labels": ["area:gui"], "lead": "sol", "requires": ["sol"], "mode": "x"}))
    rejects("a missing field is REFUSED", "missing fields",
            parsed({"labels": ["area:gui"], "lead": "sol"}))
    rejects("an empty labels list is REFUSED", "labels must be",
            parsed({"labels": [], "lead": "sol", "requires": ["sol"]}))
    rejects("a padded label is REFUSED (it could never match a real GitHub label)", "unpadded",
            parsed({"labels": [" area:gui"], "lead": "sol", "requires": ["sol"]}))
    rejects("a duplicated selector label is REFUSED", "labels contains duplicates",
            parsed({"labels": ["area:gui", "area:gui"], "lead": "sol", "requires": ["sol"]}))
    rejects("a padded lead is REFUSED", "lead must be",
            parsed({"labels": ["area:gui"], "lead": "sol ", "requires": ["sol", "opus5"]}))
    rejects("a non-table entry is REFUSED", "must be a table",
            lambda: parse_preferences({"chain_preference": ["area:gui"]}, catalog))
    rejects("a non-array chain_preference is REFUSED", "ARRAY of tables",
            lambda: parse_preferences({"chain_preference": {"labels": ["area:gui"]}}, catalog))
    rejects("two preferences claiming the SAME label are REFUSED (first-match-wins would make "
            "the outcome depend on declaration order)", "at most one preference",
            lambda: parse_preferences({"chain_preference": [
                {"labels": ["area:gui"], "lead": "sol", "requires": ["sol", "opus5"]},
                {"labels": ["area:gui"], "lead": "opus5", "requires": ["sol", "opus5"]}]},
                catalog))

    # A SECOND, DISJOINT preference is legal — the mechanism is not single-purpose.
    two = parse_preferences({"chain_preference": [
        {"labels": ["area:gui"], "lead": "sol", "requires": ["sol", "opus5"]},
        {"labels": ["area:kernel"], "lead": "opus5", "requires": ["sol", "opus5"]}]}, catalog)
    chk("a second, disjoint preference applies independently",
        (apply_preferences({"area:gui"}, ["opus5", "sol"], two),
         apply_preferences({"area:kernel"}, ["sol", "opus5"], two)),
        (["sol", "opus5"], ["opus5", "sol"]))

    print("chain_preference self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(_self_test() if "--self-test" in sys.argv else 0)
