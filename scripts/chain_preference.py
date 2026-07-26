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
* `lead` MUST appear in `requires`. Consequence: a preference can only ever RE-ORDER a chain, never
  INJECT a model into one. Without it, `lead = "sol"` on a `["opus5"]` research chain would
  silently turn a deliberately single-provider, escalating route into a cross-provider one.
* `requires` is the directive's own "tasks for which they are BOTH possible implementors"
  qualifier, encoded literally rather than as prose.
* Preference is NOT exclusion: every other model keeps its relative order behind `lead`, so the
  chain still terminates through the same fallbacks.
* A SECURITY-override route is never offered to this module by either resolver — a soundness chain
  is not a matter of implementor preference.
* Malformed declarations RAISE. A silently dropped preference is a PLAN/CLAIM divergence, i.e. the
  exact failure this module exists to prevent, so degrading to "no preference" is not available.
"""

# The complete, CLOSED key set of a `[[chain_preference]]` table. An unknown key is a typo or a
# newer schema this resolver does not implement; either way the two sides would disagree about what
# the table means, so it is refused rather than ignored.
PREFERENCE_FIELDS = frozenset({"labels", "lead", "requires"})


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
    """Validate `[[chain_preference]]` and return an immutable tuple of (labels, lead, requires).

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
        unknown = sorted(entry.keys() - PREFERENCE_FIELDS)
        missing = sorted(PREFERENCE_FIELDS - entry.keys())
        if missing:
            raise ChainPreferenceError(f"{where} is missing fields: {', '.join(missing)}")
        if unknown:
            raise ChainPreferenceError(f"{where} has unknown fields: {', '.join(unknown)}")
        labels = _string_list(entry["labels"], where, "labels")
        requires = _string_list(entry["requires"], where, "requires")
        lead = entry["lead"]
        if not isinstance(lead, str) or not lead.strip() or lead != lead.strip():
            raise ChainPreferenceError(f"{where}: lead must be a non-empty, unpadded string")
        if lead not in requires:
            # THE NO-INJECTION INVARIANT. `requires` is checked against the chain before the
            # re-order, so `lead in requires` is what makes "re-order" the only reachable effect.
            raise ChainPreferenceError(
                f"{where}: lead {lead!r} must also appear in requires — otherwise the preference "
                f"could INJECT {lead!r} into a chain that deliberately excludes it (e.g. turning a "
                f"single-provider escalating route into a cross-provider one) instead of merely "
                f"re-ordering it")
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
        parsed.append((frozenset(labels), lead, frozenset(requires)))
    return tuple(parsed)


def apply_preferences(labels, chain, preferences):
    """Return `chain` re-ordered by the FIRST matching preference, or `chain` unchanged.

    A preference matches when the issue carries at least one of its EXACT `labels` AND the chain
    already contains EVERY model in `requires`. Exact, never substring: a substring selector on
    `"gui"` would sweep `area:guide` / `area:guidance` into the carve-out.

    Idempotent, and a strict permutation of the input — asserted, not assumed.
    """
    chain = list(chain)
    label_set = set(labels)
    for wanted, lead, requires in preferences:
        if not (label_set & wanted):
            continue
        if not requires <= set(chain):
            # "for which they are BOTH possible implementors" — the chain does not offer this
            # preference's models, so the route is left exactly as the table wrote it.
            continue
        reordered = [lead] + [model for model in chain if model != lead]
        if sorted(reordered) != sorted(chain):  # pragma: no cover — structurally unreachable
            raise ChainPreferenceError(
                f"chain preference for lead {lead!r} did not preserve the chain as a permutation: "
                f"{chain} -> {reordered}")
        return reordered
    return chain


def preference_labels(preferences):
    """The union of every selector label — the audit surface for "what does this table carve out"."""
    return sorted({label for labels, _lead, _requires in preferences for label in labels})


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
    chk("a declaration parses to (labels, lead, requires)",
        [(sorted(a), b, sorted(c)) for a, b, c in gui],
        [(["area:gui"], "sol", ["opus5", "sol"])])
    chk("the audit surface is the union of the selectors", preference_labels(gui), ["area:gui"])

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
