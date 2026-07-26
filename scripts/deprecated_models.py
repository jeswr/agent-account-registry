#!/usr/bin/env python3
# [OPUS-5] Shared deprecation register for the 2026-07-26 model retirement.
"""deprecated_models.py — ONE source of truth for which models are retired, and how to migrate
history that still names them.

MAINTAINER DIRECTIVE 2026-07-26: "deprecate the use of fable and opus entirely in favour of opus5".

This module is imported (never re-declared) by every routing surface in the registry:
`dispatch-claim.py` (REVIEW_CHAIN / FIX_CHAIN), `worker-pr.py` (ESCALATION_LADDERS), and
`.github/workflows/review-fix.yml`'s inline resolve. Two hand-maintained copies of a deprecation
list is exactly how a retired model returns in one of them.

WHY A MIGRATION MAP AND NOT JUST A BAN
--------------------------------------
The retired aliases are not only written in config — they are written into HISTORY, as bot markers
on live PRs: `<!-- ...fix-model... tier=fable ... -->`, recorded per-round fix models, and pinned
fix floors. Those markers are read back on every tick.

Deleting the aliases from ESCALATION_LADDERS without migrating those reads turns
`decide_budget()` / `pinned_fix_floor()` / `record_model_pin()` into a hard `WorkerPrError`
("a recorded fix-round model is not a ladder member") for EVERY in-flight PR whose earlier rounds
ran on opus or fable — a permanent stall on work that was healthy before the deprecation, with the
failure attributed to the PR rather than to the config change. Measured here: the registry
self-test suite reproduced exactly that error the moment the ladder lost its lower rungs.

So a read of a retired tier MIGRATES UP to opus5 rather than raising. Migrating UP is the safe
direction: the fix floor may only ever rise (`pinned_fix_floor` takes the max), so mapping a
historical opus/fable rung onto opus5 can never *lower* a floor and can never re-run a tier the
pin was meant to forbid. A retired tier in NEW CONFIG is still a hard error — that is
`assert_no_deprecated()`.
"""

# Retired 2026-07-26. Both halves matter: the ALIAS (what a chain writes) and the concrete
# PROVIDER ID (what the alias resolved to) — banning only the alias lets the model come back under
# a fresh name.
DEPRECATED_ALIASES = frozenset({"fable", "opus"})
DEPRECATED_PROVIDER_MODELS = frozenset({"claude-fable-5", "claude-opus-4-8"})

# The surviving anthropic tier. Probe-verified live 2026-07-26 (`claude --model claude-opus-5 -p`
# -> OK; modelUsage canonicalModel "claude-opus-5").
SUCCESSOR = "opus5"

# Historical tier -> its successor. Applied ONLY when reading history, never when validating config.
LEGACY_PIN_MIGRATION = {alias: SUCCESSOR for alias in DEPRECATED_ALIASES}


class DeprecatedModelError(ValueError):
    """A retired model was found in a routing position (as opposed to in history)."""


def migrate_tier(tier):
    """Map a historical tier marker onto its successor. Unknown / current tiers pass through
    unchanged, so this is safe to apply to every tier read."""
    return LEGACY_PIN_MIGRATION.get(tier, tier)


def migrate_tiers(tiers):
    """`migrate_tier` over an iterable, order-preserving and de-duplicated."""
    out = []
    for t in tiers:
        m = migrate_tier(t)
        if m not in out:
            out.append(m)
    return out


def assert_no_deprecated(where, aliases):
    """Raise if any of `aliases` is retired. This is the CONFIG half — it must stay strict even
    though the history half migrates, otherwise a retired model quietly re-enters via a new chain
    and the migration silently launders it."""
    offenders = sorted(set(aliases) & DEPRECATED_ALIASES)
    if offenders:
        raise DeprecatedModelError(
            f"{where}: names model(s) retired on 2026-07-26 in favour of {SUCCESSOR!r}: "
            f"{offenders}")


def assert_table_clean(name, table):
    """`assert_no_deprecated` over a {provider: [alias, ...]} routing table."""
    for provider, chain in table.items():
        assert_no_deprecated(f"{name}[{provider!r}]", chain)


def assert_catalog_clean(models):
    """Raise if a routing [models] catalog defines a retired alias, or pins a retired provider id
    under any alias name (the smuggle-it-back-under-a-new-name path)."""
    for name, spec in (models or {}).items():
        if name in DEPRECATED_ALIASES:
            raise DeprecatedModelError(f"[models.{name}] is a retired alias (2026-07-26)")
        pm = (spec or {}).get("provider_model")
        if pm in DEPRECATED_PROVIDER_MODELS:
            raise DeprecatedModelError(
                f"[models.{name}] pins retired provider_model {pm!r} (2026-07-26)")


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def raises(name, fn, needle):
        nonlocal ok
        try:
            fn()
        except DeprecatedModelError as e:
            good = needle in str(e)
            ok = ok and good
            print(f"  {'ok  ' if good else 'FAIL'} {name}: raised "
                  f"{'with' if good else 'WITHOUT'} {needle!r}")
        else:
            ok = False
            print(f"  FAIL {name}: did NOT raise")

    chk("fable migrates up to opus5", migrate_tier("fable"), "opus5")
    chk("opus migrates up to opus5", migrate_tier("opus"), "opus5")
    chk("a current tier passes through", migrate_tier("sol"), "sol")
    chk("an unknown tier passes through (validated elsewhere)", migrate_tier("ghost"), "ghost")
    # The de-duplication matters: a PR whose rounds ran on BOTH opus and fable must not yield
    # ["opus5", "opus5"] — decide_budget indexes the ladder and a duplicate would double-count.
    chk("a legacy multi-tier history collapses onto one rung",
        migrate_tiers(["opus", "fable"]), ["opus5"])
    chk("migration preserves order and current tiers",
        migrate_tiers(["luna", "opus", "sol"]), ["luna", "opus5", "sol"])
    chk("migration is idempotent", migrate_tiers(migrate_tiers(["opus", "fable"])), ["opus5"])

    raises("a retired alias in a chain is REJECTED",
           lambda: assert_no_deprecated("FIX_CHAIN['anthropic']", ["opus5", "fable"]), "fable")
    raises("a retired alias in a TABLE is REJECTED",
           lambda: assert_table_clean("REVIEW_CHAIN", {"openai": ["opus5", "opus"]}), "opus")
    raises("a re-added [models.fable] catalog entry is REJECTED",
           lambda: assert_catalog_clean({"fable": {"provider_model": "claude-fable-5"}}),
           "retired alias")
    raises("a retired provider id under a fresh alias is REJECTED",
           lambda: assert_catalog_clean({"legacy": {"provider_model": "claude-opus-4-8"}}),
           "retired provider_model")
    chk("a clean table passes",
        assert_table_clean("FIX_CHAIN", {"anthropic": ["opus5"], "openai": ["sol", "luna"]}), None)
    chk("a clean catalog passes",
        assert_catalog_clean({"opus5": {"provider_model": "claude-opus-5"}}), None)
    # The CONFIG half must stay strict even though the HISTORY half migrates: otherwise a retired
    # model re-enters via a new chain and migrate_tier() silently launders it into opus5.
    raises("config validation does NOT use the migration map",
           lambda: assert_no_deprecated("chain", migrate_tiers(["opus"]) + ["fable"]), "fable")

    print("deprecated_models self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(_self_test() if "--self-test" in sys.argv else 0)
