#!/usr/bin/env python3
"""Shared fail-closed schema for the mutable lease ledger."""

from __future__ import annotations

import argparse
import re
from typing import Any


GLOBAL_PACKAGE = "__global__"   # the serializing partition (excludes against every area)
# A partition key names a SET of areas. One area is its own name; two or more are joined with this
# separator in sorted order, so the key is a canonical function of the set (registry #692 line of
# work). `__global__` is the UNIVERSAL set and is the only key that intersects every other.
PARTITION_SEPARATOR = ","

ACCOUNT = re.compile(r"[0-9a-f]{16}")
CLAIM = re.compile(r"[0-9a-f]{32}")
REPOSITORY = r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*"
HOLDER = re.compile(rf"{REPOSITORY}#[1-9][0-9]*@[^\r\n]+")
REPAIR_HOLDER = re.compile(rf"(?:review:|fix:){REPOSITORY}#[1-9][0-9]*(?:@[^\r\n]+)?")


class LeaseSchemaError(ValueError):
    """The ledger cannot safely be consumed or mutated."""


def is_repair_holder(value: Any) -> bool:
    return isinstance(value, str) and REPAIR_HOLDER.fullmatch(value) is not None


def plan_package(areas: Any) -> str:
    """THE canonical reduction from a row's `area:*` sections to the `package` partition key its
    lease reserves (registry issue #112). A key names a SET of areas: EXACTLY ONE distinct area ->
    that area; TWO OR MORE -> the canonical sorted, `,`-joined composite naming EXACTLY those
    areas; ZERO -> the serializing global partition. Takes BARE area names (no `area:` prefix);
    non-string / empty entries are ignored.

    WHY MULTI-AREA IS NO LONGER `__global__`. It used to be, and that made "touches A and B" mean
    "touches EVERYTHING": `packages_conflict` then excluded such a row against every partition on
    the board, so it could not co-run with anything and nothing could co-run with it. MEASURED on
    the live board: 65 of 468 ready issues (13.9%) reduced that way and self-blocked, and an
    earlier sample found 37 of those 65 (57%) carry genuinely distinct crates — the LABELS were
    right, the reduction was wrong. `{A,B}` now reserves `{A,B}`, and two rows conflict iff their
    area sets INTERSECT (`packages_conflict`). This narrows only where the labels PROVE the
    footprint.

    ZERO AREAS STAYS `__global__`, and that asymmetry is the whole safety argument. An unlabelled
    row's true footprint is UNKNOWN, so it must keep reserving everything; narrowing it to
    "nothing" would make an item whose blast radius nobody can name concurrent with all work at
    once. Registry #75 (4 no-area issues froze the sparq frontier) and #772 (one unprovenanced PR
    reserved `__global__` and zeroed the impl lane) are the two directions of that trade: an
    over-wide CANDIDATE costs one dispatch, an under-wide OCCUPANT costs correctness.

    Canonical HERE — beside `validate_ledger`, which owns the `package` field's other invariant —
    because this value is derived INDEPENDENTLY by the dispatcher that MINTS a claim and by the
    review/fix (or worker) run that ADOPTS it, and both adopt steps compare the two for EQUALITY.
    Every derivation must therefore be the SAME function, not a prose promise that four copies
    "mirror byte-for-byte".

    THE INCIDENT this exists to prevent (LIVE 2026-07-26): review-fix.yml's `resolve` job still
    carried the pre-#112 alphabetically-first reduction (`packages[0] if packages else
    "__global__"`) while dispatch-claim.py had migrated to this one. A PR whose provenance source
    issue carried TWO `area:*` labels (sparq-org/sparq#3528 <- issue #2582: `area:ci` + `area:site`)
    therefore had its claim minted as `__global__` and re-derived as `ci`, so the adopt step
    rejected its OWN dispatcher's claim, released the lease, and exited 1 — every tick, forever:
    53 of the 77 review-fix failures that day, 47+ of them on that one PR, ~20% of the review
    lane's capacity burned on a loop that could never converge. The equality check was RIGHT; one
    derivation was wrong. So there is now exactly one derivation, and every consumer that CAN
    import it does (`plan_package_csv` below is the entry point for shell callers, so even a
    `run:` script has no reason to re-implement it)."""
    unique = {area for area in (areas or ()) if isinstance(area, str) and area}
    if not unique or GLOBAL_PACKAGE in unique:
        # [#938 review N2] `__global__` is the UNIVERSAL key, so it can never be an ordinary atom
        # inside a composite: `plan_package(["__global__", "a"])` would otherwise be the key
        # `"__global__,a"`, which `package_areas` reads as the NARROW set {"__global__", "a"} and
        # which therefore does not conflict with `z` — a row that names the universal partition
        # silently ceasing to reserve it. It absorbs instead. Unreachable through the live
        # producers (`SAFE_AREA` in mint-provenance, `worker.yml`/`review-fix.yml`'s resolve
        # gates, and `SAFE_PACKAGE` all reject that spelling), which is precisely why it must be
        # closed by CONSTRUCTION here rather than left to those four gates staying correct.
        return GLOBAL_PACKAGE
    return PARTITION_SEPARATOR.join(sorted(unique))


def package_areas(package: Any) -> frozenset | None:
    """The SET of areas a partition key reserves, or `None` meaning EVERY area.

    `None` (the universal set) for `__global__` and for anything unreadable — a non-string, an
    empty string, a key with an empty atom. FAIL-CLOSED BY CONSTRUCTION: the one thing this must
    never do is return an EMPTY set for a key it cannot parse, because an empty set intersects
    nothing and would make an unparseable key concurrent with all work at once. There is no input
    for which this returns `frozenset()`."""
    if not isinstance(package, str) or not package or package == GLOBAL_PACKAGE:
        return None
    atoms = package.split(PARTITION_SEPARATOR)
    if any(not atom or atom == GLOBAL_PACKAGE for atom in atoms):
        # A malformed key — or one naming the universal partition as an atom — is unknown
        # footprint, i.e. everything. `plan_package` cannot mint the second shape (it absorbs),
        # but this reads keys off a ledger a different process wrote, so it decides it too.
        return None
    return frozenset(atoms)


def packages_conflict(left: Any, right: Any) -> bool:
    """Whether two partition keys exclude each other: TRUE iff their area sets INTERSECT.

    THE conflict predicate over two KEYS. Both LEDGER enforcement sites — the allocator's
    `partition_available` and the cross-lane `sibling_lease_conflict` — decide with this function
    rather than with `==`/`in` over the key STRING, because a widening applied at one site and not
    at another admits work the other half then refuses, which is worse than either. The universal
    key intersects everything, so `__global__` on either side still serializes in both directions
    exactly as before.

    The two OPEN-PR sites (`dispatch-claim.filter_busy_area_items` and
    `revalidate_items_against_live_pulls`) decide against the expanded busy UNION and reach this
    semantics through `partition_defer_attribution`, which shares `package_areas` but not this
    function — a second implementation, equivalent by test rather than by construction. Any change
    to the exclusion RULE (not merely to set parsing) has to land in both; see
    `research/1011-global-partition-bounded-concurrency.md` §4."""
    left_areas, right_areas = package_areas(left), package_areas(right)
    if left_areas is None or right_areas is None:
        return True
    return bool(left_areas & right_areas)


def package_conflicts_with_areas(package: Any, areas: Any) -> bool:
    """`packages_conflict` against an already-expanded set of AREA ATOMS (the busy union).

    The busy union is a union over occupants of the atoms each holds, so it is a plain set of area
    names that may additionally contain `__global__`. An EMPTY union conflicts with nothing — that
    is "nobody holds anything", not "unknown footprint" — so it is the one case here that is not
    fail-closed, and it is exactly the case every caller already special-cases (`if not busy`)."""
    if not isinstance(areas, (set, frozenset)):
        areas = frozenset(areas or ())
    if GLOBAL_PACKAGE in areas:
        return True
    own = package_areas(package)
    if own is None:
        return bool(areas)                # universal key: any live reservation excludes it
    return bool(own & areas)


def plan_package_csv(csv: Any) -> str:
    """`plan_package` over the resolve jobs' sorted, de-duplicated area CSV (`packages`), so a
    workflow `run:` SHELL step can reach the canonical reduction with one `python3` call instead of
    open-coding it in bash — which is exactly what worker.yml's self-claim step used to do. Area
    names are comma-free by construction (the resolve step rejects any `area:*` label outside
    `[A-Za-z0-9][A-Za-z0-9_.-]*`), so splitting on `,` is lossless. A non-string / empty CSV
    reduces to the serializing partition (fail-closed)."""
    if not isinstance(csv, str):
        return GLOBAL_PACKAGE
    return plan_package([area.strip() for area in csv.split(",")])


def validate_ledger(document: Any) -> list[dict[str, Any]]:
    """Validate a ledger and return canonical rows, dropping only legacy account identities."""
    if not isinstance(document, dict) or set(document) != {"leases"}:
        raise LeaseSchemaError("lease ledger top level is malformed")
    leases = document["leases"]
    if not isinstance(leases, list):
        raise LeaseSchemaError("lease ledger leases field is malformed")

    canonical = []
    claims: set[str] = set()
    for lease in leases:
        if not isinstance(lease, dict):
            raise LeaseSchemaError("lease ledger contains a non-object entry")
        account = lease.get("account")
        if not isinstance(account, str) or ACCOUNT.fullmatch(account) is None:
            # Preserve the existing bounded migration: raw pre-fingerprint rows are ignored and
            # disappear on the next CAS write, but malformed canonical rows always fail closed.
            continue
        claim = lease.get("claim_id")
        if not isinstance(claim, str) or CLAIM.fullmatch(claim) is None:
            raise LeaseSchemaError("lease ledger contains an unsafe claim id")
        if claim in claims:
            raise LeaseSchemaError("lease ledger contains duplicate claim ids")
        claims.add(claim)
        holder = lease.get("holder")
        if (not is_repair_holder(holder)
                and (not isinstance(holder, str) or HOLDER.fullmatch(holder) is None)):
            raise LeaseSchemaError("lease holder does not identify a safe target issue")
        issued = lease.get("issued_at")
        expires = lease.get("expires_at")
        if (not isinstance(issued, int) or isinstance(issued, bool) or issued <= 0
                or not isinstance(expires, int) or isinstance(expires, bool) or expires <= issued):
            raise LeaseSchemaError("lease timestamps are malformed or unordered")
        for field in ("account", "package", "role", "model"):
            if not isinstance(lease.get(field), str) or not lease[field]:
                raise LeaseSchemaError(f"lease {field} is malformed")
        canonical.append(lease)
    return canonical


def _self_test() -> int:
    base = {
        "account": "a" * 16, "claim_id": "b" * 32,
        "holder": "owner/repo#1@2.1", "package": "pkg", "role": "impl",
        "model": "sol", "issued_at": 10, "expires_at": 20,
    }
    ok = True

    def check(name: str, condition: bool) -> None:
        nonlocal ok
        ok = ok and condition
        print(f"  {'ok  ' if condition else 'FAIL'} {name}")

    check("canonical lease is accepted", validate_ledger({"leases": [base]}) == [base])
    check("legacy identity is filtered", validate_ledger(
        {"leases": [{**base, "account": "legacy-handle"}]}) == [])
    for name, document in (
        ("extra top-level field is rejected", {"leases": [], "unsafe": True}),
        ("duplicate claim is rejected", {"leases": [base, dict(base)]}),
        ("unordered timestamps are rejected",
         {"leases": [{**base, "expires_at": base["issued_at"]}]}),
        ("malformed holder is rejected", {"leases": [{**base, "holder": "unsafe"}]}),
        ("empty required field is rejected", {"leases": [{**base, "model": ""}]}),
    ):
        try:
            validate_ledger(document)
        except LeaseSchemaError:
            rejected = True
        else:
            rejected = False
        check(name, rejected)

    # ---- plan_package: THE partition reduction (registry issue #112 / the 2026-07-26 adopt loop).
    # Each case below is the counterfactual for one property of the reduction; the pre-#112
    # `sorted(areas)[0] if areas else GLOBAL_PACKAGE` REVERSES exactly the multi-area row.
    check("one area reserves that area", plan_package(["site"]) == "site")
    check("no area reserves the global partition", plan_package([]) == GLOBAL_PACKAGE)
    check("MULTI-area reserves EXACTLY its own areas, canonically ordered — never the "
          "alphabetically-first area, and never the global partition",
          plan_package(["ci", "site"]) == "ci,site"
          and plan_package(["site", "ci"]) == "ci,site")
    check("a duplicate area collapses to one area", plan_package(["ci", "ci"]) == "ci")
    check("order does not change a single-area reduction",
          plan_package(["site"]) == plan_package(("site",)))
    check("non-string / empty entries are ignored, not counted as areas",
          plan_package(["ci", "", None, 0]) == "ci"          # type: ignore[list-item]
          and plan_package([None, ""]) == GLOBAL_PACKAGE)    # type: ignore[list-item]
    check("None reduces to the global partition rather than raising",
          plan_package(None) == GLOBAL_PACKAGE)
    # The reduction is a PARTITION name, so it must satisfy the ledger's `package` field invariant
    # (non-empty str) for every input — otherwise a multi-area claim writes an unvalidatable lease.
    check("every reduction is a valid ledger package field",
          all(isinstance(plan_package(a), str) and plan_package(a)
              for a in ([], ["a"], ["a", "b"], None, ["", None])))
    # The CSV entry point workflow SHELL steps call. Same reduction, same fail-closed direction.
    check("the CSV entry point agrees with plan_package on every shape",
          plan_package_csv("") == GLOBAL_PACKAGE
          and plan_package_csv("site") == "site"
          and plan_package_csv("ci,site") == "ci,site"
          and plan_package_csv("ci,ci") == "ci"
          and plan_package_csv(None) == GLOBAL_PACKAGE)   # type: ignore[arg-type]
    # A composite key round-trips through the CSV entry point unchanged, so the shell caller that
    # reduces `$PACKAGES` and the python caller that re-derives from labels cannot disagree.
    check("a composite key is a fixed point of the CSV entry point",
          plan_package_csv("ci,site") == plan_package_csv("site,ci") == "ci,site")

    # ---- packages_conflict: THE exclusion predicate. An item labelled {A,B} must reserve {A,B},
    # not the whole world. THIS IS THE RED TEST for that change: under the pre-fix reduction
    # `{A,B}` was `__global__`, so the first line below was FALSE (it excluded against `c`) and the
    # first control was vacuous (everything conflicted with everything).
    check("[RED] {A,B} and {C} are CONCURRENT — a multi-area row no longer reserves the world",
          not packages_conflict(plan_package(["a", "b"]), plan_package(["c"])))
    check("[RED] {A,B} and {B,C} EXCLUDE — the sets intersect on B",
          packages_conflict(plan_package(["a", "b"]), plan_package(["b", "c"])))
    check("[CONTROL] two {A} items still exclude",
          packages_conflict(plan_package(["a"]), plan_package(["a"])))
    check("[CONTROL] a ZERO-area item still reserves EVERYTHING (fail-closed, both directions)",
          plan_package([]) == GLOBAL_PACKAGE
          and packages_conflict(plan_package([]), plan_package(["a"]))
          and packages_conflict(plan_package(["a"]), plan_package([]))
          and packages_conflict(plan_package([]), plan_package(["a", "b"]))
          and packages_conflict(plan_package([]), plan_package([])))
    check("[CONTROL] {A,B} and {C,D} are concurrent; {A,B} and {A,B} are not",
          not packages_conflict("a,b", "c,d") and packages_conflict("a,b", "a,b"))
    check("conflict is symmetric on every pair tried",
          all(packages_conflict(x, y) == packages_conflict(y, x)
              for x in ("a", "a,b", "b,c", GLOBAL_PACKAGE, "", None)      # type: ignore[arg-type]
              for y in ("a", "a,b", "b,c", GLOBAL_PACKAGE, "", None)))    # type: ignore[arg-type]
    # An UNPARSEABLE key must read as the universal set, never as the empty one: an empty set
    # intersects nothing and would make a key we cannot read concurrent with all live work.
    check("an unreadable key is the UNIVERSAL set, never the empty set",
          package_areas(None) is None and package_areas("") is None      # type: ignore[arg-type]
          and package_areas(GLOBAL_PACKAGE) is None and package_areas("a,") is None
          and package_areas(",a") is None and package_areas(0) is None   # type: ignore[arg-type]
          and all(packages_conflict(bad, "a")
                  for bad in (None, "", "a,", ",a", 0, [], GLOBAL_PACKAGE)))
    check("a readable key names EXACTLY its atoms",
          package_areas("a") == frozenset({"a"})
          and package_areas("a,b") == frozenset({"a", "b"}))
    # [#938 review N2] `__global__` ABSORBS: it is the universal key, so it can never be one atom
    # among others. Without this, `plan_package(["__global__", "a"])` is the key `"__global__,a"`,
    # which reads as the NARROW set {"__global__", "a"} and does NOT conflict with `z` — a row
    # that names the universal partition quietly ceasing to reserve it. Closed by construction
    # rather than left to the four label-grammar gates upstream staying correct.
    check("[N2] `__global__` absorbs — it is never an atom inside a composite key",
          plan_package(["__global__", "a"]) == GLOBAL_PACKAGE
          and plan_package(["a", "__global__", "b"]) == GLOBAL_PACKAGE
          and plan_package(["__global__"]) == GLOBAL_PACKAGE
          and plan_package_csv("__global__,a") == GLOBAL_PACKAGE)
    check("[N2] ...and a key carrying it as an atom READS as the universal set, both directions",
          package_areas("__global__,a") is None
          and package_areas("a,__global__") is None
          and packages_conflict("__global__,a", "z")
          and packages_conflict("z", "__global__,a")
          and package_conflicts_with_areas("__global__,a", {"z"}))
    # `package_conflicts_with_areas` is the same predicate against the busy UNION (a set of atoms
    # that may carry `__global__`). The two must agree wherever both are defined, or the assemble
    # leg and the allocator disagree about the same board.
    check("the busy-union form agrees with the pairwise form",
          package_conflicts_with_areas("a,b", {"c"}) is False
          and package_conflicts_with_areas("a,b", {"b"}) is True
          and package_conflicts_with_areas("a,b", {GLOBAL_PACKAGE}) is True
          and package_conflicts_with_areas(GLOBAL_PACKAGE, {"c"}) is True
          and package_conflicts_with_areas(GLOBAL_PACKAGE, set()) is False
          and package_conflicts_with_areas("a", set()) is False)
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    # The reduction as a CLI so a workflow SHELL step never re-implements it (see plan_package_csv).
    parser.add_argument("--plan-package", metavar="AREA_CSV",
                        help="print the canonical package partition for a sorted area CSV")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    if args.plan_package is not None:
        print(plan_package_csv(args.plan_package))
        return 0
    parser.error("--self-test or --plan-package is required")


if __name__ == "__main__":
    raise SystemExit(main())
