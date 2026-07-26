#!/usr/bin/env python3
"""Shared fail-closed schema for the mutable lease ledger."""

from __future__ import annotations

import argparse
import re
from typing import Any


GLOBAL_PACKAGE = "__global__"   # the serializing partition (excludes against every area)

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
    """THE canonical reduction from a row's `area:*` sections to the ONE `package` partition its
    lease reserves (registry issue #112). EXACTLY ONE distinct area -> that area; ZERO OR MULTIPLE
    -> the serializing global partition, so a multi-area row can never co-run with in-flight work
    in ANY of its areas. Fail-closed: over-serialize a multi-area row rather than free a busy
    sibling crate. Takes BARE area names (no `area:` prefix); non-string / empty entries are
    ignored.

    Canonical HERE — beside `validate_ledger`, which owns the `package` field's other invariant —
    because this value is derived INDEPENDENTLY by the dispatcher that MINTS a claim and by the
    review/fix run that ADOPTS it, and review-fix.yml's `Adopt dispatcher-owned CAS claim` step
    compares the two for EQUALITY. Every derivation must therefore be the SAME function, not a
    prose promise that three copies "mirror byte-for-byte".

    THE INCIDENT this exists to prevent (LIVE 2026-07-26): review-fix.yml's `resolve` job still
    carried the pre-#112 alphabetically-first reduction (`packages[0] if packages else
    "__global__"`) while dispatch-claim.py had migrated to this one. A PR whose provenance source
    issue carried TWO `area:*` labels (sparq-org/sparq#3528 <- issue #2582: `area:ci` + `area:site`)
    therefore had its claim minted as `__global__` and re-derived as `ci`, so the adopt step
    rejected its OWN dispatcher's claim, released the lease, and exited 1 — every tick, forever:
    51 of the 69 review-fix failures that day, 47 of them on that one PR, ~20% of the review lane's
    capacity burned on a loop that could never converge. The equality check was RIGHT; one
    derivation was wrong. So there is now exactly one derivation."""
    unique = {area for area in (areas or ()) if isinstance(area, str) and area}
    return next(iter(unique)) if len(unique) == 1 else GLOBAL_PACKAGE


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
    # Each case below is the counterfactual for one property of the reduction; the pre-fix
    # `sorted(areas)[0] if areas else GLOBAL_PACKAGE` REVERSES exactly the multi-area row.
    check("one area reserves that area", plan_package(["site"]) == "site")
    check("no area reserves the global partition", plan_package([]) == GLOBAL_PACKAGE)
    check("MULTI-area reserves the global partition (not the alphabetically-first area)",
          plan_package(["ci", "site"]) == GLOBAL_PACKAGE
          and plan_package(["site", "ci"]) == GLOBAL_PACKAGE)
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
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    parser.error("--self-test is required")


if __name__ == "__main__":
    raise SystemExit(main())
