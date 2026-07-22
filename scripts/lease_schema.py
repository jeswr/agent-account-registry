#!/usr/bin/env python3
"""Shared fail-closed schema for the mutable lease ledger."""

from __future__ import annotations

import argparse
import re
from typing import Any


ACCOUNT = re.compile(r"[0-9a-f]{16}")
CLAIM = re.compile(r"[0-9a-f]{32}")
REPOSITORY = r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*"
HOLDER = re.compile(rf"{REPOSITORY}#[1-9][0-9]*@[^\r\n]+")
REPAIR_HOLDER = re.compile(rf"(?:review:|fix:){REPOSITORY}#[1-9][0-9]*(?:@[^\r\n]+)?")


class LeaseSchemaError(ValueError):
    """The ledger cannot safely be consumed or mutated."""


def is_repair_holder(value: Any) -> bool:
    return isinstance(value, str) and REPAIR_HOLDER.fullmatch(value) is not None


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
