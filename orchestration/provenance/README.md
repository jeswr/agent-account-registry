# Implementer provenance records

One JSON file per worker pull request, `<owner>--<repo>--pr<N>.json`, written by the dedicated
`provenance` job in worker.yml after publish (and by `scripts/backfill-provenance.py` for
pre-existing PRs). That job executes NO target code — the worker job that runs model-authored
code host-side holds no registry-write token, so hostile target code can never write or forge
these records.

```json
{"pr_number": 1, "head_sha_at_open": "<40-hex>", "impl_provider": "anthropic|openai",
 "impl_alias": "<model alias>", "impl_account_h": "<16-hex>", "issue": 1,
 "recorded_at_run": "<run>.<attempt>", "ledger_hmac_sha256": "<64-hex>"}
```

`impl_account_h = sha256(handle + ':' + PROVENANCE_SALT)[:16]` — this registry is PUBLIC, so
records never carry a raw account handle; the reviewer != implementer account assertion hashes
the live reviewer handle the same way at claim time and compares hashes.

This registry file is the review loop's ROOT OF TRUST for the implementer identity. Its canonical
JSON content is authenticated with HMAC-SHA256 under the dedicated `LEDGER_RECORD_HMAC_KEY` held
by trusted host-side record jobs. Merely gaining `contents:write` on the unprotected ledger branch
therefore cannot forge a record. A missing, unsigned, or modified record is NEVER enumerated for
review (fail closed), and
the cross-provider inversion + reviewer!=implementer assertions consume ONLY these values.
Records are create-only (`worker-pr.py` refuses to overwrite an existing record with different
content), so a later run can never silently rewrite an implementer identity.
