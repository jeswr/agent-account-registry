# Implementer provenance records

One JSON file per worker pull request, `<owner>--<repo>--pr<N>.json`, written by the dedicated
`provenance` job in worker.yml after the `publish` job (and by `scripts/backfill-provenance.py`
for pre-existing PRs). That job executes NO target code — the worker job that runs model-authored
code host-side holds no registry-write token, so hostile target code can never write or forge
these records. Since issue #575 the PR itself is also opened outside that job: `publish` runs on
its own runner and reconstructs the model's work from a digest-bound patch sealed before the
target's gate ran, so no write-capable target token ever shares a runner with gated target code.
`provenance` still reconciles from the deterministic head branch and the live API — it does not
consume the publisher's reported PR number — so the root of trust is unchanged.

```json
{"pr_number": 1, "head_sha_at_open": "<40-hex>", "impl_provider": "anthropic|openai",
 "impl_alias": "<model alias>", "impl_account_h": "<16-hex>", "issue": 1,
 "recorded_at_run": "<run>.<attempt>"}
```

`impl_account_h = sha256(handle + ':' + PROVENANCE_SALT)[:16]` — this registry is PUBLIC, so
records never carry a raw account handle; the reviewer != implementer account assertion hashes
the live reviewer handle the same way at claim time and compares hashes.

## Attestation classes (issue #657)

`recorded_at_run` is not free-form audit text — it names the **trust basis** the record's
implementer identity rests on, and admission reads it. Only these shapes exist:

| stamp | class | admissible? | written by |
|---|---|---|---|
| `<run>.<attempt>` | `worker-run` | yes — machine-attested | worker.yml's `provenance` job |
| `backfill:<run>.<attempt>` | `backfill` | yes — machine-attested | `scripts/backfill-provenance.py` |
| `orchestrator:<run>.<attempt>` | `orchestrator` | **no** — self-attested | an actor holding a registry credential |
| anything else / absent | — | **no** — unrecognised | — |

The two machine classes are written **host-side**, by a job that executes no target code. A
self-attested record was written by something that may **also have authored the diff**, so its
`impl_provider` is an assertion by the implementer about itself — and the lane picks the reviewer
by *inverting* that field. Admitting the class would let a record choose its own reviewer's
provider, collapsing the cross-provider inversion into a same-provider review that still *looks*
cross-provider. The class is therefore recognised and **refused under its own diagnostic**, never
folded into the generic malformed-stamp reason, so an audit can tell "nobody stamped this" from
"an actor holding a registry credential stamped its own work".

**Honest scope:** this is a fail-closed hardening and a distinguishability primitive, **not** an
anti-forgery guarantee — an actor with registry write can simply write a machine-shaped stamp
instead. The property that survives a forged declaration is *never reading the declared provider
to pick the reviewer*; see `research/657-orchestrator-pr-admission.md`.

This registry file is the review loop's ROOT OF TRUST for the implementer identity: the target
model has no registry token, so it cannot forge these records, unlike commit trailers or PR body
markers (audit-only). A PR with no record here is NEVER enumerated for review (fail closed), and
the cross-provider inversion + reviewer!=implementer assertions consume ONLY these values.
Records are create-only (`worker-pr.py` refuses to overwrite an existing record with different
content), so a later run can never silently rewrite an implementer identity.
