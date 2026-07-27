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
| `orchestrator:<run>.<attempt>` | `orchestrator` | **only by explicit opt-in** — self-attested | an actor holding a registry credential |
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

### Admitting the `orchestrator` class (the opt-in)

The class is refused by **default and by every consumer**. One consumer can opt in, per call, via
`provenance_admission_error(record, pr, admit_orchestrator=True)` — a parameter rather than a
widening of `MACHINE_ATTESTED_CLASSES`, because the class is not safe for every consumer. A
consumer that only READS a PR is safe; one that PUSHES CODE or ARMS on the record's authority is
not. Today exactly one consumer opts in: `enumerate_review_items`, and only to emit
`needs-review`.

Admission additionally requires the PR's author login to appear in that repo's
`review_enrolment_authors` in `policy/repos.toml`. **The two halves live on branches of different
authority on purpose.** Records live on the unprotected `ledger` branch precisely because master's
required `gate` check rejects direct contents-API PUTs (issue #96), so minting a record is a
low-authority act available to anything holding the App token. The allowlist lives on master,
behind branch protection, so the *set* of logins that can ever be admitted is a reviewed change
even when an individual record is not. Neither half admits anything alone.

Enrolment never waives the fork gate, the record's field admission, the human holds, the machine
parks, or any lease rule — and it never makes the class equal to a worker PR. See
`research/657-orchestrator-pr-admission.md` §7, including **§7.3: the class is not yet wired at
CLAIM or in `review-fix.yml`, so no repo may enable `review_enrolment_authors` yet** — a
self-test interlock enforces that.

### Minting an `orchestrator` record (the ONE supported writer)

`.github/workflows/mint-provenance.yml` (`workflow_dispatch`, one PR per run, DRY RUN unless
`apply=true`) → `scripts/mint-provenance.py`. Design record:
`research/657-orchestrator-provenance-minting.md`.

There is deliberately **no operator-supplied identity**. Every field is read from the live API or
pinned by the script:

| field | source |
|---|---|
| `pr_number` / `head_sha_at_open` | the LIVE PR read; the operator's number only ever FETCHES, and a payload identifying a different PR is refused |
| `impl_provider` | a lookup of `--impl-alias` in the TARGET's protected routing catalog, refused unless it is `anthropic` — which is what keeps the review side constant (the lane inverts this field) |
| `impl_account_h` | the live author login, domain-separated as `orchestrator:<login>` so it can never collide with an `acctNN` preimage |
| `issue` | the operator-named issue, refused unless it is an OPEN, non-PR issue the PR NAMES, whose `area:*` labels are safe atoms and do not reduce to the serializing `__global__` partition |
| `recorded_at_run` | `orchestrator:<this run>.<attempt>`, built inside the script from the runner's own environment |

**The class cannot be escalated on this path.** No workflow input, env binding or CLI argument
names a run key or an attestation class (asserted structurally by the self-test), and the script
refuses any stamp whose class is not `orchestrator` — so the supported writer can only ever produce
the weakest class, which `worker-pr.ready_and_arm` refuses outright.

**It cannot enrol anyone.** The script refuses to mint for a login that is not already in that
repo's `review_enrolment_authors` (master, branch-protected), and refuses a `[bot]` login
independently of `policy-resolve`'s refusal. Removing a login from master REVOKES every record
minted for it, without touching the ledger — the consumers re-read the allowlist live.

**Failure degrades to today.** A refusal writes nothing; a PR with no record is never enumerated,
so no tick spends anything on it. The script also runs the review lane's own
`provenance_admission_error(..., admit_orchestrator=True)` over the document it is about to write
and refuses to write one the lane would then refuse. Records stay create-only: a divergent or
differently-classed existing record is a refusal for a human, never an overwrite, while an
identical record — including one stamped by a different mint run — is idempotent success.

This registry file is the review loop's ROOT OF TRUST for the implementer identity: the target
model has no registry token, so it cannot forge these records, unlike commit trailers or PR body
markers (audit-only). A PR with no record here is NEVER enumerated for review (fail closed), and
the cross-provider inversion + reviewer!=implementer assertions consume ONLY these values.
Records are create-only (`worker-pr.py` refuses to overwrite an existing record with different
content), so a later run can never silently rewrite an implementer identity.
