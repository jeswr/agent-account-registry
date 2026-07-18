# Recorded review verdicts

One JSON file per review round, `<owner>--<repo>--pr<N>-round<R>.json`, written HOST-SIDE by
review-fix.yml AFTER the verdict passed schema validation (worker-pr.py `validate-verdict`) and
the reviewer's byte-identical-tree check.

The fix run re-reads the findings from HERE (trusted storage the target model cannot write),
never from PR comments; the fixer prompt still frames them as UNTRUSTED DATA because they
originate from a model that read hostile pull-request content.

## Batch verdict writes (design record)

The batch-review worker records up to `BATCH_SIZE` verdicts in ONE atomic Git-Data-API commit
(`worker-pr.py::_registry_write_many` / `verdict_record_batch`) instead of N separate Contents-API
PUTs, which eliminates the per-file write contention that made concurrent single-review commits
thrash the branch head ("registry write for … kept conflicting"). Two properties are load-bearing
and are unit-pinned by `worker-pr.py --self-test`:

- **Writes target the `ledger` data-plane branch; reads are ledger-first with a legacy fallback.**
  The registry default branch (master) is PROTECTED by a required `gate` status check
  ([GPT-5.6 r4] / issue #96, verified live), so EVERY `github.token` write to it — Contents-API PUT
  or Git-Data-API ref update alike — is permanently rejected. Batch verdicts therefore commit to
  the unprotected `ledger` branch (`REGISTRY_VERDICT_REF`, default `ledger`) — the same data-plane
  convention as `data/leases.json` and `data/model-health.json` — and `fix/provenance-ledger`
  migrates the whole provenance+verdict store there. Every reader resolves records LEDGER-FIRST
  with a legacy default-branch-checkout fallback for pre-migration records:
  `dispatch-claim._registry_data_path` (progress grade, fix-dispatch gate, provenance) checks
  `--registry-ledger-root registry-ledger` before `--registry-root registry`, and
  `review-fix.yml`/`review-batch.yml` stage prior/round verdicts from the `registry-ledger`
  checkout before `registry`. Override `REGISTRY_VERDICT_REF` only for tests/migration — writing
  where no reader looks silently breaks the review→fix loop, and writing to the protected default
  branch cannot land at all.

- **The idempotency filter is re-run against the fresh ref on EVERY CAS attempt.** Per file:
  absent → written; byte-identical → idempotent skip; DIFFERENT content already recorded →
  FAIL CLOSED for that file (dropped, no label/arm, never rewritten). The absent/identical/different
  decision is NOT hoisted out of the CAS retry loop: on a non-fast-forward (another writer advanced
  the head — the ledger branch is the hottest ref in the system: lease claim/release, model-health
  and groom all advance it, so real same-ref contention is expected), the loop re-reads the ref,
  re-derives the filter against the NEW tree, and re-bases the
  content-addressed blobs. A concurrent writer that landed a DIFFERENT verdict at one of the batch's
  own paths in the CAS window is therefore observed as a conflict and dropped, never clobbered — the
  "never rewrite a recorded verdict" invariant holds on the WINNING attempt, not just the first. The
  retry budget matches the contended lease writer's (6), not a one-writer-per-tick assumption.
