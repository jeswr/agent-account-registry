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

- **One branch for every read AND write.** Batch verdicts commit to the branch every verdict
  READER consumes — the registry default branch (`REGISTRY_VERDICT_REF`, default `master`), the
  same branch the single path's Contents-API write targets. `dispatch-claim.latest_recorded_progress`
  and the fix-dispatch gate read the verdict from the `--registry-root registry` (default-branch)
  checkout, and `review-fix.yml` stages the prior verdict from `registry/orchestration/review-verdicts/…`
  (also the default branch). Writing batch verdicts anywhere else (e.g. a separate data-plane branch)
  makes them invisible to those readers and silently breaks the review→fix loop. Override
  `REGISTRY_VERDICT_REF` only if every reader is migrated in lockstep.

- **The idempotency filter is re-run against the fresh ref on EVERY CAS attempt.** Per file:
  absent → written; byte-identical → idempotent skip; DIFFERENT content already recorded →
  FAIL CLOSED for that file (dropped, no label/arm, never rewritten). The absent/identical/different
  decision is NOT hoisted out of the CAS retry loop: on a non-fast-forward (another writer advanced
  the head — the default branch is the hottest ref in the system, so real same-ref contention is
  expected), the loop re-reads the ref, re-derives the filter against the NEW tree, and re-bases the
  content-addressed blobs. A concurrent writer that landed a DIFFERENT verdict at one of the batch's
  own paths in the CAS window is therefore observed as a conflict and dropped, never clobbered — the
  "never rewrite a recorded verdict" invariant holds on the WINNING attempt, not just the first. The
  retry budget matches the contended lease writer's (6), not a one-writer-per-tick assumption.
