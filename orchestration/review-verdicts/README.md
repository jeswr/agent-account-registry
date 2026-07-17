# Recorded review verdicts

One JSON file per review round, `<owner>--<repo>--pr<N>-round<R>.json`, written HOST-SIDE by
review-fix.yml AFTER the verdict passed schema validation (worker-pr.py `validate-verdict`) and
the reviewer's byte-identical-tree check.

The fix run re-reads the findings from HERE (trusted storage the target model cannot write),
never from PR comments; the fixer prompt still frames them as UNTRUSTED DATA because they
originate from a model that read hostile pull-request content.
