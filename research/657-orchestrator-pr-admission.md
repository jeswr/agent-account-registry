# Admitting orchestrator-authored PRs to the review lane (#657)

> 🤖 **SPARQ agent** — design record by Claude Opus 5, 2026-07-26. Maintainer-review document.
> The first slice is implemented in the same PR; everything under "Deferred" is not.

## 1. The gap, re-measured

Measured live 2026-07-26 (`gh pr list --repo sparq-org/sparq --state open --limit 100`):

| | count |
|---|---|
| open PRs | 100 |
| authored by `app/sparq-orchestrator` (the App bot), all on `sparq-agent/issue-N-*` | 80 |
| authored by `jeswr` | 20 |
| non-draft | 25 |
| **non-draft carrying no `review:` label at all** | **17 — every one `jeswr`-authored** |

Branch prefixes of those 17: `agent/ chore/ ci/ cx/ docs/ fable/ feat/ fix/ research/`. None matches
`HEAD_REF_RE = ^sparq-agent/issue-(\d+)-`.

`enumerate_review_items` requires **all** of: worker head ref, `head.repo == repo`, a `[bot]`
author (the App bot when `bot_login` is known), and an admissible provenance record. The same
`provenance_admission_error` gates CLAIM, `review-fix.yml`'s resolve step, `resolve-conflicts.py`,
and groom's draft carve-out. The 17 fail on the first and third conditions simultaneously, so they
are invisible to every path that can run a model against a PR — not deferred, not parked.

## 2. Option 1 — route orchestrator work through the worker pattern

**Finding: sound, already fully supported, and it does not require a single line of registry
change — but it is a behavioural rule, not a fix, and it cannot reach the measured population.**

Evidence gathered against the tree:

- **The tier objection is refuted.** `policy/repos.toml` already carries the standing rule that
  frontier-tier agents author all CI/infrastructure work, and requires every target's routing
  table to declare a **frontier-only** `role = "ci"` chain (`["sol", "opus5", "fable"]` — no
  terra/sonnet/haiku), with chain exhaustion *deferring* at the claim step rather than degrading
  tier. So "file an issue and let the fleet do it" does **not** mean handing infra work to a cheap
  model. This was my main prior objection to Option 1 and the tree disproves it.
- **The registry is a live worker target.** `origin/` carries many `sparq-agent/issue-N-*`
  branches on this repository, so the pattern already works for changes to the pipeline itself.
- **The identity property holds structurally, for free.** A worker PR's implementer identity is
  written by worker.yml's dedicated `provenance` job, host-side, in a job that executes no target
  code. Nothing is self-declared, so the cross-provider inversion is genuine.

What it does not do:

- **It cannot rescue the 17 open PRs.** They exist, on ordinary branches, authored by `jeswr`.
- **It cannot cover interactively-authored work.** The orchestrator's own head ref would be
  fixable, but `enumerate_review_items` also requires a `[bot]` author, and orchestrator PRs are
  opened under the maintainer's token. Making the orchestrator open PRs *as the App* and write its
  own provenance record does not recover Option 1's property — it recovers only its *shape*. The
  record would then be written by the same agent that wrote the diff, which is Option 2 wearing
  Option 1's branch name.

**Verdict: adopt Option 1 as the standing rule for work the orchestrator can delegate. It is not a
complete answer, and it should not be described as one.**

## 3. Option 2 — an explicit admission path for non-worker PRs

The irreducible difficulty, stated precisely: for an orchestrator PR the author holds the registry
credential, so whatever writes the provenance record is the thing that wrote the diff. A declared
`impl_provider` is therefore an assertion by the implementer about itself, and the lane picks the
reviewer by **inverting** that field. A false declaration yields a same-provider review that still
*looks* cross-provider. **No amount of recording harder fixes this.**

The only resolutions that survive it are ones where **the declared provider is never read to pick
a reviewer**:

- **(a) Dual-provider review** — dispatch both sides, so one review is genuinely cross-provider
  whatever the true author. This is registry #681.
- **(b) A constant review side** — always review this class on the openai side, never resolve an
  opposite, and **never let this class auto-arm**, so a same-provider outcome (an openai-harness
  orchestrator) degrades to "an advisory comment", not "an unreviewed merge".

### What actually happened to #681 — correcting the record

#681 is **still open**, and the maintainer's own closing note on it says: *"Keeping this open
rather than closing — the design intent is right and the review-lane gap it targets is real. It is
the implementation of the evidence channel that is unsound."*

The two blocking defects were **not** the dual-review design:

1. **Forgeable evidence channel.** Per-provider "this side already reviewed" evidence was read from
   HTML comments **in the PR body**, which a same-repo author can edit. An author pre-inserting an
   `anthropic` marker for their own head sha reduced the review set to a single openai review that
   then satisfied the arm gate.
2. **Liveness.** The anthropic-side marker was gated on an arm that `ready_and_arm()` deliberately
   refuses for that side, so the marker was never recorded and the openai side was never reached.

**A writer-authenticated channel for exactly this evidence already exists and #681 did not use it.**
`orchestration/review-verdicts/<owner>--<repo>--pr<N>-round<R>.json` is written **host-side by
review-fix.yml** after schema validation and the reviewer's byte-identical-tree check; its README
states the fix run re-reads findings from there precisely because it is "trusted storage the target
model cannot write". Per-side review evidence belongs there (keyed by reviewer provider), not in
the PR body. That is a bounded rework of #681, not a redesign.

## 4. A live defect found while investigating — and what this PR fixes

`provenance_admission_error` enumerates six field constraints. `recorded_at_run` is **not** among
them: until this PR it was never inspected at admission at all.

Consequences, both live:

- A record with **no stamp**, or a malformed one, was admitted at full worker-run trust.
- A **hand-written** record was indistinguishable from a machine-written one. The one-off for
  sparq#4185 stamped `human:30209757201.1` under explicit maintainer authorisation; nothing in the
  code could tell that record's trust basis from a worker record's, and the lane resolved the
  reviewer from its self-declared `impl_provider: openai`.

Audit of the live population (`origin/ledger`, 2026-07-26): **350 provenance records — 349
machine-attested (`<run>.<attempt>` or `backfill:<run>.<attempt>`), 1 `human:` (sparq#4185, already
MERGED).**

Records are read ledger-first, with the master checkout as the pre-outage fallback
(`review-fix.yml` resolve; `dispatch.yml` PLAN unions both directories), so the ledger population
is the live one.

**You cannot safely admit a class you cannot distinguish.** This PR lands the discriminator,
fail-closed, before anything is admitted: an explicit attestation-class taxonomy derived only from
the stamp shape, with the self-attested `orchestrator:` class recognised and **refused under its
own diagnostic**. That is a *hardening* — it strictly shrinks the admitted set — and it is the
precondition either sound option needs.

**Honest scope.** An actor with registry write can write a machine-shaped stamp instead, so this is
not an anti-forgery guarantee against a registry-write holder. It closes the fail-open on
absent/unrecognised stamps, and it makes the trust basis of every record auditable and
machine-readable.

## 5. Recommendation

1. **Adopt Option 1 as the standing rule** for delegable work. It is already supported end to end
   and costs nothing.
2. **For work the orchestrator must author itself, take Option 2(b)** — a narrow
   `orchestrator`-class admission that is **review-only**: constant openai-side review side (no
   provider ever resolved from the record), **no fix dispatch, no auto-arm**. This is materially
   smaller than #681 because a single review side needs **no per-side evidence channel at all**,
   which is precisely where #681 failed. The residual risk of an openai-harness orchestrator is a
   same-provider *advisory comment*, never a merge — and the orchestrator already hand-merges its
   trust-plane PRs today (see #681's own "this is yours to merge").
3. If dual review is preferred over 2(b), **rework #681 onto `orchestration/review-verdicts/`**
   rather than reimplementing it.

## 6. Deferred (explicitly not in this PR)

- **The `orchestrator`-class admission itself.** The class is recognised and refused; nothing is
  admitted yet. Admission changes `enumerate_review_items`, CLAIM, `review-fix.yml`'s resolve step
  and its arm gate, and needs a minting path.
- **Head-ref ↔ record cross-check.** A worker head ref embeds the run id
  (`sparq-agent/issue-<N>-<run>-<attempt>`), so a record's `issue` and its stamp's run identity can
  be checked against an artefact fixed at push time. **Measured 2026-07-26: of 79 open
  worker-pattern sparq PRs, 51 have a ledger record and 51/51 match on both fields — 0
  mismatches.** Deferred only because it must be threaded to ~7 call sites (including two in
  groom.py that do not currently carry the head ref) and a defaulted `head_ref=None` would be a
  fail-open. The measurement says it is safe to add.
- **Writer-side stamp validation** in `worker-pr.py`'s provenance writer. worker.yml pins
  `--run-key "$GITHUB_RUN_ID.$GITHUB_RUN_ATTEMPT"`, so the shape is guaranteed at the YAML seam
  today; a caller passing another shape would write a record that admission then permanently
  refuses — a silent stall of exactly the kind #657 is about.
- **Retiring the `human:` stamp.** sparq#4185 is merged, so its record is inert; it is left in
  place as an audit artefact rather than rewritten.
