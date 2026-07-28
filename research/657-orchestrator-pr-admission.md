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
  and its arm gate, and needs a minting path. **→ PLAN half landed; see §7.**
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

---

## 7. Implementation status — the PLAN half (Claude Opus 5, 2026-07-27)

> 🤖 **SPARQ agent** — this section records what is now in the tree and, more importantly, what
> is **not**. Read §7.3 before enabling anything.

### 7.1 The gap, re-measured on a larger population

§1 measured 100 open sparq PRs. Re-measured 2026-07-27 with a **paginated** listing
(`gh api --paginate '/repos/sparq-org/sparq/pulls?state=open&per_page=100'`), cross-checked
against `gh search prs` and a GraphQL `totalCount` — all three returned **117**:

| | count |
|---|---|
| open PRs | 117 |
| draft / non-draft | 83 / 34 |
| authored by `sparq-orchestrator[bot]`, all on `sparq-agent/issue-N-*` | 83 |
| authored by `jeswr`, none matching `HEAD_REF_RE` | 34 |
| **open non-draft reachable by the review lane** | **4** |
| **open non-draft unreachable** | **30** |

Two facts sharpen §1's diagnosis:

- **The two gates are perfectly correlated in the live population.** All 30 unreachable PRs fail
  the head-ref gate *and* the author gate; **0 fail only one**. Widening one alone reaches nothing.
  **As of 2026-07-27T00:00Z.** This one is a snapshot, not an invariant: an independent
  re-measurement later the same day found two *newer* automation PRs (`#4488` dependabot, `#4460`
  release-plz) that fail the head-ref gate **only**. The argument is unaffected — those are not
  orchestrator-authored and enrolment would not reach them — but "0 fail only one" is time-bound
  and must be re-derived, never quoted, by any later decision.
- **The fork gate is not what is excluding anything.** `head.repo == sparq-org/sparq` for
  **117/117** open PRs. There is no fork PR in the population at all.
- Verdict coverage is exactly bimodal: reachable **4/4** hold a ledger verdict, unreachable
  **0/30** do. All 4 reachable PRs also carry `review:pass` (measured). It is tempting to conclude
  from that "the lane's live unserved queue is zero", but that does **not** follow from the label
  alone — `enumerate_review_items` is review-state-agnostic for the repair states, so a
  `review:pass` PR on a conflicting base or a concluded-red gate still enumerates. The measured
  claim is the label distribution; the queue depth was not measured.

### 7.2 What the head-ref gate is actually for — evidence

The gate reads like an issue-number binding. It is not one.

- `HEAD_REF_RE = ^sparq-agent/issue-([1-9][0-9]*)-` has a capture group, and
  **`grep -rn HEAD_REF_RE scripts/ .github/` finds 8 sites, every one a boolean `.match()`.**
  The capture group is never extracted anywhere in this repository.
- The issue a review item is bound to comes from **`record["issue"]`**, which
  `provenance_admission_error` requires to be a positive int. Driving the enumerator with a head
  ref naming issue `999999` and a record naming issue `7` binds the item to **7**.
- The per-line git history is not recoverable — `scripts/dispatch-claim.py` enters history in a
  single squashed bootstrap commit (`cf1ffab0e`), so there is no rationale commit to read. The
  code's own evidence is what stands.

So the head-ref and author gates are **producer-shape filters**: together they select exactly the
population for which worker.yml's host-side `provenance` job guarantees a record. They are a
redundant *correlate* of the record requirement, not an independent trust root. The trust roots
are (i) `head.repo == repo` and (ii) the registry-written record — which is why this change
waives the two shape gates and touches neither root.

### 7.3 ⚠️ What landed, and why it is deliberately INERT

Landed (PLAN half only):

- `provenance_admission_error(..., admit_orchestrator=False)` — an opt-in that relaxes the
  attestation requirement to the `orchestrator` class **for one named consumer at a time**.
  Default False, so every existing caller keeps refusing the class byte-for-byte.
- `admits_orchestrator_pr(record, pr_number, login, enrolled_authors)` — total, fail-closed,
  and a conjunction of **two halves on branches of different authority**: an
  `orchestrator`-attested record (`ledger`, low authority — master's required `gate` rejects
  direct PUTs, issue #96) **and** the author's login in `review_enrolment_authors`
  (`policy/repos.toml`, master, behind branch protection).
- `enumerate_review_items(..., enrolled_authors=())` waives the two shape gates for an admitted
  PR. The fork gate is **hoisted above** every waivable predicate so no waiver can reach it.
- **Review-only**, enforced twice: `emit()` refuses any state but `needs-review`, and
  `validate_plan` refuses a `self_attested` item in any other state. The four excluded states
  are exactly the ones whose run pushes commits to the PR head or re-enters the arm path.
- A new **required** plan field `self_attested`, so no consumer can default it the safe-looking
  way, plus a self-test pinning `dispatch.yml`'s hand-written field replica against
  `REVIEW_ITEM_FIELDS` (that replica had already silently drifted).

**NOT landed, and the feature is unusable without it:**

| consumer | file:line | still refuses |
|---|---|---|
| CLAIM record re-read | `dispatch-claim.py` `claim_review_admission_error(record, number)` | yes |
| review-fix.yml resolve | `.github/workflows/review-fix.yml` `admission_error = dispatch_claim.provenance_admission_error(...)` | yes |
| reviewer-side chain | `dispatch-claim.py` `chain = _resolvable_chain(REVIEW_CHAIN[impl_provider], routing)` | still **inverts** the self-declared provider |
| reviewer≠implementer check | `dispatch-claim.py` `claim_provider == impl_provider` violation | would trip on a constant side |
| the arm | `worker-pr.py ready_and_arm` | reads **no** attestation class; nothing plumbs it |

Enabling `review_enrolment_authors` now would enumerate a PR at PLAN that CLAIM re-refuses **every
tick, forever**, with a generic defer counter as the only symptom. So the tree carries a
**self-removing enable interlock**, and it is enforced at three independent depths.

**1. In production, at the decision.** `admits_orchestrator_pr` conjoins the live CLAIM wiring
fact (`claim_admits_orchestrator_class()`, which *calls* the production admission over a synthetic
`orchestrator`-attested record). With the allowlist enabled and CLAIM unwired the waiver returns
False, the two shape gates stand exactly as they do today, the pre-feature refusal reason still
prints, and the population is simply not enumerated. **Turning the key in `policy/repos.toml`
cannot turn the feature on** — not "is asserted not to", *cannot*. The clause self-removes when
step 1 of §7.4 lands.

**2. In the gate, twice.** `dispatch-claim.py --self-test` and `policy-resolve.py --self-test`
both run `enrolment_enable_error` against the live policy and the two wiring probes, so an
enabling diff has to defeat two separately enrolled self-tests to reach master.

**3. Both wiring facts are derived BEHAVIOURALLY, and both fail closed.** This is the part that
was wrong in the first draft and is worth recording, because the failure mode is a general one:

| fact | first draft | how it failed | now |
|---|---|---|---|
| CLAIM admits? | regex for an exact call line in this module's own source; **absence** ⇒ "wired" | any reflow / rename / added kwarg stops the match. A two-line reflow with **no behaviour change** disarmed it, nothing red | `claim_admits_orchestrator_class()` **calls** `claim_review_admission_error` |
| review-fix.yml admits? | `"admit_orchestrator" in <block>` | tests a **token**, not a **value**: an explicit `admit_orchestrator=False` — a *refusal* — read as admitting, as did a comment carrying the token | `review_fix_admits_orchestrator_class()` **execs** the workflow's own block against stubs and requires the opt-in **value** plus fail-closed behaviour |

A guard is only as falsifiable as the facts fed into it. Both probes now return True **only on
positive proof**; an unreadable seam, an exception or an ambiguous answer reads False and keeps the
interlock armed. `policy/repos.toml` is **unchanged** — this PR shrinks the unreachable set by
**0**, on purpose.

### 7.4 Follow-up, in the order it must land

1. Thread `admit_orchestrator` into `claim_review_admission_error` and `review-fix.yml`'s resolve
   step. Both wiring probes then flip to True by themselves, the production clause in
   `admits_orchestrator_pr` stops constraining anything, and both self-test interlocks stand down —
   nothing has to be remembered and deleted.
2. Pin a **constant** reviewer side for the class. Note this is **five** enforcement points, not
   one: the `REVIEW_CHAIN` subscript, the `claim_provider == impl_provider` violation,
   review-fix.yml's inline chain table and its two re-assertions, and `worker-pr.py`'s
   `ready_and_arm` refusal. A one-sided change deadlocks the lane.
   **Also in scope at this step**, named here because §6's "five enforcement points" list omits
   them: three *other* regexes over the same branch shape DO extract the issue number —
   `groom.py:112 WORKER_BRANCH`, `worker-pr.py:287 WORKER_HEAD_RE`, `backfill-provenance.py:52
   HEAD_RE`. `worker-pr.py`'s hold lookup falls back to that derivation when no `source_issue` is
   passed (no match ⇒ *no holds found*), and its disarm path refuses any ref that is not a worker
   ref. Neither runs on the admitted class while the feature is inert; both must be handled before
   it is not.
3. Plumb the attestation class to the arm and refuse it there (§3 option (b): the residual risk
   of an openai-harness orchestrator must be an advisory comment, never a merge).
4. A minting path. `backfill-provenance.py` + `backfill-provenance.yml` supply the ledger CAS
   writer, the record schema, the salted hash and the workflow guard idiom; what is missing is an
   identity source (backfill derives one from the worker run log, which has no orchestrator
   analogue) and idempotency for a stamp keyed on the *minting* run.
5. Only then: add a login to `review_enrolment_authors`, and enrol in **small batches** (§7.5).

### 7.5 Capacity

Enrolment is a per-PR gesture, so the load is bounded by what an operator mints — the design is
inherently rate-limited, and this is the main reason to prefer it over a blanket predicate
widening. For sizing: of the 30 unreachable PRs, 7 carry `needs:user` and stay terminal after
admission, leaving **23** enrollable. Against the operator-supplied lane figures (82 `review-fix`
runs / 3 h, 55.8 % round-1 failure), ~23 PRs implies on the order of **~52 runs** if failures
retry to a pass — roughly two thirds of a 3-hour window's throughput, i.e. enough to starve
worker-PR review if enrolled at once. Those two lane figures are **not** measurements of mine;
the derived estimate inherits their uncertainty. Enrol in batches and watch the lane.

---

## 8. The CLAIM leg — what §7.4 step 1 turned out to be (Claude Opus 5, 2026-07-27)

> 🤖 **SPARQ agent** — this section records the follow-up. Its headline is a correction to §7.4:
> **step 1 as written was not sufficient, and landing it as written would have produced exactly
> the outage the interlock exists to prevent.**

### 8.1 The correction

§7.4 step 1 says: *"Thread `admit_orchestrator` into `claim_review_admission_error` and
`review-fix.yml`'s resolve step. Both wiring probes then flip to True by themselves."*

That is true of the probes and false of the lane. Both probes would have read `True` while the
class was still refused, because **both consumers refuse the orchestrator class at predicates the
record admission never reaches**:

| consumer | predicates that refuse the class | reached by #759's probe? |
|---|---|---|
| CLAIM (`_dispatch_review_items`) | `HEAD_REF_RE` on the live head ref; `login != bot_login`; the record re-read | record re-read only |
| `review-fix.yml` `resolve` | `draft is not True`; the worker head-ref regex; `author.endswith("[bot]")`; the record admission | record admission only |

`review_fix_admits_orchestrator_class` drove the extracted block with a stub admission and a bare
`{"number": 1}` for `pull`, so **a resolve step that passed the record opt-in and then died on
`draft is not True` read as fully wired**. That is not a corner case: **every** PR in the
enrollable population is non-draft. The literal step-1 wiring would have dispatched a review run
per tick and killed it at `resolve`, forever — with `rf_admits=True` reported to the guard that
was supposed to see it.

Two further consumers §7.4 did not name at all reproduce the same loop one layer deeper:

- **`worker-pr.revalidate_outcome_head`** returns `"undrafted"` for a non-draft PR, and
  `review_outcome` then **drops the entire outcome** — findings unposted, reviewed-sha left
  unbound — *while the round budget still charges*. Silent per-round burn to a terminal park.
- **the arm**. `ready_and_arm` read no attestation class. This is the only leg whose failure mode
  contains a **merge**, and its absence is what made "enable the allowlist now" unsafe rather than
  merely useless.

**Generalisation worth keeping:** a wiring probe that stubs the predicate it is measuring measures
the stub. #759's probe was rewritten once already for exactly this reason (token → value); the
same defect class survived the rewrite one level out.

### 8.2 What this PR lands

1. **CLAIM**, completely. `claim_review_pr_admission(repo, pr, pull, record, bot_login,
   enrolled_authors) -> (orchestrator_admitted, defer_reason)` is one pure function carrying the
   fork gate, the two waivable shape gates and the record admission, so the wiring fact is derived
   by **calling the production decision**. CLAIM re-derives the waiver from the live PR, the live
   record and the master-protected allowlist, and **requires the plan's `self_attested` to agree**
   — in both directions. `dispatch()` resolves `enrolled_authors` per repo from the private
   registry checkout and passes it as a **required keyword-only** parameter.
2. **`review-fix.yml`'s resolve step**, completely. All four predicates moved into
   `dispatch_claim.review_fix_pr_admission`, so the `run:` script carries no predicate of its own
   — `call it, and die on its answer`. The fork gate is hoisted above every waivable predicate
   there too. The step exports `self_attested`. **The waiver applies to `mode == "review"`
   alone**: this workflow is `workflow_dispatch`, so its mode is an *input*, and PLAN's
   review-only `emit()` choke point and `validate_plan`'s schema re-assertion both live upstream
   of a manual dispatch and bind neither. Without that conjunct an `actions:write` holder could
   dispatch `mode=fix` against an enrolled PR and get a run that PUSHES COMMITS to a head whose
   provenance record its own author wrote — found while writing this PR's own tests, and it is the
   third choke point the review-only property actually needs.
3. **The outcome leg.** `revalidate_outcome_head(..., self_attested=)` stands down the DRAFT
   requirement **and nothing else** (state/author/head-freshness are untouched).
4. **The arm boundary**, refused twice and independently: `decide_review` never returns `"arm"`
   for the class (an approve becomes a named human hand-off), and `ready_and_arm` raises. This is
   §3 option (b) made true at the merge boundary rather than argued for in prose.
5. **The enumerator's last hole.** A non-draft PR carrying no `review:*` label walked past both
   label branches and the drafted-only fallback and left through the idle census. Measured on
   sparq 2026-07-27 (§8.5): **20 of 33 non-draft open PRs carry no `review:*` label at all**, so
   without
   `if draft or orchestrator_admitted:` the fully-wired feature would have enumerated **nothing**.
6. **The interlock, widened rather than removed.** `enrolment_enable_error` now takes four wiring
   facts (`claim_admits`, `rf_admits`, `outcome_admits`, `arm_refuses`), each derived by execution
   and each failing closed. The self-removing production clause inside `admits_orchestrator_pr` is
   gone — it has done its job, and keeping it would be a recursive call.

### 8.3 `policy/repos.toml` is deliberately UNCHANGED — the allowlist is still empty

The interlock now permits an enabling diff. It is still not taken, and the reason is measured, not
cautious:

- **There is no minting path (§7.4 step 4), so enabling reaches ZERO PRs.**
  `admits_orchestrator_pr` requires `provenance_attestation_class(record) == "orchestrator"`, and
  nothing writes such a record: `worker-pr.py`'s writer is driven by worker.yml with
  `--run-key "$GITHUB_RUN_ID.$GITHUB_RUN_ATTEMPT"`, and `backfill-provenance.py` stamps
  `backfill:<run>.<attempt>`. Grep of the tree for a producer of `orchestrator:<run>.<attempt>`
  returns the taxonomy table, the probe fixture and the tests — no writer. Enabling the allowlist
  today changes the behaviour of exactly nothing.
- **The allowlist is one of two reviewed gestures, and spending it early buys nothing.** Records
  live on the unprotected `ledger` branch by construction (#96). The master-protected allowlist is
  the *only* half that bounds which logins a minted record can ever speak for. Turning it on
  before a minting path exists spends that gesture against zero benefit.

So the honest answer to "how many of the 21 invisible sparq PRs does this PR make enumerable" is
**0 today, and 21 once a record is minted for them** — the shape gates, the draft dependency at
three separate layers, and the unlabelled-non-draft enumerator hole were all of the *code*
blockers, and they are now gone. What remains is a data blocker with its own §7.4 step.

### 8.4 Revised follow-up order

1. ~~Thread the admission into CLAIM and `review-fix.yml`~~ — done, and it was four legs, not two.
2. A **minting path** (was step 4). It is now the *only* thing between the tree and a working
   feature, so it moves up. Needs an identity source and idempotency for a stamp keyed on the
   minting run; `backfill-provenance.py` supplies the ledger CAS writer, the schema and the salted
   hash.
3. Enrol **one** login for **one** repo and watch the lane (§7.5's batching argument stands).
4. A **constant reviewer side** (was step 2) is now a *quality* item, not a safety one: with the
   arm refusing the class, a mis-declared `impl_provider` yields a same-provider **advisory
   comment**, which is precisely the residual risk §3 option (b) accepted. It should still be done
   — a self-declared field should not choose which account pool is spent — but it no longer gates
   enrolment. Note it remains five enforcement points; a one-sided change deadlocks the lane.
5. The three *other* regexes over the worker branch shape that DO extract the issue number
   (`groom.py:112`, `worker-pr.py:287`, `backfill-provenance.py:52`) still assume a worker ref.
   None runs on the admitted class today (review-only, never fixed, never armed), but each must be
   handled before that stops being true.

### 8.5 Re-derived, not quoted (2026-07-27, this PR)

§7.1's population figures are a snapshot and its own text says they must be re-derived. Re-measured
here from a paginated `gh api /repos/sparq-org/sparq/pulls?state=open&per_page=100`:

| | count |
|---|---|
| open PRs | 121 |
| draft / non-draft | 88 / 33 |
| non-draft carrying **no `review:*` label at all** | **20** |
| …failing `HEAD_REF_RE` | 20 / 20 |
| …authored by `jeswr` (no other author in the set) | 20 / 20 |
| …failing the head-ref **and** author gates together | 20 / 20 |
| non-draft failing **either** shape gate | 29 |
| **fork heads in the entire open population** | **0** |

The brief that commissioned this work said 21; the live listing says 20 — the set drifts by the
hour, which is exactly why §7.1 marked it time-bound. The structural claims are unchanged: the two
shape gates remain perfectly correlated over the unlabelled set, and the fork gate is still
excluding nothing (0/121), so hoisting it above the waiver costs nothing and guards the one
attacker-facing predicate.

---

## 9. §7.4 step 2b — the last three shape tests (Claude Opus 5, 2026-07-27)

> 🤖 **SPARQ agent** — this section closes §8.4 item 5. The three regexes it named are handled;
> what it says about each is *different*, and the differences are the point.

### 9.1 The rule this applied

Every site was extended (or explicitly *not* extended) **through the predicate the other
consumers already use** — `admits_orchestrator_pr` — rather than through a second shape test.
Re-deriving "is this the class?" locally is the drift that §8.1 spent a whole PR eliminating.

The **fork gate** is hoisted above every waivable predicate at each site touched. §8's framing
needs one correction, which #844's review made and which applies again here: master's fork test
was already the *first disjunct of an `or`*, so it was safe by **fusion, not ordering** — inside
a boolean list the order is irrelevant. The hazard the hoist removes is **co-waiver**: a waiver
written into that `or`/`and` would carry the fork gate with it. That is why each site now has the
fork test standing alone.

### 9.2 `worker-pr.py` — a fail-OPEN on a non-waivable gate

`live_human_holds` / `live_machine_parks` / `live_security_flagged` derived the **source issue**
from the worker head ref whenever no explicit `--issue` was passed. The class has an ordinary
branch by definition, so the regex could not match and the non-match read as *no source issue*,
i.e. **no holds found**. The source-issue hold is one of the gates #657 explicitly does **not**
waive, so that is a fail-open on a non-waivable gate.

One shared derivation (`hold_surface_source_issue`) now serves all three, and the class without an
explicit issue **raises**. The class is the already-resolved `self_attested` answer review-fix.yml
computes host-side, never a second record read — one view of one decision.

`run_disarm` still **refuses** the class, deliberately. It retracts *machine* latches and
`ready_and_arm` refuses the class outright, so no autonomous path can arm an orchestrator PR;
admitting it would also require waiving the #570 exact-App author gate, which buys write access to
someone's branch. Both halves are asserted executably rather than argued in a comment.

### 9.3 `backfill-provenance.py` — the class must stay out, but not by accident

`HEAD_RE`'s run id is backfill's **only** identity source (no trailer fallback: trailers on this
population are model-forgeable), and a self-authored PR has no worker run. So the class must never
enter that loop — and minting for it is `mint-provenance.py`'s job. It stayed out by accident of
the shape test; it is now **recognised** through the shared predicate and skipped with a reason.
Two live hazards this forecloses: hunting a run log that does not exist (NEEDS-HUMAN for every
orchestrator PR), and **draft-converting** a class the review lane admits *because* it stands the
draft requirement down.

`review_enrolment_authors` is read through policy-resolve's validating accessor. That accessor is
the **only** thing refusing a `[bot]` login; `admits_orchestrator_pr` is a plain casefolded
membership test and would happily admit one. Asserted where it lives.

### 9.4 `resolve-conflicts.py` — the honest non-change

`owned_by_review_rebase_lane` is a **hand-over**: True means the resolver walks away. Sound only
while the lane it hands to will take the PR — and `review_fix_pr_admission` waives for
`mode == "review"` **alone**, because a fix run pushes commits to the PR head (§3). So the class
must **never** be ceded, or a CONFLICTING PR — the population that gets no `pr-gate` run at all —
is stranded.

A runtime `and not admits_orchestrator_pr(...)` here would be a **dead conjunct**: that predicate
needs the author's login in `review_enrolment_authors`, policy-resolve refuses `[bot]` logins
there, and this predicate requires a `[bot]` author, so the conjunction is empty by construction.
Shipping it would be a guard that can never fire. The *justification* is asserted instead: the
self-test runs the live `review_fix_pr_admission` over a fully-admissible enrolled orchestrator PR
and requires `review` to admit and `fix` to refuse.

### 9.5 What still blocks enrolment after this

1. **The disarm lane cannot see the class.** `enumerate_disarm_items` and
   `_disarm_row_admissible` (dispatch-claim.py) both require a worker head ref, and `run_disarm`
   requires the exact App author. Today that is consistent — nothing autonomous arms the class.
   The moment a **human** arms an enrolled orchestrator PR, the #42 invariant (never merge a
   never-reviewed tree on green CI) has no enforcement on it. Admitting the class needs a
   *design* decision about the #570 author gate, not a shape widening; it is not residue.
2. **`AUTO_READMISSION_PER_TICK_MAX = 5`** (#844's surface, raised by #856's review): ~50 minutes
   to drain a 21-PR cohort at the 10-minute floor.
3. **A constant reviewer side** (§8.4 item 4) — quality, not safety, but a self-declared field
   should not choose which account pool is spent.
4. **`enrolment_enable_error` returning `None` is not a green light.** It checks *wiring*, not
   readiness; every blocker found so far was outside what it can express. `policy/repos.toml` is
   again deliberately unchanged.
