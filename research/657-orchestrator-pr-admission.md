# Admitting orchestrator-authored PRs to the review lane (#657)

> 🤖 **SPARQ agent** — design record, 2026-07-26. Maintainer-review document.
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

---

## 10. §9.5 item 1's other half — the refusal that recorded NOTHING (Claude Opus 5, 2026-07-28)

> 🤖 **SPARQ agent** — registry #972. This section deliberately fixes **one half** of a problem
> §9.5 item 1 named, and says clearly which half it does **not** touch.

### 10.1 The measured failure

With the first-ever `orchestrator` record minted (`orchestrator:30338368066.1`, PR #961) the lane
ran end to end for the first time:

| leg | run | result |
|---|---|---|
| PLAN, enumerated #961 | 30339511626 | ✅ |
| CLAIM, dispatched review round 1 | 30340312044 | ✅ |
| `review-fix.yml` `resolve` (exported `self_attested=true`) | 30340804869 | ✅ |
| **`run` → `Verify target App identity and default branch`** | 30340804869 | ❌ `pull request author is not the registry App bot` |
| **`outcome`** | 30340804869 | **skipped** |

That step is a **sixth #657 consumer**, downstream of the `resolve` job that had already admitted
the PR, and unreachable by all four of `enrolment_enable_error`'s wiring facts.

### 10.2 The half this PR does NOT fix, and why

**The authorship gate is untouched.** Widening it is a security-posture decision about the job
that hands a model a target-scoped App token, and §9.5 item 1 already says that needs a *design*
decision rather than a shape widening. `refuse("author-not-app-bot")` refuses exactly what
`raise SystemExit("pull request author is not the registry App bot")` refused, for exactly the
same population — asserted by executing the workflow's own block against a spoofed `*[bot]`
login, a bare human login, and a near-miss `registry-admin[bot]x`.

### 10.3 The half it does fix: a refusal must RECORD itself

The `run` job died before binding any output the `outcome` job's `if:` tests, so `outcome` was
skipped and **nothing durable was written** — no verdict, no round, no `review:*` transition. The
next tick therefore re-derived a byte-identical world and launched the identical run. #961 escaped
only because a human armed and merged it.

`always()` was **already** on the `outcome` job and was never the defect. The **conjunct** was.

Four wires, all structural:

1. the identity step names its refusal (`refusal=<code>`) and exits 0 **without** binding
   `bot_login`;
2. the next step fails the job whenever `bot_login` is empty — **fail-closed by construction**:
   the only value that lets the run continue is one written after every predicate passed;
3. `jobs.outcome.if` gains an `identity_refusal != ''` disjunct, and `reverify` gains the matching
   conjunct so the job survives the path it now admits;
4. `worker-pr.py identity-refusal` records it.

### 10.4 The two decisions, argued from the code

**The round is NOT consumed.** `round-record` runs strictly *after* the identity step, so zero
rounds are charged today and the only question is whether to start. The round budget is the
*reviewer's*: `decide_budget` grades progress between rounds and extends on improvement or a
model-tier bump, so a round in which no reviewer ran is indistinguishable from a stagnant one and
would count against the PR for work nobody did. #596 settled the same shape one step down this
same job for credential outages. And decisively: charging rounds delivers the PR into the `budget`
park, which is **capacity**-class and therefore *has* an automatic re-admission — which would hand
it straight back to the identical refusal. Consuming the round buys a strictly worse exit.

**The cap is ONE, and the park is question-class.** The gate reads the target repo's
`full_name`/`default_branch`, the App's own login and the PR's author. A re-dispatch changes none
of them, so a retry is identical *by construction*. That is the property that separates the two
halves of `PARK_CAUSES`: every capacity cause caps something that can come out differently next
attempt (`budget`, `dispatch-missed`, `nochange`, `gatefail`); every question cause is terminal on
first observation because nothing can (`history-rewritten`, `routing-unresolvable`,
`marker-corrupt`). `target-identity` is the latter. The machine exit is the cause itself, not a
timer: the durable receipt names the reason, and the park's own `readmission_cutoff` re-opens the
budget on a human gesture once the cause is gone.

### 10.5 What this does and does NOT change about enrolment

`enrolment_enable_error` still takes four wiring facts and still reads `None`. A **fifth** fact for
this step is deliberately NOT added, because a fifth fact reading `False` would force the
un-enrol-or-widen decision this PR is scoped out of. What *has* changed is the interlock's
premise: its refusal condition is "every enrolled PR would be enumerated and then refused, dropped
or merged, **on every tick, forever**". After this PR, the identity leg refuses **once**, names its
reason, and leaves the frontier. That is a bounded, counted, visible non-delivery instead of an
invisible unbounded one — so §9.5 item 4 stands, sharper: the interlock checks wiring, and the
honest statement of the lane's current delivery is *zero reviews, one named park per PR*, until the
Half-A decision lands.

### 10.6 Sequencing — this fix must land BEFORE #937

#937 (`auto-mint-provenance.yml`) mints records automatically. Landing it first would feed the
whole population into a loop with no exit — one dispatch per PR per ~10-minute tick, each burning
a claim, a runner and an account lease, forever. Landing this first makes auto-minting bounded: the
worst case becomes one terminal, named park per PR.

---

## 11. Enumerability is not deliverability — the sixth consumer (Claude Opus 5, 2026-07-29)

> 🤖 **SPARQ agent** — this section records a measurement that changes what "the #657 lane works"
> means, and it deliberately does NOT take the decision it identifies. Read §11.4 before planning
> any further work on this issue, including enrolling another repository.

### 11.1 The measurement

Every code blocker §8.3 named is gone, the allowlist is enabled for this repository (#916), and
auto-minting is live (#937). Counted over the **whole** `origin/ledger` tree, 2026-07-29:

| | count |
|---|---|
| provenance records on `ledger` | 625 |
| …`orchestrator`-attested | **2** (this repo's PRs #961, #1155) |
| review-verdict records on `ledger` | 1451 |
| …belonging to an `orchestrator`-attested PR | **0** |

**Two mints, zero reviews.** The lane is not slow or starved; it has never delivered once.

### 11.2 Why — and why the interlock could not see it

`enrolment_enable_error` models four consumers. There is a **sixth** (§10 found the fifth and fixed
only its missing exit): the `Verify target App identity and default branch` step in review-fix.yml's
**`run`** job. All four modelled facts concern `resolve`; this gate lives one job later, and refuses
any pull request whose author is not this App bot. Measured end to end on #961:

```
PLAN   30339511626  enumerated
CLAIM  30340312044  dispatched review round 1
REVIEW 30340804869  FAILED — 'pull request author is not the registry App bot'
```

The refusal covers the class **by construction, not by snapshot**: `admits_orchestrator_pr` requires
the author's login in `review_enrolment_authors`, and policy-resolve refuses a `[bot]` login there —
so an enrolled author can *never* equal the App bot's login, and **every** member of the class fails
this gate. No population change, no minting improvement and no enrolment can alter that.

This is the same error §10.5 warned about one layer up, and it is worth naming as a class: **an
admission proof is not a delivery proof.** `admissible_by_the_review_lane` proves the RECORD is
admissible; `delivery_refusal` proves the ENUMERATOR emits an item; neither can see the run.

### 11.3 What this PR lands — the third last mile

`mint-provenance.review_run_refusal`, called by `mint()` after the other two, refuses to write a
record when the review run it would dispatch cannot reach a reviewer. It consults
`dispatch_claim.review_fix_identity_admits_orchestrator_class`, which **executes review-fix.yml's own
identity block** (the idiom §7.3 established: a probe that stubs the predicate it measures measures
the stub) and demands two facts — the enrolled class is admitted, **and a stranger is still
refused**. A widening that admits the class by admitting everyone is the authority escalation #570's
author gate exists to prevent, and reads False.

Consequences, stated plainly:

- The class **stops minting** and says why, once per PR, through auto-mint's existing
  `mint-refused` comment. Today it mints and then buys one terminal `target-identity` park
  (#979) — a runner, a claim and an account lease spent to reach a receipt.
- Nothing else changes. Worker PRs mint through `worker-pr.py` and never reach this predicate.
- It is **self-removing**: the probe re-derives its answer from the workflow on every call, so the
  day the gate admits the class the refusal disappears with no edit here. The self-test row
  asserting the live gate refuses is the row that goes red on that day, by design.

A fifth wiring fact was **not** added to `enrolment_enable_error`, for the reason §10.5 gives: a
fifth fact reading False would red the gate on every PR while the allowlist is enabled, which is an
outage, not a signal. The refusal belongs where the cost is — at the write.

### 11.4 The decision this does NOT take, and who owns it

**Widening the identity gate is a maintainer security-posture decision.** §9.5 item 1 and §10.2 both
say so and both decline it; this section declines it a third time rather than quietly settling it.
The gate governs a job that mints a target-scoped App token (`contents: read`, `issues: write`,
`pull-requests: write` in review mode) and then runs a model against target code. Two shapes exist:

1. **Widen the author gate** for `mode == "review"` **and** the self-attested class only, keeping
   the master-protected allowlist as the substitute author binding. Smallest diff; it accepts that
   a token with target write scopes exists in a job running a model over a PR this App did not
   author.
2. **Remove the target App token from the review path for this class**, so the question does not
   arise. The `run` job's own comment says the verdict record, label mutations, arming and
   escalations all happen in the separate `outcome` job — so the review side may need materially
   less authority than it currently mints. This is the narrower trust boundary and the better shape
   if it holds, but it is a real change to the review path and must be measured, not assumed.

**Until one of them lands, the honest statement of this lane's delivery is zero, and every further
investment above this layer returns zero.** Two live consequences:

- **#1115 / #1252** (the `no-issue-reference` and draft populations) is work *above* the binding
  constraint. Taking the lane from "admits 1 of 17" to "admits 17 of 17" still delivers **0**
  reviews. It is worth landing on its own merits; it is not worth landing as a #657 unblock.
- **Enrolling `sparq-org/sparq`** — the denser population, and the ask that commissioned this
  work — would, before this PR, have converted ~20 lane-invisible PRs into ~20 terminal parks. It
  remains the right next step, *after* the decision above, not before it.

---

## 12. The token drop — shape 2, taken (Claude Opus 5, 2026-07-29)

> 🤖 **SPARQ agent** — this section TAKES the decision §11.4 declined three times, and it takes
> shape **2**, not shape 1. Read §12.2 before changing anything about who may be enrolled.

### 12.1 What landed

§11.4 offered two shapes for admitting the class to the `run` job:

1. **widen the author gate** for `mode == "review"` and the self-attested class, accepting that a
   token with target write scopes exists in a job running a model over a PR this App did not
   author; or
2. **remove the target App token from the review path for this class**, so the question does not
   arise — "the narrower trust boundary and the better shape *if it holds*, but a real change to
   the review path that must be measured, not assumed."

It holds, and it was measured — but the first version of this section was **wrong about that
script in a way that would have delivered zero**, and the correction is §12.8. `worker-live.sh
review` makes **no** `gh`, API or `curl` call at all, performs **no** target write, and its single
remote git operation (`git fetch origin refs/heads/<head>`) is **already anonymous**: the target checkout is `persist-credentials: false`, so no credential has
ever survived into `.git/config` for it to use. The model container additionally cannot receive a
GitHub token by construction — `_run_headless_harness` dies on any argv element beginning
`GH_TOKEN`/`GITHUB_` (worker-live.sh:403-407).

Only three things in the `run` job needed the token in review mode:

| use | what replaced it |
|---|---|
| `gh api repos/<target>` (default branch) | the registry's own `GITHUB_TOKEN` — the same token `resolve` reads the pull request with, and the same one its `target-routing` checkout of this public repo already uses |
| `actions/checkout` of the target | the same fallback; `persist-credentials: false` on both paths |
| `round-record` / `round-void` (**target writes**) | the ledger attempt store, charged from `claim` |

So for the self-attested class the review path now holds **no target authority at all**.

### 12.2 The security property that replaces the App-author check

The author gate is not widened. On any run that holds a target App token it is **byte-for-byte
unchanged**. What changed is that the admitted class does not take that branch, and four things
stand where it stood:

1. **The fork gate**, unchanged, unwaivable, and hoisted above every waiver in all three consumers
   (`enumerate_review_items`, `claim_review_pr_admission`, review-fix.yml `resolve`). The head must
   be a branch **in the target repository**, so the author already holds push access there. No
   drive-by content reaches this lane on any path.
2. **The master-protected enrolment allowlist.** `admits_orchestrator_pr` requires the author's
   login in `review_enrolment_authors`, read from the **master** checkout — never from the `ledger`
   branch the provenance record came from, because collapsing the pair onto one branch would
   collapse the authority difference that makes the pair worth having. Master requires a reviewed
   PR through the required `gate`, so the *set* of admissible logins is a reviewed change even
   though an individual record is not.
3. **The authority is removed rather than extended.** The mint is skipped, and — this is the part
   that is executable rather than documented — the identity block **refuses** the run if a target
   App token exists on that path anyway (`self-attested-run-holds-a-target-token`), and refuses a
   non-public target (`self-attested-target-is-not-public`). Re-adding the mint without restoring
   the author gate therefore **stops the run**; it does not quietly re-open the hole.
4. **No gate input is *model*-influenceable any more, and the author's reach is narrowed rather
   than eliminated — stated precisely, because the first version of this section overstated it.**
   Round accounting moved off App-written PR comments onto the ledger attempt store, and
   `already_done` moved off the `<!-- sparq-reviewed-sha -->` PR-body marker onto the ledger
   verdict record's #156 host envelope. The `ledger` branch is `protected: false` with zero
   rulesets, and the sole enrolled author is also the sole collaborator with admin — so a
   *determined author* can still write there. What the move buys is real but bounded: it removes
   the surface from the **model** (the actual threat, which has no registry credential at all) and
   from anything that can only edit a pull request body. A trusted author who writes the ledger can
   strand their own PR; they cannot obtain a review they did not earn. This is not cosmetic: for a worker PR the App authors both the pull request and the
   marker, so a body marker is the App's own record; for this class the author is a human and the
   body is theirs. Leaving `already_done` there would have left the one cheap bound on redundant
   dispatch in the hands of the party it bounds.

Unchanged and still load-bearing: `mode == "review"` alone (a `fix` run **pushes commits**, and
keeps every pre-#657 gate), `ready_and_arm` **refuses** the class outright — so the review this
buys is advisory and cannot become a merge — and the verdict crosses to `outcome` as validated,
size-capped data that is re-validated on a fresh registry checkout before any token touches it.

**What this does NOT claim.** The model still runs with the reviewer account credential mounted in
its container, exactly as it does for every worker PR today. That surface is unchanged in kind: it
was already reachable by model-authored PR content, and the content this admits is authored by a
login the maintainer named in a master-protected file. The trade here is not "no risk"; it is that
the *marginal* authority this admission adds is zero, which is a stronger statement than the one
shape 1 could have made.

### 12.3 The store has ONE writer and NO eraser — and what that costs

`round-void` (#596) is deliberately **not** ported to the ledger store. Its input is
`WORKER_EXIT_CLASS`, a value derived from the model launch and carried through `$GITHUB_ENV` in the
job the model runs in. For the target-side marker that trade was made knowingly. This store exists
to bound a prompt-injectable model's re-dispatch loop, so it is built so that **nothing downstream
of the model can extend the budget that bounds it**: one writer (`claim`, pre-model, no target
code), no eraser.

The cost is named rather than hidden. Two paths that void a target-side round leave the ledger
attempt **charged** for this class: a credential-outage launch failure (#596) and a stale-head
outcome (#162). Both are bounded and self-healing — `max_review_rounds` of them route the PR into
the **capacity** `budget` park, which has automatic re-admission — where the pre-#596 target-marker
behaviour was a forever-charge. It is a follow-up, not a silent gap.

Two smaller asymmetries, stated so nobody has to rediscover them. `review-outcome`'s own
`count_rounds_since` reads target comments, which this class does not write, so the OUTCOME-layer
budget escalation cannot fire for it; and its `--bot-login` is `pr_author`, which for this class is
a human while every marker that step writes is written by the App — so it cannot find its own
receipts. Neither is a hole: the binding round bound is at **dispatch** (`count_ledger_rounds`
decides whether a model launches at all, now pinned by a red test, §12.5), and the receipt filter
can at worst duplicate one comment on a path that `resolve` immediately makes human-owned. Both are
pre-existing on this branch and both are left alone deliberately rather than fixed untested against
the main worker lane — the `identity-refusal` step three steps below already carries the correct
form (the App's own slug) if someone wants the pattern.

### 12.4 The admission rule is a CLASS, and what it costs to add a member

The rule is **configuration, not code**: `review_enrolment_authors` in `policy/repos.toml`, a list,
today `["jeswr"]` for this repository only. Adding a second identity — the fleet machine account —
is a one-line policy edit through the normal reviewed-master path. It keys on the **PR author login
against that list**, never on `actor.type`, so it does not inherit the "`type: "User"` does not
establish a human" problem: `User` is not treated as evidence of anything here.

**One form of member still needs a code change, and this PR deliberately did not make it.** If the
fleet identity is a GitHub **App**, its PR author login is `<slug>[bot]`, and
`policy-resolve.GITHUB_LOGIN_RE` refuses a `[bot]` entry. Two reasons that refusal was left alone:

- Its stated rationale — *"a bot already satisfies the author gate, so listing one could only widen
  it to an unrelated App"* — is now **stale for a foreign App** (which is refused by
  `author-not-app-bot` exactly as `jeswr` was) but still **true for this App**. It needs
  re-deriving, not deleting.
- More decisively, `resolve-conflicts.py` documents that the orchestrator class and the
  rebase/fix-cede population are **disjoint by construction** *because* the allowlist refuses
  `[bot]` while that predicate requires `[bot]`, and calls the corresponding guard "a dead guard
  dressed as a control" for that reason. Lifting the refusal makes a `[bot]`-authored enrolled PR
  on a `sparq-agent/`-shaped head ref cede-able into the **fix** lane, **which pushes commits** —
  the one thing §3 says a self-attested record must never buy. Closing that means making that dead
  conjunct live, in a file this PR does not own.

**Recommendation, stated as a recommendation and not a decision:** make the fleet identity a
machine **user** account rather than an App, and enrolling it is pure configuration. If it must be
an App, it is a scoped follow-up of three coupled edits — re-derive `GITHUB_LOGIN_RE`, re-derive
`mint-provenance`'s independent `[bot]` refusal, and make `resolve-conflicts.py`'s
`not admits_orchestrator_pr(...)` conjunct live — and it should be one PR, because landing any one
of them alone is a hole.

The `HEAD_REF_RE` / exact-App-author **conjunction** in `claim_review_pr_admission` is untouched by
this PR. Both legs are waived together, only for a PR that is already `admitted` (orchestrator
attestation **and** master allowlist), and this change sits strictly downstream of that decision.

### 12.5 Evidence

- Full enrolled self-test suite green (`worker-live.sh print-selftest-suite` + `run-selftest`,
  the exact CI enumeration). The count moves with master: **55/55** at the time of writing, after
  rebasing onto a master that had added a script. A green suite is necessary and — see §12.8 — was
  demonstrably not sufficient.
- **M22 is CLOSED.** The `orchestrator_admitted → count_ledger_rounds` routing at the production
  `_dispatch_review_items` call site now has a red test, driven end to end through the real
  dispatch loop, with the difference observable where it matters — whether a reviewer **launches**
  — and asserted on the park **argv**, not on a log line, so "did not launch" cannot be confused
  with "did not launch for this reason". Two-sided: deleting the routing (`if False:`) is killed by
  the new row, widening it (`if True:`) is killed too, and the worker-class control is proved
  non-vacuous by an expected-value flip.
- The identity probe went from **2 facts to 6**, and is driven as a **composition** of `resolve`
  and `run` rather than as a reading of one — because "an admission proof is not a delivery proof"
  (§11.2) is the error this whole issue is made of. It now demands: admits the enrolled class,
  still refuses a human stranger, **still refuses a foreign App bot** (previously covered only by
  accident — a gate widened to `endswith("[bot]")` also stopped admitting the human-login class,
  so fact 1 caught it; that coincidence is gone), refuses a target token on the self-attested path,
  refuses a private target, and still delivers the worker class.

### 12.6 What is NOT proven, and the one thing that would prove it

**Delivery is still zero, and this PR cannot make it non-zero.** The acceptance bar is one verdict
record on `ledger` for an orchestrator-class PR — not `admits == true`, not a green self-test.
Reaching it requires an actual `review-fix.yml` run, and every job that could produce one
(`claim`, `run`, `outcome`) declares `environment: dispatch-secrets`, whose deployment-branch
policy is `master` **only** (verified against the environments API). A `workflow_dispatch` from
this branch cannot obtain that environment, so `claim` fails and `run` is skipped.

So the remaining blocker is **the merge itself**, and the first delivery is verifiable
post-merge by exactly one artefact: a file matching
`orchestration/review-verdicts/jeswr--agent-account-registry--pr<N>-round1.json` on the `ledger`
branch whose `host_envelope.repo` is `jeswr/agent-account-registry`. Until that file exists, the
honest statement of this lane's delivery is still **zero** — now with every code blocker named and
removed rather than with one hiding a job downstream.

### 12.7 Re-derived on the LIVE tree after rebase, and the one thing a merge does not buy

> 🤖 **SPARQ agent** — every number here is from the **uncapped** `/git/trees/ledger?recursive=1`
> (`truncated: false`, 2158 paths), never the contents API, which caps that directory at 1000
> entries and makes a "no match" unfalsifiable.

| | count |
|---|---|
| verdict records on `ledger` | 1512 |
| provenance records on `ledger` | 636 |
| verdict records for **any** of #1250 / #1266 / #1273 / #1275 / #1294 / #1298 / #1305 | **0** |
| provenance records for those seven | **1** (#1275 only) |

**The whole admission chain now admits the real #1275, on its real payload and its real ledger
record** — not a fixture:

```
resolve  review_fix_pr_admission(mode=review) -> self_attested=True   error=None
resolve  review_fix_pr_admission(mode=fix)    -> self_attested=False  error='pull request is not an open draft'
CLAIM    claim_review_pr_admission            -> admitted=True        defer=None
run      identity gate (6 facts, live YAML)   -> True
```

The fix-mode row is the one worth keeping: the class is admitted to **review** and still refused by
every pre-#657 gate on the path that **pushes commits**.

⚠️ **A merge alone will not produce the first verdict, and #1275 cannot be its own first delivery.**
#1275 carries `review:needs-user`, and `resolve` refuses a PR holding it (*"pull request is
human-owned"*) before any of the above runs. That park is a **genuine machine park with receipts** —
`sparq-orchestrator[bot]` wrote both `sparq-identity-refusal:v1 reason=author-not-app-bot` and
`sparq-park-reason:v1 class=question cause=target-identity` at 16:07:24/16:07:27Z. So any exit
conditioned on *"zero park-reason receipts ever"* is precondition-excluded here by construction, and
a human readmission gesture is what reopens it. **This PR must not clear its own label** — a
hand-applied or hand-removed hold carries no cause receipt.

So the first delivery will come from the hold-free part of the class. Of 12 open non-draft
`jeswr`-authored PRs, **9 are held** (`review:parked` ×5, `needs:user` ×3, `review:needs-user` ×1 —
#1275) and the rest are free: **#756, #1308, #1309**, and **#1313** which joined after that count.
The set is a moving target; the predicate, not the list, is the durable part. All three pass the shared writer's
`pr_mint_refusal` (`NONE`) and all three name a source issue (#758, #1304, #835), so auto-mint can
record provenance for them once the mint refusal self-removes — which it does the moment the
identity gate admits, with no edit anywhere.

**Verification recipe for whoever merges this:** after the merge, the first delivery is a file
matching `orchestration/review-verdicts/jeswr--agent-account-registry--pr<N>-round1.json` for any
hold-free enrolled PR, read via `/git/trees/ledger?recursive=1`. Until such a file exists, this
lane's delivery is still **zero**. ⚠️ Before §12.8's fix this prediction was simply WRONG — no such
file could ever have appeared, because the reviewer died in the shell first.

One live example of a hazard worth not leaning on: PR #1275 already contains a comment in which a
**human** quotes `<!-- sparq-identity-refusal:v1 ... -->` inside a blockquote. It is harmless here
only because the receipt reader filters on the App login — but it is exactly the shape a
marker-scanner without fence/quote stripping would misread, so nothing in this change reads a
marker without an author filter.

### 12.8 The FOURTH consumer — found in review, and the question I failed to ask

> 🤖 **SPARQ agent** — this section corrects §11.4 and §12.1. Both described
> `worker-live.sh review`'s only relevant property as *"the one remote git op is already
> anonymous"*. That was true and it was not the point.

`worker-live.sh` `run_review` carries its **own** copy of the worker head-ref gate:

```bash
[[ "$head_branch" =~ ^sparq-agent/issue-[1-9][0-9]*-[A-Za-z0-9._-]+$ ]] ||
  die 'unsafe pull request head branch'
```

It sits **29 lines above** the `git fetch` those sections cite, and §1 *defines* the #657 class by
having an ordinary head branch. So the merge outcome, before this fix, was: `review_run_refusal`
self-removes, the record mints, dispatch runs, the identity gate admits, no token is minted — **and
the reviewer dies in the shell.** `outcome`'s `if:` is then unsatisfied (`identity_refusal` empty,
`verdict_ok` skipped), so **nothing durable is written**; the ledger charge bounds it to three
attempts and then a `review:parked` hold with no capacity-recovery evidence to consume. Three
wasted dispatches and a terminal park per enrolled PR, and **zero verdicts**.

`unsafe pull request head branch` appears at **three** `die` sites in that script (`run_review`,
`run_fix`, `push_fix`) and had **zero** test coverage, because every `worker-live.sh` fixture uses a
worker-shaped branch. **That is how a 55/55 green suite coexisted with a lane that delivers
nothing** — and it is the mechanism behind `review_run_refusal`'s own warning that *"a predicate
that stops at the consumer it happens to know about writes records whose only effect is a terminal
park"*. §8.1's consumer table enumerates two and stops; `claim_review_pr_admission` even notes
CLAIM's duplicate shape gates. Three of four copies were found.

**The generalisable error is narrower than "I missed a file", and worth writing down.** The
investigation was briefed to answer *which operations on this path need a credential*. It answered
that correctly and completely. It was never asked *which predicates on this path refuse this class*.
Those are different questions over the same code, and only the second one finds a gate that costs
nothing and refuses everything. **When removing an authority, enumerate the ADMISSION predicates of
every layer the work will newly reach — not the authority's consumers.**

**The fix.** The waiver is threaded to the shell, `review`-only. `run_fix` and `push_fix` keep the
namespace check byte-for-byte, because they push commits and §3 forbids a self-attested record
buying write access to its own branch. What replaces the namespace check is **not "anything"**: the
value is interpolated into `git fetch origin "refs/heads/$head_branch"`, so a strict safe-ref
predicate (no leading `-`, no `..`/`@{`/`//`/trailing `/`/`.lock`, nothing outside
`[A-Za-z0-9._/-]`) now applies to **both** paths — the worker namespace is checked by two
predicates where it used to have one.

**The probe** (`worker_live_admits_orchestrator_class`) drives the real script by **controlled
differential execution**: the environment is shaped so the head gate is the first thing that can
fail, so `unsafe pull request head branch` versus `unsafe expected head sha` discriminates cleanly.
Six facts — admits the class in `review`; refuses it unenrolled; refuses **eight**
injection-shaped refs; refuses `fix`; refuses `push-fix`; still admits the worker lane — and it is
validated against four known positives, every one of which reds it.

Two false negatives surfaced while building that probe, both of which would have made it report
"not refused" for **every** input: the script validates its self-test manifest and every enrolled
sibling at load time, and `push_fix` refuses a missing token before reaching the head gate. A
differential that had not been checked against a known answer in both directions would have shipped
green and proved nothing — the same failure mode as the gate it was written to catch.
