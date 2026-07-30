# Minting the orchestrator-class provenance record (#657, follow-up step 4)

> 🤖 **SPARQ agent** — design record, 2026-07-27. Maintainer-review document.
> Companion to `research/657-orchestrator-pr-admission.md`, which owns the ADMISSION half
> (§7.4 steps 1–3). This record owns step 4: **the writer**. Nothing here enables anything —
> `policy/repos.toml` is unchanged and `review_enrolment_authors` stays empty for every repo.

## 1. Why a writer is the binding constraint

`enumerate_review_items` admits a PR to the autonomous review lane only when a **registry
provenance record** exists for it. worker.yml's dedicated `provenance` job writes one for every
worker PR. **Nothing writes one for a PR the orchestrator authored itself**, so #759's PLAN-side
admission and #821's four wired consumer legs are, together, a complete code path with no data on
it: enabling `review_enrolment_authors` today would reach **0 PRs**, while spending a
master-protected gesture and removing the last structural barrier.

Re-measured on the live board **2026-07-27**, `gh api --paginate --slurp
'repos/sparq-org/sparq/pulls?state=open&per_page=100'` (103 open PRs), evaluated locally against
this tree's own constants (`HEAD_REF_RE`, `HUMAN_HOLD_PR_LABELS`, `MACHINE_PARK_PR_LABEL`):

| | count |
|---|---|
| open PRs / non-draft | 103 / 30 |
| **fork heads in the whole population** | **0** |
| non-draft failing `HEAD_REF_RE` | 28 |
| — of those, `[bot]`-authored (`dependabot[bot]`, `sparq-orchestrator[bot]`) | 2 |
| — of those, human-authored (all `jeswr`, all same-repo heads) | 26 |
| — carrying a terminal human hold (`needs:user` / `review:needs-user`) | 8 |
| — carrying a machine park (`review:parked`) | 0 |
| **enrollable once records exist** | **18** |

So the answer to "how many become enumerable" is **18**, not 26: the 8 held PRs stay terminal after
admission exactly as they do now (`HUMAN_HOLD_PR_LABELS` is checked *after* the waiver, and the
waiver does not reach it). The 2 `[bot]`-authored ones are unreachable by design — `policy-resolve`
refuses a `[bot]` login in the allowlist, so dependabot and release-plz PRs are outside this
feature entirely, whatever their head ref.

The figure is a **snapshot upper bound**, not an invariant, and later decisions must re-derive it
rather than quote it. It is also an upper bound in a second sense: §4.3 below adds a source-issue
requirement that some of the 18 will not satisfy on the first attempt.

## 2. Who mints, and on what trigger

Three candidate triggers, costed.

### 2.1 A `pull_request`-triggered workflow that validates and mints — **rejected**

The provenance record lives in the **registry**; the PRs live in the **target**. A
`pull_request`-triggered workflow can only be triggered by the repository whose PR it is, so this
option means installing a workflow **in `sparq-org/sparq`** that holds a registry write credential.
That repository is where the model fleet's worker jobs run target code. The entire provenance
design exists because "the worker job that runs model-authored code host-side holds no
registry-write token" (`orchestration/provenance/README.md`); putting a registry-writing job into
that repo inverts it. It also fires for **every** PR, including third-party ones, making the
allowlist the only thing between an outside contributor and a minted record — a single-barrier
design where the current one has two.

**Rejected on the trust boundary, not on convenience.**

### 2.2 A reconciliation sweep over enrolled authors — **rejected**

A cron that mints for every open PR by an enrolled login is the cheapest to operate and the worst
to reason about. It converts the record from *"this specific PR was attested"* into *"this author
is trusted"* — which is precisely the claim §3 of the admission record says the record must **not**
make. It also destroys the capacity property the admission record's §7.5 relies on: enrolment is
safe partly because it is **per-PR and operator-paced**, and a sweep would release the whole
backlog into a lane measured at 82 `review-fix` runs / 3 h.

**Rejected: it changes what the record asserts.**

### 2.3 An explicit, operator-invoked mint — **adopted**

`.github/workflows/mint-provenance.yml`, `workflow_dispatch`, one PR per run, dry-run by default,
running `scripts/mint-provenance.py` in the registry. It mirrors `backfill-provenance.yml`'s guard
idiom exactly (default-ref guard, `dispatch-secrets` environment, self-test before invocation,
conditional `--apply`), which is the shape the repo already reviews and trusts for a
credentialed one-shot data-plane writer.

**Trade-off, stated:** it is manual. That is the point — the design record's own argument for
preferring enrolment over a blanket predicate widening is that "the load is bounded by what an
operator mints". A trigger that removes the operator removes the bound.

The one genuine cost is that a PR opened at 02:00 is not reviewed until someone mints for it. That
is strictly better than today (never reviewed), and the standing rule from admission-record §2
remains: **work the orchestrator can delegate should go through the worker lane instead**, where
minting is automatic. This path is for the residue that must be authored interactively.

## 3. What makes it unforgeable

Stated as a threat model rather than a claim, because the honest scope is narrow.

**T1 — a third party causes a record to be minted for a PR they authored or control.**
Four independent barriers, any one of which suffices:

1. **Triggering.** `workflow_dispatch` on the registry requires `actions: write` on
   `jeswr/agent-account-registry`. A third party does not have it.
2. **The allowlist.** `pr_mint_refusal` reads the PR's live author and refuses unless that login is
   already in `review_enrolment_authors` for that repo — read from `policy/repos.toml` in the
   **master** checkout, behind branch protection. **The mint can never widen the allowlist; it can
   only act inside one.** A `[bot]` login is refused twice: `policy-resolve` refuses to put one in
   the list, and the mint refuses one independently.
3. **The fork gate.** `head.repo.full_name != target_repo` is refused first and unconditionally, in
   the mint and again at every consumer. (Measured: 0/103 open sparq PRs have a fork head, so this
   is not what is excluding anything today — it is the predicate that must never be waived.)
4. **The consumers.** Even a minted record admits nothing on its own:
   `admits_orchestrator_pr` re-checks the author against the live allowlist on every tick, so
   removing a login from master **revokes** every record minted for it, without touching the ledger.

**T2 — the mint is used to escalate a record's authority.** The record's `recorded_at_run` stamp
names its trust basis, and the two *machine* classes are admitted by every consumer **including the
arm**. So the mint must be unable to write one. It is: the stamp is built inside the script from
the runner's own `GITHUB_RUN_ID`/`GITHUB_RUN_ATTEMPT`, `stamp_admission_error` refuses any class but
`orchestrator` **by name**, and the workflow-seam self-test asserts that **no input, env binding or
CLI argument anywhere on this path names a run key or an attestation class**. The escalation is not
"not done", it is unreachable — and if a future edit made it reachable, the class refusal is the
red test that fires.

**T3 — an actor with registry write forges a record directly.** Not defended, and not defensible:
records live on the unprotected `ledger` branch precisely because master's required `gate` rejects
direct contents PUTs (issue #96), so anything holding the App token can write any record, including
a machine-shaped stamp. This is unchanged by this PR and is already stated in
`orchestration/provenance/README.md`. What the mint adds is that the **supported** path cannot, and
that every field on it is derived rather than declared.

**T4 — a false `impl_provider`.** The irreducible one (admission record §2): the actor that wrote
the diff wrote the record, and the lane picks the reviewer by *inverting* that field. §4.2 removes
the operator's ability to set it; #821's arm refusal bounds the residue to an advisory comment.

## 4. What the record asserts

```json
{"pr_number": 4193, "head_sha_at_open": "<40-hex, read from the API at mint time>",
 "impl_provider": "anthropic", "impl_alias": "opus5",
 "impl_account_h": "<sha256('orchestrator:' + login + ':' + SALT)[:16]>",
 "issue": 4192, "recorded_at_run": "orchestrator:<mint run>.<attempt>"}
```

In words: **this specific PR, at this head, opened by this enrolled orchestrator identity, was
attested by registry run `<run>.<attempt>`.** It is not a claim about the author in general, and it
is not a claim that the diff is good.

### 4.1 How it binds to exactly one PR

Three bindings, each checked somewhere different, so no single edit unbinds it:

* **the path** — `orchestration/provenance/<owner>--<repo>--pr<N>.json`, derived by
  `worker_pr.provenance_path` from the PR number, so readers can only find it for that PR;
* **the field** — `pr_number`, which `provenance_admission_error` requires to be a strict `int`
  equal to the PR under consideration (bool and float excluded), and which
  `admits_orchestrator_pr` re-checks **at the waiver decision itself**, before the field admission
  runs. #821 asserts this at three waiver sites; the mint satisfies it from the other end by
  writing `pr_number` from the **live payload**, not from the operator's argument — the operator's
  number is only ever used to *fetch*, and `mint_decision` refuses when the payload that comes back
  identifies a different PR;
* **the head** — `head_sha_at_open` is the API's head sha at mint time, and CLAIM's ancestry check
  refuses when the live head no longer descends from it (history rewritten). That is a terminal
  `needs:user` hand-off, not a loop.

Red-tested both ways: a record minted for #41 is admitted for #41 and refused for #42, at
`provenance_admission_error` **and** at `admits_orchestrator_pr`.

### 4.2 The provider stops being a declaration

`impl_provider` is **not an argument**. The operator names an `--impl-alias`; the mint looks that
alias up in the **target's protected routing catalog** (the same `routing` pointer the policy row
validates) and refuses unless the catalog's provider for it is `anthropic`.

This is worth more than tidiness. Admission-record §7.4 **step 2** — "pin a *constant* reviewer side
for the class" — is listed there as **five** enforcement points (the `REVIEW_CHAIN` subscript, the
`claim_provider == impl_provider` violation, review-fix.yml's inline chain table and its two
re-assertions), and warns that "a one-sided change deadlocks the lane". But all five read the same
input. `REVIEW_CHAIN = {"anthropic": ["sol", "luna"], "openai": ["opus5"]}`, so a record that can
only ever say `anthropic` can only ever resolve to the **openai review side** — which is exactly
option 2(b)'s "constant openai-side review side". **Pinning the writer is one enforcement point
instead of five, and it cannot be half-applied.**

Honest limits: this holds for records written by this path. A hand-written ledger record can say
`openai` (T3), and #821's arm refusal is what makes that a same-provider *advisory comment* rather
than a merge. And an orchestrator genuinely running on an openai harness must **not** use this path:
the pin would make the declaration false. The mint refuses rather than recording it, so the
supported writer cannot even manufacture the advisory-comment case.

`impl_account_h` is likewise derived — from the **live PR author login**, domain-separated
(`orchestrator:<login>`) from the worker lane's `acctNN` preimages so no future account handle can
collide with a login and make an orchestrator PR look like its own reviewer.

### 4.3 The source issue, and why it is required and validated

The record's `issue` is not decoration: the review lane derives the **lease partition** and the
**human-hold surface** from it. Getting it wrong produces the per-tick forever-loop this whole
interlock exists to prevent, so the mint refuses four specific shapes.

* **A pull request as the "issue".** Tempting — a PR *is* an issue, so `issue = pr_number` always
  resolves. It is wrong: PLAN's `_live_issue_labels` **skips pull-request rows**, while
  review-fix.yml's `resolve` reads `repos/<repo>/issues/<n>` directly, which resolves a PR and
  returns its labels. The two would derive different `package` values, and the adopt step compares
  them for **equality** — the exact shape of registry issue #112, where one PR burned ~20 % of the
  review lane's capacity on a claim its own adopter refused, every tick.
* **A closed issue.** PLAN reads `state=open` only, so a closed issue is absent from its label map
  and `busy_packages_of_pulls` reserves the serializing partition for the PR.
* **An unsafe `area:*` atom.** review-fix.yml's resolve step `SystemExit`s on it, on every dispatch.
* **A reduction to `__global__`.** Zero **or more than one** `area:*` label reduces to the
  serializing partition (`lease_schema.plan_package`), which excludes against every other area for
  the life of the review lease. This is the sparq#4185 shape that took the fleet to zero worker
  launches for an hour. **Refused by default**; `--allow-global-partition` is the operator's
  explicit, per-mint acceptance of that cost. (Of the 18 enrollable PRs, 6 carry two `area:` labels
  and 1 carries none — on the PR, not the issue — so this refusal will fire in practice, which is
  the point.)

The mint additionally requires the PR to **name** the issue (`#N`, word-bounded, in the title or
body). Scope this honestly: the PR body is author-controlled, so this is a **consistency and typo
control, not an authorization control** — an enrolled author who wanted a different partition could
write a different `#N`. Its value is that an operator's mistyped `--issue` cannot silently bind a
review to an unrelated partition, and that the record's assertion is checkable from the PR alone.
Against a determined enrolled author it proves nothing, and an enrolled author already holds
strictly more direct powers than this.

### 4.4 Attacks tried, and where each one stops

Constructed rather than asserted. Every one is blocked by at least two independent barriers.

| attempt | stopped by |
|---|---|
| fork PR minted for | fork gate at the mint, again at PLAN/CLAIM/resolve; measured 0/103 fork heads |
| non-enrolled collaborator's same-repo PR | allowlist check at the mint; `admits_orchestrator_pr` re-checks live at every consumer |
| add yourself to `policy/repos.toml` on a branch, then dispatch | the job's default-ref guard refuses any non-default ref, and dispatching needs `actions: write` on the registry |
| socially engineer a mint for someone else's PR | the mint re-reads the LIVE author; the operator's PR number only ever fetches |
| **mint over an un-recorded WORKER PR** (would permanently strand worker.yml's own create-only write) | `[bot]` author refusal **and** the `sparq-agent/` namespace refusal **and** the allowlist |
| ask for a machine-attested stamp | no input on the path names a run key or class (asserted structurally); the class refusal names every other class |
| point the mint at a repo outside the policy | the workflow's enabled-target step; `review_enrolment_authors` raises on an unknown row |
| mint for a closed/merged PR | open-state check at the mint, and again at enumeration |
| **push a commit to an enrolled author's PR head after minting** | *not blocked* — see below |

The last one is a genuine, accepted residual and is worth naming. Any collaborator with write on the
target can push to a same-repo PR branch, so a review dispatched against a minted record may end up
reviewing a commit the enrolled author did not write. This is **identical to the worker lane's**
exposure and the consequences are bounded the same way: the class is review-only (`emit` refuses
every state but `needs-review`), the fix lane can never push to it (`review_fix_pr_admission` waives
nothing outside `mode == "review"`), and the arm refuses the class outright. The worst outcome is a
model review comment on someone else's commit.

## 5. Degrading when minting is unavailable

**A refusal writes nothing, and a PR with no record is never enumerated.** That is today's
behaviour exactly — not a defer, not a park, not a retry: the PR is simply absent from the walk, so
no tick spends anything on it. The mint is `workflow_dispatch`, so there is no tick for a failure
to recur in either: a failed mint is one loud red run.

Two failure directions were considered and closed:

* **Writing a record the lane would then refuse** is the silent-stall shape #657 is about. The mint
  runs the lane's **own** predicate (`provenance_admission_error(..., admit_orchestrator=True)`) on
  the exact document it is about to write, and refuses to write one that would not be admitted.
  A last-mile assertion against the consumer's definition, not the writer's.
* **Overwriting or re-writing a record.** Records are create-only. An existing record with any
  differing identifying field, of any other attestation class, or that is not valid JSON, is a
  **refusal for a human** — never an overwrite. An *identical* orchestrator record, including one
  stamped by a different mint run, is idempotent success.

That last case needed its own handling and it is worth recording why.
`worker-pr._registry_put_file` treats `recorded_at_run` as volatile, but its `_run_key_identity`
only parses `<run>.<attempt>` and `backfill:<run>.<attempt>`, so it reads **any** two orchestrator
stamps as unequal and rejects a re-run as *"already exists with different content"*. The semantics
genuinely differ rather than the helper being wrong: for a worker record the run id is the **audit
link to the log the identity was read from**, so a different run is a different evidence source and
must fail closed; for an orchestrator record the run only says "a registry Actions run minted
this". So idempotency is decided in `mint-provenance.py`, and `_run_key_identity` is left alone —
a shared helper's fail-closed semantics are not relaxed for one caller's convenience.

## 6. Guards and their red tests

Every guard below is inverted by a mutant and named by the test that reds. Mutants run against an
**isolated copy** of the tree, targeted by line, with the file asserted to have changed, under
`-B` / `PYTHONDONTWRITEBYTECODE=1`.

| guard | mutant | test that reds |
|---|---|---|
| stamp class may only be `orchestrator` | admit any recognised class | *a worker-run-shaped stamp is refused* |
| stamp built from the runner | build it from a constant | *the stamp came from the runner's own run identity* |
| fork gate | delete it | *a FORK head is refused* |
| worker-namespace refusal | delete it | *a worker-namespace head is refused* |
| `[bot]` author refusal | delete it | *a [bot] author is refused* |
| allowlist membership | delete it | *a NON-enrolled author is refused* |
| empty allowlist refuses all | delete it | *an EMPTY allowlist refuses everything* |
| draft refusal | delete it | *a DRAFT PR is refused* |
| issue is not a PR | delete it | *a PULL REQUEST as the source issue is refused* |
| issue is open | delete it | *a CLOSED source issue is refused* |
| `area:*` atoms are safe | delete it | *an unsafe area:\* atom is refused* |
| `__global__` refusal | delete it | *ZERO area labels … are refused* |
| PR names the issue | delete it | *an issue the PR does not reference is refused* |
| `#41` ≠ `#412` / `x#41` | loosen either boundary | *#41 does not match #412 / x#41* |
| catalog provider pin | delete it | *an OPENAI catalog alias is refused* |
| live payload re-binding | delete it | *a live payload for a DIFFERENT PR is refused* |
| create-only | ignore identifying-field divergence | *an existing record with a different head is REFUSED* |
| **call site**: each refusal is actually called | delete each call | *…refuses at the decision, not just at the helper* (×4) |
| **call site**: last-mile lane check | delete it | crashes; and *a record the lane would refuse is never written* |
| **call site**: dry run writes nothing | make it write | *a DRY RUN decides to mint and writes NOTHING* |
| **call site**: `allow_global_partition` is threaded | hard-code False | *the override reaches the decision from mint()'s own argument* |
| **YAML**: ref guard / `if: false` | both | *the mint job refuses to run off the default ref* |
| **YAML**: `dispatch-secrets` environment | delete it | *the mint job takes the secret-scoped environment* |
| **YAML**: no `actions: read` | grant it | *the mint job may NOT read run logs* |
| **YAML**: `--apply` conditional | make it unconditional **or comment it out** | *--apply is conditional on its own input* |
| **YAML**: dry-run default | flip to true | *dispatch defaults to a dry run* |
| **YAML**: env↔input bindings | bind `APPLY` to `allow_global_partition`; **or add a new secret** | *every env name is bound to its OWN expression, and there are no others* |
| **YAML**: no run-key input/argument | add either | *no workflow input or env names a run key* |
| **YAML**: self-test before the mint | **comment it out** | *the self-test runs BEFORE the mint* |

| **call site**: an unreadable existing-record probe | read it as "nothing recorded" | *an unreadable existing-record probe refuses and writes nothing* |

**Sweep result: 48 mutants, 48 killed, 0 survivors, 0 harness errors** (frozen `git archive HEAD`
snapshot, so no live edit could race it — a backgrounded sweep against a live tree is how a mutant
was left in a tree here earlier today).

**A measured finding worth keeping.** The first sweep left exactly one survivor: commenting the
self-test invocation out of the workflow's `run:` block did **not** red
`self_test_before_mint`, because the probe searched raw text and the token was still there — inside
a comment. This is the same class the admission record's §7.3 table records for
`review_fix_admits_orchestrator_class` ("a comment carrying the token read as admitting"). Fixed by
stripping comments with dispatch-claim's audited, quote-aware `_strip_script_comments` before every
fragment check, and pinned by three comment-only mutants **inside the committed self-test** plus a
control asserting that a raw-text grep *would* have passed them.

Because the workflow itself never runs in CI, the seam is witnessed from outside it: the mutant
table lives in `mint-provenance.py --self-test`, which the `gate` job runs via
`scripts/selftest-suite.txt`. A neutered mint job cannot hide its own neutering.

## 7. Two findings for the admission half (not fixed here)

Recorded because they bear on **step 5**, and both were found by walking the CLAIM path with an
orchestrator PR's actual shape rather than a worker PR's.

1. **CLAIM's pre-review defuse is a silent no-op on this class.** `_dispatch_review_items` runs
   `worker-pr.py disarm --when always --preserve-review-state` for any non-draft item in
   `needs-review`/`needs-fix` — which is *every* orchestrator PR, on its first CLAIM.
   `disarm` early-returns `"disarm skipped: not a same-repo bot worker PR"` on a non-worker head
   ref and exits 0, so CLAIM then sets its local `draft = True` for a PR that is still published.
   **It is benign today** — #821 waives the draft gate at review-fix's `resolve` and at
   `revalidate_outcome_head`, so the downstream reads are consistent — but it is a lie in a local
   variable on a trust path, and it is the kind of thing that stops being benign when a later
   change reads `draft`. Worth an explicit carve-out before step 5.
2. **After #821, `enrolment_enable_error` no longer blocks enablement — but step 2 is still
   partly unlanded.** All four of its wiring facts become true when #821 merges, so the interlock
   stands down as designed. §4.2 above argues the *reviewer-side* half of step 2 is satisfied by
   the provider pin. The residue is item 1 and the `WORKER_HEAD_RE`-derived paths the admission
   record §7.4 lists. **Enablement should not be treated as unblocked merely because the interlock
   goes quiet.**

## 8. What this PR does not do

* It does **not** enable `review_enrolment_authors` for any repo — `policy/repos.toml` is
  unchanged, and the self-test asserts the shipped policy enrols nobody (with a non-vacuity control
  proving the same reader *would* surface an enabled list).
* It does **not** mint anything. With an empty allowlist the mint refuses every PR, by design and
  by test, so this path ships **inert** exactly as #759 and #821 did.
* It does not touch `enrolment_enable_error`, `admits_orchestrator_pr`, `review-fix.yml` or any
  other file #821 is changing.

**Ordering.** #821 merges first. Then this. Then §7 item 1. Only then does a login go into
`review_enrolment_authors`, in small batches, watching the lane.

---

## 9. Why the writer minted for 0 PRs, and what that turned out to be (Claude Opus 5, 2026-07-28)

> 🤖 **SPARQ agent** — this section records the follow-up that closed §8's "it does not mint
> anything". §8.4 of the admission record called the minting path *"the only thing between the tree
> and a working feature"*. It landed, the allowlist was enabled for this repo (#916), and the class
> still reached **0 PRs**. This is why, measured rather than reasoned.

### 9.1 The three counters, and which tier each one is

The answer is not in the code. It is in what the system already counts — and it counted nothing,
which is itself the finding.

| counter | value on 2026-07-28 | tier |
|---|---|---|
| `mint-provenance.yml` runs, all time | **0** | authoritative (Actions run history) |
| `ledger` records carrying an `orchestrator:` stamp | **0** of 463 | authoritative (every record on the branch, classified through `provenance_attestation_class`) |
| the writer's own health | **works** — first-ever dispatch succeeded | executed (dry run) |
| open PRs mintable **and** enumerable | **0** | executed (production `mint_decision` × production `enumerate_review_items` over the live population) |

The other 462 records split 47 `backfill` / 1 `human` / 414 worker run-keys. So the honest headline
is not "the minting path is broken". It is: **the only supported writer of the record is a manual
`workflow_dispatch` that nobody had ever pressed, and pressing it on that day's population would
have bought nothing.**

### 9.2 The population, and why it was empty

Of 36 open PRs in the enrolled repo, decided by calling the production functions rather than
re-deriving their predicates:

| | count |
|---|---|
| refused at the worker-namespace gate (worker.yml owns those records) | 16 |
| refused as DRAFT (groom would age-park a drafted orchestrator PR) | 6 |
| refused at `issue_mint_refusal` — no named `#<n>` binds | 11 |
| **mintable** | **3** (#685, #689, #710) |
| …of those, that the review lane would then enumerate | **0** — all three carry `needs:user` |

Two distinct causes, and they are on different axes:

1. **A mint could deliver nothing, and the script could not tell.** `mint()`'s last-mile check,
   `admissible_by_the_review_lane`, is `provenance_admission_error(document, pr,
   admit_orchestrator=True)` — a predicate over the **record**. It said *yes* to all three mintable
   PRs. `enumerate_review_items` discards all three at `HUMAN_HOLD_PR_LABELS`. The record would have
   been written, correct, admissible, and acted on by nothing; the only symptom would have been the
   absence of a review. *A guard that proves the wrong half is not a guard.*
2. **Nothing counted the class, so discovery cost one Actions dispatch per guess.** The workflow
   requires `pr_number` *and* `issue_number`, and the issue must be open, not a PR, hold-free and
   carry ≥1 `area:*` label — **307 of 406 open issues (76%) carry no `area:*` label at all**, and
   zero areas reduce to the serializing `__global__` partition, refused by default. So the only way
   to learn which `(PR, issue)` pair binds was to dispatch and read a refusal: ~130 dispatches over
   the live population, to find 3 candidates, all dead. A gesture that expensive is a gesture nobody
   performs — and the count of times nobody performed it was, correctly, 0.

### 9.3 What landed

* **`delivery_refusal`** — the second last mile. It drives the **production**
  `enumerate_review_items` over the live PR and the exact document about to be written, and refuses
  unless the lane emits a review item for that PR. It re-implements no admission predicate, so a
  widened or narrowed enumerator changes its answer by construction (§9.1 of the admission record).
  It is deliberately permissive in exactly one direction — no lease store and no CI snapshot are
  passed, so a transient lease, a conflicting base or a red gate can never make it refuse; the only
  refusals it can produce are terminal on the PR's own live state, and a false *"it would be
  enumerated"* degrades to today's behaviour. The operator-facing **hint** reads the consumer's
  exported constants and is explicitly advisory: the enumerator records an exclusion reason only for
  PRs carrying a review-loop signal, and the enrollable population carries none.
* **`--census` / `mode=census`** — one read-only run, one disjoint verdict per open PR
  (`MINTABLE` / `MINTABLE-BUT-DEAD` / `NO-BINDABLE-ISSUE` / `ALREADY-RECORDED` / `NOT-THIS-LANE`),
  every bucket seeded at zero so *"none"* and *"stopped being counted"* cannot print the same. It
  decides through the same `mint_decision` a real `--apply` uses, so it cannot drift from what a mint
  would do: to change the census you have to change the mint. It needs **no secret** — the salt feeds
  only `impl_account_h`, which the census never prints, so it decides with a per-run ephemeral salt
  and a census run cannot disclose `PROVENANCE_SALT` even by accident.
* The workflow gains a **`mode` allowlist** (default `census`, the read-only one), and its
  `target_repo` default moves to the **enrolled** repo — the master-protected allowlist names only
  that one, so a default dispatch at any other target could only ever refuse.

### 9.4 The never-arms property is unchanged, and re-proved by execution

`self_attested` still buys **review** and never an arm. Re-verified on this tree, not quoted:
`decide_review` over **6480** input combinations returns `"arm"` **0** times with
`self_attested=True` and **180** times with it False (the non-vacuity control), and
`ready_and_arm(self_attested=True)` raises *"refusing to arm: the provenance record is
self-attested (orchestrator class)"*.

### 9.5 What still blocks a **useful** mint — and it is not code

The two axes above are closed. What remains is data, and one half of it is a human gesture:

1. **Every mintable PR on 2026-07-28 was `needs:user`-held.** `needs:user` is human-owned by
   definition; clearing it is a maintainer decision and this PR does not make one. Issue #287 already
   records the same shape on the sparq side ("26/27 worker-PR source issues are needs:user-parked"),
   and the machine-manufactured-escalation defect (#722, #941) is the live investigation into whether
   those holds were generated by a human at all. **Until that is adjudicated, the enrolled
   population's held PRs stay out — by design, loudly, with a named refusal instead of an inert
   record.**
2. **76% of open issues carry no `area:*` label**, so most PRs have no bindable source issue. That is
   a labelling gap in the triage lane, not a mint defect: the `__global__` refusal exists because a
   review lease on that partition serialises the whole fleet (sparq#4185). `--allow-global-partition`
   remains the operator's explicit per-mint acceptance of that cost, and it is not the default.
3. `AUTO_READMISSION_PER_TICK_MAX` and the constant-reviewer-side item from the admission record's
   §9.5 are unchanged.

## 10. The two populations the trigger refuses, decided rather than left emergent (#1115)

> 🤖 **SPARQ agent** — design decision record, 2026-07-29. §9 closed the *trigger*; #937 automated
> it. This section owns what the trigger **refuses**. Both populations below are correct behaviour
> of code that is working as designed, and neither is owned by #657 or by #937 — which is exactly
> why they stayed invisible: from #657 the class looks enabled, from #937 the sweep looks correct,
> and only the composition delivers 1.

### 10.1 The measurement

`scripts/auto-mint-provenance.py` at #937's head `ba1a603`, plus `mint-provenance.pr_mint_refusal`
and `issue_mint_refusal`, over the 17 live orchestrator-class open PRs (#1115):

| verdict | count | share |
|---|---|---|
| `no-issue-reference` | **8** | 47% |
| PR-shape refused — **DRAFT** | **6** | 35% |
| `MINTABLE` | 2 | 12% |
| `reference-is-a-pull-request` | 1 | 6% |

One of the two mintable PRs carries `needs:user` (§9.5 item 1, the `MINTABLE-BUT-DEAD` bucket).
**Net delivery: 1, and that one is #937 itself.** The derivation was validated against a known
answer in both directions before the counts were reported — #937 binds `#929` correctly, and each
refusal matches a case #937 documents deliberately.

### 10.2 Population 1 — 8 of 17: a strict reader with no matching writer contract — **fixed here**

#937 derives `issue_number` only from an adjacent closing-keyword reference in the PR's own title
and body, and refuses with **no fallback**. That strictness is not negotiable and is not what is
fixed: the derivation is author-controlled, and `record["issue"]` feeds the source-issue `needs:*`
human-hold check and the `plan_package` lease partition, so a loose derivation would let an author
pick a partition or step around a hold. **Loosening the derivation is REFUSED** — it re-opens the
author-controlled-evidence axis #937 closed on review.

What was missing was the obligation on the **authoring** side. Orchestrator agents wrote
`Tracking issue: …`, `Closes the composition defect in #N`, conventional-commit scopes like
`fix(#869):`, and cross-repository references, all of which #937 correctly refuses, and nothing
ever told them. Three things now close that, in the order an author meets them:

1. **The rule**, stated where orchestrator PR bodies are authored — `AGENTS.md` item 13 (#973).
2. **The composer**, `scripts/pr-body-ref.py compose` (#1154/#1155), which emits the intersection
   form and verifies its own output against the reader's *imported* grammar.
3. **The advisory**, `scripts/pr-body-ref.py check`, run by `pr-gate.yml` on every pull (#1115).
   This is the piece #1115 adds: the rule and the composer only reach an author who thought to look
   for them, and the note now lands on the object that is wrong, while it is being written.

The advisory is **sound and one-sided by construction**, which is the property that makes it worth
having. `closing_references` computes `declared = resolved & raw_refs` and `all_refs = seen ⊇
raw_refs`, so over the raw text alone, with no renderer and no network: **0** raw closing references
guarantees a refusal, **2+** guarantees `ambiguous-issue-reference`, and **exactly 1** is
undecidable offline — a body whose only reference sits in a fenced block is raw-declared and
rendered-invisible. So `check` says nothing at 1 rather than "looks good": it has no false alarms
and accepts false negatives, which is the only asymmetry an advisory may have. It grants nothing,
admits nothing, writes nothing, makes no network call, and returns 0 on every path including its
own bugs — `auto-mint-provenance` remains the sole authority.

### 10.3 Population 2 — 6 of 17: drafts stay OUT OF SCOPE — **decision, with the cost stated**

`pr_mint_refusal` refuses a draft, and the reason it gives is a coupling to a different component:
groom's stale-draft carve-out reads `is_enumerable_provenance`, which hard-codes
`admit_orchestrator=False`, so a *minted* orchestrator draft would be terminally `needs:user`-parked
by age instead of reviewed.

**The decision recorded here is that this stands: drafts are out of scope for the orchestrator
review lane.** It was previously true only emergently — a property nobody had chosen — and #1115
exists to make it a choice. The reasoning:

* `provenance_admission_error`'s docstring already records the carve-out's `admit_orchestrator=False`
  as deliberate: it asks *"is this a pipeline-owned worker draft?"*, and an orchestrator PR is not
  one. The carve-out also governs paths that **push commits**, and the orchestrator class is
  self-attested (the actor that wrote the diff wrote the record). Per §3 option (b) and the arm
  boundary in `enrolment_enable_error`, that class must never reach a leg with a write in it.
* A draft is a **reversible, author-owned state**. Unlike `no-issue-reference`, the cost of the
  refusal is one click by the person who already holds the object.

**The cost is real and is not hidden: 35% of the class.** For that population the lane is not "not
yet enabled" — it is closed, and it will keep reading as a silent zero in the census.

The rejected alternative, stated so a future reader does not have to re-derive it: give groom's
age-park a **review-only exemption** that does not hand the fix lane write access. That is a
genuine option, and it is not taken here because it is a **new opt-in on a trust-plane predicate**
whose current fail-closed default protects four consumer legs — a change of that shape needs its own
design record, its own mutant battery over each leg, and maintainer sign-off, none of which belong
in an advisory-check PR. **This section is not that sign-off.** If a maintainer wants the draft
population inside the lane, §10.3 is the record to reopen.

What #1115 changes for this population instead is **visibility**: `pr-gate.yml`'s advisory now names
the draft refusal on the pull itself, with its reason and the one-click fix, so a drafted
orchestrator PR is no longer silently outside a lane its author believes it is in.
