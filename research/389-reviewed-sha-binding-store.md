# Where should the reviewed-sha binding live? (#389)

> 🤖 **SPARQ agent** — design record, 2026-08-03. Maintainer-review document.
> **This record changes no behaviour.** #389 asks for a design record *before* the migration
> ("Proposed direction (needs a design record first)"), because moving the reviewed-sha binding
> is a coordinated trust-plane change across three scripts and two workflows, not a rework of
> `set_reviewed_sha`. This is that record. No script, workflow, or policy file is touched.
>
> **Recommendation: option (b), a per-PR MUTABLE record on the `ledger` data-plane branch —
> and NOT option (a), a commit status.** But the migration is gated on a **store-neutral step 0**
> (§7) that must land, and be reviewed, first. §8 is the maintainer's confirm-or-overrule.

## 1. What is actually broken, stated at its real size

`scripts/worker-pr.py:2353` `set_reviewed_sha` derives a whole PR body from a GET and writes it
back with an unconditional `PATCH`. GitHub's REST PR-body write has no `If-Match`/CAS
precondition, so the read→PATCH gap is irreducible: a concurrent body edit landing inside it is
overwritten, and the post-PATCH read-back verify cannot see it (that verify only observes writes
landing *after* our PATCH). PR #379 narrowed the window; #389 asks to close it.

**The damage the residual can do, stated precisely, because it bounds what the cure may cost.**
The thing lost is a maintainer's or another automation's concurrent PR-body **prose** edit, inside
a sub-second window. The reviewed-sha **marker** is still written correctly on every path, and
every trust gate still reads the correct value. **No gate is bypassed by this bug.** It is a
durability defect in a shared text field, not an arm-authority defect.

That matters, because §6 shows the obvious cures introduce failure modes the current design is
structurally immune to. A cure that trades "rare loss of a prose edit" for "a fleet-wide disarm on
a transient read" is a bad trade, and the record's job is to pick a cure that does not.

## 2. The surface — measured, not assumed

#389's own inventory is close, but wrong in four places — corrected **downward and upward** in
§2.1–§2.3 and §4.3, because the migration's cost is a direct function of this count.

### 2.1 Writers (5, not 1)

| # | site | writes | when |
|---|---|---|---|
| W1 | `.github/workflows/review-fix.yml:2413` → `worker-pr.py reviewed-sha set` | `head` | the outcome job's LAST mutation; the marker == head *is* "this head's review completed end to end" |
| W2 | `worker-pr.py:4722` (inside `disarm`) | `head` | merge-only carry-forward: the head advanced only by verified base-merge commits, so the arm is re-bound rather than retracted (#69/#81) |
| W3 | `worker-pr.py:3494` (`fix_lane_defer` hand-over) | `none` | the marker asserts a head no verdict record binds — retract so the review lane can re-admit (#560 r1) |
| W4 | `worker-pr.py:3674` (`stranded_recover`) | `none` | drafted + unarmed disproves the marker's own assertion — retract so review-fix does not exit `already_done` (#708) |
| W5 | `worker-pr.py:6216` (arm-readmit) | `none` | a no-change CI fix at a head whose arm was deferred on a false red — retract to route back through the review lane |

Plus `scripts/worker-live.sh:2647`, which **seeds** the literal `<!-- sparq-reviewed-sha:none -->`
into every worker PR body at creation.

The binding is therefore **mutable by design**: it advances (W1, W2) and it retracts (W3–W5).
§4.3 shows this is the fact that rules out reusing the existing registry record writer.

### 2.2 Readers (10 production sites across 2 scripts, plus one workflow-inline reader)

| # | site | what it decides | disposition if the binding is UNKNOWN |
|---|---|---|---|
| R1 | `dispatch-claim.py:1573` in `armed_sha_mismatch` (1533) | **SECURITY**: is an armed/ready PR latched on a head its marker does not name? → disarm | must read **UNBOUND ⇒ disarm** (see §6.2) |
| R2 | `dispatch-claim.py:7756` in `_disarm_row_admissible` (7706) | **SECURITY**: re-binds a hostile plan row to the live snapshot before disarming | same as R1 |
| R3 | `dispatch-claim.py:3990` in `enumerate_review_items` (3746) | `reviewed_match` — feeds the needs-review / GAP-A / stranded state split | defer |
| R4 | `dispatch-claim.py:7072` | live re-derivation of the `stranded` posture before recovery | defer |
| R5 | `dispatch-claim.py:7290` | "head already reviewed" defer for `needs-review` | defer |
| R6 | `dispatch-claim.py:7510` | launch invariant: refuse to spend a reviewer lease on a dispatch review-fix would resolve `already_done` | defer |
| R7 | `worker-pr.py:4691` in `disarm` | the live marker `decide_disarm` and the carry-forward test consume | fail loud |
| R8 | `worker-pr.py:3486` (`fix_lane_defer`) | whether to retract | keep (write nothing) |
| R9 | `worker-pr.py:3652` (`stranded_recover`) | whether to retract | keep (write nothing) |
| R10 | `worker-pr.py:2406` `get_reviewed_sha` | CLI/step output | fail loud |
| — | `.github/workflows/review-fix.yml:316` | `already_done` — skips the model job entirely | defer (**run** the review) |

**Correction to #389 (AGENTS.md pre-flight item 10).** `scripts/plan-snapshot.py` does **not**
read the marker in production. Its only occurrences (1646, 1655, 2657) are body **fixtures in its
own self-test**; the predicate it exercises is dispatch-claim's shared `armed_sha_mismatch`
(1533), the one invariant `enumerate_disarm_items` (1613) and the detection-only
`enumerate_disarm_observations` (1673) both consume. One fewer reader to migrate — and, more
usefully, evidence that the shared-predicate discipline already works: plan-snapshot got the
invariant for free by importing it rather than re-spelling it.
It is still migration surface — those fixtures hand a marker **body** to
`enumerate_disarm_items`, so a store change breaks them — but as a **test** dependency, and a
fixture that stops compiling is the loud failure mode, not the silent one.

**Additions to #389.** dispatch-claim has **six** production read sites, not the one the issue
names; and `review-fix.yml:316` is a reader living in a workflow heredoc, invisible to any
Python-only sweep.

### 2.3 The grammar has FOUR independent definitions — this is the #958 shape

`worker-pr.py:352` (canonical) · `dispatch-claim.py:353` (comment: *"Mirrors worker-pr.py
REVIEWED_SHA_RE … keep formats in sync"*) · `review-fix.yml:316` (an inline `re.search` with the
pattern retyped) · `worker-live.sh:2647` (the literal seed string).

This is exactly the defect class #958 names: one literal with four owners and no shared
definition, where a repoint updates some consumers and leaves others reading the old thing. **A
migration executed against this tree would land as a partial migration by construction.** The
consumer most likely to be left behind is the one in YAML — and its stale reading is
`already_done == true`, i.e. **silently skip a review round**.

This is why §7 makes collapsing the grammar a *precondition*, not a step.

## 3. Option (a) — a commit status on the reviewed SHA

`POST /repos/{repo}/statuses/{sha}` with a `sparq/reviewed` context. Per-commit, so there is no
read-modify-write of shared state and no TOCTOU at the write.

**Rejected, on four counts.**

1. **It widens target-repo write authority.** The bind runs in review-fix.yml's `outcome` job
   under `steps.app-token-outcome.outputs.token`, minted (its own step name says so) for *"PR
   labels/comments only, no target contents"*. A status write needs `statuses: write` on the
   **target**, added to a job that runs downstream of hostile model output. Option (b) needs no
   new authority at all (§4.3) and *removes* a target write.
2. **It costs one HTTP read per open PR per tick.** R1–R6 currently read `pull["body"]` out of
   the paginated listing that already identified the PR — zero marginal calls. Statuses would add
   a `GET /repos/{repo}/commits/{sha}/status` per PR to the PLAN walk that already pages
   check-runs, and each of those reads can fail **independently** (§6.2).
3. **A failing status is not inert.** A retraction would post a non-`success` state on the head
   commit, which participates in `mergeable_state`. `stranded_live` (`dispatch-claim.py:1489`)
   takes `mergeable` as an argument, fed from `pull.get("mergeable")` at 7080, and the arm path
   reads mergeability too; a retraction would perturb
   inputs it has no business perturbing.
4. **It cannot express W2 or the value readers need.** R7's carry-forward walks commit parents
   from the live head *back to the reviewed sha* (`merge_only_advance`, `worker-pr.py:1442`), and
   `dispatch.yml:1415` pins `reviewed_sha` as a required disarm-row field. A status answers "was
   *this* commit reviewed", not "*which* commit is bound" — every value reader would have to walk
   history probing per-commit statuses.

## 4. Option (b) — a per-PR mutable record on the `ledger` data-plane branch

### 4.1 Distribution is already solved, and it is solved *atomically*

`dispatch.yml` already checks out `ref: ledger` in **both** consuming jobs — PLAN at 1131, CLAIM
at 1667 — and already iterates `orchestration/provenance/*.json` out of it (1273). A per-PR
reviewed-sha record on that branch reaches R1–R6 through a checkout they already perform, at
**zero marginal API cost**.

More importantly it reaches them **all-or-nothing**. Both checkouts *"fail the job LOUDLY if the
ledger branch is missing"*, and both are immediately followed by `ledger-invariant.py` as a hard
step (1140, 1676). So a ledger read either succeeds for every PR in the tick or the tick dies
before planning. That reproduces the one property the PR body has for free — *if you can see the
PR, you can see its binding* — and it is the property option (a) cannot reproduce, because N
independent per-commit HTTP reads fail independently. **This is the decisive argument, and §6.2
is why it is decisive.**

### 4.2 A record shape that keeps the value readers whole

Keyed by PR (not by sha), because W3–W5 must retract and R7/`dispatch.yml:1415` need the value:

```json
{ "repo": "owner/name", "pr": 42,
  "reviewed_sha": "<40-hex>|none",
  "bound_by": "seed|census|review-outcome|carry-forward|retract-fix-lane|retract-stranded|retract-arm-readmit",
  "expects_sha": "<40-hex>|none",
  "expects_epoch": 6,
  "epoch": 7 }
```

**An absent record is `UNKNOWN`, NOT `none`.** These are different facts and the §6.2 tri-state
exists to keep them apart: `none` is *a retraction someone performed* — W3–W5, or the seed at PR
creation, which writes the literal `<!-- sparq-reviewed-sha:none -->` rather than writing nothing —
whereas `UNKNOWN` is *this store cannot say*. Equating them would make "not migrated yet"
indistinguishable from "deliberately retracted", which **discards live state at the cutover**: an
open PR whose body already names a 40-hex reviewed sha, but which happens to take no W1–W5 write
during step 2, would reach step 3 with no record, read as `none`, and R1/R2 would disarm a valid
latch while R3–R6 re-admit an already-reviewed head. Under `UNKNOWN` that same PR fails **closed**
on both lanes (R1/R2 disarm, R3–R6 defer) — still wrong, but loud and recoverable rather than a
silent grant.

`UNKNOWN` is the safe floor, not the answer: making the cutover *correct* is a coverage problem,
and §7 solves it as one — step 2½ bootstraps a record for every in-scope open PR and step 3
refuses to treat the ledger as authoritative until that coverage is sealed. **This migration
therefore requires a backfill** — the seed's `none` covers PRs opened *after* the cutover work
begins and says nothing about the ones already bound. `backfill-provenance.py` is the precedent
for both halves: a one-shot, idempotent, dry-run-unless-`--apply` backfill, and a population that
stays fail-closed invisible and human-listed when it cannot be resolved.

`epoch` is a monotone per-record write counter, advanced by **every** write — bind and retraction
alike. As an *audit* field it would order the writes that landed, not the decisions behind them,
which is worth nothing on its own; §6.3 therefore lifts it into the **precondition**, and that is
where its value is. Every operation carries the pair `(expects_sha, expects_epoch)` — the binding
it believed it was replacing, **and the revision it read that binding at** — because the value
alone cannot see a binding that was retracted and re-established (§6.3's ABA case).

### 4.3 The token seam is already open — but the writer is not

The `outcome` job already holds `permissions: contents: write` on the registry
(`review-fix.yml:2175`) and already writes a ledger record with it — `verdict-record` at 2211,
whose envelope (`worker-pr.py:2922` `verdict_envelope`) *already carries `reviewed_sha`*. So the
credential, the permission, and the record-writing idiom all exist in the exact job that binds.

**But `_registry_put_file` (`worker-pr.py:2721`) cannot be the writer, and #389 is half wrong
about this.** The sha-precondition PUT it wraps *is* a real CAS — but the policy wrapped around it
is **create-or-keep**: an existing record that differs raises `RegistryRecordConflictError`, a
PERMANENT class, on purpose ("provenance must never be silently rewritten"). Feeding it a binding
that advances per head and retracts to `none` would make the second write of any PR's life fail
closed forever.

The mutable-CAS writer to model on is `select-and-claim.py:1044` `_write_ledger` (args at 785),
with the classifier and wait schedule taken from `scripts/ledger_retry.py` and the re-read done in
the writer's own loop. Per the fleet rule and `ledger_retry.py`'s own header, that loop must
**re-read and re-derive the expected blob SHA on every attempt**, and must not be wrapped in
`run_gh` — a replayed ledger CAS write consumes the conflict signal its caller keys on (#558).

So option (b) is **not** "reuse the existing machinery". It is "add one mutable-record writer,
built from the two existing halves". That is a real cost and §7 sequences it.

## 5. Option (0) — accept the residual and shut the migration down as won't-do

Taken seriously, because §1 bounds the damage at "a rare lost prose edit" and §6 shows the cure is
not free. Rejected, but narrowly, and for one reason: the binding is read by **two security
surfaces** (R1, R2 — the "never keep an arm latched on a head that no longer equals its
reviewed-sha" retraction), and those surfaces read it out of a field **any maintainer can edit by
hand**. AGENTS.md pre-flight item 5 — *ask who can write the thing this reads* — has already
produced three arm-capable holes from author-controlled text (#681, #937, sparq #4743). Today the
marker is protected only by the fact that hand-editing it is unnatural. Moving it to a
data-plane path is a **trust** improvement independent of the TOCTOU, and that, not the lost
prose edit, is what justifies the work.

## 6. What the migration costs — the three things that must not be waved through

### 6.1 Two stores exist during the window — with ONE authority at every instant

The seed at `worker-live.sh:2647`, R1–R10, and the workflow-inline reader at `review-fix.yml:316`
cannot flip in one commit. During the window the body marker and the ledger record can disagree,
and a disagreement is read by a *security* surface. The record's position is **not** "the ledger is
authoritative from the first commit that writes it" — that would contradict step 2, which leaves
every reader body-backed, and two stores cannot both be authoritative. It is:

> **The body marker is authoritative for the whole of steps 1–2. The ledger becomes authoritative
> at exactly ONE boundary — the step-3 resolver repoint, which is one function because step 0 made
> it one function. No reader consults both stores at any instant**, so there is nothing to
> reconcile at read time: never a merge, never a "prefer whichever is newer". A resolver that
> continuously reconciles two stores is a third store with no owner.

**Write order and the partial-failure states**, because W1–W5 cannot write two stores atomically
and a crash between the two writes is not hypothetical:

* **Ledger first, body second, always.** The shadow store moves before the authoritative one, so
  the only residual divergence is *ledger ahead of body* — and through steps 1–2 the ledger gates
  nothing, because no reader consults it.
* A ledger write that exhausts the §4.3 retry loop is a **hard failure of its caller**; the writer
  does not fall through to the body write. For W1 that leaves the review outcome unmarked, so the
  round re-runs — fail-closed as a re-review. For W2–W5 the carry-forward or retraction simply did
  not happen, which is the pre-existing stuck-and-loud state those sites already handle (#69/#81,
  #560, #708), not a new grant. A §6.3 **stale abort** suppresses the body write the same way, but
  it is a justified refusal rather than an error: the operation was superseded, and the site that
  raised it re-derives on the next tick.
* The converse — the body write fails after the ledger write succeeded — leaves the authoritative
  store unmoved and the shadow ahead. Same disposition: it gates nothing before step 3.
* **Nothing reconciles the two continuously.** Divergence is allowed to accumulate through step 2
  precisely because it is never consulted, and it is settled **once**, at the step-2½ census (§7),
  which takes the **body** as ground truth — it is the authoritative store right up to the
  boundary — and writes the ledger from it. That is what makes an ahead-ledger *safe* rather than
  merely unread, and it is why the census is a cutover precondition rather than a cleanup.

### 6.2 The unknown-disposition is NOT uniform — and #389 gets it backwards

#389 says *"a missing/unreadable record must DEFER, never grant"*. That is right for R3–R6, R10,
and `review-fix.yml:316`. **It is wrong, and unsafe, for R1 and R2.** From
`_disarm_row_admissible`'s own docstring (`dispatch-claim.py:7724`), on fields it deliberately
does not re-derive:

> asserting them from the stale listing would fail-CLOSED on a live latch, which on THIS net (the
> one whose act IS the safety measure) is the fail-open direction.

The disarm net's *act* is the safety measure. "Defer" there means **leave the auto-merge latch on
a head that may never have been reviewed**. For R1/R2, unknown must resolve to **UNBOUND ⇒
disarm**. The two dispositions are opposites, and a resolver returning a plain
`str` (`"<sha>" | "none"`) silently hands each lane the other lane's disposition.

**Therefore the resolver must be tri-state — `(sha, UNBOUND, UNKNOWN)` — and every one of the 11
call sites must name its UNKNOWN disposition explicitly at the call.** This is the single most
important constraint in this record, and it is store-neutral: it is true of the body-backed
implementation today, where UNKNOWN is currently *unrepresentable* and every site silently gets
`"none"` — i.e. R3–R6 already have the disarm net's disposition, not their own.

That last sentence is a live finding about the shipped tree, not a migration artefact. It is
benign today only because the body always arrives with the PR. It stops being benign the moment
the binding lives anywhere the PR listing does not carry.

### 6.3 Blob-SHA CAS is necessary and NOT sufficient — a stale operation must be refused, not retried

The §4.3 writer re-reads the blob SHA and retries on conflict. That serializes *writes*; it does
not order the *decisions* behind them, and the gap is live in both directions:

* A W3–W5 retraction computed against binding `X` loses the CAS to a W1 review-bind of a newer
  head `Y`, re-reads, and — if it replays its payload — writes `none` over a review that actually
  completed. R1/R2 then disarm a valid latch and the review lane re-admits `Y`.
* Symmetrically, a W1 bind of `Y` that loses to a W3 retraction and replays re-asserts a binding
  the fix-lane hand-over just invalidated. That is the fail-**open** direction: an arm left latched
  on a head whose verdict record was withdrawn.

`epoch` **as an audit field** catches neither. It increments on whoever writes last, so the stale
overwrite lands with a perfectly monotone epoch and no reader is given any basis to reject it. "A
stale-read overwrite is detectable" is true only of a *lost* write; neither case above loses a
write, so that property was overclaimed and is withdrawn here. What does catch them is the same
counter **turned into a precondition** — an operation that names the epoch it derived against
cannot land on a record that has moved since, and a retraction moves it. That is the mechanism
below; the audit reading is a by-product of it, not its purpose.

**Every operation therefore carries a semantic precondition, and a CAS conflict re-derives that
precondition instead of replaying the payload** — which is what `ledger_retry.py`'s own header
already demands of every writer in the fleet: each writer's loop re-reads the ledger and
re-derives **both** the expected SHA **and the payload** before the next PUT.

| op | precondition checked against the RE-READ record | on conflict |
|---|---|---|
| W1 bind `head` | **`expects_epoch` equals the re-read `epoch`** — nothing at all has been written to this record since the round's justification was formed, and in particular no retraction has — **and** the PR's live head is still `head`, and the verdict record this outcome job just wrote (whose envelope already carries `reviewed_sha`, §4.3) still names it | **abort** on either: the head moved (the next round binds it), or the record moved (the bind was superseded — see below) |
| W2 carry-forward | the re-read `(reviewed_sha, epoch)` is still the `(binding, revision)` `merge_only_advance` (`worker-pr.py:1442`) walked back from | re-walk from the fresh binding; abort if the walk no longer proves merge-only |
| W3–W5 retract | `(expects_sha, expects_epoch)` equals the re-read `(reviewed_sha, epoch)` — a retraction must name the **exact** binding it invalidates, at the exact revision it read it at | **abort, never overwrite**: the justification (fix-lane hand-over / drafted+unarmed / arm-readmit) was derived against a binding that no longer exists, and must be re-derived |

**Why W1 needs the epoch and not just its own facts.** Both of W1's original predicates are
*invariant under a retraction*: the live head is unchanged by definition in this race, and the
verdict record is create-or-keep immutable (§4.3), so it goes on naming `head` forever. A W3–W5
retraction of that very binding leaves both true, and a stale W1 replaying against them writes the
binding back over a justified withdrawal — the fail-**open** case the second bullet above says must
be refused. The epoch is the one field on the record that a retraction is *guaranteed* to move, so
it is the only sound precondition, and carrying `expects_epoch` is what makes W1 **prove it derived
after** the latest write rather than merely re-observe facts that predate it.

`expects_epoch` for W1 is the epoch read by the `already_done` gate that **admitted** the round
(§2.2, `review-fix.yml:316`), carried into the outcome job as a job output — not a value re-read at
write time, which would swallow every retraction that landed during the round.

**The same-head race, walked through.** PR #42; the head is `H` throughout and never moves; every
verdict record ever written is immutable and goes on naming `H`.

| t | actor | state read | state written |
|---|---|---|---|
| t0 | gate (`review-fix.yml:316`) | `{reviewed_sha: none, epoch: 4}`; `none ≠ H` ⇒ admits round **R**, which carries `expects_epoch = 4` | — |
| t1 | W1(**R′**) — a duplicate outcome for the same head, the race the gate's own comment names | `(none, 4)` | CAS wins → `{reviewed_sha: H, epoch: 5}` |
| t2 | W3 fix-lane hand-over | `(H, 5)`; `expects_sha = H`, `expects_epoch = 5` | CAS wins → `{reviewed_sha: none, epoch: 6, expects_sha: H, expects_epoch: 5}` |
| t3 | W1(**R**) | PUT rejected (blob SHA moved); re-reads `(none, 6)` | — |
| t4 | W1(**R**) | `6 ≠ expects_epoch 4` ⇒ **STALE** | **nothing.** The record is byte-identical to what W3 wrote at t2 |

At t4 the old table's predicates are *all still true* — the live head is `H`, and the verdict record
this job wrote names `H` — which is exactly why they cannot be the precondition. And the value
alone would not have caught it either: the record travelled `none → H → none`, so a W1 checking
only `expects_sha = none` against the re-read `none` matches and overwrites. That is the **ABA**
shape, and it is why the pair is `(expects_sha, expects_epoch)` and never `expects_sha` alone.

Abort is safe in every row because each of these sites is re-derived by the next tick; none is a
last-chance write, so refusing is a deferral, not a loss. For W1 specifically, aborting leaves the
binding at the retracted `none`, and `already_done` keys on the **binding**, not on the verdict
record (§2.2) — so the round is re-admitted and re-derived rather than lost. Aborting on *any*
intervening write, not only on a retraction, is deliberately over-strict: the cost of a false abort
is one re-review, which is the fail-closed direction, while distinguishing "benign intervening
write" from "invalidation" at conflict time is a second reconciliation with no owner (§6.1).

A 409 that `ledger_retry.is_cas_conflict` accepts is then split by what the **re-read shows**,
never by any further reading of the error text: **stale** iff
`(reviewed_sha, epoch)` moved off `(expects_sha, expects_epoch)` ⇒ abort and census; **contended**
iff both are unchanged — the branch tip moved under an unrelated ledger write, so the conflict is
real but this record did not move ⇒ retry with the re-derived expected blob SHA on
`ledger_retry.py`'s CAS schedule. Nothing else retries.

Step 1's self-tests must therefore include a **bind/retract race in BOTH orders** —
stale-retract-vs-fresh-bind and stale-bind-vs-fresh-retract — each asserting that the older
operation is refused and the newer justified state survives **byte-for-byte**. Both orders must be
exercised in the **same-head** form above, where every predicate other than the epoch still holds,
and the stale-bind case must also be exercised in its **ABA** form (`none → head → none`), which is
the one an `expects_sha`-only implementation passes. A test asserting only "the write eventually
succeeded" passes for the losing implementation and is vacuous; so does one whose stale operation
would have been refused by the head check anyway.

## 7. The sequence — step 0 is a precondition, not a phase

**Step 0 (store-neutral, no migration).** One shared `reviewed_sha` module: the grammar defined
ONCE, a tri-state resolver, and `UNKNOWN` dispositions stated at each of the 11 sites.
`dispatch-claim.py:353`, `review-fix.yml:316`, and `worker-live.sh:2647` all repoint to it. The
store does not change; the body is still read. Self-tests must assert the dispositions **in both
directions** — an R1/R2 assertion that goes red if UNKNOWN stops disarming, and an R3–R6
assertion that goes red if UNKNOWN starts acting. Per pre-flight item 6, the `review-fix.yml`
seam is pinned by **exact-match on the tokenised call**, never containment.

Step 0 is independently worth doing even if steps 1–3 are never done: it kills the #958
four-copies defect and makes the currently-unrepresentable UNKNOWN representable.

**Step 1.** The mutable ledger writer (§4.3) with the §6.3 semantic preconditions, with self-tests
that inject a concurrent write and assert the CAS either preserves it or fails closed — **never**
that a lost write counts as a pass — plus the §6.3 bind/retract race in both orders, in its
same-head and ABA forms.

**Step 2.** Dual write, **ledger first, body second** (§6.1): W1–W5 write both stores, and the
seed at `worker-live.sh:2647` writes an explicit `none` **record** beside the body comment, so
every PR opened from step 2 onward is covered by construction. Readers still read the body, and
the body is still **authoritative** for the whole step; the ledger is written and consulted by
nobody.

**Step 2½ — the bootstrap, and it is a GATE, not a nicety.** Step 2 covers future events and new
PRs. It covers nothing about a PR that is open and bound *today* and takes no write during the
window, and §4.2 is why that population must not be defaulted away. A one-shot, idempotent,
`--apply`-gated backfill — modelled on `backfill-provenance.py`, which exists for exactly this
shape of migration — enumerates every in-scope open PR from the same listing PLAN walks, parses
its body with the step-0 grammar, and writes the ledger record from it, explicit `none` included.
Two rules make it a gate rather than a sweep:

* **A body marker that resolves to `UNKNOWN` — absent, malformed, duplicated — is never guessed.**
  It is refused, named, and left for a human, exactly as `backfill-provenance.py` leaves an
  unresolvable run fail-closed invisible rather than reconstructing it from forgeable evidence.
* **It seals a census** — PRs enumerated, records written, refusals by reason — arithmetically
  sealed in the `auto-mint-provenance.py:1134` `census_row` shape, because a census that does not
  add up is a sweep that cannot say what it did. The seal lands on the `ledger` branch carrying
  the enumeration boundary it covers.

**Step 3.** Repoint the step-0 resolver's backing store — **one function**, because step 0 made it
one function — **and fail closed unless coverage is proven**: the repointed resolver treats the
ledger as authoritative only if the step-2½ seal exists, reports zero refusals, and covers the PR
being asked about (below its enumeration boundary, or above it and therefore seeded by step 2).
A PR outside that coverage is `UNKNOWN`, which §6.2 already routes correctly in both directions.
Only once that holds do we stop writing the body marker and drop the body seed.

**Nothing after step 0 should be written until this record is accepted and step 0 has landed with
its dispositions pinned red-if-flipped.** Doing step 1 first would put a second store behind a
grammar with four owners, which is how a partial migration becomes permanent.

## 8. What the maintainer is being asked to confirm

1. **The cure is worth it for the §5 reason (a security surface reading a hand-editable field),
   not for the §1 reason (a lost prose edit).** If you disagree, shut the migration down as
   won't-do and take step 0 alone — it is the majority of the trust benefit at a fraction of
   the cost.
2. **Option (b) over option (a)**, on §4.1 (atomic distribution) and §3 point 1 (no new
   target-repo write authority).
3. **The §6.2 tri-state**, and specifically that R1/R2 resolve UNKNOWN to *disarm* while every
   other site defers. This is the one call where "fail closed" points in two directions, and
   getting it wrong in either direction is an arm-authority defect.
4. **Step 0 as a precondition.** If you want the migration faster, the thing to cut is steps 2–3,
   not step 0.
5. **Step 2½ (the bootstrap census) as a second precondition, on the same footing as step 0.**
   A cutover that treats an unmigrated PR's missing record as a retraction discards live bindings
   on a security surface; the only alternative to proving coverage is a bounded body-backed
   compatibility read with a stated retirement date, which re-opens the two-authority problem §6.1
   just closed. If you want to overrule this, overrule it explicitly — it is not a detail of
   step 3.

## 9. Provenance

Model-agnostic by policy (#2504): this record names the SPARQ agent, not the model that wrote it.
Every line/anchor above was read out of the tree at the commit this record lands on; where #389's
own inventory and the tree disagreed, §2 states the correction rather than repeating the issue.
