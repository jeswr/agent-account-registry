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
  "bound_by": "review-outcome|carry-forward|retract-fix-lane|retract-stranded|retract-arm-readmit",
  "epoch": 7 }
```

`epoch` is a monotone counter, incremented on every write, so a stale-read overwrite is detectable
rather than silent — the exact property the PR body cannot offer. Absent record ⇒ `none`, matching
the `worker-live.sh:2647` seed, so no backfill of existing PRs is required.

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

## 6. What the migration costs — the two things that must not be waved through

### 6.1 Two stores exist during the window

The seed at `worker-live.sh:2647`, R1–R10, and the workflow-inline reader at `review-fix.yml:316`
cannot flip in one commit. During the window the body marker and the ledger record can disagree,
and a disagreement is read by a *security* surface. The record's position: **the ledger record is
authoritative from the first commit that writes it, and the body marker becomes decoration** —
never a merge, never a "prefer whichever is newer". A resolver that reconciles two stores is a
third store with no owner. §7 orders the steps so a disagreement is never consulted.

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

**Step 1.** The mutable ledger writer (§4.3), with self-tests that inject a concurrent write and
assert the CAS either preserves it or fails closed — **never** that a lost write counts as a pass.

**Step 2.** Dual write (W1–W5 write both stores; readers still read the body). Body marker becomes
decoration.

**Step 3.** Repoint the step-0 resolver's backing store — **one function**, because step 0 made it
one function. Then stop writing the body marker and drop the seed.

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

## 9. Provenance

Model-agnostic by policy (#2504): this record names the SPARQ agent, not the model that wrote it.
Every line/anchor above was read out of the tree at the commit this record lands on; where #389's
own inventory and the tree disagreed, §2 states the correction rather than repeating the issue.
