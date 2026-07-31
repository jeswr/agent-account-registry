# Where should the reviewed-sha binding live, once it stops being the PR body? (#389)

> 🤖 **SPARQ agent** — design record, 2026-07-31. Maintainer-review document.
> **This record changes no behaviour.** #389 proposes migrating the reviewed-sha binding off the
> mutable PR body onto a CAS/immutable store, and says in its own text that the direction "needs a
> design record first". This is that record: it re-measures the defect, establishes the constraints
> the migration must satisfy (most of which are *read-path* constraints, not write-path ones),
> refutes the two options #389 proposes in the form it proposes them, and recommends a third.
>
> **Recommendation: option (b′) — write-once, generation-fenced, filename-encoded per-PR records
> on the `ledger` data-plane branch, resolved by ONE directory listing per target repo per tick.**
> §5 states the linearization rule and its recovery invariant, because per-path CAS alone does
> *not* serialize a PR-level binding and an earlier draft of this record wrongly claimed it did.
> §6 is the
> maintainer's confirm-or-overrule. §7 states what must be true before any code is written, and §8
> is the honest list of what this record does *not* settle.

## 1. The defect, restated precisely

`scripts/worker-pr.py:2310` `set_reviewed_sha` binds the canonical marker by reading the live PR
body, splicing in only `<!-- sparq-reviewed-sha:<sha|none> -->`, `PATCH`ing the whole body, and
re-reading to verify. #379 (issue #158) added the re-read/re-splice retry and the
already-canonical no-op short-circuit, which between them removed the clobber window from the
common idempotent path and made a *post*-`PATCH` concurrent edit recoverable.

What #379 could not remove is the gap between the read at `worker-pr.py:2339` and the `PATCH` at
`:2345`. An edit landing inside that gap is overwritten, and the read-back verify at `:2347`
compares against what *we* sent — so it observes only writes that land *after* our `PATCH` and
cannot see the loss. The bind then reports success. `set_reviewed_sha`'s own docstring
(`:2326-2331`) says this plainly and self-test case 5 pins it as an expected outcome.

This is not a bug in the retry loop. The GitHub REST pull-update endpoint takes no `If-Match`, no
`If-Unmodified-Since`, and no body-sha precondition; a whole-document write with no precondition
has an irreducible read→write TOCTOU. **No rework confined to `set_reviewed_sha` can close it.**
Review round 2 on #379 was correct to re-flag it, and #389 is the correct disposition: change the
store, not the loop.

**Severity, stated honestly, because it sets the budget for the fix.** The lost write is a
maintainer's concurrent *prose* edit to a PR body. The reviewed-sha marker itself is always written
correctly — the racing writer is editing prose, and the marker we splice is the value we intended.
No trust gate reads a wrong value and no gate is bypassed. So this is a **data-loss** defect in a
sub-second window, not a **trust** defect. That matters in §5: a migration that closes a prose-loss
race but opens a *disarm* race would be a net loss, and the disarm latch is the single most
destructive write in the pipeline (`worker-pr.py:3140`).

## 2. The store is read in nine places, and only one of them is on a hot path

#389's blast-radius list is close but not exact. Re-derived from the tree at `6b83c2d3e`:

| # | Site | What it decides | Transport of the body |
|---|---|---|---|
| R1 | `worker-pr.py:2363` `get_reviewed_sha` | emits the `reviewed_sha` job output | per-PR `GET /pulls/{n}` |
| R2 | `worker-pr.py:4648` (in `disarm`) | whether merge-only carry-forward applies | per-PR, already fetched |
| R3 | `worker-pr.py:3443` | fix-lane defer: retract a disproved assertion? | per-PR `GET /pulls/{n}` |
| R4 | `worker-pr.py:3609` | stranded recovery: retract? | per-PR `GET /pulls/{n}` |
| R5 | `dispatch-claim.py:1445` `armed_sha_mismatch` | **the #42 disarm safety latch** | **bulk listing row** |
| R6 | `dispatch-claim.py:3782` | `reviewed_match` → which state the enumerator emits | bulk listing row |
| R7 | `dispatch-claim.py:6864` | `stranded_live` re-derivation on live data | per-PR, already fetched |
| R8 | `dispatch-claim.py:7082` | "head already reviewed" → defer, don't burn a lease | per-PR, already fetched |
| R9 | `dispatch-claim.py:7302` | post-recovery postcondition re-check | per-PR `GET /pulls/{n}` |
| R10 | `dispatch-claim.py:7548` `_disarm_row_admissible` | re-binds a hostile plan row to live data | bulk listing row |

Two corrections to #389's framing, both load-bearing:

**`scripts/plan-snapshot.py` does not read the marker.** Its only occurrences (`:1582-1604`) are
self-test *fixtures* that construct bodies to exercise `dispatch-claim`'s predicate. The production
snapshot record (`plan-snapshot.py:941-960`) carries `head_sha`, `mergeable`, `draft`, `check_runs`
and conditionally `auto_merge` — never the body, never the marker. An implementer who trusts #389's
bullet will look for a reader that does not exist. What *is* true is that plan-snapshot is the
natural place to *add* a transport, which §5 uses.

**`scripts/worker-live.sh` is not a reader either.** It seeds the literal `none` marker into a
fresh draft body (`:2314`) and emits the reviewed head as a job output (`:2772`). Both are writer
concerns.

So the real shape is: **R5/R6/R10 are the constraint, and R5 is the hard one.** The other seven
sites sit inside per-PR branches that already issue per-PR API calls; adding one more read there
costs one round trip on a path that is already paying several.

## 3. Why R5 dominates the design

`armed_sha_mismatch` (`dispatch-claim.py:1405`) is documented as **PURE and TOTAL**: it takes a
`pull` dict, performs no I/O, and returns `None` on every malformed input rather than raising,
"because it runs inside the PLAN walk, where an exception aborts the whole tick instead of skipping
one PR" (`:1423-1424`). It is also *shared* on purpose — the write-authorised disarm enumerator and
the detection-only orchestrator census both call it, precisely so "what the lane disarms" and "what
the census calls a violation" cannot diverge (`:1416-1421`).

Its input comes from `dispatch-claim.py:8061`: a single `gh api --paginate
repos/{repo}/pulls?state=open&per_page=100`. **The body arrives free**, batched 100 PRs to a
request. That is the property any replacement store must not destroy, and it is the property both
of #389's proposed options quietly destroy.

The cost ceiling is real and already binding. `plan-snapshot.py:55-61` records the instrumented
measurement: the PLAN step is ~98% of a 771 s/829 s job against a **600 s cron period**, and it is
API-round-trip bound — 613 requests, median 0.843 s, of which check-runs are 474 req / 564.6 s.
The tick is already over its period. A migration that adds a per-PR request to the PLAN walk is
spending from an account that is overdrawn.

## 4. The two options as #389 states them

### 4.1 Option (a) — a commit status on the reviewed SHA. **Refused as stated.**

Attractive on the write side: `POST /repos/{repo}/statuses/{sha}` is append-only, commit-specific,
and involves no read-modify-write of shared state, so the TOCTOU disappears completely. Four
things sink it in this repo:

1. **Read cost lands on R5.** Statuses are per-SHA. There is no bulk "statuses for these 100 PRs"
   endpoint, so R5 needs one `GET /commits/{sha}/status` per open PR — the exact per-PR request the
   §3 budget cannot absorb. Riding it on the snapshot instead (a new per-SHA leg in
   `plan-snapshot.py`) is the same requests in a different job: ~+100 s on a 684.9 s step.
2. **A new write scope on the targets.** The repo writes no statuses today — there is no
   `statuses: write` in any workflow and no `/statuses/` POST anywhere in `scripts/`. Targets are
   `sparq-org/sparq` and `jeswr/agent-account-registry` (`dispatch.yml:54`) under **two distinct
   owners**, so this means granting a new mutating scope on target repos through the per-owner
   token path. Growing the trust plane's write surface to fix a prose-loss race is the wrong
   trade.
3. **A status is not immutable.** Statuses are append-only *per context*, and the latest write on a
   context wins. Anything holding `statuses: write` on the target can rebind. That is a weaker
   integrity property than the body marker has today, where the writer is gated by App identity.
4. **It collides with the gate.** `master`'s required `gate` status check is load-bearing
   (`worker-pr.py:2682`) and `dispatch-claim` grades check-run conclusions into an arm decision.
   Adding a bot-written status to the same commit's status surface puts a new entry into a space
   the merge gate and `repair_gate_conclusion` both read. Provably separable via `context`, but it
   is new coupling on the most destructive decision in the pipeline.

### 4.2 Option (b) — a ledger file via `_registry_*`. **Right store, wrong primitive.**

The data-plane machinery is real and proven: `_probe_registry_file` (`worker-pr.py:2507`) reads at
a pinned `ref`, `_registry_put_file` (`:2678`) writes with the read-sha as a precondition, retries
genuine CAS conflicts under `_REGISTRY_CAS_DEADLINE_S` with full-jitter backoff, splits permanent
conflicts (`RegistryRecordConflictError`) from unlanded writes (`RegistryWriteExhaustedError`), and
pins both probe and write to the unprotected `ledger` branch because `master`'s required `gate`
check rejects every direct contents-API PUT (issue #96). The sha-precondition PUT is a **true CAS**
— it is exactly the primitive the PR-body endpoint lacks.

**But `_registry_put_file` is create-or-keep, not compare-and-swap-update.** Its contract
(`:2680-2686`) is that an existing *different* record raises — "provenance must never be silently
rewritten". The reviewed-sha binding is not write-once: it is rebound on carry-forward
(`worker-pr.py:4679`) and **retracted to `none` in three places** — fix-lane defer (`:3451`),
stranded recovery (`:3631`), and the arm-readmit path (`:6173`). Pointing a mutable binding at a
write-once primitive would make the second bind on any PR raise a permanent conflict. So option (b)
as written does not compose with the machinery it names.

Two repairs are possible, and choosing between them is this record's actual decision:

- **(b-mut)** add a true CAS-*update* sibling that shares the probe/backoff/classification loop but,
  on divergence, re-derives and retries instead of raising. Sound, and genuinely closes the TOCTOU.
  Cost: the record is one mutable file per PR, so R5 needs one content read per open PR — the same
  per-PR budget problem as option (a), and a new mutating primitive next to a deliberately
  write-once one, which is a footgun for the next author.
- **(b′)** keep the store write-once and let the *set of filenames*, ordered by an explicit
  generation fence, carry the value. Recommended below.

## 5. Recommendation — (b′): write-once, generation-fenced, one listing per repo

**Layout.** `orchestration/reviewed-sha/{owner}/{repo}/{pr}-{gen}-{value}.json` on `ledger`, where
`{value}` is either the 40-hex reviewed head or the literal `none`, and `{gen}` is a zero-padded
monotonic generation counter. The JSON body carries the audit detail (round, run id, verdict record
back-link); **the binding itself is entirely in the filename.** Records for a PR are selected by
the exact `{pr}-` prefix — `1-` never matches `12-`, since `{pr}` is unpadded and `-` is the
separator.

Two properties do the work, and the second is the one an earlier draft of this record was missing:

- every record is genuinely write-once, so `_registry_put_file`'s create-or-keep contract is
  exactly right and a replayed bind is idempotent for free;
- **retraction is a `none` record, never a deletion**, and **no delete may ever remove the winning
  record at the maximum generation**. Absence therefore means *never bound*, and cannot be produced
  by an interrupted or racing transition.

**Per-path CAS is not a CAS on the PR binding — the generation fence is.** A plain
`{pr}-{sha}.json` create-then-delete-the-others protocol removes contention from the very object
that has to be serialized: two writers rebinding PR N to H1 and H2 write *different* paths, so both
creates succeed, and each per-file sha precondition guards only its own delete — never the PR-level
transition. The reachable interleavings include both writers deleting each other's record (zero
records left, read as an intentional retraction: a lost update driving the disarm latch) and the
older intent deleting the newer binding. A per-object CAS composes into a transaction only when the
writers contend on ONE object; these do not. What linearizes the binding is the generation ordering
plus the never-delete-the-winner invariant below, not the contents-API precondition on its own.

**Write** — bind PR N to value V (a 40-hex head, or `none` to retract):

1. Re-list the directory — never write from the tick's cached map — and let
   `g = max(gen over records of N) + 1`, or `0` if there are none.
2. `_registry_put_file` at `{N}-{g}-{V}.json`, unchanged and unmodified. The path is unique to the
   triple, so a rerun of the same intent is a byte-identical keep.
3. Re-list. Exactly one record at gen `g` ⇒ landed. Two or more ⇒ a concurrent bind at the same
   generation: **the lexicographically smallest filename at the maximum generation wins**, a rule
   every observer computes identically from the listing alone. A loser deletes ONLY ITS OWN record,
   and only while it can see the winner in that same listing.
4. If we lost and our intent is still live, re-derive it from live state and retry from (1) at a
   fresh generation — the "re-read and re-derive the expected SHA every time" discipline
   `select-and-claim.py` already uses, under `scripts/ledger_retry.py`'s classifier and wait
   schedule. Never a hand-rolled sleep loop; never `run_gh` around any of these writes.
5. GC, which is never load-bearing: a writer that can see a record for N at a higher generation in
   the same listing may delete records for N at strictly lower generations, each with its own
   read-sha precondition. A GC delete that fails leaks an inert record — it can never change a
   resolution, because resolution reads only the maximum generation.

**A delete is legal in exactly two cases**: (i) a record at a strictly lower generation than one
observed in the *same* listing; (ii) the deleter's own record at the maximum generation while a
lexicographically smaller sibling is present in that same listing. Every other delete is refused.
That guard belongs in the delete primitive, not in its callers (§7) — it is the invariant, so it
must not be re-implemented per site.

**Read.** ONE `GET /contents/orchestration/reviewed-sha/{owner}/{repo}?ref=ledger` per target repo
per tick returns every filename. R5, R6 and R10 all resolve from that one map, and the per-PR sites
R1-R4 and R7-R9 resolve from it too rather than paying their own read. **The §3 budget survives**:
this is two added requests per tick against a measured 613, i.e. ~0.3% — versus the one-request-
per-open-PR that options (a) and (b-mut) both require. It is not a saving; the PR body still
arrives with the listing whether or not it carries a marker. The claim is only that this is the
one layout that does not make an already-overdrawn budget worse.

**Resolution rule, and it must be four-valued.**

| records with the exact `{N}-` prefix | resolves to | why |
|---|---|---|
| none | `unbound` | never bound; NOT reachable as a race artifact, by the invariant above |
| one at max gen, 40-hex value | bound to that sha | the current binding |
| one at max gen, value `none` | retracted | the explicit tombstone |
| two or more tied at max gen | **UNKNOWN — never acts** | a same-generation bind race, not yet collapsed |

Readers may collapse `unbound` and retracted into today's single "no reviewed sha" decision — it is
the same outcome at all of R1-R10. The distinction exists for the *resolver*, not the readers: a
tombstone is what stops an interrupted or racing transition from being indistinguishable from an
intentional retraction. Absence must never be classified as `none` in a store where absence is also
reachable by losing a write; here it is not reachable that way, and that is the whole reason
retraction cannot be a delete.

UNKNOWN is not a new concept here: `armed_sha_mismatch:1441-1442` already returns `None` for a
stale/unknown snapshot with the comment "unknown never acts", and `plan-snapshot.py:954-957`
already carries the same ABSENCE≠NULL discipline for the arm bit.

**Interleaving analysis.** Every reachable state must select the intended latest binding under the
defined order, or be UNKNOWN and recoverable. The cases:

| interleaving | reachable state | resolves |
|---|---|---|
| bind/bind, W2 lists after W1's create | records at `g` and `g+1` | max gen = W2, the later intent. W1's record is inert and GC-able |
| bind/bind, both list before either creates | two records tied at `g` | UNKNOWN for the tick; each writer sees the tie on re-list, the lexicographic loser deletes its OWN record, resolution collapses to the winner |
| bind/retract | identical to bind/bind — a retraction is a `none` record, so neither writer ever deletes the peer's record | max gen, or a tie resolved as above |
| GC delete fails, or writer dies after step 5 | leaked lower-gen records | no effect: resolution reads only the max generation |
| writer dies between step 2 and its losing delete | a tie at max gen that no live writer will collapse | **UNKNOWN indefinitely** — see below |

The same-generation tie-break may award the binding to the *earlier* intent. That is acceptable
precisely because the loser does not simply resend: it re-derives from live state and rebinds at
`g+1`, so the terminal state is still the intent that was live last.

**The one unrecoverable-without-help state, stated plainly.** An earlier draft claimed the
multi-record window "is bounded by one tick and resolves without intervention". That is false: it
holds only while a writer survives to run step 3. A writer that dies between its create and its
losing delete leaves a tie at the maximum generation that nothing collapses. So **UNKNOWN must be a
swept state**: a groom lane resolves ties whose record set is unchanged across N ticks by applying
the same deterministic tie-break, and alerts. That sweep is a correctness requirement of this
migration, not an optimisation — without it a single dead writer parks one PR's binding in
fail-open-for-disarm forever.

**Be honest about the direction UNKNOWN fails.** For every *admission* reader (R6, R8) it is
fail-closed — no dispatch. For the *disarm* latch (R5, R10) declining to act is **fail-open**, and
`plan-snapshot.py:18-21` says so in as many words: an armed PR whose head advanced past its marker
keeps a stale arm latched. Bounded by a tick when the racing writers are alive; bounded only by the
sweep interval when one is not. That is a real cost, it is the same trade the existing
stale-snapshot carve-out already makes — but it is the one place this migration is not strictly
better than the status quo, and the maintainer should price it explicitly rather than discover it.
The alternative of resolving a tie optimistically (pick the newest-looking record and act) is
worse: disarm redrafts and relabels, so a false positive there is destructive while a false
negative is merely late.

**Directory-listing ceiling.** The contents API returns at most 1,000 entries for a directory. With
one live record per open PR and best-effort GC of superseded generations, steady state is
O(open PRs) — two orders of magnitude clear. But GC is deliberately not load-bearing, so leaked
lower-generation records accumulate at whatever rate deletes fail; the ceiling is a real liability
and the migration owes it a bound: fail closed (treat the whole listing as UNKNOWN and alert) at a
low-water mark well under 1,000, rather than silently truncating. The same groom lane that sweeps
ties is the natural place to re-attempt leaked GC deletes. The Git Trees API is the documented
escape hatch if the layout ever needs it; this record does not propose reaching for it now.

**Permissions.** Writes are `contents: write` on the *registry* repo — the review-fix outcome job
already holds it, and no new scope on any target is needed, which is the decisive advantage over
option (a). Reads are `contents: read` on the registry; the PLAN job holds exactly that
(`dispatch.yml:175-176`). Note the asymmetry this buys: PLAN reads registry-owned data with the
registry token instead of reading attacker-influenceable target PR bodies. That is a small but
genuine reduction in what the disarm latch trusts.

## 6. The migration must be staged, and the marker must not be deleted in stage 1

The binding is read by the disarm latch. A big-bang cutover means one deploy in which the latch's
input is a store nobody has watched under load. Proposed staging:

1. **Dual-write, body-authoritative.** `set_reviewed_sha` also writes the ledger record. Every
   reader still reads the body. Add a divergence *counter/alert*. No reader trusts the new store.
2. **Dual-read, body-authoritative, divergence loud.** Readers resolve both; the body still wins;
   any disagreement is an ops alert. This is what proves the store under real concurrency.
3. **Flip authority** to the ledger; the body marker becomes an inert human-readable mirror.
4. **Stop writing the marker** — and only here does the #158 TOCTOU actually close, because until
   step 4 the body is still being PATCHed. Steps 1-3 close nothing; they buy the evidence.

A single PR that does all four is not reviewable and should be refused.

## 7. What the implementation owes, non-negotiably

- **The self-tests must be non-vacuous, and "silent data loss" must never be a passing outcome.**
  `set_reviewed_sha`'s existing case 5 asserts the loss *as expected*; the migrated writer's
  equivalent case must assert the concurrent edit **survives**, and must fail red if the writer
  regresses to an unconditional overwrite.
- **A test that injects a concurrent write between probe and PUT** and asserts the sha precondition
  rejects it — i.e. that the CAS is real, not decorative. A test that passes against a stubbed
  store with no precondition check is vacuous.
- **A four-valued resolution test per reader**: bound / unbound / retracted / UNKNOWN, asserting
  UNKNOWN never produces a disarm row and never produces a dispatch. Missing/unreadable record ⇒
  DEFER, never grant.
- **The delete primitive does not exist yet, and it carries the invariant.** `worker-pr.py` has
  `_probe_registry_file`/`_registry_put_file` but no registry-contents DELETE — the only `-X DELETE`
  in the file is a label removal (`:1882`). Stage 1 must add one that takes a read-sha precondition
  AND refuses any delete the §5 rule does not permit: never a record at the maximum generation
  unless it is the caller's own and a lexicographically smaller sibling is present in the same
  listing. The guard lives in the primitive so no caller can re-derive it wrongly.
- **Interleaving self-tests, driven against an in-memory store, not a stub that always succeeds**:
  (i) two same-generation binds ⇒ UNKNOWN, and the record set is NEVER empty for a PR that was
  bound — the assertion that would have caught the create-then-delete design; (ii) bind racing a
  retraction ⇒ the tombstone or the bind wins by the stated order, never zero records; (iii) a
  delete that would remove the max-generation winner is REFUSED — this case must go red if the
  guard is deleted; (iv) a failed GC delete leaves resolution unchanged.
- **R5 stays PURE and TOTAL.** The resolution map is passed *in* (like `pr_status` is today); the
  predicate must not acquire I/O. If the map is absent, every PR resolves UNKNOWN.
- **The mirrored regex** at `dispatch-claim.py:349` (kept in sync with `worker-pr.py:352` by
  comment, not by construction) is deleted only in stage 4, together with its source.
- **No token-shaped or PII content** in the ledger record; it is a public repo. Salted account
  hashes only, matching the existing provenance discipline.

## 8. What this record does not decide

It does not decide the JSON schema of the record body, the alert thresholds for step 1's divergence
counter, the generation field's width and its overflow behaviour, the sweep interval for stale
UNKNOWN ties, or whether the same-generation tie-break should stay lexicographic-lowest (chosen
here only because every observer computes it identically from the listing alone) rather than
something intent-aware. It does settle that retraction is a tombstone record and not a delete —
that is a correctness requirement of §5's invariant, not the auditability preference §5 previously
treated it as. It does
not re-open #379 — that PR's narrowing is correct and should stay until stage 4 removes the writer
entirely. It does not claim the PR body is unsafe as a *human-readable* mirror; only that it cannot
be the authority. And it does not propose a schedule: the residual it closes is a rare prose-edit
loss, so this migration is correctness housekeeping, not an incident response.
