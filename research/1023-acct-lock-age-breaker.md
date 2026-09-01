# #1023: an age-bounded breaker for a leaked account-record write lock

> 🤖 **SPARQ agent** — design record, 2026-09-01. Maintainer-review document.
> **This record changes no behaviour.** No script, workflow, or policy file is touched.
>
> **The premise does not hold on this tree.** #1023 describes a breaker for the
> `refs/acct-locks/<handle>` write lock "#317 added ... taken and released by
> `account-usage.persist_limits`". That lock **does not exist and never has**: the string
> `acct-locks` matches nothing in the working tree and nothing in 1050 commits of history,
> `persist_limits` takes no lock, and README has no "Account-record write lock" runbook (§2).
> #1023 is a follow-up filed against an implementation that did not land.
>
> **Recommendation, in one line: do not build the breaker — and do not build the lock it breaks.**
> The account-record write is already guarded, fail-closed, by a different and weaker-coupling
> mechanism — which *detects* a clobber and fails loudly rather than preventing one, and the lock
> would not close the gap that leaves (§3). A lock ref is a *mutex*, and the leaked hold #1023 wants a breaker for is a
> failure mode the mutex **introduces**. The direction this repo has already adopted for exactly
> this problem — `research/1051` §6, `research/389`, commit `eff35a82d` — uses a ref update **as
> the compare-and-swap on the data**, which has no hold to leak (§4). If a lock is nevertheless
> built, §5 lists four obstacles a fail-closed breaker must clear, and §6 shows the primitive the
> repo already uses for this (holder liveness, not age).

## 1. The question

#1023 asks whether a leaked `refs/acct-locks/<handle>` ref — left behind when a run is killed
between acquire and release — should be cleared automatically by an age-bounded sweeper in
`groom.yml`, anchoring the lock ref at a commit object *created for the lock* so its committer date
is readable, and staying fail-closed ("an unreadable age is not a stale lock").

Three questions, taken in order: does the subject exist (§2); is the hazard it addresses real on
this tree (§3–4); and if the lock were built, could a breaker be made fail-closed (§5–6).

## 2. Premise corrections — three, all checkable in this checkout

**2.1 There is no `refs/acct-locks/` namespace, and there never was.**
`grep -rn 'acct-locks\|acct_locks' . --exclude-dir=.git` matches nothing outside this record, and
`git log --all -S acct-locks` returns no commit across all 1050 commits. Whatever #317 proposed,
no lock landed and none was reverted — there is no trace to revert.

The two account-related ref namespaces that *do* exist are neither of them locks:
`refs/acct-claims/acctNN` (slot ownership, `scripts/groom.py:1811`) and
`refs/acct-requests/<request>/<handle>/<provider>/<format>/<digest>` (credential binding,
`scripts/groom.py:1839-1842`). Both are **permanent ownership records**, not held-and-released
mutexes — which is why neither has the leak #1023 describes, and why §5.1's no-delete rule applies
to them without contradiction.

**2.2 `persist_limits` takes and releases no lock.** `scripts/account-usage.py:734` reads the
account catalog and calls `_persist_one` (`:682`) per issue. There is no acquire, no release, no
ref write, and no `try/finally` around a held resource anywhere in the file. The concurrency
control is entirely in-band (§3).

**2.3 There is no "Account-record write lock" runbook.** README has no heading matching
`Account|lock`, and the phrase does not occur. README's only "lock" in this area is line 15's
"cross-codebase concurrency **lock**" — that is the ledger **lease** system (`scripts/lease_schema.py`,
`scripts/select-and-claim.py`), a different mechanism at a different layer, and §6 is the one place
it is genuinely relevant.

Consequently the failure #1023 describes as observable today — "every later write for that handle
DEFERS with a `::warning::` and a non-zero step outcome each dispatch tick" — **cannot be occurring**.
No code path emits it. This matters for triage: an operator reading #1023 would go looking for a
stuck ref that does not exist.

## 3. What actually guards the account-record write

`_persist_one` (`scripts/account-usage.py:682`) does a **guarded read-merge-write with a version
stamp**. Its docstring states the constraint precisely: `gh issue edit --body` replaces the whole
body and *"GitHub's issue API has no conditional (If-Match/CAS) write"*. The stamp is the body-edit
count from `userContentEdits.totalCount` (`_issue_view`, `:653`). Success is claimed only when the
confirm read shows our merged body **and** exactly one body edit happened since the fresh read.
The count shapes are decided explicitly:

- `count2 - count0 == 1` → ours was provably the only edit in the window; a body mismatch is an
  inconsistent read → fail closed (`:720-723`).
- `count2 - count0 == 2` and the live body is not ours → the foreign edit landed strictly *after*
  ours, nothing was lost → re-merge onto their fresh body (`:724-727`).
- any other shape → a foreign edit may have landed *inside* the window and been replaced → **fail
  loudly**, without retrying (`:728-730`).

That guarantee is **narrower than "nothing is ever overwritten"**, and the difference matters.
`_persist_one` does not prevent an overwrite: `gh issue edit --body` replaces the whole body, so a
foreign edit that lands inside the read→write window *is* replaced, and the count stamp reads that
only afterwards. What the stamp buys is that the loss is never laundered into success — a suspected
in-window clobber fails **loudly and without retry** (`:728-730`), `persist_limits` returns 1,
`WRITE_FAILURE_WARNING` surfaces it as a red annotation, and the replaced revision stays recoverable
from the issue's edit history. That is **detection, loud failure and recoverability — not
prevention**. The mechanism's other property is structural: it cannot leak, because it holds nothing.

So prevention *is* a gap here, and the honest question is a separate one: would the lock close it?
`_persist_one`'s own scope statement says no. Automated writers **cannot reach the window** —
`dispatch.yml` self-serializes (`registry-dispatcher`, `cancel-in-progress: false`) and
`set-up-account` only creates catalog issues — so the guard exists for **out-of-band manual edits**,
which is also the only writer class that reaches the window at all. A ref mutex is advisory: it
excludes exactly those writers that consult it, and a human editing the issue in the GitHub web UI
never reads `refs/acct-locks/<handle>`. The lock would therefore serialize writers already
serialized by `cancel-in-progress: false` and leave the one writer that can actually clobber
entirely unexcluded. It is not a mutex over the resource; it is a mutex over one of several writers.

The recommendation in §4 therefore rests on the lock failing to supply the missing prevention — not
on the existing guard being complete, which it is not (§8).

## 4. Why the adopted direction removes the lock rather than repairing it

`research/1051-catalog-clobber-auto-restore.md` §6 already ruled on this exact write, and its
reasoning is decisive here:

> The constraint driving every hazard above is that machine-written state shares a mutable,
> human-edited field with high-trust configuration and there is no CAS. **This repo has already
> ruled on that exact class**: `research/389-reviewed-sha-binding-store.md` recommends moving the
> reviewed-sha binding off the mutable PR body onto a per-record store on the `ledger` data-plane
> branch, and commit `eff35a82d` ... landed it. **A git ref update *is* a compare-and-swap**, which
> is the primitive the issue API lacks.

That sentence is the whole argument. #1023 proposes to spend a git ref on a **mutex** — a
hold-and-release protocol layered *over* a non-CAS store. The adopted precedent spends a git ref on
a **CAS** — the ref update *is* the atomic write, so there is no interval during which anything is
held, and therefore no leak, no breaker, no sweeper, and no age to read.

The two designs cost roughly the same ref namespace and the same API surface. One of them has the
failure mode #1023 exists to patch; the other does not have it at all. Building the mutex and then
building an age-bounded breaker to contain the mutex's leak is strictly dominated.

**Honest limit on this section:** #1051 §6 explicitly files itself as *"a recommendation to open the
question, not a costed migration"*, and lists what it did not establish — the data-plane write
path's contention under the account-usage workflow's identity, the dashboard's fail-closed-vs-
degrade posture when the record is absent, and whether the capacity fallback justifies persistence
at all (deleting the lane is a live fourth option). None of that is settled here either. What this
record adds is narrower and does not depend on the migration happening: **the lock is not the
missing piece, so #1023's breaker is not the missing piece's repair.**

## 5. If a lock is built anyway: four obstacles a fail-closed breaker must clear

Stated so the maintainer can steer rather than re-derive. These are obstacles, not refutations —
none is obviously unclearable, and each has a real cost.

### 5.1 Automatic ref deletion is a locked decision against, with a mutation test behind it

`groom.py:1802-1804` states the orphan-claims report is *"DELIBERATELY REPORT-ONLY ... it never
deletes a claim ref and offers no opt-in mode that would, because deletion re-opens the
credential-overwrite race the claim closes."* `ORPHAN_CLAIM_NOTE` (`:1849`) repeats it operator-facing:
*"NEVER delete a claim ref."* And it is enforced, not merely asserted — the YAML-seam self-test at
`groom.py:12199-12202` fails if any of `("git/refs", "--delete", "--prune", "--fail-on", "DELETE")`
appears in the report step. Independently confirmed: **the repo performs no ref deletion anywhere**
(no `DELETE` against `git/refs` in any script, workflow, or shell file).

A lock sweeper would be the first automatic ref deletion in the repo. That is a defensible
distinction — a lock is *meant* to be released, unlike a claim, whose whole value is permanence —
but it must be made **explicitly**, because the existing rule is written as a namespace-independent
prohibition and its test lives in the same sweep the breaker would be added to. Adding deletion
without re-stating the boundary is how the acct-claims guarantee erodes by adjacency.

### 5.2 The age anchor requires machinery the repo does not have

`git/matching-refs` — the only ref listing in use (`groom.py:2097,2105`) — **carries no timestamp**;
`claim_ref_slots` (`:1874`) reads only `ref`. So age cannot come from the listing. #1023 anticipates
this and proposes anchoring the lock at a commit *created for the lock*.

That is new machinery: **nothing in this repo creates a git object via the API** — no
`POST git/blobs`, `git/trees`, or `git/commits` anywhere. The one existing ref creation
(`set-up-account.yml:715-716`) anchors at `$GITHUB_SHA`, an *already-existing* commit, precisely to
avoid needing any. And reading the age costs one extra `GET` per lock, since the listing cannot
supply it — a per-handle fan-out in a sweep whose other listings are already fully paginated.

### 5.3 The committer date is not a trustworthy clock — and this repo has already said so

The only age-from-a-commit precedent is `_live_base_tip` (`scripts/dispatch-claim.py:4810-4837`),
and its docstring is a warning against exactly this use:

> For this repo master moves by GitHub-authored merge commits, whose committer date IS the merge
> instant on GitHub's own clock ... **A DIRECT push would carry the pusher's clock instead, which is
> the unbounded skew the structural test in `gate_freshness` exists to not depend on.**

A commit created by a workflow run to anchor a lock is the *direct push* case, not the
GitHub-merge case. Worse, `POST /repos/{owner}/{repo}/git/commits` accepts a **caller-supplied**
`committer.date`, so the age anchor is written by the same party whose liveness it is supposed to
attest — a buggy or hostile writer can stamp a lock permanently young and make it unbreakable.
(*Unverified here, and worth confirming before relying on either branch:* whether GitHub overrides
or preserves a supplied `committer.date` on this endpoint, and what it stamps when the field is
omitted. This container has no token and no network access to check.)

The repo's own decision on this class of trust is in `gate_freshness`: it was built specifically to
**not depend** on a writer-controlled clock. A breaker that gates ref deletion on one reverses that.

### 5.4 Fail-closed on an unreadable age reinstates the permanent lock

#1023 requires — correctly — that "an unreadable age is not a stale lock". Every age-reading path in
the repo does this: `_lease_epoch` returns `None` for a non-numeric value
(`select-and-claim.py:299-303`), `plan_renewal` refuses to call a lease provable without both
timestamps (`:367`), `groom._epoch` raises on a malformed ISO string (`:517-526`), and
`latch-watchdog.parse_iso` returns `None` → ineligible (`:359-372`).

Applied here, the consequence is worth stating plainly: **a lock whose anchor object is missing,
unreadable, or malformed is never broken.** That is the correct posture, and it means the breaker
does *not* remove the operator-intervention path #1023 wants to eliminate — it narrows it to the
cases where the anchor happens to be readable, while adding a sweeper, a new object-creation path,
and the first automatic ref deletion in the repo. The residual manual runbook must still be written.

## 6. The better primitive, already in the tree: holder liveness, not age

If a hold ever does need breaking, the repo has already solved this problem once, and **not with
age alone**. The lease system correlates the *holder run's liveness* and treats the clock as a
backstop:

- `select-and-claim.plan_renewal` (`:306-388`) probes whether the holder's run is still active. A
  live holder gets its expiry **renewed**, bounded by `RENEWAL_CEILING_SECONDS` (6h) so renewal
  cannot become infinite.
- An **unprovable** holder (probe 403/5xx) is *deferred* on `RENEWAL_GRACE_SECONDS`, not reclaimed —
  failure to prove liveness is not proof of death.
- `groom.classify_lease` (`:571-613`) correlates the holder to a `worker.yml` run and only falls
  through to the policy timeout (`issued_at + threshold_seconds`) when no correlation is available.
- `classify_claim_run` (`:186-202`) returns `"finished"` only on an explicit `status: "completed"`,
  which drops a repair lease **immediately** — no TTL wait at all. Its docstring covers #1023's
  scenario exactly: *"a `completed` run will not do any further work, whether it succeeded, failed
  or was **cancelled**, so its lease is unowned either way"*. Everything else — a non-document, a
  run from another workflow, an unrecognised status — is `unknown` and *"reclaims NOTHING (absence
  and unreadability are not death)"*, which is #1023's own fail-closed requirement, already stated
  and already implemented.

This is a strictly better fit than #1023's design. A cancelled run is *knowable* — its run id can be
embedded in the lock (the lease system embeds the holder), and a `completed` run document is
positive evidence of death, available in seconds rather than after a bounded hold, and not derived
from any writer-controlled clock. Age becomes the backstop for the case where the run cannot be
correlated, exactly as `classify_lease` uses it.

It also raises the prior question: if a hold needs a liveness-correlated TTL, a renewal ceiling, and
a grace window, it is a **lease** — and the repo already has a lease system with all three. A second,
ref-shaped lease mechanism with weaker semantics is a worse outcome than either extending the
existing one or (§4) needing no hold at all.

## 7. Decision

1. **Do not implement #1023 as written.** Its subject does not exist (§2), the lock would not close
   the one gap `_persist_one` leaves open — the out-of-band manual edit no advisory mutex can
   exclude (§3) — and the failure it reports as currently observable is not reachable by any code
   path.
2. **#1023 is blocked on #317, not on this record.** It cannot be built before the lock it breaks.
   It should be re-scoped or closed rather than retried; filed as a follow-up.
3. **Prefer resolving #1051 §6 first.** If the `limits:` line moves to a CAS/immutable data-plane
   record, the ref *is* the atomic write, and #317, #1023, #320 and #198 all cease to exist rather
   than being answered. That decision outranks designing either the lock or its breaker.
4. **If a lock is built regardless**, require of the breaker: an explicit re-statement of the §5.1
   no-delete boundary (with the `groom.py:12199` seam test updated deliberately, not incidentally);
   an age anchor whose clock is not writer-controlled (§5.3); holder-run liveness as the primary
   signal with age as backstop (§6); and a written operator runbook for the §5.4 unreadable-anchor
   residue, which the breaker does not eliminate.

## 8. What this record does not do

- It ships **no behaviour change**. `_persist_one`'s count-shape refusal, the schema write guard,
  `WRITE_FAILURE_WARNING`, and the acct-claims no-delete rule are all untouched.
- It does **not** cost or endorse the #1051 §6 migration, and takes no position between moving the
  store and deleting the lane. That remains #1051's open question.
- **Not verified (no token, no network in this container):** §5.3's two GitHub API questions —
  whether `POST git/commits` preserves a caller-supplied `committer.date`, and what it stamps when
  omitted. §5.3's argument holds either way (a preserved date is writer-controlled; an omitted one
  still leaves §5.1, §5.2 and §5.4 intact), but the "unbreakable young lock" hazard specifically
  depends on the first answer.
- It does **not** assert that the account-record write is fully safe. `_persist_one` detects a
  clobber *after* it happens and depends on an operator reading a warning; §3 describes the guard
  that exists, not an audited guarantee. The out-of-band manual edit remains genuinely unexcluded
  by any mechanism, lock or otherwise — which is the strongest argument for §4.
