# #317: serializing tier-limit persistence against other account-catalog writers

> 🤖 **SPARQ agent** — design record, 2026-09-01. Maintainer-review document.
> **This record changes no behaviour.** No script, workflow, or policy file is touched.
>
> **One line: do not build the lock #317 asks for.** Its named counterparty
> (`set-up-account.yml`) does not write account-issue *bodies* at all (§2.1), so the two writers
> it wants to serialize cannot race on the field in question. The residual window is real but its
> only remaining counterparty is an **out-of-band human edit** — which no lock this repo controls
> can be forced through (§3). And the mechanism #317 proposes — an advisory lock in
> `refs/acct-claims/` — is **actively unsafe** in that namespace, whose load-bearing invariant is
> that nothing in it is ever deleted (§4).
>
> What *is* unprotected is the assumption the above rests on: the repo has **eighteen** production
> `gh issue edit --body` sites (§2.2) and **nothing enforces that `account-usage.py` stays the only
> one aimed at the account catalog** (§5). That is the cheap, real piece of work here, and it is a
> self-test, not a lock. Filed as follow-up.
>
> This record deliberately does **not** re-litigate `research/1051-catalog-clobber-auto-restore.md`
> §6 (move the `limits:` line off the mutable body). #317 and #1051 §6 converge on the same place
> from opposite directions; §6 of this record says why that matters and defers to it.

## 1. The question, and the state of the code it was written against

`persist_limits` (`scripts/account-usage.py:734`) writes one `limits:` line into each account
issue's front matter. `gh issue edit --body` (`:713`) replaces the **whole** body and GitHub's
issue API has no conditional (If-Match / CAS) write, so a foreign edit landing inside the
read→write window is replaced by ours.

**#317's description of the current guard is one revision behind.** It says `_persist_one`
"re-reads each account issue body immediately before the write, merges only the `limits:` line onto
the FRESH body, retries on a detected concurrent change". What is in this checkout is stronger and
differently shaped:

- `_ISSUE_READ_QUERY` (`:647`) reads `body` **and** `userContentEdits(first:1){totalCount}` in one
  GraphQL call. That count is a **version stamp**: per the comment at `:644-646` it counts *body*
  revisions only, and every `gh issue edit --body` adds exactly one.
- `_persist_one` (`:682`) claims success only when the confirm read shows our merged body **and**
  exactly one body edit happened since the fresh read (`:720-723`).
- A foreign edit landing strictly *after* ours (`count2 - count0 == 2` and the live body is theirs)
  clobbered nothing, so the merge is re-applied onto their fresh body, bounded by
  `PERSIST_ATTEMPTS = 3` (`:642`, `:724-727`).
- **Any other count shape fails loudly** (`:728-730`) — it does *not* retry, because a retry would
  re-read our own body, find nothing to change, and launder the loss into a false "refreshed".
  The caller counts the failure, prints `WRITE_FAILURE_WARNING` (`:590-593`) and returns 1
  (`:795-798`).

So the honest characterisation of the residual risk is **not** "a concurrent writer can silently
clobber a catalog edit". It is:

> A concurrent **body** writer landing inside the seconds-wide read→write window still has its
> revision replaced by ours — but the replacement is **detected**, surfaced as a red annotation on
> a `continue-on-error` step (`.github/workflows/dispatch.yml:1935-1940`), and the replaced
> revision remains in the issue's edit history for manual re-application.

That is detection, not prevention. It is a real residual and #317 is right to have filed it. It is
also a materially smaller residual than #317's text implies, and the difference changes what a cure
is worth paying for.

> **Citation drift.** `research/1051-...md` cites `persist_limits` at `:717` and `_persist_one` at
> `:665`; both have shifted (`:734`, `:682`). Every line number in *this* record was read from this
> checkout. Records in `research/` are dated snapshots — re-grep before trusting a line number.

## 2. Premise corrections — three, all checkable in this tree

### 2.1 `set-up-account.yml` does not write account-issue bodies. It cannot lose the race #317 describes.

#317's whole framing is "the two writers can still overlap". Grepping every `gh issue edit` in the
repo, `set-up-account.yml` has exactly two, and both are **label-only**:

- `:1216` — `gh issue edit "$num" -R "$REPO" --remove-label status:pending --add-label status:available`
- `:1490` — the same flip in the `activate` job

Neither passes `--body`. Its only body write against an account issue is `gh issue create --body`
(`:824`), which **creates a new issue**; the slot it creates under is taken atomically by
first-writer-wins `refs/acct-claims/acctNN` creation (`:653-724`) and re-registration is
fail-closed. A created issue cannot be an issue `persist_limits` is mid-write on, and a listing
that grows between `gh issue list` (`scripts/account-usage.py:766`) and the per-issue write simply
means the new account is skipped this tick — no clobber.

Two corollaries worth stating explicitly, because they close the hole from the other side too:

- **Label edits cannot false-positive the guard.** `userContentEdits.totalCount` counts body
  revisions only (`:644-646`), so a `status:pending → status:available` flip landing inside the
  window does not perturb the count shape. If it did, the guard would be *noisy* against a writer
  that loses nothing — a much worse failure than the one #317 worries about.
- **`_persist_one`'s docstring already says this** (`:695-698`): "set-up-account only CREATES
  catalog issues (fail-closed on re-registration) — so this guard covers out-of-band manual edits,
  and its soundness does not depend on that workflow config." The docstring is correct against the
  code; #317 is what disagrees with both.

### 2.2 `account-usage.py:713` is the only `gh issue edit --body` against the account catalog — full census

> **Correction (PR #2120 review round 1).** An earlier draft of this section listed only three
> other `issue edit … --body` sites and called that the complete set. **That was wrong**: this
> checkout has **eighteen** production body-edit call sites across fifteen scripts. The conclusion
> below survives, but it now rests on an enumerated census rather than an under-run grep — and the
> miss is itself the §5 argument, since nothing in the repo would have caught it.

Census method (re-run on this checkout, `scripts/**.py` + `.github/workflows/**.yml`): every line
matching `issue` + `edit` was read, then split into (a) production body writes, (b) label-only
edits, (c) self-test scaffolding and comment prose. **18 production body writes**, of which **one**
is the catalog writer:

| site(s) | how the target issue is selected | target |
|---|---|---|
| **`account-usage.py:713`** | **unlabelled** `gh issue list --state open` (`:766`), then `title == handle` against the usage-snapshot keys (`:788-790`) | **account catalog** |
| `park-stock-alert.py:304` | `issue list --label ALERT_LABEL` (`:280`) | `ops-alert` (`:56`) |
| `ratelimit-alert.py:450` | `issue list --label ALERT_LABEL` (`:419`) | `ops-alert` (`:59`) |
| `plan-alert.py:314` | `issue list --label ALERT_LABEL` (`:272`) | `ops-alert` (`:60`); the only site that also rewrites `--title` |
| `usage-alert.py:393` | `issue list --label ALERT_LABEL` (`:381`) | `ops-alert` (`:49`) |
| `metrics-alert.py:312` | `issue list --label ALERT_LABEL` (`:270`) | `ops-alert` (`:67`) |
| `groom-alert.py:171` | `issue list --label ALERT_LABEL` (`:139`) | `ops-alert` (`:36`) |
| `ledger-identity-watch.py:320` | `issue list --label ALERT_LABEL` (`:288`) | `ops-alert` (`:77`) |
| `dispatch-stall-alert.py:537` | `issue list --label ALERT_LABEL` (`:511`) | `ops-alert` (`:77`) |
| `groom-mint-alert.py:536` | `issue list --label ALERT_LABEL` (`:503`) | `ops-alert` (`:71`) |
| `triage-stock-alert.py:487` | `issue list --label ALERT_LABEL` (`:463`) | `ops-alert` (`:59`) |
| `ci-latency-alert.py:1160` | `issue list --label ALERT_LABEL` (`:1135`) | `ops-alert` (`:103`) |
| `model-health.py:2759`, `:2778` | `_find_marker_issue` → `issue list --label ALERT_LABEL` (`:2688`, `:2716`) | `ops-alert` (`:520`) |
| `metrics.py:1088`, `:1093` | `_find_marker_issue` → `issue list --label ALERT_LABEL` (`:1049`) | `throughput-alert` (`:98`) |
| `pat-validity.py:614`, `:786` | `_find_alert` (`:565`) → `issues?labels=ALERT_LABEL`, then **exact-title** match (`:583-585`) | `from:agent` (`:118`) + `ALERT_TITLE`/`PROBE_ALERT_TITLE` (`:117`, `:146`) |

**Not writers**, and why:

- **Label-only edits** (no `--body`): `set-up-account.yml:1216`/`:1490`, `triage-issue.yml:201`,
  `triage.py:1396`, `regate-sweep.py` (argv vocabulary pinned at `:1748-1749`),
  `worker-pr.py:6122`/`:6128` (PRs), and `curate-frontier.py:1231-1236` — the last is the only
  writer that **builds its argv dynamically**, and it appends only `--add-label`/`--remove-label`.
- **Self-test scaffolding**, in two distinct shapes. Stub `gh` *parsers* that branch on the verb —
  `grant-account.py:2118`, `triage.py:3780`, `model-health.py:6348`/`:6502`/`:6713` — are argv
  *consumers* and a scan keyed on `issue edit … --body` will not see them. But
  `usage-alert.py:871` is a genuine `_gh(["issue", "edit", "1", "--body", …])` call inside a
  self-test: it is **textually indistinguishable from a writer** and any census must exclude it
  deliberately. Comment prose also matches (`account-usage.py:645`, `:684`, `:708`, `:1703`), as
  does one label-only argv fixture (`gh_retry.py:1197`).

**What the census proves, and what it does not.** All 17 non-catalog writers reach their target
through a **label-filtered listing** — `ops-alert`, `throughput-alert`, or `from:agent` narrowed
further by exact title. Catalog issues are created with `--label account --label provider:$PROVIDER
--label status:pending` (`set-up-account.yml:824-826`) and carry none of those labels, so no alert
writer enumerates an account issue. That is disjointness by **label convention**, not by an
enforced invariant: nothing stops an `ops-alert` label from being applied to an account issue.

The **reverse** direction is weaker still and is worth stating plainly: `account-usage.py`'s own
listing (`:766`) is **not** label-filtered. It reads every open issue and selects on
`title == handle`. An alert issue whose title happened to equal an account handle would be written
by `persist_limits`. Alert titles are fixed emoji-prefixed sentences (e.g. `pat-validity.py:117`)
and handles are account names, so this is not a live hazard — but it is convention, not a check,
and it is the reason §5's test cannot be phrased as "prove the target sets are disjoint" (see
§5).

### 2.3 The concurrency-group names in #317 are not the ones in the file.

#317 says "the `set-up-account.yml` writer runs in the `set-up-account` concurrency group". There
is no such group. `login:` uses `set-up-account-login` (`:141-143`); `activate:` uses
`set-up-account-activate-${{ github.event.pull_request.number }}` (`:1309-1311`) — which is
**per-PR**, so it does not even serialize `activate` against itself across PRs. Immaterial to the
conclusion (both jobs write labels only), but a design that keyed on those group names would have
keyed on names that do not exist.

## 3. What the residual counterparty actually is

After §2, the set of writers that can replace an account-issue body inside `persist_limits`'
window is:

1. `persist_limits` itself — excluded. `dispatch.yml` is `concurrency: group: registry-dispatcher,
   cancel-in-progress: false` (`:42-44`), and persist is a step inside that job, so ticks are
   serialized against each other.
2. **A human editing the issue in the GitHub web UI or via `gh`.** This is the entire remaining
   set.

That matters because it decides what a lock can buy. **An advisory lock is a protocol, and a
protocol only binds participants.** `set-up-account.yml` says exactly this about its own claim refs
(`:672-674`): "Out-of-band manual writes cannot be forced through this protocol; they are caught by
deriving the slot from the COMPLETE union..." — i.e. the claim ref defeats every *protocol-observing*
writer, and a *separate* detection mechanism handles the rest.

Apply that to #317: the only remaining counterparty is precisely the one a lock cannot bind, and
the detection mechanism for it — the count-shape guard — is already shipped. **A lock added today
would serialize `persist_limits` against nothing.** Its entire value is prospective: it would be in
place if a second automated body writer is ever added. §5 handles that case far more cheaply.

## 4. Why the `acct-claims` namespace is the wrong home for a lock — reject as specified

#317 proposes "a claim-ref / advisory lock in the acct-claims namespace held across the limits
write, mirroring set-up-account.yml's first-writer-wins ref pattern". The mirror does not hold, and
the namespace choice is the problem, not the ref primitive.

**4.1 The namespace's safety argument is that nothing in it is ever deleted.** Stated twice, load-
bearingly, in `set-up-account.yml` (`:38-40` and `:669-672`): "claims are NEVER deleted (a run that
fails after claiming burns its slot rather than releasing it, so a different credential can never
overwrite an in-flight one)". Burning a slot on failure *is the correctness property*. An advisory
lock is by definition acquired and **released** — it is the opposite discipline. Putting a
release-on-success ref in a never-release namespace means the next reader of that namespace has to
distinguish two kinds of ref by name, and every future author has to know which discipline applies
to which prefix.

**4.2 A leaked lock has no reclaimer, and the persist step is exactly the step that leaks.** The
persist step is `continue-on-error: true` (`dispatch.yml:1936`). A cancelled or timed-out job
leaves the lock ref behind with nothing to reclaim it — and per 4.1 the namespace has no expiry or
sweeper concept, because it has never needed one. A stale lock then wedges the lane permanently
(fail-closed) or is ignored (vacuous). Neither is acceptable, and building a TTL/reclaimer is a
much larger change than #317 scopes.

**4.3 The namespace is read by a fail-closed auditor.** `scripts/groom.py:claim_ref_slots`
(`:1873`) enumerates `refs/acct-claims/` (`:2097`) and **raises** on an ambiguous listing — two
refs naming the same slot number — precisely so a short or confusing claim listing can never
under-report burned slots. Its regex is anchored (`ACCT_CLAIM_REF_RE`, `:1811`:
`^refs/acct-claims/acct([0-9]+)$`), as is `set-up-account.yml`'s jq filter (`:686`), so a
differently-named lock ref would be *skipped* rather than mis-parsed today. That is luck, not
design: the invariant "every ref under this prefix is a permanent slot claim" is currently true and
is what makes the allocation record readable at a glance. A lock ref falsifies it, and the next
reader written against the prefix (rather than the anchored regex) inherits a bug.

**4.4 None of this argues against a ref-based lock — only against that prefix.** A git ref update
*is* a compare-and-swap, and it is the right primitive if a lock is ever wanted. A distinct
namespace (`refs/catalog-locks/…`) costs nothing, breaks no invariant, and touches no existing
reader. If §5's guard ever fires — i.e. a second automated body writer is genuinely proposed —
that is the design to start from, together with an explicit answer to 4.2.

## 5. The gap that IS real: the single-writer invariant is asserted, not enforced

Everything above reduces to one claim: **`scripts/account-usage.py:713` is the only automated
writer of account-issue bodies.** That claim is load-bearing for `_persist_one`'s docstring
(`:695-698`), for §2.1, and for the recommendation not to build a lock.

Nothing in the repo checks it. A future PR adding a second `gh issue edit --body` against a catalog
issue — a groom repair, a provenance backfill, a credential-rotation writer — would silently
recreate exactly the race #317 describes, and the only trace of the reasoning that says it must not
would be a docstring paragraph and this record.

This repo already pins invariants of that shape statically, in the self-test of the script that
depends on them:

- `scripts/regate-sweep.py:1748-1783` pins the exact `gh` argv vocabulary the lane may emit, so a
  new call shape goes red.
- `scripts/triage.py:2450` asserts no `gh issue edit … || true` exists in the quarantine path;
  `:2699` and `:3734` pin workflow YAML seams by regex.
- `scripts/dispatch-tick-floor.py` pins a `dispatch.yml` YAML seam to a measured bound
  (`dispatch.yml:1636`).

The analogous assertion here is a **non-vacuous** self-test in `account-usage.py`. §2.2's census
constrains its shape more than the earlier draft of this record assumed, in three ways:

1. **It cannot classify targets statically.** Every writer picks its issue at runtime — the alert
   writers from a label-filtered listing, `account-usage.py` from a title match against a usage
   snapshot. "Is this site a catalog writer?" is not decidable from source text. So the assertion
   must be a **census pin**, not a target proof: enumerate every `issue edit … --body` site and
   require the set to equal a checked-in allow-list. A new writer then cannot land without a human
   adding itself to the list and recording, in that entry, which issues it targets and why they
   are not account issues. The test enforces the *review*, which is the actual missing control.
2. **The allow-list is 17 entries, not 3.** All of §2.2's non-catalog sites must be enumerated, or
   the test cannot pass on the pristine tree — the defect this review round caught.
3. **It must exclude self-test scaffolding without hand-waving.** Per §2.2, a naive scan also
   matches comment prose, a label-only argv fixture, and — the hard one — `usage-alert.py:871`, a
   real body-edit call that exists only to drive a fake `gh`. Keying the allow-list on `file:line`
   makes it churn-prone; keying it on `file` plus an occurrence count is coarse but stable. Either
   is defensible; the choice belongs to the implementer, and it should be stated in the test's
   docstring rather than left implicit.

Non-vacuity is the gate, and §2.2 gives it a concrete two-sided obligation the implementer must
demonstrate: the test **passes on the pristine tree with all 18 sites accounted for**, and **fails
when a nineteenth `gh issue edit --body` is added** — including when it is added to
`account-usage.py` itself. Absent both demonstrations it is decoration. This is the piece of work
#317 should have asked for.

It is a change to `scripts/`, so this doc-only record does not make it. Filed as follow-up.

## 6. The option that outranks both: dissolve the window

`research/1051-catalog-clobber-auto-restore.md` §6 already reached this from the other side, and
its §5 did the measurement that makes it decisive. Restating only what bears on #317:

- The **sole consumer** of the persisted `limits:` line is `scripts/dashboard-gen.py`, and only as
  a **fallback** when the live probe reported no limit (1051 §5). No allocator, dispatcher or gate
  reads it — consistent with `persist_limits`' own docstring (`:740-741`).
- So this lane writes the fleet's **highest-trust body** — the account→credential binding — to
  populate one dashboard statistic's fallback.
- 1051 §6 recommends moving the line off the mutable issue body onto a CAS/immutable store,
  citing the adopted precedent in `research/389-reviewed-sha-binding-store.md` and its landed
  implementation (`eff35a82d`).

If that lands, `_persist_one`, `_issue_view`, `_ISSUE_READ_QUERY`, `PERSIST_ATTEMPTS`, the entire
count-shape guard, **and any lock built for #317** become dead code. #317 is a request to add
machinery to a lane whose existence is under review. 1051 §6 explicitly asked for a sibling record
to open the store question; **#317 is not that record and should not be resolved by pre-empting
it.** A fourth option 1051 §6 also names — delete the persistence lane outright — would likewise
close #317 with no code.

Ordering, stated as a rule rather than a preference: **do not spend a lock on a window you may be
about to delete.** The §5 guard is the exception because it costs one self-test and is correct
under every outcome — it is worth having whether the lane stays, moves, or dies.

## 7. Decision

**WONTFIX the lock as specified in #317**, on §2.1 (the named counterparty does not write bodies),
§3 (the only remaining counterparty is one no protocol can bind), and §4 (the proposed namespace is
the wrong home and its invariant forbids release). The count-shape guard in `_persist_one` stays
exactly as it is; nothing here weakens it.

**Do build the single-writer invariant test** (§5). It is the assumption every argument above rests
on, it is currently unenforced, and it is one non-vacuous self-test in the script that depends on
it. Follow-up.

**Do not close #317 silently.** Its residual — detection, not prevention, against an out-of-band
human editor — is real and unfixed. It should be closed *onto* the store question (§6), which
dissolves it, not onto a lock that would serialize this writer against nothing.

## 8. What is NOT established here

- **No live verification.** This container has no `gh` and no token, and its web tools are
  permission-gated in a non-interactive run. Every finding above is read out of **this checkout**
  and is a statement about the code, not about the running system. In particular: that
  `userContentEdits.totalCount` is incremented by exactly one per `gh issue edit --body` and by
  **zero** for a label edit is asserted in the comment at `:644-646` and is load-bearing for §2.1's
  "label edits cannot false-positive the guard" — this record did **not** confirm it against the
  GitHub API. If it is false in either direction the guard is either noisy or blind, and that
  matters far more than #317 does. It is the same class of unverified premise `research/1051` §3
  flagged for `UserContentEdit`; worth settling in the same pass.
- **No security/trust sign-off.** §4 argues the `acct-claims` namespace is the wrong home for a
  lock. It does **not** assert that the existing claim-ref allocation protocol, the count-shape
  guard, or the `dispatch-secrets` scoping around them are sound — none of that was audited here,
  and #317 did not ask for it.
- **No cost for §6.** Deferred to 1051 §6, which is explicit that it opens a question rather than
  costing a migration.
- **The §5 test is specified, not designed.** Whether it scans source text, an argv vocabulary, or
  a parsed YAML seam — and how it stays non-vacuous under refactors that rename the call site — is
  the implementer's call, and the "prove it fails" step is part of the work, not a formality.
- **Writer/target disjointness is convention, not a proved invariant.** §2.2 shows the 17
  non-catalog writers all select by label and that account issues carry none of those labels, and
  that the catalog writer selects by title from an unlabelled listing. Both directions hold *by
  current naming*; neither is enforced anywhere, and this record did not check the live repo's
  labels. A mislabelled account issue, or an alert titled like a handle, breaks the separation
  without breaking any test — including the one §5 proposes, which pins the writer set rather than
  the target sets.
- **The census is a snapshot of this checkout, and was wrong once already.** The first draft of
  §2.2 named 3 of 18 sites. It was caught in review, not by any check — which is the §5 argument
  restated. Re-run the census before relying on it; do not cite this table as current.
