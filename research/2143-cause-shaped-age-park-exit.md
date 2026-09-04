# #2143: a cause-shaped exit for the standing machine age-park population

> 🤖 **SPARQ agent** — design record, 2026-09-03. Maintainer-review document.
> **This record changes no behaviour.** It answers the two design questions #2143 raised off the
> #1664 per-cause census, says which of the two candidate observations is worth designing, and
> states what an implementation would be obliged to carry — so that neither becomes a machine
> writing the human-owned terminal on an argument nobody wrote down.
>
> **Answer, in one line: candidate 2 (`merge-*`, "the park receipt's `head` is unreachable on the
> remote") is REJECTED (§4); candidate 1 (`orphan-draft`, "the provenance record is provably
> UNMINTABLE") has a sound cause-shaped definition, but it is NOT groom's to evaluate and is not
> buildable today (§5).** The verdict it needs is already computed, per PR and per named reason,
> by `scripts/backfill-provenance.py` — which writes it to a run log and nowhere else. The one
> prerequisite is a durable receipt for that verdict; §8 sequences it.
>
> ⚠️ **Two corrections to #2143's framing are published here.** Its `orphan-draft` premise —
> "provably unmintable, as distinct from merely absent" — reads as though *present-but-inadmissible*
> were the permanent case. It is not: **#776 shipped a machine repair for exactly that class**
> (§5.1), so the state the issue points at has an exit. And "decidable **offline**" is not
> achievable for any predicate about a remote ledger; §6 states the achievable form the constraint
> was actually asking for, which this record holds itself to.
>
> ⚠️ **Nothing about the LIVE population is measured here.** This container has no network, no
> `gh` and no token, so #2143's instruction to *"read the census off real groom ticks"* could not
> be followed. Everything below is derived from the code in this checkout, plus **one** offline
> measurement over files that are in it (§5.1). §9 says what a token would settle and how.

## 1. The question, and why it is two questions

`_execute_age_unpark_actions` (`scripts/groom.py:2863`) is the machine exit for a `review:parked`
age park. It refuses on the park's own cause — never on elapsed time — and since #873/#1664 it
counts and **names** every park it refuses:

```
CENSUS machine age parks standing (declined this tick on their own cause — the population no
amount of elapsed time moves, which any cause-shaped exit must be sized against): 3
 | merge-dirty=2 [owner/repo#34, owner/repo#41] | orphan-draft=1 [owner/repo#77]
```

(`scripts/groom.py:3321-3337`.) That population is by construction the one a clock cannot drain.
#873 and #1664 each named one candidate observation that *could* drain it, and #2143 asks which is
worth designing. They are genuinely separate questions with separate answers, because the
observations are about different objects: one is about a **registry record**, the other about a
**git object**.

## 2. What the census can and cannot rank, and what this record could not read

The census is the right instrument and it is already shipped. It emits unconditionally including a
zero row, it names each PR, and it partitions by cause — so a maintainer with a token can rank the
two candidates in one tick by reading one line. This container cannot: `bash scripts/groom.py` is
not runnable here (no token, no network), and grep found no captured groom output anywhere in the
tree. **So this record does not claim a count for either cause.** It answers the two design
questions on their merits, which is possible without the count — and §9 states the count that
would change the answer, so the record is falsifiable rather than merely unmeasured.

## 3. The population, derived from the code

`aged_orphan_worker_pr` (`scripts/groom.py:1101`) fixes it exactly: an **open, bot-authored worker
PR** on a `sparq-agent/issue-<n>-…` head branch, past the maintenance threshold, with **no
admissible registry provenance record**. `stale_worker_pr_reason` (`:1164`) then splits it — a
draft parks on `orphan-draft`; a non-draft parks only when it is *also* wedged in one of the five
`BAD_MERGE_STATES` (`:131`). So `AGE_PARK_CAUSES` (`:174`) holds exactly six tokens, and every park
in the standing census carries one of them or a token from an older vocabulary.

### 3.1 The `NO-PREDICATE` partition is empty for every cause the tree can mint today

Worth stating because #2143 describes the flagged subset as the provably-permanent one, which reads
as though it were where the population lives. It is not, and cannot be:

* `age_park_label` (`:224`) writes the **human** class outright for an unmapped cause, so an
  undecidable cause never becomes a machine park in the first place;
* `age_park_exit_reachable` (`:2786`) derives from `age_park_predicate_kind` (`:2762`), which
  decides `orphan-draft` and every `merge-*`;
* and a self-test quantifies over the whole table — *"EVERY cause the hand-off can MINT is
  decidable by the exit phase"* — asserting the empty list, with its own modelled mutant beside it
  (`scripts/groom.py:11917-11932`).

A `NO-PREDICATE` row is therefore reachable only from a **durable receipt minted under an older
vocabulary**, or a malformed one — `_AGE_RECEIPT`'s `cause=[a-z-]{1,40}` (`:213`) will read a
truncated `merge` that `age_park_predicate_kind` refuses. That is exactly why the gauge is asked of
the token *off the receipt* rather than of the table. **The consequence for #2143: the standing
population is essentially all `orphan-draft` + `merge-*`, i.e. all of it is one of the two
candidates, and neither is the flagged subset.**

## 4. Candidate 2 — `merge-*`, "the park receipt's `head` is unreachable on the remote": REJECTED

Rejected on three independent grounds. Any one of them is disqualifying.

**4.1 The receipt `head` is a dedupe KEY, not a live reference — and re-purposing it as evidence
about the world is the #958 shape.** The comment that declares it says so: *"`cause` is an
`AGE_PARK_CAUSES` value, `head` the head SHA **at park time**… The (cause, head, gen) triple is the
CONSUME-ONCE key"* (`scripts/groom.py:186-190`). Every consumer in the tree uses it that way and
only that way — `age_unpark_state` (`:328`) matches the triple, `unpark_stall_pending` (`:372`)
dedupes on it, `age_park_generation`'s clamp comment (`:313`) calls it a fingerprint. An
observation built on it would be the *only* reader treating it as a pointer to a live object.

**4.2 It fires on the repair, not on the failure — so its only fail-closed reading is the
false-positive direction.** A park-time head becomes unreachable when the branch is **force-pushed**,
and a force-push is precisely the repair for `merge-dirty`/`merge-behind`. Worse, the receipt
tracks the live head *with a lag*: the hand-off re-parks a still-stale PR at the current
`head_sha`, minting a new receipt whose fingerprint the dedupe has never seen
(`scripts/groom.py:4776-4817`), and a push bumps `updated_at`, so the sweep only catches up one
staleness threshold later. The window in which "receipt head ≠ live head" holds is therefore
**bounded by the staleness threshold measured from the last push** — which makes the observation a
restatement of the clock, and #769's "age is not its own recovery proof" is the guard it would
route around. Meanwhile the fail-closed rule #2143 correctly demands (an unavailable read must
never escalate) means the check can *only* ever act on a positive "absent" answer, i.e. only in the
direction that is wrong.

There is a zero-cost version of the same observation — the sweep already reads the pull object, so
`pull.head.sha` is in hand and no probe is needed. It does not rescue the candidate; it sharpens
the objection. What that comparison detects is *"the branch moved since the park"*, which is
progress.

**4.3 The read budget, answered even though the answer does not matter.** #2143 asks for it, so:
one `GET /repos/{repo}/commits/{sha}` per standing `merge-*` park per tick. groom-sweep runs
`7-59/15 * * * *` (`.github/workflows/groom-sweep.yml:12`) — 96 ticks/day — across two enabled
targets (`policy/repos.toml:88,183`). groom has **no HTTP cache and makes no conditional requests**
(no `--http-cache`, no `If-None-Match` in `scripts/groom.py`; research/1122 records that #1088 had
not landed and it still has not). So the cost is `96 × N` uncached reads per day for a population
that by definition never drains, and it is spent on the PRs that are *most* likely to be repaired
soon. Capping it the way `MAX_TERMINAL_REAPS_PER_TICK` caps a reap (`:130`) is not available
either: a cap on a **terminal** makes which PR gets escalated depend on tick timing, which is a
different disposition for the same evidence.

**And the fail-closed reading #2143 asks for, stated for the record:** an unavailable or ambiguous
ref read must mean *stay parked* — never *escalate* — for the same reason
`age_park_cause_recovered` falls through on `indeterminate` (`:2845-2846`). Combined with 4.2 that
leaves the check able to act only where it is wrong, which is the definition of a mechanism with no
sound configuration.

## 5. Candidate 1 — `orphan-draft`, "the provenance record is provably UNMINTABLE"

The shape is right. The definition #2143 gestures at is wrong, and the predicate does not belong in
groom.

### 5.1 What "unmintable" cannot mean — *present-but-inadmissible*, refuted by measurement

The obvious reading of *"provably unmintable, as distinct from merely absent"* is: a record
**exists** on the ledger and is refused by `is_enumerable_provenance`. It is attractive because it
costs nothing — `_live_provenance_record` (`scripts/groom.py:879`) already computes it and then
**discards the distinction**, collapsing "clean 404 on the verified tip" and "cleanly read but not
admissible" into one `denies` (`:942`, `:959`). And every minting writer is create-only:
`mint-provenance.existing_record_verdict` — *"records are create-only… This script never rewrites a
record"* (`scripts/mint-provenance.py:419-454`).

**It is still wrong, and the tree contains the refutation.** The one offline measurement this
record makes: running `dispatch-claim.provenance_admission_error` over the 33 record files in
`orchestration/provenance/` on this checkout gives **26 admissible, 7 inadmissible**, all seven for
the same reason — `provenance attestation stamp is missing or malformed`, from an attempt-less
`backfill:<run>` stamp that the `PROVENANCE_ATTESTATION_STAMPS` table closed by #657/#732
(`scripts/dispatch-claim.py:3268`) no longer recognises. That is the mechanism by which the class
arises — a **later schema tightening**, the #739 forward-compatibility concern realised — and it is
real rather than hypothetical.

And it has a machine exit. **#776 shipped it**: `record_disposition`
(`scripts/backfill-provenance.py:575`) names `RECORD_INADMISSIBLE` apart from `RECORD_ABSENT`
precisely *"because its machine action DIFFERS"*, and the walk falls through to `REPAIR #<n>`,
re-deriving identity from the run log and writing with `supersede_legacy=True`
(`:907-909`, `:987`). Its docstring cites the same seven records and names two of them
(`sparq#2439`/`#2456`) as open worker PRs stuck in exactly this state, calling it *"a state whose
only exit is a human is a state with no exit"*.

**So present-but-inadmissible is not a permanence proof.** An escalation built on it would write
the human terminal on a population a scheduled sweep repairs — and it could not have been red-tested
against the live estate either, because the only instances of the class recorded anywhere in this
repo are the seven that #776's repair path now covers. This is the correction the header flags, and
it is the whole reason the issue asked for a record before the code.

### 5.2 What it does mean — and it is already computed, by name, somewhere else

The `orphan-draft` population *is* `backfill-provenance.py`'s population (a `[bot]`-suffixed
author, a worker head branch, a non-fork head — `scripts/backfill-provenance.py:829-866`), and
that script runs unattended on `cron: '23 */4 * * *'` with `apply` on the schedule
(`.github/workflows/backfill-provenance.yml:22-24`, enabled by #1544 because *"the population only
drained when somebody remembered"*). Every tick it answers, per PR, exactly the question #2143
wants: *can this PR's provenance record be minted?* — and it splits the refusals into named codes
*"because the responses are"* different (`:78-110`):

| bucket / code | permanent? | is it a fact about THIS PR? |
|---|---|---|
| `log-unavailable` | **no** — retention or a missing `actions: read`; its own guidance says *"NOT evidence of tampering"* | no |
| `incomplete-anchored-evidence` | no — *"worker.yml changed shape and this parser has not been taught the new one"* | no |
| registry-probe `NEEDS-HUMAN` (`:886`), `WRITE-FAILED` (`:1017`) | no — transient registry/write failure | no |
| `no-anchored-source`, `sources-disagree`, `pr-binding-mismatch`, `bot-author-mismatch` | **yes** for a fixed log | **yes** |
| divergent existing record (`:1010`) — *"a PERMANENT conflict that no retry can clear"* | **yes** | **yes** |
| `BLOCKED`: no commits / malformed first-commit sha (`:955`, `:961`) | yes | yes |
| `BLOCKED`: the candidate record is itself inadmissible (`:977`) | yes | **no** — a writer/schema defect |

**The definition, then:** *a park is escalable iff the minting sweep's latest verdict for its PR is
a refusal that is (a) permanent for a fixed run log and (b) a fact about this pull request that
only a human can change.* Concretely: `no-anchored-source`, `sources-disagree`,
`pr-binding-mismatch`, `bot-author-mismatch`, the divergent-record conflict, and the two
commit-shape `BLOCKED` exits — named rather than pointed at by table position, because a row
reference survives an edit that changes what it refers to. Everything else stays parked.

That rule is not
invented here — it is `auto-mint-provenance.py`'s `SILENT_REASONS` split, which withholds a
PR-visible refusal for *"facts about the REGISTRY or the platform… not about the pull request"*
(`scripts/auto-mint-provenance.py:370-378`) — and reusing it is the point. It is cause-shaped
(a property of the evidence, not of elapsed time), it fails closed in the direction #2143 requires
(an unreadable ledger, an unreadable log and a failed write are all **not** unmintable), and the
human terminal is the *honest* target because the refusal text already says so in the operator's
own words: *"a human must establish the implementer identity"*.

### 5.3 Why groom cannot evaluate it, and what is missing

Two facts settle where this belongs.

1. **The evidence is a GitHub Actions run LOG, and the parser over it is a trust surface.**
   `backfill-provenance.py`'s module docstring makes the run log the *only* accepted identity
   source and refuses a commit-trailer fallback outright, because trailers on this population are
   model-forgeable. **Note what this objection is NOT**: groom already holds `actions: read`
   (`.github/workflows/groom-sweep.yml:30`) and already reads run metadata
   (`/repos/…/actions/runs/{id}`, `scripts/groom.py:3552`), so no permission widening is at stake
   and it would be wrong to argue one. The objection is that a *log download per standing park per
   tick* is §4.3's budget an order of magnitude worse, and that consuming it would require a second
   copy of `run_identity_from_log`'s job-prefix-anchored derivation
   (`scripts/backfill-provenance.py:303`) inside groom — a duplicated **trust** parser, which is
   the #958 shape on the one surface that decides which model implemented a PR.
2. **The verdict is not durable.** Unlike `auto-mint-provenance.py`, which posts a marker-deduped
   refusal comment and — since #1603 — censuses `refused_standing` off an annotation *it* wrote,
   `backfill-provenance.py` prints `NEEDS-HUMAN #<n> [<code>]` **to its run log and nowhere else**
   — checked rather than assumed: the file contains no PR-comment write of any kind. Its only
   target-side write is the draft conversion. There is nothing on the PR for groom to read.

So the missing piece is small, named, and in one file: **backfill must publish its permanent
refusals durably** (bot-authored, one comment per PR per code, the #1603 shape). Only then does
groom's exit phase have an author-filtered, offline-parsable fact to escalate on — at which point
its own predicate is pure, costs zero extra reads, and never consults a clock.

The author filter is load-bearing and must be stated with the mechanism, not after it: the marker
would be public on a public repo, so the reader must require the writer login exactly, as
`auto-mint-provenance.py`'s `ANNOTATOR_LOGIN` does (`:444-458`, matched by exact login and never by
a `[bot]` suffix). A measurement its own subject can forge is not one — AGENTS.md pre-flight item 5.

### 5.4 The genuinely offline-decidable residue, and why an escalation must not be built on it

Two sub-classes *are* decidable from the pull object groom already holds, and both are permanent:

* **A worker head branch backfill cannot parse.** groom's `WORKER_BRANCH` is a **prefix** match
  (`^sparq-agent/issue-(?P<issue>[1-9][0-9]*)-`, `scripts/groom.py:125`); backfill's `HEAD_RE` is a
  **full** match requiring `-<run>-<attempt>` (`scripts/backfill-provenance.py:54`).
* **A fork head.** `aged_orphan_worker_pr` does not test the head repo; backfill's fork gate is
  hoisted first and absolute — *"fork heads never get provenance"* (`:841-842`).

A PR in either sub-class is age-parked by groom on `orphan-draft` and is structurally invisible to
the only writer that could mint the record its exit waits for. That is #873's "park whose exit does
not exist" reached through a cause `age_park_exit_reachable` reports as **reachable** — a hole the
gauge cannot see, and it is filed as follow-up work rather than fixed here.

But an escalation must not be *built* on these two, and the reason is AGENTS.md item 8 rather than
squeamishness: worker branches are machine-generated by `worker-live.sh` and worker PRs are opened
from the target repo, so both sub-classes are plausibly **empty on the live estate**. A terminal
whose only trigger never fires is a fail-open surface wearing a guard's name, and its self-test
would necessarily be a fixture asserting against a population that does not exist. Measure them
(§9) before treating either as a mechanism.

## 6. Correcting "decidable offline"

Taken literally the constraint cannot be met: whether a provenance record can be minted is a fact
about a remote ledger and a remote run log, and no predicate over local state decides it. Read as
what it was protecting against — *the decision must not be an artefact of a read that failed* — it
is exactly right, and §5.2's definition meets it in the achievable form:

1. **No new network read** in the escalating sweep. The predicate consumes evidence some other tick
   already produced and made durable.
2. **The decision function is pure** over that evidence: given the receipt bytes, the verdict is
   total, deterministic, and self-testable with no network — the property `age_park_predicate_kind`
   and `age_park_exit_reachable` already have (`scripts/groom.py:2762-2799`).
3. **Every unavailability is a distinct value that is not the escalation.** Absent receipt,
   unreadable ledger, non-permanent code and unparsable receipt all mean *stay parked*, and each is
   distinguishable in the log — never folded into the terminal.

## 7. What the escalation would deliver into — and the constraint that follows

Asked because AGENTS.md item 11 exists: a transition into an unchanged tree has produced nothing.

* `park-stock-alert.py` is the surface a human actually reads, and its census requires **both**
  halves — *"the machine park label is live AND `human_owned_holds` returns a non-empty set"*
  (`scripts/park-stock-alert.py:82-97`). **So the escalation must ADD `needs:user` and LEAVE
  `review:parked` live.** Clearing the machine label would drop the PR out of the alert entirely,
  leaving only `dispatch-claim`'s per-tick `::warning::` — which #1573 measured as usually not
  emitted at all, because most ticks are floor-held. That is the visible→silent trade
  `_migrate_legacy_park` refuses to make in the other direction.
* Keeping both is coherent, not a contradiction: `human_owned_holds`
  (`scripts/park_policy.py:1065`) refuses automatic re-admission while any `needs:*` is live, and
  if the cause somehow does recover, groom clears only the label it can prove machine-applied and
  posts the #83 stall correction naming the human hold it may not touch.
* No ping-pong with the legacy migration: `_migrate_legacy_park` gates on `HUMAN_PR_PARK_LABEL`
  (`review:needs-user`) on the PR (`scripts/dispatch-claim.py:5731`), which is **not** the label
  groom's age hand-off writes (`age_park_label` returns `HUMAN_PARK_LABEL`, `needs:user`). Worth
  pinning with a test if the escalation ships, because it holds on a spelling.

## 8. If the maintainer accepts, the sequence — and it is three PRs, not one

1. **Publish the verdict.** `backfill-provenance.py` emits a durable, bot-authored, marker-deduped
   receipt naming its refusal **code** for the permanent, PR-owned subset §5.2 names;
   the transient and platform codes stay log-only, exactly as `SILENT_REASONS` does. No park, no
   label, no terminal — this PR only makes a fact that already exists readable.
2. **Measure before escalating.** Extend the #1664 census to report, per standing `orphan-draft`
   park, whether such a receipt is present and which code — the same count-then-act discipline
   #873 → #1664 → this record has followed twice. Run it over real ticks. **If the count is zero,
   stop**: the escalation has no population and shipping it would be a fail-open with a vacuous
   test.
3. **Only then, the escalation**, and it must carry: exact-login author filtering on the receipt;
   exact-membership matching on the code (never `in`/substring — AGENTS.md item 6); `needs:user`
   added with `review:parked` retained (§7); the `park_vetoed` sticky-unpark check that every other
   groom park write already makes (`scripts/groom.py:4788-4792`); receipt-first ordering; its own
   census row; and a self-test asserting **both** directions — the escalation on a permanent code
   *and* the refusal on `log-unavailable`, on an absent receipt, and on a non-bot forgery of the
   marker.

## 9. What this record does NOT claim, and what would settle it

* **No live count for either cause.** The census line exists and this container cannot read it.
  With a token, one groom tick settles the ranking: `grep 'CENSUS machine age parks standing'` over
  a `groom-sweep` run log names every standing park and its cause.
* **The seven inadmissible records are measured on `master`, not on `ledger`.** They are
  `orchestration/provenance/*.json` in this checkout, all seven written 2026-07-17 — nine days
  before #732 closed the stamp table that now refuses them, which is the drift, checkably. The
  authoritative store is the `ledger` ref, which is unreadable here. They demonstrate the
  *mechanism* of the present-but-inadmissible class and corroborate #776's own docstring; they are
  **not** a measurement of the live standing population, and none of them is claimed to be an
  open PR still carrying the bad stamp.
* **The two offline-decidable sub-classes of §5.4 are unmeasured.** The settling query: list open
  worker PRs whose head ref matches `sparq-agent/issue-<n>-` but **not**
  `^sparq-agent/issue-\d+-\d+-\d+$`, plus any whose `head.repo.full_name` is not the target. If
  both are empty — the expected result — they stay a documented gap, not a mechanism.
* **`merge-*` head reachability is not re-measured against GitHub's object-retention behaviour.**
  §4 does not rest on it: 4.1 and 4.2 are properties of this tree, and they are each sufficient.

## 10. What an overrule obliges

If the maintainer overrules §4 and wants the `merge-*` observation anyway, it must (a) be evaluated
against the **live** head, not the receipt fingerprint, (b) carry a positive proof of deadness that
a force-push cannot produce, and (c) come with its own census row and a red test for the
force-push false positive specifically. If the maintainer wants §5 without step 1 of §8 — groom
reading the run log directly — it must arrive with the per-tick read budget of §4.3 costed against
the live standing count, and with an answer to the duplicated-trust-parser objection of
§5.3.1 — the permission is already held, so the cost is a log download per park per tick plus a
second copy of the identity derivation, not a scope widening.

Related: #769 (age is not its own recovery proof), #873 (the park whose exit does not exist),
#1664 (the per-cause census this argues from), #776 (the inadmissible-record repair that refutes
the obvious definition), #1603 (standing-refusal measurement, the receipt shape §8 step 1 copies),
#1544 (why the backfill sweep is scheduled at all), #739 (schema drift as the source of the
inadmissible class), #1573 (why `park-stock-alert` exists and what it can see), #958 (one
definition, plus pointers), `research/767-human-applied-machine-park-exit.md` (the same
"a machine must not clear a park it never classified" discipline, in the other direction).
