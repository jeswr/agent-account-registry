# #1997: draining the human-terminal park — the shape, and the precondition it is blocked on

> 🤖 **SPARQ agent** — design record, 2026-09-02. Maintainer-review document.
> **This record changes no behaviour.** It answers the three questions #1997 asked a design record
> to settle, states the safety rules the drain inherits rather than re-deriving them, and reports
> one measurement that changes the priority of the whole item.
>
> **Verdict, in one line: the drain is NOT authorised to be built yet, because the census it is
> defined against is not in this tree.** `groom.py --report-human-holds` does not exist on
> `master` (§1). #1997 says *"Run the census first; if the candidate count is zero the work is not
> needed"* — the count is not zero, it is **UNMEASURED**, and on this repo's standing direction an
> unmeasured population is a refusal, not a licence. So: no writer, no label, no script. What this
> record does instead is decide the shape *now*, from the code that already exists, so that when
> the census lands the only open question is the count.
>
> **The three answers.** (§3) A **separate one-shot audited script**, not a second population
> inside `reconcile-park-misescalation.verdict()` — the two proofs are disjunctive and a
> disjunction is where the fail-open lives. (§4) The #614/#797 rules apply unchanged and are
> **restated with their call sites**, including the one that is easiest to get wrong: the drain
> must **not** consume `AUTO_READMISSION_MAX` and must **not** reuse `RECONCILE_MARKER`. (§5) The
> exit delivers into the **#767 four-gate ladder**, not the bot path, because a hand-run script
> writes its label as a **proven human** — so the drain must write an attestation **and register
> its marker in `PARK_RECONCILE_ATTESTATIONS`**, or gate 3 refuses its entire population on the
> next tick while the run reports success. That, plus the fact that the drain's own label write
> **re-anchors every strictly-after ordering rule to drain time**, is the AGENTS.md pre-flight
> item 11 answer and the two most likely ways this lands as a no-op.
>
> ⚠️ **Two of this record's own first-draft claims were false and are published as corrections
> rather than quietly fixed** — §2 (a containment claim that a single clause of the code it cited
> refutes) and §5 (the actor of the drain's own label write). Both were found by asking a named
> question of the draft, not by re-reading it.
>
> ⚠️ **Nothing here is measured against the live board.** This container has no network, no `gh`
> and no token. Every count in this document is either read out of the repository tree (and the
> command is given) or reported as a claim of the issue that made it. §7 says what would settle
> the rest.

## 1. The precondition — the census #1997 is defined against is not in the tree

#1997 opens *"`groom.py --report-human-holds` (registry #1292) **now** MEASURES the human-terminal
park population and dispositions each held PR"*, and defines its subject — `machine-exit-candidate`
— as a disposition that census emits. Checked against `master` at `995dd9080`:

| probe | result |
|---|---|
| `grep -n "add_argument(" scripts/groom.py` | **10** arguments: `--self-test`, `--print-owner-repos`, `--target-repos-env`, `--report-orphan-claims`, `--registry-repo`, `--policy-file`, `--policy-resolver`, `--stale-hours`, `--bot-slug`, `--ledger-root`. No `--report-human-holds`. |
| `grep -rn "report-human-holds\|report_human" .github/ scripts/` | no match |
| `grep -rn "machine-exit-candidate\|machine_exit_candidate"` over the worktree | no match |
| `grep -n "label_application_ownership" scripts/*.py` | `park_policy.py` (the definition at `:1194`, three internal call sites, one docstring mention) and `resolve-conflicts.py`. **`groom.py` never calls it** — so no groom-side census can be computing the ownership half of the candidate definition. |
| `git log --all --oneline --grep="#1292"` | one commit, `45ada45a4` *"fix(groom): the age-park cap must count RE-ADMISSIONS, not parks (registry #1292)"* |

All **eleven** live `[registry #1292]` references inside `groom.py` — three in code (`:210`,
`:271`, `:2944`) and eight in its self-test (`:10587`–`:11999`) — are about `age_park_generation`
counting **grants** rather than parks. That is a
different change from the one #1997 attributes to the same number.

**So the reading is: the census is either unmerged, or landed under a name this record cannot
find, or #1997's premise is a forward reference to work that was planned and not done.** All three
have the same consequence for the drain, and it is the fail-closed one: **the population the drain
would write to has never been enumerated by the definition #1997 gives it.** A drain built now
would be a writer with no measured input, against the one label `park_policy` invariant 3 says no
automation may touch.

**This is not a reason to build the census here.** It is a different item, in a different lane
(a read-only measurement), and #1997's own sequencing — *"Run the census first"* — puts it first
deliberately. It is filed as follow-up work.

## 2. What DOES measure this population today, and what the census must add

The estate is not blind to the human terminal; it measures it three ways, none of which is the
candidate partition.

1. **`dispatch-claim`'s per-tick park census** — the widest. It counts a park human-terminal when
   **any** of three hold: a live human-owned hold, a proven human applied the park, or the
   automatic cap is spent. Its warning names every PR. It is emitted only on an **executed** tick,
   inside a dispatch log (`park-stock-alert.py:10-21`).
2. **`park-stock-alert.py`** — a **deliberately narrower** label-only census: a PR counts iff
   `MACHINE_PARK_PR_LABEL` (`review:parked`) is live **AND** `human_owned_holds` is non-empty
   (`park-stock-alert.py:82-88`). Its own header states the gap and measures it: on 2026-08-01
   dispatch-claim reported 6 terminal on the registry; this label-only census found **2**. It is
   titled for the narrow population precisely so it cannot close as healthy while four PRs are
   stuck (`park-stock-alert.py:35-45`).
3. **`park_policy`'s refusal taxonomy** — `PARK_REFUSAL_CODES` / `PARK_REFUSAL_HUMAN_TERMINAL`,
   one writer (`park_census_record`) and one aggregator (`park_census_summary`). Every admission
   decision emits exactly one row. This is per-**decision**, and only for PRs that reach the
   admission at all — the sweep's pre-admission exits census themselves separately for exactly
   that reason (`dispatch-claim.py:6020-6026`, `:6065-6070`).

What #1997's census adds over all three is the **per-PR ownership walk**: `machine-exit-candidate`
requires `label_application_ownership` to return `machine` for **every** live `needs:*` /
`review:needs-user` label, with `unknown` and `unattributable` both disqualifying
(`park_policy.py:1194-1224`). That is the expensive half — a timeline read per label per PR — and
it is exactly the half `park-stock-alert` declined to do.

⚠️ **A correction to this record's own first draft, published because the wrong version is the
tempting one.** The draft read *"the candidate partition is a strict subset of subset 2, so the
recorded `2` bounds it from above"*. **That is false**, and the falsifier is one clause of the code
it cites: subset 2 requires a live `review:parked` **as well as** the hold
(`park-stock-alert.py:93-94` — `if park_policy.MACHINE_PARK_PR_LABEL not in names: continue`). A
PR carrying `review:needs-user` **alone** — which is exactly the population
`reconcile-park-misescalation.py` enumerates (`:241-246`) — is human-terminal and **invisible** to
that census. The two sets **overlap**; neither contains the other.

The consequence is the one that matters for sequencing: **nothing in this tree bounds the candidate
count, in either direction.** There is no stale prior to lean on and no "it is probably about two"
to reason from. That is not an argument for building the drain speculatively — it is the strongest
available argument for §8's ordering, that the census is not a nicety preceding the real work but
the only thing that can tell anyone whether the real work exists.

## 3. Answer 1 — a separate one-shot script, not a second population inside `verdict()`

#1997 asks whether the drain is *"a one-shot audited script like
`scripts/reconcile-park-misescalation.py` … or an extension of that script's `verdict()` to a
second proven population"*.

**Answer: a separate one-shot script that imports the same shared predicates.** Four reasons, in
descending order of how much they cost if ignored.

1. **`verdict()`'s refusals are only fail-closed because its clauses are a CONJUNCTION.** Its
   contract — *"Every one is a REFUSAL condition — anything unproven leaves the PR exactly where it
   is"* (`reconcile-park-misescalation.py:22-23`) — holds because every clause must pass. Adding a
   second population makes the function a **disjunction of two proofs**, and each refusal stops
   meaning "this PR stays put" and starts meaning "this proof failed; the other one may still
   admit it". That is the shape a fail-open takes in this module, and it would be introduced into
   the one function whose entire purpose is refusing.
2. **The two populations are defined by different receipt families, and one of them is
   `verdict()`'s explicit refusal.** #797's clause 2 requires a **park-generation** receipt whose
   window key is byte-identical to one of the PR's own `sparq-auto-readmit` stamps; a PR with no
   generation receipts is refused by name and handed to `dispatch-claim._migrate_legacy_park`
   (`:129-134`). The #1997 candidate is defined by a **park-reason** receipt
   (`PARK_REASON_MARKER`, read through `human_park_capacity_proof`) being capacity-class. A
   candidate can hold the second and not the first. Extending `verdict()` to admit it means either
   weakening the no-generation-receipt refusal or branching around it — and "never weaken a trust
   check to make a population fit" is the standing rule.
3. **The one-shot key would collide.** `already_reconciled` is keyed on `RECONCILE_MARKER`
   (`park_policy.py:934`), a single literal shared between the writer and
   `park_instance_attested`'s reader. If the drain wrote the same marker, each script's
   "already corrected — one-shot" check would silently consume the **other's** population, and a
   PR corrected by one would be invisible to the other forever. The drain needs its **own**
   marker constant, declared in `park_policy` beside `RECONCILE_MARKER` for the same
   writer/reader-cannot-drift reason.
4. **The audit body is the deliverable and the two are not the same claim.** #797's comment quotes
   a **receipt pair** and asserts *"it had not been human-readmitted"*. The drain's claim is
   *"every live hold on this PR was applied by proven automation, and the machine's own park-reason
   receipt classifies this episode capacity"* — a different proof, quoting different evidence. A
   shared body that says both would say neither precisely.

**What IS shared, and must be imported rather than re-derived** (#958's one-definition rule):
`human_owned_holds`, `label_application_ownership` / `label_application_machine_owned`,
`human_park_capacity_proof`, `migration_residual_holds`, `legacy_deny_signal`,
`AUTO_READMISSION_MAX`, and `worker-pr`'s `auto_readmission_marker_count`. The drain adds **no new
predicate about ownership or cause**; if it needs one, that is a sign the population is not the one
the census named.

### 3.1 The option not offered, and its rejection

A third shape is available and must be rejected explicitly, because it is the one a future author
reaches for when the script feels heavyweight: **making the drain a mode of the routine `groom`
tick.** It is rejected on `reconcile-park-misescalation.py`'s own founding sentence
(`:5-12`) — *"`review:needs-user` / `needs:user` are HUMAN-OWNED (park_policy invariant 3, written
after an incident in which the orchestrator re-applied `needs:user` 37 minutes after the maintainer
removed it). Teaching a routine tick to strip a human-owned label would trade one silent failure
for a worse one."* Nothing about the #1997 population changes that. A tick that can clear the human
terminal is a standing capability; a hand-run, `--apply`-gated, capped, per-PR-audited script is a
bounded one. The drain gets the bounded one.

## 4. Answer 2 — the #614/#797 rules, stated rather than re-derived

#1997 asks that these be *"stated explicitly rather than re-derived"*. Each is given with the place
it is already enforced, so the drain's implementation is a citation rather than a judgement call.

| rule | statement | where it already lives |
|---|---|---|
| **Receipt-first ordering** | The audit comment is POSTed **before** any label write, so a crash leaves an *explained* PR rather than a silently-moved one. Never label-then-receipt. | `reconcile-park-misescalation.py:308-312`; the same ordering the `auto-mint` branch demands of its caller (`park_policy.py:1582-1588`), and #610's original rule. |
| **Consume-exactly-once** | A durable, bot-authored, uniquely-named marker; a second run must be a **no-op**, not a second conversion. Read from the **bot's own** comments only — a third party must not be able to key it. | `already_reconciled` (`reconcile-park-misescalation.py:72-85`); marker declared in `park_policy` so writer and reader cannot drift (`:934`). **The drain declares a new one.** |
| **The cap, and whose cap it is** | The drain must **not** spend `AUTO_READMISSION_MAX`. #1309 created a separate `RECEIPTLESS_VOID_MAX = 1` for exactly this, on the stated grounds that *"routing one mechanism's receipts through another's cap makes the two consume each other"*. The drain gets its own one-shot ceiling plus a per-run `--limit`. | `park_policy.py:212`, `:2796`; `research/767-human-applied-machine-park-exit.md` §8.2. |
| **Dry run is the default** | `--apply` is required to write anything; without it the run mutates nothing and prints the same per-PR verdicts. | `reconcile-park-misescalation.py:45`, `:231-232`. |
| **Ownership fails closed** | `unknown` (no `labeled` event at all) and `unattributable` (newest applier is neither proven human nor proven automation, #1849) are **both** refusals. Absence of evidence is not proof of machine ownership. | `park_policy.py:1198-1206`, `:1228-1236`. |
| **Re-prove ownership around the delete** | Labels have no compare-and-swap. The careful writers re-prove machine ownership immediately **before** the delete and again immediately **after**, restoring the label if a human application landed inside the window (#965's check → delete → re-check → restore). | `park_policy.py:1265-1272` and the adjudicate-stuck protocol it names. |
| **Deny is unconditional and order-independent** | An injection / human-arm signal **anywhere** in the bot's own history refuses, whatever came after it. Read through `legacy_deny_signal`, never over the prose table, because the bot's history includes **republished model verdict text** (#814). | `reconcile-park-misescalation.py:120-128`. |
| **Residual holds** | Refuse if any hold would survive the conversion — *"refusing to move a park into a state it could not leave"*. | `migration_residual_holds`, `reconcile-park-misescalation.py:141-148`. |

## 5. Answer 3 — what the exit DELIVERS INTO (AGENTS.md pre-flight item 11)

This is the question that decides whether the drain is worth building at all, and the answer is
**not** the reassuring one.

**Where a drained PR lands depends on WHOSE TOKEN the drain ran under, and this record got it
wrong first.** The drain clears the human-owned hold(s) and applies `MACHINE_PARK_PR_LABEL`
(`review:parked`); on the next dispatch tick the PR reaches `capacity_park_admission`
(`dispatch-claim.py:6070`). The draft of this section asserted that the drain's write is a
*machine* application, so `human_park` is `None` and gates 1–3 of the #767 ladder are skipped.
**That is false for a hand-run script**, which is the shape §3 just selected.

`_is_proven_human` (`park_policy.py:543-548`) proves a human from a present non-`[bot]` login with
no `performed_via_github_app` whose collaborator permission the probe confirms. A one-shot script
run under a **maintainer PAT** produces exactly that event, and `park_policy` says so in as many
words: the reconciler's markers are *"authored by that maintainer, not by the App"* because *"the
script is HAND-RUN under a maintainer token"* (`park_policy.py:953-957`). So:

| the drain runs under | its `review:parked` write is | what evaluates it |
|---|---|---|
| a **maintainer PAT** (the #797 shape) | a **proven-human** park application | the full #767 four-gate ladder: `human_park_is_machine_owned` → `human_park_capacity_proof` → **`park_instance_attested`** |
| the **App / bot token** | a machine park application | `human_park` is `None`; gates 1–3 skipped, ordinary bot path |

**On the hand-run path the drain must write an attestation, and register it — or it is a no-op.**
Gate 3 admits only when an attestation authored by *the actor that applied this park* falls inside
*this park's own window* (`park_policy.py:968-1019`). `reconcile_attestations` recognises a
comment only if its marker is a member of **`PARK_RECONCILE_ATTESTATIONS`**
(`park_policy.py:944-946`, consumed at `:961`) — and that tuple's own comment states the failure
direction explicitly: *"A converter whose marker is NOT in this tuple simply does not bind an
instance, which is the conservative direction: its PRs stay parked"* (`:941-943`). The tuple has
**one** member today.

That is AGENTS.md pre-flight item 11 in its sharpest available form: **a drain that writes a
perfect audit comment, converts every label correctly, and omits one line from a tuple in another
module is a script that refuses its whole population on the next tick and reports success.** It
would fail as `human-applied-unbound`, which is a *silent, correct-looking* refusal — the PR is
counted, the code is named, and nothing says the converter is the reason. The drain's marker
therefore belongs in `PARK_RECONCILE_ATTESTATIONS` **in the same change**, and the self-test that
proves the round trip — attestation written, gate 3 admits; attestation absent or unregistered,
gate 3 refuses — is the one assertion in the whole implementation that cannot be skipped.

**Everything below applies to both paths**, because it follows from the label write alone.

**The re-anchoring, and why it is the hazard.** `park_application_view` returns the latest
`labeled` event for **any** of `READMISSION_LABELS` across **both** surfaces
(`park_policy.py:740-744`, `:128`). `review:parked` is a member. Therefore **the drain's own write
becomes the newest park application**, and every ordering rule downstream re-anchors to drain time:

* `auto-mint` requires *"fresh, unconsumed recovery evidence **strictly newer than the latest park
  application**"* (`park_policy.py:1580-1588`). After the drain, that means a successful run
  recorded **after the drain wrote the label** — not after the original outage.
* `capacity_recovery_evidence` reads a rolling **48 h** model-health window. For a PR that has been
  sitting on the human terminal for weeks, the account that was failing when the *original* park
  landed is not going to record a fresh post-drain success on cue, so the strong exit is, in
  practice, unreachable for exactly the population the drain targets — this is #691's
  unobtainable-cause case, restated.
* What is left is the **explicitly-labelled heuristic**, `sustained_fleet_health_evidence` —
  *"the fleet has been demonstrably healthy for a sustained span"*, i.e. an elapsed-time condition
  measured from after the drain.

So the honest description of what the drain delivers is: **it converts a permanent human-terminal
hold into a machine hold that clears on a fleet-health timer.** That may well be the right trade —
a countable state with a heuristic exit beats a terminal state with none — but it must be written
down as what it is, because `human_park_capacity_proof`'s founding measurement is the sentence
*"an exit briefed as 'gated on proven cause-recovery, never elapsed time' was, for that population,
a six-hour timer wearing an evidence gate's name"* (`park_policy.py:858-865`). A drain briefed as
delivering proven cause-recovery would be making that same claim a second time, and it would be
false in the same way.

**The subset for which the drain delivers NOTHING, and what to do about it.** If a candidate's
`auto_readmission_marker_count` already meets `AUTO_READMISSION_MAX = 2`, re-parking it produces a
PR that is machine-quiet with **no machine exit at all** — the absorbing shape #764 named, and the
precise case #797's `verdict()` already handles with its second disposition:

> `"retire"` — *the machine's automatic re-admissions are ALREADY spent, so re-parking alone would
> leave the PR machine-quiet but with no machine exit … The machine terminal is already due: take
> it now* (`reconcile-park-misescalation.py:92-100`).

**The drain must make the same split, or refuse the over-cap subset outright.** A drain with only
one disposition would move its over-cap members from a *visible* human-terminal stall into a
*silent* machine one — the exact trade `_migrate_legacy_park`'s harm gate forbids and
`research/767-…` §6.3 rejects. Refusing them is acceptable and honest; converting them without an
exit is not.

**Consequence for the census.** The candidate definition #1997 gives (`all live holds
machine-applied` AND `newest bot receipt capacity-class`) does **not** include a cap check. So the
census's `machine-exit-candidate` count is an **upper bound** on the drainable population, not the
population. If the census is extended before the drain is built, adding
`auto_readmission_marker_count` to each candidate row is the single highest-value column: it
partitions candidates into *reclassify* and *retire/refuse* before anybody writes a writer.

## 6. The refusal ladder the drain's `verdict()` must implement

Stated as a table so the implementation is a transcription. Ordering is deliberate — cheapest and
most absolute first; every row is a **refusal**, and the PR stays exactly where it is on each.

| # | refuses when | shared predicate |
|---|---|---|
| 0 | this script already corrected this PR — keyed on its own marker, filtered to **the actor that ran the script** (see the note below) | new drain marker + `already_reconciled` shape |
| 1 | no live human-owned hold to drain | `human_owned_holds` |
| 2 | **any** live hold's newest application is not `machine` — `human`, `unknown`, or `unattributable` | `label_application_ownership` (per label, all of them) |
| 3 | no well-formed bot park-reason receipt, or **any** receipt anywhere is non-capacity | `human_park_capacity_proof` |
| 4 | an injection / human-arm signal exists anywhere in the **bot's own** history | `legacy_deny_signal` |
| 5 | a residual hold would survive the conversion | `migration_residual_holds` |
| 6 | the automatic re-admission budget is already spent → `retire` **or** refuse (§5), never a bare reclassify | `auto_readmission_marker_count` vs `AUTO_READMISSION_MAX` |
| 7 | the per-run `--limit` / one-shot ceiling is reached | own constant, never `AUTO_READMISSION_MAX` |

Rows 2 and 3 together are the candidate definition; rows 0, 4, 5, 6, 7 are inherited unchanged from
#614/#797/#764. **Nothing in this ladder is new policy.** That is the point: a drain that needs a
new permissive rule is a drain for a different population.

⚠️ **Row 0's author filter is the one place the reference implementation should not be copied
blind.** `already_reconciled` documents itself as reading a *"bot-authored marker only"* and
filters comments on `bot_login` (`reconcile-park-misescalation.py:72-85`), while `park_policy`
states of the same script's markers that *"the script is HAND-RUN under a maintainer token, so its
markers are authored by that maintainer, not by the App"* (`:953-957`). Those two cannot both be
describing the same run. Whichever is right, the drain's one-shot key must filter on **the
identity that actually authors its comment**, and its self-test must assert the one-shot property
by *round trip* — write, re-read, second run is a no-op — rather than by constructing a fixture
comment under a login the test chose. A one-shot check that silently never matches is a converter
that will convert twice. Whether the reference implementation has this defect today is a question
about its operational token that cannot be settled offline; it is filed rather than asserted.

## 7. What this record does NOT claim

* **No live census was run**, because none exists to run (§1) and the container has no token
  regardless. #1997's instruction *"run the census first"* is **not** satisfied by this record and
  is not treated as satisfied.
* **The candidate count is unknown, and this record bounds it in NEITHER direction.** The only
  anchored numbers in this document are `park-stock-alert`'s recorded 2026-08-01 registry
  measurement (**6** terminal by dispatch-claim's three causes, **2** by the label-only rule), and
  §2 shows why neither is a bound: that census requires a live `review:parked` alongside the hold,
  so the `review:needs-user`-only population is outside it entirely. Both numbers are reported as
  claims of `park-stock-alert.py`'s own header about **that repo on that day**, and they predict
  nothing about today or about `sparq-org/sparq`.
* **The re-anchoring finding in §5 is derived from the code, not observed on a board.** It follows
  from `park_application_view` reading `labeled` events for `review:parked`
  (`park_policy.py:740-744`, `:128`) plus `auto-mint`'s strictly-after rule
  (`:1580-1588`). It has not been demonstrated against a live PR.
* **Whether `reconcile-park-misescalation.py`'s own `reclassify` disposition already meets this
  same re-anchoring is not assessed here.** It writes the same label through the same reader, so
  the mechanism applies to it too; whether its `reclassify` members actually re-admitted after
  their correction is a live-board question, and the answer changes whether the drain's §5 trade
  is proven or merely plausible. It is filed as follow-up rather than asserted either way.
* **Two of this record's own claims were wrong and are corrected in place** rather than deleted —
  §2's containment claim and §5's actor claim. Both survived a re-read of the draft and fell to a
  named question (AGENTS.md pre-flight items 2 and 12). A reader should price the remaining
  unverified claims accordingly: the ones with a line citation were mechanically checked against
  the tree, and the ones without are reasoning.
* **The settling commands**, for whoever has a token: enumerate open PRs carrying a live
  `needs:*` / `review:needs-user`; for each, resolve `label_application_ownership` for **every**
  such live label and read whether any bot park-reason receipt exists and what class it carries;
  report `auto_readmission_marker_count` alongside. That produces the candidate count **and** its
  reclassify/retire split in one pass, which is the whole input this design is waiting on.

## 8. What landing the drain obliges

In order. Do not start at 2.

1. **The census first, as its own read-only change.** It writes no label, no comment and no ledger
   record — #1292's stated posture, and the reason the measurement is safe to land alone. It must
   **always emit, including a zero row** (AGENTS.md pre-flight item 8): a candidate census that
   prints nothing when the count is zero is indistinguishable from one that did not run.
2. **If the count is zero, stop.** #1997 says so, and it is the correct outcome, not a failure.
   Record the count and close it.
3. **If it is non-zero, the drain is a new script** with its own `--self-test`, its own marker
   constant declared in `park_policy`, `--apply`-gated, `--limit`-capped, receipt-first, and its
   refusal ladder from §6 imported wholesale.
4. **Register the marker in `PARK_RECONCILE_ATTESTATIONS` in the SAME change** (§5). It is one
   line and it is the difference between a drain and a no-op; the tuple's own comment already
   warns that an unregistered converter *"does not bind an instance … its PRs stay parked"*
   (`park_policy.py:941-946`). The tuple is also the place the record's advice is verifiable: a
   self-test that drives `park_instance_attested` with the drain's real marker, and again with it
   removed from the tuple, is a **red** test for exactly this omission.
5. **Its self-test must assert BOTH directions for every gate** — the admit **and** the refusal —
   or it is a new fail-open in the module whose entire subject is failing closed. That is
   `research/767-…` §8.3's obligation restated, and it is the gate profile's own rule: an
   assertion that cannot go red is vacuous. In particular, the `unknown` and `unattributable`
   ownership values need their own red rows; they are the two that silently read as permission if
   the boolean projection is used by mistake.
6. **Its dispositions must be censused** in `PARK_REFUSAL_CODES` / `PARK_REFUSAL_HUMAN_TERMINAL`
   alongside every existing one, so a drained PR and a refused one are both counted rather than
   disappearing from the taxonomy the moment this script touches them.
7. **The `retire` half of §5 is not optional.** Shipping only `reclassify` converts a visible stall
   into a silent one for its over-cap members.

Related: #1292 (the census this is blocked on), #797 (`reconcile-park-misescalation.py`, the
reference shape), #614 (invariant 3 — receipt-first, consume-once, capped), #764 (the absorbing
park), #769 (age is not its own recovery proof), #691 (the unobtainable cause), #1309
(`RECEIPTLESS_VOID_MAX`, why a new mechanism gets its own cap), #1573 (`park-stock-alert`, the
label-only subset), #1849 (`unattributable` is not permission), #958 (one definition, plus
pointers), #767 / `research/767-human-applied-machine-park-exit.md` (the ladder this drain sits
beside).
