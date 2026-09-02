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
> ⚠️ **Four of this record's own claims were wrong and are published as corrections rather than
> quietly fixed** — §2 (a containment claim that a single clause of the code it cited refutes), §5
> (the actor of the drain's own label write), and **§4/§6 (review round 1)**: the record specified
> receipt-first ordering *and* a marker-keyed one-shot refusal while specifying **no convergence
> branch**, which is the only thing that makes that ordering safe — so a drain interrupted between
> its receipt and its label writes was stranded **permanently**, with a public receipt promising a
> transition that row 0 then refused to finish. The correction is **§4.1**. The first two were
> found by asking a named question of the draft; **the third was found by an external reviewer, not
> by this author**, and is recorded that way because §7 asks the reader to price this record's
> unverified claims — a defect the author walked past is the best available evidence on how.
>
> ⚠️ **And the fourth, review round 2, is the third one again one level down.** §4.1 rule 5 named
> the invariant — *the write that leaves the enumeration goes last* — and then applied it only
> **between** surfaces, while §8 still described each surface's park-label transition as a
> **delete and add**: two external writes, with the enumeration key already gone in the gap. A
> crash there leaves a PR that row 1 (`no live human-owned hold to drain`) refuses, so the
> full-ladder rerun rule 3 mandates stands down forever with the matching add outstanding — the
> same permanent strand, moved from the receipt boundary to the label boundary. The correction is
> **§4.1 rule 5**, and it is again an external reviewer's, not this author's. The lesson the record
> is now two-for-two on: **transcribing a safety rule is not applying it** — an invariant stated in
> one paragraph and contradicted by the write sequence three sections later reads as satisfied.
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
| **Receipt-first ordering** | The audit comment is POSTed **before** any label write, so a crash leaves an *explained* PR rather than a silently-moved one. Never label-then-receipt. ⚠️ **This is only HALF the rule.** Receipt-first is safe **because a convergence branch finishes the interrupted write**; the ordering copied without the branch converts a silent strand into an *explained* one, which is worse only in that it also looks handled. **§4.1 is not optional.** | `reconcile-park-misescalation.py:308-312`; the same ordering the `auto-mint` branch demands of its caller (`park_policy.py:1582-1588`) — whose very next clause is the convergence branch that redeems it (`:1573-1587`) — and #610's original rule. |
| **Consume-exactly-once** | A durable, bot-authored, uniquely-named marker; a second run is never a second **conversion**. ⚠️ Not *"a no-op"*: §4.1 splits the marker-present case in two — **no-op** when the recorded transition is proven complete on a fresh read, **converge** when any authorised write is still outstanding. Read from the **bot's own** comments only — a third party must not be able to key it. | `already_reconciled` (`reconcile-park-misescalation.py:72-85`); marker declared in `park_policy` so writer and reader cannot drift (`:934`). **The drain declares a new one**, and it carries a plan (§4.1). |
| **The cap, and whose cap it is** | The drain must **not** spend `AUTO_READMISSION_MAX`. #1309 created a separate `RECEIPTLESS_VOID_MAX = 1` for exactly this, on the stated grounds that *"routing one mechanism's receipts through another's cap makes the two consume each other"*. The drain gets its own one-shot ceiling plus a per-run `--limit`. | `park_policy.py:212`, `:2796`; `research/767-human-applied-machine-park-exit.md` §8.2. |
| **Dry run is the default** | `--apply` is required to write anything; without it the run mutates nothing and prints the same per-PR verdicts. | `reconcile-park-misescalation.py:45`, `:231-232`. |
| **Ownership fails closed** | `unknown` (no `labeled` event at all) and `unattributable` (newest applier is neither proven human nor proven automation, #1849) are **both** refusals. Absence of evidence is not proof of machine ownership. | `park_policy.py:1198-1206`, `:1228-1236`. |
| **Re-prove ownership around the delete** | Labels have no compare-and-swap. The careful writers re-prove machine ownership immediately **before** the delete and again immediately **after**, restoring the label if a human application landed inside the window (#965's check → delete → re-check → restore). | `park_policy.py:1265-1272` and the adjudicate-stuck protocol it names. |
| **Deny is unconditional and order-independent** | An injection / human-arm signal **anywhere** in the bot's own history refuses, whatever came after it. Read through `legacy_deny_signal`, never over the prose table, because the bot's history includes **republished model verdict text** (#814). | `reconcile-park-misescalation.py:120-128`. |
| **Residual holds** | Refuse if any hold would survive the conversion — *"refusing to move a park into a state it could not leave"*. | `migration_residual_holds`, `reconcile-park-misescalation.py:141-148`. |

### 4.1 The convergence branch — the half of receipt-first this record first omitted

**The defect, stated plainly.** §4 requires the receipt before any label write; §6 row 0 originally
refused any PR carrying the drain's marker. Together those two say: *if the process dies after the
POST and before the delete/add, the rerun refuses.* The PR then holds a public receipt asserting a
transition that never happened, its human-owned hold is still live, and **no later run will ever
finish it** — the drain's own one-shot key is what forbids the completion. That is not a small gap:
it converts every transient on the label write into a permanent strand, on the exact population the
drain exists to un-strand, and it does so while reporting the PR as corrected.

**The estate already solved this, twice, and says so in the docstring §4 cites.** `auto-mint`'s
receipt-first instruction is one clause; the next names its redeemer — *"dying receipt-then-label is
recoverable — the `auto-receipt` branch above converges it — while label-then-receipt would erase
the re-admission from every proof surface"* (`park_policy.py:1582-1588`). `auto-receipt`
(`:1573-1587`) and `void-receipt` (`:1588-1594`) are that branch, and the latter's comment states
the drain's failure mode in advance: it is *"NOT optional — the void is one-shot, so without this
branch a crash between the receipt and the label write would leave a PR holding a spent budget and
a live park, i.e. it would reproduce the permanent strand this exit exists to remove."* **The drain
is one-shot for the same reason and inherits that sentence unchanged.**

The protocol, in six rules. Each is a transcription of a mechanism already in this tree.

1. **The receipt is an INTENT receipt: it encodes the exact authorised transition.** Its marker
   carries the **disposition** (`reclassify` / `retire`) and the **label plan for each surface** —
   PR and source issue — drawn from a closed set of named plans. Prior art:
   `RECEIPTLESS_VOID_PLANS` (`park_policy.py:2941`) and `receiptless_void_comment`, which derives
   its destination sentence *from* `evidence["plan"]` and says nothing at all for an unknown plan
   (`:3096-3113`). Without this a rerun cannot know **which** transition it is finishing — and
   `reclassify` and `retire` have different write sets (§5), so guessing means performing a
   conversion the first run never authorised. An intent receipt whose plan is unreadable is a
   **refusal**, never a re-derivation from scratch.
2. **A rerun that finds its own marker CONVERGES; it refuses only when the plan is COMPLETE.** Row 0
   becomes two outcomes, decided against a **fresh read**: every planned write observed landed →
   `already-drained`, a true no-op; any planned write outstanding → `converge`, which performs only
   the outstanding ones. Completion is thereby **derived from live state, never asserted by a second
   comment** — a completion marker would need its own write, and a crash before *it* would
   reproduce this same strand one step later. That is the `auto-receipt` shape exactly: the branch
   asserts nothing new — it recognises the **existing** receipt as already newer than every park
   application (`park_policy.py:1843-1852`) and is reached only for a PR the sweep still enumerates
   as parked, so *"a consumed receipt with the label STILL LIVE completes the interrupted unlabel —
   no second receipt, no new evidence"* (`groom.py:11565-11587`).
3. **Convergence RE-PROVES; it never replays — and the recorded plan BOUNDS a write, it never
   AUTHORISES one.** ⚠️ This is the rule that decides whether §4.1 is a fix or a new fail-open, and
   the tempting weak form is *"re-derive the label plan and finish"*. That is wrong: between the
   crash and the rerun a human may have re-applied the hold, an injection signal may have been
   posted, or a new residual hold may have appeared — and a converge that re-derived only the
   **plan** would complete a transition the ladder now refuses, using the first run's stale proof
   as its authority. So **convergence re-runs the FULL §6 ladder (rows 1–5) against a fresh read**,
   exactly as the first run did. The recorded plan then *intersects* that result: a write happens
   only where the ladder still admits it **and** the plan authorised it. Rows 6–7 are not re-derived
   but **compared** — the disposition the receipt recorded is what the public comment promised, so a
   live state now implying the other disposition is a **disagreement, not an upgrade**. Every
   disagreement is a logged **stand-down**, never a write. This is
   `void_receiptless_park`, which re-derives via `receiptless_void_label_plan` on a live read and
   returns `"plan-changed"` / `"refused"` rather than writing (`worker-pr.py:2358-2385`), under the
   rule its own predicate states — *"a hand-copied second rule at the writer is exactly how the
   gate and the write come to disagree about what is deterministic"* (`park_policy.py:2955-2958`;
   the writer restates it at `worker-pr.py:2366-2368`). §4's **re-prove-around-the-delete** row
   applies to the convergence write **exactly as to the first one**: without it,
   convergence is a blind replay that would re-strip a hold a human re-applied in the crash window,
   which is the incident invariant 3 was written after.
   ⚠️ **Rerunning the ladder UNCHANGED is only coherent because rule 5 keeps every row true at
   every interruption point** — and rows 1 and 3 are the two the drain's own writes could
   otherwise falsify, since row 1 reads the hold this plan deletes and row 3 reads a receipt this
   plan's own comment sits beside. Requiring the full ladder *and* guaranteed convergence is a
   contradiction for any plan whose partial states falsify one of its own rows, and the ladder is
   the side that wins: the run stands down and the write is outstanding forever. **A plan with such
   a partial state is mis-ordered, not a reason to weaken a row** — rule 5 is what discharges the
   obligation, and any future write added to the plan has to be placed under it or it re-opens
   this exact defect.
4. **Convergence is COUNTED APART and spends NO budget.** It is a retry of an already-authorised
   write, not a new conversion, so it must consume neither the one-shot ceiling nor `--limit`, and
   it gets its own census row. `groom`'s convergence test asserts precisely this pair —
   `age_unparked=0` **alongside** `age_converged=1`, annotated *"grants stay at 0 however many times
   the tick replays"* (`groom.py:11576-11587`). Without the split, N crashes read as N conversions
   and one PR silently spends the whole run's cap.
5. **The hold that keys the enumeration is deleted by the LAST write of the plan, and each
   surface's transition is ONE write.** The drain enumerates open PRs by the live human-owned hold
   itself — the listing query filters on `HUMAN_PR_PARK_LABEL`
   (`reconcile-park-misescalation.py:241-246`) and §6 row 1 refuses without it. So the hold is not
   merely the subject of the transition, it is the **enumeration key and the row-1 witness**, and
   every state this plan can be interrupted in must still carry it. Two obligations follow, and
   round 2's defect was stating only the first.

   **(a) Ordering, across every write.** The removal of the last live human-owned hold on the PR is
   the **final** write of the plan, on **every** disposition. That inverts the reference's surface
   order — source issue before PR, `:308-318` then `:319-335` — and, for `retire`, it puts the PR
   **close** (`worker-pr.py:3915`) *before* the hold removal too. The close also drops the PR out of
   `state=open`, but that loss is **covered**: rule 6's marker-keyed sweep enumerates closed PRs by
   the drain's own marker, and `_retire_worker_pr` is idempotent end to end and re-driven from the
   receipt (`worker-pr.py:3909-3933`). Nothing covers a lost row 1, because row 1 is not an
   enumeration question — it is a **proof** the ladder re-derives, and no sweep can restore a
   witness that has been deleted.

   **(b) Atomicity, inside each surface.** A `DELETE` then a `POST` is **two** external writes, and
   the state between them has already lost the hold — so a plan ordered correctly across surfaces
   and split into delete-then-add inside one reproduces the strand the ordering was there to
   remove. Each surface's park-label transition is therefore a **single full-label-set write**
   (`PATCH issues/{n}` with the destination set), never delete-then-add. The prior art is in this
   tree with its reason already stated: the retirement's role swap is *"a FULL label-set PATCH,
   never add-then-remove … the planner rejects an issue with two role labels or none, and **both
   interleavings can produce one**"* (`worker-pr.py:3922-3927`). The reference implementation writes
   both surfaces as `DELETE` then `POST` (`:313-318`, `:329-335`); **that is the second place it
   must not be copied blind**, and for the same reason as the first — it has no convergence branch,
   so it has no row that a partial state could falsify.

   ⚠️ **The trades, both named rather than hidden.** *Inverting the surfaces* means a crash in the
   gap leaves the issue on `status:parked` while the PR still holds `review:needs-user` — a
   transiently inconsistent pair, accepted because it is **convergent** (rule 2 finishes it)
   whereas the reference's order produces an **unenumerable** one that nothing finishes. *The
   full-set write* clobbers any label applied between the fresh read the ladder was evaluated
   against and the write itself: that is the no-compare-and-swap race #976 records against #965's
   check → delete → re-check → restore protocol — *"labels have no compare-and-swap … a
   maintainer re-asserting a hold between the proof and the DELETE leaves NOTHING in the live
   label set"*
   (`park_policy.py:1259-1272`) — **widened from one label to the set**. It is bounded exactly as
   that protocol bounds it: derive the set from a read taken immediately
   before, re-read immediately after, restore per §4's re-prove row, and treat
   `human_hold_deleted_by_machine` (`:1282-1306`) as the durable detector for the case that matters.
   The alternative that avoids the widening — **add** `review:parked` first, **then** delete the
   hold — is survivable and is the required fallback on any surface with no single-write form,
   because it also keeps the hold live throughout; it is not the default because it publishes a
   `review:parked` + `review:needs-user` pair that other writers already read as a distinct state
   (`receiptless_void_label_plan` refuses on exactly that pair, `park_policy.py:2968-2973`), so its
   safety has to be re-proven against every future reader, while the atomic form has no such state
   to read. Where it is used the pair must be censused, not merely tolerated.

   **This is also the whole discrimination the boundary needs, and it needs no actor attribution.**
   Under (a) and (b) the drain cannot produce a state in which the hold is gone *and* a write is
   outstanding. So a converge run that reads one has **positive evidence of a third-party removal**,
   and rule 3's stand-down applies: it censuses and writes nothing, and the recorded plan never
   becomes the authority for finishing a transition on live state the ladder no longer admits. The
   symmetric reading is the completion proof — hold gone with **nothing** outstanding is row 0's
   `already-drained`, a no-op, which needs no authority at all. That the discrimination falls out of
   ordering rather than out of reading the timeline is not a convenience: §5's hand-run token means
   the drain's own removal is authored by a **proven human**, so `human_hold_deleted_by_machine`
   — which requires the removal to be provably *machine* — returns `False` for it and can serve as
   a forensic detector but **never** as the authorisation.
6. **Plus a marker-keyed sweep, because ordering alone cannot cover `retire`.** Rule 5(a) puts
   `retire`'s close (`worker-pr.py:3915`) *before* the hold-removing write, so there is an
   interruption point at which the PR is out of `state=open` with a write still outstanding — the
   hold is live and row 1 holds, but no `state=open` listing reaches it; and a third party clearing
   the hold mid-drain drops any PR out regardless. A `--converge` pass over PRs carrying
   the drain's marker — **including closed ones**, or `retire`'s partials are invisible — with the
   same re-proof of rule 3, is the cheapest complete cover. For the retirement steps themselves the
   drain inherits rather than invents: `_retire_worker_pr` is already *"IDEMPOTENT end to end —
   every step is a no-op when it has already happened … because a retirement that could only be
   applied once would strand half of itself on the first transient"*, and it already names the
   durable receipt the caller posted first as the authoritative record it is re-driven from
   (`worker-pr.py:3909-3933`). **The drain's gap was never the retirement; it was row 0 refusing
   before that re-drive could be reached.**

⚠️ **The failure this section prevents is invisible to a census that counts intent.** A drain that
counts a PR corrected because it posted the receipt reports the same success whether the labels
moved or not — the shape `dispatch-claim` guards with *"the write is REPORTED, never assumed … a
census that counts intent rather than effect is how it comes to read healthy over an untouched
population"*, censusing the failed write under its own refusal code and declining to count it as a
re-admission (`dispatch-claim.py:6121-6139`). The drain counts **effect**, and an outstanding plan
is a census row, not a correction.

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
| 0 | this script already **completed** this PR's recorded transition — keyed on its own marker, filtered to **the actor that ran the script** (see the notes below), and **proven complete against a fresh read**. ⚠️ Marker present with any authorised write still **outstanding** is NOT this row: it is §4.1's `converge` branch, which *finishes* the recorded transition. A bare marker-present refusal here is the review-round-1 defect — it strands every PR the drain crashes on. | new drain marker + `already_reconciled` shape + §4.1's plan re-derivation |
| 1 | no live human-owned hold to drain. ⚠️ On a **convergence** run this row is a witness the plan must not have destroyed: it is rerun unchanged only because §4.1 rule 5 makes the hold's removal the plan's **last** write. A missing hold with any write still outstanding is therefore evidence of a **third-party** removal — stand down and census, never write. | `human_owned_holds` |
| 2 | **any** live hold's newest application is not `machine` — `human`, `unknown`, or `unattributable` | `label_application_ownership` (per label, all of them) |
| 3 | no well-formed bot park-reason receipt, or **any** receipt anywhere is non-capacity | `human_park_capacity_proof` |
| 4 | an injection / human-arm signal exists anywhere in the **bot's own** history | `legacy_deny_signal` |
| 5 | a residual hold would survive the conversion | `migration_residual_holds` |
| 6 | the automatic re-admission budget is already spent → `retire` **or** refuse (§5), never a bare reclassify | `auto_readmission_marker_count` vs `AUTO_READMISSION_MAX` |
| 7 | the per-run `--limit` / one-shot ceiling is reached | own constant, never `AUTO_READMISSION_MAX` |

Rows 2 and 3 together are the candidate definition; rows 4, 5, 6, 7 are inherited unchanged from
#614/#797/#764. **Row 0 is inherited in its KEY but not in its OUTCOME**: the marker still decides,
but it selects between *no-op* and *converge* (§4.1) rather than refusing outright — and that is a
**stricter** rule, not a looser one, because it is the branch that stops a crashed run from
counting as a completed one. **Nothing in this ladder is new permissive policy.** That is the
point: a drain that needs a new permissive rule is a drain for a different population.

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
* **Four of this record's own claims were wrong and are corrected in place** rather than deleted —
  §2's containment claim, §5's actor claim, §4/§6's receipt-first-without-convergence specification
  (corrected in §4.1), and §4.1/§8's own write sequence, which stated the enumeration invariant and
  then violated it inside each surface's delete-and-add (corrected in §4.1 rule 5). The first two
  survived a re-read of the draft and fell to a named question (AGENTS.md pre-flight items 2 and
  12); **the third and fourth survived both, and fell to an external reviewer in rounds 1 and 2.**
  A reader should price the remaining unverified claims accordingly, and price them *lower* than
  the first two corrections alone would suggest: the ones with a line citation were mechanically
  checked against the tree, the ones without are reasoning, and this record has now demonstrated
  **twice** that its reasoning can state a safety rule and drop it one level down — first the
  companion rule that made receipt-first safe, then the application of its own ordering invariant
  to the writes it had already enumerated — in a section (§4) whose stated purpose was to
  transcribe those rules rather than re-derive them. The corrected count of interruption boundaries
  the design must survive is **6**, not the 4 the round-1 draft implied: receipt, source-issue
  write, retirement close, PR write, and the two intra-surface delete/add gaps the round-2
  correction **removes** rather than covers — a boundary eliminated by construction is the only
  kind that needs no test, which is why §8 rule 6 asks for a red row proving it stays eliminated.
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
   constant declared in `park_policy`, `--apply`-gated, `--limit`-capped, receipt-first **and
   crash-convergent per §4.1** (intent receipt carrying the plan, `converge` branch, each surface's
   transition a single full-label-set write with the hold-removing one **last**, marker-keyed
   `--converge` sweep), with its refusal ladder from §6 imported wholesale.
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
6. **An INTERRUPTION test after every external write** — the §4.1 obligation, and the one whose
   absence the record itself demonstrates is easy to walk past, twice. The apply path performs, in
   §4.1 rule 5's order: the receipt POST, the **source-issue** transition as one full-set write,
   (for `retire`) the retirement close, and **last** the **PR** transition as one full-set write,
   which is the one that removes the hold. The self-test drives a fixture that **stops after each
   one in turn** and asserts the rerun **converges to the intended final state** — or stands down,
   loudly and without writing, when the live state no longer matches the recorded plan. Neither an
   interrupted run nor its rerun may report the PR corrected. Four assertions carry the weight and
   every one must be able to go **red**:
   * deleting the `converge` branch must red the after-receipt case (it reverts to the permanent
     strand);
   * **narrowing §4.1 rule 3's re-proof from the full ladder down to the plan alone** must red —
     which needs a row per hazard the ladder owns, because they fail differently: a human
     re-applies the hold inside the crash window (row 2), a deny signal is posted inside it (row 4),
     and a new residual hold appears inside it (row 5). Each asserts the converge run **stood down
     and wrote nothing**;
   * **splitting either surface's transition back into delete-then-add** — the reference
     implementation's own shape (`:313-318`, `:329-335`) — must red the interruption row taken
     *between* those two writes. That is round 2's defect and it is the one boundary the earlier
     draft had no row for at all: the fixture must assert the rerun **completes the transition**,
     and it can only do so by observing that row 1's witness is still live, so a test that stops
     only at surface boundaries cannot see this and does not discharge the obligation;
   * **moving the hold-removing write earlier** — before the source-issue write, or (for `retire`)
     before the close — must red, each with its own row, because each strands a different
     outstanding write behind a row-1 refusal.

   A convergence test that passes with the branch removed is measuring nothing — `groom`'s states
   its own kill condition, *"Delete the `if consumed:` block and this reds"*
   (`groom.py:11568-11569`), and every one of these must too. The convergence rows must also assert
   the §4.1 rule 4 counter split (`converged=1` **with** `corrected=0`), or a replay silently reads
   as a second conversion.
7. **Its dispositions must be censused** in `PARK_REFUSAL_CODES` / `PARK_REFUSAL_HUMAN_TERMINAL`
   alongside every existing one — **`converge` and the outstanding-plan stand-down included**, so a
   drained PR, a refused one and a half-written one are all counted rather than disappearing from
   the taxonomy the moment this script touches them.
8. **The `retire` half of §5 is not optional.** Shipping only `reclassify` converts a visible stall
   into a silent one for its over-cap members.

Related: #1292 (the census this is blocked on), #797 (`reconcile-park-misescalation.py`, the
reference shape), #614 (invariant 3 — receipt-first, consume-once, capped), #764 (the absorbing
park), #769 (age is not its own recovery proof), #691 (the unobtainable cause), #1309
(`RECEIPTLESS_VOID_MAX`, why a new mechanism gets its own cap), #1573 (`park-stock-alert`, the
label-only subset), #965 / #976 (labels have no compare-and-swap, and the residual that leaves —
why §4.1 rule 5 writes each surface once), #1849 (`unattributable` is not permission),
#958 (one definition, plus pointers), #767 / `research/767-human-applied-machine-park-exit.md` (the ladder this drain sits
beside).
