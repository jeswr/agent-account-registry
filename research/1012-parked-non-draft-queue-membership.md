# Should the parked-free carve-out gain a GraphQL merge-queue-membership proof? (#1012)

> 🤖 **SPARQ agent** — design record, 2026-07-31. Maintainer-review document.
> **This record changes no behaviour.** It answers the design question #1012 raises before any
> API-surface change is written, so the answer is a *decided* thing rather than an omission the
> next author "fixes" by relaxing a trust check.
>
> **Recommendation: do NOT add a queue-membership read to `_pull_inactivity_decision`. Spend the
> same GraphQL probe on the other side of the problem — as the safety guard on converting a
> machine-parked `__global__` holder to DRAFT, which moves the PR into the state the existing test
> already proves. The probe does NOT license the machine to issue that conversion itself — §4.1 —
> so the conversion is human-executed.** §6 is the maintainer's confirm-or-overrule; §7 is what an
> overrule obliges before any code is written.

## 1. The question

Registry #677 point 3 observed that `busy_packages_of_pulls` treats *every* parked NON-draft PR as
active, so a parked non-draft PR never frees its crates — parking is supposed to be the release
valve and here it is not.

#1012 records that this is **not** unintended, and that the naive repair — accept an explicit-null
REST `auto_merge` as proof of inertness for a non-draft — is a **fail-OPEN change to a trust
check** and must not be done. Merge-queue membership is GraphQL-only: a directly-queued PR shows
**no** REST latch, so `auto_merge: null` on a non-draft means "not armed", never "cannot merge".
That reasoning is already written out at `scripts/dispatch-claim.py:1867-1888` and pinned in the
self-test at `scripts/dispatch-claim.py:17825-17831`.

#1012 then proposes the honest direction: give the non-draft case a **POSITIVE** proof of
non-mergeability — a GraphQL read of `mergeQueueEntry` (and its state), head-matched to the listing
row exactly as the current detail path is — and asks for a design record first, because that is a
real API-surface change with its own cost and failure modes.

This record answers: **is that proof worth buying, and is it even the proof the carve-out needs?**

## 2. What the carve-out actually has to prove — and the asymmetry the proposal misses

`_pull_inactivity_decision` (`scripts/dispatch-claim.py:1592`) does not answer *"can this PR merge
right now?"*. Its answer is consumed to **free a crate for a sibling worker that has not launched
yet** and will push to that crate minutes later. The property it needs is therefore:

> this PR cannot land in that crate **between now and then**.

Draft and not-queued are not the same kind of evidence for that property:

| | `draft: True` (today's proof) | `mergeQueueEntry: null` + `autoMergeRequest: null` |
|---|---|---|
| what it establishes | GitHub **structurally refuses** to merge it, and cancels/refuses auto-merge on it | it is **not enqueued at this instant** |
| mutations between it and a merge | **two** — un-draft, *then* arm/enqueue | **one** — arm/enqueue; and **zero** for a human pressing Merge |
| who performs them | a human, or a loop that refuses to act on a parked PR | the same, plus every arm path in the fleet |
| stable under time passing? | yes — un-drafting is itself the thing the fleet observes | **no** — the answer expires the instant it is read |

The proposed proof is a **point-in-time** read used to license a decision whose risk window is the
whole gap to the sibling's first push. `draft` is a **standing** condition over that same window.
The two reads look symmetric at the call site and are not: adding `mergeQueueEntry` to the
non-draft branch buys a *weaker* proof for the *riskier* population, and buys it at the exact place
where the file's own doctrine says the direction of error is corrupting (two workers on one crate
can produce a semantic conflict that compiles and passes, `scripts/dispatch-claim.py:2685-2689`).

The claim-time live re-check (`revalidate_items_against_live_pulls`,
`scripts/dispatch-claim.py:2780`) narrows the window but cannot close it — it re-proves at launch,
not at the sibling's push.

**This is the load-bearing finding.** The rest of the record is cost, and cost alone would not
settle it.

## 3. What the positive proof would cost, itemised

### 3.1 It is a four-leg change, and the legs must move together

`_pull_inactivity_decision` is consumed on four legs, and the repo's own linkage-parity doctrine
(`scripts/dispatch-claim.py:1960-1968`, and sparq#4819 as recorded at
`scripts/plan-snapshot.py:1031-1043`) forbids the two occupancy legs from deciding the same PR
differently:

1. **PLAN attestation** — `inertness_attestation` (`scripts/plan-snapshot.py:1028`), fed by
   `_pr_status_record` (`scripts/plan-snapshot.py:911`).
2. **PLAN→CLAIM projection** — the field-selected row written by `dispatch.yml`
   (`.github/workflows/dispatch.yml:1086-1105`), whose key set is pinned by an executed assertion
   (`scripts/dispatch-claim.py:17851`). A new bit that is not projected is **unreachable in
   production** — precisely the defect round 3 found and this pin exists to catch.
3. **CLAIM assemble** — `filter_busy_area_items` → `busy_packages_of_pulls`.
4. **CLAIM live re-check** — `live_pull_detail_stub` (`scripts/dispatch-claim.py:2754`) over a raw
   `/pulls?state=open` listing. **This leg has no per-PR read at all today**, by design ("zero extra
   pulls-API cost", `scripts/dispatch-claim.py:8006-8011`). It is where the new probe hurts most:
   it would add a per-holder read to the tick's most latency-sensitive step, and a probe added on
   legs 1-3 but not 4 is *inert*, because the live re-check runs last and defers the row anyway.

Also `ABSENCE != NULL` applies to the new bit exactly as it does to `auto_merge`
(`.github/workflows/dispatch.yml:1094-1098`, `scripts/plan-snapshot.py:941-948`): a projected row
that merely *lacks* the queue key must read UNKNOWN, never "proven not queued". That is a third
tri-state to keep coherent across four legs.

### 3.2 GraphQL is a POST, and this repo's read plumbing is GET-shaped

- **No ETag saving.** `plan-snapshot.make_fetch` (`scripts/plan-snapshot.py:695-732`) is a GET
  reader with a cross-tick conditional-request store; #1207 measured 213-222 of 222 per-PR reads
  answering `304`, taking a warm tick from 613 requests to ~190-200
  (`scripts/dispatch-tick-floor.py:248-266`). A GraphQL POST cannot participate: **every probe is
  billable on every tick, forever.**
- **No retry.** `gh_retry` refuses to retry any non-GET `gh api` call
  (`scripts/gh_retry.py:507-534`, asserted at `scripts/gh_retry.py:920-927`), and `_gh_json` on the
  CLAIM leg goes through it (`scripts/dispatch-claim.py:4042-4046`). A transient blip on the probe
  is therefore a **zero-retry** UNKNOWN. That fails closed (correct), but it means the carve-out it
  is supposed to widen would be *off* whenever the probe flakes — buying flakiness for the
  behaviour, not throughput.
- **A second budget bucket.** GitHub meters GraphQL separately from REST, so the probe's spend is
  **not** described by `requests_per_tick` (`scripts/dispatch-tick-floor.py:224-230`) — the model
  the tick floor is derived from. The floor would silently stop describing the tick's true cost
  until a second, GraphQL-denominated accounting is added. *(The exact point cost of the document
  must be measured, not assumed, before any implementation — see §7.)*

### 3.3 The population, and the spare it eats

Measured on sparq-org/sparq 2026-07-27 (paginated open-PR listing, recorded at
`scripts/dispatch-claim.py:12754-12755`): **121 open / 88 draft / 33 non-draft**. A probe on the
non-draft population is ~33 reads per tick against a measured spare of **~102 requests per tick**
(`scripts/dispatch-claim.py:2451-2455`) — ~32% of the spare, paid on **every** tick, to change the
answer for a population that is mostly not parked at all. Batching the document with GraphQL
aliases collapses the request count but not the point cost, and converts 33 independent per-PR
failures into one all-or-nothing read.

## 4. The remedy that reaches the same outcome, with the better fail direction

The carve-out already has a sound path to freeing a parked non-draft holder that requires **no
change to the trust check whatsoever**: **convert the holder to a draft.** Then the existing,
stable, standing proof applies and today's carve-out frees its crates on the next tick, unchanged.

The GraphQL read #1012 asks for is still needed — but as the **guard on that mutation**, which is
where a point-in-time queue read is exactly the right evidence, because it licenses an action taken
*now* rather than a permission that must hold *later*. And it is **already written and self-tested
in this repository**: `REVIEW_STATE_QUERY` / `parse_review_state` / `review_state` /
`draft_skip_reason` (`scripts/backfill-provenance.py:638-734`), with the doctrine spelled out at
`scripts/backfill-provenance.py:578-596` — drafting a queued PR **evicts** it, drafting an armed PR
**un-arms** a merge that passed review, so the probe exists precisely to refuse both, and an
unreadable probe skips the conversion.

Failure directions the probe closes **at the instant it is read**:

| probe answer | action | resulting occupancy |
|---|---|---|
| unknown / unreadable / malformed | **do not convert** | busy — identical to today |
| queued, or armed, or `review:pass` | **do not convert** | busy — and no live merge is evicted |
| not-queued and not-armed | convert to draft | the PR now carries the **draft** proof; the existing carve-out frees it next tick |

That table is **not** a claim that the remedy is race-free, and an earlier revision of this section
wrongly captioned it as one ("all closed"). The probe and the conversion are two separate requests;
§4.1 is the correction, and it is what decides *who executes* the last row.

Three further properties this shape has and the §2 proposal does not:

- **The cost is paid only when it buys something.** The natural trigger is the existing starvation
  sweep, which fires only on a MEASURED starved lane (`planned_items` empty AND `deferred > 0`,
  `scripts/dispatch-claim.py:2494-2526`) and is already paced (`STARVATION_PARKS_PER_TICK_MAX = 12`,
  with an itemised per-action request budget at `scripts/dispatch-claim.py:2474-2485`). That is
  ≤12 probes on a starved tick, not ~33 on every tick.
- **It is a mutation the fleet already knows how to reason about**, not a new class of evidence
  admitted into a reservation predicate. `_pull_inactivity_decision` stays byte-identical, so the
  four-leg parity problem of §3.1 does not arise at all.
- **It is reversible by a human** (press "Ready for review"); a merge into a crate handed to a
  sibling is not.

**Scope constraint — MACHINE parks only.** The action must be restricted to holders carrying
`review:parked` (`park_policy.MACHINE_PARK_PR_LABEL`, `scripts/park_policy.py:117`) and must refuse
any human-owned hold — `needs:user` / `review:needs-user` (`scripts/park_policy.py:119,123`) —
exactly as `park_starved_partition_holder` already refuses them
(`scripts/dispatch-claim.py:6031-6071`), and for the same reason #967 gave: the machine does not act
out of the label that exists to mean "a human decides this one". The measured holder is inside that
scope: registry #677 recorded sparq#3628 as `review:parked` + non-draft, holding `__global__` across
ticks. A human-parked non-draft holder stays busy — which is correct, and is a human's to release.

### 4.1 The probe-to-mutation race — and why the conversion is HUMAN-EXECUTED

`review_state` and the conversion are **two separate requests with nothing binding them**. Between
them the PR can be enqueued, armed, or labelled `review:pass`, and the conversion then does exactly
the damage the probe exists to refuse: `gh pr ready N --undo`
(`scripts/backfill-provenance.py:756`) evicts a live queue entry or un-arms a merge that passed
review (`scripts/backfill-provenance.py:578-596`). Calling the read "point-in-time evidence
licensing an action taken *now*" (§4) quietly assumes `now` is atomic. It is not.

**No compare-and-swap can close it.** This estate's one atomic merge-state primitive is
`enablePullRequestAutoMerge`, whose `expectedHeadOid` is a CAS evaluated at arm time
(`scripts/regate-sweep.py:90-92`). The conversion path has no counterpart — worker-pr says it
outright: "`pr ready` (undraft) carries no CAS" (`scripts/worker-pr.py:5468-5472`). And a head CAS
would be the **wrong** CAS even if one existed: enqueuing, arming and labelling all happen
**without moving the head**, which is precisely why worker-pr re-probes holds on every arm attempt
instead of leaning on `expectedHeadOid` (`scripts/worker-pr.py:5390-5396`), and why the same class
of window is still open as #294 — "no atomic label/base CAS exists"
(`scripts/worker-pr.py:4271-4280`).

**Detect-and-recover is not available either.** After the conversion the queue entry and the
auto-merge request are simply *gone*, so a re-probe cannot distinguish "was never queued" from "I
just evicted it" without a timeline read whose completeness nobody here has demonstrated. And the
repair for either harm is a **re-arm** — an arm-class mutation, human-gated on this estate. A loop
that re-armed to undo its own eviction would be a machine arming a PR, the one thing this fleet
must never do. There is therefore no protocol under which the machine both causes this harm and
safely undoes it.

**What genuinely narrows the window — stated as narrowing, not as closure.** In scope the holder
carries `review:parked`, which is a live hold that `ready_and_arm` aborts on before any
undraft/arm (`scripts/worker-pr.py:4246-4258`, `:5484-5490`). So **no machine in this fleet can arm
or enqueue a holder in scope**; the only actor that can transition it inside the gap is a **human**
— pressing Merge, enqueuing by hand, or unparking and then arming. Narrow. Not zero.

That asymmetry decides the executor rather than the mechanism. §2's objection to #1012's proposal
was that a point-in-time read must not license an outcome that has to hold *later*; here "later" is
milliseconds rather than minutes, but the loss it risks — a reviewed, queued merge destroyed — is
**not machine-recoverable**, while the thing bought is a throughput optimisation the estate
demonstrably survives without (§5). An optional gain must not carry an irreversible-by-machine
downside. **So the machine probes and does not mutate**: on a measured starved lane it surfaces a
pre-validated, human-executable request naming the exact command, and the human's press is atomic
with that human's own observation. That is §6 **(A1)**.

If the maintainer prefers the loop to execute the conversion (§6 **(A2)**), these bind before any
code is written:

1. **A fresh re-probe immediately before the mutation, with nothing between.** The #139 pattern
   (`scripts/worker-pr.py:5468-5490`) — the tightest boundary GitHub's API allows. A probe taken
   earlier in the tick may not license a conversion.
2. **Post-mutation verification that ESCALATES, never repairs.** Re-read after converting; on any
   evidence the PR was queued/armed/`review:pass` at conversion time, apply a human hold and say so
   loudly. Do **not** re-arm, re-enqueue, or un-draft to "put it back".
3. **The residual window is NAMED, not claimed closed** — in the code comment and in the follow-up
   issue, in the shape #294 is named, with its worst case written out.
4. **Mandatory adversarial cases, non-vacuous, both directions**: a queue entry appearing between
   probe and mutation; an arm appearing between probe and mutation; `review:pass` appearing between
   probe and mutation. Each must assert the *implemented* response (refused at the re-probe, or
   detected-and-escalated) and each must go **RED** if the re-probe or the post-mutation check is
   deleted.

## 5. What this leaves unfixed, stated plainly

- A **human-parked** non-draft holder still never frees its crates. By design (§4), not by
  oversight. Its exit is a human.
- A machine-parked non-draft holder that IS queued or armed still never frees its crates. Correct:
  it can merge.
- Nothing here narrows an **unprovenanced** holder's reservation — that is
  `starvation_provenance_escalation`'s territory (`scripts/dispatch-claim.py:2671`) and its named
  recovery is the backfill workflow.
- The measured holder is still **counted and named** every tick after #677, and still does not
  self-heal until the remedy in §4 (or an overrule per §7) is built.
- Under **(A1)** it does not self-heal even then: its exit is still a human press. What the remedy
  buys is that the press becomes one pre-validated click on a measured starved lane instead of a
  diagnosis. Self-healing is what **(A2)** buys, and §4.1 is its price.

## 6. Maintainer decision

Confirm **one**:

- [ ] **(A1) Confirm the recommendation.** `_pull_inactivity_decision` keeps `non-draft` as an
      unconditional BUSY. A follow-up implements the §4 remedy with the conversion
      **human-executed**: the starvation sweep probes with `backfill-provenance.review_state`,
      MACHINE parks only, and *surfaces* the conversion rather than issuing it (§4.1).
      #1012 closes on this record; the follow-up is a separate issue.
- [ ] **(A2) As (A1), but the loop executes the conversion** — accepting the named probe-to-
      mutation window of §4.1 and bound by its four obligations, which are as non-negotiable as
      §7's.
- [ ] **(B) Overrule — build the positive queue proof anyway.** Then §7 binds it.
- [ ] **(C) Neither — leave the hold in place, unremedied.** #1012 closes as `wontfix` and the
      counted/named holder is accepted as the standing cost.

## 7. If the maintainer overrules (B), these bind before any code is written

Non-negotiable, because each one is a place this change can fail open:

1. **Fail closed on unknown, everywhere.** Probe unreadable, errored, partially-rendered
   (`data` alongside `errors`), unexpected shape, absent key, or ambiguous queue state ⇒ **BUSY**.
   Copy `parse_review_state`'s strictness (`scripts/backfill-provenance.py:676-699`); do not write a
   second, laxer parser.
2. **Head-matched, exactly as the detail path is.** The queue read must be bound to the same head
   sha as the listing row it licenses (`scripts/dispatch-claim.py:1661-1665`); a head that moved
   between the reads is UNPROVABLE, never inert.
3. **All four legs of §3.1 in one change**, with the projection key set pinned by the executed
   assertion at `scripts/dispatch-claim.py:17851` extended to the new key, and the new key
   conditionally spread (`ABSENCE != NULL`).
4. **Budget accounting, in the same change.** A GraphQL-denominated cost model, measured not
   assumed, reconciled against `dispatch-tick-floor.requests_per_tick` so the floor keeps describing
   the tick it admits. Pin every measured input by **equality**, per registry #871
   (`scripts/dispatch-claim.py:2464-2472`) — an inequality leaves the understating direction open,
   and that is the direction that already survived a whole green suite once.
5. **Non-vacuous tests.** At minimum: a queued-but-unlatched non-draft stays BUSY; an unreadable
   probe stays BUSY; a head-mismatched probe stays BUSY; and a **positive control** — the one
   posture the change is for actually reads `parked-free` end to end, on both occupancy legs
   independently. A suite that stays green when the probe is deleted from the document has tested
   nothing (`query_selected_fields`, `scripts/backfill-provenance.py:652-673`, exists for exactly
   that mutant).
6. **Do not relax the REST test as a fallback.** If the GraphQL read is unavailable, the answer is
   BUSY. There is no degraded mode in which `auto_merge: null` proves a non-draft inert.
