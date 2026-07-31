# Should `__global__` be an N-slot partition instead of an exclusive one? (#1011)

> 🤖 **SPARQ agent** — design record, 2026-07-31. Maintainer-review document.
> **This record changes no behaviour.** It answers the design question registry #677 point 1 raises
> — *is the serializing partition exclusive because it must be, or only because nobody bounded it?*
> — before any code moves, so the exclusivity is a *decided* property rather than an omission the
> next author widens.
>
> **Recommendation: `__global__` stays EXCLUSIVE (N = 1).** "Bounded N-slot concurrency" is
> ambiguous between two mechanisms (§2); the reading that is nearly safe schedules a population
> that is not runnable and buys ~nothing (§3), and the reading that buys throughput deletes the one
> invariant the partition exists to hold and admits exactly the conflict class this estate has no
> detector for (§4). The answer does not differ per cause — it fails by *proof* on the one
> genuinely-repo-wide cause and by *ignorance* on the other three (§5). The lever that does work is
> cause-NARROWING, which is already the shipped direction and comes with a soundness proof a slot
> count cannot get (§6). §8 is the maintainer's confirm-or-overrule; §9 is what an overrule owes
> before any code is written.

## 1. The question, and one correction to the record it rests on

Registry #677 asks four questions about the serializing partition. Point 1 — carried here as #1011
— asks whether `__global__` should be exclusive **at all**, proposing bounded N-slot concurrency,
and requires a written soundness argument first because this is the partition that decides who may
run concurrently over the arm surface. The `needs:design` label is the hold that keeps it out of
`ready` until a human clears it (`scripts/ready-issues.py:29-31`, gate prefix at `:41`).

**#1011's summary of what already shipped does not match the tree, and the difference matters.**
#1011 says the #677 PR "answered only the terminal-state half (every unknown-crate `__global__`
holder now escalates with its own named recovery)". In the tree:

- What PR #1415 (`30c5bd5c8`, "resolve target issue #677") actually added is the **narrowing** of
  `source-unlisted`, under the banner `[registry #677 point 1]` — `unlisted_source_narrowing`
  (`scripts/dispatch-claim.py:1798`) plus the sixth cause `CAUSE_SOURCE_UNLISTED_NARROWED` (`:547-566`).
- The **escalation** half is registry #772's, not #677's (`starvation_provenance_escalation`,
  `scripts/dispatch-claim.py:2757`), and it does **not** cover every unknown-crate holder: it fires
  on `missing-provenance` **only** and deliberately declines `source-no-areas`, because that holder
  has no provenance recovery to name (`:2782-2784`). So one unknown-crate class — a PR whose source
  issue is known and carries no `area:*` — today neither narrows nor escalates. It is counted, and
  that is all.

Both corrections push the same way: less of point 1's territory has been retired than #1011
assumes, and the residual is *not* the part a slot count would help with (§6).

#1011's own load-bearing finding is confirmed and is not restated at length here: the
"unknown crate vs genuinely repo-wide" distinction is not a throughput lever, because
`GLOBAL_RESERVATION_CAUSES` already draws exactly that line (`scripts/dispatch-claim.py:510-527`)
and it falls the wrong way — `declared-areas` is the only genuinely-repo-wide cause and the other
three are all unknown-crate. §5 shows that this inversion is *why* the per-cause answer is uniform.

## 2. "Bounded N" is ambiguous between two mechanisms with nothing in common

A design that does not name which one it means is unimplementable, so this record names both.

| | **Reading A** — N *global holders* may co-run | **Reading B** — a live `__global__` reservation stops excluding, up to N in flight |
|---|---|---|
| what changes | `packages_conflict(__global__, __global__)` stops being `True` for the first N | `package_conflicts_with_areas` stops being `True` against a global occupant for the first N |
| who gets to run | only *other* `__global__` rows | every deferred row, global or narrow |
| pairs whose footprints overlap | universal ∩ universal — **certain**, every pair, every crate | unknown ∩ known — unbounded, unmeasured |
| what it buys on the measured board | ~nothing (§3) | one extra in-flight row per starved tick (§3) |

**Bounded N already exists in this fleet, and it is not the partition.** `max_concurrent` is a
per-repo policy cap — 40 on sparq, 3 on the registry (`policy/repos.toml:98`, `:143`) — narrowed
live by account headroom (`allocator.dynamic_concurrency`, `scripts/dispatch-claim.py:8679-8681`).
That is a **capacity** governor: it answers *how much work can the account pool sustain*, and being
wrong costs rate limits. The partition is a **correctness** governor: it answers *which pairs of
rows may touch the tree at once*, and being wrong costs a corrupted crate. Point 1 proposes to
convert the second into a second copy of the first. The two failure directions are not comparable,
and a single integer cannot serve both.

## 3. (a) What N buys against the measured board — and the resource it mis-models

**The load-bearing empirical finding: on the measured board `__global__` is held by open PRs'
*reservations*, not by *runnable queue entries*.** `busy_packages_of_pulls`
(`scripts/dispatch-claim.py:1852`) derives occupancy from every open same-repo `sparq-agent/*` PR;
that reservation stands for the PR's whole life, not for a worker's runtime. A slot is a
**dispatch-time admission** primitive. Under Reading A it would schedule holders that are not
waiting to be admitted — they are already open, mostly inert, and hold their crates regardless.

Measured, all of it already in the tree:

| measurement | value | where |
|---|---|---|
| executed sparq ticks 2026-07-27..28 carrying a `__global__` reservation | **14 of 101** | `scripts/dispatch-claim.py:18376-18380` |
| — of which `source-unlisted` | **7**, and **6 of those 7 were the same PR** (sparq#3620) on six consecutive ticks | same |
| that whole class after PR #1415 | **narrowed away** — it no longer holds `__global__` | `:1798`, `:547-566` |
| registry ticks 2026-07-27 planning 0 items behind an unprovenanced holder | **5 of 84**, three PRs, still recordless 16h/8h/4h later | `:2766-2769` |
| widest co-occurring starved `__global__` board ever measured | **4 holders** (2026-07-27 20:12:40Z–20:47:36Z), all provably **inert** | `:2574-2577` |
| observed outage from that window | **~55 min** | `:2544-2545` |

Read against the two readings:

- **Reading A buys ~0.** Six of the seven largest-residual ticks were *one* holder — a slot count
  of 2 has nothing to put in the second slot. The one window where holders genuinely co-occurred
  (4 of them) is the window where every holder was a provably-inert draft: the thing that frees
  that partition is **parking** them, which the sweep already does and which actually releases the
  crates (`starvation_park_targets`, `:2580`; the inertness clause at `:2596-2602` exists precisely
  because parking an *active* holder writes a label and frees nothing).
- **Reading B buys at most one extra in-flight row per starved tick**, on a residual of ≤7/101
  sparq ticks (~7%) and 5/84 registry ticks (~6%), and only while the deferred backlog is non-empty.

**The honest counterweight, stated so this section is not one-sided:** the outage is real. ~55
minutes of a lane at zero with a live backlog is not nothing, and the estate built two sweeps and a
tick-floor argument around it. The claim here is not "there is no problem". It is that the measured
problem is *inert open PRs holding a partition*, and a dispatch-admission slot count is not an
instrument that touches that population — while the sweeps, the narrowings, and upstream area
labelling all are.

## 4. (b) What conflict class N > 1 admits, and why nothing in this estate detects it

**The invariant today, stated exactly.** Any two concurrently dispatched rows have **provably
disjoint area sets**. A partition key names a set; two keys exclude iff their sets intersect;
`__global__` is the universal set and anything unreadable reduces to it
(`scripts/lease_schema.py:86-102`, `:105-117`). One predicate decides this at all four enforcement
sites — the PLAN assemble filter (`filter_busy_area_items`, `scripts/dispatch-claim.py:2385`), the
CLAIM live re-check (`revalidate_items_against_live_pulls`, `:2866`), the cross-lane ledger view
(`sibling_lease_conflict`, `:994`), and the allocator (`partition_available`,
`scripts/select-and-claim.py:747-772`).

N > 1 does not weaken that invariant. It **deletes** it for the admitted pairs — and under Reading
A it deletes it for the pairs where overlap is not a risk but a certainty, since both operands are
the universal set.

**The detection ladder, and where each rung stops.**

1. **Textual conflict** — caught by git, repaired by `scripts/resolve-conflicts.py`, which is
   explicitly *non-semantic* ("syntax-only parsing of changed Python and YAML blobs before the
   push; semantic validation belongs to CI", `:1-11`) and stands off `needs:design` and
   `trust-surface` PRs entirely (`HARD_EXCLUDE_LABELS`, `:47-53`).
2. **A green gate that graded a tree the co-tenant has since changed** — caught, but only because
   someone built the detector. Registry #940 **measured** two PRs reading MERGEABLE/CLEAN with a
   green `gate` that "would each have reddened `gate` for every subsequent PR, because master moved
   under them after their gate ran"; `pr-gate.yml` fires only on `pull_request` events and this repo
   has **no merge queue**, so nothing re-derives the green (`scripts/worker-pr.py:4908-4919`). The
   detector is `gate_freshness` (`scripts/dispatch-claim.py:4512`) and the consequence is a bounded
   deferral. It fails closed, and it is evidence *for* this record's direction: even with the
   partition serializing, "CI is green" was already not a statement about the tree that would
   merge. N > 1 multiplies the population that rests on it.
3. **The class neither rung reaches**: two edits to the *same crate*, textually disjoint, each
   individually correct, each green on a post-merge base, **jointly wrong**. This file names it as
   the corrupting direction in its own words — "two workers on one crate can produce a semantic
   conflict that compiles and passes" (`scripts/dispatch-claim.py:2771-2775`, restated at
   `research/1012-parked-non-draft-queue-membership.md` §2) — and it is exactly why
   `busy_packages_of_pulls` fails closed on an unknown footprint.

No gate grades that class, and **no reviewer reads it either**: review is per-PR, cross-provider,
against that PR's own diff. The *pair* is nobody's artifact. So the class N > 1 admits is precisely
the class this estate cannot observe — the failure would surface as a defect in a crate, days
later, with no receipt naming the co-tenant that produced it.

**Arm-adjacency, which is why this is not merely a throughput trade.** `__global__` is by
construction the partition of rows whose footprint is *unknown*, and "unknown" includes the trust
surface: nothing tells the dispatcher that a global holder is *not* editing `policy/`, `scripts/`
or `.github/workflows/`. Two co-admitted unknown-footprint workers can therefore both be mid-change
on the arm path, and under Decision 7 an approved trust-surface change auto-arms. The reviewer that
approves each one sees one diff and cannot see the other. Exclusivity is what makes "who may run
concurrently over the arm surface" a decidable question at all.

## 5. (c) Does the answer differ per cause?

No — but for two *different* reasons, and the asymmetry is the reason the taxonomy cannot license
slots on either side of itself.

| cause | footprint | why N > 1 fails | narrowing available? |
|---|---|---|---|
| `declared-areas` (`:520`) | **KNOWN, and it is everything** | overlap is **certain**: two universal sets intersect on every crate. Unsound by proof. | none — nothing to narrow |
| `missing-provenance` (`:521`) | UNKNOWN | overlap probability is unmeasured and unmeasurable from inside the dispatcher. Unsound by ignorance. | shipped (sparq#4821) where the PR's own labels bound it |
| `source-unlisted` (`:522`) | UNKNOWN | same | shipped (#1415, `:1798`) |
| `source-no-areas` (`:523`) | UNKNOWN | same | **deliberately not** — see below |

This is the inversion #1011 identified, carried to its conclusion: the only cause where the
footprint is *known* is the one where concurrency is provably wrong, and the causes where it is
unknown are the ones where no bound can be derived. A distinction that separates "certainly
overlapping" from "unknown" is not a licence in either direction.

Two live sub-cases worth naming so a later author does not rediscover them as bugs:

- A PR wearing the literal `area:__global__` label is a **declared** universal footprint and is
  routed to `source-unlisted`, not to the narrowed cause, precisely so the closed-enum census still
  accepts it (`scripts/dispatch-claim.py:18429-18447`). Co-admitting that row is a declared
  collision, not an inferred one.
- `source-no-areas` is not narrowed **on purpose**: the source issue is known and already reserves
  `__global__` on the PLAN side, so narrowing only the PR half would desynchronise the two
  occupancy legs — the linkage-parity failure the two legs share one function to avoid
  (`:18412-18419`, `:1803-1809`). Its lever is upstream (§6), not in the partition.

## 6. What does buy throughput here, with a soundness proof attached

**Cause-narrowing, which is monotone in the safe direction.** A narrowing converts a global holder
into a *set* holder using evidence that PROVES the footprint — the PR's own path-derived `area:*`
labels — so the disjointness invariant of §4 survives intact rather than being suspended. That is
the difference between the shipped direction and a slot count: narrowing buys concurrency **by
adding evidence**, slots buy it **by removing a check**. The ledger figures say it also works: the
`source-unlisted` narrowing alone retired 7 of the 14 global-carrying ticks, and the earlier
multi-area reduction retired 65 of 468 ready issues (13.9%) that had been self-blocking
(`scripts/lease_schema.py:41-44`).

What remains, with honest ceilings:

- **`source-no-areas` → label the source issue.** This is the one materially unexploited lever, and
  it is upstream of the partition entirely. `research/809-area-derivation-feasibility.md` measures
  the shipped deriver at **92.6% precision held out (137/148)** — but it **fires on only 148 of 506
  rows** and declines 370, and that record is explicit that the residual is "the class of issues
  that genuinely span several surfaces". So this lever is real, sound, and **partial**; it is not a
  substitute for the partition and it must not be sold as one.
- **`missing-provenance` → backfill.** Already counted, capped and named, with the recovery
  workflow spelled in the escalation body (`scripts/dispatch-claim.py:2757`, `:2820`).
- **Inert holders → park them.** The only remedy that actually releases crates, and it releases
  them *legitimately* (`:2580`, `:2596-2602`).
- **`declared-areas` → nothing.** A genuinely repo-wide change serializing is the partition working
  as designed.

## 7. The honest cost of this recommendation

- **Global holders keep serializing.** On ~7% of sparq ticks and ~6% of measured registry ticks the
  lane runs at zero against a live backlog, with an observed ~55-minute window. This record does not
  fix that; it argues the fix is elsewhere.
- **An ACTIVE, provenanced, area-less-source holder blocks the lane for its whole lifetime.** The
  park sweep declines it (parking an active holder frees nothing), the escalation sweep declines it
  (no provenance recovery), and §6's remedy is upstream and only ~29% recall. That is a real gap,
  owned by `source-no-areas`, and naming it is part of this record's job.
- **Refusing slots also refuses the cheap experiment.** The only way to measure the true overlap
  rate is to admit the overlap. That asymmetry *is* the argument: the experiment's failure mode is
  a silent semantic corruption in a crate, discovered late, in a fleet where the artifact merges
  automatically on approve.

## 8. Maintainer decision

Confirm **one**:

- [ ] **(A) Confirm the recommendation.** `__global__` stays exclusive; `packages_conflict` keeps
      the universal-set semantics unchanged. #1011 closes on this record. The throughput work
      continues as §6 — narrowing where evidence proves a footprint, upstream area labelling for
      `source-no-areas`, and the existing sweeps — each a separate issue.
- [ ] **(B) Overrule — build bounded N anyway.** Then §9 binds it, starting with naming Reading A
      or Reading B, and it does not begin until §9.2 (the detector) is answered.
- [ ] **(C) Neither.** Leave point 1 open and unremedied; the counted holders stay the standing
      cost.

## 9. If the maintainer overrules (B), these bind before any code is written

Non-negotiable, because each is a place this change can fail open:

1. **Name the reading.** A (global-vs-global only) or B (global-vs-everything), in the issue title.
   They share no code, no cost model and no soundness argument, and a design that leaves it implicit
   will be implemented as B by accident, because B is the one that changes the measured number.
2. **Supply the detector for §4.3, or prove the class empty — measured, not assumed.** "CI is
   green" is disqualified by registry #940's own measurement. If the answer is "review catches it",
   say which reviewer reads *both* diffs, and note that today neither does.
3. **One predicate, all four sites.** `lease_schema.packages_conflict` is THE predicate. A slot
   admitted at PLAN and not at `partition_available` plans work the allocator then refuses —
   `package-single-flight` every tick, forever, which is the failure that predicate was unified to
   prevent (`scripts/select-and-claim.py:756-760`).
4. **Say where the slot count lives, and how a PR-derived reservation consumes one.** The ledger is
   the only serialized state in this system (CAS over `data/leases.json`), so N is countable inside
   a lease transaction. But §3's population is **open-PR occupancy, which is not in the ledger** — a
   slot scheme that counts only leases bounds nothing about the holders that were actually measured
   and ships a number that describes no observed outage.
5. **Fail closed on an unknown N.** An absent, unreadable or malformed slot count reduces to
   **N = 1**, never to "unbounded" and never to a permissive default. Same direction as
   `package_areas` returning the universal set for anything it cannot parse.
6. **Non-vacuous tests, both directions.** At minimum: the (N+1)th global row **defers**; a
   malformed count defers **everything**; narrow rows are still excluded by a global occupant
   (positive control on the invariant that is *not* being relaxed); and the suite goes **RED** when
   the cap is deleted, not merely when it is mis-set. A suite that stays green with the slot check
   removed has tested nothing.
7. **A co-tenancy receipt.** Whenever two rows are co-admitted over `__global__`, both PR numbers
   are recorded on both PRs, durably and bot-authored. If §4.3's class is ever real, that receipt is
   the only thing that will let anyone find it — and if the maintainer is unwilling to pay for the
   receipt, that is itself the answer to whether the class is acceptable.

## 10. What this record does not decide

It does not decide #1012's remedy for parked non-draft holders, does not propose changing
`max_concurrent` or the tick floor, does not re-open either shipped narrowing, and does not propose
new labelling automation for `source-no-areas` (§6 names the lever; sizing it is that issue's job).
It does **not** claim this estate's semantic-conflict rate is zero — only that nothing in the tree
measures it, that the one adjacent thing that was measured (#940) went the wrong way, and that
admitting the overlap is the wrong instrument for finding out.
