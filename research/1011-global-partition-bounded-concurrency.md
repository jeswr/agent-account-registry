# Should `__global__` be exclusive at all? — bounded N-slot concurrency (#1011 / #677 point 1)

> 🤖 **SPARQ agent** — design record, 2026-07-31. Maintainer-review document.
> **This record changes no behaviour.** #1011 (split out of #677) says in its own body that point 1
> "needs a written soundness argument before any code moves" and "do NOT implement without that
> record". This is that record. It answers the three questions #1011 asks — (a) what N buys against
> the measured board, (b) what conflict class `N > 1` admits and how it is detected, (c) whether the
> answer differs per cause — and it names the one thing #1011 does not: **"N-slot concurrency" is
> two different changes**, and the reading that is *bounded* buys nothing while the reading that
> buys something is *not bounded*.
>
> **Recommendation: NO — `__global__` stays exclusive, and N is not the lever.** §7 is the
> maintainer's confirm-or-overrule; §8 is what an overrule owes before any code is written.

## 0. State of the tree, and the provenance of every number below

Written against `master` @ `bf62eab70` (2026-07-30T23:15:36Z). The partition is decided in five
places and this record cites all five by line:

| what | where |
|---|---|
| the reduction: areas → partition key | `scripts/lease_schema.py:32` (`plan_package`), `:86` (`package_areas`) |
| **the** exclusion predicate | `scripts/lease_schema.py:105` (`packages_conflict`), `:120` (`package_conflicts_with_areas`) |
| PLAN-side assemble filter | `scripts/dispatch-claim.py:2294` (`filter_busy_area_items`), `:1778` (`busy_packages_of_pulls`) |
| CLAIM-side allocator | `scripts/select-and-claim.py:747` (`partition_available`), `dispatch-claim.py:974` (`sibling_lease_conflict`) |
| the target's own readiness engine | `scripts/ready-issues.py:154` (`packages_of`), `:164` (`_pr_reserving_packages`) |

> **NOTHING IN THIS RECORD WAS FRESHLY MEASURED.** The authoring container is offline and holds no
> token, so every figure here is **re-cited from an in-tree measurement that carries its own
> instant and population**, and is named as such at the point of use. Two consequences the reader
> must hold: (i) each figure is only as current as its own snapshot — the pair-collision table at
> `dispatch-claim.py:1696-1722` already records one re-measurement moving `area:ci` from 5% to
> 9.2% on a later board; (ii) the **one number this decision would need in order to size N has
> never been measured at all** (§8.1), and this record does not pretend otherwise.
>
> The recommendation therefore does **not** rest on those figures. It rests on §3.1, which is a
> **structural** claim about the deciding predicate — checkable by reading
> `partition_defer_attribution` (`dispatch-claim.py:2022`) and needing no board at all. The
> measured figures only size the *cost* side (§4.2).

## 1. The question — and the ambiguity that has to be resolved first

#677 point 1 asks whether the serializing partition should admit **bounded N-slot concurrency**:
`N` holders of `__global__` in flight at once instead of one. Before it can be answered, "N slots"
has to be pinned down, because it names two changes with completely different blast radii.

Today `__global__` is the **universal set**, not a lock: `package_areas("__global__")` is `None`
meaning *every area* (`lease_schema.py:86-104`), and `packages_conflict` returns True whenever
either side is universal (`:105-118`). Exclusivity is therefore not a separate rule that could be
relaxed by a counter — it is a **consequence of set intersection over a set that contains
everything**. So:

- **Reading (A) — "a global reservation stops excluding, and the number of global holders is
  capped at N."** The cap is on holders; narrow rows co-run with a global holder freely. This is
  the reading that would clear the measured starvation (§3.2) — and it is **not a bound on the
  hazard**, because the hazard is a global holder overlapping *narrow* work, and reading (A) puts
  no bound on how many narrow rows run alongside it. `N` bounds the wrong axis.
- **Reading (B) — "global holders serialize against each other up to N; every other exclusion is
  unchanged."** This is the literal reading of "N-slot concurrency", it is the only one whose
  bound binds the thing it names, and it is **structurally inert on any live board** (§3.1).

#1011's own framing — *"with N > 1, two `__global__` holders can be in flight over the same crate"*
— is reading (B). The rest of this record answers both, because a maintainer who reads "N-slot
concurrency buys nothing" (true of B) must not then reach for (A) as the fix.

## 2. `__global__` never means "genuinely repo-wide" — but it does not always mean "footprint unknown"

This is the load-bearing premise for (b) and (c). Its first half is stated by the code itself
rather than inferred; its second half has an exception that an earlier draft of this record
flattened, and §2.1 states it. `plan_package` (`lease_schema.py:48-55`):

> **ZERO AREAS STAYS `__global__`, and that asymmetry is the whole safety argument.** An unlabelled
> row's true footprint is **UNKNOWN**, so it must keep reserving everything; narrowing it to
> "nothing" would make an item whose blast radius nobody can name concurrent with all work at once.

Neither side of the partition reaches `__global__` because the work is *genuinely* repo-wide:

**ROW side** (a dispatch candidate). `plan_package` returns `__global__` for **zero** areas and for
an unreadable key; two or more areas reduce to the composite `{A,B}` since #112. So a global ROW is
exactly an issue nobody has labelled. `ready-issues.py:550-552` pins both halves — a lone global row
is ready, and a global row serializes a labelled sibling out of the same tick.

**OCCUPANCY side** (an open worker PR). The four declared causes (`dispatch-claim.py:520-528`).
The fourth column is the one an earlier draft of this record did not ask, and §2.1 is what the
answer costs:

| cause | what it means | genuinely repo-wide? | footprint evidence at decision time? |
|---|---|---|---|
| `missing-provenance` | no admissible record **and** the PR declares nothing | no | **none, by construction** (`:1925-1942` peels every PR that *does* declare areas off into `missing-provenance-narrowed` before this branch is reached) |
| `source-unlisted` | valid record, source issue closed/unlisted | no | **possibly PR-side.** `areas` is already seeded from the PR's own `area:*` (`:1900-1901`) and `:1922` unions `__global__` on top **regardless**. Source side unavailable (issue closed) |
| `source-no-areas` | valid record, source issue open, carries no `area:` | no | **possibly PR-side**, same seed; source side absent by *observation*, not unknowable (`:1918`) |
| `declared-areas` | the reservation came from real `area:*` labels | **see below** | n/a — structurally near-empty |

#1011 already found that this is 3-to-1 against the throughput reading of #677's proposed
"unknown crate vs genuinely repo-wide" distinction. **It is stronger than 3-to-1: the fourth bucket
has no reachable population either.** `cause` is initialised to `declared-areas` and is only
*changed* on the three branches above (`dispatch-claim.py:1906-1978`), and
`global_reservation_census` (`:2581`) counts a row only if `__global__` is in the areas it
*reserves*. Those two facts compose to: a `declared-areas` row can hold `__global__` **only if some
label is literally `area:__global__`** — a spelling `plan_package` absorbs by construction
(`lease_schema.py:71-84`), that `SAFE_AREA`/`SAFE_PACKAGE`/the resolve gates reject, that no
deriver mints, and that `dispatch-claim.py:1933-1941` records as absent from sparq's 99 labels.

**So on today's boards there is no genuinely-repo-wide `__global__` holder to trade against** — a
repo-wide change arrives wearing several `area:` labels and reduces to a *composite*, which is
narrow and already concurrent with disjoint work. The distinction #677 hoped to spend does not
merely fall the wrong way; **one side of it is empty.**

### 2.1 The two globals: safety-driven and linkage-parity-driven

What does **not** follow — and what an earlier draft of this record wrongly asserted as "100% of
`__global__` holders are unknown-crate holders" — is that every global holder's footprint is
*unmeasurable*. Reservation **shape** and footprint **evidence** are different things, and
`busy_packages_of_pulls` decides them at different places:

```
areas = {PR's own area:* labels}          # :1900-1901  — evidence, may be non-empty
...
areas |= issue_areas or {GLOBAL_PACKAGE}  # :1918  source-no-areas  — union, never a replacement
areas |= {GLOBAL_PACKAGE}                 # :1922  source-unlisted — unconditional
```

So an occupancy row may be `{__global__, crate_a, …}`: it holds the universal key **and** carries
machine path-derived atoms that name part of its footprint. Two populations, not one:

- **Safety-driven global** — nothing names the footprint, so the universal key is the only honest
  answer. This is `missing-provenance`'s residual *by construction*: the `elif areas and
  GLOBAL_PACKAGE not in areas` guard at `:1925` has already taken every PR with usable PR-side
  areas, so a row reaching the `else` at `:1944` declares **no footprint-naming area at all**. (The
  guard's second clause admits one other entrant — a PR wearing the literal `area:__global__` — but
  that is the spelling §2 shows no producer mints, and it names nothing either way.)
- **Linkage-parity global** — the footprint may be partly named, and the row is global anyway
  because **the other leg has not moved**. `source-unlisted` says so in the code comment at
  `:1922-1923` (*"the enumerator still emits this PR as `__global__` — mirror it"*) and this record
  says so itself in §5 and §9: it can be narrowed once both legs move together. `source-no-areas`
  is global because the *source* side is unlabelled, while the PR side may still declare.

**How large each population is has not been measured** (§8.1), and it is target-dependent: a target
with no PR-area deriver produces no PR-side evidence at all, so *every* holder there is
safety-driven. This repository is such a board — 40 of 41 open PRs declare no `area:` label
(`:1815-1819`, measured 2026-07-29; the one exception is hand-applied, not derived). sparq runs
`scripts/pr-area-labels.py`, so its linkage-parity population may be non-zero — **that is a may,
not a measurement** (§8.1). The rest of this record is written so that **it does not depend on
which**: §4.1 shows `N` is the wrong lever for the safety-driven population because overlap is
unmeasurable, and §5 shows `N` is the wrong lever for the linkage-parity population because
*narrowing* dominates it.

## 3. (a) What N buys against the measured board

### 3.1 Reading (B) releases a population that is empty on any board with a labelled occupant

`partition_defer_attribution` (`dispatch-claim.py:2022-2130`) is the deciding predicate, and its
precedence is explicit (`PARTITION_DEFER_REASONS` at `:2018`; the enum descriptions at
`:2003-2013`):

```
1. `__global__` in busy          -> global-reservation   (defers EVERY row, whatever its crate)
2. row's package is __global__   -> cross-cutting-item   (ANY live reservation defers it)
3. row's areas ∩ busy ≠ ∅        -> crate-conflict
4. a live sibling lease          -> sibling-lease
```

Under reading (B), rule 1 stops applying **to global rows only** while fewer than N global holders
are in flight; narrow rows keep being deferred by rule 1 exactly as today, because a global
occupant still reserves every area. So the set of rows reading (B) can newly keep is:

> rows whose **own** package is `__global__` (i.e. zero-area ready issues), on a tick where the
> count of global occupants is `< N` **and rule 2 does not fire** — i.e. where **no busy occupant
> reserves any narrow atom at all**.

That second condition is the one that kills it. `busy` is the union over every busy occupancy row
of the atoms it reserves (`busy_packages_of_pulls:1978-1996`), so it is narrow-free only if *every*
open worker PR that is not `ci`/`docs`-exempt (`NON_RESERVING_PARTITIONS`, `:1733`) reserves
`__global__` and nothing else — **including the global holders themselves**, which contribute their
own narrow atoms too wherever the PR or its source issue carries any `area:` label
(`areas |= issue_areas or {GLOBAL_PACKAGE}`, `:1918`). Against the boards this repo has
actually recorded:

- sparq, the pair-collision snapshot (`dispatch-claim.py:1704-1708`): **7** `area:deps` holders plus
  a crate-area population, none of them exempt — every one of them a narrow atom in `busy`.
- the 101-tick census (`:1838-1848`): **14** ticks carried a `__global__` reservation, so **87** did
  not. On those 87 the busy union is narrow by definition, and reading (B) has nothing to release
  because rule 2 defers every global row against any of it.

**A board with zero narrow occupants is a board with essentially no open worker PRs — which is a
board that was not starved.** So reading (B) is inert precisely when the lane is congested, which
is the only time anyone would want it.

**The honest form of this claim.** What is *structural* is the shape of the release population — it
follows from the predicate at `:2022-2130` and needs no board. What is *not* measured here is
whether any of those 14 global-reserving ticks was **also** narrow-free, which is the only way the
population is non-empty. §8.1 states that measurement, and the burden of taking it sits with an
overrule rather than with this record: the change is inert unless it is non-zero.

The one board where it would have fired is registry **#75** — *4 no-area issues froze the entire
sparq frontier, 48 planned → 0 launched every tick* (`ready-issues.py:169-173`). With `N = 4` that
tick launches all four. That is not an argument for N; it is §4's worked example: four items whose
blast radius **nobody can name**, launched concurrently, giving `C(4,2) = 6` unknown-vs-unknown
pairs at once.

### 3.2 Reading (A) does clear the measured stall — by deleting the guarantee, not by bounding it

The measured stall is a **rule-1** stall. `dispatch-claim.py:2392-2410` records it: `assemble-census`
read `kept=0` on four consecutive executed ticks (2026-07-27 20:12:40Z → 20:47:36Z), **every row
deferred by `reason.global-reservation`**, zero impl workers launched. That reason means the row was
dropped by a *global occupant* **whatever the row's own crate was** — the enum says so in as many
words: "`global-reservation` … **THE ROW'S CRATE IS NOT CONTENDED**" (`:2004-2005`). Clearing that
stall therefore means admitting rows the occupant's reservation covers, and on any ordinary frontier
almost all of them are narrow.

Releasing those rows means letting narrow work run **concurrently with a holder whose footprint is
unknown, or at best partly named while it still reserves the universal key** (§2.1). That is not
"bounded N-slot concurrency". It is the direction `plan_package`,
`_pr_reserving_packages`, `_legacy_global_minting` (`:580-600`) and `non_reserving_partitions`
(`:1736-1776`) each independently refuse, in the same words — *an item whose blast radius nobody
can name becomes concurrent with all work at once* — and it is the direction #1011 itself names as
corrupting. `N` does not make it bounded: `N` caps the unknown holders, while the co-running narrow
rows are uncapped (the whole frontier, 48 of them on the #75 board).

### 3.3 The stall class N would be bought for is already owned, by an action that admits no concurrency

#677/#822 already shipped the repair for exactly the measured board: `starvation_park_targets`
(`:2489`) parks **every** provably-inert unparked `__global__` holder in one tick, capped at
`STARVATION_PARKS_PER_TICK_MAX = 12` (`:2481`) against a widest-measured board of
`MEASURED_STARVED_HOLDER_BOARD = 4` (`:2486`) — so the measured outage drains in **one** 10-minute
tick rather than four. It fires only on `planned_items == []` **and** `deferred > 0`, so it cannot
cost throughput it did not first prove was zero.

That matters for the trade #1011 is really being asked to price: the throughput N would buy is
throughput the fleet **already has**, bought by *removing* a holder rather than by *admitting a
second one*. The residual N could add on top is the §3.1 population — empty.

## 4. (b) The conflict class `N > 1` admits, and how it is detected

### 4.1 The class

Under either reading, the admitted class is: **two in-flight branches editing the same crate, where
at least one of them has no nameable footprint.** Its worst member is the one #1011 names — a
*semantic* conflict: both branches merge cleanly, both compile, both pass CI, both pass an
independent cross-provider review, and the composition is wrong. Nobody's diff is wrong; the pair
is.

**The soundness argument, stated as plainly as it can be:**

> `N` bounds the **cardinality** of the set of global holders in flight. The hazard is the
> **overlap** between their footprints. A bound on cardinality is not a bound on overlap unless the
> footprints are known to be disjoint. For a **safety-driven** holder (§2.1) they are not known at
> all, so **there is no value of `N > 1` for which the overlap is bounded** — the quantity being
> bounded is unmeasured at the moment the scheduling decision is made. `N = 1` is not a tuning
> choice; it is the only value at which the unknown quantity cannot be multiplied.

**And `N` does not get better on the population that does have evidence — because `N` never reads
it.** A slot counter admits a pair by *count*; it does not consult either holder's atoms. Two facts
make that decisive:

1. **The predicate erases the distinction the counter would need.** `packages_conflict` returns
   True whenever either side is universal (`lease_schema.py:105-118`), so `{__global__, crate_a}`
   and `{__global__}` are the *same row* to every enforcement site. A cardinality rule sitting on
   top of that predicate cannot tell a linkage-parity holder from a safety-driven one, so it admits
   both on the same counter — buying whatever the evidence-bearing pairs are worth **and** the
   evidence-free pairs at the same time.
2. **Where the evidence exists, narrowing strictly dominates `N`.** Narrowing turns the row into a
   *composite*, which is concurrent with disjoint work already (#112) and still excluded from
   overlapping work by the unchanged predicate. `N` buys the same concurrency by switching the
   exclusion off instead of by resolving the unknown — same throughput, guarantee deleted. There is
   no board on which `N` beats narrowing on the linkage-parity population; §5 ranks that work.

This is why the answer cannot be recovered by picking a small N. Going from `N = 1` to `N = 2`
takes the number of unbounded-overlap pairs from **0** to **1**. Every increment after that is
arithmetic; the first one is the whole decision.

### 4.2 The base rate, and what it is honestly worth

The best in-tree estimate of how often two in-flight branches share a file is the table at
`dispatch-claim.py:1696-1722` (sparq, snapshot reproducing dispatch run 30405421829; pairs are
`nCr` over holders, no exclusions):

| population | pairs sharing ≥1 changed file |
|---|---|
| `area:ci` (30 holders, 435 pairs) | 9.2% |
| `area:docs` (36 holders, 630 pairs) | 4.8% |
| `area:deps` (7 holders, 21 pairs) | **100%** — every pair collides on `Cargo.lock` |
| crate areas | **57.1%** (sparq `research/crate-region-parallelism.md` §4) |

**Honesty about this number, and it lands differently on the two populations of §2.1.** 57.1% is
measured over PRs that carry crate `area:` labels.

- Against **linkage-parity** holders that carry PR-derived `area:*`, that is the *same* kind of
  population, so the figure applies about as directly as any in-tree figure can. It is evidence
  **for** the hazard on the population #677 would most want to release, not against it.
- Against **safety-driven** holders it is a **different** population — they carry no labels by
  construction — so there it is an **estimate, not a bound and not a measurement of the admitted
  class**. It is the best available because those holders are drawn from the same work
  distribution; it could be wrong in either direction.

Used only as an order of magnitude, it says: at `N = 2` roughly **one in two** concurrent global
pairs would touch a shared crate area, and on the #75 board (`N = 4`, 6 pairs) the expectation is
~3.4 colliding pairs per tick. The `deps`/`Cargo.lock` row says the floor is worse than that: some
shared files are touched by *everything*, at 100%.

### 4.3 The detectors that exist, and what each one misses

| detector | sees | misses the admitted class because |
|---|---|---|
| git merge / `resolve-conflicts.py` | textual overlap on the same lines | it is **non-semantic by design** — "This program never imports target code, runs tests, invokes hooks… **semantic validation belongs to CI**" (`resolve-conflicts.py:7-11`). A clean rebase is not a correct composition. |
| `pr-gate` / CI | what compiles and what the tests assert | the class is defined by *passing*. And a `CONFLICTING` PR gets **no `pr-gate` run at all** while it conflicts (registry #853, cited at `reconcile-conflict-park.py:9-10`) — so the one signal that does fire suppresses the other. |
| the cross-provider review lane | **one diff, against base** | the sibling is not in the reviewer's context. Two reviewers each correctly approve; nobody reviews the pair. |
| the partition itself | the conflict, *before* it exists | this is the detector. Reading (A) or (B) is the proposal to switch it off. |

**There is no detector for the class `N > 1` admits.** That is the disqualifying fact, and it is
not repairable by adding an alarm downstream: a semantic conflict that compiles and passes is only
detectable by *review of the composition*, which nothing in the estate performs.

### 4.4 The throughput accounting is worse than neutral

Admitted overlap that manifests as a textual conflict is not free — it lands in the lane the fleet
has twice measured as its own bottleneck. `reconcile-conflict-park.py:12-20`: **14 of 34** open
registry PRs carried `needs:user`, **12 of them machine-applied by the resolver**, 11 through a
timeout branch, and a resolver-escalated PR "can never again be touched by the resolver… It decays
in a state only a human can exit." `resolve-conflicts.py:36-41` re-measures the same edge:
**17 of 17** conflicting open PRs dropped at one predicate, production running `attempted:0`.

So the trade is: buy dispatch slots now, pay in conflicts that route into a lane whose measured
exit rate is near zero and whose terminal is a human. A throughput change whose failure mode
consumes more review capacity than the dispatch it bought is **negative-sum**, and this one's
failure mode is the expensive kind.

## 5. (c) Does the answer differ per cause?

**No — but not because the causes are alike.** The *answer* is NO for all four; the *reason* is
not the same one four times, and an earlier draft of this record collapsed them by asserting every
holder's footprint was unmeasurable. Taking the causes one at a time, in the order #1011 asks, with
the §2.1 split made explicit:

| cause | population | global is… | why N is still no |
|---|---|---|---|
| `declared-areas` | structurally near-empty (§2 — requires a literal `area:__global__`) | n/a | **no population to concede to.** A genuinely repo-wide change wears several `area:` labels and is a *composite*, already concurrent with disjoint work since #112. |
| `missing-provenance` | already narrowed wherever the PR's own path-derived labels bound it (#4821, `:1926-1946`); the residual declares nothing at all | **safety-driven** | §4.1 in its unqualified form. The residual is unknown-ness in its purest form: overlap is unmeasurable at decision time, so cardinality cannot bound it at any `N > 1`. |
| `source-unlisted` | **the single largest residual** — 7 of the 14 `__global__`-reserving ticks over 101 executed ticks (2026-07-27 12:54Z – 2026-07-28 14:52Z, `:1838-1848`) | **linkage-parity** (`:1922`) — PR-side `area:*` may already be in the row | §4.1's dominance leg: where evidence exists the repair is *narrowing*, which buys the same concurrency with the exclusion predicate intact. Blocked only on doing both legs together (`enumerate_review_items` still emits the same PR as `__global__`; splitting them is the LINKAGE PARITY failure). Where the evidence does *not* exist it falls back to the safety-driven case. |
| `source-no-areas` | source issue open, unlabelled | **linkage-parity** on the source side (`:1918`); PR side may declare | narrowing the occupancy leg alone buys nothing — the in-progress source issue reserves `__global__` on the PLAN side anyway under the unchanged candidate-side `packages_of` (`ready-issues.py:154-161`). What it needs is an `area:` label on the issue, not a second slot. |

**Why the answer nonetheless does not differ.** `N` sits on top of `packages_conflict`, which sees
only "is either side universal" (§4.1, point 1). It therefore cannot admit the linkage-parity
population without admitting the safety-driven one on the same counter, so it must be priced
against the worse of the two.

**How far that carries, stated honestly.** The only board whose PR-label population this record can
cite is *this* repository, where the safety-driven share is everything (40 of 41 declaring no
`area:`, `:1815-1819`, 2026-07-29). **Whether sparq's global holders are safety-driven, linkage-parity,
or a mix has not been measured here** — the 7-of-14 `source-unlisted` figure counts ticks by cause,
not by whether those PRs carried their own derived labels. So the pricing argument above is
load-bearing on this board and *conditional* on sparq. It does not need to be unconditional: if a
target's safety-driven count turned out to be zero, `N` would still lose there on §4.1's dominance
leg alone, because narrowing buys the same concurrency with the predicate intact. §8.1 names the
read that would settle it.

What **does** differ per cause is the **narrowing** work — the direction that removes unknown-ness
rather than un-serialising it — and the table above ranks it by measured residual:
`source-unlisted` (both legs, together) > `missing-provenance` (source-side write repair, since
#4821 already fixed the symptom and `unprovenanced_narrowed_holders` at `:2602` keeps the
population visible) > `source-no-areas` (labelling) > `declared-areas` (nothing).

**This is the recommendation's constructive half, and it has a precedent in this exact file.** The
last successful un-serialisation here — `NON_RESERVING_PARTITIONS = {"ci", "docs"}` (`:1733`) —
bought throughput by **measuring that the population does not collide** (0 of 15 `ci` pairs, 0 of 10
`docs` pairs on the busy board; 9.2% / 4.8% on the wider one) and exempting only where the evidence
was there; `deps` at 100% and crate areas at 57.1% were refused on the same evidence, in the same
change. That is the template any future concurrency change must follow. `__global__` **cannot** be
run through it as a single class: for the safety-driven half the evidence is a measurement of a
footprint that has no name, and for the linkage-parity half the evidence that *does* exist points
the other way — 57.1% on crate areas (§4.2), which is the same refusal `deps` and crate areas
already took. Either half fails the template; neither is an argument for `N`.

## 6. What an overrule inherits: cardinality is not expressible in this model

Three implementation facts a maintainer should price before overruling, because they are not
"one constant and a counter":

1. **The conflict predicate is 2-ary and pure, with no notion of "how many".**
   `packages_conflict(left, right)` (`lease_schema.py:105`) answers *do these two exclude* and is
   deliberately **the** predicate for every enforcement site: PLAN's assemble filter, CLAIM's live
   re-check, `sibling_lease_conflict`, and the allocator's `partition_available`. A slot count is a
   property of the *board*, not of a pair, so it cannot be expressed there — it has to be threaded
   through every call site as new state.
2. **Every copy must move in one wave, and some copies are not in this repository.** PLAN runs the
   **target's own** `ready-issues.py`/`dispatch-plan.py`, cloned at run time
   (`ready-issues.py:1-5`). The measured cost of one leg moving alone is on the record: the #112
   incident, where `resolve` still carried the pre-#112 reduction and the adopt step rejected its
   own dispatcher's claim **every tick, forever** — 53 of 77 review-fix failures in one day, 47+ on
   one PR, ~20% of the review lane (`lease_schema.py:60-70`). A cardinality rule adopted at CLAIM
   and not at PLAN plans work the allocator then refuses, which `partition_available:755-760` names
   as strictly worse than either width.
3. **A union is idempotent; a counter is not.** Today the busy view (open PRs) and the ledger view
   (live leases) are folded with `|` and `∩`, so a PR appearing in both is harmless. Counting
   global holders across those two views double-counts a PR that also holds a lease — the counter
   needs a de-duplicating identity the set model never had to carry. And the fail-closed direction
   must survive the rewrite: an unreadable row must **occupy** a slot, never read as a free one
   (compare `package_areas`'s "there is no input for which this returns `frozenset()`",
   `lease_schema.py:92-96`).

## 7. Recommendation — maintainer confirm or overrule

**`__global__` stays exclusive. `N` stays 1. #1011 point 1 is answered NO, and no code moves.**

Stated as the three answers #1011 asked for:

- **(a) What N buys against the measured board: nothing, under the only reading that is bounded.**
  Reading (B) can release only zero-area rows, and only on a board where no busy occupant reserves
  any narrow atom (§3.1 — structural, with its one unmeasured leg named there and in §8.1). The
  measured `kept=0` stall is a rule-1 stall caused by a *global occupant*, which reading (B) does
  not touch (§3.2) and which the #677/#822 sweep already drains in one tick (§3.3).
- **(b) The class it admits is concurrent same-crate edits by a global holder, and it has no
  detector** (§4.3). The bound does not bind: `N` caps cardinality, the hazard is overlap. For a
  **safety-driven** holder overlap is unmeasured at decision time by construction; for a
  **linkage-parity** holder it may be partly named, but `N` never reads it — `packages_conflict`
  shows the enforcement sites only "is either side universal", so one counter admits both
  populations, and where the evidence *does* exist narrowing dominates `N` outright (§2.1, §4.1).
- **(c) The answer does not differ per cause, though the reason does** (§5). After #4821 and #112
  the "genuinely repo-wide" bucket is structurally near-empty, so there is no repo-wide population
  to concede to; but `missing-provenance` is refused as unmeasurable while `source-unlisted` /
  `source-no-areas` are refused because narrowing is the better lever and `N` cannot be aimed at
  them alone. What differs per cause is that narrowing work, ranked in §5.

Until a maintainer overrules, **#1011 keeps its `needs:design` gate** — a hard `needs:*` gate in
`ready-issues.GATE_LABELS` (`:40`), so the issue cannot be dispatched to an implementer while it is
present. The disposition on confirm is to close #1011 as **answered, decided NO**, citing this
record, and to leave the gate in place on any successor issue that proposes the same lever.

## 8. If the maintainer wants N anyway, this is what it owes first — in this order

**8.1 Measure the release population before writing a line — the instrumentation already exists.**
The number that would falsify §3.1 has never been read: on ticks where
`by_reason.global-reservation > 0`, how many deferred rows had `by_reservation.global.deferred > 0`
(a row whose *own* package is `__global__`), and how many busy occupants reserved **any** narrow
atom. Both are already computed and printed every tick —
`record_partition_reservation` (`:2179`) splits kept/deferred by shape, `record_partition_defer`
(`:2130`) splits by reason, and `dispatch.yml:1355` emits `assemble-census`. **No new code is
needed to answer this; only a read of runs already in the log.** If the first count is 0, or the
second is > 0, reading (B) is inert and the change is a no-op with a soundness cost — stop there.

**And split the holder population while reading the same log, because §2.1 leaves it unmeasured.**
Each `busy` occupancy row already carries both its `cause` and its reserved set
(`busy_packages_of_pulls:1991-1992`), so one pass answers: of the rows holding `__global__`, how
many reserve **only** `__global__` (safety-driven) versus `__global__` *plus* at least one narrow
atom (linkage-parity, footprint partly named). That ratio is what decides whether the narrowing
work of §5 is worth more than the residual — and if the safety-driven count is 0 on a target, §4.1's
unqualified leg does not apply *there* and the case against `N` rests only on its dominance leg,
which an overrule must then argue against directly.

**8.2 Build the detector before the concurrency, not after.** The minimum honest bar: for any two
PRs the scheduler *allowed to run concurrently*, assert post-hoc that their changed-file sets are
**disjoint**, and raise — not log — when they are not. This is buildable today: the changed-file
data is exactly what the pair-collision table at `:1696` was computed from. A detector that fires
after the fact does not make the class safe, but a change that admits an undetectable class should
not ship while a detectable version of the same evidence is one query away.

**8.3 Move every leg in one wave**, per §6.2, including the target-repo copies this repository does
not own; and pin the cardinality rule with a **non-vacuous** self-test on both legs (the
`[#4929] applied AFTER every fail-closed branch` ordering rule — reasoned at `:1974`, *executed* at
`:18871` — is the shape to copy: an assertion that runs, plus a mutant that would flip it).

**8.4 Prefer reading (B) explicitly, or say you are choosing (A).** If an overrule is written,
it must name which reading it adopts. An overrule that adopts (A) is not "bounded concurrency" and
should not be recorded under that name — it is the removal of the unknown-footprint guarantee, and
it is the direction four independent guards in this tree currently refuse.

## 9. What this record does not decide

- It does not touch the **narrowing** work (§5). `source-unlisted` narrowing is real, it is the
  largest measured residual, and it is a separate change that must move both legs together
  (`busy_packages_of_pulls:1836-1848`).
- It does not revisit `NON_RESERVING_PARTITIONS` (`ci`/`docs`) or the composite-key reduction
  (#112). Both are evidence-based narrowings of *named* footprints and are unaffected.
- It does not decide the terminal-state half of #677, which is already shipped (every unknown-crate
  `__global__` holder escalates with its own named recovery).
- It does not claim the `declared-areas` bucket is provably unreachable — only that its reachability
  requires a label spelling every producer rejects, and that its live count has **not** been read
  here. That reading is worth taking on its own terms; it is the same "permanently-zero bucket in a
  closed enum" hazard this file already names for `CAUSE_NO_PROVENANCE_NARROWED` (`:531-535`).
