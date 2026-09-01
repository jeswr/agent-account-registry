# #767: a human-applied `review:parked` — is the actor rule or the label rule authoritative?

> 🤖 **SPARQ agent** — design record, 2026-09-01. Maintainer-review document.
> **This record changes no behaviour.** It answers the design question #767 raised, states which
> of #767's three options the tree actually took, points at the code that took it, and names the
> sub-population where #767's complaint is still true *by construction* — so the shape is a
> **decided** thing rather than an undocumented omission the next author "fixes".
>
> **Answer, in one line: option 2 — HONOUR THE LABEL — was adopted, but strictly narrower than
> #767 sketched it.** A human-applied `review:parked` takes the ordinary machine exit only behind
> **three** additional proofs (`human_park_is_machine_owned` → `human_park_capacity_proof` →
> `park_instance_attested`), each of which refuses on absence. **Option 3 is REJECTED** (§6): the
> tree carries a migration that runs the opposite direction, and #767's own concern about the
> `needs:user` conveyor is that migration's founding evidence.
>
> ⚠️ **The residue is real and is not a bug** (§5). A park a human applied to `review:parked` for
> which the machine holds **no receipt of any kind** still has no machine exit, unless the park's
> actor is positively proven to have been a machine driving a user account. That is the deliberate
> direction — a machine must not clear a park no machine ever classified. **One correction to #767
> is published in §5**: its *"the label still advertises an exit it lacks"* is no longer true of
> the tree — `MACHINE_PARK_DESCRIPTION` was reworded and now names the human unlabel first.
>
> ⚠️ **Nothing here is re-measured.** This container has no network, no `gh` and no token, so
> #767's four named PRs, its `busy_packages_of_pulls` census and its two dispatch run IDs are
> reproduced as **claims of that issue**, never as findings of this record. §7 says what would
> settle them.

## 1. The question #767 asked

`capacity_park_admission` answered *"may the machine clear this park?"* with two rules that
disagreed about a human-applied `review:parked`:

1. **`human_owned_holds(live_holds)`** — keyed on **label identity** (`review:needs-user` /
   `needs:*`). `review:parked` is not a member, so it does not block. Documented in its own
   docstring as *"THE ONE RULE for what blocks an automatic re-admission."*
2. **the actor rule** — `park_applications(...) -> latest_was_human`. A proven human applying
   *any* park label refused unconditionally with `PARK_REFUSAL_HUMAN_APPLIED`.

Rule 2 made the label choice **inert for a human writer**: a maintainer applying the
machine-owned soft hold and one applying the human-owned terminal got identical machine
behaviour, which voids the taxonomy invariant 1 of `scripts/park_policy.py` is built on. #767
declined to decide it, offered three options, and asked for steering.

## 2. What the tree does now, and where

Rule 2 no longer exists in the form #767 describes. `capacity_park_admission`
(`scripts/park_policy.py:1353`) evaluates a human-applied park through a **four-gate ladder**, and
only the first gate is the one #767 called "the actor rule":

| # | gate | keyed on | line | on failure |
|---|---|---|---|---|
| 0 | `human_owned_holds(live_holds)` | **live label identity** | `:1453` | `human-hold` |
| 1 | `human_park_is_machine_owned(human_park, human_park_labels)` | **actor × the label they chose** | `:1464-1465` | `human-applied` |
| 2 | `human_park_capacity_proof(reason_records)` | **the bot's own park-reason receipts** | `:1545` | `human-applied-unclassified` |
| 3 | `park_instance_attested(attestations, latest_park, previous_park, …)` | **this park application's own window** | `:1623` | `human-applied-unbound` |

Past gate 3 the park drops into *exactly* the bot-applied path — `auto-receipt` convergence, the
`AUTO_READMISSION_MAX` flap cap, the strictly-after ordering, the consume-exactly-once evidence
key — with nothing relaxed (`:1628-1631`, and the module header's invariant 3 states the same
contract in prose at `scripts/park_policy.py:35-100`).

So the answer to #767 is **option 2, adopted with two proofs the option did not contain**. The
question #767 framed as *"label rule or actor rule"* is answered *"label rule, and then prove the
cause"*: ownership decides **whether the machine may look at the park at all**; the machine's own
durable receipts decide **whether it may clear it**.

## 3. Why rule 1 and rule 2 no longer contradict each other

They answer different questions and now say so:

* `human_owned_holds` (`:1010`) answers *"is a human question live on either surface right now?"*
  It is a **live-label** predicate, it is checked first and unconditionally, and it has since
  become genuinely shared — `dispatch-claim`, `groom`, `resolve-conflicts`, `park-stock-alert`,
  `worker-pr` and two further call sites inside `park_policy` itself all consume it. That is the
  "one shared rule" discipline holding.
* `human_park_is_machine_owned` (`:974`) answers *"did the actor who applied the latest park pick
  a label whose published description promises this exit?"* Its docstring names itself **"THE ONE
  PLACE the label-vs-actor ownership question is answered"**, and its subset test is **positive
  and directional**: every label applied at the latest instant must be in
  `MACHINE_OWNED_PARK_LABELS`, so an unclassified label refuses rather than admits.

#767's complaint was that the second rule *subsumed* the first. It no longer does: gate 1 is a
**conjunction of actor and label**, not a test of actor alone, and `PARK_REFUSAL_HUMAN_APPLIED`
now means what its comment at `:1193` says — *"a proven human applied the **HUMAN** terminal"*.

## 4. The label choice is no longer inert for a human writer

This is the concrete disposal of #767's central charge. A maintainer's choice of label now selects
between materially different machine behaviours:

| what the human applied | machine outcome |
|---|---|
| `needs:user` / `review:needs-user` (or any label the module cannot classify) | `human-applied` — **terminal**, correctly: only a human clears it |
| `review:parked` / `status:parked`, bot receipt says `capacity`, attested to *this* park | the **ordinary machine exit** (`auto-mint` / `auto-receipt`) under every unchanged gate |
| `review:parked`, bot receipt exists but is **off-class** | `human-applied-unclassified` — terminal, and honestly so: the machine did form an opinion and it was not "capacity" |
| `review:parked`, capacity receipt exists but attests a **different, closed** episode | `human-applied-unbound` — terminal; the class proof is entity-scoped and monotone, so without gate 3 any PR ever bot-capacity-parked would be permanently immune to a hand-applied hold |
| `review:parked`, **no receipt at all**, actor provably a machine on a user account | one-shot `void-mint` / `void-receipt` (registry #1309, `:1562`, `RECEIPTLESS_VOID_MAX = 1`) |
| `review:parked`, **no receipt at all**, actor not provably a machine | `human-applied-unclassified` — **terminal**. This is the residue; see §5 |

**Five of those six rows did not exist when #767 was filed**, and the dating is checkable in this
repo rather than asserted. At `2e6ec0772` (#766, 2026-07-27 — the commit #767 was written
against) `capacity_park_admission` read `if human_park:` and refused, unconditionally; only row 1
existed. The whole ladder landed the **next day**, at `303dc759a` (#969, 2026-07-28), which is the
sole commit that ever introduced `human_park_is_machine_owned`. #1309's two void rows followed at
`2ae7a9ae2` on 2026-07-30.

Gates 2 and 3 were added because the first cut of option 2 — the one #767 sketched, label over
actor and nothing else — was measured and found to be clearing parks it had no business clearing:
`human_park_capacity_proof`'s own docstring records that keying on the label alone admitted 12
live PRs of which **12/12** recovered on the labelled aged-out **heuristic** and **0/12** on proof
that their own cause had cleared — *"a six-hour timer wearing an evidence gate's name"* — and that
**5 of the 12** carried no bot receipt of any kind, the exact case in which registry #769's
"age is not its own recovery proof" guard is inert.

**#767's own cohort is named in that measurement.** `sparq-org/sparq#4197` — the first of the four
PRs #767 lists — is one of the five receiptless PRs pinned in that docstring. So the population
#767 measured is not merely *covered* by the decision; it is part of the evidence that narrowed
it.

#767's other requested outcome — *"the cohort becomes visible and named"* — shipped as #766 and is
now a closed taxonomy: `PARK_REFUSAL_CODES`, the `PARK_REFUSAL_HUMAN_TERMINAL` split (`:1261`),
one writer (`park_census_record`, `:1303`) and one aggregator (`park_census_summary`, `:1319`).
Every row in the table above is counted, and the human-terminal ones are counted **as**
human-terminal. #767's *"counted by nothing"* is no longer true of any of them.

## 5. The residue — where a human-applied `review:parked` still has no machine exit

A park that is (a) applied by an actor not provably a machine, (b) on `review:parked`, (c) with
**no** well-formed bot park-reason receipt anywhere in the PR's history has **no machine exit**.
It refuses `human-applied-unclassified` on every tick, forever.

That is deliberate, and the reasoning is worth stating so it is not re-litigated as a bug:

* The exit the machine could offer is *cause-recovery*. A park with no recorded cause has no cause
  whose recovery could be probed, so running the probe could only produce an answer about some
  **other** condition — which is precisely the aged-out heuristic that gate 2 was built to stop.
  `capacity_park_admission` makes this ordering explicit: the void mint returns **before** the
  recovery-evidence path (`:1669-1670`) rather than falling through it.
* The refusal code's own comment (`:1194-1199`) states why it is human-terminal rather than
  merely slow: *"a receipt that does not exist for an already-parked PR cannot appear on a later
  tick, because only a fresh BOT park would write one, and that park would not be
  human-applied."* This is not a gate waiting to open. It is a gate that cannot be evaluated.
* #1309 already carved out the one sub-case where an answer **is** obtainable — a park the machine
  wrote while driving a user account, proven from the fleet's own required self-ID
  (`machine_operated_park_proof`, `:2494`), which is a *positive* provenance signal rather than an
  inference from `actor.__typename`. Absent that signal the park may genuinely be a human's, and
  it keeps the human terminal it has.

**Correction to #767's framing, and it matters.** #767 wrote that *"the label still advertises an
exit it lacks"*. Checked against the live text rather than assumed: `MACHINE_PARK_DESCRIPTION`
(`scripts/park_policy.py:203-205`) reads *"Machine-owned capacity park (soft hold; human unlabel,
proven recovery, or capped retry)"* — it lists **human unlabel first** and names the other two
exits by their proofs. It was reworded for exactly this reason; its own comment records that the
original *"cleared automatically on readmission"* **"described a mechanism that did not exist"**.
So the label does **not** advertise an exit the residue lacks: for a receiptless human-applied
park the first of the three advertised exits is the one that applies, and it is the human unlabel.
#767's sentence was true of the wording it was written against and is no longer true of the tree.
There is therefore **no documentation gap to close here**, and this record does not open one.

What remains is only the substantive point: `review:parked` delivers a *machine* exit for every
park the machine applied (which always carries a receipt — `PARK_CAUSES` carries
`capacity-unspecified` precisely so that every capacity park emits *some* receipt) and for a
human-applied park the machine had already classified, and it delivers none for a park a human
applied to a PR the machine never classified. That state is counted, named, and classed
human-terminal. It is not silent, and it is not a broken promise.

## 6. Option 3 (`review:parked` → `review:needs-user`) is rejected

#767 offered it as "honest about the behaviour". It is rejected on three independent grounds.

1. **The tree runs a migration in the opposite direction.** `_migrate_legacy_park`
   (`scripts/dispatch-claim.py:5677`) exists to move PRs **out** of the human terminal: 31 of 33
   stalled sparq draft PRs were parked before the capacity/question split and carry
   `review:needs-user` for an infra cause, *"stalled permanently by construction"*. Option 3 would
   feed the exact population that migration drains, in the same sweep.
2. **It converts a countable state into a terminal one.** The residue in §5 is a park with an
   unevaluable exit; `review:needs-user` is a park with **no** exit and a human obligation
   attached. Trading the first for the second raises no re-admission count and adds work to a
   human's queue for a PR nobody asked a question about. `MACHINE_PARK_DESCRIPTION`'s whole reason
   for existing is that *"a capacity blip must never masquerade as a human question"* (module
   header, invariant 1, citing the 2026-07-18 mass-park incident).
3. **The migration's own harm gate forbids the mirror move.** `_migrate_legacy_park` will not
   convert a park unless `provable` holds, on the stated grounds that *"converting a park into a
   machine class that cannot release it trades a VISIBLE stall a human can see and clear for a
   SILENT one nothing will ever clear."* Option 3 is that trade with the signs flipped, and it has
   no equivalent gate to offer.

## 7. What this record does NOT claim

* **#767's four PRs are not re-verified.** `sparq-org/sparq#4197`, `#3620`, `#3598`, `#3577` are
  reported as of the issue's own 2026-07-27 measurement. Only `#4197` is corroborated inside this
  repo, and only as *receiptless* (`human_park_capacity_proof`'s docstring), not as still parked.
* **The frontier claim is not re-verified either**, and it is worth keeping: #767 recorded that
  re-admitting the cohort would free **no** frontier capacity, because `busy_packages_of_pulls`
  releases a parked PR's crates precisely when `parked AND inactive`. If that still holds, the
  residue in §5 costs visibility and honesty — not throughput — and should be priced that way.
* **The settling commands**, for whoever has a token: enumerate open PRs carrying `review:parked`
  with no `needs:*` / `review:needs-user`, and for each read whether any bot park-reason marker
  exists. That partition — receipted vs receiptless — is the whole question, and the second half
  is the residue this record declines to close.

## 8. What an overrule obliges

If the maintainer overrules §5 and wants a machine exit for the receiptless human-applied park:

1. It must be a **new positive proof**, not a relaxation of gates 2 or 3. Deleting either
   re-creates the measured 12/12-on-a-timer failure, and this repo's standing rule is that a trust
   check is never weakened to raise a count.
2. It must not consume the `AUTO_READMISSION_MAX` budget — #1309's separate `RECEIPTLESS_VOID_MAX`
   exists because *"routing one mechanism's receipts through another's cap makes the two consume
   each other"* — and it must be receipt-first, converging idempotently like `void-receipt`
   (`:1515-1529`), or a crash between receipt and label write strands the PR permanently.
3. It must arrive with its own census code in `PARK_REFUSAL_CODES` / `PARK_REFUSAL_HUMAN_TERMINAL`
   and its own red self-test asserting **both** directions — the admit and the refusal — or it is
   a new fail-open in the module whose entire subject is failing closed.

Related: #766 (the census, shipped), #769 (age is not its own recovery proof), #691 (the
unobtainable-cause fallback), #1309 (the receipt-less void), #703 (parks are a conveyor into
`needs:user`), #958 (one definition, plus pointers).
