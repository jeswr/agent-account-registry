# #1828: correlating the `why_no_diff` census with what dispatch actually DID — the design record

> 🤖 **SPARQ agent** — findings-only design record. **Nothing in this PR changes behaviour**, and
> that is deliberate: #1828 asks for the design record *before* any code. #738 §7 M4 has two halves.
> (a) *which reason dominates* is delivered by a reason census — written here as #1595's proposed
> `model-health.no_change_reason_census`, but what merged is #1827's
> `dashboard-gen._no_change_reason_census`, whose shape differs where §6 depends on it (§6.1).
> (b) *does the routing each reason drives match what happens next* is what this record scopes.
>
> **Headline: (b) is NOT derivable from the public health ledger, and the reason is structural, not
> a tuning gap.** The ledger records a target issue number **only** on `no_change` rows — the write
> validator refuses the field on every other exit class (`scripts/model-health.py:886-889`). So the
> store that holds the *reason* half of the correlation is, by construction, blind to the *success*
> half of the outcome. A query run against it alone does not return "unknown"; it returns a
> confident **0 % success**, which is the fabricated measurement the census exists to replace.
>
> §3–§7 are the findings; §8 recommends **which store holds the join** and §9 answers **what a
> mismatch should DO** (**report only** — never auto-narrow `DECOMPOSE_REASONS`; §9.2 is the reason
> the measurement *cannot* license that edit). §10 is what this record does **not** establish.

## 1. The question, restated as two joins

M4(b) is one sentence:

> For each `no_change` row, did the routing its declared reason drove match what actually happened
> next?

That decomposes into two joins, and they have **different keys, different stores, and different
lifetimes**:

| join | left | right | key | cardinality | right-hand lifetime |
|---|---|---|---|---|---|
| **J1 — reason → decision** | the `why_no_diff` on each health row | the arm `retry_decision` took on a tick that row was evidence in | `(issue, evidence-set digest)`; a row joins by **membership** in that tick's evidence set | many rows → one arm; one row → many arms | the dispatch tick (a workflow log line) |
| **J2 — decision → outcome** | that arm | what became of the issue | `(repo, issue)` | one arm → one issue timeline | permanent issue state |

The census answers neither. It is a *marginal* distribution over the left column of J1. Every
finding below is about why J1 and J2 are harder than a `GROUP BY` over the same blob.

**J1 is not a per-row join, and M4(b)'s wording hides that.** `retry_decision`
(`scripts/no_change_routing.py:170-199`) is called **once per dispatch tick** with *every* validated
in-window `no_change` row for the issue (`dispatch-claim.py:8559-8560` → `_issue_no_change_outcomes`,
`:6388-6399`, over the pruned window) and returns **one** arm. Inside it the rows are reduced to
**sets** before the arm is chosen — `declared_reasons` (`:159-167`) returns a set of reason names,
`excluded_tiers` (`:137-156`) a set of aliases — so by the point the arm exists the individual rows
are already anonymous *to the code*. And a row is not consumed once: the health window is 48 h
(`model-health.py:81-82`) while the tier exclusion is 6 h (`no_change_routing.py:82`), so the same
row is re-read on every later dispatch of that issue until it is pruned.

So the honest cardinality is **many rows → one decision**, and **one row → many decisions**. M4(b)'s
"for each `no_change` row" is a *row-level* sentence over a *decision-level* event, and reconciling
the two is not cosmetic — it is what fixes the denominator:

- **decision-level** (primary here, because that is the granularity at which an arm exists): the
  denominator is *decisions*. A reason carried by three of five rows in one tick contributes once.
- **row-level** (derived): the denominator is *(row, decision) participations*, and a row that is
  evidence in K ticks is counted K times.

The derived view is only sound if each decision names the rows it consumed — otherwise the reader
cannot recover membership, cannot compute either denominator, and cannot tell two decisions over
different windows apart. Naming the rows is necessary but *not* sufficient: the arm also moves with
the 6 h exclusion cutoff over an unchanged window, and with the route the chain is resolved against,
so the binding has to cover the decision's whole input — the rows *and* the tier sequence they are
evaluated against. §8's option C is what has to carry it; §8.1 specifies it, and states what the
artifact degrades to if the tier sequence has to stay off the target timeline.

## 2. What the repo records today — the three seams, grounded

**The reason is produced** in `worker-live.sh:184`, encoded as a vocabulary **index** into the
numeric `no-change-v1` envelope, decoded in `model-health._parse_no_change_envelope`
(`scripts/model-health.py:2800-2823`) and stored as the vocabulary **name**
(`make_record`, `:520-533`). There is deliberately no CLI flag for it (`:2868-2871`).

**The decision is taken** in `dispatch-claim.py:8586-8613`, from
`no_change_routing.retry_decision` over the validated window, before `allocator.claim()`. It has
three arms — `proceed`, `retry-other-tier`, `decompose` — and `DECOMPOSE_REASONS`
(`scripts/no_change_routing.py:77`) is what makes two of the six vocabulary words skip the lateral
ladder entirely.

**The outcome lives** in the target repo: labels (`role:impl` → `role:research`,
`status:parked`), the bot's durable comments, and ultimately a merged PR.

Each seam is fine on its own. The problem is every pair.

## 3. Finding A — the outcome half is *structurally* absent from the health ledger

`RECORD_NO_CHANGE_FIELDS` (`scripts/model-health.py:290-291`) declares `issue` a **no-change-only**
field, and `_validate_record` enforces that in both directions:

```python
present_no_change = set(r) & no_change_fields
if r.get("exit_class") != CLASS_NO_CHANGE:
    if present_no_change:
        raise ValueError("model-health record has no-change fields on another exit class")
    return extra
if not _is_bounded_int(r.get("issue"), 1, MAX_ISSUE_NUMBER):     # :889
```

A `success` row therefore carries **no issue number at all** — not "usually absent", *refused*. The
consequence is one-sided and it is the whole finding:

> The ledger can observe `issue N failed on tier A, then failed on tier B`.
> It can **never** observe `issue N failed on tier A, then SUCCEEDED on tier B`.

The lateral ladder's entire purpose is to produce the second sentence. A correlation computed from
the ledger alone is **censored on exactly the treatment effect it is measuring**, and — this is the
part that makes it dangerous rather than merely incomplete — the censoring is *silent*: the query
returns rows, the rows are well-formed, and the derived "lateral retry success rate" is
**0 % by construction**. Pre-flight item 8's rule applies verbatim: a residual computed from rows
that entered a pipeline cannot see a loss that prevented entry. Here, success *prevents entry*.

Relaxing the validator to attach `issue` to `success` rows is not a small change. It is a schema
change to a **shared, public, rolling-upgrade** ledger whose last one-commit field addition
(`why_no_diff`, #733) took three in-flight runs down and cost the whole `#739` forward-tolerance
posture to repair (`scripts/model-health.py:305-316`). It also widens what the public ledger says
about *successful* work, which is a locked-decision-22 question, not an implementation detail.

## 4. Finding B — the join key is not repo-qualified, and two targets are enabled

`issue` is a bare bounded integer (`:889`, `MAX_ISSUE_NUMBER` at `:283`). No `repo` field exists on
a health record. `_issue_no_change_outcomes` (`scripts/dispatch-claim.py:6388-6392`) selects on
`record.get("issue") == issue` and nothing else, while the dispatch loop iterates **every** target
repository against **one** global window (`:8289-8290`). `policy/repos.toml` enables two targets
(`:88` `sparq-org/sparq`, `:185` `jeswr/agent-account-registry`).

For J2 this is decisive: `(issue)` does not identify an issue, so the correlation cannot be joined
to a timeline without a qualifier the store does not carry. Number ranges happen to be disjoint
today; that is an accident of counter position, not an invariant. This also touches live routing
and `model-health._no_change_limit_view`'s distinct-issue count (`scripts/model-health.py:965-976`),
so it is filed as its own issue rather than analysed further here — it is a correctness question,
not a measurement one.

## 5. Finding C — the *decision* is never recorded, and the receipt that exists cannot name the arm

- The **`retry-other-tier`** arm emits one `print()` (`scripts/dispatch-claim.py:8612`) into the
  dispatch workflow log. Nothing durable. J1's right column exists for the retention period of an
  Actions log and is not queryable as data.
- The **`decompose`** arm *does* leave a durable receipt — `<!-- sparq-task-decline-escalation:v1
  key=<sha> action=research|needs-user -->` on the target issue — but read the body it ships with
  (`:6496-6520`): the outcome lines are `_decline_outcome_name` (`:6430-6432`), i.e.
  ``run `<id>` → `no_change` ``. **The declared reason is not in it.** So the receipt cannot
  distinguish the two ways an issue reaches `decompose`:

  1. `declared_reasons(rows) & DECOMPOSE_REASONS` fired — the *reason* drove it; or
  2. the chain had no untried tier left — *exhaustion* drove it.

  Those are the two populations M4(b) has to keep apart. Merging them is not a rounding error: it
  is the difference between "`too_large` routes correctly" and "single-rung chains decompose after
  one attempt, and the reason was never consulted" — and the `role:impl` chain is single-rung
  (`orchestration/routing.toml`, the #738 measurement; `scripts/dispatch-claim.py:10687-10706`), so
  population 2 is expected to be *large*, not marginal.

An easy-looking fix — hang the arm onto the existing attempt receipt — is a **trap worth naming**,
because it is the first thing an implementer will reach for. `_receipt_run_keys`
(`scripts/worker-issue.py:135`) matches:

```python
re.findall(re.escape(marker) + r" run=(\S+) -->", body)
```

`\S+` cannot span a space, and the marker must be immediately followed by ` run=`. So a new key
placed on **either side** of `run=<key>` stops every attempt receipt from matching — measured by
calling `_receipt_run_keys` directly:

| body | keys returned |
|---|---|
| `<!-- sparq-worker-attempt:v1 run=abc123 -->` | `{'abc123'}` |
| `<!-- sparq-worker-attempt:v1 run=abc123 arm=decompose -->` | `set()` |
| `<!-- sparq-worker-attempt:v1 arm=decompose run=abc123 -->` | `set()` |

`budget_used` would collapse to 0 and the deferred-retry budget would become unbounded — silently,
because an uncounted receipt reads exactly like an issue with budget left. Any new fact needs a
**distinct marker**, which is already this repo's established pattern (`CLAIM_MARKER`,
`REFUSAL_MARKER`, `ATTEMPT_VOID_MARKER`, `worker-issue.py:44-94`).

## 6. Finding D — `unspecified` is unreachable in the live ledger

The census (#1595) publishes `unspecified` and `undeclared` separately and documents the split as
"the recorder stored index 0" vs "the recorder attached nothing". **The live producer never stores
index 0.** `worker-live.sh:184`:

```sh
fields = [("issue", int(issue_raw))] + ([("why", why)] if why else [])
```

`why` is the vocabulary index; `if why` is false for `0`, so `unspecified` is omitted from the
envelope, `_parse_no_change_envelope` sets no `why_no_diff`, and `make_record` drops the field
(`:530-532`).

Be precise about **where** the unreachability lives, because it is one layer up from where a reader
expects it: the *decoder* handles index 0 correctly — `_parse_no_change_envelope("no-change-v1
issue:500,why:0")` returns `{'issue': 500, 'why_no_diff': 'unspecified'}`. It is the **producer**
that never emits `why:0`, and the envelope is the only ingress, since the CLI flag is withheld on
purpose (`:2868-2871`). So the value is unreachable *in the live ledger* while being perfectly
constructible in a fixture — which is why a self-test can hold `unspecified` green over a bucket
that production can never fill.

Therefore, on records written by the current worker:

- `census["reasons"]["unspecified"]` is a **structural zero**, and
- `census["undeclared"]` conflates *"the model declared nothing or unparseably"* (the
  intended `unspecified`) with *"the evidence seam dropped the field"* — the exact conflation the
  census's denominator argument says it prevents.

This does not make the census wrong about the other five words, and (a) still stands. It does mean
M4(b) cannot ask "does the *no-signal* population route differently?" from this data, because the
no-signal population is not separable from a seam failure. Filed as a follow-up against #1595's
change rather than repaired here: it is a producer-side edit on the envelope seam, out of scope for
a design record, and `worker-live.sh` is a gate-profile script.

### 6.1 Re-checked against what actually merged (#2004) — the two bullets above describe an object that does not exist

§10 asks for this finding to be re-checked against whatever merged, because the two bullets
immediately above are written against #1595's census **as proposed**. #1595's shape never merged.
What is on `master` is #1827's `_no_change_reason_census` (`scripts/dashboard-gen.py:1495`),
published as `no_change_reasons` on the model-health payload, and it differs in the one way that
decides both bullets: it has **no `undeclared` key at all**, and `reasons` is a *list* of
`{"reason", "count"}` rows rather than a mapping, so `census["reasons"]["unspecified"]` does not
index it either. Every `no_change` row is folded by
`counts[reason if reason in counts else unspecified] += 1` — an absent `why_no_diff`, and any value
the reader does not recognise, lands in the `unspecified` row. So on the merged census neither
bullet holds: `unspecified` is not a structural zero but a **real measurement of the
absent-declaration population** — non-zero exactly when that population is — and there is no second
key for it to be conflated with. Read those
two bullets as a record of a shape that was proposed and abandoned, not as a defect on `master`.

The **producer** finding is untouched by this and is correct: the live producer never emits `why:0`,
so a *stored* `why_no_diff == "unspecified"` remains unreachable. #1950's disposition was to
document and pin that, and to leave the producer deliberately unchanged. It is documented at the
census (`scripts/dashboard-gen.py:1520-1535`, which states that the fold is total and must not be
re-split) and at the decoder (`scripts/model-health.py:3133-3143`, which names its index-0 row as
fixture-side coverage of an arm production never writes); and it is pinned in both directions —
`worker-live.sh`'s own self-test asserts that all three ingresses for index 0 (absent, unparseable,
and an explicit in-vocabulary `{"why": "unspecified"}`) yield **no** `why` field, and
`dashboard-gen.py`'s asserts that an absent declaration and a hand-written stored `unspecified` land
in **one** bucket of 2. The producer stays as it is because the envelope's wire format is
append-only and index 0 is load-bearing on the routing side: `UNSPECIFIED` is deliberately not in
`DECOMPOSE_REASONS`, so it is the arm that sends a no-signal or malformed declaration down
`retry_decision`'s ordinary ladder instead of its reason-driven terminal `decompose` route (tier
exhaustion can still decompose such a run; the *declaration* never forces it).
Making index 0 storable would let a garbage declaration become a real declared value and would split
the census row back into two populations.

What this leaves of M4(b): the question is now askable of a real population, with one caveat the
census states itself — a seam that *dropped* a declared reason would also land in `unspecified`, so
that row **bounds** "no signal" from above rather than measuring it exactly. The producer self-test
is what makes that a tested-against failure mode rather than an assumption. The stronger claim above
("not separable from a seam failure") no longer applies to the merged shape.

## 7. Retention: 48 h of evidence against an outcome horizon of days

`WINDOW_HOURS = 48` and `MAX_RECORDS = 200` (`scripts/model-health.py:81-82`); the census reads the
**retained** window by design. `TIER_EXCLUSION_SECONDS` is 6 h (`no_change_routing.py:82`). A
`decompose` outcome, though, is a reroute to architect decomposition whose *result* is child issues
and eventually merged PRs — a horizon of days. The left and right sides of J2 do not merely live in
different stores; the left side is **deleted before the right side exists**. Any store that holds
the join has to be append-only with a retention longer than the health window, or the join has to be
performed at write time, while both sides are in hand.

## 8. Which store holds the join — the options

| # | store | J1 | J2 | cost / hazard |
|---|---|---|---|---|
| A | extend `data/model-health.json` (add `issue` to more classes + a `decision` field) | yes | partial | public-ledger schema change with live pre-merge readers (#739/#733); grows a *health* store with *routing* facts; still capped at 48 h / 200 records; still not repo-qualified |
| B | new append-only `data/no-change-outcomes.json` on the `ledger` branch, CAS-written at the decision site | yes | no (outcome still elsewhere) | a **new ledger write on the dispatch hot path**. It must be best-effort or a ledger blip blocks dispatch — and a best-effort store is lossy, so its denominator is unaudited, which is the failure mode this whole line of work exists to remove |
| C | the **target issue's own timeline**, via a new distinct bot-comment marker at the decision site | yes, at **decision** granularity, and row-level only if the marker binds its whole decision input (§8.1) | yes | one extra comment per decision; must not touch `ATTEMPT_MARKER`'s grammar (§5); still needs a reader to aggregate |
| D | derive nothing durably; answer M4(b) as a **bounded one-off study** against the API, published as a record | yes (log-limited) | yes | not standing; costs a maintainer-run query; the J1 half degrades as Actions logs expire |

**Recommendation: C for J1's missing half, and D for the first answer.**

The reasoning is one property: **the join must be recorded where the longer-lived side lives.**
J2's right column is permanent issue state; J1's right column currently lives for the life of a log
line. Writing the short-lived fact into the long-lived store (C) closes the gap with one durable
artifact. Writing the long-lived fact into the short-lived store (A/B) does not — it re-creates
Finding A one layer over.

Concretely, C is: at `dispatch-claim.py:8586-8613`, post one bot comment carrying a **new** marker
naming the `arm` (`proceed` / `retry-other-tier` / `decompose`), whether a decompose was
**reason-driven or exhaustion-driven** (§5's population split, which is the fact nothing records
today), and — §8.1 — a binding to the decision's *whole* input, rows and tier sequence both (or, if
the sequence must stay unpublished, the weaker artifact §8.1 scopes it down to). It is bot-authored, so it
inherits the existing "only the orchestration bot's own comments are receipts" filter (pre-flight
item 5) and cannot be forged from a target repo. It is *adjacent to*, and must not modify, the
existing decline-escalation receipt, whose `key=` is an idempotence hash over evidence
(`_decline_escalation_evidence`, `:6402-6406`) — changing that marker re-fires escalations that
already reconciled.

**Do A only if a maintainer independently wants `issue` on success rows** for another reason. It
should not be bought by this measurement.

### 8.1 Option C's decision binding — a reason *set* is not enough

The obvious payload is "the arm plus the declared reason set". That does **not** support §1's join,
and the gap is worth stating precisely because the set is what the code itself computes
(`declared_reasons`, `no_change_routing.py:159-167`) and is therefore the thing an implementer will
reach for. A set discards **multiplicity** (two rows carrying `too_large` collapse to one word),
**provenance** (when several reasons are present, nothing says which row carried which), and
**window identity** (a later decision over a *changed* window that happens to yield the same reason
set is indistinguishable from a repeat). With all three gone the receipt supports neither
denominator in §1: it cannot be counted per row, and per decision it cannot be deduplicated.

And a reason set is not the only thing the arm depends on. `retry_decision` is **not** a function of
the rows alone: `excluded_tiers` takes `now` (`no_change_routing.py:137-156`) and the arm is then
chosen against the **resolved chain** (`:190-199`). So the marker must bind the whole *decision
input*, using the shape this repo already uses one screen away — with one deliberate departure,
named below because it will otherwise be copied wrong:

- **An ordered entry per consumed row**, in `_issue_no_change_outcomes`'s own sort order
  (`:6393-6399`), each carrying only `ts`, the row's `run_id` (or `ledger-ts-<ts>` when it is empty)
  and its `why_no_diff` (absent → `unspecified`, matching `declared_reasons`). `run_id`-or-`ts` is
  the identifier `_decline_outcome_name` (`:6430-6432`) **already** publishes on this timeline, so
  this widens no disclosure. `account` and `provider` must **not** be republished from the health
  ledger onto a target repo's issue; they are not needed to reconstruct the arm.
- **`at=<ts>`** — the bounded int `now` the decision was evaluated at, i.e. the value handed to
  `retry_decision`. Without it the 6 h cutoff is unrecoverable, and an entry's `ts` then says nothing
  about whether that row was still excluding its tier at decision time.
- **`chain=<n> remaining=<n>`** — two small bounded ints, `len(chain)` and `len(remaining)` at
  `no_change_routing.py:184-199`. Aliases are **not** published; see the disclosure note below.
- **`evidence=<sha256 hex[:16]>` — the membership digest, over EXACTLY the published entry list**:
  canonical `json.dumps(entries, sort_keys=True, separators=(",", ":"))`, truncated the way
  `_decline_escalation_evidence` (`:6402-6406`) truncates its own. Its **preimage is the comment
  body**, so any reader recomputes it offline; it is stable across ticks over an unchanged window,
  which is what lets a reader group the receipts that share one evidence set.
- **`key=<sha256 hex[:16]>` — the idempotence key**: the `evidence` digest, the per-entry recency
  bit `ts >= at - TIER_EXCLUSION_SECONDS`, `chain`, `remaining`, the arm, the
  `reason-driven`/`exhaustion-driven` flag, **and `chain-digest`/`remaining-digest`** — canonical
  digests, taken exactly as `evidence=` is, of the **ordered alias lists** `chain`
  (`no_change_routing.py:184`) and `remaining` (`:191`). Those last two are what make the key a
  binding of the decision *input* rather than of its published shadow, and they are not optional
  padding: `retry_decision` is a function of the alias **sequences**, not of their lengths, so
  `chain=<n> remaining=<m>` is satisfied by more than one routing input — and for
  `retry-other-tier`, `remaining=<n>` never says *which* tier runs next.

> **The departure.** `_decline_escalation_evidence` digests the **full validated rows** — `account`,
> `provider` and `model_alias` included. That is fine for a marker that only has to be *stable*, but
> its preimage is a health row pruned at 48 h (§7), so after the window it is an **opaque token**:
> nothing on the timeline can ever check it. `evidence=` above is defined over the **published
> projection only**, and that is the entire reason it is checkable; `key=`'s two chain digests are
> the one deliberate exception, and the paragraph below states exactly what that costs. Do not reuse
> `_decline_escalation_evidence` for the new marker, and do not describe its `key=` as verifiable.

**`key=` is therefore only half-checkable — do not describe it the way `evidence=` is described.**
The two chain digests' preimages are **not** on the comment. A reader recomputes `evidence=` from the
body alone; it can recompute `key=` only if it also holds the dispatching commit's
`resolved["model_chain"]` (`dispatch-claim.py:8587-8588`), and that is not a pure function of the
public route table — the review chain proper is computed cross-provider in `dispatch-claim.py`
(`orchestration/routing.toml:308`), and the table itself can be edited between two ticks of the same
issue. Nor do the digests buy confidentiality: this repo's table holds only three distinct chains
(`["opus5", "sol"]`, `["opus5"]`, `["sol", "opus5"]`), so anyone holding it inverts a chain digest by
enumeration. They buy **collision-freedom only** — which is precisely what an idempotence key needs
and what the published counts cannot supply. If the maintainer will not put a field on a target-repo
timeline that a reader there cannot verify, the honest alternative is to omit the two digests and
**scope the artifact down**, next paragraph — not to keep the counts and call the result a
whole-input binding.

**Scoped-down variant: without the chain digests, `key=` is an outcome-projection key, and distinct
keys are a LOWER BOUND on distinct routing decisions.** The preimage is then the published
projection plus the arm and the flag, and two genuinely different decision inputs collide whenever
they agree on it. Both cases are reachable:

1. **The chain moved under an unchanged window.** Two chains of equal length that differ in order or
   membership are the same `chain=<n>`, and — since `remaining` preserves chain order over the same
   exclusion set — often the same `remaining=<n>` and the same arm. That pair is live today:
   `role = "ci"`/`role = "site"` resolve to `["opus5", "sol"]` and `role = "docs"` to
   `["sol", "opus5"]` (`orchestration/routing.toml:284,262,302`), and `choose_account` walks the
   chain **in order** (`select-and-claim.py:613-624`, "Walks the model chain"). The chain is
   re-resolved on every tick from the issue's labels — which
   dispatch itself rewrites (`role:impl` → `role:research`, `dispatch-claim.py:5315`) and triage can
   re-label — against a table that is editable between two ticks of the same issue. The receipt reads
   `proceed` on a 2-rung chain both times; the model that actually runs differs. Equal-length chains
   differing in **membership** are not prevented either — every onboarded target carries its own
   `routing.toml` (`orchestration/routing.toml:253-257`) — and that is the case where the *narrowed*
   chain's next tier differs at an identical `remaining=<n>`.
2. **The exclusion moved under an unchanged projection.** `excluded_tiers` keys on `model_alias`
   (`no_change_routing.py:153-155`), which is deliberately unpublished. Entries publish
   `ts`/`run_id`-or-`ledger-ts-<ts>`/`why_no_diff` only, so a row with an empty `run_id` that is
   pruned and replaced by another row of the same `ts` and reason but a **different alias** leaves
   `evidence=` and every recency bit identical while retiring a different tier of the same count.

In both, the second tick is suppressed although the tier sequence changed. So under that variant the
comment is a receipt of the **published outcome projection**, not a binding of the decision, and the
distinct-`key=` count must be labelled a lower bound on distinct routing decisions rather than a
count of them.

**What that payload does and does not reconstruct — state it, do not over-claim.** The entries carry
the `declared_reasons` input in full, so the **reason** half of the arm is re-derivable offline, and
membership *is* verifiable against `evidence=`, because that digest's preimage is the comment itself
rather than a health row that will be pruned out from under it. With `chain`/`remaining` the **arm** is re-derivable too, as a pure function of published
fields: reason intersection first, then `remaining == 0` → `decompose`, `remaining == chain` →
`proceed`, else `retry-other-tier` (`no_change_routing.py:188-199`). What is **not** reconstructable
is *which* tiers `excluded_tiers` retired: no `model_alias` is published, so `chain` and `remaining`
are **bot-asserted counts, not reader-derived ones**, and a reader can only check them for internal
consistency against the arm and the flag — a disagreement is detectable, a jointly-wrong pair is not.
`chain-digest`/`remaining-digest` are bot-asserted in exactly the same sense: they let a reader tell
two decisions **apart**, never tell it which tiers either one held.
That residual is the disclosure tradeoff, and it is taken deliberately: publishing aliases would make
the counts independently checkable but puts fleet composition onto a public target-repo timeline,
which the existing decline receipt (`_decline_outcome_name`) pointedly does not do — a separate
decision for the maintainer, not one this record takes. §5's `reason-driven`/`exhaustion-driven` flag
survives as the cross-check that makes such a disagreement visible.

Every field above is closed, bounded, or shape-validated before it reaches the body — `why_no_diff`
is a closed vocabulary (`NO_CHANGE_REASONS`), `run_id` is `_is_safe_field`-checked to the
`<run>.<attempt>` token shape (`model-health.py:877-879`), `ts` and `at` are bounded ints, and
`chain`/`remaining` are counts bounded by the resolved chain length. That is not
incidental: the marker writes ledger-derived data onto a **public** target-repo timeline, so it must
inherit the `no-change-v1` envelope's own posture — no free text, no model-authored string — rather
than reintroduce the one field able to carry attacker-chosen text (`no_change_routing.py:57-62`).

The four cases the binding has to define, each answered from the code:

- **Duplicate timestamps.** `ts` is not unique — `_issue_no_change_outcomes` breaks ties on
  `run_id`, then `account`, then the whole canonical row, which is only necessary because collisions
  are reachable. Identity is therefore **positional within the digest**, never `ts`: two rows with
  the same `ts` and the same reason are two entries, and the entry count *is* the multiplicity.
  `ledger-ts-<ts>` is a display label, not a key.
- **Multiple reasons.** Record the per-row reasons (above) **and**, separately, the deciding subset
  `declared_reasons(rows) & DECOMPOSE_REASONS` — the intersection at `no_change_routing.py:188`.
  Together they let the reader name *which* row(s) drove the arm, which the set alone cannot.
- **Aged-out rows.** `declared_reasons` applies **no** age bound, unlike `excluded_tiers`
  (`:137-156`, `TIER_EXCLUSION_SECONDS`). A `too_large` row therefore still forces `decompose` for
  the full health window — up to 48 h, and up to 8× longer than the same row keeps excluding its own
  tier. The receipt must list **every** row it was handed, aged ones included, or the arm is not
  reproducible; each entry's `ts` **read against `at`** is what lets the reader see which rows were
  still inside the 6 h exclusion horizon — `ts` alone cannot, which is why `at` is on the marker.
  Note also that once a row is past the 7 h retention floor
  (`RETENTION_FLOOR_SECONDS`, `model-health.py:112`) it can leave the window to the **global
  `MAX_RECORDS` count cap** and not only to age (`prune`, `:602-617`) — so "the window shrank" is
  not a pure function of elapsed time, and unrelated fleet traffic can change an issue's evidence
  set.
- **Repeated decisions.** Idempotence is on `key=` — the decision input, rows *and* tier sequence
  (or, in the scoped-down variant, its published projection) — and never on the
  evidence alone: if the bot has already posted this marker with this key, post nothing, exactly as
  `_decline_marker_action` (`:6409-6427`) does. **An evidence-only key would be wrong here, and the
  routing function is why.** `excluded_tiers` cuts on `now` (`no_change_routing.py:145-151`), so an
  **unchanged** row list yields `retry-other-tier` on one tick and `proceed` on the next as soon as
  the last excluding row ages past `TIER_EXCLUSION_SECONDS` — both directions are pinned in the
  self-test at `:322-328` — and exhaustion flips the same way as rows age out from under
  `remaining`. Deduplicating on the rows would suppress the second arm entirely, leaving a receipt
  count that is neither a count of decisions nor a faithful arm history; and a `reason-driven` /
  `exhaustion-driven` flag cannot repair that, because the second receipt would never be written to
  carry it. With the recency bits, `chain`/`remaining`, the two chain digests and the arm inside the
  preimage, **any cutoff transition that changes the arm necessarily yields a new `key=`**, a row
  added or pruned yields one via `evidence`, and a re-resolved or edited chain yields one via
  `chain-digest`. ⚠️ What stays deliberately invisible is a tick that changes *nothing* — same rows,
  same recency partition, same chain, same arm. Those collapse to one receipt, so this is a count of
  distinct **decisions**, never of dispatch attempts. A tick count needs a separate counter, and this
  record does not propose one. ⚠️ Under the scoped-down variant the two collisions listed above stay
  invisible as well, and they are *not* no-op ticks — that is the whole cost of omitting the digests.

**The denominators this yields.** Decision-level: the count of distinct `key=` receipts — which is
**distinct (evidence, recency partition, ordered chain, ordered remaining, arm) decisions**, and must
be labelled that way rather than as "decisions" unqualified or "dispatch attempts"; under the
scoped-down variant it is instead a **lower bound** on distinct routing decisions, because the two
collisions above merge inputs that differ, and it must be published under that name. Row-level: the sum of entry
counts across receipts, where a row appearing in K receipts contributes K times — double-counted, but
*visibly* so, because the receipts name it, and `evidence=` is what lets a reader collapse the
receipts that share one window. Both are countable offline from the issue timeline, and the row-level
one is *verifiable* there, because `evidence=`'s preimage is the comment body itself. The
decision-level one is only verifiable to a reader that also holds the resolved chain: `key=` is
counted from the timeline, checked from the dispatch side.

⚠️ **One denominator hazard, named because §10 invites it.** If the maintainer takes §10's
suggestion and suppresses the `proceed`-arm receipt as noise, the denominator is no longer *all*
decisions — it is all **non-`proceed`** decisions, and every rate computed against it is inflated by
exactly the suppressed population. That is pre-flight item 8's rule applied to this store. Either
emit the `proceed` receipt (including on the quiet tick), or publish the ratio against a denominator
the record explicitly names as partial. Silently dividing by "decisions" is the same fabricated
measurement as Finding A's 0 %, one layer over.

## 9. What a mismatch should DO

**Report only. `DECOMPOSE_REASONS` is a maintainer edit, and the measurement must not license it
automatically.** Three independent reasons; the second is the one that would survive even if
everything else were built:

**9.1 It is an arm-adjacent trust surface.** `DECOMPOSE_REASONS` decides which issues take the
**terminal** routing arm. Widening it retires issues from implementation; narrowing it spends
leases re-running a task whose blocker is its shape. `orchestration/routing.toml`'s keyword sets are
already load-bearing for both model selection and the arm-side classifier, and the standing rule is
that a machine never thins them. A measurement that edits its own routing constant is the same
class of object.

**9.2 The counterfactual is censored by construction — the data can never license the edit.**
`retry_decision` checks the reason **first** (`no_change_routing.py:188-189`): a declared
`too_large` goes to `decompose` *even when an untried tier exists*. So for the `DECOMPOSE_REASONS`
population, "what would the lateral ladder have done?" is **never observed** — there is no treatment
arm, because the rule under test is what assigns treatment. Any "`too_large` should be removed from
`DECOMPOSE_REASONS`" conclusion drawn from this correlation is fitting on a population the rule
itself selected: precisely the self-grading circularity `research/809-area-derivation-feasibility.md`
had to hold out for, except here the hold-out set **cannot be constructed from observational data at
all**. Answering it needs a deliberate, maintainer-authorised experiment (e.g. a bounded sample
routed laterally despite the declared reason), and that is a decision, not a metric.

**9.3 A census that steers is no longer a census.** The feedback loop is direct — a narrowed
`DECOMPOSE_REASONS` changes which rows the next window contains, so the measurement's input is a
function of its own last output. Nothing downstream could then read the distribution as evidence.

So: publish the correlation the way #1595 publishes the census — unconditionally, including the
all-zero row, with `reason-driven` and `exhaustion-driven` decomposes counted separately — and let a
mismatch be **maintainer-visible**, exactly like the throughput alerts. If a threshold is wanted
later, the fail-closed direction is an *alert*, never an automatic constant edit.

## 10. What this record does NOT establish

Stated plainly, because an over-claimed design record gets cited as a decision:

- **No number is measured here.** Every finding is derived from the checked-out tree by reading
  code, offline. This record does not say which reason dominates, how often `decompose` is
  exhaustion-driven, or whether the routing is in fact wrong. It says what would have to exist
  before those questions have an honest answer.
- **#1595 is not on `master` at the time of writing** (its change is on the `#1595` PR branch;
  `no_change_reason_census` does not exist in this checkout). §6's finding is stated against that
  change as proposed and should be re-checked against whatever merges. **That re-check has since
  been done — §6.1.** #1595's shape never merged; #1827's did, without the `undeclared` key §6's
  bullets assume, so those two bullets no longer describe anything on `master`. The producer half of
  the finding survives and is now documented and pinned (#1950).
- **§8's option C is a sketch, not a spec.** §8.1 pins the one part that cannot be left open —
  what the marker must carry for §1's join to close — but the *cost* is unresolved: one comment per
  decision on the issue timeline, on a plane four consumers already parse. A `proceed`-arm comment
  in particular may be pure noise and is probably better left unrecorded; §8.1 states what that
  choice costs the denominator, and the maintainer should steer it before anyone writes the marker.
  The marker's grammar, and whether a decision over an unchanged *input* should be visible at all,
  are also still open — as is the disclosure call §8.1 leaves to the maintainer, which is the larger
  of the two: publishing aliases would make `chain`/`remaining` reader-derivable instead of
  bot-asserted, and withholding even their digests decides whether `key=` binds the decision at all
  or only its published projection (§8.1's scoped-down variant, whose denominator is a lower bound).
- **Findings B and D are defects, not design options.** Both are filed separately; neither is
  repaired here, and (b) cannot be answered honestly while D stands.
