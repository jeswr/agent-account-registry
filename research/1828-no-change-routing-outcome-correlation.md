# #1828: correlating the `why_no_diff` census with what dispatch actually DID — the design record

> 🤖 **SPARQ agent** — findings-only design record. **Nothing in this PR changes behaviour**, and
> that is deliberate: #1828 asks for the design record *before* any code. #738 §7 M4 has two halves.
> (a) *which reason dominates* is delivered by #1595's `model-health.no_change_reason_census`.
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

| join | left | right | key | right-hand lifetime |
|---|---|---|---|---|
| **J1 — reason → decision** | the `why_no_diff` on a health row | the arm `retry_decision` took for that row | `(issue, ts)` | the dispatch tick (a workflow log line) |
| **J2 — decision → outcome** | that arm | what became of the issue | `(repo, issue)` | permanent issue state |

The census answers neither. It is a *marginal* distribution over the left column of J1. Every
finding below is about why J1 and J2 are harder than a `GROUP BY` over the same blob.

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
| C | the **target issue's own timeline**, via a new distinct bot-comment marker at the decision site | yes | yes | one extra comment per decision; must not touch `ATTEMPT_MARKER`'s grammar (§5); still needs a reader to aggregate |
| D | derive nothing durably; answer M4(b) as a **bounded one-off study** against the API, published as a record | yes (log-limited) | yes | not standing; costs a maintainer-run query; the J1 half degrades as Actions logs expire |

**Recommendation: C for J1's missing half, and D for the first answer.**

The reasoning is one property: **the join must be recorded where the longer-lived side lives.**
J2's right column is permanent issue state; J1's right column currently lives for the life of a log
line. Writing the short-lived fact into the long-lived store (C) closes the gap with one durable
artifact. Writing the long-lived fact into the short-lived store (A/B) does not — it re-creates
Finding A one layer over.

Concretely, C is: at `dispatch-claim.py:8586-8613`, post one bot comment carrying a **new** marker
— `arm` (`proceed` / `retry-other-tier` / `decompose`), the declared reason set that drove it, and
whether the decompose was **reason-driven or exhaustion-driven** (§5's population split, which is
the fact nothing records today). It is bot-authored, so it inherits the existing "only the
orchestration bot's own comments are receipts" filter (pre-flight item 5) and cannot be forged from
a target repo. It is *adjacent to*, and must not modify, the existing decline-escalation receipt,
whose `key=` is an idempotence hash over evidence (`_decline_escalation_evidence`, `:6402-6406`) —
changing that marker re-fires escalations that already reconciled.

**Do A only if a maintainer independently wants `issue` on success rows** for another reason. It
should not be bought by this measurement.

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
  change as proposed and should be re-checked against whatever merges.
- **§8's option C is a sketch, not a spec.** It has an unresolved cost — one comment per decision
  on the issue timeline, on a plane four consumers already parse — and the maintainer should steer
  that before anyone writes it. A `proceed`-arm comment in particular may be pure noise and is
  probably better left unrecorded.
- **Findings B and D are defects, not design options.** Both are filed separately; neither is
  repaired here, and (b) cannot be answered honestly while D stands.
