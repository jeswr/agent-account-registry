# Opus 5 premium-quota gating: what to observe, and why the gate cannot fail closed first

> 🤖 **SPARQ agent**

Design record for registry #720. **Findings only — this record changes no behaviour.** Every claim
below is cited to the code as it stands at the time of writing; where the code and a comment
disagree, the code is reported.

---

## 1. The question

`select-and-claim.py:435` gates a "premium sub-quota" bucket:

```python
PREMIUM_MODELS = frozenset({"fable"})
FABLE_WINDOW = "fable_7d_oi"
```

After the 2026-07-26 deprecation, `opus5` is the sole anthropic tier. #720 asks: does
`claude-opus-5` have its own rate-limit bucket, and if so, should admission gate on it?

The answer has to come from data. This record establishes what the code does today, what it would
take to observe the answer, and — the finding that dominates everything else — **why the
fail-closed shape the issue asks for would, applied naively, take the whole fleet down rather than
protect it.**

---

## 2. What the code does today

### 2.1 No probe is ever addressed to `claude-opus-5`

There are exactly two probes, and neither names the model the fleet actually runs on:

| probe | model sent | shape | `account-usage.py` |
|---|---|---|---|
| base (whole-account 5h/7d) | `claude-haiku-4-5` | plain | `_probe_anthropic`, line 112 |
| premium sub-quota | `claude-fable-5` | Claude-Code UA + system prompt | `_probe_fable`, line 180 |

`_probe_fable` runs only for accounts whose catalog `models` list contains `fable`
(`_probe_account`, line 333). `fable` is in `deprecated_models.DEPRECATED_ALIASES`. So for any
account still carrying that catalog entry the fleet is, every tick, spending a request on a
**retired provider model** — `_assemble_fable` returns `None`, the fields are absent, and nothing
downstream is affected because nothing downstream asks for them (§2.2). It is dead cost, not a
correctness bug, but it is dead cost repeated per account per tick.

**The fleet therefore has zero observations of `claude-opus-5`'s rate-limit headers.** Not
"unobserved and hard to observe" — unobserved because no request is made.

### 2.2 `PREMIUM_MODELS` currently governs nothing

`usage_eligible` applies the premium arm at `select-and-claim.py:551`:

```python
if model in PREMIUM_MODELS and not _fable_eligible(u, margin):
    return False
```

`model` reaches that line from `dynamic_concurrency` (line 649) and `_choose_account_model`
(line 604), in both cases drawn from a route's `model_chain`. No `model_chain` in
`orchestration/routing.toml` names `fable`, and `deprecated_models.assert_no_deprecated` raises on
any that tries. **`model` can never equal `"fable"`, so line 551 is unreachable.** The issue's
central claim is confirmed: the premium gate is inert, and admission for every route now rests
entirely on the whole-account 5h/7d headroom test at lines 543–550.

### 2.3 The observation seam is one function, and it discards

`_parse_rate_headers` (`account-usage.py:49`) is already general — it keeps **every**
`anthropic-ratelimit-unified-*` header, prefix-stripped and lowercased. Nothing is lost there.

The loss is one function later. `_assemble_usage` (line 99) hand-builds the entry from a fixed key
list:

```python
entry = {"status": ..., "5h_util": ..., "5h_reset": ..., "7d_util": ..., "7d_reset": ...}
for key, source in (("5h_limit", "5h-limit"), ("7d_limit", "7d-limit")):
```

Any header the provider emits under a name this list does not enumerate is parsed and then
dropped on the floor. If `claude-opus-5` returns, say, a `7d_o5-utilization` bucket, the current
code would see it and forget it — on every probe, forever.

That is the whole of the observation problem. **The "observe" half of #720 is a change to one
function's key handling, not new probe machinery** — plus a probe actually addressed to
`claude-opus-5`, since the haiku base probe will not surface a premium bucket even if one exists
(the FABLE-5 header block at `account-usage.py:18–27` records that the `7d_oi` headers appear only
on a Claude-Code-shaped request naming the premium model).

### 2.4 `_fable_eligible` is window-hardcoded — the one-line fix is the wrong fix

The obvious reading of #720 step 2 is "append `opus5` to `PREMIUM_MODELS`". That would be actively
harmful. `_fable_eligible` (line 488) hardcodes the fable probe flag and the fable window:

```python
if not isinstance(u, dict) or not u.get("fable_ok"):
    return False
util, _ = _usage_window(u, FABLE_WINDOW)
```

Adding `"opus5"` to the frozenset therefore gates opus5 admission on **`fable_ok` and the fable
bucket's headroom** — precisely the "gate opus5 on another model's headers" failure the existing
comment at lines 431–434 was written to prevent. Since `fable_ok` is never set any more (§2.1),
the practical effect would be `_fable_eligible` returning `False` for every account, for every
opus5 route, i.e. total fleet starvation.

`PREMIUM_MODELS` has to become a mapping (alias → probe-ok flag + window prefix) **before** any
alias can be added to it. The set-shaped API only ever worked because it had exactly one member.

### 2.5 The `needs:user` premise in #720 step 4 is already false

The issue asks that a quota cliff not terminate into `needs:user`. **That was fixed by issue #116
and the current code already does what #720 asks for.** The ladder in `dispatch-claim.py`:

- `escalate_starved` (line 7807) — true only when a live usage map shows `effective_cap == 0`. A
  missing usage map reads as unknown and merely defers.
- `escalate_persist_decision` (line 8008) — the first starved tick posts a durable
  `STARVE_ALERT_MARKER`, sets `status:deferred`, and auto-retries. Only *continuous* starvation
  past `ESCALATE_PERSIST_SECONDS` (30 min, line 7829) promotes.
- The promotion target (lines 8712–8746) is `status:parked` — `park_policy.MACHINE_PARK_LABEL`,
  the machine-owned soft hold — explicitly **not** `needs:user`. The comment at 8712–8717 and
  `park_policy.py:6–13` both say so, and `capacity_park_readmitted` / `capacity_park_admission`
  provide the automatic re-admission path.

So the five single-rung routes (§3) do degrade gracefully today: defer → alert → machine park →
auto-readmit. #720's blast-radius argument is directionally right about *which* routes are
exposed, but wrong about *where they land*.

**Two stale comments say otherwise, not one.** An exact search for `needs:user` in
`orchestration/routing.toml` returns four sites; they split two and two:

| line | text | verdict |
|---|---|---|
| 141–142 | security-label override header: "on chain-exhaustion, **ESCALATES** to a human (`needs:user`) rather than degrading" | **stale** — that route (183–191) lands in `status:parked` |
| 276 | `role = "ci"`: `escalate = true` "flips a starved item to `needs:user`" | **stale** — same reason |
| 14 | an approved trust-surface PR "is routed to a HUMAN arm (`needs:user`), never auto-armed" | correct — the review-lane **arm gate**, a different mechanism |
| 278 | the security override "still WINS (opus + human arm)" | correct — arm gate again |

Only the first two describe the *starvation* terminal, and both are wrong post-#116. The
`role = "impl"` block at 239–246 in the same file describes the post-#116 behaviour correctly and
in detail. So the file contains three descriptions of one terminal class, two of which contradict
the code — and the stale one at 141–142 sits in the header of the very route §3 lists as the most
exposed. That is a live hazard, not a typo: a future change reasons from whichever comment it
reads first.

The same override header carries an adjacent staleness worth fixing in one pass: lines 139–140
describe "opus-4.8 as tail fallback … so an opus5 capacity outage degrades to the previous
soundness tier", while the route's `model_chain` at line 188 is `["opus5"]` alone. The fallback
that comment promises is the one §3 records as absent.

---

## 3. Who is actually exposed

Routes with a single-rung `["opus5"]` chain and no cross-provider fallback:

| route | lines | `escalate` |
|---|---|---|
| security-label override | 183–191 | true |
| `role = "impl"` | 247–251 | true |
| `role = "research"` | 291–295 | true |
| `role = "review"` | 310–314 | true |
| `role = "soundness"` | 316–320 | true |

Routes that survive an opus5 cliff by degrading to `sol`: `site` (260–263), `ci` (282–285), `docs`
(300–303), and `[defaults]` (132–134).

Five of nine routes have no anthropic fallback **and no cross-provider fallback either** — which is
deliberate: those are the authorship-restricted surfaces, and `chain_preference.py:137,211` exists
specifically to stop a well-meaning change from adding a rung to them. A cliff there is *meant* to
be a visible stall. The question #720 raises is only whether the stall is detected at admission
(cheap) or mid-run (a burned lease + burned credits).

---

## 4. The finding that dominates: fail-closed on a sole tier is an outage

#720 step 3 asks that unreadable opus5 sub-quota data refuse admission rather than fall back to
whole-account headroom. As a statement about *observed-then-drifted* data, that is right and it
matches how `_assemble_fable` already behaves (line 159: any parse mismatch → `None` →
`_fable_eligible` refuses).

But the premium gate's fail-closed default also treats **never-observed** as refuse — that is what
`if not u.get("fable_ok"): return False` means. That default was safe for fable because fable was
one rung of a multi-rung chain: a fable-ineligible account still served the chain's other rungs.

**opus5 has no other rung on five of nine routes.** A fail-closed premium gate on opus5 that is
armed before every account is *known* to probe successfully does not degrade the fleet — it stops
it. Every opus5 route reads `effective_cap == 0`, `escalate_starved` fires fleet-wide, and within
30 minutes every escalate-tier issue is machine-parked simultaneously. The gate would be
indistinguishable, from the outside, from the total quota exhaustion it was built to prevent.

This is the same self-latch that `select-and-claim.py:519–535` already argues about at length for
`USAGE_REACHABILITY_UNPROVEN` (registry #639): *no dispatch ⇒ no records ⇒ unproven forever ⇒ no
dispatch*, with no recovery path. That block's resolution — admit on `unproven`, bounded, and let
positive evidence of deadness be what refuses — is the precedent this repo has already reasoned
through for exactly this shape, and it is the right one here.

**So the fail direction has to be split three ways, not two:**

| bucket state | admission | rationale |
|---|---|---|
| observed, headroom ≥ margin | admit | normal |
| observed, exhausted | **refuse** | the case #720 exists to catch |
| observed, unparseable (shape drift) | **refuse after N consecutive, admit loudly before** | provider changed under us — but see §4.1 |
| never observed on this account | **admit, loudly** | absence of evidence; refusing self-latches the sole tier |

The current `fable_ok` idiom collapses rows 3 and 4 into a single immediate **refuse**, and on a
sole tier that is the outage. Note that rows 3 and 4 still *admit alike* for the first N−1 ticks;
what separates them is destiny, not this tick's decision, and §4.1 is what makes that destiny
representable at all.

### 4.1 The state that makes rows 3 and 4 distinguishable, and where it has to live

The table above is not implementable against the Stage A data as first drafted, and that gap is
exactly at the gate's fail direction, so it is spelled out here rather than left to Stage B.

**The problem.** Stage A's output is a per-tick header set inside the ephemeral usage snapshot that
`account-usage.py main()` writes and `select-and-claim` reads once. On a tick where the expected
opus5 window is absent, that snapshot alone cannot tell row 3 from row 4: a newly enrolled account
that has never been probed and an account that exposed the window last week and has now drifted
produce byte-identical snapshot entries (no window). It also cannot count "N consecutive" anything
— it has no yesterday. Left unspecified, an implementer picks a reading, and both readings are bad:
refuse-on-absent reproduces §4's fleet self-latch, admit-on-absent means row 3 never fires and the
gate is vacuous.

**The store already exists.** This repo has one durable per-account record and one guarded writer
for it: the account catalog issue body, written by `persist_limits` (`account-usage.py:536`) via
`_persist_one` (line 484) — a read-merge-write whose version stamp is the issue's body-edit count,
which fails loudly rather than clobbering a concurrent edit — and validated before every write by
`select-and-claim.account_record_schema_errors` (line 1313). The `limits:` line (`LIMIT_KEYS`,
line 403; `_limits_line`, line 415) is an existing instance of exactly this shape. Premium-bucket
state should be a second front-matter line through the same seam, not a new store.

**Fields**, per account, keyed by model alias:

- `last_ok` — RFC3339 UTC of the most recent probe that returned a *well-formed* window.
- `fail_streak` — probes since `last_ok` that reached the provider and did not return one.

Absence of the line is itself meaningful and is the safe default: `persist_limits` already skips
accounts missing from the snapshot and writes nothing when `_limits_line` returns `None`, so a
never-probed account carries no state, which is row 4.

**Writer transitions** — at most one per account per tick, and the three-way split matters:

| probe outcome | seam that already distinguishes it | transition |
|---|---|---|
| well-formed window | `_assemble_fable`-shaped classifier returns an entry | `last_ok = now`, `fail_streak = 0` |
| response received, window absent or unparseable | classifier returns `None` after headers were parsed | `fail_streak += 1`, `last_ok` untouched |
| transport failure / no token / account not probed | `_probe_headers` returns `None` (line 80); `_probe_anthropic` (line 112) already splits this from shape failure | **no write at all** |

The third row is load-bearing. A transport failure is evidence about the prober, not about the
account; counting it would let one broken runner, an expired credential set, or a workflow outage
drive every account to the refusing state in N ticks — §4's outage reached by a slower path. The
existing `_probe_anthropic` already makes precisely this distinction (`hdr is None` = transport,
`_valid_base_usage` false = shape); the counter must key off the same split, not off "entry is
falsy".

**Reset** is one rule: any well-formed window zeroes `fail_streak`. There is no other reset path,
and in particular a human edit of the issue body is not one we design for.

One writer hazard, because it is easy to get wrong at this exact seam: `_limits_line` is a pure
function of the snapshot alone, but a *streak* line is not — it depends on the record's prior
value. The increment therefore has to be computed inside `_persist_one`'s read-merge, from the body
that read returns, not precomputed once from the snapshot. `_persist_one` retries up to
`PERSIST_ATTEMPTS` (line 444) when a foreign edit lands after ours, and a precomputed
`fail_streak = k + 1` would be re-applied on each retry against a body that already carries it —
silently correct by idempotence in that particular case, but the same shape double-counts the
moment the merge is expressed as "read k, write k+1" outside the retry loop. Make the merge a pure
`(old_line, outcome) -> new_line` function and unit-test it; that is the seam every transition row
in §8 exercises.

**Freshness decays toward admitting, not toward refusing.** A record whose `last_ok` is older than
a TTL (one full weekly window plus slack is the natural choice, since that is the bucket's own
period) reads as row 4 — never-observed — not as dead. An expiry that decays toward refuse turns
any sustained probe outage into a fleet-wide latch with no recovery path, which is the #639 shape
`select-and-claim.py:519–535` already rejected.

**Resolving rows 3 and 4 against Stage B's counter.** As first written, §4's table refused
immediately on drift while Stage B item 3 refused only after N consecutive failures. They cannot
both hold; the counter wins, and the table above is corrected to match. Reason: fable's
refuse-on-first-drift was safe because fable was one rung of a multi-rung chain, so a drift cost an
account a rung. A provider-side header rename hits *every* account on the *same* tick, and on the
sole tier that is a synchronous fleet stop. N converts that into N ticks of loud warnings. The cost
of those N ticks is bounded and is not new: it is exactly today's behaviour (option A). The
counter-argument is real and should bound N — a *single*-account drift is not fleet-wide, and there
each tick below N burns a lease — so N should be small (2–3 ticks), and row 3's "loudly" has to be
an actual usage-alert row, not a log line nobody reads.

**Consumer rules.** The state line is parsed by a pure, unit-tested function next to
`_fable_eligible`, and:

1. **The record supplies "how long", never "whether".** A refusal fires only when *this tick's*
   snapshot also lacks a well-formed window. The durable record can only escalate an
   already-live absence past the streak threshold; it can never refuse on its own.
2. **Malformed state reads as row 4** (admit loudly, `::warning::`) — not as dead. This is
   fail-closed in the direction that matters, and the bound is worth stating explicitly: the
   exhaustion signal comes from the live snapshot, so a corrupt record can at worst downgrade a
   would-be drift refusal to the row the policy already chose to admit. It can never admit past an
   observed-exhausted bucket.
3. **A corrupt state line must not drop the account from the catalog.** `_account_schema_errors`
   (`select-and-claim.py:1266`) validates a required-field allow-list and does not reject unknown
   keys, so an additive line is safe here today — but that also means the consumer is the *only*
   validator, and rule 2 is therefore not optional.

**Trust caveat, not audited.** This state lives in a public issue body that an out-of-band editor
can change, so it is operator-influenceable input to an admission gate. Rule 1 is what keeps that
from being a capacity kill switch — without it, editing one line would refuse an account
indefinitely. Rule 2 is what keeps it from being a bypass. Neither has been reviewed by anyone but
this record; treat the pairing as **needing review before Stage B arms**, not as established.

**If no durable state is wanted**, the alternative is honest and available: drop rows 3 and 4 to a
single "no well-formed window this tick ⇒ admit loudly" row, gate only on observed-and-exhausted,
and accept that shape drift fails open until someone reads the warnings. That is strictly weaker
than the table above and strictly safer than getting the state machine wrong; it is a legitimate
Stage B scope cut, not a failure.

---

## 5. What is not known

Stated plainly, because the recommendation below is shaped entirely by it:

1. **Whether `claude-opus-5` publishes a distinct bucket at all.** No probe has asked. It is
   equally consistent with the evidence that opus5 draws on the same `7d_oi` premium window as
   fable did, on a differently-named window, or on no separate window.
2. **Whether the bucket (if any) is per-account or per-organisation.** The `7d_oi` block's
   empirical note (`account-usage.py:18–27`) covers acct2/3/4 plus the box's own session; nothing
   establishes the granularity for a different model.
3. **Whether the Claude-Code request shape is still the gate.** The premium path was
   subscription-OAuth gated when observed; `_CLAUDE_CODE_UA` is pinned to `claude-cli/2.1.177`
   (line 37). A UA pin is a shape assumption with an expiry date.
4. **What a premium probe costs.** Each probe is a real `max_tokens:1` request. Adding a third
   per-account per-tick probe against the *sole remaining tier* spends that tier's quota to measure
   that tier's quota. If the bucket is small, the measurement is non-trivially self-defeating. No
   number is asserted here; it should be measured from row 1's data before the probe is made
   unconditional.

---

## 6. Options for the gate

**A. Do nothing.** Admission keeps resting on whole-account 5h/7d headroom. Correct iff no distinct
bucket exists. Cost if wrong: a burned lease + partial credits per mid-run failure, recovered by the
existing park/readmit ladder — bounded, not catastrophic. Cost if right: zero.

**B. Add `opus5` to `PREMIUM_MODELS` now.** Rejected. §2.4: with the current window-hardcoded
`_fable_eligible` this gates opus5 on fable's absent headers and starves the fleet. Even after
generalising the window, gating on a bucket nobody has observed is §4's outage.

**C. Observe first, gate second (recommended).** Two changes, in order, with a real interval between
them.

**D. Gate on a *general* premium-bucket rule** — "refuse if any observed sub-quota window for the
routed model is exhausted", discovered from header names rather than a hardcoded alias list. More
future-proof, and it would have caught this class of drift automatically. But it requires the
observation from C anyway to know what names to trust, and a rule keyed on unvalidated provider
header names is a fail-closed gate whose trigger the provider controls. Worth revisiting after C
produces data; not a first move.

---

## 7. Recommendation

### Stage A — observe, changing no admission decision

1. `_assemble_usage` (`account-usage.py:99`): stop discarding. Carry through every parsed
   `anthropic-ratelimit-unified-*` key under a namespaced prefix (e.g. `raw_hdr_<name>`), or at
   minimum persist the observed key **set**. Header *names* are not credential material; the
   privacy posture of the dashboard artifact is about handles and counts, and this adds neither.
   Values for `-limit` headers are already persisted via `LIMIT_KEYS` (line 403).
2. Add a `claude-opus-5` probe with the Claude-Code shape, parallel to `_probe_fable`, run for
   accounts whose catalog `models` contains `opus5`. Record its header set. **Emit no
   `opus5_ok`-style field that any consumer gates on** — Stage A must be observation-only, because
   a producer field that a consumer half-reads is how §4 happens by accident.
3. Retire the now-dead `_probe_fable` call at line 333, or make it conditional on the account
   genuinely serving a live model. It currently spends a request per account per tick on a retired
   model.
4. Give the `Persist probed tier limits` step (`dispatch.yml:1920–1926`) an `id:`. It is the only
   account-usage step in that job without one, so it is the only one
   `dashboard-gen._workflow_step` (line 913) cannot extract — which means the self-test cannot
   assert it structurally, which is exactly the `if: false` hole #720's test obligations name.

Stage A is safe to ship on its own: no admission decision changes, so there is no fail direction to
get wrong.

### Stage B — gate, after at least one full weekly window of Stage A data

Only if Stage A shows a distinct bucket:

1. Generalise `PREMIUM_MODELS` from a frozenset to a mapping `alias → (ok_flag, window_prefix)`,
   and rewrite `_fable_eligible` to take the window from that mapping (§2.4). This is a
   prerequisite, not an optimisation.
2. Add `opus5` with its observed window — **in the same change** as the producer emitting that
   window's fields, which is what #720 step 2 is really asking for and is achievable.
3. Implement §4's fail direction **together with §4.1's durable per-account state** — they are one
   change, not two. The never-observed row must admit, loudly (a `::warning::` and a usage-alert
   row); the drifted row refuses only after N consecutive shape failures, counted and reset by
   §4.1's writer transitions and read under §4.1's three consumer rules. Shipping the gate without
   the state is what §4.1 rules out: the snapshot alone cannot tell the two rows apart, so the gate
   silently becomes either the fleet self-latch or a vacuous check.
4. Extend the front-matter writer for the state line: `LIMIT_KEYS`/`_limits_line`
   (`account-usage.py:403,415`) gains a sibling, routed through the same `_persist_one` edit-count
   guard, and `persist_limits` (line 536) gains an injectable clock — it has no `now` today, and
   `last_ok` is untestable without one. The self-test already injects `run=`, so the idiom exists.

### On #720's "same change" requirement

Steps 1 and 2 of the issue cannot land in one PR in the sense the issue implies, and it is worth
being precise about why: **the observation is a runtime output, not a code artifact.** No PR can
contain the answer to "what headers does `claude-opus-5` return", because producing that answer
requires a probe running against real credentials in the dispatch workflow. What *can* and *must*
land together is the producer field and the consumer gate — and Stage B does exactly that. The
window #720 worries about ("we know but do not act") is closed by Stage A emitting nothing any
consumer reads.

### On step 4

No change needed — §2.5. The follow-up is to fix **both** stale comment sites in one pass —
`routing.toml:141–142` (the security-label override header, the most exposed route) and
`routing.toml:276` (`role = "ci"`) — so the next reader does not re-derive a conclusion the code
stopped supporting in #116. Fixing only one leaves the file still self-contradicting. The two
`needs:user` mentions at lines 14 and 278 describe the review-lane arm gate and must be left
alone. While in that comment block, correct the "opus-4.8 as tail fallback" claim at lines 139–140
against the actual `model_chain = ["opus5"]` at line 188.

---

## 8. Test obligations, mapped to seams

#720 names three. Where each would have to bite, and what mutation reds it:

| obligation | seam | mutant it must catch |
|---|---|---|
| healthy whole-account headroom + exhausted opus5 bucket ⇒ **refused** | `usage_eligible`, `select-and-claim.py:551` | delete the premium arm |
| no opus5 bucket data at all ⇒ **behaves as today** | same, never-observed row of §4 | flip never-observed to refuse (this is the outage test — it must be a *named* test asserting admission) |
| a cliff produces a **capacity park, never `needs:user`** | `escalate_persist_decision` + the `_park_source_issue` write at `dispatch-claim.py:8729` | swap `MACHINE_PARK_LABEL` (`park_policy.py:112`) for `HUMAN_PARK_LABEL` (line 119) |

§4.1 adds a state machine, and every transition in it needs its own red. These are the obligations
that make it non-vacuous — each row names the mutant that must fail:

| transition / rule | seam | mutant it must catch |
|---|---|---|
| well-formed window ⇒ `last_ok = now`, `fail_streak = 0` | state writer in `persist_limits` | delete the reset — `fail_streak` becomes monotonic and every account eventually refuses |
| response with absent/unparseable window ⇒ `fail_streak += 1`, `last_ok` untouched | same | also advance `last_ok`, which makes the TTL never expire |
| transport failure / unprobed ⇒ **no write** | the `hdr is None` vs shape-invalid split (`account-usage.py:112`) | count transport failures too — one broken runner kills the fleet in N ticks |
| `fail_streak < N` + absent window ⇒ **admit** | the pure state reader beside `_fable_eligible` | flip to refuse — this is §4's fleet-stop mutant and needs a *named* test asserting admission |
| `fail_streak ≥ N` + absent window ⇒ **refuse** | same | never refuse — the gate is vacuous and #720 is unfixed |
| `fail_streak ≥ N` **but this tick's window is well-formed** ⇒ headroom decides, record ignored | same (consumer rule 1) | let the record refuse alone — an issue-body edit becomes a capacity kill switch |
| `last_ok` older than TTL ⇒ reads as never-observed (**admit**) | same | treat stale as dead — a probe outage latches the fleet with no recovery |
| malformed/garbage state line ⇒ never-observed + `::warning::`, account **stays in the catalog** | consumer rules 2–3 | raise or refuse — corrupt state removes capacity instead of degrading |

Loudness rows assert over emitted workflow commands via `workflow_commands`
(`account-usage.py:741`), against named message constants in the discipline already set at lines
405–413 — a message and its assertion written as two separate literals drift apart in the
permissive direction exactly once and then stay there.

On the YAML seam: this repo already has the right idiom and it is not substring counting.
`account-usage.py`'s self-test extracts step bodies **by `id:`** via
`dashboard-gen._workflow_step` / `_workflow_step_script` (lines 1597–1625, 1717, 1742) and in
places executes them. A step with `if: false` yields a body the extractor still returns but whose
guard is visible in the extracted text — which is why the assertion has to be over the extracted
body, not over a count of matching lines in the file. Any new probe/persist step must get an `id:`
and an extraction-based assertion, per Stage A item 4.

---

## 9. What this record does not do

- It does not implement Stage A or Stage B.
- It does not assert that any bucket exists. §5 row 1 is genuinely open.
- It does not claim the current admission gate is *sound* — only that it is the pre-existing state,
  that its failure mode is bounded by the #116 park ladder, and that the proposed replacement has a
  worse unbounded failure mode if adopted without observation first. The trust properties of the
  admission path as a whole have not been audited here.
- It does not claim §4.1's state machine is sound. It is specified so that the fail direction is
  decidable rather than left to an implementer, and its trust caveat (durable state living in an
  operator-editable public issue body) is named but unreviewed. It needs review before Stage B arms.
- No performance or cost numbers are asserted; §5 row 4 is a measurement to take, not one taken.

## References

- `scripts/select-and-claim.py` — 427–436 (`PREMIUM_MODELS`), 488–497 (`_fable_eligible`),
  499–553 (`usage_eligible`), 519–535 (the `unproven` self-latch argument), 604, 627–653, 683,
  1266–1324 (`_account_schema_errors` / `account_record_schema_errors`), 1375, 1459
- `scripts/account-usage.py` — 18–27 (`7d_oi` empirical note), 49–57, 80–96, 99–110, 112–125,
  159–178, 180–189, 301–341, 403–421 (`LIMIT_KEYS`, the named diagnostics, `_limits_line`),
  455–482 (`_issue_view`), 484–534 (`_persist_one`), 536–604 (`persist_limits`), 741, 1597–1625
- `scripts/dispatch-claim.py` — 7807–7830, 8008–8055, 8690–8790
- `scripts/deprecated_models.py` — `DEPRECATED_ALIASES`, `assert_no_deprecated`
- `scripts/park_policy.py` — 1–60, `MACHINE_PARK_LABEL`, `capacity_park_readmitted`
- `orchestration/routing.toml` — 14, 132–134, 139–144, 183–191, 239–251, 260–263, 276, 278,
  282–285, 291–295, 300–303, 310–320
- `.github/workflows/dispatch.yml` — 1765, 1889–1926, 2187
- Prior records: registry #116 (starvation ladder), #639 (exemption ≠ reachability), #703
  (park classes), #715 / sparq#4211 (the deprecation)
