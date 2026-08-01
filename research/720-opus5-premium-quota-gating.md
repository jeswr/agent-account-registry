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

**One stale comment does say otherwise**, and it is worth correcting because it is the kind of
thing a future change reasons from: `orchestration/routing.toml:276`, in the `role = "ci"` block,
claims `escalate = true` "flips a starved item to needs:user". It has not done that since #116.
The `role = "impl"` block at lines 239–246 in the *same file* describes the post-#116 behaviour
correctly. Two comments in one file disagreeing about the terminal class is a live hazard.

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
| observed, unparseable (shape drift) | **refuse** | provider changed under us; `_assemble_fable`'s posture |
| never observed on this account | **admit, loudly** | absence of evidence; refusing self-latches the sole tier |

Collapsing rows 3 and 4 — which the current `fable_ok` idiom does — is the outage.

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
3. Implement §4's three-way fail direction. The never-observed row must admit; make it loud
   (a `::warning::` and a usage-alert row), and consider bounding it the way `unproven`
   reachability is bounded — after N consecutive probe failures on an account, that account's
   opus5 state becomes *observed-dead* and refuses.

### On #720's "same change" requirement

Steps 1 and 2 of the issue cannot land in one PR in the sense the issue implies, and it is worth
being precise about why: **the observation is a runtime output, not a code artifact.** No PR can
contain the answer to "what headers does `claude-opus-5` return", because producing that answer
requires a probe running against real credentials in the dispatch workflow. What *can* and *must*
land together is the producer field and the consumer gate — and Stage B does exactly that. The
window #720 worries about ("we know but do not act") is closed by Stage A emitting nothing any
consumer reads.

### On step 4

No change needed — §2.5. The follow-up is to fix the stale `routing.toml:276` comment so the next
reader does not re-derive a conclusion the code stopped supporting in #116.

---

## 8. Test obligations, mapped to seams

#720 names three. Where each would have to bite, and what mutation reds it:

| obligation | seam | mutant it must catch |
|---|---|---|
| healthy whole-account headroom + exhausted opus5 bucket ⇒ **refused** | `usage_eligible`, `select-and-claim.py:551` | delete the premium arm |
| no opus5 bucket data at all ⇒ **behaves as today** | same, never-observed row of §4 | flip never-observed to refuse (this is the outage test — it must be a *named* test asserting admission) |
| a cliff produces a **capacity park, never `needs:user`** | `escalate_persist_decision` + the `_park_source_issue` write at `dispatch-claim.py:8729` | swap `MACHINE_PARK_LABEL` (`park_policy.py:112`) for `HUMAN_PARK_LABEL` (line 119) |

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
- No performance or cost numbers are asserted; §5 row 4 is a measurement to take, not one taken.

## References

- `scripts/select-and-claim.py` — 427–436 (`PREMIUM_MODELS`), 488–497 (`_fable_eligible`),
  499–553 (`usage_eligible`), 519–535 (the `unproven` self-latch argument), 604, 627–653, 683
- `scripts/account-usage.py` — 18–27 (`7d_oi` empirical note), 49–57, 80–96, 99–110, 112–125,
  159–178, 180–189, 301–341, 403, 1597–1625
- `scripts/dispatch-claim.py` — 7807–7830, 8008–8055, 8690–8790
- `scripts/deprecated_models.py` — `DEPRECATED_ALIASES`, `assert_no_deprecated`
- `scripts/park_policy.py` — 1–60, `MACHINE_PARK_LABEL`, `capacity_park_readmitted`
- `orchestration/routing.toml` — 132–134, 183–191, 239–251, 260–263, 276, 282–285, 291–295,
  300–303, 310–320
- `.github/workflows/dispatch.yml` — 1765, 1889–1926, 2187
- Prior records: registry #116 (starvation ladder), #639 (exemption ≠ reachability), #703
  (park classes), #715 / sparq#4211 (the deprecation)
