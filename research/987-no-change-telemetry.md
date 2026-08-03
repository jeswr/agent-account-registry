# #987: per-issue telemetry for the no-change gate — the design record

> 🤖 **SPARQ agent** — findings-only design record. Nothing in this PR changes behaviour.
> #987 (split out of #466 AC3) proposes adding `worker_no_change_1h` /
> `worker_no_change_rate_1h` + a per-reason breakdown + a repeat-offender list to
> `scripts/metrics.py`, "derived from the same health window
> `dispatch-claim._read_model_health_window` already reads". This record checks that suggestion
> against the code and finds **one structural blocker the issue does not mention** (§4), plus a
> denominator that is not the one the issue assumes (§5). The maintainer should steer §8 before
> anyone writes the collector.

## 1. The question, restated as a property

The fleet's per-tick worker outcome is already counted; its *composition* is not. The property
#466 AC3 wants:

> From the published snapshot alone, a reader can tell how much of this hour's worker failure rate
> was **the model exiting clean with no diff**, and — separably — whether that was `already_done`
> (the issue is finished; close it) or `underspecified` (the issue needs a human).

That distinction is what decides an operator action, and it is exactly the distinction the current
snapshot erases.

## 2. What the snapshot carries today (grounded)

`compute_target_metrics` emits two worker fields — schema comment at `scripts/metrics.py:48-49`,
derivation at `scripts/metrics.py:188-190`:

```python
worker_attempts = g("worker_attempts_1h")
worker_success_rate = (round(g("worker_success_1h") / worker_attempts, 4)
                       if worker_attempts > 0 else None)
```

The `None`-at-zero-attempts idiom is the established one and #987's "rate stays null, not 0.0"
acceptance criterion is asking for the same shape. It is asserted at `scripts/metrics.py:1414-1418`.

**Where those two counts come from matters, and it is not the health ledger.** `collect_counts`
(`scripts/metrics.py:668-672`) calls `_worker_runs` → `_orchestration_lane_runs`
(`scripts/metrics.py:704-738`), which paginates `repos/{orchestration_repo}/actions/runs`, keeps
runs whose workflow matches `WORKER_WORKFLOWS = ("worker",)` (`:680`) **and** whose
`display_title` names the target (`_run_matches`, `:683-692`), and counts the ones that *concluded*
inside the trailing hour. `worker_attempts_1h` is therefore **a count of GitHub Actions run
conclusions**, keyed to a target by the run-name seam that `scripts/run_name_grammar.py` pins.

So today a `no_change` run is inside `worker_attempts_1h` and outside `worker_success_1h` — because
`worker-live.sh:645-660` sets `WORKER_EXIT_CLASS=no_change` and then `die 'model produced no
repository changes'`, i.e. the worker job *fails*. The issue's framing is right: it is
indistinguishable from a compile error, a lease loss, or a push rejection.

## 3. The raw signal, and two stale line references in the issue

The signal exists and is typed, as the issue says — but not where it says.

* The writer is **`make_record`, `scripts/model-health.py:494-533`** (not `:428`, which is inside
  the `AUTH_COOLDOWN_MIN` comment block). It attaches `issue` and `why_no_diff` only when
  `exit_class == no_change`.
* The closed-enum check is **`scripts/model-health.py:896-901`** (not `:747`, which is
  `validate_ledger`'s tolerated-field warning):
  `if "why_no_diff" in r and r["why_no_diff"] not in NO_CHANGE_REASONS: raise`.
* The value reaches the record via `WORKER_RESET_HINT` — the `no-change-v1 issue:N,why:K` envelope
  built in `worker-live.sh:153-180` and decoded by `_parse_no_change_envelope`
  (`scripts/model-health.py:2800`). The recorder step is `.github/workflows/worker.yml:2199-2204`.
* The vocabulary is `no_change_routing.NO_CHANGE_REASONS` (`scripts/no_change_routing.py:63-70`):
  `unspecified, underspecified, blocked_on_decision, too_large, already_done, other`.

**`why_no_diff` is optional on the row.** `make_record` drops any `None` field (`:530-532`), and
`unspecified` is index 0 precisely so an absent declaration is not inferred to be a
decompose-triggering value (`no_change_routing.py:71-77`). A breakdown must therefore fold
**absent → `unspecified`**, not drop the row; otherwise the counts do not sum to
`worker_no_change_1h` and the "how many models refused to say why" signal — the one that tells you
whether the declaration mechanism itself is working — disappears.

## 4. The blocker: a health record has no target repo

`RECORD_KNOWN_FIELDS` (`scripts/model-health.py:288-291`) is:

```
ts, provider, account, model_alias, exit_class, run_id, reset_hint
    + input_tokens, output_tokens, wall_seconds, issue, why_no_diff
```

There is **no repo field**, and `issue` is validated only as a bounded int
(`:889-890`). The metrics snapshot is keyed per target (`targets: {"owner/repo": {...}}`), and
`policy/repos.toml` carries three rows — `sparq-org/sparq`, `jeswr/agent-account-registry`
(both enabled) and `jeswr/solid-sdk` (enabled = false, pending solid-sdk#23). Issue numbers collide
across those repos trivially; #987 itself is a registry number that also exists in sparq.

**A per-target `worker_no_change_1h` cannot be derived from the health window alone.** This is the
part of the issue's suggested design that does not survive contact with the schema, and it is also
what makes the "repeat-offender list keyed on `issue`" ambiguous — `issue: 987` names no repository.

Three ways out:

**Option A — join on `run_id`, using data metrics.py already fetches.** The health `run_id` is
`"$GITHUB_RUN_ID.$OUTCOME_ATTEMPT"` of the **worker.yml run** (`worker.yml:2191-2204`; the recorder
job is `needs: worker`, same workflow run). `_paginate_runs` already returns those run objects with
`id` and `display_title`, and `_run_matches` already attributes them to a target. So: build
`{str(run["id"]): target}` from the runs metrics.py has in hand, split each no_change row's
`run_id` on `"."`, and attribute. Join on the **id prefix only** — the runs *list* API returns the
latest attempt, while `OUTCOME_ATTEMPT` deliberately pins the attempt that produced the outcome
(`worker.yml:2191-2197`), so an attempt-suffix comparison would silently drop re-run rows.
*Costs:* no extra API calls beyond one contents GET for the ledger; `metrics.yml` takes a full
checkout (`metrics.yml:39-42`) so importing `model-health.py` by path — the pattern already used
for `gh_403.py` (`metrics.py:777`) and `ready-issues.py` — needs no sparse-checkout edit. The
registry token (`REGISTRY_GH_TOKEN`, `metrics.yml:102`) already has the `contents` scope the ledger
read needs.
*Weakness:* the join is only as good as the run-name seam, and it inherits `_paginate_runs`'
`page_cap=10` bound and the `created>=` fetch lookback. A no_change row whose worker run is outside
the fetched page set attributes to nothing — a **silent zero**, the exact failure class
`run_name_grammar.py` was written for (#1130: 0 of 100 titles matched for eight days). Any
implementation must count and `::warning::` the unattributed rows, per the repo's no-silent-caps
convention (`metrics.py:94-96`).

**Option B — add a `repo` field to the health record.** Honest and permanent, but it touches the
shared public ledger schema: writer + `RECORD_KNOWN_FIELDS` + the field grammar + every reader,
under the rolling-upgrade constraint documented at `model-health.py:308-315` (a worker's registry
checkout is pinned at dispatch and its health job runs tens of minutes later). The read posture is
already additive-tolerant since #739, so this is *safe*, but it is a schema change to the trust
plane's data plane for an observability want — a much larger blast radius than #987 justifies on
its own. Worth doing if something else also needs it; not worth doing only for this.

**Option C — publish the no-change fields FLEET-WIDE, outside `targets`.** Add a top-level
`fleet: {no_change_1h, no_change_by_reason_1h, ...}` block instead of per-target fields. This is
the honest encoding of what the ledger can actually prove without a join, and it matches the
ledger's own `provider: "fleet"` convention (`dispatch.yml:2147-2175`). *But* it collides with
`PUBLIC_SNAPSHOT_KEYS` (`metrics.py:90`), a deliberately closed top-level key set for a document
served at `jeswr.github.io/agent-account-registry/metrics.json` — so it is a reviewable widening of
the public surface, by design. It also cannot feed the existing per-target alert machinery, all of
which reads per-target ring rows (`_recent_rows`, `metrics.py:221-229`).

## 5. The denominator is not the one the issue assumes

#987 says "threshold-alert it the way `worker_success_rate_1h` already is". That rate has a single
source: both numerator and denominator come from the same Actions-run pass. A no-change rate does
not:

| | source | window basis |
|---|---|---|
| `worker_attempts_1h` | Actions runs on the orchestration repo | run **completion** time (`_run_in_window`, `metrics.py:694-701`) |
| no_change rows | model-health ledger on `ledger` | `ts` stamped in the **recorder job**, which runs after the worker job concludes |

Consequences, all of which should be written into the field's doc comment rather than discovered
later:

1. **Boundary skew.** A worker that concludes at 10:59:50 and whose recorder writes at 11:00:10
   lands its attempt in one hour and its no_change row in the next. With a small denominator the
   ratio can exceed 1.0. Either clamp and warn, or accept and document — do not silently `min()`.
2. **A missing recorder biases the rate DOWN.** No row is written if the record step fails; the
   attempt is still counted. The metric under-reports, which is the *safe* direction for a
   "wasted-run" alarm (it under-fires rather than over-fires), but it is a real fail-open and
   should be named as such.
3. **Retention.** `prune` (`model-health.py:602`) keeps a 48 h window with a 7 h *time-based*
   retention floor (`RETENTION_FLOOR_SECONDS`, `:112`) that overrides the `MAX_RECORDS = 200` count
   cap — so a 1 h window is **not** at risk from the count cap. It *is* still bounded by the
   absolute ceiling (`RETENTION_CEILING_RECORDS = 2000` / `RETENTION_CEILING_BYTES = 750_000`,
   `:128-129`), which can cut inside the floor at an extreme record rate. That is a genuine, if
   remote, undercount path.
4. **Skipped targets.** `metrics.yml:50-73` mints per-owner read tokens `continue-on-error`; a
   target whose token fails to mint is skipped and contributes no snapshot row at all. The health
   ledger read uses the registry token and would still succeed — so a naive fleet-wide read could
   report no_change rows for a target that has no row this tick. `compute_recoveries`
   (`metrics.py:1130`) already treats "not collected this tick" as *no evidence*; the new
   field must not create a second, contradicting notion of presence.

## 6. Publication surface

`data/metrics.json` is CAS-published to the `ledger` branch and copied verbatim into the Pages
artifact (`metrics.py:83`, `dashboard/app.js:451-459`). So a repeat-offender list means **issue
numbers and a `why_no_diff` classification on a public page**.

Two honest observations, in tension:

* This is **not a new disclosure class.** `issue` and `why_no_diff` are already on the public health
  ledger, and `why_no_diff` is a closed enum precisely so model-authored text can never reach a
  public document (`model-health.py:896-899`). Republishing them is a re-presentation, not a leak.
* But it is a **new aggregation**. "Issue #N has burned 4 worker slots and the model says
  `underspecified`" is a judgement about a specific issue, rendered on a public dashboard.
  That is a maintainer call, not an implementer's — flagged here, not decided.

Independently: `PUBLIC_SNAPSHOT_KEYS` is a closed key set **at the top level only**. The per-target
dict inside `targets` is unbounded, so a new per-target field reaches the public page with no
boundary check. That is not a defect introduced by #987, but #987 is the first change to lean on it.
Filed as follow-up work rather than fixed here.

A repeat-offender list also needs an explicit cap with a logged truncation (`metrics.py:94-96`) and
a ring-size sanity check: `MAX_SNAPSHOTS = 24` (`:93`) rows × 3 targets × a 6-key reason breakdown
is small, but an *uncapped* offender list is not.

## 7. Alerting

Adding a fifth classification is more than a predicate. The surfaces that must all move together:

| surface | location |
|---|---|
| classification constant | `metrics.py:102-105` |
| fire predicate (also used for recovery) | `_CLASS_PRED`, `metrics.py:1122-1127` |
| the class tuple | `ALERT_CLASSES`, `metrics.py:1117` |
| threshold defaults | `DEFAULT_THRESHOLDS`, `metrics.py:108-115` |
| threshold **type** validation | `_thresholds_of`, `metrics.py:357-377` — note the `int`-unless-`worker_success_floor` branch at `:372-376`; a second float key must be added there or it is rejected as "must be a positive integer" |
| policy schema prose | `policy/repos.toml` throughput block |

`worker_min_samples` (default 3) is the right guard and #987 is correct to reuse it. Gate it on
`worker_attempts_1h` — the rate's **denominator** — exactly as `_worker_failing_pred` already does
(`metrics.py:255-262`, whose comment names the reason: "a single failed run (attempts=1) is noise").
The attempts are the observations, so they are the sample size; a guard on the *attributed no_change
count* would gate eligibility on the outcome, treating 100 attributable attempts that produced 2
no-change rows as a 2-sample hour rather than a 100-run one. It also fails at the anti-noise job it
was meant to do, in the direction that matters: an hour with 4 attempts that were all no_change
clears a 3-row numerator guard while still being a 4-observation sample — precisely the spiky tick
the guard exists to suppress.

**Attribution completeness is a separate property and needs its own control.** A target with 20
attempts and 1 attributable row is not a small sample; it is a rate of 0.05, which a high-side
alert would not fire on anyway. The hazard there is the §5.2/§4 one — dropped rows bias the rate
DOWN, so the alert under-fires — and no minimum-sample guard can see it, because a silent join miss
and a genuine absence of no-change runs are numerically identical. Carry it separately instead:
emit the unattributed-row count **always** (a real zero, not an omitted key) alongside a coverage
ratio, and **refuse to evaluate** the alert for that tick when coverage is below a declared bar,
rather than evaluating a rate known to be incomplete. Deferring is the fail-closed direction:
it withholds a verdict instead of publishing a confidently wrong low one.

Every rule in this file is SUSTAINED over K snapshots with `recover_snapshots` hysteresis
(`_sustained`, `metrics.py:231-238`). A no-change rate is *exactly* the kind of metric that flaps
across a rolling-1h boundary, so it must go through `_sustained` like the others — not be evaluated
point-in-time.

## 8. Recommendation (maintainer to steer)

**Option A, in two beads, smallest first.**

1. **Bead 1 — count and attribute, no alert.** Read the health window in `collect_counts`, join on
   the `run_id` prefix, emit `worker_no_change_1h` (int) and `worker_no_change_rate_1h`
   (float|null, `None` at zero attempts) plus `worker_no_change_by_reason_1h` (a dict over all six
   `NO_CHANGE_REASONS`, absent folded to `unspecified`, always fully populated so a zero is a real
   zero). Emit `worker_no_change_unattributed_1h` (int, always present) as a snapshot field, not
   only as a `::warning::` — bead 2's coverage bar (§7) has to read it from the ring, and a log line
   is not in the ring. Warn on it as well, per the no-silent-caps convention. **No new alert
   class.** This alone satisfies #466 AC3's "observable" and gives the ring the history a threshold
   needs to be chosen from evidence rather than guessed.
2. **Bead 2 — alert, once bead 1 has ring history.** Add the classification, the threshold key,
   and the mutation-check. The key is a **ceiling**, not a floor: a no-change alert fires when the
   rate is too HIGH, the opposite direction to `worker_success_floor` (`wsr < floor`,
   `metrics.py:261`). Name it `worker_no_change_ceiling`, with the predicate

   ```
   isinstance(rate, (int, float))
       and worker_attempts_1h >= worker_min_samples
       and rate > worker_no_change_ceiling
   ```

   Strictly `>`, mirroring `open_pr_alert_threshold` (`prs_open > th[...]`, `metrics.py:240`),
   so the boundary value itself does NOT fire and a ceiling of `1.0` is a coherent way to disable
   the rule. Being a float, it must join `worker_success_floor` in the `_thresholds_of` float branch
   (`metrics.py:372-374`) or it is rejected as "must be a positive integer" (`:376`) — the same
   trap flagged in §7's table.

   Picking the ceiling's *value* before any snapshot exists means picking it from the #466-era ~75%
   recollection, which is a measurement of a different lane at a different time. That is what bead 1
   ships first to avoid.

Reject the repeat-offender list **in this shape**. The value is real, but a public per-issue
league table is a maintainer decision (§6), and the same information is already actionable through
`no_change_routing.retry_decision` + the decline ladder — the loop that #701 exists to bound.
If it lands, it belongs behind the same choice that governs whether it is published at all.

**Reject Option B for #987 alone** (§4): a public-ledger schema change under the rolling-upgrade
constraint is disproportionate to an observability field, though it is the cleaner end state if a
second consumer ever needs per-repo health attribution.

## 9. What is NOT known

* **The current no-change rate.** The ~75% in #466 is a recollection of a different measurement
  (`no_change_routing.py:6-9` records the grounded one: 126 of 196 completed runs failed,
  no_change dominant, measured 2026-07-26). Nothing in this repo measures it *now*, which is the
  whole point of #987. No threshold should be defended by a number from this record.
* **The attribution hit-rate of the Option A join.** It is unmeasured. #1130's precedent —
  0 of 100 titles matching for eight days, silently — is the reason bead 1 must ship the
  unattributed-row warning *before* anything alerts on the counts.
* **Whether `why_no_diff` is populated often enough to be useful.** The field is optional and
  model-authored; if most rows fold to `unspecified`, the `already_done` vs `underspecified` split
  #987 asks for does not exist yet, and the honest first finding of bead 1 would be "the
  declaration mechanism needs work", not a threshold.
* **Whether this is sound.** Nothing here has been reviewed against the trust-plane's security
  posture beyond the surface reading in §6. It is a design survey, not an audit.

## 10. Acceptance criteria, mapped

#987's acceptance list is implementable as written **for bead 1**, with one correction:

| #987 says | as implementable |
|---|---|
| "a fixture health window containing N no_change rows produces the new fields" | needs a fixture *pair*: health rows **and** the orchestration runs they join to, or the fixture proves nothing about attribution (§4) |
| "a window with zero attempts leaves the rate null (not 0.0)" | as written — mirrors `metrics.py:1414-1418` |
| "mutation-check that the threshold flips the alert" | bead 2 only; there is no threshold in bead 1 |
