# Per-tick dispatch telemetry — making the dispatcher able to attribute its own stall

Design record for `scripts/dispatch-telemetry.py` and the `frontier-census` / `assembler-census`
blocks in `.github/workflows/dispatch.yml`.

## Why

`research/crate-region-parallelism.md` §8 in the sparq target gates the "split the over-broad
non-crate partitions" work behind **Gate A**:

> Instrument the dispatcher to record, per tick, `frontier_width`, `realised_dispatches`, and
> `conflict_deferrals` attributed by held area. Open the gate only when realised dispatches ≥ ~80%
> of frontier width for a sustained period … Until then, widening the frontier adds plan rows
> nobody executes.

Before this record existed, `grep -rn "frontier_width\|realised_dispatch\|conflict_deferral"`
returned zero hits across both repos, and the public feed (`data/metrics.json`) carried
`issues_ready`, `worker_attempts_1h` and `worker_success_rate_1h` — none of the three. An
unevaluable gate is a permanently closed gate.

The broader reason: noticing where the pipeline is stuck was a manual, once-per-tick human job.
This is the instrumentation that lets the system attribute its own stalls.

## What the tick records

One record per (tick, target) on the `ledger` branch, `data/dispatch-telemetry.json`, a bounded
ring (`REGISTRY_DISPATCH_TELEMETRY_RING`, default 480 ≈ 40h of both targets).

### The dispatch chain, as disjoint legs that sum

The single most useful thing here is not any one number but that the legs *add up*, so a loss
cannot hide between two counters:

```
frontier_and_retry_rows   = frontier_width + deferred_retry_width      (PLAN, readiness engine)
  - route_rejections      rows plan_dispatch refused (ambiguous / unconfigured role)
  - assembler_deferrals   rows the busy-area + lease partition ate     (PLAN, assemble step)
  - claim_deferrals       rows CLAIM saw but did not launch
  - realised_dispatches   rows whose worker run was LAUNCHED           (CLAIM)
  - unrealised_planned_rows
  = unaccounted           carried EXPLICITLY, normally 0
```

`conflict_deferrals` (candidates the target's package partition dropped before the frontier) is
recorded alongside with per-held-area attribution, since that is Gate A's wording.

### The population census

`frontier_width` alone cannot express a *missing edge* — the defect class behind registry #753,
where PRs re-skipped ~135 times over 45h produced no label, no error and no count. So the record
also partitions **every** open issue in the target snapshot into disjoint buckets
(`frontier`, `conflict-deferred`, `trust-or-linked-excluded`, one `excluded:<class>` per readiness
verdict) and carries `unclassified` explicitly, at zero too. A dispatch state that stops having an
exit shows up as a growing bucket, not as a quiet rebalance.

An admitted, non-candidate issue for which the readiness engine returns no verdict is deliberately
left unbucketed and lands in the residual: inventing an `excluded:other` for it would hide exactly
the missing instrumentation the census exists to expose.

## Three constraints that shaped the design

**1. The log is not a usable channel.** GitHub's secret masker rewrites `{` and `}` to `***`.
Measured on run `30222895098`: 159 log lines carry `***`, and the corruption reaches genuine runtime
stdout, not only the echoed script source — a self-test line printing `frozenset({'live',
'unproven'})` came out as `frozenset(***'live', 'unproven'***)`. So the record goes to the ledger
over the contents API, and the single log line is brace-free `key=value` text; `render_log_line`
raises rather than emit a brace.

**2. Cost.** The conflict-resolver author rejected a census in `metrics.py` because its snapshot
lacks `mergeable` and counting there would cost one detail fetch per open PR per run. That finding
is respected: every input here is derived from data PLAN and CLAIM already fetch. The only added
cost is **one contents GET + one contents PUT per dispatch tick** (the CAS shape `model-health.py`
already uses) and **one contents GET per metrics run**.

**3. No double counting.** Registry #737 was a `sort|uniq -c` inflating a count 4×. Every bucket
counts distinct issue numbers, parsed area attribution is capped at the subtraction-derived total,
and `append_records` is idempotent on `(run_id, repo)` so a replayed emission is a confirmed no-op.

## Where the loss actually is (measured, not assumed)

Live sparq snapshot, 2026-07-26, run through the shipped census block:

| quantity | value |
| --- | --- |
| open issues | 1403 |
| drainable candidates | 374 |
| **frontier_width** | **15** |
| **conflict_deferrals** | **359** (attributed across 25 areas + a capped `__other__`) |
| census buckets | sum to 1403, `unclassified` = 0 |

And from dispatch run `30222895098` (the last successful tick before this work):
`PLAN complete: 0 issue item(s)`, 30 `assembler defer` lines, `lane worker: planned=0 launched=0`.

That is the finding that changed the design: the frontier was not narrow, it was **consumed at the
assemble leg** by the busy-area/lease partition, and no counter existed on that leg at all — the
pre-existing `frontier_size` field is literally assigned the *post*-filter `planned` count, so it
cannot see the loss by construction. Hence `assembler_deferrals` / `assembler_by_area`.

**Gate A verdict on that evidence: firmly CLOSED** (realised 0 against a non-empty frontier).
Nothing in this record opens it; it only makes the question answerable per tick.

## Publication

`metrics.py` folds the newest record per target onto the published snapshot as
`targets.<repo>.dispatch`, with an explicit `status ∈ {ok, stale, no-record, unavailable}`:

- `stale` — the newest tick predates `REGISTRY_DISPATCH_STALE_SECONDS` (default 2700). A dead
  dispatcher must not present its last good tick as current.
- `no-record` (this target never reported) is kept distinct from `unavailable` (the ring could not
  be read) — collapsing them would hide an outage.
- `realisation_rate` is `null` on an empty frontier: a tick with nothing to dispatch says nothing
  about whether the frontier is the ceiling, and counting it as a pass is how a gate opens on no
  evidence. `gate_a.open` requires `GATE_A_SUSTAIN_TICKS` informative ticks all at/above the ratio.

The panel rides the **published** snapshot only, not the `metrics-history.json` ring rows — the
telemetry ledger is already the time series, so duplicating a census onto every ring row would only
inflate that blob.

## Honest limits

- `realised_dispatches` counts a confirmed workflow **launch**. A worker that launches and then
  no-ops is still counted as realised; the dispatcher cannot observe the worker's outcome inside
  its own tick. The complementary signal is `worker_success_rate_1h` on the same feed. This record
  does not measure worker yield, and Gate A's ratio should be read with that in mind — it can only
  ever be an upper bound on genuinely productive dispatch.
- A cross-cutting (`__global__`) candidate is attributed to the deterministic first reserved area,
  not to a fabricated `__global__` holder — the same convention the sparq readiness engine uses.
- Area-attribution cardinality is capped at 25 keys plus `__other__`; the **total is preserved**.
- The registry target's readiness engine gained the `conflict_log` sink so both targets attribute
  identically. A target planner without it degrades to `attribution: "unavailable"` with the whole
  count in `__unattributed__` — loudly, never as a fabricated zero.

## Cross-references

- `scripts/dispatch-telemetry.py` — the record, census, chain, Gate A evaluator, ledger CAS.
- `.github/workflows/dispatch.yml` — `frontier-census` (PLAN readiness) and `assembler-census`
  (PLAN assemble) sentinel blocks, both EXTRACTED AND EXECUTED by the telemetry self-test.
- `scripts/dispatch-claim.py` — `_by_repo_summary`, the per-target worker-lane counters.
- `scripts/ready-issues.py` — `compute_ready(conflict_log=…)`.
- `scripts/metrics.py` — `dispatch_panel`, `read_dispatch_telemetry`, `attach_dispatch_panels`.
- `data/README.md` — the ledger data plane this record joins.
