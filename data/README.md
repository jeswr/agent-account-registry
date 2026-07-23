# data/ — TOMBSTONE: the mutable data plane moved to the `ledger` branch

**Do not read or write the JSON files in this directory on `master`.** They are frozen
snapshots from the 2026-07-17 migration (issue #28) and are kept only so consumers deployed
before the migration do not hard-crash; removing them entirely is a tracked follow-up.

The live, bot-written data plane — `data/leases.json`, `data/model-health.json`,
`data/cache-affinity.json`, `data/metrics-history.json`, `data/metrics.json`, plus the record stores
`orchestration/provenance/*.json` and `orchestration/review-verdicts/*.json` (issue #96) —
lives on the dedicated, **unprotected** [`ledger` branch](../../tree/ledger/data). Why a
separate branch:

- `master` carries required-status-check branch protection (`gate`), which rejects every
  `github-actions[bot]` contents-API `PUT` — that outage silently starved ALL dispatch,
  mislabeled as "account cap is active" (issue #28).
- Granting the bot a protection bypass instead would let a compromised workflow push **code**
  to `master`. Confining bot writes to a branch from which no workflow executes keeps master's
  protection fully intact.
- The `ledger` branch is an **orphan, DATA-ONLY branch**. The single canonical allowlist lives in
  `scripts/ledger-invariant.py`: mode `100644` blobs may be only `README.md`, flat
  `data/*.json`, or flat `orchestration/{provenance,review-verdicts}/*.json`; only the parent
  directories may be mode `040000` trees. Every other path, mode, or Git object type is refused.
  This is load-bearing, not cosmetic (review rounds 1–2): a
  `workflow_dispatch` at `ref: ledger` executes the **ledger's** copy of a workflow file, so
  the non-execution property requires no workflow file at that ref (a dispatch against it
  404s; no workflow in this repo triggers on `push`).
- Why the invariant HOLDS against the confined actor (review round 2): the only credential
  the bot/compromised-workflow actor holds is Actions' `GITHUB_TOKEN`, and **GitHub refuses
  every `.github/workflows/**` create/update from a token without the `workflows` permission
  — which `GITHUB_TOKEN` never has** (platform-enforced, on every branch). An actor with a
  workflow-scoped PAT (the repo owner) can already push arbitrary workflows to any unprotected
  branch repo-wide, so `ledger` adds zero net-new execution surface. Defense-in-depth on top:
  every master's reader workflow and scheduled `groom.yml` run that same validator immediately
  after checkout, before consuming ledger content. (A path-restriction push ruleset
  would be stronger still, but push rulesets are not available on a user-owned repo plan.)

Every reader/writer pins the ref via the `LEDGER_REF` constant
(`REGISTRY_LEDGER_REF` env override, default `ledger`) in `scripts/select-and-claim.py`,
`scripts/groom.py`, `scripts/model-health.py`, `scripts/metrics.py`, and `scripts/worker-pr.py` (provenance +
verdict record writes, issue #96); workflow-side readers use an explicit `ref: ledger`
checkout (`dispatch.yml` PLAN + CLAIM, `review-fix.yml` resolve + run, `groom.yml`,
`dashboard.yml`). Record readers consult the ledger checkout FIRST and fall back to the
master-checkout copy so pre-outage records stay visible. Readers fail LOUD if the `ledger`
branch is missing — never silently-empty.

Provenance and review-verdict records are additionally authenticated with HMAC-SHA256 in
`ledger_hmac_sha256`. Writers and trusted host-side readers receive the dedicated
`LEDGER_RECORD_HMAC_KEY` environment secret; it is never stored on the ledger or passed to a
model command. Missing-key, unsigned, or modified records are rejected fail closed, so
`contents:write` access to the unprotected data branch alone cannot forge an implementer or
verdict identity. Deployments must configure this secret before enabling record writers; legacy
unsigned envelopes are intentionally not trusted and must be re-recorded by a trusted writer.

## `data/observability.json` — agent-run observability snapshot (issue #246)

The dashboard's Observability panels (cache effectiveness / per-lane run health + top defer
reasons / queue-lease-review flow / auto-fixer trigger fires) render the OPTIONAL
`observability` key of the published `site/data.json`. That key is produced by
`scripts/dashboard-gen.py --observability ledger/data/observability.json` from a snapshot the
metrics collector persists on the `ledger` branch. Until the collector lands, the file is
simply absent and the panels stay hidden — the rest of the dashboard is unaffected.

The consumer-side contract IS `dashboard-gen._normalize_observability()` (self-tested with a
golden fixture; collector authors: build against it, not this prose). Root shape:
`{"schema": "registry-observability/v1", "generated_at", "cache", "lanes",
"defer_reasons_1h", "model_exit_classes_1h", "flow", "trigger_fires", "thresholds"}` — every
group optional. Validation is FAIL-CLOSED: an absent file hides the panel; a present document
with the wrong `schema` fails the dashboard build LOUD; malformed rows inside a well-formed
document are dropped (the model-health tolerance) — EXCEPT privacy violations, which are
always fatal (decision 22): a `flow.leases[].label` that is not the 8-hex HMAC-salted account
label raises, trigger `evidence` links are pinned to `https://github.com/`, and the existing
`_assert_private` raw-handle sweep runs over the finished document.

## `data/metrics-history.json` — throughput time-series (ring)

`scripts/metrics.py` (workflow `metrics.yml`, `*/15` cron) CAS-appends a per-target throughput
snapshot here, pruned to a bounded ring (`REGISTRY_METRICS_RING`, default 24 snapshots ≈ 6h). It is
the durable rate-OVER-TIME record that backs the backlog-vs-drain alert rules. **Every** alert rule
is SUSTAINED (K-snapshot): its condition must hold in ALL of the last `sustain_snapshots` snapshots
before it fires, so a single spiky tick never alarms. Document shape:

```json
{"snapshots": [
  {"generated_at": "2026-07-18T09:10:00Z", "_ts": 1752829800, "schema_version": 1,
   "targets": {
     "<owner/repo>": {
       "issues_open": 1048, "issues_ready": 86,          // ready = the DRAINABLE count from the
       "issues_closed_1h": 0, "issues_closed_24h": 31,   //   target's REAL readiness definition
       "prs_open": 52, "prs_draft": 34,                  //   (sparq: ready-issues.ready_candidates
       "prs_opened_1h": 5, "prs_closed_1h": 0,           //   label-gate — NOT the one-per-package
       "prs_merged_1h": 0, "prs_merged_24h": 51,         //   concurrency width; registry: open
       "review_changes_backlog": 10, "needs_user_parked": 23,  //   from:agent), NOT a label count
       "review_lane_health": "ok|idle|stalled|unknown",  // stalled = review-fix runs CONCLUDED with
       "review_lane_runs_1h": 3,                         //   0 success + a review:changes backlog;
       "worker_attempts_1h": 4,                          //   idle = backlog but 0 concluded runs;
       "worker_success_rate_1h": 0.75,                   //   drafts are NOT part of the backlog
       "pr_open_rate": 5.0, "pr_close_rate": 0.0, "net_pr_flow": 5.0  // net>0 => backlog GROWING
     }
   }}
]}
```

`review_lane_health` and the worker counts are read off the runs of the repo that HOSTS each
target's `review-fix.yml` / `worker.yml` (this registry — sparq's review/worker orchestration is
driven cross-repo from here, not from a sparq-hosted workflow), filtered to the target by its
run-name and windowed by run COMPLETION time; in-progress runs count as neither an attempt nor a
success. Absent that signal the health is `unknown` (fail-open — never a false `ok`).

The current snapshot is also CAS-written to `data/metrics.json` on the `ledger` branch (same
per-target shape plus a top-level `alerts: [...]`). The sole Pages owner, `dashboard.yml`, copies it
to `site/metrics.json` in its generated artifact for the dashboard panel to consume. Alert rows:
`{target, classification, fire, summary, metrics}` where `classification ∈ {backlog-growing,
review-lane-stalled, ready-starved, worker-failing}`. Alerts are deduped to ONE rolling
`throughput-alert`-labelled issue per `(target, classification)`, and auto-close only with
hysteresis (the condition must be clear for `recover_snapshots` consecutive ticks) so a
boundary-flapping metric never churns the same issue open/closed — never spammed. A target SKIPPED
this tick (its read-token mint failed) keeps its live alerts; recoveries are reconciled only for
targets actually collected.

Per-target alert thresholds live in `policy/repos.toml` (`[repos.*].throughput`); defaults are in
`metrics.DEFAULT_THRESHOLDS`. Mutating a threshold flips the alert (mutation-checked in
`scripts/metrics.py --self-test`).

> **Rate-window caveat.** `pr_open_rate` / `pr_close_rate` derive from the `*_1h` search windows,
> but snapshots run every 15 min, so consecutive windows overlap by 45 min: a single burst is
> visible in several consecutive windows. The SUSTAINED gate therefore attests "the condition held
> across K ticks", not "K independent hours" — for K independent windows set
> `sustain_snapshots ≥ 4` (window ÷ interval). The `backlog-growing` PR-open threshold gate guards
> against a lone small burst tripping it regardless.
