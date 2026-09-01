# data/ — TOMBSTONE: the mutable data plane moved to the `ledger` branch

**Do not read or write the JSON files in this directory on `master`.** They are frozen
snapshots from the 2026-07-17 migration (issue #28) and are kept only so consumers deployed
before the migration do not hard-crash; removing them entirely is a tracked follow-up.

The live, bot-written data plane — `data/leases.json`, `data/model-health.json`,
`data/metrics-history.json`, `data/metrics.json` (NOT `data/cache-affinity.json`, which has no
producer at all — see below), plus the record stores
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
  every master's reader workflow and scheduled `groom-sweep.yml` run that same validator immediately
  after checkout, before consuming ledger content. (A path-restriction push ruleset
  would be stronger still, but push rulesets are not available on a user-owned repo plan.)

Every reader/writer pins the ref via the `LEDGER_REF` constant
(`REGISTRY_LEDGER_REF` env override, default `ledger`) in `scripts/select-and-claim.py`,
`scripts/groom.py`, `scripts/model-health.py`, `scripts/metrics.py`, and `scripts/worker-pr.py` (provenance +
verdict record writes, issue #96); workflow-side readers use an explicit `ref: ledger`
checkout (`dispatch.yml` PLAN + CLAIM, `review-fix.yml` resolve + run, `groom-sweep.yml`,
`dashboard.yml`). Record readers consult the ledger checkout FIRST and fall back to the
master-checkout copy so pre-outage records stay visible. Readers fail LOUD if the `ledger`
branch is missing — never silently-empty.

## `data/cache-affinity.json` — NO PRODUCER, on either branch (issue #1557)

This file is deliberately NOT in the live-data-plane list above: it is not part of that plane,
because nothing has ever written it. `README.md` §Cache-affinity metadata described it as "a rolling
`{account -> [{package,role,model,at}]}` affinity for prompt-cache warm-routing" and its own
`_comment` still says so, but a repo-wide search finds no writer and no reader — the frozen master
copy is `{"accounts":{}}` and there is no `ledger`-branch counterpart to read.

Prompt-cache affinity is **derived at claim time** from the lease ledger by
`select-and-claim.choose_account` (most-recent lease for the same `package`+`role`), so it needs no
store — but it also keeps **no history**, which is what a rolling affinity file would have provided.
So the observability `cache` group's `warm_drain_rate_1h`, `drained_1h` and `chain_length_histogram`
had no source in this repo, and issue #1839 **retired all three** rather than leave three contract
fields open against a producer that cannot exist while affinity is re-derived per claim.
`prompt_cache_read_fraction_1h` / `usage_samples_1h` stay, and come from the provider usage responses
the account-usage probe already reads. Do not build a collector against this file — and re-opening
the retired fields is producer-first: record the chain transitions durably, then re-add the field.

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
group optional, and an optional group means **omit it** — a group supplied with nothing readable
in it is not a group of zeros. `cache` is the one that had this backwards (issue #1557):
`usage_samples_1h` / `drained_1h` were coerced to `0` on publication, so a `cache` key with no
parseable field rendered a confident `of 0 drained / 1h` on a panel no producer has ever filled.
It now publishes only when **at least one** of its fields parses — a measured `0`/`0.0` is a
reading and still publishes, an unreadable or empty group is dropped and NAMED on stdout. **And the
group is TWO fields, not five (issue #1839): `prompt_cache_read_fraction_1h` and `usage_samples_1h`.**
`warm_drain_rate_1h`, `drained_1h` and `chain_length_histogram` are RETIRED — send one and it is
ignored (never republished, and never measurement enough to publish the group) and named on stdout,
so a collector on the old contract hears about it rather than watching its data vanish.
**Every row array on this panel is a top-N DISPLAY slice** — 12 lanes, 12 `flow.queue` classes, 12
`flow.target_ci_queue` repositories, 16 defer reasons, 16 model exit classes, 20 trigger fires — and
the rows past a cap are dropped SILENTLY, because a truncation of rows the seam successfully read is
a display contract rather than the producer/consumer mismatch #982/#1570/#1571 announce. Since issue
#1868 the published document carries the pre-cap total of the WELL-FORMED rows beside each slice
(`lanes_total`, `defer_reasons_1h_total`, `model_exit_classes_1h_total`, `trigger_fires_total`,
`flow.queue_total`, `flow.target_ci_queue_total`) and `dashboard/app.js` renders `showing 12 of 50`,
so a fleet with 50 congested target repositories no longer renders identically to one with 12. These
are OUTPUT-side keys: a collector neither sends them nor is read for them, and each is published on
every build, including the ones where the cap hid nothing. The page states a note only where the
total is a whole NUMBER OF ROWS greater than the slice beside it — a missing, non-numeric, negative,
fractional or already-satisfied total is "no truncation known" and draws nothing, so a document
published before #1868 or edited by hand degrades to the old silence instead of a fabricated count.

**Issue #2009 closed the one slice nested INSIDE a row**: a fire's `evidence` links are still cut at
5, but the cut is now counted first — `trigger_fires[].evidence_total` is the number of links that
survived the `https://github.com/` pin, published on every fire including the ones that hid nothing,
and the page draws a per-FIRE `+7 more` beside the links rather than a card-level note (a
`showing 5 of 12` above a stack of alarms names none of them). The 8-link cap on the READ is gone
with it: it truncated the list before the pin ran, so a 9th link that was not a github.com URL was
neither published nor counted by the drop diagnostic that exists to announce exactly that. `evidence`
itself remains unbounded on the way in, like every other row array here.

Validation is otherwise FAIL-CLOSED as before: an absent file hides the panel; a present document
with the wrong `schema` fails the dashboard build LOUD; malformed rows inside a well-formed
document are dropped (the model-health tolerance) — EXCEPT privacy violations, which are
always fatal (decision 22): a `flow.leases[].label` that is not the salted account fingerprint
raises, trigger `evidence` links are pinned to `https://github.com/`, and the existing
`_assert_private` raw-handle sweep runs over the finished document.

**The label is the CANONICAL account fingerprint — `sha256(handle + ":" + salt)[:16]`, 16 lowercase
hex (locked decision 22a; issue #375).** It is the same value `model-health.account_hash` /
`worker-pr.account_hash` produce and the same one `data/leases.json`, the provenance records and
the model-health ledger already carry, so a collector reuses that helper rather than deriving a
second identity format. Until issue #375 this seam validated an 8-hex shape no producer in this
repo emits, which meant the canonical fingerprint every other surface uses would have failed the
dashboard build while a truncated half of it passed as "salted". Tightening it was safe in this
order only because the collector has not landed: there is no producer to break, and the shape it
must be built against is now the canonical one. An 8-hex label is now FATAL, not a second accepted
format.

**`flow.leases` rows are DEPRECATED — send `flow.lease_utilization_1h` instead (issues #374,
#841).** Issue #374 stopped the per-account rows being PUBLISHED: a `{label, provider,
utilization_1h}` array is a direct read of the fleet's size and its salted labels are stable
across builds, which is exactly what the dashboard's own `accounts` array was removed for. But
#374 only fixed the Pages surface — this snapshot itself is a file on the **public** `ledger`
branch, so a contract that says "keep sending the rows and we will drop them" still parks that
same array one branch over from the page it cleaned (issue #841).

So the aggregate is now the contract. Send `flow.lease_utilization_1h = {"mean", "max"}`,
computed collector-side, and write no per-account rows anywhere:

- **Preferred (row-free).** `flow.lease_utilization_1h` is published as-is once both fields are
  real fractions and `max >= mean`. An incoherent or half-supplied aggregate is DROPPED (the stat
  hides) rather than published as a plausible number — it carries no identity, so it takes the
  malformed-row tolerance, not the fatal path.
- **Legacy (rows).** `flow.leases[]` is still accepted and still aggregated to the same
  `{mean, max}`. Precedence is ROWS-FIRST and total, and it keys on the PRESENCE of the `leases`
  key rather than on whether a row parsed: send that key at all and the rows decide the published
  value, down to the `null` you get when none of them reports a usable `utilization_1h`. The
  aggregate is consulted only by the genuinely row-free form. So a collector mid-migration that
  sends both publishes exactly its pre-#841 value and nothing changes silently underneath it.
- **The decision-22 label check is unconditional over whatever rows ARE present** — supplying the
  aggregate is not a way past it. A raw (non-salted) handle in a lease row is a privacy incident
  whether or not this build would have published that row, and it still fails the build LOUD.

Note this closes only the dashboard's half of #841: `data/leases.json` on the same branch is one
row per live lease and is producer-side (`select-and-claim.py`), still tracked there.

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
