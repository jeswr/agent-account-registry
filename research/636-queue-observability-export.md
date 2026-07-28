> 🤖 SPARQ agent

# 636 — Exporting task-queue depth/oldest-age to the dashboard and the metrics collector

**Status**: design record / findings only. No behaviour changed by this document.
**Question**: issue #636 asks to "surface the same figures in `scripts/dashboard-gen.py` and
`scripts/metrics.py`" that #243 Phase A exposed drain-side. What does that actually require,
given what is on `master` today?

**Headline finding, stated up front because it changes the shape of the work**: the issue's
premise does not hold on `master`. `scripts/task-queue.py` is **not on `master`** — it exists only
on the unmerged branch `origin/sparq-agent/issue-243-30145257121-1` (commit `84a7cf6b6`, which adds
`scripts/task-queue.py`, `.github/workflows/drain.yml`, and the `dispatch.yml`/`policy-resolve.py`
enqueue edges). Meanwhile the **dashboard half of #636 is already implemented**, by a different
route than the issue assumes, and the actual gap is a *producer* nobody has written. The
"pure functions already return exactly the needed shape" claim is false on three axes. Details
below.

---

## 1. What is actually on `master` today

### 1a. The dashboard already consumes per-class queue depth and oldest-age

`scripts/dashboard-gen.py` validates and publishes exactly the figures #636 asks for, through the
**issue-#246 agent-run observability snapshot**, not through any `task-queue` import:

- `OBS_QUEUE_CLASS_RE = re.compile(r"[1-4][a-z]?")` — commented in-source as *"the #243 queue
  classes (1, 2, 2a..2d, 3, 4)"* (`scripts/dashboard-gen.py:54`).
- `queue_age_clamp_minutes` is a member of `OBS_THRESHOLD_KEYS` (`scripts/dashboard-gen.py:57-58`),
  so the anti-starvation clamp is already a publishable, collector-tunable threshold.
- `_obs_flow()` parses `flow.queue` as a list of rows and emits
  `{"class": str, "depth": int, "oldest_age_minutes": float|None}`, dropping malformed rows and
  sorting by class, capped at 12 (`scripts/dashboard-gen.py:1279-1290`, returned at `:1372-1375`).
- `_normalize_observability()` folds that into the published document under `flow`
  (`scripts/dashboard-gen.py:1408-1458`); an absent input file yields `None` and hides the panel
  rather than failing the build.
- The self-test pins the contract with a fixture carrying `{"class": "2a", "depth": 1,
  "oldest_age_minutes": 12.34}`, a class-only-integer row, and a rejected `"9z"` row
  (`scripts/dashboard-gen.py:3058-3060`, expected output at `:3094`).

### 1b. The page already renders it, including the class-2 clamp alarm and a depth trend

`dashboard/app.js`:

- `obsFlowCard()` renders a `"task queue depth · oldest age"` list, one row per class
  (`dashboard/app.js:790-806`).
- The class-2 clamp is already the red state: `const late = age !== null &&
  String(row.class).startsWith("2") && age >= thresholds.queue_age_clamp_minutes`
  (`dashboard/app.js:798-800`) — i.e. the non-terminal class-2 alarm #636 describes is on the page.
- `OBS_DEFAULT_THRESHOLDS.queue_age_clamp_minutes = 10` (`dashboard/app.js:582`) matches
  `DEFAULT_HEAL_MAX_WAIT_MINUTES = 10` on the #243 branch.
- A `"queue depth trend"` sparkline exists (`dashboard/app.js:856`), fed by `obsRecordTrend()`
  summing `row.depth` across classes (`dashboard/app.js:613-618`).

### 1c. Wiring exists; the producer does not

`.github/workflows/dashboard.yml:401` already passes
`--observability ledger/data/observability.json`, and the comment immediately above it
(`:391`) says the snapshot is *"OPTIONAL on the ledger until its collector"* ships.

**Nothing in this repository writes `data/observability.json`.** The evidence is a *writer*-oriented
search, not a mention count — the word appears in more places than a reader might expect, and all of
them are consumers, UI, or prose. `grep -ril observability` (excluding `.git`) matches twelve files
— this record plus the eleven below:

| file | what it is | can it persist `data/observability.json`? |
|---|---|---|
| `scripts/dashboard-gen.py` | the consumer (`--observability`, `_normalize_observability`) | no — reads a path handed to it |
| `.github/workflows/dashboard.yml:391,401` | passes `--observability ledger/data/observability.json` | no — read-side flag + the "until its collector" comment |
| `dashboard/app.js`, `dashboard/index.html:108`, `dashboard/styles.css:189` | render the published `site/data.json` key | no — browser-side |
| `data/README.md:46-63` | documents the snapshot's schema and names its intended producer | no — prose |
| `research/orchestrator-task-queue.md:66` | the #243 design doc's "Observability" bullet | no — prose |
| `.github/workflows/metrics.yml:1`, `scripts/metrics.py:2`, `scripts/policy-resolve.py:111` | header comments using the word for the *throughput* surface | no — unrelated surface |
| `scripts/select-and-claim.py:1147` | `return_reason` docstring, "observability-only extension" | no — unrelated word |

The load-bearing check is the write side: `grep -rn 'observability\.json'` matches only the
`dashboard.yml` read flag, three explanatory comments in `dashboard-gen.py`/`app.js`, and
`data/README.md` — no script opens or CAS-writes that path, and no workflow step commits it to the
`ledger` branch. So the queue panel is a fully-built, fully-tested consumer wired to a file no
workflow produces — it is permanently hidden in production.

`data/README.md:50-53` is worth reading before designing §3: it already fixes the producer as "a
snapshot the **metrics collector** persists on the `ledger` branch", and states the collector-author
contract is `dashboard-gen._normalize_observability()` "not this prose". That narrows §6's open
question — the documented intent is that the #246 collector, not the drain, owns this file.

> This is the single most useful thing this record establishes: **#636's dashboard half is not a
> `dashboard-gen.py` change at all.** It is "write the #246 collector, and have it emit
> `flow.queue`". Editing `dashboard-gen.py` to import `task-queue` would build a *second*,
> competing ingestion path for a figure the file already ingests.

### 1d. The metrics collector has no queue concept at all

`scripts/metrics.py` is per-**target-repo** throughput (issues open/ready/closed, PR open/close/
merge rates, review-lane and worker health). Relevant structure:

- `build_snapshot()` produces `{generated_at, _ts, schema_version, targets:{repo: {...}}}`
  (`scripts/metrics.py:1111-1127`).
- The ring is `data/metrics-history.json` on the `ledger` branch, bounded by
  `MAX_SNAPSHOTS` (default 24) (`scripts/metrics.py:82`, `:93`).
- Publication is key-set-closed: `PUBLIC_SNAPSHOT_KEYS = {"generated_at", "schema_version",
  "targets", "alerts"}` (`:90`) and `publish_snapshot()` **refuses before encoding a byte** if the
  key set is not exactly that (`:902-907`). The in-source comment is explicit that widening it is
  meant to be "a deliberate, reviewable act" (`:84-89`).
- `validate_history()` keeps any snapshot with a dict `targets` (`:848-860`) — so it tolerates an
  added sibling key without a migration, but silently drops a snapshot that *lacks* `targets`.

So the metrics half of #636 is genuinely unimplemented, and it is where the issue's stated motive
("trended rather than only warned per-tick") actually lands — see §4.

---

## 2. The "already exactly the needed shape" claim is wrong — three mismatches

`queue_stats()` on the #243 branch (`84a7cf6b6:scripts/task-queue.py:378-386`) returns:

```python
{klass: {"depth": len(rows), "oldest_age_seconds": max(0, oldest)} for klass in CLASSES}
```

against `CLASSES = (1, 2, 3, 4)` and `HEAL_CLASS = 2` (`:69-70`). Compared with what
`_obs_flow()` accepts:

| axis | `queue_stats()` | `_obs_flow()` expects | consequence |
|---|---|---|---|
| container | `dict` keyed by class | `list` of row dicts (`dashboard-gen.py:1280`) | a dict is not a `list`, so the whole block is skipped — `flow.queue` publishes `[]` |
| class type | `int` (`CLASSES = (1,2,3,4)`) | `isinstance(queue_class, str)` (`:1285`) | every row silently `continue`s — **empty panel, no error** |
| unit | `oldest_age_seconds` | `oldest_age_minutes` (`:1289`, rounded to 1dp by `_obs_minutes`, `:1187-1190`) | 600s would render as "600m" if passed through unconverted |

Two of the three fail **silently** (drop-the-row tolerance, by design — see the
`_normalize_model_health` tolerance note at `dashboard-gen.py:1412-1415`). A naive wiring would
therefore ship a green self-test and a blank panel. That is the failure mode to design against.

A fourth, subtler gap: `OBS_QUEUE_CLASS_RE` admits the sub-classes `2a..2d` — the heal-rank
ordering the design doc specifies (`research/orchestrator-task-queue.md`, "Queue priority" §2a–d).
`queue_stats()` aggregates only the four top-level classes, so the dashboard can *display* a
resolution the queue does not currently *produce*. Whether class-2 should be broken out by
`heal_rank` is an open product question, not a mechanical port.

One partial reprieve worth recording so a future reader is not confused: `drain.yml` consumes
`--stats` through **JSON** (`84a7cf6b6:.github/workflows/drain.yml:229-240`), and JSON object keys
are strings, so `sorted(report["stats"])` sees `"1".."4"`. The int/str mismatch therefore
disappears over the wire but **not** for a direct Python `import`. Any design that imports
`queue_stats()` in-process inherits the mismatch; any design that shells out to `--stats` does not.

---

## 3. Options for the dashboard half

**A. Collector-produced `flow.queue` (recommended).** Write the #246 observability collector (or
extend whatever lands as it) to read `data/task-queue.json` from the ledger branch, call
`queue_stats()`, and adapt: `[{"class": str(k), "depth": v["depth"],
"oldest_age_minutes": v["oldest_age_seconds"] / 60} for k, v in stats.items()]`, plus
`thresholds.queue_age_clamp_minutes` from the resolved heal-wait policy.
*For*: zero change to `dashboard-gen.py`, `app.js`, or their self-tests — all three are already
written and pinned for this shape; the privacy/validation boundary stays exactly where it is;
`dashboard.yml` needs no edit. *Against*: blocked on the collector existing, and on #243 merging.

**B. `dashboard-gen.py` imports `task-queue.py` directly.** *For*: no collector needed.
*Against*: `dashboard-gen.py` is a pure-ish builder over inputs handed to it by `dashboard.yml`;
it does not reach for ledger documents itself. This would give `flow.queue` two producers with
different validation paths, and would make the dashboard build depend on a script that is not on
`master`. **Reject** unless the collector is abandoned as a concept.

**C. Have `drain.yml` write the observability snapshot.** *For*: the drain already computes
`queue_stats()` and `clamp_alarm()`; it is the cheapest producer. *Against*: `data/observability.json`
is a *multi-source* document (cache effectiveness, lane health, defer reasons, model exit classes,
trigger fires — `dashboard-gen.py:1450-1457`). A drain that CAS-writes the whole document would
have to preserve keys it does not own, or the collector and the drain will clobber each other on
the same ledger path. Viable only as "drain writes `flow.queue` into a *separate* sidecar the
collector merges", which is really option A with an extra hop.

**Recommendation**: A. Concretely, #636's dashboard half should be re-scoped to *"the observability
collector must emit `flow.queue` and `thresholds.queue_age_clamp_minutes`"*, and should carry the
three-axis adapter above as its acceptance criterion — with a test that asserts a **non-empty**
`flow.queue` after the adapter, since every mismatch here fails silently to `[]`.

---

## 4. Options for the metrics half

The genuine open question is **where a fleet-global figure lives in a per-target snapshot**. The
task queue is one queue for the orchestrator; `targets` is keyed by maintained repo
(`policy/repos.toml [repos.*]`). Three shapes:

**A. New top-level `queue` key.** `{generated_at, schema_version, targets, alerts, queue}` with
`queue = {"<class>": {"depth": n, "oldest_age_minutes": m}, ...}`.
*For*: honest about the cardinality — the queue is not per-target; `validate_history()` already
tolerates the extra key (`metrics.py:848-860`), so the existing ring needs no migration.
*Against*: requires widening `PUBLIC_SNAPSHOT_KEYS` (`:90`), which `publish_snapshot()` enforces
exactly (`:902-907`). That is *by design* a reviewable act, so it should be its own explicit,
justified hunk with a self-test that the old key set now fails — not a quiet frozenset edit.

**B. Fold per-class depth into each `targets[repo]` row** by filtering the queue on `task["repo"]`.
*For*: no public-key-set change; alerts are already per-target
(`evaluate_alerts`, `:265`), so a "class-2 backlog for repo X" alarm would slot into the existing
`ALERT_CLASSES` / `_CLASS_PRED` machinery (`:1048-1059`) and inherit its dedupe + recovery
hysteresis (`compute_recoveries`, `:1061`) for free.
*Against*: class 1 (cache warmth) and class 2 (self-healing) are substantially *orchestration*
work, not target work; attributing them to a target repo is a modelling lie for exactly the rows
the clamp cares about. Also `build_snapshot()` **skips** a target with no token (`:1122-1125`), and
a skipped target must have no row — so queue depth would vanish for reasons unrelated to the queue.

**C. Both**: top-level `queue` for the fleet truth, per-target `queue_depth` for alerting.
*Against*: two sources for one number is how they drift. Not recommended without a stated reason.

**Recommendation**: A. The value #636 adds is the *ring*: `metrics.py` gives class-2 age a
**sustained** predicate over K snapshots (`_sustained`, `:231`), whereas both existing trend
surfaces are weaker than they look — `drain.yml`'s alarm is per-tick, and the dashboard's own
`obsTrend` is **client-side and in-memory, keyed on `generated_at` and lost on page reload**
(`dashboard/app.js:586-588`). Only the metrics ring makes "the class-2 backlog has been growing for
six ticks" a durable, alertable fact. That, and not the panel, is the part of #636 that is not
already built.

### 4a. The alert path must be built alongside `ALERT_CLASSES`, NOT inside it

An earlier draft of this record recommended adding the clamp alarm as a *fifth `ALERT_CLASSES`
member reading the top-level `queue` key*. **That is not implementable as stated** — the existing
alert machinery is target-scoped end to end, and the fifth-member shape breaks on all three legs:

- **Firing.** `evaluate_alerts` only ever evaluates inside `for target, m in targets.items()`
  (`:275`); a predicate whose data lives at `current["queue"]` is never reached with the queue in
  hand. It would be dead code on the fire path.
- **Recovery.** `compute_recoveries` iterates `collected_targets` and applies **every**
  `ALERT_CLASSES` predicate via `_CLASS_PRED[cls](th)` to that target's rows (`:1074-1082`). A
  fifth member would therefore be invoked against unrelated `targets[repo]` rows — finding no queue
  fields, returning false for all of them, and "recovering" the fleet alarm on zero queue evidence.
- **Identity.** Reconciliation keys are `(target, classification)` (`_marker`, `:949-950`;
  `reconcile_alerts`, `:1088-1091`). Routing a fleet-global alarm through `collected_targets` would
  make a *fleet* queue alarm's closure depend on *target collection* — a repo losing its read token
  would close the queue alert. That inverts the blocker `compute_recoveries` was written to prevent.

The correct shape keeps the fleet rule **parallel to**, not inside, the per-target machinery, and
reuses only `reconcile_alerts` (which is already generic over `(target, classification)` pairs):

1. **Identity.** A module constant `QUEUE_BACKLOG = "queue-backlog"` plus a reserved pseudo-target
   `FLEET_TARGET = "(fleet)"`. It must be unable to collide with any `owner/repo` key from
   `policy/repos.toml` — parentheses are not legal in a GitHub repo name and the token carries no
   `/`. `_marker`/`_alert_title` then produce a stable, unique marker with no change to either.
2. **History helper.** A separate `_recent_queue_rows(history, k)` returning the last k snapshots'
   `snap["queue"]` blocks **only where the block is a well-formed dict of class rows** — not
   `_recent_rows`, which is hard-wired to `snapshots[].targets[target]`. Note the `queue` key must
   ride on the normal snapshot: `validate_history` drops any snapshot lacking a dict `targets`
   (`:848-860`), so a queue-only snapshot would silently vanish from the ring.
3. **Sustained predicate.** `_queue_clamp_pred(th)` over one queue block (class-2 rows at or past
   the clamp), applied by a `_queue_sustained(history, k, pred)` that mirrors `_sustained`'s
   `len(rows) >= k and all(...)` contract — insufficient history never fires, one spiky tick never
   fires. Called from `evaluate_alerts` **after** the target loop, appending at most one row.
4. **Threshold source.** Fleet-level, not per-target: `thresholds_by_target` is keyed by repo, so
   there is no honest entry to read. Add a `DEFAULT_FLEET_THRESHOLDS` carrying
   `queue_age_clamp_minutes` (same resolved heal-wait value §3 sends to the dashboard's
   `thresholds`) plus its own `sustain_snapshots`/`recover_snapshots`. Borrowing an arbitrary
   target's overrides would be exactly the silent-default this repo forbids.
5. **Recovery, fail-closed.** A separate `compute_queue_recovery(history, th)` returning
   `{(FLEET_TARGET, QUEUE_BACKLOG)}` or `set()`, unioned into the set handed to `reconcile_alerts`.
   It recovers **only** when the last `recover_snapshots` snapshots each carry a *valid* queue block
   AND the fire predicate is false in every one. A missing or malformed `queue` block in any of
   those snapshots yields **no recovery** — the alert stays open on absent evidence, mirroring the
   skipped-target blocker. The fleet class stays **out of `ALERT_CLASSES` and `_CLASS_PRED`**, so
   `compute_recoveries` can never apply it to a target row.

Dedupe then comes free and unchanged: `reconcile_alerts` already upserts one issue per
`(target, classification)` and skips any pair that is firing this tick (`:1088-1094`).

**Self-tests that would make this non-vacuous** (each must go red if the behaviour regresses):

- **fires**: clamp condition true in all K queue blocks ⇒ exactly one `(FLEET_TARGET,
  QUEUE_BACKLOG)` row, with the tripping values in `metrics`.
- **insufficient history**: same condition with only K-1 snapshots ⇒ no row; and one spiky tick
  inside K ⇒ no row.
- **missing data fails closed, both directions**: a snapshot with no `queue` key, and one with a
  malformed block, each ⇒ (a) no fire, and (b) **not** in the recovery set — asserting the alert
  is left open rather than auto-closed.
- **dedupe**: a pair both firing and nominally recovered this tick is upserted once, as a fire.
- **hysteretic recovery**: clear across all `recover_snapshots` *valid* blocks ⇒ recovered; clear
  across `recover_snapshots - 1` ⇒ not yet.
- **identity/regression guard**: `QUEUE_BACKLOG not in ALERT_CLASSES`, `"/" not in FLEET_TARGET`,
  and `FLEET_TARGET` absent from the targets loaded from `policy/repos.toml` — this is the
  assertion that goes red if a future change folds the rule back into `_CLASS_PRED`.

On the read path: `metrics.py` already holds a `GitHubAPI(registry_token)` reading the ledger
branch (`:777`, `:820-846`), so `data/task-queue.json` is reachable with no new credential. For
the pure functions, the established in-repo pattern for importing a hyphenated sibling is
`importlib.util.spec_from_file_location` — used for `gh_retry` (`metrics.py:73-79`), for
`ready-issues` (`_ready_issues_module`, `:624`), and for `dashboard-gen` inside the suite
(`_load_dashboard_gen`, `:1756`). Reuse it rather than reimplementing `queue_stats()`, so the
drain-side and metrics-side numbers cannot disagree.

---

## 5. Sequencing constraint (the thing that blocks #636 today)

1. **#243 must merge first.** Until `scripts/task-queue.py` is on `master`, neither half can import
   the pure functions and there is no `data/task-queue.json` to read. A PR that vendors a copy of
   `queue_stats()` to unblock itself would create the drift the shared import exists to prevent.
2. The dashboard half additionally depends on the **#246 collector existing**. If that collector is
   not planned, say so and #636's dashboard half becomes a re-scope decision, not an
   implementation.
3. The metrics half depends only on (1) and can proceed independently of the collector.

Nothing in §3/§4 should be built before (1). Attempting #636 now yields either a vendored
duplicate or a silently-empty panel.

## 6. What this record does not establish

- Whether the #246 collector is planned, in flight elsewhere, or abandoned. The repo states the
  *intent* — `data/README.md:50-53` names the metrics collector as the producer and pins the
  collector-author contract to `_normalize_observability()`, and `dashboard.yml:391` says "until its
  collector" — but nothing records whether anyone is building it. Status is a maintainer call.
- Whether class 2 should be exported at `heal_rank` resolution (`2a..2d`). The dashboard *accepts*
  it; the queue does not *produce* it. Maintainer call.
- No claim that the existing validation boundary is *audited*. `_obs_flow` enforces the decision-22
  salted-label rule fatally for lease rows (`dashboard-gen.py:1315-1320`), and `_assert_private` /
  `_assert_no_fleet_composition` backstop the finished document — but queue rows carry `class`,
  `depth`, and an age, and a future `repo`/`cache_key`/`id` field on a queue row would put target
  and surface identity on a public page. If §3/§4 ever widen the queue row, that widening needs its
  own privacy review; it is not covered by the existing checks.
- No measurements. Any timing figure taken on a work box is non-canonical.
