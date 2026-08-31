# #427: per-run model-health records aggregated on read — the design record

> 🤖 **SPARQ agent** — findings-only design record. No behaviour changes ship with it.

#427 proposes replacing the single-blob `data/model-health.json` CAS ledger with immutable,
idempotently-named per-run records aggregated at read time, as the fuller successor to #200's
minimal fix (dedup by producing-run identity + full-jitter bounded CAS retries).

This record states what the code actually does today, corrects three claims in the issue that do
not survive contact with the source, names the one structural property that makes the proposal
much harder here than the issue implies, lays out four options, and recommends the order to take
them in. It does **not** recommend implementing #427 as specified.

---

## 1. What the issue gets wrong about the reader set

#427 lists the readers that a storage-format change would touch as: `model-health.py`
`read_ledger`/`prune`/`decide`, `account-usage.py`, `groom.py`, `select-and-claim.py`
(`backoff_until` derivation), and `dashboard.yml`. Three of those five are wrong, and one real
reader is missing.

**`scripts/groom.py` does not read the model-health ledger.** Its only mention of it is a
cross-module comment on the *lease* ledger's ref constant:

```python
# write pins this ref. Keep in sync with select-and-claim.py / model-health.py LEDGER_REF.
```
— `scripts/groom.py:69`

`groom.py` owns `data/leases.json` (`LEDGER_PATH = "data/leases.json"`), not model-health. The
coupling the issue is probably thinking of is at the *workflow* level: `groom-sweep.yml:349` and
`groom-core.yml:272` invoke `python3 scripts/model-health.py decide` as a separate process. That is
a CLI invocation, not a code dependency — `groom.py` needs no change under any option below.

**`scripts/select-and-claim.py` does not derive `backoff_until`.** It *consumes* a value already
stamped onto the usage entry:

```python
        until = _usage_num(u.get("backoff_until"))
```
— `scripts/select-and-claim.py:528`, in `usage_eligible`

whose own docstring says so: *"`backoff_until` (derived from the model-health rate-limit records)
onto an exempt entry"* (`select-and-claim.py:506-507`). The derivation lives one process earlier, in
`account-usage.py::_load_health_state` (`scripts/account-usage.py:386-416`), which is the module
that calls `mh.account_backoffs(window, now)`. `select-and-claim.py` reaches the data across a
**file boundary** (`WORKER_USAGE_FILE`, read by `dispatch-claim.py::_load_usage`), so it is
insulated from the ledger's storage format entirely. It needs no change either.

**`scripts/dispatch-claim.py` is a real ledger reader and the issue does not list it.** It reads
the full validated window on production paths:

```python
        records, _ = model_health.read_ledger(api, registry_repo)
        window = model_health.prune(records, now)
```
— `scripts/dispatch-claim.py:5404-5405`, in `_read_model_health_window`

called at `dispatch-claim.py:8366` (capacity-park auto-readmit) and `:8556` (deferred-retry decline
escalation). Its docstring is explicit that *"Dispatch is a read-only consumer: it never calls
append_record"* — but it is on the dispatch hot path, and it is the reader most sensitive to read
cost.

For completeness: `scripts/worker-pr.py` loads `model-health.py` but never the ledger — *"Nothing
on the live path imports it — the class gate stays a pure, dependency-free predicate"*
(`worker-pr.py:2085-2090`); the single call site is inside `_self_test`, for a taxonomy drift lock.

### The corrected reader set

| reader | how it loads | needs |
| --- | --- | --- |
| `model-health.py` `append_record` / `decide` | contents API, `read_ledger` (`:2198`) | full window |
| `account-usage.py` `_load_health_state` (`:386`) | contents API, or `MODEL_HEALTH_FILE` override | full window |
| `dispatch-claim.py` `_read_model_health_window` (`:5396`) | contents API | full window |
| `dashboard-gen.py` `_normalize_ledger_health` (`:1561`) | **git checkout** of the `ledger` branch | full window |

`dashboard.yml` is the odd one out and in the *easy* direction: it already does a full
`actions/checkout` of the ledger branch into `ledger/` (`dashboard.yml:359-364`) and then guards
`test -f ledger/data/model-health.json` (`:389`) before passing `--model-health` (`:400`). A
checkout gets a directory of shards for the same cost as a blob. Only the three contents-API
readers pay for sharding.

---

## 2. The structural obstacle: every model-health read is a full-window scan

This is the finding that decides the issue.

The repo **already has** immutable per-record stores on the `ledger` branch —
`orchestration/provenance/*.json` and `orchestration/review-verdicts/*.json` (#96). They are
genuine prior art for the write side, and they work:

```python
def provenance_path(target_repo, pr_number):
    owner, name = target_repo.split("/", 1)
    return f"{PROVENANCE_DIR}/{owner}--{name}--pr{pr_number}.json"
```
— `scripts/worker-pr.py:2673-2675`

The write is a create-only contents-API PUT that omits `sha` on a fresh create
(`worker-pr.py:3017-3021`), with an existing byte-identical file treated as idempotent success and
a divergent one failing closed (`worker-pr.py:3009-3015`). No CAS, no read-modify-write, no
contention. Exactly what #427 wants.

**But that store is only ever point-looked-up.** The reader derives the filename from data it
already holds and GETs that one path:

```python
    location = f"repos/{registry_repo}/contents/{path}" + (f"?ref={ref}" if ref else "")
```
— `scripts/worker-pr.py:2767-2782`, `_probe_registry_file`

Nothing in the repo enumerates the provenance directory. The pattern is cheap *because* the access
pattern is keyed.

Model-health is the exact opposite. Not one of its four readers wants a single record; all four
want the whole window, and the derivations are **global and order-dependent**:

- `prune` sorts the entire set (`kept.sort(key=lambda r: r["ts"])`, `model-health.py:656`) and then
  runs a cross-account selection over it.
- `account_backoffs` and `credential_states` walk records chronologically, maintaining per-account
  consecutive chains where *a success resets the chain* — so a missing or out-of-order record
  changes the derived state.
- `classify_records` needs fleet-wide counts (a whole provider capped vs one account).

So the prior art does not transfer. Sharding a store whose every read is `SELECT *` converts one
request into an enumeration, and there is no key to look up by.

### What enumeration costs on the contents API

Today `read_ledger` is **one** GET returning inline base64 content (`model-health.py:2203-2217`).
With per-run shards, the three API readers need a directory listing followed by a fetch per shard,
because the contents API's directory response carries entry metadata without file content. The
git trees API can return all names in one request but likewise not their content; blobs still cost
one request each.

So a read becomes **1 + N requests**: one listing (or trees call), plus one blob fetch per retained
shard. N is the retained *record count*, and it is not a constant.
`RETENTION_CEILING_RECORDS = 2000` (`model-health.py:128`) is an **upper** bound on N, not a lower
one — and not a clean upper bound either. Retention is floor-selected (every record inside
`RETENTION_FLOOR_SECONDS`, 7 h, `:112`, survives) and the ceiling only clamps that selection when it
overshoots; `RETENTION_CEILING_BYTES = 750_000` (`:129`) can bind first and push N lower still;
while `_apply_retention_ceiling` clamps to `max(len(preserved), RETENTION_CEILING_RECORDS)`
(`:638-639`), so a large preserved set can hold N *above* 2000.

Which N actually occurs is the question, and this record does not answer it. The source states the
ceiling as *"~4.6x today's live rate"* and *"~285 records/h sustained"* (`:115-117`), i.e. a live
rate on the order of 60 rec/h, which over a 7 h floor is a few hundred shards rather than two
thousand. That figure is a comment in the source, not something measured here (§7). Stated as
scenarios instead of as a single number:

| scenario | N | read cost |
| --- | --- | --- |
| the live rate the source states (~60 rec/h, 7 h floor) | a few hundred | 1 listing page + a few hundred GETs |
| sustained at the tolerated rate (~285 rec/h) | ~2000 | 20 listing pages + ~2000 GETs |
| ceiling binding with a large preserved set | >2000 | listing exceeds `paginate`'s cap |

The pagination interaction is therefore a worst-case property, not a steady-state one:
`GitHubAPI.paginate` (`model-health.py:2419-2431`) caps at 20 pages of 100 and raises
`"model-health snapshot may be truncated"` beyond that, so a *saturated* window lands exactly on
that cap with no headroom and a preserved-set-inflated window exceeds it, while a window at the
stated live rate pages comfortably. The per-shard GETs are the cost that binds at every N; the
listing is only the cost that binds at the top of the range.

> **MUST VERIFY before implementing.** I have not confirmed against current GitHub API docs: (a) the
> exact directory-listing entry cap on the contents API and whether it is a hard truncation or a
> pagination boundary, (b) whether any bulk-content endpoint could return many small blobs in one
> response. Both materially change option A's cost, and neither should be taken from recollection.
> No performance numbers in this record are measured; the repo has no benchmark for either shape.

Note also the direction of the failure. `account-usage.py::_load_health_state` fails **open** —
*"exempt accounts admitted WITHOUT rate-limit backoff this tick (fail-open)"*
(`account-usage.py:410-416`) — and #739 records that the same fail-open path is what turns a ledger
read failure into *"accounts admitted uncapped"*. Going from 1 request to 1+N on that path
multiplies the transport-failure surface guarding a fail-open decision. Worse, it introduces a
failure class that cannot exist today: a **partial** read. One blob with one sha is atomic; a
partially-fetched shard set is indistinguishable from a genuinely smaller window, and under-coverage
changes decisions silently. #699's coverage warning (`dispatch-claim.py:5414`,
`_warn_health_coverage_shortfall`) catches some but not all of that.

---

## 3. Retention is the harder half, and the issue does not mention it

Today retention is a **side effect of the write**: `append_record` calls `prune(records + [record],
now)` before the PUT (`model-health.py:2345`). Immutable records are never rewritten, so under
#427 nothing evicts anything and a separate reaper must exist.

That reaper is not a time filter. `prune` (`model-health.py:602-723`) is a stateful, cross-account
selection with several never-evict classes:

- the tail of a live backoff chain, because otherwise a flood of unrelated successes readmits a
  rate-limited account mid-backoff (#82);
- the auth-run tail of a **proven-dead credential**, which *"is the ONLY thing keeping a dead
  probe-exempt account out of dispatch"* (`model-health.py:630-631`, #639);
- a derived `no_change` limit's three source observations, and a live auth cooldown's tail (#596);
- all of that unioned with the #699 time floor, then clamped by `_apply_retention_ceiling`.

A reaper would have to re-run that entire derivation over the full shard set to know which files
are safe to delete — i.e. it must do the expensive read anyway — and **every mistake fails open**:
deleting a preserved shard silently readmits a rate-limited or dead-credentialed account. The
current design makes that impossible by construction, because the only writer of the window is also
the only pruner, and it prunes on data it has just read.

The provenance store's precedent is a warning here, not a reassurance: it has **no** retention or GC
at all and grows forever. That is tolerable for point lookups. It is not tolerable for a store whose
readers enumerate it every dispatch tick.

---

## 4. What sharding genuinely does buy

Stated fairly, because two of these are real:

1. **Write contention goes to zero, not just down.** The filename becomes the idempotency key. The
   fields `_record_identity` already keys on — `(run_id, provider, account, exit_class,
   model_alias)` (`model-health.py:2275-2276`) — hash into a name, and a create-only PUT dedups
   *without a read at all*. Today dedup costs a full ledger GET per attempt
   (`model-health.py:2338-2342`). This is a strict improvement on the write path.
2. **#739's forward-compatibility hazard shrinks.** The ORIGIN_WRITE/ORIGIN_READ split exists
   because read-modify-write carries other releases' records back through this writer, so an
   additive field must be *"neither blocked nor silently erased"* (`model-health.py:2350-2353`).
   With immutable shards no writer ever rewrites another writer's record, and that whole hazard
   class disappears. Credit where due — this is the cleanest argument for #427.
3. **The `ledger-invariant.py` cost is smaller than expected, if the naming is flat.** The allowlist
   already admits any flat `data/*.json`:
   ```python
       ("100644", "blob", re.compile(r"data/[^/]+\.json")),
   ```
   — `scripts/ledger-invariant.py:15`
   So `data/model-health-<key>.json` needs **no** trust-surface amendment. A subdirectory
   `data/model-health/` would need two new patterns (a tree and a blob) added to `ALLOWED_ENTRIES`
   — a change to a fail-closed validator, which is a review-heavy edit but a small one. The flat
   scheme avoids it at the cost of an unbounded flat namespace next to `leases.json`, which I would
   not recommend: `ledger-invariant`'s protection of `data/*.json` is coarse, and burying the
   lease ledger in thousands of sibling files makes the branch hard to inspect by eye.

---

## 5. The options

**A — full per-run shards, aggregate on read (#427 as written).** Removes write contention and the
#739 hazard. Costs: read goes from 1 request to 1+N on three consumers including the dispatch hot
path; retention becomes a separate reaper that must re-derive `prune`'s cross-account preserved set
and whose every bug fails open; a new partial-read failure class on a fail-open path; and, in the
saturated case, a listing that lands exactly on `paginate`'s 20x100 cap with no headroom (§2).
**Not recommended as specified.** The
read side pays for a write-side problem, and it pays on the paths whose failure mode is "admit a
capped account".

**B — log-structured: shard tail + compacted base blob.** Writers create-only into a bounded tail
(no CAS, no read). A compactor folds the tail into `data/model-health.json` and deletes the folded
shards — and `prune` runs *there*, in the one place that already holds the whole window, which is
exactly where its cross-account derivation belongs. Readers fetch the base blob (1 GET) plus a tail
bounded by the compaction interval times the record rate, not by the retention window — that is the
read's *cost*; whether it is a *safe* read is the unresolved consistency item below. The obvious
host for the compactor is the existing `groom-sweep.yml` cron that already runs `model-health.py
decide` (`:349`) and therefore already reads the window.

B also has the migration story #427 asks for and A does not: the base blob keeps its current shape
(modulo the dedup field the protocol below turns out to need), so a reader deployed before the
change reads it and sees a **valid but slightly stale** window. The degradation is staleness, not breakage — which matters given #739's finding that this
ledger is read during rolling upgrades by pre-merge readers. A's compat path, by contrast, requires
every reader to learn enumeration before any writer stops writing the blob.

Two things are unresolved for B, and neither is a detail.

*Latency.* A record is invisible to `decide` until compaction, so the compaction interval becomes
alert latency, and it must be shown to stay under the windows the outage/transient conditions need.
That analysis has not been done here.

*Consistency.* "Fold the tail into the base, then delete the folded shards" is not atomic against a
concurrent reader, and the order-dependence §2 uses against A applies to B just as hard:

- reader fetches the **new** base and also a shard the compactor has not deleted yet → the outcome
  is counted twice → a consecutive-failure chain gains a link, i.e. a backoff that should not exist;
- reader lists the tail, the compactor folds and deletes, the reader's per-shard GET 404s → partial
  window → a chain is short a link and `account-usage.py::_load_health_state` fails **open**
  (`:410-416`).

So B does not get a ~1-request *safe* read for free; it gets it only under a publication protocol,
and no such protocol exists in this repo today. In outline it would need at least:

1. **Delete only after publish.** The compactor PUTs the new base (CAS on the base sha) and deletes
   folded shards only once that PUT has landed. Every record is then visible *at least once* to any
   interleaving, never zero. A crash between the steps leaves duplicates — the tolerable direction —
   and the next compaction clears them.
2. **Identity dedup on read**, without which at-least-once is not safe. `_record_identity`
   (`:2270-2276`) already exists and is already the write-side dedup key, but it returns `None` when
   `run_id` is missing or non-string, and those records cannot be deduped by it. The shard filename
   is the natural key — it is the idempotency key on the write side (§4.1) — which means the base
   must carry it per record: an additive field. #739's ORIGIN_READ posture tolerates additive fields
   on stored records (`:855`), so an older writer's read-modify-write neither blocks nor erases it,
   but it is still a change to `RECORD_KNOWN_FIELDS` and so to a fail-closed validator, and it
   weakens the "the base blob keeps its exact current shape" migration claim above.
3. **A stale listing must not read as a short tail.** On a 404 for a listed shard the reader re-GETs
   the base: base sha changed → that shard was folded, drop it; base sha unchanged → the shard is
   genuinely gone and the read must fail **closed**. That rule terminates, unlike a blanket retry,
   but it costs a request on the failure path and it obliges `account-usage.py` to grow a
   fail-closed branch it does not have today.
4. **A rollout ordering constraint.** An old *reader* sees base-only and is merely stale, as claimed
   above. An old *writer* is the hazard: it read-modify-writes the base knowing nothing of the tail,
   so its `prune` runs over an incomplete window and can evict records the tail's context would have
   preserved — precisely the never-evict classes of §3. No writer may still be appending to the base
   once the tail exists, which is an ordering constraint B's migration story has to carry.

Until that protocol is written down, costed and reviewed, **B is a direction, not a design**, and
the "~1 request, safe" claim for it is unproven in the same way A's cost is.

**C — time-bucketed blobs (e.g. one blob per hour).** Contention divides by live bucket count;
reads cost one request per bucket in the window (~48 at `WINDOW_HOURS`). Retention becomes
whole-bucket deletion, which is simple until it collides with `prune`'s preserved records — a live
backoff chain crossing a bucket boundary is precisely what #82 says must never be evicted. Strictly
worse than B on reads and no simpler on retention. Mentioned for completeness; I would not take it.

**D — measure first.** #200 shipped both halves of its mitigation: `CAS_RETRIES = 8`
(`model-health.py:2232`) with a full-jitter exponential sleep between attempts, plus the dedup
no-op. Whether residual contention still discards records **is not known**, and nothing in this repo
measures it. The exhaustion path is a single raise:

```python
    raise HealthError("model-health ledger CAS conflicts did not settle")
```
— `model-health.py:2373`

with no counter, no alert condition, and no dashboard row. #427's entire justification is a
contention rate that no one has observed since the mitigation landed. It may be near zero.

---

## 6. Recommendation

**Take D, then reconsider between B and "close #427".**

Instrument the CAS-exhaustion path first — a counter or alert on `model-health.py:2373`, plus the
observed retry-attempt distribution. It is a small, self-contained change in the same area, and it
converts the premise of #427 from an assumption into a number. If exhaustion is rare, #427 should be
closed as "mitigated by #200" and the remaining value (the #739 hazard reduction) is not worth
rebuilding the read path of four consumers.

If the number justifies acting, **B is the better direction than A — conditionally.** B gets the
entire write-side win — zero CAS contention, filename-as-idempotency-key, no read before write —
while keeping `prune`'s cross-account derivation in a single place that holds the whole window,
keeping the hot-path read near 1 request, and degrading to staleness rather than breakage for
readers deployed before the change.

The conditions are the two unresolved items in §5, and B should not be adopted before both are
discharged: (a) the compaction interval must be shown to fit the alert-latency windows, and (b) the
base/tail publication protocol must be specified and reviewed — ordering, identity dedup, deletion
timing, the fail-closed rule on a stale listing, and the no-old-writers rollout constraint. Without
(b), B trades A's partial-read failure class for its own rather than avoiding it, and the safe-read
advantage that makes it preferable to A does not yet exist.

I would not implement #427 as literally specified. The proposal treats the read path as a mechanical
migration ("touches every reader of the blob"), but the readers are not incidental: their access
pattern is a full-window scan with order-dependent, cross-account state, and that is what makes this
different from the provenance store the pattern is borrowed from.

## 7. What is not established here

- No measurement of the current CAS conflict or exhaustion rate — see option D. Everything about the
  size of the problem is assumption.
- The GitHub API limits in §2 are stated from recollection and flagged MUST-VERIFY; they should be
  confirmed against current docs before any option is costed.
- The retained-record count N that sets A's read cost is **not measured**. The scenarios in §2 lean
  on rate figures written in `model-health.py`'s own comments, not on an observed distribution of
  window sizes; nothing in this repo records one. Which scenario is the operating point decides how
  bad A actually is.
- Option B's compaction interval versus alert-latency requirements is unanalysed.
- Option B's base/tail publication protocol (§5) is sketched, not specified, and has had no
  consistency or trust review. Treat the four numbered points as the shape of the obligation, not as
  a design that has been shown to close the races.
- No security or trust review of the shard-naming scheme has been done. A filename derived from
  record fields is a **new** place where record content reaches a path, and the privacy invariant
  (decision 22 — no raw handle in any record, log line, or alert body) would need to hold for
  filenames too, since the ledger branch is public. `_tolerable_unknown_field`'s raw-handle scan
  (`model-health.py:800-812`) has no filename counterpart today. Treat this as unreviewed, not as
  sound.
