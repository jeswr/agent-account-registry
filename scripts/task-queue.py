#!/usr/bin/env python3
"""Durable orchestrator task queue on the ledger data-plane branch (issue #243, Phase A).

WHAT THIS IS. `research/orchestrator-task-queue.md` (maintainer-directed, 2026-07-18) replaces
push dispatch with a queue the orchestrator DRAINS: lanes ENQUEUE agent tasks and one drain loop
owns ordering, dedup, backoff, and priority. This module is the substrate — the CAS-disciplined
`data/task-queue.json` document, the PURE pick function, and the enqueue/complete/requeue/compact
operations. `.github/workflows/drain.yml` is its only production driver.

WHAT THIS IS NOT — the trust boundary, stated once and load-bearing everywhere below. ENQUEUEING
DOES NOT GRANT EXECUTION. A queue row is a HINT that work may exist; live state is truth. Nothing
here claims a lease, selects an account, resolves a model chain, checks provenance, or admits an
author — dispatch-claim.py keeps every one of those roles unchanged. `revalidate()` below is a
LIVENESS filter (is this row still worth looking at?) and is deliberately weaker than CLAIM's
validation; it may only ever DROP a task, never admit one. A drained task still passes through the
same validation/lease/trust path a pushed task does.

PRIORITY (maintainer-specified; see the design record for the why):
  1. cache warmth   — chain work on a still-warm agent context (`cache_key`) inside `cache_ttl_minutes`
  2. self-improvement (class 2) — self-healing first, internally ranked 1..4 = outage repair,
     stuck adjudication, alarm-driven convergence, orchestration improvements
  3. project infrastructure (class 3) — target-repo CI/build health
  4. project work (class 4) — the issues themselves, in project-defined order
ANTI-STARVATION CLAMP: warm-cache preference reorders only inside a bounded age window. A class-2
task older than `heal_max_wait_minutes` overrides ANY warm-cache preference — without it a hot
class-4 streak starves a cold outage repair, inverting the directive.

HOSTILE INPUT, BOTH DIRECTIONS. The queue document is read back from a branch other workflows
write, and enqueue payloads are derived from the dispatch PLAN artifact, which is itself produced
by a job that executes untrusted target code. So the schema is validated on READ and again before
every WRITE, with bounded sizes and character-class-pinned atoms. A malformed document FAILS
CLOSED (the drain refuses) rather than degrading to an empty queue, which would look exactly like
"no work" while starving every lane. And because safe characters prove nothing about ORIGIN, the
PLAN artifact is put through dispatch-claim.py's FULL validator first (`validate_plan_artifact`) —
the same validation the CLAIM consumer applies to the same artifact — so every projected row is
bound to a repository the plan itself declared.

CAS discipline is the lease ledger's, thread for thread (select-and-claim.py): read-SHA
compare-and-swap pinned to the data-plane branch, bounded FULLY JITTERED retries, and REAL API
errors (auth/validation/missing-branch/5xx) surfaced immediately instead of being collapsed into
"CAS kept conflicting" after N wasted attempts (issue #179).
"""

import argparse
import base64
import importlib.util
import json
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path

_retry_spec = importlib.util.spec_from_file_location(
    "registry_ledger_retry_tq", os.path.join(os.path.dirname(__file__), "ledger_retry.py"))
if _retry_spec is None or _retry_spec.loader is None:
    raise RuntimeError("cannot load the shared ledger retry policy")
ledger_retry = importlib.util.module_from_spec(_retry_spec)
_retry_spec.loader.exec_module(ledger_retry)

QUEUE_PATH = "data/task-queue.json"
# The SAME data-plane branch constant every ledger reader/writer threads (see data/README.md):
# master's required `gate` check rejects the bot's contents-API PUTs, and a bot confined to
# `ledger` can never push code. Env override is for tests/migration only.
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")
SCHEMA = "registry-task-queue/v1"

# Priority classes (design record). Class 2 is the self-improvement/self-healing class and is the
# ONLY class the anti-starvation clamp escalates.
HEAL_CLASS = 2
CLASSES = (1, 2, 3, 4)
# In-class heal rank: 1=active-outage repair, 2=stuck-item adjudication, 3=alarm-driven
# convergence, 4=orchestration improvements. Absent ranks sort AFTER every present one.
HEAL_RANKS = (1, 2, 3, 4)
UNRANKED = max(HEAL_RANKS) + 1
KINDS = frozenset({"review", "fix", "disarm", "issue", "adjudicate", "repair"})
# The kinds whose target is a PULL REQUEST. These — and only these — carry the full planned head
# SHA (`head`) and are re-validated against the LIVE head, so a row can never be routed for a head
# it was not planned for. Kept as a named set because three separate rules key on it (the schema's
# required/forbidden `head`, `revalidate`'s exact-match binding, and the live endpoint below).
PR_KINDS = frozenset({"review", "fix", "disarm"})
# Which contents the drain must read to re-validate a kind against LIVE state. Kept here rather
# than in drain.yml so it is covered by this module's self-test: the suite asserts every KIND has
# an endpoint, so a kind added without classifying it turns the gate red instead of silently
# probing the wrong API and dropping every task of that kind as "unreadable".
LIVE_ENDPOINT = {
    "review": "pulls", "fix": "pulls", "disarm": "pulls",
    "issue": "issues", "adjudicate": "issues", "repair": "issues",
}

DEFAULT_CACHE_TTL_MINUTES = 60
DEFAULT_HEAL_MAX_WAIT_MINUTES = 10
DEFAULT_DRAIN_BATCH = 3
# A picked task is hidden for this long so a drain that dies between pick and complete/requeue
# cannot hot-loop the same row every tick; the row stays queued and simply becomes eligible again.
# Comfortably longer than the 10-minute drain cadence.
DEFAULT_VISIBILITY_MINUTES = 30
# A HOLD is not a failure: it hides a healthy, never-launched row for this long WITHOUT touching
# `attempts`. Kept equal to the visibility window so a hold after a pick is normally already
# satisfied and writes nothing (see `hold_task`).
DEFAULT_HOLD_MINUTES = 30
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_MAX_AGE_MINUTES = 24 * 60

# Bounded sizes: a queue document is read into memory by every drain, so an unbounded one is a
# denial-of-service on the whole orchestrator. Exceeding either bound fails CLOSED.
MAX_TASKS = 2000
MAX_CACHE = 256

ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}")
REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
CACHE_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}")
ENQUEUED_BY_RE = re.compile(r"https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,255}")
SHA_RE = re.compile(r"[0-9a-f]{40}")

REQUIRED_TASK_FIELDS = frozenset(
    {"id", "class", "kind", "repo", "ref", "cache_key", "enqueued_by", "enqueued_at", "attempts"})
# `head` is OPTIONAL only in the flat-set sense: validate_task REQUIRES it on every PR kind and
# FORBIDS it on every issue kind, so neither a PR row without a head binding nor a meaningless head
# on an issue row can enter the queue.
OPTIONAL_TASK_FIELDS = frozenset({"heal_rank", "not_before", "head"})


class TaskQueueError(ValueError):
    """A fail-closed queue schema/IO error, never carrying credential material."""


# ---- hostile-input validation (applied on READ and before every WRITE) --------------------------
def _positive_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _non_negative_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _atom(value, pattern, what):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise TaskQueueError(f"task {what} is malformed")
    return value


def validate_task(task):
    """Return the canonical task record, or raise TaskQueueError.

    Every field is character-class pinned because these values cross workflow boundaries (log
    lines, job summaries, and — once a lane converts — `workflow_dispatch` inputs). A newline or
    shell metacharacter in `repo`/`cache_key` must never reach any of them.
    """
    if not isinstance(task, dict):
        raise TaskQueueError("queue contains a non-object task")
    present = set(task)
    missing = REQUIRED_TASK_FIELDS - present
    if missing:
        raise TaskQueueError(f"task is missing required field(s): {', '.join(sorted(missing))}")
    unknown = present - REQUIRED_TASK_FIELDS - OPTIONAL_TASK_FIELDS
    if unknown:
        raise TaskQueueError(f"task carries unknown field(s): {', '.join(sorted(unknown))}")

    _atom(task["id"], ID_RE, "id")
    _atom(task["repo"], REPO_RE, "repo")
    _atom(task["cache_key"], CACHE_KEY_RE, "cache_key")
    _atom(task["enqueued_by"], ENQUEUED_BY_RE, "enqueued_by")
    if task["kind"] not in KINDS:
        raise TaskQueueError(f"task kind {task['kind']!r} is not a known kind")
    # HEAD BINDING. A PR row names the exact head it was planned for; `revalidate` drops it the
    # moment the live head differs, so a force-push or a new commit can never be executed against
    # a superseded plan. A row without that binding could outlive its head, so it is refused —
    # and a head on an issue row is meaningless (nothing would ever check it), so that is refused
    # too rather than being silently carried.
    if task["kind"] in PR_KINDS:
        if "head" not in task:
            raise TaskQueueError("a PR-kind task must carry its planned head sha")
        _atom(task["head"], SHA_RE, "head")
    elif "head" in task:
        raise TaskQueueError("head is only meaningful on a PR-kind task")
    if task["class"] not in CLASSES or isinstance(task["class"], bool):
        raise TaskQueueError("task class must be 1..4")
    if not _positive_int(task["ref"]):
        raise TaskQueueError("task ref must be a positive integer")
    if not _positive_int(task["enqueued_at"]):
        raise TaskQueueError("task enqueued_at must be a positive integer")
    if not _non_negative_int(task["attempts"]):
        raise TaskQueueError("task attempts must be a non-negative integer")
    if "not_before" in task and not _positive_int(task["not_before"]):
        raise TaskQueueError("task not_before must be a positive integer")
    if "heal_rank" in task:
        # A rank outside the heal class is meaningless and would silently reorder a non-heal task
        # ahead of its peers, so it fails closed rather than being ignored.
        if task["class"] != HEAL_CLASS:
            raise TaskQueueError("heal_rank is only meaningful on a class-2 task")
        if task["heal_rank"] not in HEAL_RANKS or isinstance(task["heal_rank"], bool):
            raise TaskQueueError("task heal_rank must be 1..4")
    return task


def validate_cache_row(row):
    if not isinstance(row, dict) or set(row) != {"cache_key", "last_drained_at"}:
        raise TaskQueueError("cache row fields are invalid")
    _atom(row["cache_key"], CACHE_KEY_RE, "cache_key")
    if not _positive_int(row["last_drained_at"]):
        raise TaskQueueError("cache row last_drained_at must be a positive integer")
    return row


def validate_document(document):
    """Validate a whole queue document and return it canonically. Fails CLOSED — a malformed
    document must never degrade to an empty queue, which reads as 'no work' while every lane
    starves."""
    if not isinstance(document, dict) or set(document) != {"schema", "tasks", "cache"}:
        raise TaskQueueError("task queue top level is malformed")
    if document["schema"] != SCHEMA:
        raise TaskQueueError(f"task queue schema must be {SCHEMA}")
    tasks, cache = document["tasks"], document["cache"]
    if not isinstance(tasks, list) or not isinstance(cache, list):
        raise TaskQueueError("task queue tasks/cache fields are malformed")
    if len(tasks) > MAX_TASKS:
        raise TaskQueueError(f"task queue holds more than {MAX_TASKS} tasks")
    if len(cache) > MAX_CACHE:
        raise TaskQueueError(f"task queue holds more than {MAX_CACHE} cache rows")
    seen_ids = set()
    for task in tasks:
        validate_task(task)
        if task["id"] in seen_ids:
            raise TaskQueueError(f"task queue contains duplicate id {task['id']!r}")
        seen_ids.add(task["id"])
    seen_keys = set()
    for row in cache:
        validate_cache_row(row)
        if row["cache_key"] in seen_keys:
            raise TaskQueueError("task queue contains duplicate cache rows")
        seen_keys.add(row["cache_key"])
    return document


def empty_document():
    return {"schema": SCHEMA, "tasks": [], "cache": []}


# ---- PURE pick core (the component the whole design exists to centralise) -----------------------
def warm_cache_keys(document, now, cache_ttl_minutes):
    """The cache_keys still warm at `now`. A row timestamped in the FUTURE is not warm: clock skew
    (or a hostile row) must not mint permanent warmth."""
    ttl = cache_ttl_minutes * 60
    return {row["cache_key"] for row in document["cache"]
            if 0 <= now - row["last_drained_at"] < ttl}


def clamp_escalated(task, now, heal_max_wait_minutes):
    """The anti-starvation clamp: a class-2 (self-healing) task that has waited at least
    `heal_max_wait_minutes` overrides ANY warm-cache preference. Scoped to class 2 deliberately —
    the directive's concern is a cold outage repair starved behind a hot streak."""
    return (task["class"] == HEAL_CLASS
            and now - task["enqueued_at"] >= heal_max_wait_minutes * 60)


def eligible(task, now):
    """Backoff/visibility gate: a task hidden until `not_before` is not pickable."""
    return task.get("not_before", 0) <= now


def pick_sort_key(task, now, warm_keys, heal_max_wait_minutes):
    """The ONE ordering, in the maintainer's stated precedence:

        clamp-escalated heal > warm-cache preference > class > in-class rank > FIFO

    Ties break on `id` so the order is total and the self-test is deterministic.
    """
    return (
        0 if clamp_escalated(task, now, heal_max_wait_minutes) else 1,
        0 if task["cache_key"] in warm_keys else 1,
        task["class"],
        task.get("heal_rank", UNRANKED),
        task["enqueued_at"],
        task["id"],
    )


def drain_pick(document, now, *, cache_ttl_minutes=DEFAULT_CACHE_TTL_MINUTES,
               heal_max_wait_minutes=DEFAULT_HEAL_MAX_WAIT_MINUTES, limit=DEFAULT_DRAIN_BATCH):
    """PURE: up to `limit` eligible tasks in priority order.

    Selection is GREEDY and re-sorts after each pick, folding the chosen task's cache_key into the
    warm set. That is the point of the cache-warmth priority: a batch CHAINS on one warm context
    instead of interleaving cold ones. The clamp still overrides — an escalated heal task outranks
    the chain on the next iteration.
    """
    if not _positive_int(limit):
        return []
    warm = warm_cache_keys(document, now, cache_ttl_minutes)
    remaining = [task for task in document["tasks"] if eligible(task, now)]
    picked = []
    while remaining and len(picked) < limit:
        remaining.sort(key=lambda task: pick_sort_key(task, now, warm, heal_max_wait_minutes))
        chosen = remaining.pop(0)
        picked.append(chosen)
        warm = warm | {chosen["cache_key"]}
    return picked


def requeue_delay_ceiling(attempts, base=60, cap=3600):
    """Bounded exponential ceiling (seconds) for the requeue of a task that has now failed
    `attempts` times. Split from the random draw so the schedule is unit-asserted without the
    RNG, exactly as the ledger CAS backoff is."""
    if attempts < 1 or base <= 0 or cap <= 0:
        raise ValueError("requeue backoff inputs must be positive")
    return min(cap, base * (2 ** (attempts - 1)))


def apply_pick(document, picked, now, visibility_minutes=DEFAULT_VISIBILITY_MINUTES):
    """PURE: hide the picked tasks for the visibility window and record their cache warmth.

    Attempts are NOT incremented here — a pick is not a failure. `requeue_task` owns that.
    """
    picked_ids = {task["id"] for task in picked}
    tasks = []
    for task in document["tasks"]:
        if task["id"] in picked_ids:
            task = dict(task, not_before=now + visibility_minutes * 60)
        tasks.append(task)
    cache = {row["cache_key"]: row["last_drained_at"] for row in document["cache"]}
    for task in picked:
        cache[task["cache_key"]] = now
    rows = [{"cache_key": key, "last_drained_at": stamp} for key, stamp in cache.items()]
    rows.sort(key=lambda row: (-row["last_drained_at"], row["cache_key"]))
    return {"schema": SCHEMA, "tasks": tasks, "cache": rows[:MAX_CACHE]}


def complete_task(document, task_id):
    """PURE: remove a finished task. Returns (document, removed?), and (None, False) when the id is
    unknown so `mutate` skips the CAS write entirely — an unknown id must not burn a commit (and a
    retry storm of them) rewriting the queue to its existing contents."""
    tasks = [task for task in document["tasks"] if task["id"] != task_id]
    if len(tasks) == len(document["tasks"]):
        return None, False
    return dict(document, tasks=tasks), True


def requeue_task(document, task_id, now, *, draw=random.uniform):
    """PURE-ish: bump attempts and push the task out by a jittered bounded backoff.

    Returns (document, attempts), or (None, 0) when the id is unknown so `mutate` skips the CAS
    write. `draw` is injected so the self-test pins the schedule without the RNG.
    """
    tasks, attempts = [], 0
    for task in document["tasks"]:
        if task["id"] == task_id:
            attempts = task["attempts"] + 1
            delay = int(draw(0, requeue_delay_ceiling(attempts)))
            # max(1, ...) because a zero jitter draw would leave the task instantly eligible and
            # the drain would spin on it every tick — the backoff must always be a real delay.
            task = dict(task, attempts=attempts, not_before=now + max(1, delay))
        tasks.append(task)
    if not attempts:
        return None, 0
    return dict(document, tasks=tasks), attempts


def hold_task(document, task_id, now, hold_minutes=DEFAULT_HOLD_MINUTES):
    """PURE: hide a HEALTHY task for `hold_minutes` WITHOUT touching `attempts`.

    A hold is NOT a failure, and that distinction is the whole point of this operation. `requeue`
    exists for a task that was attempted and did not succeed: it burns one of `max_attempts`, which
    `compact` uses to drop a row that keeps failing. A task the drain deliberately did not launch —
    Phase A's still-push-dispatched kinds — has failed nothing, so requeueing it would classify a
    perfectly healthy row as repeatedly failed and delete it after `max_attempts` drain ticks,
    destroying queue continuity while emitting a false attempts-exhausted signal.

    Returns (document, not_before) or (None, 0) for an unknown id. When the row is ALREADY hidden
    at least this long (the normal case: `apply_pick`'s visibility window ≥ the hold), the document
    is unchanged and (None, existing_not_before) is returned so `mutate` skips the CAS write — a
    held row must not burn one ledger commit per row per tick.
    """
    if not _positive_int(hold_minutes):
        raise TaskQueueError("hold_minutes must be a positive integer")
    until = now + hold_minutes * 60
    tasks, found, current = [], False, 0
    for task in document["tasks"]:
        if task["id"] == task_id:
            found = True
            current = task.get("not_before", 0)
            if current < until:
                task = dict(task, not_before=until)
        tasks.append(task)
    if not found:
        return None, 0
    if current >= until:
        return None, current
    return dict(document, tasks=tasks), until


def compact(document, now, *, max_attempts=DEFAULT_MAX_ATTEMPTS,
            cache_ttl_minutes=DEFAULT_CACHE_TTL_MINUTES, max_age_minutes=DEFAULT_MAX_AGE_MINUTES):
    """PURE: drop dead rows and expired cache warmth. Returns (document, [(id, reason), ...]).

    Dropping is always REPORTED, never silent — a task that leaves the queue without being done is
    exactly the event an operator needs to see.
    """
    kept, dropped = [], []
    for task in document["tasks"]:
        if task["attempts"] >= max_attempts:
            dropped.append((task["id"], "attempts-exhausted"))
        elif now - task["enqueued_at"] >= max_age_minutes * 60:
            dropped.append((task["id"], "max-age-exceeded"))
        else:
            kept.append(task)
    ttl = cache_ttl_minutes * 60
    cache = [row for row in document["cache"] if 0 <= now - row["last_drained_at"] < ttl]
    cache.sort(key=lambda row: (-row["last_drained_at"], row["cache_key"]))
    return {"schema": SCHEMA, "tasks": kept, "cache": cache[:MAX_CACHE]}, dropped


def enqueue_tasks(document, new_tasks):
    """PURE: add tasks whose id is not already queued. Returns (document, added, skipped).

    Dedup by id is what makes a dual-writing enqueuer IDEMPOTENT: PLAN re-emits the same rows every
    tick, and re-enqueueing must never reset an in-flight task's attempts or backoff.
    """
    known = {task["id"] for task in document["tasks"]}
    tasks, added, skipped = list(document["tasks"]), 0, 0
    for task in new_tasks:
        validate_task(task)
        if task["id"] in known:
            skipped += 1
            continue
        known.add(task["id"])
        tasks.append(task)
        added += 1
    if len(tasks) > MAX_TASKS:
        raise TaskQueueError(
            f"enqueue would push the queue past {MAX_TASKS} tasks — refusing (fail closed)")
    return dict(document, tasks=tasks), added, skipped


# ---- observability ------------------------------------------------------------------------------
def queue_stats(document, now):
    """PURE: per-class depth and oldest age (seconds). Every class is present even at depth 0, so
    the drain summary shape is stable and a class that empties is visibly empty."""
    stats = {}
    for klass in CLASSES:
        rows = [task for task in document["tasks"] if task["class"] == klass]
        oldest = max((now - task["enqueued_at"] for task in rows), default=0)
        stats[klass] = {"depth": len(rows), "oldest_age_seconds": max(0, oldest)}
    return stats


def clamp_alarm(document, now, heal_max_wait_minutes=DEFAULT_HEAL_MAX_WAIT_MINUTES):
    """PURE: (alarming, oldest_class2_age_seconds). NON-TERMINAL by contract — self-healing is
    itself monitored, but a queue that is merely slow must not fail the drain and stop the queue
    from being drained at all."""
    ages = [now - task["enqueued_at"] for task in document["tasks"]
            if task["class"] == HEAL_CLASS]
    oldest = max(ages, default=0)
    return oldest >= heal_max_wait_minutes * 60 and bool(ages), max(0, oldest)


# ---- live-state re-validation (LIVENESS ONLY — never a trust check) -----------------------------
# The queue is a HINT; live state is truth. This may only DROP a stale row. It is deliberately
# weaker than dispatch-claim.py's validation and does not replace any part of it.
def revalidate(task, live):
    """PURE: (ok, reason). `live` is the target's live issue/PR record as the drain fetched it."""
    if live is None:
        return False, "live-state-unreadable"
    if not isinstance(live, dict):
        return False, "live-state-malformed"
    if live.get("state") != "open":
        return False, "target-not-open"
    if task["kind"] in PR_KINDS:
        if live.get("merged"):
            return False, "target-merged"
        # EXACT HEAD BINDING, for every PR kind. The row was planned for one head; anything else
        # live means the PR moved on (new commit or force-push) and this row is SUPERSEDED — the
        # PLAN tick that observed the new head enqueues its own row. An unreadable/malformed live
        # head fails CLOSED to a drop rather than to "assume it still matches".
        live_head = live.get("head")
        if not isinstance(live_head, dict):
            return False, "live-state-malformed"
        live_sha = live_head.get("sha")
        if not isinstance(live_sha, str) or SHA_RE.fullmatch(live_sha) is None:
            return False, "live-state-malformed"
        if live_sha != task["head"]:
            return False, "head-superseded"
        draft = live.get("draft")
        if not isinstance(draft, bool):
            return False, "live-state-malformed"
        # review/fix act on the OPEN DRAFT worker PR (review-fix.yml's own input contract); a
        # disarm exists precisely because the PR was un-drafted/armed. Either mismatch means the
        # PR moved on since enqueue.
        if task["kind"] == "disarm" and draft:
            return False, "pr-already-disarmed"
        if task["kind"] in {"review", "fix"} and not draft:
            return False, "pr-no-longer-draft"
    return True, "ok"


# ---- PLAN -> queue projection (the first enqueuer, issue #243 item 3) ---------------------------
# Class/rank assignment, per the design record's "class 2c/3/4 by kind":
#   disarm      -> class 2 rank 3  (alarm-driven convergence: retracting an unsafe arm)
#   ci/rebase   -> class 3         (project INFRASTRUCTURE: target CI/build health)
#   review/fix  -> class 4         (project WORK: the issue flow itself)
# The keys are dispatch-claim.REVIEW_STATES; an unknown state fails closed (it is not silently
# dropped OR silently defaulted into a class — a new state must be classified deliberately).
PLAN_STATE_ROUTE = {
    "needs-review": ("review", 4, None),
    "stranded": ("review", 4, None),
    "needs-fix": ("fix", 4, None),
    "needs-ci-fix": ("fix", 3, None),
    "needs-rebase": ("fix", 3, None),
}
DISARM_ROUTE = ("disarm", HEAL_CLASS, 3)


def _sanitise_component(value, fallback="unknown"):
    """Reduce a free-form PLAN field to a cache_key-safe component. PLAN's artifact is produced by
    a job that ran untrusted target code, so nothing from it is trusted verbatim."""
    if not isinstance(value, str):
        return fallback
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return cleaned[:48] or fallback


def plan_cache_key(repo, package, lane, provider):
    """repo + surface + agent, per the design record. Phase A uses the PLAN item's `package` as the
    surface and `impl_provider` as the agent proxy: the review lane runs on the OPPOSITE provider
    of the implementation, so two items sharing an impl_provider share a reviewer context."""
    return (f"{_sanitise_component(repo, 'repo')}#{_sanitise_component(package, 'nopkg')}"
            f"#{lane}#{_sanitise_component(provider, 'noprov')}")


def _plan_items(plan, key):
    """The PLAN artifact's emission list under `key`, or raise.

    `plan.get(key) or []` would be WRONG here in the way that matters most: a truncated artifact
    missing the key, a null, or a hostile wrong type (`{}`, `""`, `0`) is falsey and would project
    to an empty queue that is INDISTINGUISHABLE from a genuine 'this lane had no work' tick. PLAN
    (dispatch.yml) always emits both keys as lists, so anything else is corruption and fails loud.
    """
    if key not in plan:
        raise TaskQueueError(f"plan artifact is missing required key {key!r}")
    items = plan[key]
    if not isinstance(items, list):
        raise TaskQueueError(f"plan artifact key {key!r} must be a list")
    return items


_CLAIM_MODULE = None


def _claim_module():
    """Cached dispatch-claim.py module — CLAIM's OWN strict PLAN validator, IMPORTED rather than
    replicated so the enqueue side of the artifact can never drift into a weaker schema than the
    dispatch side. dispatch-claim.py is import-side-effect-free (constants and defs only); the
    same lazy-load seam groom.py/plan-snapshot.py already use for this file."""
    global _CLAIM_MODULE
    if _CLAIM_MODULE is None:
        path = Path(__file__).resolve().with_name("dispatch-claim.py")
        spec = importlib.util.spec_from_file_location("registry_dispatch_claim_tq", path)
        if spec is None or spec.loader is None:
            raise TaskQueueError(f"cannot load the PLAN validator {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _CLAIM_MODULE = module
    return _CLAIM_MODULE


def validate_plan_artifact(plan):
    """FULL dispatch-claim.py PLAN validation, run before ANY projection or queue mutation.

    WHY THE WHOLE SCHEMA, NOT JUST THE FIELDS THIS MODULE READS. The enqueue job holds
    `contents: write` on the data-plane branch while consuming an artifact produced by the
    unprivileged job that executes untrusted target code. Character-class checks on the handful of
    fields the projection touches stop injection but establish NOTHING about authenticity: a
    compromised producer could emit well-formed rows for repositories the tick never planned, or
    repeat a row until the queue hits MAX_TASKS and every later legitimate enqueue fails closed.
    So the enqueuer applies exactly the validation the CLAIM consumer applies to the SAME artifact
    — exact top-level and per-item fields, schema version, deterministic order, uniqueness, and
    (the binding that matters here) every review/disarm item's `repo` must be a member of the
    plan's own validated `repositories` set. A plan that CLAIM would refuse to act on is a plan
    this job refuses to enqueue.
    """
    claim = _claim_module()
    try:
        return claim.validate_plan(plan)
    except claim.DispatchError as error:
        raise TaskQueueError(f"plan artifact failed dispatch validation: {error}") from error


def tasks_from_plan(plan, enqueued_by, now):
    """PURE: the queue rows a dispatch PLAN artifact implies. Raises TaskQueueError on a malformed
    artifact — the enqueuer must fail LOUD rather than silently enqueue a truncated view of the
    tick, which would read downstream as 'the lane had no work'.

    The artifact is FULLY validated (`validate_plan_artifact`) before a single row is projected, so
    every emitted row is bound to a repository the plan itself declared. The per-field checks below
    are kept as defence in depth for the fields this projection actually reads.

    Each row carries the FULL planned head SHA (and embeds its prefix in the id), so a new push
    produces a NEW row and the superseded one is dropped by `revalidate`'s exact head match instead
    of executing against a stale head.
    """
    if not isinstance(plan, dict):
        raise TaskQueueError("plan artifact is not an object")
    validate_plan_artifact(plan)
    tasks = []
    for item in _plan_items(plan, "review_items"):
        if not isinstance(item, dict):
            raise TaskQueueError("plan review item is not an object")
        state = item.get("state")
        route = PLAN_STATE_ROUTE.get(state)
        if route is None:
            raise TaskQueueError(f"plan review item carries unclassified state {state!r}")
        kind, klass, rank = route
        repo, number = item.get("repo"), item.get("pr_number")
        head = item.get("head_sha")
        if not isinstance(head, str) or re.fullmatch(r"[0-9a-f]{40}", head) is None:
            raise TaskQueueError("plan review item head_sha is malformed")
        task = {
            "id": f"{kind}:{repo}#{number}:{head[:12]}",
            "class": klass,
            "kind": kind,
            "head": head,
            "repo": repo if isinstance(repo, str) else "",
            "ref": number,
            "cache_key": plan_cache_key(repo, item.get("package"), kind,
                                        item.get("impl_provider")),
            "enqueued_by": enqueued_by,
            "enqueued_at": now,
            "attempts": 0,
        }
        if rank is not None:
            task["heal_rank"] = rank
        tasks.append(validate_task(task))
    for item in _plan_items(plan, "disarm_items"):
        if not isinstance(item, dict):
            raise TaskQueueError("plan disarm item is not an object")
        kind, klass, rank = DISARM_ROUTE
        repo, number = item.get("repo"), item.get("pr_number")
        head = item.get("head_sha")
        if not isinstance(head, str) or re.fullmatch(r"[0-9a-f]{40}", head) is None:
            raise TaskQueueError("plan disarm item head_sha is malformed")
        # The disarm row binds the same way every PR kind does: the head the mismatch was observed
        # at. A push moves the head, so the old row is superseded and PLAN's next tick re-emits the
        # disarm for the new head if the armed-SHA mismatch still holds. The reviewed-sha side of
        # that invariant stays where it lives — dispatch-claim/worker-pr re-derive it live before
        # any disarm acts; nothing here replaces it.
        tasks.append(validate_task({
            "id": f"{kind}:{repo}#{number}:{head[:12]}",
            "class": klass,
            "heal_rank": rank,
            "kind": kind,
            "head": head,
            "repo": repo if isinstance(repo, str) else "",
            "ref": number,
            "cache_key": plan_cache_key(repo, None, kind, None),
            "enqueued_by": enqueued_by,
            "enqueued_at": now,
            "attempts": 0,
        }))
    return tasks


# ---- GitHub CAS I/O (the lease ledger's discipline, thread for thread) --------------------------
def queue_read_path(repo):
    """Contents-API GET path, pinned to the data-plane branch (never the protected default)."""
    return f"repos/{repo}/contents/{QUEUE_PATH}?ref={LEDGER_REF}"


def queue_write_args(repo, message, content_b64, sha):
    """gh argv for the CAS PUT, pinned to the data-plane branch — a PUT without `branch=` commits
    to the default branch, which its required-status-check protection rejects (issue #28)."""
    args = ["gh", "api", "-X", "PUT", f"repos/{repo}/contents/{QUEUE_PATH}",
            "-f", f"message={message}", "-f", f"content={content_b64}",
            "-f", f"branch={LEDGER_REF}"]
    if sha:
        args += ["-f", f"sha={sha}"]
    return args


def _branch_exists(repo):
    return subprocess.run(
        ["gh", "api", f"repos/{repo}/git/ref/heads/{LEDGER_REF}"],
        capture_output=True, text=True, check=False).returncode == 0


def _read_404(branch_exists):
    """Pure 404 policy, identical in spirit to the lease ledger's: file-absent on a PRESENT branch
    seeds an empty queue (the first CAS PUT creates it); an ABSENT/unreadable branch fails LOUD —
    silently-empty would make every drain report 'no work' against a queue nobody can see."""
    if branch_exists:
        return empty_document(), None
    raise TaskQueueError(
        f"ledger branch '{LEDGER_REF}' is missing or unreadable — create it from master "
        "(see data/README.md) before draining")


def read_queue(repo):
    """Return (document, blob_sha or None). Validates the document as hostile input."""
    result = subprocess.run(["gh", "api", queue_read_path(repo)],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        if "HTTP 404" in result.stderr:
            return _read_404(_branch_exists(repo))
        raise TaskQueueError("task queue read failed")
    try:
        meta = json.loads(result.stdout)
        raw = base64.b64decode(meta["content"]).decode() or json.dumps(empty_document())
        document = validate_document(json.loads(raw))
        sha = meta["sha"]
        if not isinstance(sha, str) or not sha:
            raise ValueError("blob sha is missing")
        return document, sha
    except TaskQueueError:
        raise
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise TaskQueueError("task queue document is malformed") from exc


def write_queue(repo, document, sha, message):
    """PUT via CAS. True on success; False ONLY on a genuine CAS conflict so the caller re-reads
    and retries. ANY other failure — authorization (403), missing branch/file (404), request
    validation (non-race 422), availability (5xx) — raises immediately instead of being collapsed
    into a retryable conflict and mislabeled 'CAS kept conflicting' (issue #179)."""
    validate_document(document)
    body = base64.b64encode(
        (json.dumps(document, indent=1, sort_keys=True) + "\n").encode()).decode()
    result = subprocess.run(queue_write_args(repo, message, body, sha),
                            capture_output=True, text=True, check=False)
    if result.returncode == 0:
        return True
    if ledger_retry.is_cas_conflict(result.stderr, create=sha is None):
        return False
    raise TaskQueueError(
        "task queue CAS PUT failed with a non-conflict error (authorization, validation, missing "
        "branch, or availability) — failing loud rather than exhausting CAS retries")


def _sleep_backoff(attempt):
    """Module-level so the self-test stubs it without sleeping."""
    ledger_retry.sleep_backoff(attempt, sleeper=time.sleep, draw=random.uniform)


def mutate(repo, transform, message, retries=6):
    """Read-modify-CAS-write under bounded, fully jittered retries.

    `transform(document)` returns (document, result) and MUST be pure: it is re-run from a fresh
    read after every lost race, so any side effect would replay. Returns (result, True) on a
    committed write, (None, False) when the CAS kept conflicting, and raises TaskQueueError on a
    real API error.
    """
    for attempt in range(retries):
        if attempt:
            _sleep_backoff(attempt)
        document, sha = read_queue(repo)
        updated, result = transform(document)
        if updated is None:
            return result, True  # transform decided there is nothing to write
        if write_queue(repo, updated, sha, message):
            return result, True
    return None, False


# ---- CLI ----------------------------------------------------------------------------------------
def build_parser():
    """The CLI contract. A named builder so the self-test can assert that every flag
    .github/workflows/drain.yml and dispatch.yml pass is actually DECLARED (the PR #595 finding-2
    vacuity class: a workflow-shaped invocation exiting 2 with 'unrecognized arguments' on every
    tick while the enrolled suite stays green because the tests call the functions directly)."""
    parser = argparse.ArgumentParser(description="orchestrator task queue (issue #243)")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo", default="", help="registry repo owning the ledger branch")
    parser.add_argument("--enqueue-from-plan", default="", metavar="PLAN_JSON",
                        help="dual-write a dispatch PLAN artifact's emissions into the queue")
    parser.add_argument("--run-url", default="", help="enqueuing workflow run URL (provenance)")
    parser.add_argument("--pick", action="store_true", help="pick a drain batch")
    parser.add_argument("--complete", default="", metavar="TASK_ID")
    parser.add_argument("--requeue", default="", metavar="TASK_ID",
                        help="a task was ATTEMPTED and failed: back it off and burn one attempt")
    parser.add_argument("--hold", default="", metavar="TASK_ID",
                        help="a healthy task was deliberately NOT launched: hide it without "
                             "consuming its failure budget")
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--limit", type=int, default=DEFAULT_DRAIN_BATCH)
    parser.add_argument("--cache-ttl-minutes", type=int, default=DEFAULT_CACHE_TTL_MINUTES)
    parser.add_argument("--heal-max-wait-minutes", type=int,
                        default=DEFAULT_HEAL_MAX_WAIT_MINUTES)
    parser.add_argument("--visibility-minutes", type=int, default=DEFAULT_VISIBILITY_MINUTES)
    parser.add_argument("--hold-minutes", type=int, default=DEFAULT_HOLD_MINUTES)
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    return parser


def _require_repo(args, parser):
    if not args.repo or REPO_RE.fullmatch(args.repo) is None:
        parser.error("--repo must be a well-formed owner/name")
    # Every tunable must be a POSITIVE integer. argparse's type=int happily accepts 0 and negatives,
    # and each of them silently breaks the queue in a way that still looks like it is working:
    # --limit 0 drains nothing forever, --heal-max-wait-minutes 0 escalates every class-2 task, and
    # --visibility-minutes 0 leaves a picked task instantly re-pickable (a hot loop).
    for flag, value in (("--limit", args.limit),
                        ("--cache-ttl-minutes", args.cache_ttl_minutes),
                        ("--heal-max-wait-minutes", args.heal_max_wait_minutes),
                        ("--visibility-minutes", args.visibility_minutes),
                        # --hold-minutes 0 would leave a held row instantly re-pickable, so the
                        # drain would spin on the same unconverted kind every tick.
                        ("--hold-minutes", args.hold_minutes),
                        ("--max-attempts", args.max_attempts)):
        if not _positive_int(value):
            parser.error(f"{flag} must be a positive integer")
    return args.repo


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    now = int(time.time())

    if args.enqueue_from_plan:
        repo = _require_repo(args, parser)
        if ENQUEUED_BY_RE.fullmatch(args.run_url) is None:
            parser.error("--run-url must be an https run URL")
        plan = json.loads(Path(args.enqueue_from_plan).read_text(encoding="utf-8"))
        new_tasks = tasks_from_plan(plan, args.run_url, now)

        def _enqueue(document):
            document, added, skipped = enqueue_tasks(document, new_tasks)
            if not added:
                return None, (0, skipped)
            return document, (added, skipped)

        outcome, committed = mutate(repo, _enqueue, f"enqueue {len(new_tasks)} planned task(s)")
        if not committed:
            print("::error::task queue enqueue CAS kept conflicting", file=sys.stderr)
            return 1
        added, skipped = outcome
        print(f"enqueued {added} task(s), {skipped} already queued")
        return 0

    if args.pick:
        repo = _require_repo(args, parser)

        def _pick(document):
            picked = drain_pick(document, now, cache_ttl_minutes=args.cache_ttl_minutes,
                                heal_max_wait_minutes=args.heal_max_wait_minutes,
                                limit=args.limit)
            if not picked:
                return None, []
            return apply_pick(document, picked, now, args.visibility_minutes), picked

        picked, committed = mutate(repo, _pick, f"drain pick {args.limit}")
        if not committed:
            print("::error::task queue pick CAS kept conflicting", file=sys.stderr)
            return 1
        print(json.dumps(picked or [], sort_keys=True))
        return 0

    if args.complete:
        repo = _require_repo(args, parser)
        _, committed = mutate(
            repo, lambda doc: complete_task(doc, args.complete),
            f"complete task {args.complete}")
        if not committed:
            print("::error::task queue complete CAS kept conflicting", file=sys.stderr)
            return 1
        print(f"completed {args.complete}")
        return 0

    if args.requeue:
        repo = _require_repo(args, parser)
        attempts, committed = mutate(
            repo, lambda doc: requeue_task(doc, args.requeue, now),
            f"requeue task {args.requeue}")
        if not committed:
            print("::error::task queue requeue CAS kept conflicting", file=sys.stderr)
            return 1
        print(f"requeued {args.requeue} (attempts={attempts})")
        return 0

    if args.hold:
        repo = _require_repo(args, parser)
        until, committed = mutate(
            repo, lambda doc: hold_task(doc, args.hold, now, args.hold_minutes),
            f"hold task {args.hold}")
        if not committed:
            print("::error::task queue hold CAS kept conflicting", file=sys.stderr)
            return 1
        if not until:
            # Not an error: the row can have been completed or compacted between pick and hold.
            print(f"::warning::hold of unknown task {args.hold} (already completed or compacted)")
            return 0
        print(f"held {args.hold} until {until} (attempts unchanged)")
        return 0

    if args.compact:
        repo = _require_repo(args, parser)

        def _compact(document):
            updated, dropped = compact(document, now, max_attempts=args.max_attempts,
                                       cache_ttl_minutes=args.cache_ttl_minutes)
            if updated == document:
                return None, []
            return updated, dropped

        dropped, committed = mutate(repo, _compact, "compact task queue")
        if not committed:
            print("::error::task queue compact CAS kept conflicting", file=sys.stderr)
            return 1
        for task_id, reason in dropped or []:
            print(f"::warning::dropped task {task_id}: {reason}")
        print(f"compacted; dropped {len(dropped or [])} task(s)")
        return 0

    if args.stats:
        repo = _require_repo(args, parser)
        document, _ = read_queue(repo)
        alarming, oldest = clamp_alarm(document, now, args.heal_max_wait_minutes)
        print(json.dumps({"stats": {str(k): v for k, v in queue_stats(document, now).items()},
                          "class2_alarm": alarming, "class2_oldest_age_seconds": oldest},
                         sort_keys=True))
        return 0

    parser.error("one of --self-test/--enqueue-from-plan/--pick/--complete/--requeue/--hold/"
                 "--compact/--stats is required")
    return 2


# ---- self-test ----------------------------------------------------------------------------------
HEAD_A = "a" * 40


def _task(task_id, klass, *, enqueued_at, cache_key="r#p#review#anthropic", rank=None,
          kind="review", not_before=None, attempts=0, repo="o/r", ref=1, head=HEAD_A):
    task = {"id": task_id, "class": klass, "kind": kind, "repo": repo, "ref": ref,
            "cache_key": cache_key, "enqueued_by": "https://example.invalid/run/1",
            "enqueued_at": enqueued_at, "attempts": attempts}
    if kind in PR_KINDS:
        task["head"] = head
    if rank is not None:
        task["heal_rank"] = rank
    if not_before is not None:
        task["not_before"] = not_before
    return task


def _doc(tasks, cache=None):
    return {"schema": SCHEMA, "tasks": list(tasks), "cache": list(cache or [])}


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    def refuses(name, thunk):
        try:
            thunk()
        except TaskQueueError:
            check(name, "refused", "refused")
        else:
            check(name, "ACCEPTED", "refused")

    now = 1_000_000

    # ---- PURE pick ordering: every precedence level, each asserted in ISOLATION so a check can
    # only pass for the reason it names.
    # class beats FIFO: the older class-4 must NOT outrank the newer class-2.
    doc = _doc([_task("old-c4", 4, enqueued_at=now - 900, cache_key="k-a"),
                _task("new-c2", 2, enqueued_at=now - 30, cache_key="k-b")])
    check("class outranks FIFO",
          [t["id"] for t in drain_pick(doc, now, limit=2)], ["new-c2", "old-c4"])

    # in-class heal rank orders within class 2, and an UNRANKED class-2 sorts last.
    doc = _doc([_task("c2-r3", 2, enqueued_at=now - 10, rank=3, cache_key="k"),
                _task("c2-none", 2, enqueued_at=now - 10, cache_key="k"),
                _task("c2-r1", 2, enqueued_at=now - 10, rank=1, cache_key="k")])
    check("in-class heal rank then unranked last",
          [t["id"] for t in drain_pick(doc, now, limit=3)], ["c2-r1", "c2-r3", "c2-none"])

    # FIFO breaks a full tie.
    doc = _doc([_task("later", 4, enqueued_at=now - 10, cache_key="k"),
                _task("earlier", 4, enqueued_at=now - 500, cache_key="k")])
    check("FIFO breaks a full tie",
          [t["id"] for t in drain_pick(doc, now, limit=2)], ["earlier", "later"])

    # WARM CACHE outranks class: a warm class-4 is picked before a COLD class-3.
    warm = [{"cache_key": "warm", "last_drained_at": now - 60}]
    doc = _doc([_task("cold-c3", 3, enqueued_at=now - 100, cache_key="cold"),
                _task("warm-c4", 4, enqueued_at=now - 100, cache_key="warm")], warm)
    check("warm cache outranks class",
          [t["id"] for t in drain_pick(doc, now, limit=2)], ["warm-c4", "cold-c3"])

    # ...and that preference is BOUNDED BY THE TTL: the same document with the warmth aged out
    # inverts the order. This is the check that makes the one above non-vacuous.
    stale = [{"cache_key": "warm", "last_drained_at": now - 61 * 60}]
    doc = _doc([_task("cold-c3", 3, enqueued_at=now - 100, cache_key="cold"),
                _task("warm-c4", 4, enqueued_at=now - 100, cache_key="warm")], stale)
    check("warm preference expires at cache_ttl_minutes",
          [t["id"] for t in drain_pick(doc, now, limit=2, cache_ttl_minutes=60)],
          ["cold-c3", "warm-c4"])
    check("a future cache stamp is not warm",
          warm_cache_keys(_doc([], [{"cache_key": "f", "last_drained_at": now + 5}]), now, 60),
          set())

    # ---- THE ANTI-STARVATION CLAMP. Same document, only the heal task's AGE differs.
    clamp_doc = lambda age: _doc(  # noqa: E731 - fixture builder, deliberately terse
        [_task("heal-c2", 2, enqueued_at=now - age, rank=1, cache_key="cold", kind="repair"),
         _task("hot-c4", 4, enqueued_at=now - 5, cache_key="warm")],
        [{"cache_key": "warm", "last_drained_at": now - 60}])
    check("BELOW the clamp, warm cache still wins",
          [t["id"] for t in drain_pick(clamp_doc(9 * 60), now, limit=2, heal_max_wait_minutes=10)],
          ["hot-c4", "heal-c2"])
    check("AT the clamp, the cold heal task overrides warm preference",
          [t["id"] for t in drain_pick(clamp_doc(10 * 60), now, limit=2, heal_max_wait_minutes=10)],
          ["heal-c2", "hot-c4"])
    check("the clamp escalates ONLY the heal class",
          (clamp_escalated(_task("a", 2, enqueued_at=now - 601), now, 10),
           clamp_escalated(_task("b", 3, enqueued_at=now - 6000), now, 10),
           clamp_escalated(_task("c", 4, enqueued_at=now - 6000), now, 10)),
          (True, False, False))

    # ---- batch CHAINING: picking a task warms its key for the rest of the batch, so the second
    # pick prefers the same context over an equal-priority cold one.
    doc = _doc([_task("a-first", 4, enqueued_at=now - 300, cache_key="ctx-a"),
                _task("a-second", 4, enqueued_at=now - 100, cache_key="ctx-a"),
                _task("b-middle", 4, enqueued_at=now - 200, cache_key="ctx-b")])
    check("a batch chains on the warmed cache_key",
          [t["id"] for t in drain_pick(doc, now, limit=2)], ["a-first", "a-second"])

    # ---- eligibility / limits
    doc = _doc([_task("hidden", 2, enqueued_at=now - 900, not_before=now + 60),
                _task("ready", 4, enqueued_at=now - 10)])
    check("a not_before task is not picked",
          [t["id"] for t in drain_pick(doc, now, limit=5)], ["ready"])
    check("limit is honoured",
          len(drain_pick(_doc([_task(f"t{i}", 4, enqueued_at=now - i) for i in range(9)]),
                         now, limit=3)), 3)
    check("a non-positive limit picks nothing",
          drain_pick(_doc([_task("t", 4, enqueued_at=now)]), now, limit=0), [])

    # ---- SCHEMA FAIL-CLOSED (hostile input, both directions)
    good = _task("ok", 4, enqueued_at=now)
    check("a well-formed task validates", validate_task(dict(good))["id"], "ok")
    refuses("unknown field refused", lambda: validate_task(dict(good, payload={"x": 1})))
    refuses("missing field refused",
            lambda: validate_task({k: v for k, v in good.items() if k != "kind"}))
    refuses("class 5 refused", lambda: validate_task(dict(good, **{"class": 5})))
    refuses("bool class refused", lambda: validate_task(dict(good, **{"class": True})))
    refuses("unknown kind refused", lambda: validate_task(dict(good, kind="exec")))
    refuses("newline in repo refused", lambda: validate_task(dict(good, repo="o/r\nx")))
    refuses("shell metachar in cache_key refused",
            lambda: validate_task(dict(good, cache_key="a;rm -rf /")))
    refuses("non-https enqueued_by refused",
            lambda: validate_task(dict(good, enqueued_by="file:///etc/passwd")))
    refuses("bool ref refused", lambda: validate_task(dict(good, ref=True)))
    refuses("zero ref refused", lambda: validate_task(dict(good, ref=0)))
    refuses("negative attempts refused", lambda: validate_task(dict(good, attempts=-1)))
    refuses("heal_rank outside class 2 refused",
            lambda: validate_task(dict(good, heal_rank=1)))
    # HEAD BINDING is part of the schema: a PR row without one could outlive its head, and a head
    # on an issue row is never checked by anything.
    refuses("a PR-kind task without a head refused",
            lambda: validate_task({k: v for k, v in good.items() if k != "head"}))
    refuses("a short head refused", lambda: validate_task(dict(good, head="a" * 39)))
    refuses("an upper-case head refused", lambda: validate_task(dict(good, head="A" * 40)))
    refuses("a non-string head refused", lambda: validate_task(dict(good, head=1)))
    refuses("a head on an issue-kind task refused",
            lambda: validate_task(dict(_task("i", 4, enqueued_at=now, kind="issue"), head=HEAD_A)))
    check("an issue-kind task needs no head",
          validate_task(_task("i", 4, enqueued_at=now, kind="issue"))["kind"], "issue")
    refuses("heal_rank 9 refused",
            lambda: validate_task(dict(_task("h", 2, enqueued_at=now), heal_rank=9)))
    refuses("wrong schema refused",
            lambda: validate_document({"schema": "other/v9", "tasks": [], "cache": []}))
    refuses("extra top-level key refused",
            lambda: validate_document({"schema": SCHEMA, "tasks": [], "cache": [], "x": 1}))
    refuses("duplicate ids refused",
            lambda: validate_document(_doc([_task("dup", 4, enqueued_at=now),
                                            _task("dup", 3, enqueued_at=now)])))
    refuses("oversized queue refused",
            lambda: validate_document(_doc([_task(f"t{i}", 4, enqueued_at=now)
                                            for i in range(MAX_TASKS + 1)])))
    refuses("malformed cache row refused",
            lambda: validate_document(_doc([], [{"cache_key": "k"}])))
    check("a valid document validates", validate_document(_doc([good]))["schema"], SCHEMA)

    # ---- enqueue dedup / idempotence
    base, added, skipped = enqueue_tasks(_doc([]), [good, dict(good)])
    check("enqueue dedups within one batch", (added, skipped, len(base["tasks"])), (1, 1, 1))
    inflight = _doc([dict(good, attempts=3, not_before=now + 999)])
    again, added, skipped = enqueue_tasks(inflight, [dict(good)])
    check("re-enqueue never resets an in-flight task",
          (added, skipped, again["tasks"][0]["attempts"], again["tasks"][0]["not_before"]),
          (0, 1, 3, now + 999))
    refuses("enqueue past the cap refused",
            lambda: enqueue_tasks(_doc([_task(f"t{i}", 4, enqueued_at=now)
                                        for i in range(MAX_TASKS)]), [good]))

    # ---- pick bookkeeping: visibility + cache warmth, and attempts NOT bumped by a pick
    doc = _doc([_task("p", 4, enqueued_at=now - 10, cache_key="ck")])
    picked = drain_pick(doc, now, limit=1)
    applied = apply_pick(doc, picked, now, visibility_minutes=30)
    check("pick hides the task for the visibility window",
          applied["tasks"][0]["not_before"], now + 30 * 60)
    check("pick records cache warmth", applied["cache"], [{"cache_key": "ck",
                                                           "last_drained_at": now}])
    check("pick does not bump attempts", applied["tasks"][0]["attempts"], 0)
    check("a hidden task is not re-picked next tick",
          drain_pick(applied, now + 60, limit=1), [])

    # ---- complete / requeue-with-backoff
    done, removed = complete_task(applied, "p")
    check("complete removes the task", (removed, done["tasks"]), (True, []))
    # An unknown id must yield the no-write sentinel, not a rewrite of the queue to its own
    # contents (which would burn a ledger commit per stale id, every tick).
    check("complete of an unknown id writes nothing", complete_task(applied, "nope"), (None, False))
    check("requeue of an unknown id writes nothing", requeue_task(applied, "nope", now), (None, 0))
    bumped, attempts = requeue_task(applied, "p", now, draw=lambda lo, hi: hi)
    check("requeue bumps attempts and backs off",
          (attempts, bumped["tasks"][0]["not_before"]), (1, now + 60))
    twice, attempts = requeue_task(bumped, "p", now, draw=lambda lo, hi: hi)
    check("requeue backoff is exponential",
          (attempts, twice["tasks"][0]["not_before"]), (2, now + 120))
    check("requeue backoff is bounded",
          [requeue_delay_ceiling(i) for i in (1, 2, 6, 7, 40)], [60, 120, 1920, 3600, 3600])
    check("a jittered requeue is never instantly eligible",
          requeue_task(applied, "p", now, draw=lambda lo, hi: 0)[0]["tasks"][0]["not_before"] > now,
          True)

    # ---- HOLD: a deliberate non-launch is NOT a failure and must not consume the retry budget.
    held_doc = _doc([_task("h", 4, enqueued_at=now - 10)])
    holding, until = hold_task(held_doc, "h", now, hold_minutes=30)
    check("hold hides the task WITHOUT bumping attempts",
          (holding["tasks"][0]["attempts"], holding["tasks"][0]["not_before"], until),
          (0, now + 30 * 60, now + 30 * 60))
    check("a held task is not re-picked inside its window",
          drain_pick(holding, now + 60, limit=1), [])
    check("a held task IS pickable again once the window lapses",
          [t["id"] for t in drain_pick(holding, now + 31 * 60, limit=1)], ["h"])
    check("hold of an unknown id writes nothing", hold_task(held_doc, "nope", now), (None, 0))
    # A row already hidden at least this long needs NO write — otherwise every held row would burn
    # one ledger commit on every drain tick.
    already = _doc([_task("h", 4, enqueued_at=now - 10, not_before=now + 9999)])
    check("hold writes nothing when the row is already hidden longer",
          hold_task(already, "h", now, hold_minutes=30), (None, now + 9999))
    refuses("a non-positive hold window refused",
            lambda: hold_task(held_doc, "h", now, hold_minutes=0))

    # END TO END, the claim drain.yml's Phase-A hold branch makes: a healthy row that is picked and
    # held on EVERY tick survives more than `max_attempts` ticks with its attempts untouched...
    def _drain_cycles(cycles, settle):
        """Run `cycles` full drain ticks (pick -> apply -> settle -> compact) over one row."""
        doc, clock, picks = _doc([_task("phase-a", 4, enqueued_at=now, cache_key="ck")]), now, 0
        for _ in range(cycles):
            batch = drain_pick(doc, clock, limit=1)
            if batch:
                picks += 1
                doc = apply_pick(doc, batch, clock, visibility_minutes=30)
                updated = settle(doc, clock)
                doc = updated if updated is not None else doc
            clock += 40 * 60          # the next tick after the hiding window lapses
            doc, _dropped = compact(doc, clock, max_attempts=DEFAULT_MAX_ATTEMPTS)
        return doc, picks

    cycles = DEFAULT_MAX_ATTEMPTS + 2
    held_end, held_picks = _drain_cycles(
        cycles, lambda doc, clock: hold_task(doc, "phase-a", clock, hold_minutes=30)[0])
    check("a HELD row survives more than max_attempts drain ticks, attempts untouched",
          ([t["id"] for t in held_end["tasks"]], [t["attempts"] for t in held_end["tasks"]],
           held_picks),
          (["phase-a"], [0], cycles))
    # ...whereas the SAME loop settling with --requeue burns the failure budget and the row is
    # compacted as attempts-exhausted. This is the check that makes the one above non-vacuous: it
    # is the exact defect the hold operation exists to fix.
    burned_end, burned_picks = _drain_cycles(
        cycles, lambda doc, clock: requeue_task(doc, "phase-a", clock, draw=lambda lo, hi: 0)[0])
    check("the SAME loop on requeue is compacted as attempts-exhausted",
          ([t["id"] for t in burned_end["tasks"]], burned_picks < cycles),
          ([], True))

    # ---- compact
    doc = _doc([_task("dead", 4, enqueued_at=now - 60, attempts=5),
                _task("ancient", 4, enqueued_at=now - 48 * 3600),
                _task("live", 4, enqueued_at=now - 60)],
               [{"cache_key": "fresh", "last_drained_at": now - 60},
                {"cache_key": "stale", "last_drained_at": now - 7200}])
    packed, dropped = compact(doc, now, max_attempts=5, cache_ttl_minutes=60)
    check("compact drops exhausted and ancient rows, reporting each",
          ([t["id"] for t in packed["tasks"]], sorted(dropped)),
          (["live"], [("ancient", "max-age-exceeded"), ("dead", "attempts-exhausted")]))
    check("compact expires stale cache warmth",
          [row["cache_key"] for row in packed["cache"]], ["fresh"])

    # ---- observability
    doc = _doc([_task("h1", 2, enqueued_at=now - 1200, rank=1),
                _task("w1", 4, enqueued_at=now - 60),
                _task("w2", 4, enqueued_at=now - 30)])
    stats = queue_stats(doc, now)
    check("per-class depth and oldest age",
          (stats[2]["depth"], stats[2]["oldest_age_seconds"], stats[4]["depth"],
           stats[4]["oldest_age_seconds"], stats[1]["depth"], stats[3]["depth"]),
          (1, 1200, 2, 60, 0, 0))
    check("class-2 age past the clamp alarms", clamp_alarm(doc, now, 10), (True, 1200))
    check("class-2 age inside the clamp does not alarm",
          clamp_alarm(_doc([_task("h", 2, enqueued_at=now - 60, rank=1)]), now, 10), (False, 60))
    check("an EMPTY class 2 never alarms", clamp_alarm(_doc([]), now, 10), (False, 0))

    # ---- live re-validation (LIVENESS ONLY, may only drop)
    review = _task("rv", 4, enqueued_at=now, kind="review")
    disarm = _task("dz", 2, enqueued_at=now, kind="disarm", rank=3)
    issue = _task("is", 4, enqueued_at=now, kind="issue")

    def _live_pr(sha=HEAD_A, **overrides):
        live = {"state": "open", "draft": True, "merged": False, "head": {"sha": sha}}
        live.update(overrides)
        return live

    check("open draft PR revalidates for review", revalidate(review, _live_pr()), (True, "ok"))
    check("closed PR drops", revalidate(review, _live_pr(state="closed"))[1], "target-not-open")
    check("merged PR drops", revalidate(review, _live_pr(merged=True))[1], "target-merged")
    check("un-drafted PR drops a review", revalidate(review, _live_pr(draft=False))[1],
          "pr-no-longer-draft")
    check("a re-drafted PR drops its disarm", revalidate(disarm, _live_pr())[1],
          "pr-already-disarmed")
    check("an armed PR revalidates for disarm",
          revalidate(disarm, _live_pr(draft=False)), (True, "ok"))
    check("unreadable live state drops (fail closed)", revalidate(review, None)[1],
          "live-state-unreadable")
    check("missing draft flag drops (fail closed)",
          revalidate(review, {"state": "open", "merged": False, "head": {"sha": HEAD_A}})[1],
          "live-state-malformed")
    check("an open issue revalidates", revalidate(issue, {"state": "open"}), (True, "ok"))

    # ---- HEAD BINDING: the row is bound to the EXACT head it was planned for, for EVERY PR kind.
    # Both directions, one character apart, so neither check can pass for any other reason.
    for kind, task, live_extra in (("review", review, {}),
                                   ("fix", _task("fx", 4, enqueued_at=now, kind="fix"), {}),
                                   ("disarm", disarm, {"draft": False})):
        check(f"the SAME live head revalidates a {kind}",
              revalidate(task, _live_pr(HEAD_A, **live_extra)), (True, "ok"))
        check(f"a one-character-different live head drops a {kind}",
              revalidate(task, _live_pr("a" * 39 + "b", **live_extra))[1], "head-superseded")
        check(f"a wholly new live head drops a {kind}",
              revalidate(task, _live_pr("e" * 40, **live_extra))[1], "head-superseded")
    check("an unreadable live head drops (fail closed, never assumed-matching)",
          (revalidate(review, {"state": "open", "draft": True, "merged": False})[1],
           revalidate(review, _live_pr(head="not-a-sha"))[1],
           revalidate(review, _live_pr(head={"sha": "A" * 40}))[1]),
          ("live-state-malformed", "live-state-malformed", "live-state-malformed"))
    # A COMPLETE, dispatch-valid PLAN artifact — the projection now refuses anything less (see
    # validate_plan_artifact), so every fixture below is a genuine v4 document. The schema string
    # is READ FROM the validator rather than hard-coded, so a schema bump does not turn these
    # fixtures into a false red while the membership/uniqueness properties they assert stay live.
    claim_mod = _claim_module()

    # Fields the PLAN schema has gained since these fixtures were written, each with the value a
    # worker-lane PLAN really emits. Kept as an EXPLICIT table, not a blanket "default anything
    # missing to empty": a silent auto-fill would let a future required field — one whose value
    # actually changes routing — slip in defaulted the safe-looking way, which is exactly the
    # failure `_require_exact_fields` exists to prevent. The assertions below make an unlisted
    # new field a LOUD red here instead.
    _PLAN_DEFAULTS = {"partition_starvation": []}   # registry #677
    _REVIEW_ITEM_DEFAULTS = {"self_attested": False}  # registry #657 — false for worker-lane items

    def _plan_doc(reviews, disarms, repos=("o/r",), **overrides):
        document = {
            "schema": claim_mod.SCHEMA,
            "generated_at": "2026-07-18T00:00:00Z",
            "repositories": [{"target_repo": repo, "target_sha": "0" * 40, "items": []}
                             for repo in repos],
            "review_items": [dict(_REVIEW_ITEM_DEFAULTS, **item) for item in reviews],
            "disarm_items": list(disarms),
            "snapshot_skips": [],
        }
        document.update(_PLAN_DEFAULTS)
        document.update(overrides)
        return document

    # The fixture must cover EVERY field the live validator requires. Without this, a new required
    # PLAN or review-item field would surface as a confusing "missing X" inside an unrelated
    # assertion (measured: `missing partition_starvation`) rather than as a named failure here.
    _missing_plan = claim_mod.PLAN_FIELDS - set(_plan_doc([], []))
    check("the plan fixture covers every field the live validator requires", _missing_plan, set())
    _missing_item = claim_mod.REVIEW_ITEM_FIELDS - set(_REVIEW_ITEM_DEFAULTS) - {
        "pr_number", "head_sha", "state", "impl_provider", "repo", "package", "security",
        "context"}
    check("the review-item fixture covers every field the live validator requires",
          _missing_item, set())

    # END TO END: the supersession the projection docstring claims. The row PLAN emitted for the
    # old head is DROPPED once the PR's live head moves, so it can never be routed as live work.
    superseded = tasks_from_plan(
        _plan_doc([{"pr_number": 7, "head_sha": HEAD_A, "state": "needs-review",
                    "impl_provider": "anthropic", "repo": "o/r", "package": "core",
                    "security": False, "context": ""}], []),
        "https://example.invalid/run/5", now)[0]
    check("a queued row is dropped once the PR is pushed to a new head",
          (revalidate(superseded, _live_pr(HEAD_A))[0],
           revalidate(superseded, _live_pr("f" * 40))), (True, (False, "head-superseded")))
    # Every kind must declare the endpoint the drain re-validates it against; an unclassified kind
    # would probe the wrong API and drop all its tasks as "unreadable".
    check("every kind has a live-state endpoint", sorted(LIVE_ENDPOINT), sorted(KINDS))
    check("PR kinds read pulls, issue kinds read issues",
          sorted({k for k, v in LIVE_ENDPOINT.items() if v == "pulls"}),
          ["disarm", "fix", "review"])
    # PR_KINDS drives the schema's head requirement AND the head binding above; a kind that reads
    # `pulls` but is missing here would be routed with no head binding at all.
    check("PR_KINDS is exactly the set of pulls-endpoint kinds",
          sorted(PR_KINDS), sorted(k for k, v in LIVE_ENDPOINT.items() if v == "pulls"))

    # ---- PLAN projection (the first enqueuer)
    plan = _plan_doc(
        [
            {"pr_number": 7, "head_sha": "a" * 40, "state": "needs-review",
             "impl_provider": "anthropic", "repo": "o/r", "package": "core",
             "security": False, "context": ""},
            {"pr_number": 8, "head_sha": "b" * 40, "state": "needs-ci-fix",
             "impl_provider": "openai", "repo": "o/r", "package": "core",
             "security": False, "context": "gate"},
        ],
        [{"pr_number": 9, "head_sha": "c" * 40, "reviewed_sha": "d" * 40, "repo": "o/r"}],
    )
    rows = tasks_from_plan(plan, "https://example.invalid/run/5", now)
    check("PLAN emissions project to class 4 / 3 / 2c by kind",
          [(t["kind"], t["class"], t.get("heal_rank")) for t in rows],
          [("review", 4, None), ("fix", 3, None), ("disarm", 2, 3)])
    check("PLAN ids bind the head SHA",
          [t["id"] for t in rows],
          ["review:o/r#7:aaaaaaaaaaaa", "fix:o/r#8:bbbbbbbbbbbb", "disarm:o/r#9:cccccccccccc"])
    # The id carries only a PREFIX; the row carries the FULL head, which is what revalidate binds.
    check("every projected PR row carries the FULL planned head",
          [t["head"] for t in rows], ["a" * 40, "b" * 40, "c" * 40])
    check("PLAN cache_key is repo+surface+lane+agent",
          rows[0]["cache_key"], "o-r#core#review#anthropic")
    check("a new head SHA is a NEW task, not a mutation of the old one",
          tasks_from_plan(_plan_doc([dict(plan["review_items"][0], head_sha="e" * 40)], []),
                          "https://example.invalid/run/5", now)[0]["id"],
          "review:o/r#7:eeeeeeeeeeee")
    check("re-projecting the same PLAN enqueues nothing new",
          enqueue_tasks(enqueue_tasks(_doc([]), rows)[0], rows)[1], 0)
    def _one_review(**overrides):
        return _plan_doc([dict(plan["review_items"][0], **overrides)], [])

    refuses("an unclassified PLAN state refuses (never silently defaulted)",
            lambda: tasks_from_plan(_one_review(state="needs-telepathy"),
                                    "https://example.invalid/run/5", now))
    refuses("a malformed PLAN head_sha refuses",
            lambda: tasks_from_plan(_one_review(head_sha="nope"),
                                    "https://example.invalid/run/5", now))
    refuses("a hostile PLAN repo refuses",
            lambda: tasks_from_plan(_one_review(repo="o/r; rm -rf /"),
                                    "https://example.invalid/run/5", now))
    # A MALFORMED PLAN MUST NEVER LOOK LIKE 'NO WORK'. Each emission key must be PRESENT and a
    # LIST: a missing key, a null, or a falsey wrong type would otherwise project to an empty
    # queue indistinguishable from a genuine empty tick, silently starving the lane. Asserted at
    # BOTH layers — through the projection, AND against `_plan_items` directly, so this
    # defence-in-depth layer cannot go vacuous behind the full-schema gate now running in front
    # of it (the gate refuses these first, which is why the inner layer needs its own test).
    for label, key, value in (("null", "review_items", None),
                              ("empty-object", "disarm_items", {}),
                              ("string", "review_items", ""),
                              ("non-empty string", "review_items", "[]"),
                              ("zero", "disarm_items", 0)):
        bad_plan = _plan_doc([], [], **{key: value})
        refuses(f"a PLAN with {label} {key} refuses (never a silent empty queue)",
                lambda bad=bad_plan: tasks_from_plan(bad, "https://example.invalid/run/5", now))
        refuses(f"_plan_items refuses a {label} {key}",
                lambda bad=bad_plan, k=key: _plan_items(bad, k))
    for key in ("review_items", "disarm_items"):
        missing = {name: value for name, value in _plan_doc([], []).items() if name != key}
        refuses(f"a PLAN missing {key} refuses (never a silent empty queue)",
                lambda bad=missing: tasks_from_plan(bad, "https://example.invalid/run/5", now))
        refuses(f"_plan_items refuses a missing {key}",
                lambda bad=missing, k=key: _plan_items(bad, k))
    refuses("a non-object PLAN refuses",
            lambda: tasks_from_plan([], "https://example.invalid/run/5", now))
    # ...and ONLY a genuinely empty tick — a complete, dispatch-valid document with both emission
    # lists empty — projects to zero rows. Without this the checks above could pass by refusing
    # everything, and the new full-schema gate would be indistinguishable from a blanket refusal.
    check("a genuinely empty PLAN projects to zero rows",
          tasks_from_plan(_plan_doc([], []), "https://example.invalid/run/5", now), [])
    check("a hostile PLAN package cannot inject into cache_key",
          plan_cache_key("o/r", "co re;$(id)", "review", "anthropic"),
          "o-r#co-re-id#review#anthropic")
    check("every PLAN state dispatch-claim enumerates is classified",
          sorted(PLAN_STATE_ROUTE),
          sorted({"needs-review", "needs-fix", "needs-ci-fix", "needs-rebase", "stranded"}))
    # ...pinned against the LIVE validator too, not only the literal above. validate_plan_artifact
    # now admits exactly dispatch-claim's REVIEW_STATES, so a state added there without a class
    # here would reach an unclassified route at enqueue time (fail-closed, but only in production).
    # This makes that drift turn the GATE red instead.
    check("the classification table matches dispatch-claim's live REVIEW_STATES",
          sorted(PLAN_STATE_ROUTE), sorted(claim_mod.REVIEW_STATES))

    # ---- AUTHENTICITY OF THE ARTIFACT (review round 2 on PR #634), not merely well-formedness.
    # The enqueue job holds `contents: write` on the ledger while consuming an artifact assembled
    # by the unprivileged job that executes untrusted target code. Character classes stop
    # injection but prove nothing about ORIGIN: a well-formed row naming a repository the tick
    # never planned, an unknown field smuggling state past the schema, or the same row repeated
    # until the queue hits MAX_TASKS are all "safe strings" and all forgeries. Each is refused
    # BEFORE projection by validate_plan_artifact, and each has a positive control so the refusal
    # cannot be an artefact of the fixture.
    forged_review = dict(plan["review_items"][0], repo="o/unplanned")
    forged_disarm = dict(plan["disarm_items"][0], repo="o/unplanned")
    refuses("a review item for a repo the PLAN never planned refuses",
            lambda: tasks_from_plan(_plan_doc([forged_review], []),
                                    "https://example.invalid/run/5", now))
    refuses("a disarm item for a repo the PLAN never planned refuses",
            lambda: tasks_from_plan(_plan_doc([], [forged_disarm]),
                                    "https://example.invalid/run/5", now))
    check("...and the SAME rows project once that repo IS in the planned set",
          [task["repo"] for task in tasks_from_plan(
              _plan_doc([forged_review], [forged_disarm], repos=("o/r", "o/unplanned")),
              "https://example.invalid/run/5", now)],
          ["o/unplanned", "o/unplanned"])
    refuses("an unknown top-level PLAN field refuses",
            lambda: tasks_from_plan(_plan_doc([], [], smuggled="x"),
                                    "https://example.invalid/run/5", now))
    refuses("an unknown review-item field refuses",
            lambda: tasks_from_plan(
                _plan_doc([dict(plan["review_items"][0], smuggled="x")], []),
                "https://example.invalid/run/5", now))
    refuses("a missing review-item field refuses",
            lambda: tasks_from_plan(
                _plan_doc([{name: value for name, value in plan["review_items"][0].items()
                            if name != "security"}], []),
                "https://example.invalid/run/5", now))
    refuses("an unsupported PLAN schema version refuses",
            lambda: tasks_from_plan(_plan_doc([], [], schema="registry-dispatch-plan/v0"),
                                    "https://example.invalid/run/5", now))
    refuses("a repeated review item refuses (queue-flooding by duplication)",
            lambda: tasks_from_plan(
                _plan_doc([plan["review_items"][0], plan["review_items"][0]], []),
                "https://example.invalid/run/5", now))
    refuses("a repeated disarm item refuses (queue-flooding by duplication)",
            lambda: tasks_from_plan(
                _plan_doc([], [plan["disarm_items"][0], plan["disarm_items"][0]]),
                "https://example.invalid/run/5", now))

    # ---- CAS I/O: argv shape, branch pinning, 404 policy, conflict classification, retry loop
    args = queue_write_args("o/r", "msg", "Ym9keQ==", "sha1")
    check("CAS PUT pins the data-plane branch and the read SHA",
          (f"branch={LEDGER_REF}" in args, "sha=sha1" in args, args[3] == "PUT"),
          (True, True, True))
    check("a create PUT omits the sha", "sha=" in " ".join(queue_write_args("o/r", "m", "c", None)),
          False)
    check("the read path pins the ref", queue_read_path("o/r"),
          f"repos/o/r/contents/{QUEUE_PATH}?ref={LEDGER_REF}")
    check("404 on a PRESENT branch seeds an empty queue", _read_404(True), (empty_document(), None))
    refuses("404 on an ABSENT branch fails loud", lambda: _read_404(False))
    check("only a real CAS race is retryable",
          (ledger_retry.is_cas_conflict("HTTP 409: Conflict", create=False),
           ledger_retry.is_cas_conflict('HTTP 422: "sha" wasn\'t supplied', create=True),
           ledger_retry.is_cas_conflict("HTTP 422: bad branch", create=True),
           ledger_retry.is_cas_conflict("HTTP 403: Forbidden", create=False)),
          (True, True, False, False))

    # CAS RETRY LOOP, driven through the REAL mutate() with the I/O layer stubbed: two lost races
    # then a win, and the transform re-runs from a FRESH read each time (never replays stale state).
    saved_read, saved_write, saved_sleep = read_queue, write_queue, _sleep_backoff
    slept = []
    try:
        reads = [(_doc([]), "sha-a"), (_doc([]), "sha-b"), (_doc([]), "sha-c")]
        seen_shas = []

        def fake_read(repo):
            return reads.pop(0)

        def fake_write(repo, document, sha, message):
            seen_shas.append(sha)
            return len(seen_shas) == 3  # lose twice, then win

        globals()["read_queue"] = fake_read
        globals()["write_queue"] = fake_write
        globals()["_sleep_backoff"] = lambda attempt: slept.append(attempt)
        result, committed = mutate("o/r", lambda doc: (dict(doc, tasks=[good]), "done"), "m")
        check("mutate retries a lost CAS race and commits",
              (result, committed, seen_shas), ("done", True, ["sha-a", "sha-b", "sha-c"]))
        check("mutate backs off between attempts (bounded, jittered)", slept, [1, 2])

        # Retries are BOUNDED: a permanently conflicting CAS reports failure, never loops forever.
        reads.extend([(_doc([]), f"s{i}") for i in range(6)])
        globals()["write_queue"] = lambda *a, **k: False
        result, committed = mutate("o/r", lambda doc: (dict(doc, tasks=[good]), "x"), "m",
                                   retries=6)
        check("mutate gives up after bounded retries", (result, committed), (None, False))

        # A REAL API error propagates instead of being retried into "CAS kept conflicting".
        def angry_write(*a, **k):
            raise TaskQueueError("task queue CAS PUT failed with a non-conflict error")

        reads.append((_doc([]), "s"))
        globals()["write_queue"] = angry_write
        refuses("a non-conflict API error surfaces, not swallowed",
                lambda: mutate("o/r", lambda doc: (dict(doc, tasks=[good]), "x"), "m"))

        # A transform returning None commits nothing (the enqueue/compact no-op path).
        reads.append((_doc([]), "s"))
        globals()["write_queue"] = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("must not write"))
        check("a no-op transform writes nothing",
              mutate("o/r", lambda doc: (None, "noop"), "m"), ("noop", True))
    finally:
        globals()["read_queue"] = saved_read
        globals()["write_queue"] = saved_write
        globals()["_sleep_backoff"] = saved_sleep

    # MUTATION-SENSITIVE end-to-end proof that the artifact gate sits IN FRONT of the ledger: the
    # forged plan is refused with ZERO writes, and the genuine plan commits its rows through the
    # very same stubbed I/O — so "refused" can never be an artefact of the stub.
    saved_read, saved_write = read_queue, write_queue
    try:
        import tempfile
        writes = []
        globals()["read_queue"] = lambda repo: (_doc([]), "sha-a")
        globals()["write_queue"] = lambda repo, document, sha, message: (
            writes.append(len(document["tasks"])) or True)
        with tempfile.TemporaryDirectory() as tmp:
            forged_path = Path(tmp, "forged.json")
            forged_path.write_text(
                json.dumps(_plan_doc([dict(plan["review_items"][0], repo="o/unplanned")], [])),
                encoding="utf-8")
            genuine_path = Path(tmp, "genuine.json")
            genuine_path.write_text(json.dumps(plan), encoding="utf-8")
            argv = ["--repo", "o/r", "--run-url", "https://example.invalid/run/5",
                    "--enqueue-from-plan"]
            refuses("a forged PLAN is refused before ANY queue write",
                    lambda: main(argv + [str(forged_path)]))
            check("...with nothing written to the ledger", writes, [])
            check("a genuine PLAN still enqueues its rows through the same path",
                  (main(argv + [str(genuine_path)]), writes), (0, [3]))
    finally:
        globals()["read_queue"] = saved_read
        globals()["write_queue"] = saved_write

    # ---- CLI GUARDS, driven through the REAL entrypoint (argparse exits 2 on error). No I/O runs:
    # every case below is refused during argument validation, before the first `gh` call.
    def cli_run(argv):
        # argparse prints usage to stderr on error; capture it so a PASSING suite does not emit
        # 4KB of usage text that reads like a failure in the pr-gate log — and so a check can
        # assert WHICH guard refused, not merely that something exited 2.
        import contextlib
        import io
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stderr(buffer):
                return main(argv), buffer.getvalue()
        except SystemExit as exc:
            return exc.code, buffer.getvalue()

    def cli_exit(argv):
        return cli_run(argv)[0]

    for bad_flag, bad_value in (("--limit", "0"), ("--cache-ttl-minutes", "0"),
                                ("--heal-max-wait-minutes", "-1"), ("--visibility-minutes", "0"),
                                # 0 would leave a held row instantly re-pickable every tick.
                                ("--hold-minutes", "0"), ("--max-attempts", "0")):
        check(f"{bad_flag}={bad_value} is refused by the CLI",
              cli_exit(["--pick", "--repo", "o/r", bad_flag, bad_value]), 2)
    check("a malformed --repo is refused", cli_exit(["--pick", "--repo", "not-a-repo"]), 2)
    # --hold must be a REAL action, not an undeclared flag falling through to "no action selected"
    # (both exit 2, so the exit code alone cannot tell them apart — the guard message can).
    hold_code, hold_err = cli_run(["--hold", "review:o/r#1:abc", "--repo", "not-a-repo"])
    check("--hold is a real CLI action, refused by the --repo guard (not 'no action selected')",
          (hold_code, "--repo must be a well-formed owner/name" in hold_err,
           "one of --self-test" in hold_err),
          (2, True, False))
    check("a non-https --run-url is refused",
          cli_exit(["--enqueue-from-plan", "/nonexistent", "--repo", "o/r",
                    "--run-url", "file:///etc/passwd"]), 2)
    check("no action selected is refused", cli_exit(["--repo", "o/r"]), 2)

    # ---- WORKFLOW/CLI SIGNATURE PINNING (the PR #595 finding-2 vacuity class). Every flag the
    # workflows actually pass is read OUT OF THE WORKFLOW FILES and asserted DECLARED, so a drift
    # that would exit 2 with "unrecognized arguments" on every tick turns the suite red instead of
    # hiding behind these direct-call tests.
    root = Path(__file__).resolve().parent.parent
    triage_path = root / "scripts" / "triage.py"
    spec = importlib.util.spec_from_file_location("registry_static_triage_tq", triage_path)
    static_triage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(static_triage)
    declared = static_triage.declared_options(build_parser())
    invocations = []
    for workflow in ("drain.yml", "dispatch.yml"):
        path = root / ".github" / "workflows" / workflow
        check(f"{workflow} exists for the CLI pin", path.is_file(), True)
        if not path.is_file():
            continue
        argvs = static_triage.workflow_argvs(str(path), "task-queue.py", {})
        invocations.extend((workflow, argv) for argv in argvs)
    passed = sorted({token for _, argv in invocations for token in argv
                     if token.startswith("--")})
    check("the workflows invoke scripts/task-queue.py", len(invocations) >= 2, True)
    check(f"every flag the workflows pass is DECLARED: {passed}",
          sorted(set(passed) - declared), [])
    check("drain.yml runs the enrolled self-test",
          any(wf == "drain.yml" and "--self-test" in argv for wf, argv in invocations), True)
    # The Phase-A hold branch is asserted against the WORKFLOW TEXT, because its verb is passed
    # through a python list the argv reader cannot see. A drain that settles an unconverted kind
    # with `--requeue` burns that healthy row's failure budget and compacts it as exhausted after
    # `max_attempts` ticks, so the verb itself is the invariant.
    drain_body = "\n".join(
        line for line in (root / ".github" / "workflows" / "drain.yml")
        .read_text(encoding="utf-8").splitlines() if not line.strip().startswith("#"))
    check("drain.yml holds an unconverted kind (--hold), never --requeue",
          (bool(re.search(r'queue\(\s*"--hold"', drain_body)),
           bool(re.search(r'queue\(\s*"--requeue"', drain_body)),
           "--hold" in declared),
          (True, False, True))
    check("dispatch.yml dual-writes PLAN emissions into the queue",
          any(wf == "dispatch.yml" and "--enqueue-from-plan" in argv
              for wf, argv in invocations), True)

    print("task-queue self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
