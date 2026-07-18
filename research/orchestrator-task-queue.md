# Orchestrator task queue — pull-based drain replacing push dispatch

**Status**: maintainer-directed design (2026-07-18). Phase A implements the substrate; the
push dispatch lanes are converted to enqueuers incrementally, never big-bang.

## Why (maintainer directive, in their framing)

The goal is repositories that are **self-managing**; *then* **self-healing is the critical
part to get right**. Workflows must be structured so self-healing tasks get priority — and
are internally prioritised too. Rather than the current push-based dispatch, repos should
**enqueue** agent tasks (reviews, open issues, adjudications, …) and the orchestrator
**drains** a queue it controls.

One day of production push-dispatch supplies the evidence: doorbell storms cancelling each
other, defer-loops each tick (idempotent-disarm, trust-gate absence, plan-ordering), silent
cross-repo races — all shapes where *the pusher decides timing* and every consumer must be
defensive. A single drain loop with a durable queue makes ordering, dedup, backoff, and
priority one component's job.

## Queue priority (maintainer-specified, in order)

1. **Cache warmth** — prompt caches expire (~minutes-to-an-hour depending on tier); the
   drain prefers tasks that reuse a currently-warm agent context (`cache_key`) so work on
   the same repo/surface/agent chains within the cache window instead of interleaving cold.
2. **Self-improvement** — orchestration visibility, optimisation, and fast issue
   resolution so orchestration failures never block project development. **Self-healing
   tasks sit at the top of this class**, internally ordered: (a) active-outage repair
   (a lane is DOWN), (b) stuck-item adjudication (`needs:orchestrator`), (c) alarm-driven
   convergence (reclaims, re-arms), (d) orchestration improvements (audit-backlog fixes).
3. **Project infrastructure** — target-repo CI/build health (e.g. sparq's gate/runner
   economy) so orchestration over projects runs smoothly.
4. **Project work** — the actual issues, in the project-defined order (priority labels).

**Anti-starvation clamp**: cache preference (1) reorders only within a bounded age window —
a class-2 heal task older than `heal_max_wait_minutes` (default 10) overrides any warm-cache
preference. Without the clamp, a hot class-4 streak could starve a cold outage repair, which
inverts the directive's intent.

## Substrate (Phase A)

- **Durable queue** on the ledger data-plane branch: `data/task-queue.json` — the same CAS
  append/compact discipline as the lease ledger (read-SHA compare-and-swap, bounded retries
  with jitter, real API errors surfaced; never a protected branch).
- **Task record** (hostile-input-validated on BOTH enqueue and drain):
  `{id, class: 1..4, heal_rank?, kind: review|fix|adjudicate|issue|repair|…, repo, ref
  (pr/issue number), cache_key (repo+surface+agent), enqueued_by (workflow run URL),
  enqueued_at, attempts, not_before?}`.
- **Enqueuers** (converted lanes; each a small PR):
  1. PLAN's review/fix/disarm emission → enqueue (class 2c/3/4 by kind) — CLAIM keeps its
     validation/lease role but reads FROM the queue.
  2. The stuck-escalation lane (`needs:orchestrator`) → class-2b heal tasks (subsumes the
     in-flight stuck-mode work; its per-park structured reason comment is the enqueue
     payload).
  3. Alarms (pipeline-alarm rows, plan-alert) → class-2a/2c repair tasks.
  4. Issue triage's ready issues → class 4 (project-defined order preserved inside the
     class via the existing priority labels).
- **Drain loop**: one workflow (`drain.yml`, cron + manual), single-flight per target
  (concurrency group), pops by: clamp-escalated heal first, then warm-cache preference,
  then class, then in-class rank, then FIFO. Every pop re-validates the task against live
  state (the queue is a HINT, live state is truth — a drained task whose PR/issue moved on
  is dropped with a logged reason, never executed stale).
- **Cache-warmth tracking**: the drain records `{cache_key, last_drained_at}` in the queue
  doc; "warm" = within the cache TTL configured in policy (`cache_ttl_minutes`, default 60
  per the maintainer's Anthropic figure; conservative for tiers with shorter TTLs since
  warm-preference is an optimisation, not a correctness gate).
- **Observability**: queue depth per class + oldest-age per class exported to the dashboard
  and the metrics collector; an alarm when class-2 age exceeds the clamp (self-healing is
  itself monitored — the directive's "proper visibility of all of your orchestration").

## Migration

Push lanes convert one at a time; each conversion PR removes exactly one push edge and its
doorbell. The cron cadence stays as the drain's heartbeat. Rollback per-lane = re-enable the
push edge. Success criterion per lane: zero defer-loop lines in a full day of drains.

## Non-goals (Phase A)

No change to the trust model (enqueue does not grant execution — the drain's CLAIM-side
validation and lease discipline stay exactly as they are); no batch-execution semantics
(#224 owns that); no cross-registry federation.
