#!/usr/bin/env python3
# [FABLE-5] Observability + alerting for the throughput of EVERY maintained target (the targets in
# policy/repos.toml [repos.*]: sparq-org/sparq and jeswr/agent-account-registry itself). The
# maintainer asked to track, per target: (1) issues open, (2) issues ready to drain, (3) issues
# drained in the last hour, (4) PRs open, (5) PR open rate, (6) PR close/merge rate — plus derived
# health and ALERTING when the open-PR backlog GROWS with insufficient throughput to triage / ready
# / close it. The signal this exposes: sparq PR open-rate (5/hr) >> close-rate (0/hr) while
# merged_1h=0 despite merged_24h=51 — the review lane stalled and the backlog is GROWING.
#
# DESIGN (mirrors the rest of the registry orchestration plane):
#  * PURE-ish core: metric computation, rate derivation over a snapshot window, and alert-rule
#    evaluation are PURE functions of fixture inputs (list/window counts + prior snapshots) and are
#    unit-tested with `--self-test`. Only the live collection/write paths reach out over `gh` / API.
#  * READINESS is per-target and uses each target's REAL definition — NOT a naive label count.
#    sparq is drained by the ready-issues.py engine (status:ready + priority + role + no gate +
#    no open blocker + conflict-free packages); the registry drains its OWN open `from:agent`
#    issues. Both definitions are resolved here from policy/repos.toml (readiness.kind) so a new
#    target picks the right engine declaratively. For sparq we reuse ready-issues.compute_ready()
#    directly (imported), so the two never drift.
#  * TIME-SERIES: each snapshot is appended to a bounded ring (last MAX_SNAPSHOTS) on the LEDGER
#    branch (LEDGER_REF, data/metrics-history.jsonl-style JSON) via the SAME CAS contents-API
#    helpers the model-health ledger uses — so rates over time are REAL, not point-in-time, and a
#    missing ledger branch fails LOUD (issue #28), never silently-empty.
#  * PUBLICATION: the alert-enriched current snapshot is CAS-written to `data/metrics.json` on the
#    ledger branch. dashboard.yml copies it to `site/metrics.json` in the one Pages artifact.
#  * ALERTING is NON-terminal and DEDUPED: one rolling `throughput-alert` issue per (target,
#    classification), keyed by a hidden HTML marker in the body (the model-health upsert pattern) —
#    a flap REOPENS the closed marker issue, recovery closes it, nothing is spammed. Thresholds
#    live in policy/repos.toml ([repos.*].throughput) with sensible defaults so they are tunable
#    per target; mutating a threshold flips the alert (mutation-checked in --self-test).
#  * The emitted snapshot is shaped for a dashboard panel to consume (documented schema below);
#    the dashboard UI itself is built elsewhere (routes to codex).
#
# SNAPSHOT SCHEMA (stdout + one ring record on the ledger):
#   {
#     "generated_at": "<RFC3339 UTC>",
#     "schema_version": 1,
#     "targets": {
#       "<owner/repo>": {
#         "issues_open": int, "issues_ready": int,
#         "issues_closed_1h": int, "issues_closed_24h": int,
#         "prs_open": int, "prs_draft": int,
#         "prs_opened_1h": int, "prs_closed_1h": int,
#         "prs_merged_1h": int, "prs_merged_24h": int,
#         "review_changes_backlog": int, "needs_user_parked": int,
#         "review_lane_health": "ok" | "idle" | "stalled" | "unknown",
#         "review_lane_runs_1h": int | null,   # review-fix runs CONCLUDED this hour (null=no signal)
#         "worker_attempts_1h": int,           # worker runs concluded this hour (0 => rate null)
#         "worker_success_rate_1h": float | null,
#         # [#987] the NO-CHANGE gate, per target: how much of the fleet's work produced nothing.
#         # All four are null when the model-health ledger yielded no attributable signal — never 0.
#         "worker_no_change_1h": int | null,        # THIS hour's worker RUNS that produced no diff
#                                                   # (one vote per run id: re-run attempts fold)
#         "worker_no_change_rate_1h": float | null, # /worker_attempts_1h (0 attempts => null)
#         "worker_no_change_by_reason_1h": {"<why_no_diff>": int, ...} | null,  # CLOSED vocabulary,
#                                                   # every reason always present (zero rows included)
#         "worker_no_change_repeat_issues_1h": [{"issue": int, "count": int}, ...] | null,
#         # derived:
#         "pr_open_rate": float,      # PRs opened / hr (from prs_opened_1h, or the ring delta)
#         "pr_close_rate": float,     # PRs closed+merged / hr
#         "net_pr_flow": float        # open_rate - close_rate (>0 => backlog growing)
#       }, ...
#     },
#     "alerts": [ {target, classification, fire, summary, metrics:{...}}, ... ]
#   }
import argparse
import base64
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

# Shared bounded-retry mechanics for IDEMPOTENT gh reads (registry #563 adoption item 4;
# sparq#3759 / #558 transient-red class). READS ONLY — the ledger CAS writers below keep their
# own deliberate conflict/fail-loud semantics and are NEVER routed through this wrapper.
_gh_retry_spec = importlib.util.spec_from_file_location(
    "registry_gh_retry", os.path.join(os.path.dirname(__file__), "gh_retry.py"))
if _gh_retry_spec is None or _gh_retry_spec.loader is None:
    raise RuntimeError("cannot load shared gh retry policy")
gh_retry = importlib.util.module_from_spec(_gh_retry_spec)
_gh_retry_spec.loader.exec_module(gh_retry)

# [#987] The `why_no_diff` vocabulary is DECLARED ONCE, in no_change_routing.py (registry #701), and
# IMPORTED here — never restated. The no-change census below emits one key per reason, so a copy of
# the tuple would silently publish a stale breakdown the moment a reason is appended (#958 shape).
_nc_spec = importlib.util.spec_from_file_location(
    "registry_no_change_routing_for_metrics",
    os.path.join(os.path.dirname(__file__), "no_change_routing.py"))
if _nc_spec is None or _nc_spec.loader is None:
    raise RuntimeError("cannot load the shared no_change routing vocabulary")
no_change_routing = importlib.util.module_from_spec(_nc_spec)
_nc_spec.loader.exec_module(no_change_routing)
NO_CHANGE_REASONS = no_change_routing.NO_CHANGE_REASONS

# Keep in sync with select-and-claim.py / groom.py / model-health.py LEDGER_REF (issue #28 data
# plane). Every write pins this ref; readers fail LOUD if the branch is missing.
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")
LEDGER_PATH = os.environ.get("REGISTRY_METRICS_PATH", "data/metrics-history.json")
PUBLISHED_PATH = "data/metrics.json"  # data-only ledger source for dashboard site/metrics.json
# [OPUS-5] This repository is PUBLIC and this document is served verbatim at
# jeswr.github.io/agent-account-registry/metrics.json, so the published snapshot is a CLOSED key
# set enforced at the write boundary rather than trusted from the caller. Widening it is how fleet
# internals reach a public page, and it is not hypothetical: build_snapshot carries the ring's
# internal `_ts` tick identity, which run() has to strip by hand on the way here. Adding a key
# below is a deliberate, reviewable act; adding one upstream is an accident.
PUBLIC_SNAPSHOT_KEYS = frozenset({"generated_at", "schema_version", "targets", "alerts"})
# The rolling ring: enough snapshots (at */15 cron => ~6h) to derive a rate from history and to
# evaluate a SUSTAINED (K-snapshot) backlog condition without unbounded growth.
MAX_SNAPSHOTS = int(os.environ.get("REGISTRY_METRICS_RING", "24"))
# Event windows deliberately read only one newest-first REST page. A burst larger than this is
# still useful as a lower bound, but MUST trigger the no-silent-caps warning below.
EVENT_LIST_LIMIT = 100

ALERT_LABEL = "throughput-alert"
MARKER_PREFIX = "throughput-alert"   # hidden HTML marker keying the idempotent upsert

# --- alert classifications (each alert row carries exactly one) ---
BACKLOG_GROWING = "backlog-growing"
REVIEW_LANE_STALLED = "review-lane-stalled"
READY_STARVED = "ready-starved"
WORKER_FAILING = "worker-failing"
WORKER_NO_CHANGE = "worker-no-change"

# --- per-target default thresholds; overridable in policy/repos.toml [repos.*].throughput ---
DEFAULT_THRESHOLDS = {
    "open_pr_alert_threshold": 20,   # backlog-growing needs prs_open above this
    "ready_alert_threshold": 40,     # ready-starved needs issues_ready above this
    "sustain_snapshots": 2,          # K: how many recent snapshots must agree (SUSTAINED, not spiky)
    "worker_success_floor": 0.5,     # worker-failing when success rate below this with >0 attempts
    "worker_min_samples": 3,         # worker-failing needs at least this many attempts (anti-noise)
    # [#987] worker-no-change fires when MORE than this share of the hour's concluded worker runs
    # left the tree untouched. 0.5 sits well under the ~75% #466 measured and well over the rate a
    # healthy fleet shows, and it shares worker_min_samples so one honest empty-handed run is noise.
    "worker_no_change_ceiling": 0.5,
    "recover_snapshots": 2,          # hysteresis: condition must be clear this many ticks to recover
}
# The thresholds that are RATIOS in [0, 1] rather than positive counts — validated as floats in
# _thresholds_of. Named as a set so adding a ratio threshold cannot fall through to the
# positive-integer arm (which would reject every legal value it can take).
RATIO_THRESHOLD_KEYS = frozenset({"worker_success_floor", "worker_no_change_ceiling"})
CURATOR_THROUGHPUT_KEYS = {"target_ready"}

# readiness engines per target (declared in policy; falls back by repo below)
READY_STATUS_ENGINE = "status-ready"   # sparq: the ready-issues.py fail-closed frontier
READY_FROM_AGENT = "from-agent-open"   # registry: its own open from:agent backlog


# =============================================================================================
# errors
# =============================================================================================
class MetricsError(RuntimeError):
    """A concise, credential-free operational error."""


class MetricsConflict(MetricsError):
    """A retryable contents-API compare-and-swap conflict."""


# =============================================================================================
# PURE metric computation (unit-tested; no I/O)
# =============================================================================================
def no_change_census(records, run_ids):
    """PURE per-target census of the NO-CHANGE gate (#987 / #466 AC3), from validated model-health
    rows. Returns the three `worker_no_change_*` count inputs compute_target_metrics consumes.

    `records` are model-health rows already validated + pruned by model-health's own reader, so a
    `no_change` row's `issue` is a bounded int and its `why_no_diff` (when present) is inside the
    CLOSED `NO_CHANGE_REASONS` vocabulary. Nothing else from a row is republished: the snapshot is
    served on a PUBLIC page, and these two are the only no-change fields whose grammar is closed.

    ATTRIBUTION. A health record carries no target repo, so it is charged to a target through the
    ONLY thing that links it to one: `run_id` is `<workflow run id>.<attempt>` (worker.yml's health
    step), and `run_ids` is the set of worker-run ids ALREADY attributed to this target by run-name
    and windowed by conclusion time — that same set, rather than a second timestamp filter. An
    UNATTRIBUTABLE row (empty/absent run_id, or one whose run is not this target's) is charged to
    NOBODY: guessing a target here would invent wasted runs for a repo that never had them.

    ONE RUN, ONE VOTE. The census FOLDS to the base run id, so a run is counted at most once however
    many of its attempts are on the ledger. The denominator counts RUN OBJECTS — the Actions list
    returns one per run id whatever attempt it is on — while the ledger deliberately RETAINS each
    separately EXECUTED attempt of a full re-run: `123.1` and `123.2` are two real outcomes there,
    not a replay (model-health `_record_identity`). Counting both against a denominator of one would
    publish a rate above 1 and could sustain `worker-no-change` off a single re-run; the fold is
    what puts numerator and denominator over one population and keeps `no_change <=
    worker_attempts_1h` true by construction. A run's REASON and ISSUE are taken from its LATEST
    no-change attempt — the outcome it finally had — with ledger order breaking a tie an unparsable
    attempt cannot rank; they are never summed across attempts, which would re-inflate the
    repeat-offender list with a loop no issue actually took.

    THE FOLD SPANS EVERY EXIT CLASS, and the `no_change` test is applied to its WINNER — not the
    other way round (review round 2 of PR #1584). worker.yml's health job records exactly ONE row
    per executed attempt, carrying THAT attempt's class, so `117.1 = no_change` then `117.2 =
    success` is one run whose final outcome produced a diff. Filtering to `no_change` BEFORE the
    fold discards attempt 2 and lets the superseded attempt 1 keep voting — the run is still
    published as wasted, and that phantom can hold `worker-no-change` firing over a re-run that
    actually fixed it. Selecting first and testing after also makes the reverse case honest:
    `success` then `no_change` counts, because the run's last word was no diff. A row with no
    usable exit class joins no fold at all rather than superseding a real outcome (the reader
    already refuses any class outside model-health's DECISION_CLASSES, so this only guards a
    hand-shaped row from silently CANCELLING a no-change vote).

    The reason breakdown always carries EVERY reason in the vocabulary, including the zeroes — a
    census that omits its empty rows reads as "not measured" exactly when an operator needs "0"
    (AGENTS pre-flight item 8). Repeat offenders are the issues with >= 2 no-change RUNS in the
    window, loudest first; the list is UNCAPPED on purpose (it is already bounded by the
    ledger's own retention ceiling, and a silent top-N would hide the worst loopers)."""
    by_reason = {reason: 0 for reason in NO_CHANGE_REASONS}
    per_issue = {}
    wanted = {rid for rid in (run_ids or ()) if isinstance(rid, str) and rid}
    latest = {}   # base run id -> (attempt ordering key, that attempt's record)
    for position, record in enumerate(records or ()):
        if not isinstance(record, dict):
            continue
        exit_class = record.get("exit_class")
        if not isinstance(exit_class, str) or not exit_class:
            continue
        run_id = record.get("run_id")
        if not isinstance(run_id, str):
            continue
        base, _, attempt = run_id.partition(".")
        if base not in wanted:
            continue
        # A higher attempt is a LATER execution of the same run. A missing/non-numeric attempt
        # ranks lowest so a well-formed row always wins the fold, and ledger position breaks the
        # remaining ties (the later-read row wins) rather than leaving the pick order-dependent.
        key = (int(attempt) if attempt.isdigit() else -1, position)
        if base not in latest or key > latest[base][0]:
            latest[base] = (key, record)
    # The no-change test lands on the fold's WINNER: only a run whose LATEST executed attempt was a
    # no_change is a run that left the tree unchanged.
    wasted = [record for _key, record in latest.values()
              if record.get("exit_class") == "no_change"]
    for record in wasted:
        # The absent -> `unspecified` fold is no_change_routing's, called on the single row so the
        # breakdown can never drift from the routing decision the same field drives (#701).
        for reason in no_change_routing.declared_reasons([record]):
            # Indexed, never `.get`-folded: declared_reasons only ever returns a member of
            # NO_CHANGE_REASONS, which is the same tuple that seeded this dict, so the key set of
            # this PUBLICLY-served document is closed by construction. A producer that broke that
            # contract must raise here rather than quietly mint a new key on a served page.
            by_reason[reason] += 1
        issue = record.get("issue")
        if isinstance(issue, int) and not isinstance(issue, bool):
            per_issue[issue] = per_issue.get(issue, 0) + 1
    repeats = sorted(((issue, n) for issue, n in per_issue.items() if n > 1),
                     key=lambda pair: (-pair[1], pair[0]))
    return {
        "worker_no_change_1h": len(wasted),
        "worker_no_change_by_reason_1h": by_reason,
        "worker_no_change_repeat_issues_1h": [{"issue": issue, "count": n} for issue, n in repeats],
    }


def compute_target_metrics(counts):
    """Build one target's metric dict from raw collector COUNTS.

    `counts` (all ints, from REST list snapshots, immutable-window searches, or readiness) supplies:
      issues_open, issues_ready, issues_closed_1h, issues_closed_24h,
      prs_open, prs_draft, prs_opened_1h, prs_closed_1h, prs_merged_1h, prs_merged_24h,
      review_changes_backlog, needs_user_parked,
      review_lane_success_1h  (int: # of SUCCEEDED review-fix runs in the last hour),
      review_lane_runs_1h      (int: # of review-fix runs attempted in the last hour),
      worker_success_1h, worker_attempts_1h  (ints: worker run outcomes in the last hour)
      worker_no_change_1h, worker_no_change_by_reason_1h, worker_no_change_repeat_issues_1h
                               (the no_change_census() block; ABSENT when the model-health ledger
                                gave no attributable signal — which publishes null, never 0)

    The instantaneous per-hour rates come straight from authoritative REST list windows; the REAL
    rate-OVER-TIME signal is the SUSTAINED (K-snapshot) condition that evaluate_alerts() reads off
    the ledger ring — so a single spiky hour never alarms. Derived:
    pr_open_rate, pr_close_rate (merged+closed), net_pr_flow, review_lane_health,
    worker_success_rate_1h, worker_no_change_rate_1h. Pure — no network, no clock beyond what the
    caller stamps."""
    g = lambda k: int(counts.get(k, 0) or 0)  # noqa: E731 — terse local getter
    prs_opened_1h = g("prs_opened_1h")
    # close-rate counts BOTH merges and plain closes (either drains the open-PR backlog).
    prs_closed_1h = g("prs_closed_1h")
    prs_merged_1h = g("prs_merged_1h")
    close_flow_1h = prs_closed_1h + prs_merged_1h

    pr_open_rate = float(prs_opened_1h)
    pr_close_rate = float(close_flow_1h)
    net_pr_flow = round(pr_open_rate - pr_close_rate, 4)

    # review-lane health. The review-fix lane acts on review:changes PRs — NOT on drafts (drafts
    # are author work-in-progress the lane never touches), so the stall signal is keyed off the
    # review:changes backlog ONLY. States:
    #   unknown  — the run signal is unavailable (fail-open: never claim `ok` without evidence).
    #   idle     — there IS a review:changes backlog but NO lane run CONCLUDED this hour: the lane
    #              simply hasn't run yet (a fresh changes-request between ticks), not a failure. It
    #              is NOT reported as stalled off a single tick; the sustain gate promotes a
    #              persistent idle-with-backlog to an alert.
    #   stalled  — a review:changes backlog exists AND lane runs CONCLUDED but NONE succeeded.
    #   ok       — no review:changes backlog, or a lane run succeeded this hour.
    # `prs_draft` is deliberately NOT part of the backlog: a repo with only drafts and no
    # changes-requested PR has no lane work to do and must read `ok`, not `stalled`.
    review_backlog = g("review_changes_backlog")
    concluded = g("review_lane_runs_1h")
    lane_success = g("review_lane_success_1h")
    if "review_lane_runs_1h" not in counts:
        review_lane_health = "unknown"
    elif review_backlog <= 0 or lane_success > 0:
        review_lane_health = "ok"
    elif concluded == 0:
        review_lane_health = "idle"      # backlog present but the lane hasn't concluded a run
    else:
        review_lane_health = "stalled"   # ran, none succeeded, backlog still waiting

    worker_attempts = g("worker_attempts_1h")
    worker_success_rate = (round(g("worker_success_1h") / worker_attempts, 4)
                           if worker_attempts > 0 else None)

    # [#987] The no-change gate. `worker_no_change_1h` ABSENT means the model-health ledger yielded
    # nothing attributable this tick, which publishes null across all four fields — an unreadable
    # ledger must never render as a healthy 0% wasted-run rate. Present-with-0 attempts also leaves
    # the RATE null: 0/0 is not 0.0, and a 0.0 there would read as "the fleet wasted nothing".
    has_no_change = "worker_no_change_1h" in counts
    worker_no_change = g("worker_no_change_1h") if has_no_change else None
    worker_no_change_rate = (round(worker_no_change / worker_attempts, 4)
                             if has_no_change and worker_attempts > 0 else None)

    return {
        "issues_open": g("issues_open"),
        "issues_ready": g("issues_ready"),
        "issues_closed_1h": g("issues_closed_1h"),
        "issues_closed_24h": g("issues_closed_24h"),
        "prs_open": g("prs_open"),
        "prs_draft": g("prs_draft"),
        "prs_opened_1h": prs_opened_1h,
        "prs_closed_1h": prs_closed_1h,
        "prs_merged_1h": prs_merged_1h,
        "prs_merged_24h": g("prs_merged_24h"),
        "review_changes_backlog": g("review_changes_backlog"),
        "needs_user_parked": g("needs_user_parked"),
        "review_lane_health": review_lane_health,
        # runs/attempts are carried through onto the ring row so the SUSTAINED alert predicates
        # (which read only the stored rows, not the raw counts) can apply the worker min-sample
        # floor and distinguish an idle lane from a stalled one across snapshots.
        "review_lane_runs_1h": concluded if "review_lane_runs_1h" in counts else None,
        "worker_attempts_1h": worker_attempts,
        "worker_success_rate_1h": worker_success_rate,
        "worker_no_change_1h": worker_no_change,
        "worker_no_change_rate_1h": worker_no_change_rate,
        "worker_no_change_by_reason_1h": (counts.get("worker_no_change_by_reason_1h")
                                          if has_no_change else None),
        "worker_no_change_repeat_issues_1h": (counts.get("worker_no_change_repeat_issues_1h")
                                              if has_no_change else None),
        "pr_open_rate": round(pr_open_rate, 4),
        "pr_close_rate": round(pr_close_rate, 4),
        "net_pr_flow": net_pr_flow,
    }


# =============================================================================================
# PURE alert evaluation (unit-tested; no I/O)
# =============================================================================================
def _recent_rows(history, target, k):
    """The last k snapshot rows (metric dicts) for one target across the ring, oldest->newest."""
    rows = []
    for snap in history[-k:]:
        row = (snap.get("targets") or {}).get(target)
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _sustained(history, target, k, predicate):
    """True iff there are at least k recent snapshot rows for `target` AND `predicate(row)` holds
    in EVERY one of the last k. A single spiky tick therefore never alarms; the condition must
    persist across K snapshots (the SUSTAINED contract the PR advertises for EVERY rule)."""
    rows = _recent_rows(history, target, k)
    return len(rows) >= k and all(predicate(row) for row in rows)


def _backlog_growing_pred(th):
    return lambda r: (r.get("prs_open", 0) > th["open_pr_alert_threshold"]
                      and r.get("net_pr_flow", 0) > 0)


def _review_stalled_pred(_th):
    # keyed off the review-fix lane's real work item (review:changes), drafts excluded. `stalled`
    # (not `idle`) already means a lane run CONCLUDED without success against a real backlog.
    return lambda r: r.get("review_lane_health") == "stalled"


def _ready_starved_pred(th):
    return lambda r: (r.get("issues_ready", 0) > th["ready_alert_threshold"]
                      and r.get("issues_closed_1h", 0) == 0)


def _worker_failing_pred(th):
    def pred(r):
        wsr = r.get("worker_success_rate_1h")
        # min-sample floor: a single failed run (attempts=1) is noise, not a failing lane.
        return (isinstance(wsr, (int, float))
                and r.get("worker_attempts_1h", 0) >= th["worker_min_samples"]
                and wsr < th["worker_success_floor"])
    return pred


def _worker_no_change_pred(th):
    def pred(r):
        rate = r.get("worker_no_change_rate_1h")
        # Same min-sample floor as worker-failing: with the ledger's per-run granularity a single
        # honest "nothing to do here" run is 100% and must not page. `None` (no ledger signal, or
        # no attempts) is NOT a firing condition — absent evidence never alarms.
        return (isinstance(rate, (int, float)) and not isinstance(rate, bool)
                and r.get("worker_attempts_1h", 0) >= th["worker_min_samples"]
                and rate > th["worker_no_change_ceiling"])
    return pred


def evaluate_alerts(current, history, thresholds_by_target):
    """Return a DEDUPED list of FIRING alert rows for the current snapshot, given the ring `history`
    (INCLUDING `current` as its last element) and per-target thresholds. Each row:
        {target, classification, fire, summary, metrics:{...tripping values...}}
    EVERY rule is SUSTAINED: its condition must hold in ALL of the last K snapshots, so a single
    spiky tick never alarms (K = sustain_snapshots). Pure — history + thresholds in, rows out.
    `fire=False` recoveries are derived by reconcile_alerts against the live tracker (with its own
    recover_snapshots hysteresis), not here."""
    alerts = []
    targets = (current.get("targets") or {})
    for target, m in targets.items():
        th = {**DEFAULT_THRESHOLDS, **(thresholds_by_target.get(target) or {})}
        k = int(th["sustain_snapshots"])

        # 1) backlog-growing: prs_open over threshold AND open-rate > close-rate, SUSTAINED over K.
        if _sustained(history, target, k, _backlog_growing_pred(th)):
            alerts.append(_alert(target, BACKLOG_GROWING,
                                 f"open PRs {m['prs_open']} > {th['open_pr_alert_threshold']} and "
                                 f"net PR flow +{m['net_pr_flow']}/hr (open {m['pr_open_rate']} > "
                                 f"close {m['pr_close_rate']}) sustained over {k} snapshots",
                                 {"prs_open": m["prs_open"], "net_pr_flow": m["net_pr_flow"],
                                  "pr_open_rate": m["pr_open_rate"],
                                  "pr_close_rate": m["pr_close_rate"]}))

        # 2) review-lane-stalled: review:changes backlog + lane runs concluded with 0 success,
        #    SUSTAINED over K (a single idle/stalled tick, or a transient, never alarms).
        if _sustained(history, target, k, _review_stalled_pred(th)):
            alerts.append(_alert(target, REVIEW_LANE_STALLED,
                                 f"review lane STALLED over {k} snapshots: review-fix runs "
                                 f"concluded with 0 successes while review:changes="
                                 f"{m['review_changes_backlog']} waits",
                                 {"review_changes_backlog": m["review_changes_backlog"],
                                  "review_lane_runs_1h": m.get("review_lane_runs_1h"),
                                  "prs_merged_1h": m["prs_merged_1h"]}))

        # 3) ready-starved: a large ready frontier not draining (0 issues closed), SUSTAINED over K
        #    — a normal quiet hour (issues close in bursts) no longer single-tick trips it.
        if _sustained(history, target, k, _ready_starved_pred(th)):
            alerts.append(_alert(target, READY_STARVED,
                                 f"ready frontier {m['issues_ready']} > "
                                 f"{th['ready_alert_threshold']} but 0 issues closed over {k} "
                                 f"snapshots — the drain has stalled",
                                 {"issues_ready": m["issues_ready"],
                                  "issues_closed_1h": m["issues_closed_1h"]}))

        # 4) worker-failing: success rate below floor with >= min_samples attempts, SUSTAINED over K
        #    — one failed run no longer trips it, and it must persist across K snapshots.
        if _sustained(history, target, k, _worker_failing_pred(th)):
            wsr = m.get("worker_success_rate_1h")
            alerts.append(_alert(target, WORKER_FAILING,
                                 f"worker success rate {wsr:.0%} < "
                                 f"{th['worker_success_floor']:.0%} floor over {k} snapshots "
                                 f"({m.get('worker_attempts_1h', 0)} attempts this hour)",
                                 {"worker_success_rate_1h": wsr,
                                  "worker_attempts_1h": m.get("worker_attempts_1h", 0)}))

        # 5) worker-no-change [#987]: the fleet is burning worker slots and account leases to
        #    produce no diff at all. Distinct from worker-failing — these runs SUCCEED as runs, so
        #    the success rate can read healthy while ~75% of the work lands nothing (#466). The
        #    breakdown rides along on the alert body: `already_done` means the issues are finished
        #    and want closing, `underspecified`/`blocked_on_decision` mean they want a human.
        if _sustained(history, target, k, _worker_no_change_pred(th)):
            ncr = m.get("worker_no_change_rate_1h")
            alerts.append(_alert(target, WORKER_NO_CHANGE,
                                 f"no-change rate {ncr:.0%} > "
                                 f"{th['worker_no_change_ceiling']:.0%} ceiling over {k} snapshots "
                                 f"({m.get('worker_no_change_1h')} of "
                                 f"{m.get('worker_attempts_1h', 0)} worker runs this hour left the "
                                 f"tree unchanged)",
                                 {"worker_no_change_rate_1h": ncr,
                                  "worker_no_change_1h": m.get("worker_no_change_1h"),
                                  "worker_attempts_1h": m.get("worker_attempts_1h", 0),
                                  "worker_no_change_by_reason_1h":
                                      m.get("worker_no_change_by_reason_1h"),
                                  "worker_no_change_repeat_issues_1h":
                                      m.get("worker_no_change_repeat_issues_1h")}))
    return alerts


def _alert(target, classification, summary, metrics):
    return {"target": target, "classification": classification, "fire": True,
            "summary": summary, "metrics": metrics}


# =============================================================================================
# policy + readiness resolution
# =============================================================================================
def load_targets(policy_path):
    """Return [(repo, readiness_kind, thresholds_dict), ...] for the ENABLED targets in the policy.
    readiness_kind is read from [repos.*].readiness.kind if present, else defaulted by repo:
    the registry drains its own from:agent backlog, every other target uses the status:ready
    engine (the shared ready-issues.py definition)."""
    import tomllib
    try:
        with open(policy_path, "rb") as handle:
            doc = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise MetricsError(f"cannot read policy file {policy_path!r}") from exc
    repos = doc.get("repos") if isinstance(doc, dict) else None
    if not isinstance(repos, dict) or not repos:
        raise MetricsError("policy file has no [repos.*] targets")
    out = []
    for repo, row in repos.items():
        if not isinstance(row, dict) or row.get("enabled") is not True:
            continue
        thr = _thresholds_of(repo, row)
        kind = _readiness_kind_of(repo, row)
        out.append((repo, kind, thr))
    if not out:
        raise MetricsError("policy file has no enabled targets")
    return out


def _thresholds_of(repo, row):
    """Per-target throughput thresholds from [repos.*].throughput, validated, over the defaults."""
    thr = dict(DEFAULT_THRESHOLDS)
    override = row.get("throughput")
    if override is None:
        return thr
    if not isinstance(override, dict):
        raise MetricsError(f"throughput thresholds for {repo!r} must be a table")
    for key, val in override.items():
        if key not in DEFAULT_THRESHOLDS and key not in CURATOR_THROUGHPUT_KEYS:
            raise MetricsError(f"unknown throughput key {key!r} for {repo!r}")
        if key == "target_ready":
            if not isinstance(val, int) or isinstance(val, bool) or not 1 <= val <= 100:
                raise MetricsError(f"{key} for {repo!r} must be an integer in [1, 100]")
            continue
        if key in RATIO_THRESHOLD_KEYS:
            if not isinstance(val, (int, float)) or isinstance(val, bool) or not (0.0 <= val <= 1.0):
                raise MetricsError(f"{key} for {repo!r} must be a float in [0, 1]")
        elif not isinstance(val, int) or isinstance(val, bool) or val <= 0:
            raise MetricsError(f"{key} for {repo!r} must be a positive integer")
        thr[key] = val
    return thr


def _readiness_kind_of(repo, row):
    if "readiness" not in row:
        # default by repo: the registry drains its own from:agent backlog; everyone else status:ready.
        return READY_FROM_AGENT if repo == "jeswr/agent-account-registry" else READY_STATUS_ENGINE
    r = row["readiness"]
    if not isinstance(r, dict):
        raise MetricsError(f"readiness for {repo!r} must be a table")
    # security_paths lives in this table for the arm-side trust-surface audit (policy line
    # "security_paths below feeds the audit"); metrics does not consume it but must not
    # reject the live policy that carries it.
    unknown = set(r) - {"kind", "security_paths"}
    if unknown:
        raise MetricsError(f"unknown readiness key {sorted(unknown)[0]!r} for {repo!r}")
    kind = r.get("kind")
    if not isinstance(kind, str) or not kind:
        raise MetricsError(f"readiness.kind for {repo!r} must be a non-empty string")
    if kind not in (READY_STATUS_ENGINE, READY_FROM_AGENT):
        raise MetricsError(f"unknown readiness.kind {kind!r} for {repo!r}")
    return kind


# =============================================================================================
# live collection (the only I/O path)
# =============================================================================================
def _gh_json(args, token, what):
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    # Every _gh_json call site is an idempotent READ (search counts, --paginate lists,
    # actions-run reads), so transient 5xx/secondary-403/connection blips get gh_retry's bounded
    # backoff (registry #563 item 4 — the 16:00-class 503 red) instead of redding the whole tick.
    # Mutations (_gh: issue create/edit/comment) and the ledger CAS writers stay fail-loud.
    proc = gh_retry.run_gh(args, env=env)
    if proc.returncode != 0:
        raise MetricsError(f"gh {what} failed (rc={proc.returncode})")
    try:
        return json.loads(proc.stdout or "null")
    except json.JSONDecodeError as exc:
        raise MetricsError(f"gh {what} returned malformed JSON") from exc


def _search_count(repo, qualifiers, token):
    """Count a lag-tolerant 24h date-window event via search (never live-hour/current state)."""
    q = f"repo:{repo} {qualifiers}"
    result = _gh_json(["api", "-X", "GET", "search/issues",
                       "-f", f"q={q}", "-f", "per_page=1"], token, f"search ({qualifiers})")
    if not isinstance(result, dict) or "total_count" not in result:
        raise MetricsError(f"search response for {qualifiers!r} is malformed")
    return int(result["total_count"])


def _iso_ago(seconds, now):
    return datetime.fromtimestamp(now - seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _list_open_rows(repo, resource, token):
    """Return every row from the authoritative paginated REST list for open issues or PRs.

    GitHub's search index is eventually consistent, so it is forbidden for live state/label
    counts. `--paginate --slurp` makes pagination explicit; malformed pages fail closed rather than
    becoming a plausible partial count."""
    if resource not in ("issues", "pulls"):
        raise MetricsError(f"unsupported current-state resource {resource!r}")
    pages = _gh_json(["api", "--paginate", "--slurp",
                      f"repos/{repo}/{resource}?state=open&per_page=100"], token,
                     f"open {resource} list")
    if not isinstance(pages, list):
        raise MetricsError(f"open {resource} listing is malformed")
    rows = []
    for page in pages:
        if not isinstance(page, list):
            raise MetricsError(f"open {resource} listing page is malformed")
        for row in page:
            if not isinstance(row, dict):
                raise MetricsError(f"open {resource} listing row is malformed")
            rows.append(row)
    return rows


def _list_event_rows(repo, resource, state, sort, token):
    """Return one bounded, newest-first REST page for a trailing event window.

    Unlike current-state lists, event lists MUST NOT paginate without a bound: a sufficiently busy
    repository could otherwise make a metrics tick chase an unbounded history. The caller checks
    whether all EVENT_LIST_LIMIT rows are still in-window and warns that the count is a floor."""
    allowed = {
        ("pulls", "closed", "updated"),
        ("pulls", "all", "created"),
        ("issues", "closed", "updated"),
    }
    if (resource, state, sort) not in allowed:
        raise MetricsError(
            f"unsupported event-list query {(resource, state, sort)!r}")
    rows = _gh_json(
        ["api", "-X", "GET",
         f"repos/{repo}/{resource}?state={state}&sort={sort}&direction=desc"
         f"&per_page={EVENT_LIST_LIMIT}&page=1"],
        token, f"{state} {resource} event list")
    if not isinstance(rows, list):
        raise MetricsError(f"{state} {resource} event listing is malformed")
    for row in rows:
        if not isinstance(row, dict):
            raise MetricsError(f"{state} {resource} event listing row is malformed")
    return rows


def _event_stamp(row, field, what, nullable=False):
    """Return one REST event timestamp, failing closed on a missing/malformed field."""
    if field not in row:
        raise MetricsError(f"{what} {field} is missing")
    stamp = row[field]
    if nullable and stamp is None:
        return None
    if not isinstance(stamp, str) or not stamp:
        raise MetricsError(f"{what} {field} is malformed")
    return stamp


def _warn_truncated_window(repo, what, rows, stamps, since_iso):
    """Apply the no-silent-caps rule when the bounded page is entirely inside the window."""
    if len(rows) >= EVENT_LIST_LIMIT and all(stamp >= since_iso for stamp in stamps):
        print(f"::warning::metrics: WARNING: {repo} {what} window truncated at {len(rows)} "
              "— count is a floor", file=sys.stderr)


def _list_event_counts_1h(repo, token, since_iso):
    """Real-time 1h issue/PR event counts from bounded REST LIST snapshots."""
    closed_pulls = _list_event_rows(repo, "pulls", "closed", "updated", token)
    pull_closed_stamps = []
    prs_merged, prs_closed = 0, 0
    for row in closed_pulls:
        closed_at = _event_stamp(row, "closed_at", "closed pull request")
        merged_at = _event_stamp(row, "merged_at", "closed pull request", nullable=True)
        pull_closed_stamps.append(closed_at)
        if merged_at is not None and merged_at >= since_iso:
            prs_merged += 1
        elif merged_at is None and closed_at >= since_iso:
            prs_closed += 1
    _warn_truncated_window(
        repo, "closed pull-request 1h", closed_pulls, pull_closed_stamps, since_iso)

    # GitHub's REST issues endpoint includes pull requests. They consume part of the explicit bound
    # but are excluded from the issue count; this preserves the published issue/PR split.
    closed_items = _list_event_rows(repo, "issues", "closed", "updated", token)
    item_closed_stamps = []
    issues_closed = 0
    for row in closed_items:
        closed_at = _event_stamp(row, "closed_at", "closed issue-list item")
        item_closed_stamps.append(closed_at)
        if "pull_request" not in row and closed_at >= since_iso:
            issues_closed += 1
    _warn_truncated_window(
        repo, "closed issue 1h", closed_items, item_closed_stamps, since_iso)

    opened_pulls = _list_event_rows(repo, "pulls", "all", "created", token)
    pull_created_stamps = [
        _event_stamp(row, "created_at", "pull request") for row in opened_pulls
    ]
    prs_opened = sum(stamp >= since_iso for stamp in pull_created_stamps)
    _warn_truncated_window(
        repo, "opened pull-request 1h", opened_pulls, pull_created_stamps, since_iso)
    return {
        "issues_closed_1h": issues_closed,
        "prs_opened_1h": prs_opened,
        "prs_closed_1h": prs_closed,
        "prs_merged_1h": prs_merged,
    }


def _warn_if_one_hour_exceeds_24h(repo, counts):
    """Trip loudly when real-time LIST sees events the lagging 24h SEARCH index does not yet see."""
    for one_hour, day in (
            ("issues_closed_1h", "issues_closed_24h"),
            ("prs_merged_1h", "prs_merged_24h")):
        if counts[one_hour] > counts[day]:
            print(f"::warning::metrics: WARNING: {repo} list-derived {one_hour}="
                  f"{counts[one_hour]} exceeds search-derived {day}={counts[day]} — "
                  "search index lag sanity tripwire fired", file=sys.stderr)


def _label_names(row, what):
    labels = row.get("labels")
    if not isinstance(labels, list):
        raise MetricsError(f"{what} labels are malformed")
    names = set()
    for label in labels:
        name = label.get("name") if isinstance(label, dict) else label
        if not isinstance(name, str):
            raise MetricsError(f"{what} label is malformed")
        names.add(name)
    return names


def _current_state(repo, token):
    """Authoritative current counts plus the issue rows used by the readiness engine."""
    issue_rows = _list_open_rows(repo, "issues", token)
    issues = [row for row in issue_rows if "pull_request" not in row]
    pulls = _list_open_rows(repo, "pulls", token)
    pull_labels = [(_label_names(row, "pull request"), row) for row in pulls]
    for _labels, row in pull_labels:
        if not isinstance(row.get("draft"), bool):
            raise MetricsError("open pull request draft state is malformed")
    return ({
        "issues_open": len(issues),
        "prs_open": len(pulls),
        "prs_draft": sum(1 for _labels, row in pull_labels if row["draft"]),
        "review_changes_backlog": sum(
            1 for labels, _row in pull_labels if "review:changes" in labels),
        "needs_user_parked": sum(
            1 for labels, _row in pull_labels if "needs:user" in labels),
    }, issues)


def _ready_count(repo, kind, token, open_issues=None):
    """Compute issues_ready with the target's REAL readiness definition (not a naive label count).

    The maintainer's ask is 'issues READY TO DRAIN' — the count of drainable ready work. For the
    status:ready target that is ready_candidates(): every issue that passes the FAIL-CLOSED label
    gate (open + status:ready + priority + role + no gate/busy + no open blocker). It is NOT
    compute_ready(), which serializes that set down to a one-per-package, conflict-free CONCURRENCY
    frontier (how many a worker fleet could claim at once without a package collision) — for sparq
    that collapses ~86 drainable issues to ~4, ~20x under the real backlog and below every alert
    threshold. We import ready_candidates() from the shared engine so the label-gate definition can
    never drift from the dispatcher's."""
    issues = open_issues if open_issues is not None else _current_state(repo, token)[1]
    if kind == READY_FROM_AGENT:
        return sum(1 for issue in issues if "from:agent" in _label_names(issue, "issue"))

    # Reuse the shared label gate over the SAME coherent REST issue snapshot. Reconstruct only its
    # derived open-blocker field (the shared _fetch() does this after its own list call).
    open_numbers = {row.get("number") for row in issues}
    prepared = []
    for row in issues:
        number = row.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise MetricsError("open issue number is malformed")
        blockers = re.findall(r"[Bb]locked-by:\s*#(\d+)", row.get("body") or "")
        prepared.append({"number": number, "state": row.get("state", "open"),
                         "labels": row.get("labels"),
                         "open_blockers": sum(1 for b in blockers if int(b) in open_numbers)})
    return len(_ready_issues_module().ready_candidates(prepared))


def _ready_issues_module():
    """Import the shared ready-issues.py engine (dashed filename => importlib, cached)."""
    cached = getattr(_ready_issues_module, "_mod", None)
    if cached is not None:
        return cached
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("ready_issues",
                                                  os.path.join(here, "ready-issues.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _ready_issues_module._mod = mod
    return mod


def collect_counts(repo, kind, token, now, orchestration=None, health_records=None):
    """Live raw counts from REST lists, lag-tolerant 24h search, and the readiness engine.

    `orchestration`, when given, is (orchestration_repo, orchestration_token): the repo that HOSTS
    this target's review-fix / worker workflows. sparq's review orchestration is driven cross-repo
    from the REGISTRY's own review-fix.yml/worker.yml, NOT from a sparq-hosted workflow — so the
    lane/worker health for a target must be read off the ORCHESTRATION repo's runs, filtered to
    that target, not off `repo`'s actions. When absent, lane/worker health is left unknown/null.

    `health_records`, when given, is the validated model-health window read ONCE per tick by the
    caller (it is a fleet-wide ledger, not a per-target read). None — an unreadable ledger, or a
    run that never read it — leaves every no-change field null rather than 0 (#987)."""
    h1, h24 = _iso_ago(3600, now), _iso_ago(86400, now)
    current, open_issues = _current_state(repo, token)
    c = {
        **current,
        "issues_ready": _ready_count(repo, kind, token, open_issues),
        **_list_event_counts_1h(repo, token, h1),
        # INTENTIONAL: the published 24h counters stay on SEARCH. Its minutes-scale indexing lag is
        # negligible against a full day, while the live 1h alert inputs above MUST use REST LIST.
        # Do not collapse these back into one search-based collector (issue #501).
        "issues_closed_24h": _search_count(repo, f"is:issue is:closed closed:>={h24}", token),
        "prs_merged_24h": _search_count(repo, f"is:pr is:merged merged:>={h24}", token),
    }
    _warn_if_one_hour_exceeds_24h(repo, c)
    if orchestration is not None:
        orch_repo, orch_token = orchestration
        # review-lane health: of the review-fix runs for THIS target that CONCLUDED in the last
        # hour, how many succeeded? (in-progress runs are neither an attempt-failure nor a success)
        total, ok = _review_lane_runs(orch_repo, repo, orch_token, now)
        if total is not None:
            c["review_lane_runs_1h"] = total
            c["review_lane_success_1h"] = ok
        # worker success this hour (best-effort; absent => worker_success_rate_1h stays null)
        wattempts, wok, wrun_ids = _worker_runs(orch_repo, repo, orch_token, now)
        if wattempts is not None:
            c["worker_attempts_1h"] = wattempts
            c["worker_success_1h"] = wok
            # [#987] The no-change census over THIS target's worker runs. Gated on the runs signal
            # too: without the run-id set there is no way to tell which ledger rows are this
            # target's, and a census computed over the wrong population is worse than none.
            if health_records is not None:
                c.update(no_change_census(health_records, wrun_ids))
    return c


# review-fix.yml / worker.yml both embed the TARGET owner/repo in their run-name (display_title), so
# an orchestration run can be attributed to the target it acted on. Keep in sync with those
# workflows' `run-name:`. (review-loop is a legacy alias still tolerated.)
REVIEW_LANE_WORKFLOWS = ("review-fix", "review-loop")
WORKER_WORKFLOWS = ("worker",)


def _run_matches(run, lane_names, target):
    """A run is attributed to (lane, target) iff its workflow path/name matches a lane name AND its
    display_title/name mentions the target repo. Both review-fix.yml and worker.yml put the target
    in the run-name (`review-fix <mode> owner/repo#pr`, `worker owner/repo claim=...`)."""
    wf = f"{run.get('path') or ''} {run.get('name') or ''}"
    if not any(name in wf for name in lane_names):
        return False
    title = f"{run.get('display_title') or ''} {run.get('name') or ''}"
    return target in title


def _run_in_window(run, since_iso):
    """A run counts for the trailing window if it COMPLETED (or, if still running, was UPDATED) at
    or after `since_iso`. Using completion time — not created_at — means a long run created 61 min
    ago that SUCCEEDED 5 min ago is still counted; a stale created-window would drop that success
    and read the lane as falsely stalled."""
    stamp = run.get("updated_at") if run.get("status") != "completed" else (
        run.get("updated_at") or run.get("created_at"))
    return isinstance(stamp, str) and stamp >= since_iso


def _orchestration_lane_runs(orch_repo, target, lane_names, token, now, window_s=3600,
                             fetch_lookback_s=6 * 3600):
    """(concluded, succeeded, run_ids) for `target`'s runs of `lane_names` on the ORCHESTRATION
    repo that CONCLUDED within the trailing window, or (None, None, set()) if the runs API is
    unavailable.

    `run_ids` is the id of every run counted into `concluded`, as strings — the ONLY key that links
    a model-health ledger row (which carries no repo) back to the target it acted on (#987). It is
    derived HERE, from the same filtered walk that produced the counts, so the census can never be
    computed over a different population than the denominator it divides by.

    Only runs whose conclusion is set (completed) count toward `concluded`; an in-progress run is
    neither an attempt nor a success — treating it as attempted-but-failed reads the lane as
    stalled while a fix is actively landing. `concluded == 0` therefore means IDLE (no lane work
    finished this hour), which the caller distinguishes from `succeeded == 0 with concluded > 0`
    (genuinely stalled). Paginated within the window so a busy hour (>100 runs) can't silently
    drop the one success that keeps the lane 'ok' (the API returns newest-first).

    The API `created>=` filter uses a WIDER lookback (`fetch_lookback_s`) than the completion
    window so a run CREATED before the window but that COMPLETED inside it is still returned by the
    API; the in-window decision itself is made on completion time (`_run_in_window`). Otherwise a
    long review-fix created 61 min ago and succeeded 5 min ago would be filtered out at the API and
    the lane read as falsely stalled."""
    since = _iso_ago(window_s, now)
    fetch_since = _iso_ago(max(window_s, fetch_lookback_s), now)
    runs = _paginate_runs(orch_repo, fetch_since, token, now)
    if runs is None:
        return (None, None, set())
    concluded, succeeded, run_ids = 0, 0, set()
    for r in runs:
        if not isinstance(r, dict) or not _run_matches(r, lane_names, target):
            continue
        if not _run_in_window(r, since):
            continue
        conclusion = r.get("conclusion")
        if conclusion is None:          # still in progress — neither attempt-failure nor success
            continue
        concluded += 1
        if conclusion == "success":
            succeeded += 1
        run_id = r.get("id")
        if isinstance(run_id, int) and not isinstance(run_id, bool):
            run_ids.add(str(run_id))
    return (concluded, succeeded, run_ids)


def _paginate_runs(repo, since_iso, token, now, page_cap=10):
    """All actions runs for `repo` created at/after `since_iso`, following pages until the window is
    exhausted (runs come back newest-first, so we stop once a page's oldest run predates the
    window). Returns None if the runs API is unavailable. `page_cap` bounds a runaway."""
    collected = []
    for page in range(1, page_cap + 1):
        try:
            result = _gh_json(["api", "-X", "GET", f"repos/{repo}/actions/runs",
                               "-f", f"created=>={since_iso}", "-f", "per_page=100",
                               "-f", f"page={page}"], token, "actions runs")
        except MetricsError:
            return None
        runs = result.get("workflow_runs") if isinstance(result, dict) else None
        if not isinstance(runs, list):
            return None
        collected.extend(runs)
        if len(runs) < 100:
            break   # last page
        # newest-first: if the oldest run on this full page still predates the window, we're done.
        oldest = runs[-1].get("created_at") if isinstance(runs[-1], dict) else None
        if isinstance(oldest, str) and oldest < since_iso:
            break
    return collected


def _review_lane_runs(orch_repo, target, token, now):
    # The review lane has no ledger census to join, so its run ids are dropped here rather than
    # threaded through a caller that would never read them.
    concluded, succeeded, _run_ids = _orchestration_lane_runs(
        orch_repo, target, REVIEW_LANE_WORKFLOWS, token, now)
    return (concluded, succeeded)


def _worker_runs(orch_repo, target, token, now):
    return _orchestration_lane_runs(orch_repo, target, WORKER_WORKFLOWS, token, now)


# =============================================================================================
# ledger time-series I/O (CAS over the contents API, pinned to LEDGER_REF) — model-health pattern
# =============================================================================================
def _load_gh_403():
    """Load scripts/gh_403.py (same checkout) — THE 403 taxonomy (registry #1208). By PATH, not
    `import gh_403`: `scripts/` is not a package and the CWD a job runs from is not fixed.

    The `metrics` job takes a FULL checkout, so this file is always beside us; a missing one is a
    real regression (someone made the job sparse) and must say so rather than degrade to the
    unclassified message this exists to replace."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gh_403.py")
    spec = importlib.util.spec_from_file_location("registry_gh_403_for_metrics", path)
    if spec is None or spec.loader is None:
        raise MetricsError(
            "cannot load scripts/gh_403.py — if this job was made sparse, add "
            "scripts/gh_403.py to its sparse-checkout list in metrics.yml")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gh_403 = _load_gh_403()

# GitHub's own error envelope is a diagnostic, never resource content, but it is still bounded and
# token-masked before it reaches a log: an unbounded echo of a response body is how a credential
# ends up in an Actions log by accident.
_ENVELOPE_LIMIT = 300
_TOKEN_SHAPE = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b")


def _failure_suffix(exc):
    """`: <class> — <masked envelope>` for a failed call, or "" when nothing is readable.

    WHY THIS EXISTS. Until now this client raised `GitHub API GET failed with HTTP 403` and
    stopped — no body, no headers. Measured 2026-07-28/29, metrics.yml failed 9 times in the
    window and every one of those failures was UNCLASSIFIABLE after the fact: a budget-exhausted
    403 and a permission 403 are the same string, and the two need opposite responses (#1208).
    Reading `x-ratelimit-remaining` off THIS response is also the only way to see the request
    budget that actually binds — `GET /rate_limit` reports a different route partition and reads
    healthy straight through an outage of this one (#796, re-measured #1303).

    Never raises: a diagnostic that can fail replaces one lost cause with another (groom #647)."""
    body = ""
    try:
        raw = exc.read()
        body = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw or "")
    except Exception:  # noqa: BLE001 — a diagnostic read must never mask the real failure
        body = ""
    headers = getattr(exc, "headers", None)
    parts = []
    if getattr(exc, "code", None) == 403:
        parts.append(gh_403.classify_403(headers, body))
        remaining = gh_403.int_header(headers, "x-ratelimit-remaining")
        limit = gh_403.int_header(headers, "x-ratelimit-limit")
        if remaining is not None:
            parts.append(f"x-ratelimit-remaining={remaining}"
                         + (f"/{limit}" if limit is not None else ""))
        reset = gh_403.int_header(headers, "x-ratelimit-reset")
        if reset is not None:
            parts.append("resets at " + datetime.fromtimestamp(
                reset, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    envelope = _TOKEN_SHAPE.sub("***", " ".join((body or "").split()))
    if len(envelope) > _ENVELOPE_LIMIT:
        envelope = envelope[:_ENVELOPE_LIMIT] + "…"
    if envelope:
        parts.append(envelope)
    return (": " + " — ".join(parts)) if parts else ""


class GitHubAPI:
    """Minimal contents API client (same shape as model-health.GitHubAPI). Local so the script has
    no cross-module import at CLI time; the token never enters a target-code job."""

    def __init__(self, token):
        from urllib.request import Request
        if not token:
            raise MetricsError("registry token is missing")
        self._token = token
        self._Request = Request

    def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
        from urllib.error import HTTPError, URLError
        from urllib.request import urlopen
        if not path.startswith("/") or "\n" in path or "\r" in path:
            raise MetricsError("unsafe GitHub API path")
        payload = json.dumps(body).encode() if body is not None else None
        request = self._Request(
            "https://api.github.com" + path, data=payload, method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "registry-metrics",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if payload is not None else {}),
            })
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as exc:
            if allow_404 and exc.code == 404:
                return None
            if retry_conflict and exc.code in {409, 422}:
                raise MetricsConflict("metrics ledger compare-and-swap conflict") from exc
            raise MetricsError(
                f"GitHub API {method} failed with HTTP {exc.code}"
                + _failure_suffix(exc)
            ) from exc
        except (URLError, TimeoutError) as exc:
            raise MetricsError("GitHub API request failed") from exc
        try:
            return json.loads(raw or b"null")
        except json.JSONDecodeError as exc:
            raise MetricsError("GitHub API returned malformed JSON") from exc


def ledger_read_path(registry_repo):
    return f"/repos/{registry_repo}/contents/{LEDGER_PATH}?ref={LEDGER_REF}"


def _model_health_module():
    """Load scripts/model-health.py (hyphenated name => importlib, the _ready_issues_module pattern,
    cached). LAZY on purpose: metrics.py is also read as TEXT by metrics-alert.py's sparse-checkout
    self-test, and the collector job that actually calls this takes the FULL checkout."""
    cached = getattr(_model_health_module, "_mod", None)
    if cached is not None:
        return cached
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("registry_model_health_for_metrics",
                                                  os.path.join(here, "model-health.py"))
    if spec is None or spec.loader is None:
        raise MetricsError("cannot load scripts/model-health.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _model_health_module._mod = mod
    return mod


def read_health_window(api, registry_repo, now):
    """The validated, pruned model-health window — the raw no-change signal (#987) — or None.

    Read through model-health's OWN reader/validator, never a private parse, so a poisoned row is
    refused here exactly as it is everywhere else. Returns None (never []) on any failure: None
    means NO EVIDENCE and publishes null across the no-change fields, while [] would publish a
    confident `0 wasted runs` off an unreadable ledger. Never raises — this is telemetry riding
    alongside the throughput collection, and a health-ledger blip must not take the whole snapshot
    (and with it every other alert) down."""
    def unreadable(exc):
        print(f"::warning::metrics: the model-health ledger is unreadable ({exc}) — the no-change "
              "telemetry is published as null this tick, NOT as zero")
        return None

    try:
        health = _model_health_module()
    except (MetricsError, OSError, ImportError, SyntaxError) as exc:
        return unreadable(exc)
    # HealthError is model-health's own RuntimeError; MetricsError is what THIS module's api client
    # raises on a transport/HTTP failure (read_ledger's `api` is ours, so both classes reach here).
    try:
        records, _sha = health.read_ledger(api, registry_repo)
        return health.prune(records, now)
    except (health.HealthError, MetricsError, ValueError, OSError) as exc:
        return unreadable(exc)


def read_history(api, registry_repo):
    """Return (snapshots, sha). A MISSING history FILE on a present ledger branch is the first-write
    path (empty ring, sha=None). A MISSING ledger BRANCH fails LOUD (issue #28) — never silently-
    empty, since a silently-empty ring would defeat the SUSTAINED (K-snapshot) alert logic."""
    result = api.request("GET", ledger_read_path(registry_repo), allow_404=True)
    if result is None:
        if api.request("GET", f"/repos/{registry_repo}/git/ref/heads/{LEDGER_REF}",
                       allow_404=True) is None:
            raise MetricsError(
                f"ledger branch '{LEDGER_REF}' is missing — create it from master "
                "(see data/README.md) before recording metrics")
        return [], None
    if not isinstance(result, dict):
        raise MetricsError("metrics ledger response is malformed")
    content, sha = result.get("content"), result.get("sha")
    if not isinstance(content, str) or not isinstance(sha, str) or not sha:
        raise MetricsError("metrics ledger metadata is malformed")
    try:
        document = json.loads(base64.b64decode("".join(content.split()), validate=True).decode())
    except (ValueError, UnicodeDecodeError) as exc:
        raise MetricsError("metrics ledger content is malformed") from exc
    return validate_history(document), sha


def validate_history(document):
    """A ring document is {"snapshots": [ {generated_at, _ts, targets:{...}}, ... ]}."""
    if not isinstance(document, dict):
        raise MetricsError("metrics ledger root must be an object")
    snaps = document.get("snapshots")
    if not isinstance(snaps, list):
        raise MetricsError("metrics ledger 'snapshots' must be a list")
    out = []
    for s in snaps:
        if isinstance(s, dict) and isinstance(s.get("targets"), dict):
            out.append(s)
    return out


def append_snapshot(api, registry_repo, snapshot, retries=6):
    """CAS-append one snapshot and prune to the last MAX_SNAPSHOTS (bounded ring). Retries on
    conflict exactly like the model-health writer. `_ts` identifies one collection tick: replaying
    that tick after a crash is a confirmed no-op, so it cannot satisfy a sustained-alert threshold
    twice. Returns the kept snapshot count, or the unchanged count on a replay."""
    tick = snapshot.get("_ts") if isinstance(snapshot, dict) else None
    if not isinstance(tick, int) or isinstance(tick, bool) or tick < 0:
        raise MetricsError("metrics snapshot has no valid _ts tick identity")
    for _ in range(retries):
        snaps, sha = read_history(api, registry_repo)
        if any(s.get("_ts") == tick for s in snaps):
            return len(snaps)
        snaps = (snaps + [snapshot])[-MAX_SNAPSHOTS:]
        encoded = base64.b64encode(
            (json.dumps({"snapshots": snaps}, indent=1) + "\n").encode()).decode()
        body = {"message": f"metrics snapshot {snapshot.get('generated_at')}",
                "content": encoded,
                "branch": LEDGER_REF}  # pin the data-plane branch, never the protected default
        if sha:
            body["sha"] = sha
        try:
            result = api.request(
                "PUT", f"/repos/{registry_repo}/contents/{LEDGER_PATH}", body, retry_conflict=True)
        except MetricsConflict:
            continue
        if isinstance(result, dict) and isinstance(result.get("content"), dict):
            return len(snaps)
    raise MetricsError("metrics ledger CAS conflicts did not settle")


def publish_snapshot(api, registry_repo, snapshot, retries=6):
    """CAS-write the current public snapshot to ledger:`data/metrics.json`.

    dashboard.yml is the sole Pages deploy owner; it copies this ledger data file to
    `site/metrics.json` in its generated artifact. This writer never invents a second deployment —
    it asks dashboard.yml to run (metrics.yml `dashboard-publish`), which is what keeps the
    published copy on THIS collector's cadence instead of the sum of both crons.

    Refuses, before the first byte is encoded, any snapshot whose key set is not exactly
    PUBLIC_SNAPSHOT_KEYS: the destination is a public page, so an unrecognised key is a leak and a
    missing one is a broken contract."""
    keys = set(snapshot) if isinstance(snapshot, dict) else set()
    if keys != set(PUBLIC_SNAPSHOT_KEYS):
        raise MetricsError(
            "published metrics key set drifted from the public contract — "
            f"unexpected: {sorted(keys - PUBLIC_SNAPSHOT_KEYS)}, "
            f"missing: {sorted(PUBLIC_SNAPSHOT_KEYS - keys)}")
    for _ in range(retries):
        path = f"/repos/{registry_repo}/contents/{PUBLISHED_PATH}?ref={LEDGER_REF}"
        current = api.request("GET", path, allow_404=True)
        sha = None
        if current is None:
            if api.request("GET", f"/repos/{registry_repo}/git/ref/heads/{LEDGER_REF}",
                           allow_404=True) is None:
                raise MetricsError(
                    f"ledger branch '{LEDGER_REF}' is missing — cannot publish metrics")
        elif (not isinstance(current, dict) or not isinstance(current.get("sha"), str)
              or not current["sha"]):
            raise MetricsError("published metrics metadata is malformed")
        else:
            sha = current["sha"]
        encoded = base64.b64encode((json.dumps(snapshot, indent=2) + "\n").encode()).decode()
        body = {"message": f"metrics dashboard snapshot {snapshot.get('generated_at')}",
                "content": encoded, "branch": LEDGER_REF}
        if sha:
            body["sha"] = sha
        try:
            result = api.request(
                "PUT", f"/repos/{registry_repo}/contents/{PUBLISHED_PATH}", body,
                retry_conflict=True)
        except MetricsConflict:
            continue
        if isinstance(result, dict) and isinstance(result.get("content"), dict):
            return
    raise MetricsError("published metrics CAS conflicts did not settle")


# =============================================================================================
# alert upsert (idempotent, DEDUPED, non-terminal) — the model-health _upsert_alert pattern
# =============================================================================================
def _gh(args, token, capture=False):
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    return subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)


def _marker(target, classification):
    return f"<!-- {MARKER_PREFIX}:{target}:{classification} -->"


def _alert_title(target, classification):
    return f"[throughput] {classification} — {target}"


def _render_alert_body(alert, maintainer):
    lines = [
        _marker(alert["target"], alert["classification"]),
        f"> 🤖 SPARQ agent — automated throughput alert (maintainer action: {maintainer})",
        "",
        f"**Target:** `{alert['target']}`  ",
        f"**Classification:** `{alert['classification']}`",
        "",
        alert["summary"],
        "",
        "Tripping metrics:",
        "```json",
        json.dumps(alert["metrics"], indent=2),
        "```",
        "",
        "This is a NON-terminal, auto-deduped signal (one rolling issue per target+class). It "
        "auto-closes when the condition clears. Tune thresholds in `policy/repos.toml` "
        "`[repos.*].throughput`.",
    ]
    return "\n".join(lines)


def _find_marker_issue(repo, token, marker, state):
    proc = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", state,
                "--json", "number,body", "--limit", "50"], token, capture=True)
    if proc.returncode != 0:
        raise MetricsError(f"gh issue list ({state}) failed")
    try:
        found = json.loads(proc.stdout or "[]")
    except ValueError as exc:
        raise MetricsError(f"gh issue list ({state}) returned malformed JSON") from exc
    if not isinstance(found, list):
        raise MetricsError(f"gh issue list ({state}) returned non-list JSON")
    if len(found) >= 50:
        raise MetricsError(f"gh issue list ({state}) may be truncated at 50 issues")
    return next((i["number"] for i in found if isinstance(i, dict)
                 and marker in (i.get("body") or "")), None)


def upsert_alert(action, repo, token, maintainer):
    """Idempotent one-issue-per-(target, classification) upsert keyed by the hidden body marker.
    `action["fire"]` True => raise/refresh; False => close a live marker issue on recovery. Every gh
    return code is checked; a flap REOPENS the closed marker issue (never a duplicate); the recovery
    comment posts only AFTER a CONFIRMED close (no next-tick spam). Mirrors model-health exactly."""
    title = _alert_title(action["target"], action["classification"])
    marker = _marker(action["target"], action["classification"])
    body = _render_alert_body(action, maintainer)
    _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
         "--description", "Autonomous throughput / backlog-vs-drain alert (maintainer action)"],
        token, capture=True)
    try:
        num = _find_marker_issue(repo, token, marker, "open")
        closed = (_find_marker_issue(repo, token, marker, "closed")
                  if action["fire"] and num is None else None)
    except MetricsError as exc:
        # An unreadable tracker is UNKNOWN, never empty. Creating on that ambiguity duplicates the
        # existing marker issue, so every issue mutation is skipped until the next tick.
        print(f"::error::metrics: alert lookup failed ({exc}); skipping issue mutation",
              file=sys.stderr)
        return False
    if action["fire"]:
        if num is not None:
            _gh(["issue", "edit", str(num), "-R", repo, "--body", body], token)
            print(f"::warning::metrics: refreshed {action['classification']} on {action['target']}")
            return True
        if closed is not None:
            if _gh(["issue", "reopen", str(closed), "-R", repo], token).returncode == 0:
                _gh(["issue", "edit", str(closed), "-R", repo, "--body", body], token)
                print(f"::warning::metrics: reopened {action['classification']} on "
                      f"{action['target']}")
            else:
                print(f"::warning::metrics: reopen of {action['classification']} FAILED "
                      "(retry next tick)")
            return True
        if _gh(["issue", "create", "-R", repo, "--title", title,
                "--label", ALERT_LABEL, "--body", body], token).returncode == 0:
            print(f"::warning::metrics: raised {action['classification']} on {action['target']}")
            return True
        else:
            print(f"::warning::metrics: raising {action['classification']} FAILED (retry next tick)")
    elif num is not None:
        if _gh(["issue", "close", str(num), "-R", repo], token).returncode == 0:
            _gh(["issue", "comment", str(num), "-R", repo, "--body",
                 "✅ Recovered — throughput condition cleared. Auto-closed."], token)
            print(f"metrics: recovered {action['classification']} on {action['target']} — closed")
        else:
            print(f"::warning::metrics: close of {action['classification']} FAILED "
                  "(retry next tick, no comment)")
    return False


ALERT_CLASSES = (BACKLOG_GROWING, REVIEW_LANE_STALLED, READY_STARVED, WORKER_FAILING,
                 WORKER_NO_CHANGE)

# The per-class predicate factory used both to FIRE (sustained over K) and to RECOVER (clear over
# recover_snapshots). Keeping one source of truth means the recovery test can never drift from the
# fire test — a class recovers exactly when its OWN fire predicate has been false long enough.
_CLASS_PRED = {
    BACKLOG_GROWING: _backlog_growing_pred,
    REVIEW_LANE_STALLED: _review_stalled_pred,
    READY_STARVED: _ready_starved_pred,
    WORKER_FAILING: _worker_failing_pred,
    WORKER_NO_CHANGE: _worker_no_change_pred,
}


def compute_recoveries(history, collected_targets, thresholds_by_target):
    """The set of (target, class) pairs eligible to AUTO-CLOSE this tick, with hysteresis.

    A pair recovers only when BOTH hold:
      * the target was actually COLLECTED this tick (in `collected_targets`) — a target SKIPPED
        because its read token failed to mint (a documented, expected transient) produces no rows,
        and must NEVER have its live alerts closed as 'recovered' on zero evidence (blocker); and
      * its fire predicate has been FALSE for the last `recover_snapshots` consecutive snapshots
        (hysteresis) — so a metric flapping across the rolling-1h boundary does not churn the same
        issue open->closed->open every tick.
    Pure: history + collected set + thresholds in, recovery key set out."""
    recoveries = set()
    for target in collected_targets:
        th = {**DEFAULT_THRESHOLDS, **(thresholds_by_target.get(target) or {})}
        n = int(th["recover_snapshots"])
        rows = _recent_rows(history, target, n)
        if len(rows) < n:
            continue   # not enough clear history to assert recovery yet — leave the issue open
        for cls in ALERT_CLASSES:
            pred = _CLASS_PRED[cls](th)
            if not any(pred(row) for row in rows):   # clear in EVERY one of the last n snapshots
                recoveries.add((target, cls))
    return recoveries


def reconcile_alerts(fired, repo, token, maintainer, recoveries):
    """Fire the current alerts and CLOSE any live marker issue whose (target, class) is in the
    explicit `recoveries` set (computed with hysteresis, only for COLLECTED targets). Deduped:
    exactly one issue per (target, class). A (target, class) that is neither firing nor a confirmed
    recovery is LEFT ALONE — never touched on a skipped target or mid-hysteresis."""
    fired_keys = {(a["target"], a["classification"]) for a in fired}
    for a in fired:
        upsert_alert(a, repo, token, maintainer)
    for target, cls in sorted(recoveries):
        if (target, cls) in fired_keys:
            continue   # firing this tick — not a recovery
        upsert_alert({"target": target, "classification": cls, "fire": False,
                      "summary": "", "metrics": {}}, repo, token, maintainer)


# =============================================================================================
# orchestration
# =============================================================================================
def _token_for(repo, token_map, default_token):
    """Pick the read token for `repo` from a {owner: token} map, else the single default token. A
    per-owner App token is least-privilege (issues/PRs/actions READ scoped to that owner's repos)."""
    owner = repo.split("/", 1)[0]
    return (token_map or {}).get(owner) or default_token


def build_snapshot(targets, token_map, default_token, now, orchestration=None,
                   health_records=None):
    """Collect live counts for every target and assemble the snapshot (no ledger write here). Each
    target is read with its owner's token so a cross-owner search is never attempted on the wrong
    token; a target whose token is missing is SKIPPED loudly (never silently zero) — a skipped
    target has NO row, which the recovery reconciler uses to avoid closing its alerts on no
    evidence. `orchestration` = (orch_repo, orch_token): the repo hosting the review-fix/worker
    workflows, read for per-target lane/worker health. `health_records` = the fleet-wide validated
    model-health window, read ONCE by the caller and censused per target (#987)."""
    generated_at = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = {"generated_at": generated_at, "_ts": int(now), "schema_version": 1, "targets": {}}
    for repo, kind, _thr in targets:
        tok = _token_for(repo, token_map, default_token)
        if not tok:
            print(f"::warning::metrics: no token for {repo} — skipping (not counted as zero)")
            continue
        counts = collect_counts(repo, kind, tok, now, orchestration=orchestration,
                                health_records=health_records)
        out["targets"][repo] = compute_target_metrics(counts)
    return out


def run(policy_path, token_map, registry_token, registry_repo, maintainer, do_alert, do_publish, now):
    """Build a snapshot, append the ring, evaluate/reconcile alerts, and optionally publish it.

    Reads use the per-owner `token_map` (falling back to `registry_token`); ledger writes and alert
    upserts use `registry_token` (scoped to the registry itself). Review-fix/worker lane health for
    every target comes from the registry orchestration runs, filtered by target run-name."""
    targets = load_targets(policy_path)
    thresholds_by_target = {repo: thr for repo, _kind, thr in targets}
    orchestration = (registry_repo, registry_token)
    api = GitHubAPI(registry_token)
    # ONE fleet-wide read of the model-health window per tick, censused per target below (#987).
    health_records = read_health_window(api, registry_repo, now)
    snapshot = build_snapshot(targets, token_map, registry_token, now, orchestration=orchestration,
                              health_records=health_records)

    read_history(api, registry_repo)  # fail LOUD before we compute if the ledger branch is missing
    append_snapshot(api, registry_repo, snapshot)
    history, _sha = read_history(api, registry_repo)  # re-read the pruned ring (includes current)

    alerts = evaluate_alerts(snapshot, history, thresholds_by_target)
    snapshot_out = {k: v for k, v in snapshot.items() if k != "_ts"}
    snapshot_out["alerts"] = alerts

    if do_alert:
        # Recoveries are computed ONLY for targets actually collected this tick (skipped targets
        # keep their live alerts), and only after the condition has been clear over recover_snapshots.
        collected = list(snapshot.get("targets") or {})
        recoveries = compute_recoveries(history, collected, thresholds_by_target)
        reconcile_alerts(alerts, registry_repo, registry_token, maintainer, recoveries)
    if do_publish:
        publish_snapshot(api, registry_repo, snapshot_out)
    return snapshot_out


def main():
    ap = argparse.ArgumentParser(description="throughput metrics collector + alerting")
    ap.add_argument("--policy-file", default="policy/repos.toml")
    ap.add_argument("--registry-repo", default=os.environ.get("REGISTRY_REPO",
                                                              "jeswr/agent-account-registry"))
    ap.add_argument("--maintainer", default=os.environ.get("MAINTAINER_HANDLE", "jeswr"))
    ap.add_argument("--alert", action="store_true",
                    help="evaluate + upsert/close the deduped throughput alert issues")
    ap.add_argument("--publish", action="store_true",
                    help=f"CAS-publish the current snapshot to ledger:{PUBLISHED_PATH}")
    ap.add_argument("--out", help="also write a local copy of the JSON snapshot to this path")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    registry_token = os.environ.get("REGISTRY_GH_TOKEN") or os.environ.get("GH_TOKEN")
    if not registry_token:
        print("::error::metrics: no REGISTRY_GH_TOKEN/GH_TOKEN in the environment", file=sys.stderr)
        return 2
    # Optional per-owner read tokens: TARGET_TOKENS='{"sparq-org":"<t>","jeswr":"<t>"}'. Absent =>
    # every read falls back to the registry token (which sees the public targets read-only anyway).
    token_map = {}
    raw = os.environ.get("TARGET_TOKENS")
    if raw:
        try:
            token_map = {k: v for k, v in json.loads(raw).items() if isinstance(v, str) and v}
        except (ValueError, AttributeError):
            print("::warning::metrics: TARGET_TOKENS is malformed — using the registry token for "
                  "all reads")
    snapshot = run(args.policy_file, token_map, registry_token, args.registry_repo,
                   args.maintainer, args.alert, args.publish, time.time())
    text = json.dumps(snapshot, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return 0


# =============================================================================================
# self-tests (gh stubbed): metric computation, rate derivation, each alert rule, dedupe
# =============================================================================================
def _test_403_diagnosis(chk):
    """[#1303] The failure message has to say WHICH 403 it met.

    Nine metrics failures on 2026-07-28/29 were unclassifiable after the fact because this client
    printed a bare status. The two 403s that matter need opposite responses — a budget 403 must
    NOT be retried (the bucket has nothing to spend and the reset is up to an hour away), a
    secondary one must be, after the wait it asks for — so a message that cannot tell them apart
    cannot be acted on.
    """
    import io
    from urllib.error import HTTPError

    def err(code, headers, body):
        return HTTPError("https://api.github.com/x", code, "err", headers,
                         io.BytesIO(body.encode()))

    # The MEASURED installation-budget shape: no Retry-After, remaining 0. Named the class the
    # taxonomy names, and carrying the number that proves it.
    budget = _failure_suffix(err(
        403, {"x-ratelimit-remaining": "0", "x-ratelimit-limit": "5000",
              "x-ratelimit-reset": "1785182238"},
        '{"message":"API rate limit exceeded for installation."}'))
    chk("403 diagnosis: an installation-budget 403 is named 'budget' and carries the count",
        ("budget" in budget, "x-ratelimit-remaining=0/5000" in budget,
         "API rate limit exceeded for installation." in budget), (True, True, True))
    chk("403 diagnosis: ...and the reset stamp, which is the only thing that says WHEN to retry",
        "resets at 2026-07-27T19:57:18Z" in budget, True)

    secondary = _failure_suffix(err(
        403, {"Retry-After": "30"},
        '{"message":"You have exceeded a secondary rate limit."}'))
    chk("403 diagnosis: a secondary 403 is NOT called budget (opposite response)",
        ("secondary" in secondary, "budget" in secondary), (True, False))

    permission = _failure_suffix(err(
        403, {"x-ratelimit-remaining": "4931"},
        '{"message":"Resource not accessible by integration"}'))
    chk("403 diagnosis: a permission 403 is the residual class, never inferred from absence",
        "permission" in permission, True)

    # NON-VACUITY. All three must differ, or the classifier is decorative.
    chk("403 diagnosis: the three classes really are distinguishable from each other",
        len({budget.split("—")[0], secondary.split("—")[0], permission.split("—")[0]}), 3)

    # A non-403 gets the envelope but no class: this file must not invent a taxonomy for 500s.
    server = _failure_suffix(err(500, {}, '{"message":"Server Error"}'))
    chk("403 diagnosis: a 500 carries its envelope and NO 403 class",
        ("Server Error" in server,
         any(c in server for c in ("budget", "secondary", "permission"))), (True, False))

    # CREDENTIAL MASKING + BOUND. The envelope is echoed into an Actions log, so a token-shaped
    # string in it must never survive, and a huge body must not flood the log.
    leak = _failure_suffix(err(403, {}, '{"message":"bad ghp_' + "A" * 40 + '"}'))
    chk("403 diagnosis: a token-shaped string in the envelope is masked",
        ("ghp_" + "A" * 40 not in leak, "***" in leak), (True, True))
    chk("403 diagnosis: the envelope is bounded",
        len(_failure_suffix(err(403, {}, "x" * 5000))) < _ENVELOPE_LIMIT + 200, True)

    # A diagnostic that raises would replace one lost cause with another (groom #647).
    class _Unreadable(HTTPError):
        def read(self, *_a, **_k):
            raise OSError("stream already consumed")

    chk("403 diagnosis: an unreadable body degrades, never raises",
        isinstance(_failure_suffix(
            _Unreadable("https://api.github.com/x", 403,
                        "err", {"x-ratelimit-remaining": "0"}, None)), str), True)


def _self_test():
    ok = True

    def chk(name, got, want, diag=None):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")
        # #616 lesson (the halted dispatch run): a harness that discards the output of a body it
        # EXECUTED makes the next failure unreadable — the real cause never reaches the log and the
        # failure gets misattributed. Printed only on failure, so a green run stays quiet.
        if not good and diag:
            print("       executed-body diagnostics:")
            for line in str(diag).splitlines():
                print(f"       | {line}")

    _test_403_diagnosis(chk)
    _test_metric_computation(chk)
    _test_rate_derivation(chk)
    _test_alert_rules(chk)
    _test_alert_mutation_nonvacuous(chk)
    _test_no_change_census(chk)
    _test_no_change_wiring(chk)
    _test_list_api_contract(chk)
    _test_event_list_contract(chk)
    _test_collection_contract(chk)
    _test_run_windowing(chk)
    _test_run_name_seam(chk)
    _test_review_lane_states(chk)
    _test_recovery_hysteresis_and_skip(chk)
    _test_ledger_cas(chk)
    _test_publish_cas_and_wiring(chk)
    _test_upsert_dedupe(chk)
    _test_policy_and_readiness(chk)
    print("metrics self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


# the LIVE sparq snapshot the maintainer handed us (2026-07-18T09:10Z) — a real fixture.
SPARQ_LIVE = {
    "issues_open": 1048, "issues_ready": 86, "issues_closed_1h": 0, "issues_closed_24h": 31,
    "prs_open": 52, "prs_draft": 34, "prs_opened_1h": 5, "prs_closed_1h": 0,
    "prs_merged_1h": 0, "prs_merged_24h": 51,
    "review_changes_backlog": 10, "needs_user_parked": 23,
    "review_lane_runs_1h": 3, "review_lane_success_1h": 0,   # lane ran 3x, none succeeded => stalled
    "worker_attempts_1h": 4, "worker_success_1h": 3,
}
REGISTRY_LIVE = {
    "issues_open": 45, "issues_ready": 19, "issues_closed_1h": 1, "issues_closed_24h": 4,
    "prs_open": 7, "prs_draft": 3, "prs_opened_1h": 1, "prs_closed_1h": 0,
    "prs_merged_1h": 1, "prs_merged_24h": 16,
    "review_changes_backlog": 0, "needs_user_parked": 0,
    "review_lane_runs_1h": 1, "review_lane_success_1h": 1,
    "worker_attempts_1h": 2, "worker_success_1h": 2,
}


def _test_metric_computation(chk):
    m = compute_target_metrics(SPARQ_LIVE)
    chk("sparq issues_open pass-through", m["issues_open"], 1048)
    chk("sparq issues_ready pass-through", m["issues_ready"], 86)
    chk("sparq pr_open_rate = opened_1h", m["pr_open_rate"], 5.0)
    chk("sparq pr_close_rate = merged+closed_1h", m["pr_close_rate"], 0.0)
    chk("sparq net_pr_flow +5/hr (backlog growing)", m["net_pr_flow"], 5.0)
    chk("sparq review lane STALLED (backlog + 0 success)", m["review_lane_health"], "stalled")
    chk("sparq worker_success_rate 3/4", m["worker_success_rate_1h"], 0.75)
    # registry: a healthy lane (1 success) is ok, close-rate (1 merge) matches open-rate.
    r = compute_target_metrics(REGISTRY_LIVE)
    chk("registry review lane ok", r["review_lane_health"], "ok")
    chk("registry net_pr_flow 0 (balanced)", r["net_pr_flow"], 0.0)
    # health is 'unknown' (not falsely 'ok') when the run signal is absent — fail-open.
    no_runs = {k: v for k, v in SPARQ_LIVE.items()
               if k not in ("review_lane_runs_1h", "review_lane_success_1h")}
    chk("review lane unknown without run signal",
        compute_target_metrics(no_runs)["review_lane_health"], "unknown")
    # worker_success_rate is None (not 0) when no workers ran this hour.
    no_workers = {k: v for k, v in REGISTRY_LIVE.items()
                  if k not in ("worker_attempts_1h", "worker_success_1h")}
    chk("worker rate null when no runs",
        compute_target_metrics(no_workers)["worker_success_rate_1h"], None)


# [#987] Health rows are built through model-health's OWN writer, never hand-shaped: the census
# reads field names (`exit_class`/`run_id`/`issue`/`why_no_diff`) that make_record decides, and a
# hand-written fixture would stay green through a rename on the writer side. make_record also
# fail-closed VALIDATES what it returns, so every fixture below is a row the live reader accepts.
def _health_row(run_id, issue=None, why=None, exit_class="no_change"):
    return _model_health_module().make_record(
        "anthropic", "a1b2c3d4e5f60718", "opus5", exit_class, run_id, 1_700_000_000,
        issue=issue, why_no_diff=why)


def _test_no_change_census(chk):
    """[#987 / #466 AC3] Per-issue telemetry for the no-change gate.

    #466 measured ~75% of worker runs producing no diff at all, and none of it was visible: a
    no_change is a run that SUCCEEDS as a run, so `worker_success_rate_1h` reads healthy straight
    through it. These assertions pin (a) which ledger rows are charged to a target, (b) that a
    breakdown separating `already_done` (close the issue) from `underspecified` (get a human) is
    published, (c) that no-signal publishes NULL rather than a reassuring zero, (d) that moving the
    ceiling flips the alert, and (e) that a re-run's RETAINED attempts fold to one run, so the
    numerator can never outgrow the run-object denominator it is divided by.
    """
    import contextlib
    import io
    global _model_health_module

    # Six worker runs for THIS target. 111/112/113 are three attempts at ONE issue — the exact
    # #701 looper shape — 114/116 are one repeat pair, 115 succeeded with a real diff.
    attributed = {"111", "112", "113", "114", "115", "116"}
    records = [
        _health_row("111.1", issue=3241, why="underspecified"),
        _health_row("112.1", issue=3241),                        # no declaration => unspecified
        _health_row("113.2", issue=3241, why="already_done"),    # ATTEMPT suffix must not defeat it
        _health_row("114.1", issue=2575, why="already_done"),
        _health_row("116.1", issue=2575, why="other"),
        _health_row("115.1", exit_class="success"),              # a real diff — never a no-change
        _health_row("999.1", issue=42, why="too_large"),         # ANOTHER target's worker run
        _health_row("", issue=43, why="too_large"),              # unattributable: no run id at all
    ]
    census = no_change_census(records, attributed)
    chk("census counts only the no_change rows of THIS target's worker runs",
        census["worker_no_change_1h"], 5)
    # The breakdown is written out LITERALLY rather than derived from NO_CHANGE_REASONS: comparing
    # the emitted keys against the constant the emitter reads is a tautology that cannot fail
    # (AGENTS pre-flight 2b). Appending a reason to the vocabulary must land here too — this dict IS
    # the published public schema.
    chk("census breaks the reasons out, with a ZERO row for every unused reason",
        census["worker_no_change_by_reason_1h"],
        {"unspecified": 1, "underspecified": 1, "blocked_on_decision": 0, "too_large": 0,
         "already_done": 2, "other": 1})
    chk("...so `already_done` (close the issue) is separable from `underspecified` (needs a human)",
        (census["worker_no_change_by_reason_1h"]["already_done"],
         census["worker_no_change_by_reason_1h"]["underspecified"]), (2, 1))
    chk("census names the repeat offenders, loudest first",
        census["worker_no_change_repeat_issues_1h"],
        [{"issue": 3241, "count": 3}, {"issue": 2575, "count": 2}])
    # DIRECTION 2 of the attribution guard: drop the run-id filter and the other target's row plus
    # the unattributable one are charged here — 5 becomes 7 and issue 42 appears from nowhere.
    wide = no_change_census(records, attributed | {"999", ""})
    chk("an unattributable row is charged to NOBODY (it is not simply the other-target filter)",
        (wide["worker_no_change_1h"],
         wide["worker_no_change_by_reason_1h"]["too_large"]), (6, 1))
    # THE RE-RUN FOLD. A full re-run re-EXECUTES the producing job under the SAME GITHUB_RUN_ID with
    # a fresh attempt, and the ledger RETAINS both outcomes (neither is a replay — model-health
    # `_record_identity`). The Actions list, though, hands _orchestration_lane_runs ONE run object
    # for run 117, so a per-ROW numerator charges 2 against a denominator of 1: a rate above 1 off a
    # single re-run, which can hold `worker-no-change` firing on its own.
    rerun = no_change_census([_health_row("117.1", issue=808, why="underspecified"),
                              _health_row("117.2", issue=808, why="already_done")], {"117"})
    chk("two RETAINED attempts of ONE run id are one no-change run, not two",
        rerun["worker_no_change_1h"], 1)
    chk("...the reason is the LATEST attempt's, and the superseded attempt casts no second vote",
        rerun["worker_no_change_by_reason_1h"],
        {"unspecified": 0, "underspecified": 0, "blocked_on_decision": 0, "too_large": 0,
         "already_done": 1, "other": 0})
    chk("...and a re-run issue is NOT a repeat offender — that loop never happened",
        rerun["worker_no_change_repeat_issues_1h"], [])
    # Hand-shaped ON PURPOSE (the one exception to the make_record rule above): a non-string run_id
    # is outside make_record's grammar, so only a raw dict can reach the guard that keeps a poisoned
    # row from crashing the census — telemetry riding alongside every other alert must not take the
    # tick down over one row it cannot attribute.
    chk("a row whose run_id is not a string is SKIPPED, not crashed on",
        no_change_census([{"exit_class": "no_change", "run_id": 117, "issue": 808},
                          _health_row("117.1", issue=808, why="other")],
                         {"117"})["worker_no_change_1h"], 1)
    chk("the latest attempt wins on ATTEMPT NUMBER, not on ledger position",
        no_change_census([_health_row("117.2", issue=808, why="already_done"),
                          _health_row("117.1", issue=808, why="underspecified")],
                         {"117"})["worker_no_change_by_reason_1h"]["already_done"], 1)
    # THE TRANSITION, BOTH DIRECTIONS (review round 2 of #1584). A re-run's attempts do not all
    # share one exit class, and the fold must span EVERY class so the LATEST outcome — not the
    # latest no_change — decides. Filtering to `no_change` before the fold keeps a superseded
    # attempt 1 voting while the success that fixed it is dropped: the run reads as wasted forever
    # and can hold `worker-no-change` firing on its own. Both fixtures put the LOW attempt LAST in
    # ledger order, so neither can pass by reading the ledger's final row.
    fixed = no_change_census([_health_row("118.2", exit_class="success"),
                              _health_row("118.1", issue=808, why="underspecified")], {"118"})
    chk("a SUCCESSFUL re-run supersedes the earlier no-change attempt — that run is not wasted",
        fixed["worker_no_change_1h"], 0)
    chk("...so it casts no reason vote and names no repeat offender either",
        (fixed["worker_no_change_by_reason_1h"]["underspecified"],
         fixed["worker_no_change_repeat_issues_1h"]), (0, []))
    # DIRECTION 2: the reverse transition must still COUNT, so the fix is not just "drop any run
    # that ever succeeded" — a re-run that ends with no diff is exactly the waste this measures.
    regressed = no_change_census([_health_row("119.2", issue=808, why="already_done"),
                                  _health_row("119.1", exit_class="success")], {"119"})
    chk("...but a run whose LAST attempt produced no diff still counts, earlier success or not",
        (regressed["worker_no_change_1h"],
         regressed["worker_no_change_by_reason_1h"]["already_done"]), (1, 1))
    # Hand-shaped for the same reason as the non-string run_id above: a row with NO usable exit
    # class is outside make_record's grammar (and the reader refuses one), so only a raw dict can
    # reach the entry guards. Now that the fold spans every class, an unusable row that skipped
    # them would win run 120 on its higher attempt and CANCEL a real no-change vote — the silent
    # direction, where the gate under-counts waste. Neither guard has any other fixture.
    chk("a row with no usable exit class (or no dict at all) supersedes NOTHING",
        no_change_census(["not a record at all",
                          {"run_id": "120.2", "issue": 808},
                          {"exit_class": "", "run_id": "120.3", "issue": 808},
                          _health_row("120.1", issue=808, why="other")],
                         {"120"})["worker_no_change_1h"], 1)
    rerun_rate = compute_target_metrics({**SPARQ_LIVE, "worker_attempts_1h": 1,
                                         "worker_success_1h": 1, **rerun})
    chk("...so the rate holds the documented no_change <= attempts invariant: 1.0, never 2.0",
        rerun_rate["worker_no_change_rate_1h"], 1.0)
    # A tie on count is broken by issue number ASCENDING (a stable, reviewable order).
    tie = no_change_census([_health_row("111.1", issue=9), _health_row("112.1", issue=9),
                            _health_row("113.1", issue=4), _health_row("114.1", issue=4),
                            _health_row("115.1", issue=8)], attributed)
    chk("repeat offenders tie-break on issue number, and a ONE-row issue is not a repeat",
        tie["worker_no_change_repeat_issues_1h"],
        [{"issue": 4, "count": 2}, {"issue": 9, "count": 2}])
    chk("an EMPTY window still censuses — a zero row, never a missing one",
        no_change_census([], attributed),
        {"worker_no_change_1h": 0,
         "worker_no_change_by_reason_1h": {"unspecified": 0, "underspecified": 0,
                                           "blocked_on_decision": 0, "too_large": 0,
                                           "already_done": 0, "other": 0},
         "worker_no_change_repeat_issues_1h": []})

    # ---- the RATE, and the null-vs-zero boundary the acceptance criteria name explicitly.
    m = compute_target_metrics({**SPARQ_LIVE, "worker_attempts_1h": 6, "worker_success_1h": 6,
                                **census})
    chk("no-change rate is the census over the SAME hour's concluded worker runs",
        m["worker_no_change_rate_1h"], round(5 / 6, 4))
    chk("...and the raw count rides along for the alert body", m["worker_no_change_1h"], 5)
    chk("the reason breakdown reaches the published snapshot row",
        m["worker_no_change_by_reason_1h"]["already_done"], 2)
    # Sliced, not indexed: a mutant that empties this list must RED this row, not raise an
    # IndexError that aborts the suite and hides every check below it (AGENTS pre-flight 4).
    chk("the repeat-offender list reaches the published snapshot row",
        m["worker_no_change_repeat_issues_1h"][:1], [{"issue": 3241, "count": 3}])
    zero_attempts = compute_target_metrics({**SPARQ_LIVE, "worker_attempts_1h": 0,
                                            "worker_success_1h": 0,
                                            **no_change_census([], attributed)})
    chk("ZERO attempts leaves the rate NULL, not 0.0 (0/0 is not 'nothing was wasted')",
        zero_attempts["worker_no_change_rate_1h"], None)
    chk("...while the COUNT is a real 0 — the census ran and found nothing",
        zero_attempts["worker_no_change_1h"], 0)
    real_zero = compute_target_metrics({**SPARQ_LIVE, "worker_attempts_1h": 4,
                                        "worker_success_1h": 4,
                                        **no_change_census([], attributed)})
    chk("4 attempts and no no-change rows IS 0.0 — distinguishable from 'not measured'",
        real_zero["worker_no_change_rate_1h"], 0.0)
    absent = compute_target_metrics(SPARQ_LIVE)   # no census at all: an unreadable health ledger
    chk("NO ledger signal publishes null across all four fields, never a healthy-looking zero",
        [absent[k] for k in ("worker_no_change_1h", "worker_no_change_rate_1h",
                             "worker_no_change_by_reason_1h",
                             "worker_no_change_repeat_issues_1h")],
        [None, None, None, None])

    # ---- the ALERT. The tripping fixture is the #466 shape: 3 of 4 runs wasted.
    firing = compute_target_metrics({**REGISTRY_LIVE, "worker_attempts_1h": 4,
                                     "worker_success_1h": 4,
                                     "worker_no_change_1h": 3,
                                     "worker_no_change_by_reason_1h": {"already_done": 3},
                                     "worker_no_change_repeat_issues_1h": []})
    chk("the tripping fixture's rate is the 0.75 #466 measured",
        firing["worker_no_change_rate_1h"], 0.75)
    chk("...and its SUCCESS rate reads a perfect 1.0 — which is why worker-failing cannot see it",
        firing["worker_success_rate_1h"], 1.0)
    hist = [_snap(1000, {"o/r": firing}), _snap(2000, {"o/r": firing})]

    def fired(thresholds, history=None):
        history = history or hist
        return {a["classification"]
                for a in evaluate_alerts(history[-1], history, {"o/r": thresholds})}

    # THRESHOLD MUTATION (the acceptance criterion): the literal ceilings below are written out, not
    # read from DEFAULT_THRESHOLDS, so a mutant that moves the shipped default cannot move the
    # expected value with it (AGENTS pre-flight 2c).
    chk("worker-no-change FIRES at a 0.5 ceiling", WORKER_NO_CHANGE in fired(
        {**DEFAULT_THRESHOLDS, "worker_no_change_ceiling": 0.5}), True)
    chk("...and a 0.9 ceiling silences exactly that alert (the threshold is load-bearing)",
        WORKER_NO_CHANGE in fired({**DEFAULT_THRESHOLDS, "worker_no_change_ceiling": 0.9}), False)
    chk("a rate EXACTLY at the ceiling does not fire (strictly above, like every other rule)",
        WORKER_NO_CHANGE in fired({**DEFAULT_THRESHOLDS, "worker_no_change_ceiling": 0.75}), False)
    chk("the shipped default ceiling fires on the #466 shape",
        WORKER_NO_CHANGE in fired(DEFAULT_THRESHOLDS), True)
    # the min-sample floor, mutated the same way: 4 attempts is above 3 and below 5.
    chk("min_samples 5 silences it — one or two empty-handed runs are not a failing gate",
        WORKER_NO_CHANGE in fired({**DEFAULT_THRESHOLDS, "worker_min_samples": 5}), False)
    chk("worker-FAILING does NOT fire on this shape (the classes are genuinely distinct)",
        WORKER_FAILING in fired(DEFAULT_THRESHOLDS), False)
    # SUSTAINED, like every other rule: one tick never alarms.
    chk("a single snapshot never alarms (K=2 sustain)",
        WORKER_NO_CHANGE in fired(DEFAULT_THRESHOLDS, [_snap(2000, {"o/r": firing})]), False)
    # absent evidence never alarms, in either of its two shapes.
    null_rate = compute_target_metrics({**REGISTRY_LIVE, "worker_attempts_1h": 4,
                                        "worker_success_1h": 0})
    null_hist = [_snap(1000, {"o/r": null_rate}), _snap(2000, {"o/r": null_rate})]
    chk("a NULL no-change rate never alarms (no ledger signal is not a wasted-run rate of 100%)",
        WORKER_NO_CHANGE in fired(DEFAULT_THRESHOLDS, null_hist), False)
    chk("...though that same fixture DOES trip worker-failing, so the history itself is live",
        WORKER_FAILING in fired(DEFAULT_THRESHOLDS, null_hist), True)
    # the class is registered for RECOVERY as well as firing — an alert with no auto-close is a
    # conveyor onto the maintainer's desk (#703).
    healthy = compute_target_metrics({**REGISTRY_LIVE, "worker_attempts_1h": 4,
                                      "worker_success_1h": 4,
                                      **no_change_census([], attributed)})
    rec = compute_recoveries([_snap(1000, {"o/r": healthy}), _snap(2000, {"o/r": healthy})],
                             ["o/r"], {"o/r": DEFAULT_THRESHOLDS})
    chk("worker-no-change auto-closes once the rate clears", ("o/r", WORKER_NO_CHANGE) in rec, True)
    chk("...and does NOT auto-close while it is still tripping",
        ("o/r", WORKER_NO_CHANGE) in compute_recoveries(
            hist, ["o/r"], {"o/r": DEFAULT_THRESHOLDS}), False)

    # ---- the READ: an unreadable health ledger yields None (=> null fields), never [] (=> 0).
    class _Boom:
        def request(self, *args, **kwargs):
            raise MetricsError("HTTP 503")

    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        window = read_health_window(_Boom(), "o/r", 1_700_000_000)
    chk("an unreadable model-health ledger reads None, never an empty (confidently zero) window",
        window, None)
    chk("...and says so loudly", "::warning::" in log.getvalue() and "no-change" in log.getvalue(),
        True)

    class _NoFile:
        """The ledger BRANCH resolves but carries no health file yet (the first-record path)."""

        def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
            return {"object": {"sha": "f" * 40}} if "/git/ref/" in path else None

    log_empty = io.StringIO()
    with contextlib.redirect_stdout(log_empty):
        empty = read_health_window(_NoFile(), "o/r", 1_700_000_000)
    chk("a ledger branch with no health file yet is an EMPTY window, not a failure", empty, [],
        diag=log_empty.getvalue())
    chk("...and that is silent — it is not a degraded read", log_empty.getvalue(), "")

    class _MissingBranch:
        def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
            return None      # neither the file NOR the ledger branch resolves

    log_branch = io.StringIO()
    with contextlib.redirect_stdout(log_branch):
        gone = read_health_window(_MissingBranch(), "o/r", 1_700_000_000)
    chk("a MISSING ledger branch is None (no evidence), never an empty window", gone, None,
        diag=log_branch.getvalue())

    real_loader = _model_health_module
    try:
        def _no_module():
            raise MetricsError("scripts/model-health.py is not in this checkout")

        _model_health_module = _no_module
        log_load = io.StringIO()
        with contextlib.redirect_stdout(log_load):
            unloadable = read_health_window(_NoFile(), "o/r", 1_700_000_000)
        chk("a checkout without model-health.py degrades to None, it does not crash the snapshot",
            unloadable, None, diag=log_load.getvalue())
    finally:
        _model_health_module = real_loader


def _test_no_change_wiring(chk):
    """[#987] THE CALL SITES. `_test_no_change_census` is entirely pure, and `build_snapshot`'s loop
    body plus `run()` are the two lines it can never reach — measured at 0 executions before this
    test existed. A mutant that drops `health_records=` at either production hand-off leaves every
    pure assertion green while the published snapshot goes permanently null (#937's Z6 shape: one
    argument, one call site, a whole suite blind to it)."""
    global collect_counts, build_snapshot, read_health_window, read_history, append_snapshot
    global load_targets
    real = (collect_counts, build_snapshot, read_health_window, read_history, append_snapshot,
            load_targets)
    window_sentinel = [_health_row("111.1", issue=3241, why="already_done")]
    seen = {}
    try:
        collect_counts = lambda *a, **kw: seen.update(to_collect=kw.get("health_records")) or {}
        build_snapshot([("o/r", READY_FROM_AGENT, DEFAULT_THRESHOLDS)], {}, "tok", 0,
                       health_records=window_sentinel)
        chk("build_snapshot hands the health window to EVERY target's collector",
            seen.get("to_collect"), window_sentinel)
        collect_counts, build_snapshot = real[0], real[1]

        load_targets = lambda _path: [("o/r", READY_FROM_AGENT, DEFAULT_THRESHOLDS)]
        read_health_window = lambda api, repo, at: (
            seen.update(read_args=(repo, at)) or window_sentinel)
        build_snapshot = lambda *a, **kw: (
            seen.update(to_snapshot=kw.get("health_records")) or {"_ts": 0, "targets": {}})
        read_history = lambda *a, **kw: ([], None)
        append_snapshot = lambda *a, **kw: None
        run("policy/repos.toml", {}, "tok", "o/r", "jeswr", False, False, 1_700_000_000)
        chk("run() reads the health window ONCE, for the registry, at the snapshot's own stamp",
            seen.get("read_args"), ("o/r", 1_700_000_000))
        chk("...and hands exactly that window to build_snapshot",
            seen.get("to_snapshot"), window_sentinel)
    finally:
        (collect_counts, build_snapshot, read_health_window, read_history,
         append_snapshot, load_targets) = real


def _test_rate_derivation(chk):
    # two snapshots => close-rate reacts to the newer merge count (point-in-1h-window semantics).
    early = compute_target_metrics({**SPARQ_LIVE, "prs_merged_1h": 0, "prs_closed_1h": 0})
    later = compute_target_metrics({**SPARQ_LIVE, "prs_merged_1h": 4, "prs_closed_1h": 1})
    chk("close-rate 0 at stall", early["pr_close_rate"], 0.0)
    chk("close-rate 5 once the lane recovers", later["pr_close_rate"], 5.0)
    chk("net flow flips negative on recovery", later["net_pr_flow"], 0.0)  # open 5 - close 5
    chk("net flow positive at stall", early["net_pr_flow"], 5.0)


def _snap(ts, targets):
    return {"generated_at": _iso_ago(0, ts), "_ts": ts, "targets": targets}


def _test_list_api_contract(chk):
    """The current-state reader itself must use the paginated REST LIST API, never search."""
    global _gh_json
    real, calls = _gh_json, []

    def fake(args, token, what):
        calls.append(args)
        return [[{"number": 1, "labels": []}], [{"number": 2, "labels": []}]]

    try:
        _gh_json = fake
        rows = _list_open_rows("o/r", "issues", "tok")
        chk("LIST API pagination flattens every page", [r["number"] for r in rows], [1, 2])
        chk("current-state reader is REST list --paginate --slurp (not search index)", calls,
            [["api", "--paginate", "--slurp", "repos/o/r/issues?state=open&per_page=100"]])
    finally:
        _gh_json = real


def _test_event_list_contract(chk):
    """The 1h reader is bounded REST LIST, with cap and search-lag warnings kept loud."""
    import contextlib
    import io
    global _gh_json
    real, calls = _gh_json, []
    now = 1_000_000
    since = _iso_ago(3600, now)

    def fake(args, token, what):
        calls.append(args)
        url = args[-1]
        if "/pulls?state=closed" in url:
            return [
                # Regression fixture for #501: SEARCH may not see this yet, but LIST must count it.
                {"number": 501, "closed_at": _iso_ago(300, now),
                 "merged_at": _iso_ago(300, now)},
                {"number": 502, "closed_at": _iso_ago(240, now), "merged_at": None},
                {"number": 400, "closed_at": _iso_ago(7200, now),
                 "merged_at": _iso_ago(7200, now)},
            ]
        if "/issues?state=closed" in url:
            return [
                {"number": 503, "closed_at": _iso_ago(180, now)},
                {"number": 504, "closed_at": _iso_ago(120, now), "pull_request": {}},
                {"number": 401, "closed_at": _iso_ago(7200, now)},
            ]
        if "/pulls?state=all" in url:
            return [
                {"number": 505, "created_at": _iso_ago(60, now)},
                {"number": 402, "created_at": _iso_ago(7200, now)},
            ]
        raise AssertionError(f"unexpected event LIST URL {url}")

    try:
        _gh_json = fake
        got = _list_event_counts_1h("o/r", "tok", since)
        chk("event LIST: PR merged 5 minutes ago is counted despite SEARCH lag",
            got["prs_merged_1h"], 1)
        chk("event LIST: closed-unmerged requires merged_at null",
            got["prs_closed_1h"], 1)
        chk("event LIST: issues exclude pull requests", got["issues_closed_1h"], 1)
        chk("event LIST: opened PR uses created_at window", got["prs_opened_1h"], 1)
        chk("event LIST: exact bounded newest-first REST queries", calls, [
            ["api", "-X", "GET",
             "repos/o/r/pulls?state=closed&sort=updated&direction=desc&per_page=100&page=1"],
            ["api", "-X", "GET",
             "repos/o/r/issues?state=closed&sort=updated&direction=desc&per_page=100&page=1"],
            ["api", "-X", "GET",
             "repos/o/r/pulls?state=all&sort=created&direction=desc&per_page=100&page=1"],
        ])

        # A full page entirely inside the hour is an honest lower bound, never a silent exact count.
        recent = _iso_ago(60, now)
        floor_log = io.StringIO()
        with contextlib.redirect_stderr(floor_log):
            _warn_truncated_window(
                "o/r", "merged PR 1h", [{}] * EVENT_LIST_LIMIT,
                [recent] * EVENT_LIST_LIMIT, since)
        chk("event LIST: full in-window page logs no-silent-cap floor warning",
            f"window truncated at {EVENT_LIST_LIMIT} — count is a floor" in floor_log.getvalue(),
            True)

        lag_log = io.StringIO()
        with contextlib.redirect_stderr(lag_log):
            _warn_if_one_hour_exceeds_24h("o/r", {
                "issues_closed_1h": 2, "issues_closed_24h": 1,
                "prs_merged_1h": 4, "prs_merged_24h": 3,
            })
        chk("event LIST: 1h > SEARCH 24h sanity tripwire warns for every published sibling",
            ("issues_closed_1h=2 exceeds search-derived issues_closed_24h=1" in lag_log.getvalue()
             and "prs_merged_1h=4 exceeds search-derived prs_merged_24h=3"
             in lag_log.getvalue()), True)
    finally:
        _gh_json = real


def _test_collection_contract(chk):
    """COLLECTION-LEVEL contract (blocker #3): stub the live reads with SPARQ-SHAPED responses and
    assert what collect_counts -> compute_target_metrics ACTUALLY produces, so the fixture can never
    drift from reality. The real sparq shape: 86 drainable ready issues (NOT the 4-wide concurrency
    frontier), and NO sparq-hosted review-fix/worker workflow — the lane health must be sourced from
    the ORCHESTRATION (registry) runs filtered to the sparq target, not from sparq's own actions."""
    global _search_count, _ready_count, _paginate_runs, _list_open_rows, _list_event_rows
    real_sc, real_rc, real_pr, real_lr, real_er = (
        _search_count, _ready_count, _paginate_runs, _list_open_rows, _list_event_rows)
    now = 1_000_000
    since = _iso_ago(3600, now)
    # Search is allowed ONLY for the lag-tolerant 24h siblings. Its live-hour result is deliberately
    # stale: reverting the 1h fields to search makes the 5-minutes-ago LIST fixture below go red.
    search_calls = []
    search_table = {
        "is:issue is:closed": 31,
        "is:pr is:merged": 51,
    }

    def fake_search(repo, qualifiers, token):
        search_calls.append(qualifiers)
        for needle, val in search_table.items():
            if needle in qualifiers:
                return val
        return 0  # deliberately stale for every forbidden 1h query

    def fake_list(repo, resource, token):
        if resource == "issues":
            return [{"number": n, "state": "open", "body": "", "labels": []}
                    for n in range(1, 1050)]
        pulls = []
        for n in range(1, 53):
            labels = []
            if n <= 10:
                labels.append({"name": "review:changes"})
            if n <= 23:
                labels.append({"name": "needs:user"})
            pulls.append({"number": n, "draft": n <= 34, "labels": labels})
        return pulls

    def fake_event_list(repo, resource, state, sort, token):
        if (resource, state, sort) == ("pulls", "closed", "updated"):
            return [
                {"number": 501, "closed_at": _iso_ago(300, now),
                 "merged_at": _iso_ago(300, now)},
                {"number": 400, "closed_at": _iso_ago(7200, now),
                 "merged_at": _iso_ago(7200, now)},
            ]
        if (resource, state, sort) == ("issues", "closed", "updated"):
            return [{"number": 399, "closed_at": _iso_ago(7200, now)}]
        if (resource, state, sort) == ("pulls", "all", "created"):
            return [{"number": n, "created_at": _iso_ago(60 * n, now)} for n in range(1, 6)]
        raise AssertionError(f"unexpected event list {(resource, state, sort)!r}")

    # sparq orchestration runs live on the REGISTRY, tagged with the sparq target in the run-name.
    # A review-fix run for sparq that CONCLUDED failure, plus a worker run for sparq (2 concluded,
    # 1 success) and one still in_progress (must NOT count). A registry-only worker run for a
    # DIFFERENT target must be attributed away from sparq.
    runs_by_target = {
        "sparq-org/sparq": [
            {"id": 7001, "path": ".github/workflows/review-fix.yml",
             "display_title": f"review-fix fix sparq-org/sparq#3400 claim={'d' * 32}",
             "name": "review-fix",
             "status": "completed", "conclusion": "failure",
             "updated_at": _iso_ago(600, now), "created_at": _iso_ago(1200, now)},
            {"id": 8001, "path": ".github/workflows/worker.yml",
             "display_title": "worker sparq-org/sparq claim=aaa", "name": "worker",
             "status": "completed", "conclusion": "success",
             "updated_at": _iso_ago(300, now), "created_at": _iso_ago(900, now)},
            {"id": 8002, "path": ".github/workflows/worker.yml",
             "display_title": "worker sparq-org/sparq claim=bbb", "name": "worker",
             "status": "completed", "conclusion": "failure",
             "updated_at": _iso_ago(200, now), "created_at": _iso_ago(800, now)},
            {"id": 8003, "path": ".github/workflows/worker.yml",
             "display_title": "worker sparq-org/sparq claim=ccc", "name": "worker",
             "status": "in_progress", "conclusion": None,
             "updated_at": _iso_ago(60, now), "created_at": _iso_ago(120, now)},
            # a DIFFERENT target — must not count for sparq
            {"id": 8004, "path": ".github/workflows/worker.yml",
             "display_title": "worker other/repo claim=zzz", "name": "worker",
             "status": "completed", "conclusion": "failure",
             "updated_at": _iso_ago(100, now), "created_at": _iso_ago(150, now)},
            {"id": 9001, "path": ".github/workflows/ci.yml",        # unrelated workflow — ignored
             "display_title": "ci sparq-org/sparq", "name": "ci",
             "status": "completed", "conclusion": "failure",
             "updated_at": _iso_ago(50, now), "created_at": _iso_ago(90, now)},
        ],
    }
    # [#987] The fleet-wide health window this tick. Only 8002 is a CONCLUDED sparq worker run, so
    # only its row may be censused here: 8003's run is still in progress (not an attempt yet) and
    # 8004 belongs to another target — either one leaking in would publish a wasted-run rate that
    # sparq did not earn.
    health_window = [
        _health_row("8002.1", issue=3241, why="underspecified"),
        _health_row("8003.1", issue=999, why="already_done"),
        _health_row("8004.1", issue=555, why="too_large"),
    ]

    def fake_paginate(repo, since_iso, token, now_, page_cap=10):
        return list(runs_by_target.get("sparq-org/sparq", []))

    try:
        _search_count = fake_search
        _list_open_rows = fake_list
        _list_event_rows = fake_event_list
        _ready_count = lambda *args: 86   # drainable candidates, NOT the 4-wide frontier
        _paginate_runs = fake_paginate
        counts = collect_counts("sparq-org/sparq", READY_STATUS_ENGINE, "tok", now,
                                orchestration=("jeswr/agent-account-registry", "regtok"),
                                health_records=health_window)
        # readiness is the DRAINABLE count (blocker #1) — not the concurrency width.
        chk("collect: issues_ready is the 86 drainable count", counts["issues_ready"], 86)
        chk("collect: authoritative LIST counts all five live state/label metrics",
            {key: counts[key] for key in ("issues_open", "prs_open", "prs_draft",
                                          "review_changes_backlog", "needs_user_parked")},
            {"issues_open": 1049, "prs_open": 52, "prs_draft": 34,
             "review_changes_backlog": 10, "needs_user_parked": 23})
        chk("collect: PR merged 5 minutes ago comes from LIST despite stale SEARCH",
            counts["prs_merged_1h"], 1)
        chk("collect: SEARCH is retained only for the two published 24h counters", search_calls, [
            f"is:issue is:closed closed:>={_iso_ago(86400, now)}",
            f"is:pr is:merged merged:>={_iso_ago(86400, now)}",
        ])
        # lane health sourced from the ORCHESTRATION repo, filtered to sparq (blocker #2):
        # review-fix: 1 concluded (failure) => stalled with a review:changes backlog.
        chk("collect: review_lane_runs_1h from orchestration (1 concluded)",
            counts.get("review_lane_runs_1h"), 1)
        chk("collect: review_lane_success_1h (0 succeeded)", counts.get("review_lane_success_1h"), 0)
        # worker: 2 concluded for sparq (1 success), the in_progress + other-target excluded.
        chk("collect: worker_attempts_1h = 2 concluded sparq runs (in_progress/other excluded)",
            counts.get("worker_attempts_1h"), 2)
        chk("collect: worker_success_1h = 1", counts.get("worker_success_1h"), 1)
        # [#987] the no-change census, joined to those SAME two concluded sparq worker runs.
        chk("collect: worker_no_change_1h = 1 (8003 in-progress + 8004 other-target excluded)",
            counts.get("worker_no_change_1h"), 1)
        chk("collect: ...and the excluded rows' reasons never reach the breakdown",
            counts.get("worker_no_change_by_reason_1h"),
            {"unspecified": 0, "underspecified": 1, "blocked_on_decision": 0, "too_large": 0,
             "already_done": 0, "other": 0})
        m = compute_target_metrics(counts)
        chk("collect->metrics: no-change rate 1/2 over the same denominator as the success rate",
            m["worker_no_change_rate_1h"], 0.5)
        # the derived metrics + alerts that ACTUALLY result from the sparq shape:
        chk("collect->metrics: review lane STALLED (real, off orchestration)",
            m["review_lane_health"], "stalled")
        chk("collect->metrics: net_pr_flow +4 (5 opened, 1 fresh LIST merge)",
            m["net_pr_flow"], 4.0)
        chk("collect->metrics: worker rate 1/2", m["worker_success_rate_1h"], 0.5)
        # sustained over two identical sparq snapshots => the three sparq alerts fire (contract).
        hist = [_snap(now - 900, {"sparq-org/sparq": m}), _snap(now, {"sparq-org/sparq": m})]
        fired = {a["classification"] for a in evaluate_alerts(hist[-1], hist,
                 {"sparq-org/sparq": DEFAULT_THRESHOLDS})}
        chk("collect->alerts: backlog-growing fires on the real shape",
            BACKLOG_GROWING in fired, True)
        chk("collect->alerts: review-lane-stalled fires on the real shape",
            REVIEW_LANE_STALLED in fired, True)
        chk("collect->alerts: ready-starved fires on the real shape (86>40, 0 closed)",
            READY_STARVED in fired, True)
        # a sparq target with NO orchestration signal at all reads unknown (never falsely ok/stalled).
        _paginate_runs = lambda *a, **k: None
        counts_no_orch = collect_counts("sparq-org/sparq", READY_STATUS_ENGINE, "tok", now,
                                        orchestration=("jeswr/agent-account-registry", "regtok"),
                                        health_records=health_window)
        chk("collect: no orchestration runs => review_lane_health unknown",
            compute_target_metrics(counts_no_orch)["review_lane_health"], "unknown")
        # ...and with no run-id set there is nothing to attribute the ledger rows to, so the census
        # is SKIPPED rather than computed over a population it cannot partition — the whole health
        # window is in hand here, so a census that ran anyway would report 3 wasted sparq runs.
        chk("collect: no orchestration runs => the no-change census is absent, not zero",
            [k for k in counts_no_orch if k.startswith("worker_no_change")], [])
        # The OTHER no-signal direction: the runs are readable but the health ledger was not, so
        # there is nothing to census. The keys must be absent (=> null) rather than a confident 0.
        _paginate_runs = fake_paginate
        counts_no_health = collect_counts("sparq-org/sparq", READY_STATUS_ENGINE, "tok", now,
                                          orchestration=("jeswr/agent-account-registry", "regtok"),
                                          health_records=None)
        chk("collect: an unreadable health ledger leaves the census ABSENT (not a zero census)",
            ([k for k in counts_no_health if k.startswith("worker_no_change")],
             counts_no_health.get("worker_attempts_1h")), ([], 2))
    finally:
        _search_count, _ready_count, _paginate_runs, _list_open_rows, _list_event_rows = (
            real_sc, real_rc, real_pr, real_lr, real_er)
    _ = since  # documented window boundary; the fake ignores it


def _test_run_windowing(chk):
    """Run attribution + completion-time windowing + idle-vs-stalled counting (should #10)."""
    now = 1_000_000
    since = _iso_ago(3600, now)
    # target attribution: only runs whose run-name mentions the target AND match a lane name.
    # The REAL shape review-fix.yml renders — `claim=<id>` included (#1144). This fixture carried a
    # claim-less title, which is the drift that makes a hand-written fixture worthless as evidence;
    # `_test_run_name_seam` now pins the shape against the workflow itself.
    rf = {"path": ".github/workflows/review-fix.yml",
          "display_title": f"review-fix fix sparq-org/sparq#1 claim={'a' * 32}",
          "name": "review-fix"}
    chk("review-fix run attributes to its target",
        _run_matches(rf, REVIEW_LANE_WORKFLOWS, "sparq-org/sparq"), True)
    chk("run for one target does not attribute to another",
        _run_matches(rf, REVIEW_LANE_WORKFLOWS, "other/repo"), False)
    chk("non-lane workflow never attributes",
        _run_matches({"path": ".github/workflows/ci.yml", "display_title": "ci sparq-org/sparq",
                      "name": "ci"}, REVIEW_LANE_WORKFLOWS, "sparq-org/sparq"), False)
    # completion-time window: created 61 min ago, completed 5 min ago => IN window (bias fixed).
    old_created_new_done = {"status": "completed", "conclusion": "success",
                            "created_at": _iso_ago(3660, now), "updated_at": _iso_ago(300, now)}
    chk("run created before window but completed inside it counts",
        _run_in_window(old_created_new_done, since), True)
    # a run that completed before the window is out.
    chk("run completed before the window is excluded",
        _run_in_window({"status": "completed", "conclusion": "failure",
                        "updated_at": _iso_ago(4000, now), "created_at": _iso_ago(4200, now)},
                       since), False)
    # empty run list => IDLE (0 concluded), NOT stalled: 0-runs is distinguishable from 0-success.
    global _paginate_runs
    real_pr = _paginate_runs
    try:
        _paginate_runs = lambda *a, **k: []
        chk("no runs at all => (0 concluded, 0 succeeded) — idle, not stalled",
            _orchestration_lane_runs("o/r", "sparq-org/sparq", REVIEW_LANE_WORKFLOWS, "t", now),
            (0, 0, set()))
        _paginate_runs = lambda *a, **k: None
        chk("runs API unavailable => (None, None) — health stays unknown",
            _orchestration_lane_runs("o/r", "sparq-org/sparq", REVIEW_LANE_WORKFLOWS, "t", now),
            (None, None, set()))
        # [#987] the run-id set is derived from the SAME filtered walk as the counts: only runs
        # attributed to the target, in the window, and CONCLUDED contribute an id. An id that
        # slipped in from an in-progress or other-target run would charge that run's ledger rows to
        # the wrong denominator.
        _paginate_runs = lambda *a, **k: [
            {"id": 111, "path": ".github/workflows/worker.yml", "name": "worker",
             "display_title": "worker sparq-org/sparq claim=aaa", "status": "completed",
             "conclusion": "success", "updated_at": _iso_ago(300, now)},
            {"id": 222, "path": ".github/workflows/worker.yml", "name": "worker",
             "display_title": "worker sparq-org/sparq claim=bbb", "status": "in_progress",
             "conclusion": None, "updated_at": _iso_ago(60, now)},
            {"id": 333, "path": ".github/workflows/worker.yml", "name": "worker",
             "display_title": "worker other/repo claim=ccc", "status": "completed",
             "conclusion": "failure", "updated_at": _iso_ago(120, now)},
            {"id": 444, "path": ".github/workflows/worker.yml", "name": "worker",
             "display_title": "worker sparq-org/sparq claim=ddd", "status": "completed",
             "conclusion": "failure", "updated_at": _iso_ago(9000, now)},
        ]
        chk("run ids cover exactly the CONCLUDED, in-window, this-target runs",
            _orchestration_lane_runs("o/r", "sparq-org/sparq", WORKER_WORKFLOWS, "t", now),
            (1, 1, {"111"}))
    finally:
        _paginate_runs = real_pr


def _test_run_name_seam(chk):
    """[#1144] The YAML seam: attribution reads a title the WORKFLOWS compose, not one we wrote.

    Every fixture above hand-writes its own `display_title`, so all of them stay green no matter
    what `worker.yml` / `review-fix.yml` actually render. That is not a hypothetical gap: the same
    shape in `groom.py` went unnoticed for eight days (#1130) — worker.yml's run-name gained a
    `${{ inputs.target_repo }}` segment, groom's regex did not follow, and it `fullmatch`ed 0 of
    100 live titles with a green suite throughout. Here the harm would be the mirror image: DROP
    the target segment and every per-target throughput counter silently reads zero, which is
    indistinguishable from a genuinely idle lane.

    So render the workflows' OWN run-names — through `run_name_grammar.py`, the one reader all
    three consumers share — and require that `_run_matches` still attributes them.
    """
    spec = importlib.util.spec_from_file_location(
        "registry_run_name_grammar",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_name_grammar.py"))
    assert spec and spec.loader, "run_name_grammar.py is missing for the run-name seam check"
    grammar = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(grammar)

    for lane, lane_names in ((grammar.WORKER_LANE, WORKER_WORKFLOWS),
                             (grammar.REVIEW_FIX_LANE, REVIEW_LANE_WORKFLOWS)):
        rendering = grammar.render_lane(lane)
        chk(f"[#1144] every {lane.name} run-name expression has a known rendering",
            rendering.unknown, ())
        # A run-name that DROPS a segment still renders to a perfectly plausible string; only the
        # missing sample value reveals it, so this is the assertion that sees a removal.
        chk(f"[#1144] the {lane.name} render is not vacuous — every sample value reached the title",
            rendering.reached, tuple(sorted(lane.samples.values())))
        run = {"path": lane.workflow, "name": lane.name, "display_title": rendering.text}
        chk(f"[#1144] {lane.name}.yml's OWN rendered run-name is attributed to its target repo",
            _run_matches(run, lane_names, lane.target), True)
        # ...and attribution is a DECISION, not a constant True: the same run must not attribute to
        # a target it has nothing to do with, or the row above would pass on a `return True`.
        chk(f"[#1144] ...and that same run does NOT attribute to an unrelated target",
            _run_matches(run, lane_names, "unrelated/repo"), False)
        # State the harm the seam exists to prevent: with the target segment gone, the lane's runs
        # stop being attributed at all — a silent zero, not an error.
        without_target = " ".join(rendering.text.replace(lane.target, " ").split())
        chk(f"[#1144] a {lane.name} title with the target segment REMOVED attributes to nothing — "
            "this is the silent-zero the seam above prevents",
            _run_matches(dict(run, display_title=without_target), lane_names, lane.target), False)


def _test_review_lane_states(chk):
    """The idle/stalled/ok/unknown state machine (blocker #5 + should #10): drafts are NOT a
    backlog; a review:changes backlog with 0 concluded runs is IDLE (not stalled); a repo with
    only drafts reads ok."""
    base = {"prs_draft": 40, "review_changes_backlog": 0}
    # only drafts, lane ran/none succeeded => OK (drafts are not the lane's work item).
    chk("drafts-only lane is ok, not stalled",
        compute_target_metrics({**base, "review_lane_runs_1h": 2, "review_lane_success_1h": 0,
                                "prs_draft": 40})["review_lane_health"], "ok")
    # real changes-requested backlog but NO concluded run this hour => IDLE (not stalled).
    chk("changes backlog + 0 concluded runs is idle",
        compute_target_metrics({"review_changes_backlog": 10, "review_lane_runs_1h": 0,
                                "review_lane_success_1h": 0})["review_lane_health"], "idle")
    # changes backlog + concluded runs + 0 success => STALLED.
    chk("changes backlog + concluded no-success is stalled",
        compute_target_metrics({"review_changes_backlog": 10, "review_lane_runs_1h": 3,
                                "review_lane_success_1h": 0})["review_lane_health"], "stalled")
    # a success this hour => OK regardless of backlog.
    chk("a success clears to ok",
        compute_target_metrics({"review_changes_backlog": 10, "review_lane_runs_1h": 3,
                                "review_lane_success_1h": 1})["review_lane_health"], "ok")
    # idle does NOT fire review-lane-stalled even sustained (only 'stalled' does).
    idle = compute_target_metrics({"review_changes_backlog": 10, "review_lane_runs_1h": 0,
                                   "review_lane_success_1h": 0, "prs_open": 1})
    hist = [_snap(1000, {"t": idle}), _snap(2000, {"t": idle})]
    chk("sustained IDLE lane does not fire review-lane-stalled",
        any(a["classification"] == REVIEW_LANE_STALLED
            for a in evaluate_alerts(hist[-1], hist, {"t": DEFAULT_THRESHOLDS})), False)


def _test_recovery_hysteresis_and_skip(chk):
    """compute_recoveries: hysteresis + skipped-target protection (blockers #4, #9)."""
    sparq_firing = compute_target_metrics(SPARQ_LIVE)
    healthy = compute_target_metrics(REGISTRY_LIVE)
    thr = {"sparq-org/sparq": DEFAULT_THRESHOLDS}
    # BLOCKER #4: a SKIPPED target (absent from collected_targets) yields NO recoveries even though
    # the ring's last rows show it clear — its live alerts must NOT be auto-closed on no evidence.
    hist_clear = [_snap(1000, {"sparq-org/sparq": healthy}),
                  _snap(2000, {"sparq-org/sparq": healthy})]
    chk("skipped target produces no recoveries (never auto-closes its alerts)",
        compute_recoveries(hist_clear, collected_targets=[], thresholds_by_target=thr), set())
    # a COLLECTED target clear for recover_snapshots => all four classes recover.
    rec = compute_recoveries(hist_clear, ["sparq-org/sparq"], thr)
    chk("collected + clear over hysteresis recovers all classes",
        rec == {("sparq-org/sparq", c) for c in ALERT_CLASSES}, True)
    # HYSTERESIS: the latest tick is clear but the prior tick still tripped => NOT yet recovered.
    hist_flap = [_snap(1000, {"sparq-org/sparq": sparq_firing}),
                 _snap(2000, {"sparq-org/sparq": healthy})]
    flap_rec = compute_recoveries(hist_flap, ["sparq-org/sparq"], thr)
    chk("backlog NOT recovered while a prior tick still tripped (hysteresis)",
        ("sparq-org/sparq", BACKLOG_GROWING) in flap_rec, False)
    # not enough history to assert recovery yet => empty (leave the issue open).
    chk("insufficient clear history yields no recovery",
        compute_recoveries([_snap(2000, {"sparq-org/sparq": healthy})], ["sparq-org/sparq"], thr),
        set())


def _test_alert_rules(chk):
    sparq = compute_target_metrics(SPARQ_LIVE)
    reg = compute_target_metrics(REGISTRY_LIVE)
    # SUSTAINED over 2 snapshots (default K): two ticks with the bad condition.
    hist = [_snap(1000, {"sparq-org/sparq": sparq, "jeswr/agent-account-registry": reg}),
            _snap(2000, {"sparq-org/sparq": sparq, "jeswr/agent-account-registry": reg})]
    current = hist[-1]
    thr = {"sparq-org/sparq": DEFAULT_THRESHOLDS,
           "jeswr/agent-account-registry": DEFAULT_THRESHOLDS}
    alerts = evaluate_alerts(current, hist, thr)
    kinds = {(a["target"], a["classification"]) for a in alerts}
    chk("sparq backlog-growing fires", ("sparq-org/sparq", BACKLOG_GROWING) in kinds, True)
    chk("sparq review-lane-stalled fires",
        ("sparq-org/sparq", REVIEW_LANE_STALLED) in kinds, True)
    chk("sparq ready-starved fires (86>40 ready, 0 closed)",
        ("sparq-org/sparq", READY_STARVED) in kinds, True)
    # registry is healthy on ALL rules.
    chk("registry backlog silent (7 open)",
        ("jeswr/agent-account-registry", BACKLOG_GROWING) in kinds, False)
    chk("registry review-lane silent (lane ok)",
        ("jeswr/agent-account-registry", REVIEW_LANE_STALLED) in kinds, False)
    chk("registry ready-starved silent (19<40)",
        ("jeswr/agent-account-registry", READY_STARVED) in kinds, False)
    chk("no worker-failing (both healthy this hour)",
        any(a["classification"] == WORKER_FAILING for a in alerts), False)
    # worker-failing DOES fire when the rate is under floor with >= min_samples attempts, SUSTAINED.
    bad_worker = compute_target_metrics({**REGISTRY_LIVE, "worker_success_1h": 0,
                                         "worker_attempts_1h": 4})
    h2 = [_snap(1000, {"jeswr/agent-account-registry": bad_worker}),
          _snap(2000, {"jeswr/agent-account-registry": bad_worker})]
    wf = evaluate_alerts(h2[-1], h2, {"jeswr/agent-account-registry": DEFAULT_THRESHOLDS})
    chk("worker-failing fires at 0/4 sustained",
        any(a["classification"] == WORKER_FAILING for a in wf), True)
    # MIN-SAMPLE FLOOR: a single failed run (attempts=1) is noise, not a failing lane.
    one_bad = compute_target_metrics({**REGISTRY_LIVE, "worker_success_1h": 0,
                                      "worker_attempts_1h": 1})
    h1w = [_snap(1000, {"jeswr/agent-account-registry": one_bad}),
           _snap(2000, {"jeswr/agent-account-registry": one_bad})]
    chk("worker-failing SILENT on a single failed run (below min_samples)",
        any(a["classification"] == WORKER_FAILING
            for a in evaluate_alerts(h1w[-1], h1w, {"jeswr/agent-account-registry":
                                                    DEFAULT_THRESHOLDS})), False)
    # EVERY rule is SUSTAINED: a single bad tick (K=2 default) raises NONE of the four.
    one = [_snap(2000, {"sparq-org/sparq": sparq, "jeswr/agent-account-registry": bad_worker})]
    single = evaluate_alerts(one[-1], one, {"sparq-org/sparq": DEFAULT_THRESHOLDS,
                                            "jeswr/agent-account-registry": DEFAULT_THRESHOLDS})
    chk("backlog-growing silent on a single tick (not sustained)",
        any(a["classification"] == BACKLOG_GROWING for a in single), False)
    chk("review-lane-stalled silent on a single tick (not sustained)",
        any(a["classification"] == REVIEW_LANE_STALLED for a in single), False)
    chk("ready-starved silent on a single tick (not sustained)",
        any(a["classification"] == READY_STARVED for a in single), False)
    chk("worker-failing silent on a single tick (not sustained)",
        any(a["classification"] == WORKER_FAILING for a in single), False)


def _test_alert_mutation_nonvacuous(chk):
    """Non-vacuity: mutating a threshold flips the alert (the rule reads the threshold, not a
    constant). Raise the open-PR threshold ABOVE the live 52 => backlog-growing goes silent."""
    sparq = compute_target_metrics(SPARQ_LIVE)
    hist = [_snap(1000, {"sparq-org/sparq": sparq}), _snap(2000, {"sparq-org/sparq": sparq})]
    lo = evaluate_alerts(hist[-1], hist, {"sparq-org/sparq": DEFAULT_THRESHOLDS})
    hi = evaluate_alerts(hist[-1], hist,
                         {"sparq-org/sparq": {**DEFAULT_THRESHOLDS, "open_pr_alert_threshold": 100}})
    chk("backlog fires at default threshold",
        any(a["classification"] == BACKLOG_GROWING for a in lo), True)
    chk("backlog SILENT once threshold raised past 52 (non-vacuous)",
        any(a["classification"] == BACKLOG_GROWING for a in hi), False)
    # ready threshold mutation: raise past 86 => ready-starved silent.
    hi_ready = evaluate_alerts(hist[-1], hist,
                               {"sparq-org/sparq": {**DEFAULT_THRESHOLDS,
                                                    "ready_alert_threshold": 200}})
    chk("ready-starved SILENT once threshold raised past 86 (non-vacuous)",
        any(a["classification"] == READY_STARVED for a in hi_ready), False)
    # sustain mutation: K=3 with only 2 snapshots => backlog cannot be SUSTAINED => silent.
    k3 = evaluate_alerts(hist[-1], hist,
                         {"sparq-org/sparq": {**DEFAULT_THRESHOLDS, "sustain_snapshots": 3}})
    chk("backlog SILENT when K exceeds available history (non-vacuous)",
        any(a["classification"] == BACKLOG_GROWING for a in k3), False)


def _test_ledger_cas(chk):
    now = 2_000_000
    api = _StubAPI(seed=None)
    snap = _snap(now, {"sparq-org/sparq": compute_target_metrics(SPARQ_LIVE)})
    kept = append_snapshot(api, "o/r", snap)
    chk("CAS creates the ring from missing", (kept, len(api.snapshots())), (1, 1))
    # Crash replay: the same logical tick must be a true no-op. Without the `_ts` identity check,
    # this becomes two bad rows and falsely satisfies the default sustain_snapshots=2 gate.
    kept = append_snapshot(api, "o/r", snap)
    replay_history = api.snapshots()
    replay_alerts = evaluate_alerts(
        replay_history[-1], replay_history, {"sparq-org/sparq": DEFAULT_THRESHOLDS})
    chk("double-append of one _ts tick is a no-op (one row, one PUT)",
        (kept, len(replay_history), api.put_count), (1, 1, 1))
    chk("one replayed bad tick cannot satisfy sustain_snapshots=2",
        any(a["classification"] == BACKLOG_GROWING for a in replay_alerts), False)
    kept = append_snapshot(api, "o/r", _snap(now + 900, {"x": {}}))
    chk("CAS appends onto existing ring", kept, 2)
    # conflict retry
    apic = _StubAPI(seed=[], conflict_first=True)
    chk("CAS retries past a conflict", append_snapshot(apic, "o/r", snap), 1)
    # ring is bounded
    big = _StubAPI(seed=[_snap(i, {"x": {}}) for i in range(MAX_SNAPSHOTS + 5)])
    chk("ring bounded to MAX_SNAPSHOTS", append_snapshot(big, "o/r", snap), MAX_SNAPSHOTS)
    # branch targeting (issue #28)
    chk("history read targets the ledger ref",
        ledger_read_path("o/r"), f"/repos/o/r/contents/{LEDGER_PATH}?ref=ledger")
    chk("CAS writes pinned branch=ledger", api.last_put_branch, "ledger")
    loud = False
    try:
        read_history(_StubAPI(seed=None, branch_missing=True), "o/r")
    except MetricsError:
        loud = True
    chk("missing ledger BRANCH fails loud (never silently-empty)", loud, True)
    chk("missing history FILE on a present branch seeds empty ring",
        read_history(_StubAPI(seed=None), "o/r"), ([], None))


def _load_dashboard_gen():
    """dashboard-gen's workflow-step extraction primitives (#612), shared rather than re-implemented:
    ONE implementation of "locate exactly this step, fail closed if you cannot", so a wiring
    assertion can never pass vacuously against a step it failed to find."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard-gen.py")
    spec = importlib.util.spec_from_file_location("registry_dashboard_gen", path)
    if spec is None or spec.loader is None:
        raise MetricsError("cannot load dashboard-gen.py for workflow-step extraction")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Hermetic `gh` stub for the publish-decision harness (the #533 reconcile-harness pattern): keyed on
# the EXACT api path so a reshaped step fails LOUDLY (exit 64) instead of quietly satisfying every
# assertion. The REAL jq evaluates the step's REAL `--jq` filter over a fixture, so a mutated filter
# — dropping the self-exclusion, or reading the run rollup instead of the deploy job — is caught
# here too, not merely the surrounding shell.
_PUBLISH_DECISION_GH_STUB = r'''#!/usr/bin/env bash
filter=""
want=0
for a in "$@"; do
  if [ "$want" = 1 ]; then filter="$a"; want=0; fi
  if [ "$a" = "--jq" ]; then want=1; fi
done
case "$2" in
  "repos/o/r/actions/workflows/dashboard.yml/runs?per_page=5")
    if [ "${STUB_RUNS_FAIL:-0}" = 1 ]; then
      printf 'gh-stub: runs read failed\n' >&2
      exit 1
    fi
    printf '%s' "${STUB_RUNS_JSON}" | jq -r "$filter"
    ;;
  repos/o/r/actions/runs/*/jobs)
    if [ "${STUB_JOBS_FAIL:-0}" = 1 ]; then
      printf 'gh-stub: jobs read failed\n' >&2
      exit 1
    fi
    printf '%s' "${STUB_JOBS_JSON}" | jq -r "$filter"
    ;;
  *)
    printf 'gh-stub: unexpected argv: %s\n' "$*" >&2
    exit 64
    ;;
esac
'''

# Hermetic `gh` stub for the publish-KICK harness. Every dispatch POST is appended verbatim to
# $STUB_CALLS so the test can assert WHICH workflow was kicked and with which marker.
_PUBLISH_KICK_GH_STUB = r'''#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_CALLS}"
case "$*" in
  *"/dispatches"*)  : ;;
  *"runs?per_page=30"*) printf '0\n' ;;
  *"runs?per_page=1"*)  printf '%s\n' "${STUB_LAST_RUN_AT}" ;;
  *) printf 'gh-stub: unexpected argv: %s\n' "$*" >&2; exit 64 ;;
esac
'''


def _stub_bin(tmp, name, body):
    """Write an executable stub onto a private PATH directory and return that directory."""
    binpath = os.path.join(tmp, "bin")
    os.makedirs(binpath, exist_ok=True)
    target = os.path.join(binpath, name)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(target, 0o755)
    return binpath


def _iso_at(offset_seconds):
    """An RFC3339 UTC stamp `offset_seconds` in the past — the shape the runs API returns."""
    moment = datetime.fromtimestamp(time.time() - offset_seconds, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_publish_decision(script, *, reason="", runs=(), jobs=(),
                          runs_fail=False, jobs_fail=False):
    """EXECUTE dashboard.yml's extracted publish-decision body. -> (exit code, publish, log)."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        binpath = _stub_bin(tmp, "gh", _PUBLISH_DECISION_GH_STUB)
        body = os.path.join(tmp, "publish-decision.sh")
        with open(body, "w", encoding="utf-8") as handle:
            handle.write(script)
        out_file = os.path.join(tmp, "github-output")
        with open(out_file, "w", encoding="utf-8"):
            pass
        env = dict(os.environ)
        env.update({"PATH": binpath + os.pathsep + env.get("PATH", ""),
                    "GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "999",
                    "GITHUB_EVENT_NAME": "schedule", "GITHUB_OUTPUT": out_file,
                    "GH_TOKEN": "stub", "KICK_REASON": reason,
                    "FRESH_WINDOW_SECONDS": "900",
                    "STUB_RUNS_JSON": json.dumps({"workflow_runs": list(runs)}),
                    "STUB_JOBS_JSON": json.dumps({"jobs": list(jobs)}),
                    "STUB_RUNS_FAIL": "1" if runs_fail else "0",
                    "STUB_JOBS_FAIL": "1" if jobs_fail else "0"})
        proc = subprocess.run(["bash", body], capture_output=True, text=True, env=env)
        with open(out_file, encoding="utf-8") as handle:
            emitted = handle.read()
    values = re.findall(r"^publish=(\S+)$", emitted, re.M)
    return proc.returncode, (values[-1] if values else None), proc.stdout + proc.stderr


def _run_publish_kick(script, *, metrics_result, last_run_age=60):
    """EXECUTE metrics.yml's extracted dashboard-publish body. -> (exit code, [gh argv], log)."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        binpath = _stub_bin(tmp, "gh", _PUBLISH_KICK_GH_STUB)
        body = os.path.join(tmp, "dashboard-publish.sh")
        with open(body, "w", encoding="utf-8") as handle:
            handle.write(script)
        calls_file = os.path.join(tmp, "calls")
        with open(calls_file, "w", encoding="utf-8"):
            pass
        env = dict(os.environ)
        env.update({"PATH": binpath + os.pathsep + env.get("PATH", ""),
                    "GITHUB_REPOSITORY": "o/r", "GH_TOKEN": "stub",
                    "METRICS_RESULT": metrics_result, "STUB_CALLS": calls_file,
                    "STUB_LAST_RUN_AT": _iso_at(last_run_age)})
        proc = subprocess.run(["bash", body], capture_output=True, text=True, env=env)
        with open(calls_file, encoding="utf-8") as handle:
            calls = [line for line in handle.read().splitlines() if line.strip()]
    return proc.returncode, calls, proc.stdout + proc.stderr


# [OPUS-5] round-2 review: the ONE grammar of job-level `if:` this repo's publish chain uses.
# Anchored and single-comparison on purpose — see _eval_job_if for why an unmodelled rewrite must
# raise rather than be waved through.
_JOB_IF_COMPARISON = re.compile(
    r"^needs\.([A-Za-z0-9_-]+)\.(result|outputs\.[A-Za-z0-9_.-]+)\s*(==|!=)\s*'([^']*)'$")


def _eval_job_if(expr, needs):
    """EVALUATE a job-level `if:` against a hypothetical `needs` context. -> bool.

    Round-2 review finding (mutants A and C): the wiring assertions here matched job conditions by
    SUBSTRING, which is polarity-blind by construction. `==` -> `!=` on the publish gate made the
    dashboard publish only when the dedupe decided to SKIP — the freshness fix becoming a freshness
    outage — and every check in the repo stayed green. Deletion was caught; inversion was not. So
    the gate is now evaluated over the outcomes that matter instead of pattern-matched.

    `expr is None` models GitHub's default for a job with `needs:` and no `if:` — an implicit
    `success()` over the needed jobs. That is what makes dropping `if: always()` visible here.

    Only `always()`, a boolean literal, `success()`, and ONE
    `needs.<job>.(result|outputs.<key>) (==|!=) '<literal>'` comparison are modelled. Anything else
    raises: a gate rewritten into a form this harness cannot reason about must fail LOUDLY rather
    than silently stop being checked, which is the failure mode that produced this function."""
    def _success():
        return all((ctx or {}).get("result") == "success" for ctx in needs.values())

    if expr is None:
        return _success()
    if isinstance(expr, bool):  # `if: false` parses as a YAML boolean, not the string "false"
        return expr
    text = str(expr).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    if text == "always()":
        return True
    if text in ("true", "false"):
        return text == "true"
    if text == "success()":
        return _success()
    match = _JOB_IF_COMPARISON.match(text)
    if not match:
        raise MetricsError(
            f"unmodelled job `if:` expression {expr!r} — this harness only evaluates the restricted "
            "grammar the publish chain uses, and an expression it cannot evaluate is an UNCHECKED "
            "polarity on a surface that cannot be reviewed at runtime (round-2 mutants A and C). "
            "Extend _eval_job_if deliberately, or keep the gate in the modelled grammar.")
    job, field, operator, want = match.groups()
    context = needs.get(job)
    if context is None:
        raise MetricsError(
            f"job `if:` reads needs.{job}, which is not among the modelled needs {sorted(needs)} — "
            "a gate that names a job it does not depend on always reads the empty string")
    if field == "result":
        got = context.get("result", "")
    else:
        got = (context.get("outputs") or {}).get(field.split(".", 1)[1], "")
    return (got == want) if operator == "==" else (got != want)


def _job_step(job, step_id):
    """The parsed step mapping with `id: step_id` inside a parsed job. Fails closed."""
    found = [step for step in (job.get("steps") or []) if step.get("id") == step_id]
    if len(found) != 1:
        raise MetricsError(
            f"expected exactly one step with `id: {step_id}`, found {len(found)} — refusing to "
            "assert against a step that cannot be located")
    return found[0]


def _test_publish_cas_and_wiring(chk):
    snapshot = {"generated_at": "2026-07-21T00:00:00Z", "schema_version": 1,
                "targets": {}, "alerts": []}
    api = _StubAPI(seed=[])
    publish_snapshot(api, "o/r", snapshot)
    chk("published snapshot stays inside the ledger data-only whitelist",
        re.fullmatch(r"data/[^/]+\.json", PUBLISHED_PATH) is not None, True)
    chk("dashboard snapshot CAS targets ledger:data/metrics.json",
        (api.last_put_path, api.last_put_branch), (PUBLISHED_PATH, LEDGER_REF))
    chk("dashboard snapshot CAS writes the public snapshot exactly", api.published(), snapshot)
    updated = {**snapshot, "generated_at": "2026-07-21T00:15:00Z"}
    publish_snapshot(api, "o/r", updated)
    chk("dashboard snapshot CAS updates with the current blob SHA", api.published(), updated)
    conflicted = _StubAPI(seed=[], conflict_first=True)
    publish_snapshot(conflicted, "o/r", snapshot)
    chk("dashboard snapshot CAS retries a lost update", conflicted.published(), snapshot)

    # Mutation guard for the workflow handoff: the collector must invoke the CAS, and the sole
    # dashboard deploy must consume the same ledger path into the same site-relative path.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, ".github", "workflows", "metrics.yml"), encoding="utf-8") as fh:
        collector_workflow = fh.read()
    with open(os.path.join(root, ".github", "workflows", "dashboard.yml"), encoding="utf-8") as fh:
        dashboard_workflow = fh.read()
    chk("metrics workflow invokes ledger CAS publication", "--publish" in collector_workflow, True)
    chk("dashboard's sole Pages build publishes ledger metrics at site/metrics.json",
        ("ledger/data/metrics.json" in dashboard_workflow
         and "site/metrics.json" in dashboard_workflow), True)

    # --- the PUBLIC key contract at the write boundary --------------------------------------
    # The repository is public and this document is served verbatim at
    # jeswr.github.io/agent-account-registry/metrics.json. Both directions are asserted, because
    # only one of them is a leak but both are contract breaks.
    chk("the public contract is exactly the key set the site serves today",
        sorted(PUBLIC_SNAPSHOT_KEYS), ["alerts", "generated_at", "schema_version", "targets"])
    widened = False
    try:
        publish_snapshot(_StubAPI(seed=[]), "o/r", {**snapshot, "account_handles": ["acct01"]})
    except MetricsError:
        widened = True
    chk("a WIDENED snapshot is refused before a byte is encoded (a public page never learns a new "
        "key by accident)", widened, True)
    narrowed = False
    try:
        publish_snapshot(_StubAPI(seed=[]),
                         "o/r", {k: v for k, v in snapshot.items() if k != "generated_at"})
    except MetricsError:
        narrowed = True
    chk("a snapshot MISSING a contracted key is refused too (the freshness stamp is the one field "
        "the whole publish path exists to move)", narrowed, True)
    stripped = {k: v for k, v in build_snapshot([], {}, None, 0).items() if k != "_ts"}
    chk("run()'s `_ts` strip is what keeps build_snapshot publishable — the standing proof that "
        "the boundary check has something real to catch",
        ("_ts" in build_snapshot([], {}, None, 0), set(stripped) <= set(PUBLIC_SNAPSHOT_KEYS)),
        (True, True))

    # --- the CAUSAL publish path (#656 follow-up) -------------------------------------------
    # A ledger snapshot is not published until dashboard.yml copies it into its Pages artifact.
    # On independent crons that copy inherited BOTH cadences; metrics.yml now kicks the dashboard
    # the moment the snapshot exists. These assertions pin the wire contract, the dedupe that
    # stops the retained cron fallback doubling the deploys, and the liveness mesh the dedupe is
    # forbidden to touch.
    import yaml  # lazy, self-test only: already a hard self-test-suite dep (resolve-conflicts.py)
    dg = _load_dashboard_gen()
    dash = yaml.safe_load(dashboard_workflow)
    coll = yaml.safe_load(collector_workflow)
    # PyYAML is YAML 1.1, where the `on:` key parses as the boolean True.
    triggers = dash.get("on", dash.get(True)) or {}
    dispatch_inputs = ((triggers.get("workflow_dispatch") or {}).get("inputs") or {})

    kick_script = dg._workflow_step_script(collector_workflow, "dashboard-publish")
    decision_script = dg._workflow_step_script(dashboard_workflow, "publish-decision")
    # NESTED, not flat. Verified against an echo server: `gh api -f reason=x` builds the FLAT body
    # {"ref":...,"reason":"x"}, which the dispatch API does not read as an input — the kicked run
    # would start with an EMPTY reason, be indistinguishable from a keepalive dispatch, and be
    # deduped away, so the causal publish would silently never happen. gh's documented nesting
    # syntax is `key[subkey]=value`, and this assertion is the only thing standing between the two.
    sent = re.search(r"-f\s+'inputs\[reason\]=([^']+)'", kick_script)
    marker = sent.group(1) if sent else ""
    chk("the publish kick carries a causal-leg marker, sent as a NESTED workflow_dispatch input "
        "(a flat `-f reason=` is accepted by gh, ignored by the API, and fails silently)",
        bool(marker), True)
    chk("dashboard DECLARES the input the kick sends — an undeclared input makes the dispatch POST "
        "a 422 and the whole causal path a silent no-op",
        marker and marker != "" and "reason" in dispatch_inputs, True)
    chk("the dashboard's dedupe tests the SAME marker metrics.yml sends (cross-file wire contract: "
        "renaming either side goes red here rather than in production)",
        bool(marker) and re.search(rf"KICK_REASON[^\n]*=\s*{re.escape(marker)}\b",
                                   decision_script) is not None, True)
    chk("that marker reaches the decision from the dispatch input, not from thin air",
        "github.event.inputs.reason"
        in dg._workflow_step_env(dashboard_workflow, "publish-decision").get("KICK_REASON", ""),
        True)
    chk("the metrics-driven kick fires on the METRICS JOB's result, not the workflow rollup (a "
        "rollup also carries this very job, so a keepalive failure would suppress a good publish)",
        (coll["jobs"]["dashboard-publish"].get("needs"),
         "needs.metrics.result" in dg._workflow_step_env(
             collector_workflow, "dashboard-publish").get("METRICS_RESULT", "")),
        ("metrics", True))

    # The retained cron is the liveness fallback; the whole publish chain — and ONLY the publish
    # chain — hangs off the dedupe.
    chk("dashboard KEEPS its own schedule (a dashboard triggered only by the kick would make "
        "metrics a single point of failure for the fleet-wide cron-keepalive mesh)",
        "schedule" in triggers, True)
    chk("the publish chain is gated on the dedupe, transitively through probe -> build -> deploy",
        (dash["jobs"]["probe"].get("needs"),
         "needs.publish-decision.outputs.publish" in str(dash["jobs"]["probe"].get("if", "")),
         dash["jobs"]["build"].get("needs"), dash["jobs"]["deploy"].get("needs")),
        ("publish-decision", True, "probe", "build"))

    # --- THE YAML `if:` SEAM (round-2 review, mutants A and C) ------------------------------
    # The assertion above catches DELETION of the gate and nothing else: it is a substring test, so
    # `== 'true'` -> `!= 'true'` survived it, and the dashboard would then publish only when the
    # dedupe decided to SKIP. `if: always()` on the kick job was pinned by nothing at all, so
    # deleting it survived too — and with the NEW `needs: metrics` edge that silently kills the
    # mutual cron-delivery keepalive on exactly the failure path it exists for (the 2026-07-22
    # stall). Both mutants live one level ABOVE the executed shell bodies, on a surface no runtime
    # check can reach. So each condition is pinned EXACTLY and then EVALUATED.
    publish_gate = dash["jobs"]["probe"].get("if")
    chk("the publish gate is the EXACT positive polarity (an inverted dedupe publishes only when it "
        "decided to skip — the freshness fix becoming a freshness outage)",
        str(publish_gate).strip(), "needs.publish-decision.outputs.publish == 'true'")
    chk("...and the gate is EVALUATED, not merely matched: publish=true runs the chain, "
        "publish=false skips it, and an absent output skips (fail-closed if the decision job itself "
        "dies — one cron of no publish, never a wedge)",
        tuple(_eval_job_if(publish_gate,
                           {"publish-decision": {"result": "success", "outputs": outputs}})
              for outputs in ({"publish": "true"}, {"publish": "false"}, {})),
        (True, False, False))
    chk("no OTHER job in the publish chain carries a condition of its own — a second gate anywhere "
        "on publish-decision/build/deploy (`if: false` being the cheapest) stops the site "
        "publishing while every dedupe assertion above stays green",
        {job: dash["jobs"][job].get("if") for job in ("publish-decision", "build", "deploy")},
        {"publish-decision": None, "build": None, "deploy": None})
    chk("...and neither EXECUTED step body is itself conditional — a step-level `if:` would leave "
        "this harness exercising a body production can skip",
        (_job_step(dash["jobs"]["publish-decision"], "publish-decision").get("if"),
         _job_step(coll["jobs"]["dashboard-publish"], "dashboard-publish").get("if")),
        (None, None))
    keepalive_gate = coll["jobs"]["dashboard-publish"].get("if")
    chk("the kick job runs even when the metrics job FAILS: `needs: metrics` is NEW here, so "
        "without `always()` the mutual cron-delivery keepalive dies on precisely the failure path "
        "it was built for (2026-07-22: dashboard 44+ min overdue, nothing kicked it)",
        str(keepalive_gate).strip(), "always()")
    chk("...evaluated across every metrics-job outcome, so DELETING the condition (leaving GitHub's "
        "implicit success()) or pinning it false goes red here, not in production",
        {result: _eval_job_if(keepalive_gate, {"metrics": {"result": result}})
         for result in ("success", "failure", "cancelled", "skipped")},
        {"success": True, "failure": True, "cancelled": True, "skipped": True})
    unmodelled = False
    try:
        _eval_job_if("github.event_name == 'schedule' && needs.publish-decision.result == 'success'",
                     {"publish-decision": {"result": "success"}})
    except MetricsError:
        unmodelled = True
    chk("a gate rewritten outside the modelled grammar RAISES rather than silently stopping being "
        "checked — the evaluator above must not be the next thing that fails open", unmodelled, True)

    chk("cron-keepalive is NEVER gated by the dedupe — the liveness mesh that revives every other "
        "scheduled workflow must run on every scheduled fire, publish or skip",
        ("needs" in dash["jobs"]["cron-keepalive"], "if" in dash["jobs"]["cron-keepalive"]),
        (False, False))
    window = int(re.search(r"FRESH_WINDOW_SECONDS:\s*'(\d+)'", dashboard_workflow).group(1))
    cadence = re.search(r"- cron: '(\S+)", collector_workflow).group(1)
    step_minutes = int(cadence.split("/")[1]) if "/" in cadence else 60
    chk("the dedupe window never exceeds the metrics cadence it defers to (a wider window lets a "
        "stalled kick suppress the very fallback that covers that stall)",
        window <= step_minutes * 60, True)
    deploy_job_name = dash["jobs"]["deploy"]["name"]
    chk("the dedupe interrogates the deploy job by its REAL name (renaming the job must not "
        "silently turn the freshness check into a coin flip)",
        deploy_job_name in decision_script, True)

    # --- and now EXECUTE both bodies. Neither `bash -n` nor actionlint can see polarity. -----
    chk("jq is available for the hermetic harness below (a missing dependency must be NAMED, "
        "never silently skipped into a green run)",
        subprocess.run(["jq", "--version"], capture_output=True).returncode, 0)
    self_run = {"id": 999, "status": "in_progress", "conclusion": None,
                "created_at": _iso_at(10)}
    fresh_prev = {"id": 12, "status": "completed", "conclusion": "success",
                  "created_at": _iso_at(120)}
    deployed = [{"name": deploy_job_name, "conclusion": "success"}]
    skipped = [{"name": deploy_job_name, "conclusion": "skipped"}]

    rc, published, log = _run_publish_decision(
        decision_script, runs=[self_run, fresh_prev], jobs=deployed)
    chk("a scheduled run DEFERS when the previous run deployed inside the window — and finds that "
        "previous run only because it excludes ITSELF from the listing",
        (rc, published), (0, "false"), log)
    rc, published, log = _run_publish_decision(
        decision_script, reason=marker, runs=[self_run, fresh_prev], jobs=deployed)
    chk("the CAUSAL leg publishes regardless — a deploy seconds old carried the PREVIOUS snapshot, "
        "which is the whole lag being removed", (rc, published), (0, "true"), log)
    rc, published, log = _run_publish_decision(
        decision_script, runs=[self_run, fresh_prev], jobs=skipped)
    chk("a previous run that CONCLUDED success while skipping its deploy does not count as a "
        "publish — deferring to one would make the skip self-sustaining and freeze the site",
        (rc, published), (0, "true"), log)
    rc, published, log = _run_publish_decision(
        decision_script,
        runs=[self_run, {**fresh_prev, "created_at": _iso_at(window + 60)}], jobs=deployed)
    chk("a previous deploy OLDER than the window does not suppress the scheduled fallback",
        (rc, published), (0, "true"), log)
    for label, kwargs in (
            ("the runs listing is unreadable", {"runs": [self_run, fresh_prev],
                                                "jobs": deployed, "runs_fail": True}),
            ("the deploy-job read is unreadable", {"runs": [self_run, fresh_prev],
                                                   "jobs": deployed, "jobs_fail": True}),
            ("no other run is visible at all", {"runs": [self_run], "jobs": deployed}),
            ("the previous run's timestamp is garbage",
             {"runs": [self_run, {**fresh_prev, "created_at": "not-a-date"}], "jobs": deployed}),
            ("the previous run failed", {"runs": [self_run, {**fresh_prev,
                                                             "conclusion": "failure"}],
                                         "jobs": deployed}),
            ("the previous run has not settled", {"runs": [self_run, {**fresh_prev,
                                                                      "status": "in_progress"}],
                                                  "jobs": deployed})):
        rc, published, log = _run_publish_decision(decision_script, **kwargs)
        chk(f"FAIL-OPEN: {label} -> the run still publishes (a dedupe that can wedge itself shut "
            "turns a freshness fix into a freshness outage)", (rc, published), (0, "true"), log)

    rc, calls, log = _run_publish_kick(kick_script, metrics_result="success")
    chk("a SUCCESSFUL metrics job kicks dashboard.yml exactly once, carrying the causal marker in "
        "the nested-input form the dispatch API actually reads",
        (rc, len(calls), calls and "dashboard.yml/dispatches" in calls[0],
         calls and f"inputs[reason]={marker}" in calls[0]), (0, 1, True, True), log)
    rc, calls, log = _run_publish_kick(kick_script, metrics_result="failure", last_run_age=60)
    chk("a FAILED metrics job publishes nothing and does not fake a causal kick",
        (rc, [c for c in calls if "dispatches" in c]), (0, []), log)
    rc, calls, log = _run_publish_kick(kick_script, metrics_result="failure", last_run_age=9000)
    chk("...but the pre-existing MUTUAL keepalive survives: a stale dashboard is still revived, "
        "without the causal marker", (rc, len([c for c in calls if "dispatches" in c]),
                                      any(f"reason={marker}" in c for c in calls)),
        (0, 1, False), log)


def _test_upsert_dedupe(chk):
    import contextlib
    import io
    import types
    global _gh
    real_gh, calls = _gh, []

    def fake_gh(open_issues, closed_issues, fail_verbs):
        def run(args, token, capture=False):
            calls.append(list(args))
            if args[:2] == ["issue", "list"]:
                state = args[args.index("--state") + 1]
                issues = open_issues if state == "open" else closed_issues
                return types.SimpleNamespace(returncode=1 if "list" in fail_verbs else 0,
                                             stdout=json.dumps(issues), stderr="transient")
            verb = args[1] if args[0] == "issue" else args[0]
            return types.SimpleNamespace(returncode=1 if verb in fail_verbs else 0,
                                         stdout="", stderr="")
        return run

    def verbs():
        return [c[1] for c in calls if c and c[0] == "issue"]

    action = {"target": "sparq-org/sparq", "classification": REVIEW_LANE_STALLED, "fire": True,
              "summary": "s", "metrics": {"prs_merged_1h": 0}}
    marker = _marker(action["target"], action["classification"])
    try:
        # fresh: no open, no closed => CREATE exactly one (deduped).
        _gh, calls[:] = fake_gh([], [], set()), []
        upsert_alert(action, "o/r", "t", "m")
        chk("fresh alert CREATES one issue", verbs().count("create"), 1)
        # A transient authoritative lookup failure is UNKNOWN, not "not found": fail closed and
        # create nothing. Replacing the raise with `return None` makes this assertion red.
        _gh, calls[:] = fake_gh([], [], {"list"}), []
        lookup_log = io.StringIO()
        with contextlib.redirect_stderr(lookup_log):
            upsert_alert(action, "o/r", "t", "m")
        chk("transient issue-list failure creates NO duplicate alert issue",
            verbs().count("create"), 0)
        chk("transient issue-list failure logs loudly", "::error::metrics" in lookup_log.getvalue(),
            True)
        # already open => EDIT (refresh), never a second create.
        _gh, calls[:] = fake_gh([{"number": 8, "body": marker}], [], set()), []
        upsert_alert(action, "o/r", "t", "m")
        chk("existing open alert refreshes (edit), no create",
            ("edit" in verbs(), "create" in verbs()), (True, False))
        # flap: closed marker exists => REOPEN, never create.
        _gh, calls[:] = fake_gh([], [{"number": 7, "body": marker}], set()), []
        upsert_alert(action, "o/r", "t", "m")
        chk("flap reopens the closed marker issue", "reopen" in verbs(), True)
        chk("flap does not create a duplicate", "create" in verbs(), False)
        # recovery (fire=False) on an open issue => CLOSE + comment.
        _gh, calls[:] = fake_gh([{"number": 8, "body": marker}], [], set()), []
        upsert_alert({**action, "fire": False}, "o/r", "t", "m")
        chk("recovery closes + comments", ("close" in verbs(), "comment" in verbs()), (True, True))
        # FAILED close => NO comment (no next-tick spam).
        _gh, calls[:] = fake_gh([{"number": 8, "body": marker}], [], {"close"}), []
        upsert_alert({**action, "fire": False}, "o/r", "t", "m")
        chk("failed close posts no comment", "comment" in verbs(), False)
        # reconcile fires the one firing class and closes ONLY the explicit recovery keys.
        _gh, calls[:] = fake_gh([], [], set()), []
        reconcile_alerts([action], "o/r", "t", "m",
                         recoveries={("sparq-org/sparq", BACKLOG_GROWING)})
        chk("reconcile fires the one firing class (create)", verbs().count("create"), 1)
        # a firing (target, class) is NEVER also closed even if it appears in recoveries.
        _gh, calls[:] = fake_gh([{"number": 9, "body": marker}], [], set()), []
        reconcile_alerts([action], "o/r", "t", "m",
                         recoveries={(action["target"], action["classification"])})
        chk("reconcile never closes a class that is firing this tick", "close" in verbs(), False)
        # reconcile touches NOTHING for a (target, class) that is neither firing nor a recovery
        # (e.g. a SKIPPED target, or one still inside the recovery hysteresis window).
        _gh, calls[:] = fake_gh([{"number": 5, "body": _marker("skipped/target", BACKLOG_GROWING)}],
                                [], set()), []
        reconcile_alerts([], "o/r", "t", "m", recoveries=set())
        chk("reconcile leaves a non-recovered, non-firing class untouched (no close)",
            "close" in verbs(), False)
    finally:
        _gh = real_gh


def _test_policy_and_readiness(chk):
    import tempfile
    import tomllib as _t
    _ = _t
    policy = (
        '[repos."sparq-org/sparq"]\nenabled = true\n'
        '[repos."jeswr/agent-account-registry"]\nenabled = true\n'
        '[repos."jeswr/agent-account-registry".throughput]\n'
        'target_ready = 12\nopen_pr_alert_threshold = 5\n'
        '[repos."disabled/repo"]\nenabled = false\n')
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write(policy)
        path = fh.name
    targets = load_targets(path)
    repos = {r for r, _k, _t in targets}
    chk("load_targets skips disabled", "disabled/repo" in repos, False)
    chk("load_targets keeps both enabled", repos,
        {"sparq-org/sparq", "jeswr/agent-account-registry"})
    kinds = {r: k for r, k, _t in targets}
    chk("sparq readiness = status-ready engine", kinds["sparq-org/sparq"], READY_STATUS_ENGINE)
    chk("registry readiness = from-agent-open",
        kinds["jeswr/agent-account-registry"], READY_FROM_AGENT)
    thr = {r: t for r, _k, t in targets}
    chk("registry threshold override applied",
        thr["jeswr/agent-account-registry"]["open_pr_alert_threshold"], 5)
    chk("sparq falls back to default threshold",
        thr["sparq-org/sparq"]["open_pr_alert_threshold"],
        DEFAULT_THRESHOLDS["open_pr_alert_threshold"])
    # a bad threshold key is rejected loudly.
    bad = ('[repos."o/r"]\nenabled = true\n[repos."o/r".throughput]\nbogus = 1\n')
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write(bad)
        badpath = fh.name
    rejected = False
    try:
        load_targets(badpath)
    except MetricsError:
        rejected = True
    chk("unknown throughput key rejected", rejected, True)
    zero = ('[repos."o/r"]\nenabled = true\n'
            '[repos."o/r".throughput]\nsustain_snapshots = 0\n')
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write(zero)
        zeropath = fh.name
    zero_error = ""
    try:
        load_targets(zeropath)
    except MetricsError as exc:
        zero_error = str(exc)
    chk("sustain_snapshots=0 rejected loudly (anti-spike cannot be disabled)",
        "sustain_snapshots" in zero_error and "positive integer" in zero_error, True)

    # [#987] worker_no_change_ceiling is a RATIO, so it must take the float arm — the positive-
    # integer arm would reject every legal value it can hold (0.6) and accept an illegal one (7).
    def _threshold_outcome(line):
        doc = f'[repos."o/r"]\nenabled = true\n[repos."o/r".throughput]\n{line}\n'
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
            fh.write(doc)
            where = fh.name
        try:
            return load_targets(where)[0][2]["worker_no_change_ceiling"]
        except MetricsError as exc:
            return str(exc)

    chk("a fractional worker_no_change_ceiling is ACCEPTED (it is validated as a ratio)",
        _threshold_outcome("worker_no_change_ceiling = 0.6"), 0.6)
    chk("...and one outside [0, 1] is refused",
        "must be a float in [0, 1]" in str(_threshold_outcome("worker_no_change_ceiling = 7")),
        True)
    chk("...and a non-numeric one is refused too",
        "must be a float in [0, 1]" in str(
            _threshold_outcome('worker_no_change_ceiling = "half"')), True)

    # The live registry policy nests security_paths under readiness (arm-side audit input);
    # metrics must ACCEPT it (regression: run 29838473663 rejected the live policy) while
    # still rejecting genuinely unknown keys.
    secpaths_readiness = ('[repos."o/r"]\nenabled = true\n'
                          '[repos."o/r".readiness]\nkind = "from-agent-open"\n'
                          'security_paths = ["scripts/"]\n')
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write(secpaths_readiness)
        secpath = fh.name
    secpaths_error = ""
    try:
        load_targets(secpath)
    except MetricsError as exc:
        secpaths_error = str(exc)
    chk("readiness.security_paths accepted (live arm-audit key, run-29838473663 regression)",
        secpaths_error, "")
    os.unlink(secpath)

    malformed_readiness = ('[repos."o/r"]\nenabled = true\n'
                           '[repos."o/r".readiness]\nunrelated = "silently-defaulted-before"\n')
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write(malformed_readiness)
        readinesspath = fh.name
    readiness_error = ""
    try:
        load_targets(readinesspath)
    except MetricsError as exc:
        readiness_error = str(exc)
    chk("malformed readiness table rejected instead of silently defaulting",
        "readiness" in readiness_error, True)
    os.unlink(path)
    os.unlink(badpath)
    os.unlink(zeropath)
    os.unlink(readinesspath)


class _StubAPI:
    """In-memory contents API for the ring CAS test (the model-health _StubAPI shape). A GET that
    does not pin ?ref=ledger misses and a PUT that does not carry branch=ledger fails, so pointing
    the I/O back at the default branch turns the CAS suite red. `branch_missing` = absent ledger
    branch; `conflict_first` = a lost CAS race on the first PUT."""

    def __init__(self, seed=None, conflict_first=False, branch_missing=False):
        self._blob = None if seed is None else base64.b64encode(
            json.dumps({"snapshots": seed}).encode()).decode()
        self._sha = None if seed is None else "sha0"
        self._published_blob = None
        self._published_sha = None
        self._n = 0
        self._conflict_first = conflict_first
        self._branch_missing = branch_missing
        self.last_put_branch = None
        self.last_put_path = None

    def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
        if method == "GET" and "/git/ref/heads/" in path:
            if self._branch_missing or not path.endswith(f"/git/ref/heads/{LEDGER_REF}"):
                if allow_404:
                    return None
                raise MetricsError("missing branch")
            return {"object": {"sha": "ledger-tip"}}
        if method == "GET":
            if path.endswith(f"/contents/{PUBLISHED_PATH}?ref={LEDGER_REF}"):
                if self._published_blob is None or self._branch_missing:
                    if allow_404:
                        return None
                    raise MetricsError("missing")
                return {"content": self._published_blob, "sha": self._published_sha}
            if self._blob is None or self._branch_missing or not path.endswith(
                    f"/contents/{LEDGER_PATH}?ref={LEDGER_REF}"):
                if allow_404:
                    return None
                raise MetricsError("missing")
            return {"content": self._blob, "sha": self._sha}
        # PUT
        self.last_put_branch = body.get("branch")
        self.last_put_path = path.rsplit("/contents/", 1)[-1]
        if self.last_put_branch != LEDGER_REF:
            raise MetricsError("PUT did not pin the ledger branch")
        expected_sha = (self._published_sha if self.last_put_path == PUBLISHED_PATH else self._sha)
        if body.get("sha") != expected_sha:
            raise MetricsError("PUT did not carry the current blob SHA")
        self._n += 1
        if self._conflict_first and self._n == 1 and retry_conflict:
            raise MetricsConflict("stub conflict")
        if self.last_put_path == PUBLISHED_PATH:
            self._published_blob = body["content"]
            self._published_sha = f"sha{self._n}"
            sha = self._published_sha
        elif self.last_put_path == LEDGER_PATH:
            self._blob = body["content"]
            self._sha = f"sha{self._n}"
            sha = self._sha
        else:
            raise MetricsError("PUT targeted an unexpected ledger path")
        return {"content": {"sha": sha}}

    def snapshots(self):
        return json.loads(base64.b64decode(self._blob).decode())["snapshots"]

    @property
    def put_count(self):
        return self._n

    def published(self):
        return json.loads(base64.b64decode(self._published_blob).decode())


if __name__ == "__main__":
    try:
        sys.exit(main())
    except MetricsError as exc:
        print(f"::error::metrics: {exc}", file=sys.stderr)
        sys.exit(1)
