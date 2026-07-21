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
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

# Keep in sync with select-and-claim.py / groom.py / model-health.py LEDGER_REF (issue #28 data
# plane). Every write pins this ref; readers fail LOUD if the branch is missing.
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")
LEDGER_PATH = os.environ.get("REGISTRY_METRICS_PATH", "data/metrics-history.json")
PUBLISHED_PATH = "data/metrics.json"  # data-only ledger source for dashboard site/metrics.json
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

# --- per-target default thresholds; overridable in policy/repos.toml [repos.*].throughput ---
DEFAULT_THRESHOLDS = {
    "open_pr_alert_threshold": 20,   # backlog-growing needs prs_open above this
    "ready_alert_threshold": 40,     # ready-starved needs issues_ready above this
    "sustain_snapshots": 2,          # K: how many recent snapshots must agree (SUSTAINED, not spiky)
    "worker_success_floor": 0.5,     # worker-failing when success rate below this with >0 attempts
    "worker_min_samples": 3,         # worker-failing needs at least this many attempts (anti-noise)
    "recover_snapshots": 2,          # hysteresis: condition must be clear this many ticks to recover
}
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
def compute_target_metrics(counts):
    """Build one target's metric dict from raw collector COUNTS.

    `counts` (all ints, from REST list snapshots, immutable-window searches, or readiness) supplies:
      issues_open, issues_ready, issues_closed_1h, issues_closed_24h,
      prs_open, prs_draft, prs_opened_1h, prs_closed_1h, prs_merged_1h, prs_merged_24h,
      review_changes_backlog, needs_user_parked,
      review_lane_success_1h  (int: # of SUCCEEDED review-fix runs in the last hour),
      review_lane_runs_1h      (int: # of review-fix runs attempted in the last hour),
      worker_success_1h, worker_attempts_1h  (ints: worker run outcomes in the last hour)

    The instantaneous per-hour rates come straight from authoritative REST list windows; the REAL
    rate-OVER-TIME signal is the SUSTAINED (K-snapshot) condition that evaluate_alerts() reads off
    the ledger ring — so a single spiky hour never alarms. Derived:
    pr_open_rate, pr_close_rate (merged+closed), net_pr_flow, review_lane_health,
    worker_success_rate_1h. Pure — no network, no clock beyond what the caller stamps."""
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
        if key == "worker_success_floor":
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
    proc = subprocess.run(["gh"] + args, capture_output=True, text=True, env=env)
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


def collect_counts(repo, kind, token, now, orchestration=None):
    """Live raw counts from REST lists, lag-tolerant 24h search, and the readiness engine.

    `orchestration`, when given, is (orchestration_repo, orchestration_token): the repo that HOSTS
    this target's review-fix / worker workflows. sparq's review orchestration is driven cross-repo
    from the REGISTRY's own review-fix.yml/worker.yml, NOT from a sparq-hosted workflow — so the
    lane/worker health for a target must be read off the ORCHESTRATION repo's runs, filtered to
    that target, not off `repo`'s actions. When absent, lane/worker health is left unknown/null."""
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
        wattempts, wok = _worker_runs(orch_repo, repo, orch_token, now)
        if wattempts is not None:
            c["worker_attempts_1h"] = wattempts
            c["worker_success_1h"] = wok
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
    """(concluded, succeeded) run counts for `target`'s runs of `lane_names` on the ORCHESTRATION
    repo that CONCLUDED within the trailing window, or (None, None) if the runs API is unavailable.

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
        return (None, None)
    concluded, succeeded = 0, 0
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
    return (concluded, succeeded)


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
    return _orchestration_lane_runs(orch_repo, target, REVIEW_LANE_WORKFLOWS, token, now)


def _worker_runs(orch_repo, target, token, now):
    return _orchestration_lane_runs(orch_repo, target, WORKER_WORKFLOWS, token, now)


# =============================================================================================
# ledger time-series I/O (CAS over the contents API, pinned to LEDGER_REF) — model-health pattern
# =============================================================================================
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
            raise MetricsError(f"GitHub API {method} failed with HTTP {exc.code}") from exc
        except (URLError, TimeoutError) as exc:
            raise MetricsError("GitHub API request failed") from exc
        try:
            return json.loads(raw or b"null")
        except json.JSONDecodeError as exc:
            raise MetricsError("GitHub API returned malformed JSON") from exc


def ledger_read_path(registry_repo):
    return f"/repos/{registry_repo}/contents/{LEDGER_PATH}?ref={LEDGER_REF}"


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
    `site/metrics.json` in its generated artifact. This writer never invents a second deployment."""
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


ALERT_CLASSES = (BACKLOG_GROWING, REVIEW_LANE_STALLED, READY_STARVED, WORKER_FAILING)

# The per-class predicate factory used both to FIRE (sustained over K) and to RECOVER (clear over
# recover_snapshots). Keeping one source of truth means the recovery test can never drift from the
# fire test — a class recovers exactly when its OWN fire predicate has been false long enough.
_CLASS_PRED = {
    BACKLOG_GROWING: _backlog_growing_pred,
    REVIEW_LANE_STALLED: _review_stalled_pred,
    READY_STARVED: _ready_starved_pred,
    WORKER_FAILING: _worker_failing_pred,
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


def build_snapshot(targets, token_map, default_token, now, orchestration=None):
    """Collect live counts for every target and assemble the snapshot (no ledger write here). Each
    target is read with its owner's token so a cross-owner search is never attempted on the wrong
    token; a target whose token is missing is SKIPPED loudly (never silently zero) — a skipped
    target has NO row, which the recovery reconciler uses to avoid closing its alerts on no
    evidence. `orchestration` = (orch_repo, orch_token): the repo hosting the review-fix/worker
    workflows, read for per-target lane/worker health."""
    generated_at = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = {"generated_at": generated_at, "_ts": int(now), "schema_version": 1, "targets": {}}
    for repo, kind, _thr in targets:
        tok = _token_for(repo, token_map, default_token)
        if not tok:
            print(f"::warning::metrics: no token for {repo} — skipping (not counted as zero)")
            continue
        counts = collect_counts(repo, kind, tok, now, orchestration=orchestration)
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
    snapshot = build_snapshot(targets, token_map, registry_token, now, orchestration=orchestration)

    api = GitHubAPI(registry_token)
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
def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    _test_metric_computation(chk)
    _test_rate_derivation(chk)
    _test_alert_rules(chk)
    _test_alert_mutation_nonvacuous(chk)
    _test_list_api_contract(chk)
    _test_event_list_contract(chk)
    _test_collection_contract(chk)
    _test_run_windowing(chk)
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
            {"path": ".github/workflows/review-fix.yml",
             "display_title": "review-fix fix sparq-org/sparq#3400", "name": "review-fix",
             "status": "completed", "conclusion": "failure",
             "updated_at": _iso_ago(600, now), "created_at": _iso_ago(1200, now)},
            {"path": ".github/workflows/worker.yml",
             "display_title": "worker sparq-org/sparq claim=aaa", "name": "worker",
             "status": "completed", "conclusion": "success",
             "updated_at": _iso_ago(300, now), "created_at": _iso_ago(900, now)},
            {"path": ".github/workflows/worker.yml",
             "display_title": "worker sparq-org/sparq claim=bbb", "name": "worker",
             "status": "completed", "conclusion": "failure",
             "updated_at": _iso_ago(200, now), "created_at": _iso_ago(800, now)},
            {"path": ".github/workflows/worker.yml",
             "display_title": "worker sparq-org/sparq claim=ccc", "name": "worker",
             "status": "in_progress", "conclusion": None,
             "updated_at": _iso_ago(60, now), "created_at": _iso_ago(120, now)},
            {"path": ".github/workflows/worker.yml",   # a DIFFERENT target — must not count for sparq
             "display_title": "worker other/repo claim=zzz", "name": "worker",
             "status": "completed", "conclusion": "failure",
             "updated_at": _iso_ago(100, now), "created_at": _iso_ago(150, now)},
            {"path": ".github/workflows/ci.yml",        # unrelated workflow — ignored
             "display_title": "ci sparq-org/sparq", "name": "ci",
             "status": "completed", "conclusion": "failure",
             "updated_at": _iso_ago(50, now), "created_at": _iso_ago(90, now)},
        ],
    }

    def fake_paginate(repo, since_iso, token, now_, page_cap=10):
        return list(runs_by_target.get("sparq-org/sparq", []))

    try:
        _search_count = fake_search
        _list_open_rows = fake_list
        _list_event_rows = fake_event_list
        _ready_count = lambda *args: 86   # drainable candidates, NOT the 4-wide frontier
        _paginate_runs = fake_paginate
        counts = collect_counts("sparq-org/sparq", READY_STATUS_ENGINE, "tok", now,
                                orchestration=("jeswr/agent-account-registry", "regtok"))
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
        m = compute_target_metrics(counts)
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
                                        orchestration=("jeswr/agent-account-registry", "regtok"))
        chk("collect: no orchestration runs => review_lane_health unknown",
            compute_target_metrics(counts_no_orch)["review_lane_health"], "unknown")
    finally:
        _search_count, _ready_count, _paginate_runs, _list_open_rows, _list_event_rows = (
            real_sc, real_rc, real_pr, real_lr, real_er)
    _ = since  # documented window boundary; the fake ignores it


def _test_run_windowing(chk):
    """Run attribution + completion-time windowing + idle-vs-stalled counting (should #10)."""
    now = 1_000_000
    since = _iso_ago(3600, now)
    # target attribution: only runs whose run-name mentions the target AND match a lane name.
    rf = {"path": ".github/workflows/review-fix.yml",
          "display_title": "review-fix fix sparq-org/sparq#1", "name": "review-fix"}
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
            (0, 0))
        _paginate_runs = lambda *a, **k: None
        chk("runs API unavailable => (None, None) — health stays unknown",
            _orchestration_lane_runs("o/r", "sparq-org/sparq", REVIEW_LANE_WORKFLOWS, "t", now),
            (None, None))
    finally:
        _paginate_runs = real_pr


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
