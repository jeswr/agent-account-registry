#!/usr/bin/env python3
# [OPUS-5] Per-tick dispatch telemetry: the record that makes the dispatcher's own bottleneck
# attributable without a human running a script every tick.
"""dispatch-telemetry.py — record, per dispatch tick and per target, the three quantities the
crate-region-parallelism Gate A criterion is written against, plus a census of the whole open-issue
population so a MISSING EDGE shows up as a growing bucket instead of hiding in a remainder.

Gate A (research/crate-region-parallelism.md §8, sparq):

    Instrument the dispatcher to record, per tick, `frontier_width`, `realised_dispatches`, and
    `conflict_deferrals` attributed by held area. Open the gate only when realised dispatches ≥
    ~80% of frontier width for a sustained period.

Nothing recorded those. `data/metrics.json` carried `issues_ready`, `worker_attempts_1h` and
`worker_success_rate_1h` — none of the three. An unevaluable gate is a permanently closed gate.

WHERE THE RECORD LIVES, AND WHY
  `data/dispatch-telemetry.json` on the **`ledger` data-plane branch**, as a bounded rolling ring,
  written with the same contents-API CAS + idempotency pattern `model-health.py` uses for
  `data/model-health.json` and `metrics.py` uses for `data/metrics-history.json`. No new store is
  invented: `ledger-invariant.py` already whitelists `data/<name>.json`, master permanently rejects
  protected-path contents PUTs (registry #96), and mutable data belongs on the ledger branch.

  It is deliberately NOT the workflow log. GitHub's secret masker replaces `{` and `}` with `***`
  in log output — MEASURED on run 30222895098: 159 lines carry `***`, and the corruption reaches
  genuine RUNTIME stdout, not just the echoed script source (e.g. a self-test line printing
  `frozenset({'live', 'unproven'})` came out as `frozenset(***'live', 'unproven'***)`). Any JSON
  emitted to the log as a telemetry channel is destroyed. The one line this module prints to the
  log is therefore BRACE-FREE `key=value` text (`render_log_line`), asserted by --self-test.

PLANNED VS REALISED
  The whole point of the gate is that a plan row which never becomes a run is a failure. This
  record keeps the chain separate and never collapses it:

    open_issues  ->  candidates (drainable)  ->  frontier_width (compute_ready concurrency width)
                 ->  planned_rows (rows CLAIM's worker lane actually saw)
                 ->  realised_dispatches (rows whose worker run was LAUNCHED)

  `unrealised_rows = planned_rows - realised_dispatches` is derived and reported. `realised` counts
  a confirmed workflow launch. HONEST LIMIT: a launched worker that then no-ops is still counted as
  realised here — the dispatcher cannot observe the worker's outcome inside its own tick. The
  complementary signal is `worker_success_rate_1h` on the metrics feed; this record does not claim
  to measure worker yield.

BUCKETS MUST SUM
  Per-stage success rates structurally cannot express a missing edge (registry #753: PRs re-skipped
  ~135 times over 45h produced no label, no error and no count). `census()` therefore partitions
  the ENTIRE open-issue population into disjoint buckets and carries `unclassified` explicitly, so
  a state with no exit is a growing bucket rather than an unlabelled remainder.

NO DOUBLE COUNTING
  Every record is keyed by `(run_id, repo)` and `append_record` is idempotent on that key
  (registry #737: a `sort|uniq -c` over repeated emissions inflated a count 4x). A replayed
  emission is a confirmed no-op, asserted by --self-test.
"""
import argparse
import base64
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger_retry  # noqa: E402  — sibling helper, same pattern as model-health.py

# Keep in sync with model-health.py / metrics.py / groom.py LEDGER_REF (issue #28 data plane).
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")
LEDGER_PATH = os.environ.get("REGISTRY_DISPATCH_TELEMETRY_PATH", "data/dispatch-telemetry.json")
# ~10 min cadence x 2 targets => 288 records/day/target. 480 keeps ~40h of both targets, which is
# more than the sustain window Gate A needs and keeps the blob small.
MAX_RECORDS = int(os.environ.get("REGISTRY_DISPATCH_TELEMETRY_RING", "480"))
CAS_RETRIES = 8
# Bounded cardinality: the record is written forever, and `area:` values are target-controlled.
MAX_AREA_KEYS = 25
OTHER_AREA = "__other__"
UNATTRIBUTED_AREA = "__unattributed__"

# Gate A opens at realised >= 80% of frontier width, sustained.
GATE_A_RATIO = 0.8
GATE_A_SUSTAIN_TICKS = 12

REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$")
RUN_ID_RE = re.compile(r"^[0-9]+\.[0-9]+$")
# The attribution line the target readiness engine emits for a package-serialised candidate:
#   `conflict #4318: area bench held by pr#4318`
CONFLICT_LINE_RE = re.compile(r"^conflict #(\d+): area (\S+) held by (\S+)$")


class TelemetryError(RuntimeError):
    """A concise, credential-free operational error."""


class TelemetryConflict(TelemetryError):
    """A retryable contents-API compare-and-swap conflict."""


# =================================================================================================
# PURE: census bucketing
# =================================================================================================
# `exclusion_reason()` returns prose that embeds VARIABLE text (the offending label, a blocker
# count). Used raw as a bucket key that is unbounded cardinality in a forever-growing ring, so it is
# normalised to a bounded key here. This is PRESENTATION normalisation of the readiness engine's own
# verdict — it never re-derives the predicate (that would be the third-divergent-copy defect
# ready-issues.py warns about); the reason string always comes from the engine.
_REASON_RULES = (
    ("no status:ready", "no-attestation"),
    ("kind:epic", "epic"),
    ("gated by ", "gated"),
    ("busy: ", "busy"),
    ("parked: ", "parked"),
    ("no single valid priority", "invalid-priority"),
    ("no role", "no-role"),
    ("open blocker", "blocked"),
)


def normalise_reason(reason):
    """Bounded census key for one `exclusion_reason()` verdict.

    A reason this table does not recognise becomes `other` rather than minting an unbounded key —
    and `other` growing is itself the signal that the readiness engine gained a verdict this census
    has not been taught, which is exactly the missing-edge shape the census exists to expose.
    """
    text = str(reason or "")
    for needle, key in _REASON_RULES:
        if needle in text:
            return f"excluded:{key}"
    return "excluded:other"


def _cap_areas(counter):
    """Bound the per-area attribution to MAX_AREA_KEYS keys, rolling the tail into `__other__`.

    Total is PRESERVED — a cap that dropped counts would break the sum guarantee.
    """
    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    if len(items) <= MAX_AREA_KEYS:
        return {area: count for area, count in items if count}
    head = items[:MAX_AREA_KEYS]
    tail_total = sum(count for _area, count in items[MAX_AREA_KEYS:])
    capped = {area: count for area, count in head}
    if tail_total:
        capped[OTHER_AREA] = capped.get(OTHER_AREA, 0) + tail_total
    return capped


def parse_conflict_areas(lines, total):
    """Attribute `total` conflict deferrals to the areas that HELD them.

    `lines` are the readiness engine's own attribution lines. Anything that does not parse — or any
    shortfall against the authoritative `total` (which is computed by subtraction, never by counting
    lines) — lands in `__unattributed__`, so attribution loss is VISIBLE and the areas still sum to
    `total`. Returns (areas, attributed_count).
    """
    counts = {}
    attributed = 0
    for line in lines or ():
        match = CONFLICT_LINE_RE.match(str(line).strip())
        if match is None:
            continue
        area = match.group(2)
        counts[area] = counts.get(area, 0) + 1
        attributed += 1
    total = max(0, int(total))
    # Never let parsed attribution exceed the authoritative total (a duplicated line must not
    # inflate a bucket — registry #737).
    if attributed > total:
        counts, attributed = {}, 0
    areas = _cap_areas(counts)
    shortfall = total - attributed
    if shortfall:
        areas[UNATTRIBUTED_AREA] = areas.get(UNATTRIBUTED_AREA, 0) + shortfall
    return areas, attributed


def census(open_numbers, admitted_numbers, exclusion_reasons, candidate_numbers,
           frontier_numbers, conflict_areas):
    """Partition the WHOLE open-issue population into disjoint, summing buckets.

    Inputs are all sets/dicts of issue numbers, so a repeated emission of the same issue cannot
    inflate a bucket (registry #737 — distinct entities, counted once).

      open_numbers        every OPEN non-PR issue in the target snapshot (the population)
      admitted_numbers    those that survived PLAN's trust + linked-PR filter
      exclusion_reasons   {number: reason} from the readiness engine, for admitted issues
      candidate_numbers   admitted issues the label gate accepts (reason is None)
      frontier_numbers    candidates the package partition admitted this tick
      conflict_areas      {area: count} attribution for the conflict-deferred candidates

    Classification order mirrors what the dispatcher actually does: the trust/linked filter runs
    first (in-progress rows are exempted from it upstream and therefore land in `excluded:busy`),
    then the label gate, then the package partition.

    An admitted non-candidate for which the readiness engine supplied NO verdict is deliberately
    left UNBUCKETED and falls into the residual: fabricating an `excluded:other` for it would hide
    exactly the missing instrumentation this census exists to expose.

    Returns {"buckets": {...}, "total": int, "population": int, "unclassified": int}. `unclassified`
    is the residual and is ALWAYS emitted, at zero too: a bucketing that stops covering a state must
    show as a gap, not silently rebalance.
    """
    population = set(open_numbers)
    admitted = set(admitted_numbers) & population
    candidates = set(candidate_numbers) & admitted
    frontier = set(frontier_numbers) & candidates

    buckets = {"frontier": len(frontier)}
    buckets["trust-or-linked-excluded"] = len(population - admitted)
    for number in sorted(admitted - candidates):
        reason = (exclusion_reasons or {}).get(number)
        if reason is None:                     # no engine verdict -> residual, never invented
            continue
        key = normalise_reason(reason)
        buckets[key] = buckets.get(key, 0) + 1
    conflict_total = sum(int(v) for v in (conflict_areas or {}).values())
    if conflict_total:
        buckets["conflict-deferred"] = conflict_total
    classified = sum(buckets.values())
    unclassified = len(population) - classified
    buckets["unclassified"] = unclassified
    return {"buckets": {k: v for k, v in buckets.items() if v or k == "unclassified"},
            "total": classified + unclassified,
            "population": len(population),
            "unclassified": unclassified}


# =================================================================================================
# PURE: the record
# =================================================================================================
def build_record(repo, run_id, frontier, dispatch, now):
    """One tick record for one target. PURE.

    `frontier` is the PLAN-side census document for this repo; `dispatch` is the CLAIM-side
    per-repo worker-lane counts {planned, launched}. `realised_dispatches` is the LAUNCHED count —
    a planned row that did not launch is `unrealised_rows`, never a dispatch.
    """
    frontier = frontier if isinstance(frontier, dict) else {}
    dispatch = dispatch if isinstance(dispatch, dict) else {}

    def _n(source, key):
        value = source.get(key, 0)
        return int(value) if isinstance(value, int) and value >= 0 else 0

    def _areas(key):
        value = frontier.get(key)
        return ({str(k): int(v) for k, v in value.items() if isinstance(v, int) and v > 0}
                if isinstance(value, dict) else {})

    planned_rows = _n(dispatch, "planned")
    realised = min(_n(dispatch, "launched"), planned_rows)
    frontier_width = _n(frontier, "frontier_width")
    areas = _areas("conflict_by_area")
    census_doc = frontier.get("census")
    census_doc = census_doc if isinstance(census_doc, dict) else {}
    # THE DISPATCH CHAIN, as disjoint legs that add up. The gap between "the frontier was wide" and
    # "nothing launched" is where the real bottleneck lives (measured: run 30222895098 dropped 30
    # rows at the assemble leg and ended `lane worker: planned=0 launched=0`, with no counter
    # anywhere on it), so each leg is named and the residual is carried explicitly rather than
    # absorbed. `route_rejections` is the frontier rows plan_dispatch refused (ambiguous/unknown
    # role) — derived, never assumed zero.
    before_assemble = _n(frontier, "plan_rows_before_assemble")
    assembler_deferrals = _n(frontier, "assembler_deferrals")
    entering = frontier_width + _n(frontier, "deferred_retry_width")
    chain = {
        "frontier_and_retry_rows": entering,
        "route_rejections": max(0, entering - before_assemble) if before_assemble else 0,
        "assembler_deferrals": assembler_deferrals,
        "claim_deferrals": max(0, before_assemble - assembler_deferrals - planned_rows)
                           if before_assemble else 0,
        "realised_dispatches": realised,
        "unrealised_planned_rows": planned_rows - realised,
    }
    chain["unaccounted"] = entering - (
        chain["route_rejections"] + chain["assembler_deferrals"] + chain["claim_deferrals"]
        + chain["realised_dispatches"] + chain["unrealised_planned_rows"])
    return {
        "ts": int(now),
        "run_id": str(run_id),
        "repo": str(repo),
        "open_issues": _n(frontier, "open_issues"),
        "candidates": _n(frontier, "candidates"),
        "frontier_width": frontier_width,
        "deferred_retry_width": _n(frontier, "deferred_retry_width"),
        "planned_rows": planned_rows,
        "realised_dispatches": realised,
        "unrealised_rows": planned_rows - realised,
        "conflict_deferrals": _n(frontier, "conflict_deferrals"),
        "conflict_by_area": areas,
        "plan_rows_before_assemble": before_assemble,
        "assembler_deferrals": assembler_deferrals,
        "assembler_by_area": _areas("assembler_by_area"),
        "chain": chain,
        "census": {str(k): int(v) for k, v in (census_doc.get("buckets") or {}).items()
                   if isinstance(v, int)},
        "census_total": _n(census_doc, "total"),
        "census_unclassified": int(census_doc.get("unclassified", 0) or 0),
        "attribution": ("exact" if frontier.get("attribution") == "exact" else "unavailable"),
    }


def render_log_line(record):
    """The ONE log line this module prints — deliberately BRACE-FREE.

    GitHub replaces `{` and `}` with `***` in log output (measured: run 30222895098, 159 corrupted
    lines, runtime stdout included). Emitting the record as JSON to the log would destroy it, so the
    log carries a flat key=value summary and the ledger carries the record.
    """
    line = (
        "dispatch-telemetry "
        f"repo={record.get('repo', '?')} "
        f"frontier_width={record.get('frontier_width', 0)} "
        f"planned_rows={record.get('planned_rows', 0)} "
        f"realised_dispatches={record.get('realised_dispatches', 0)} "
        f"unrealised_rows={record.get('unrealised_rows', 0)} "
        f"conflict_deferrals={record.get('conflict_deferrals', 0)} "
        f"assembler_deferrals={record.get('assembler_deferrals', 0)} "
        f"chain_unaccounted={(record.get('chain') or {}).get('unaccounted', 0)} "
        f"census_total={record.get('census_total', 0)} "
        f"census_unclassified={record.get('census_unclassified', 0)} "
        f"attribution={record.get('attribution', 'unavailable')}"
    )
    if "{" in line or "}" in line:            # fail closed rather than emit a maskable line
        raise TelemetryError("telemetry log line must not contain braces (secret-mask corruption)")
    return line


def gate_a_state(records, repo, ratio=GATE_A_RATIO, sustain=GATE_A_SUSTAIN_TICKS):
    """Evaluate Gate A from the ring: realised >= `ratio` * frontier_width, sustained.

    Ticks with `frontier_width == 0` carry no information about whether the frontier is the limit,
    so they are EXCLUDED from the window rather than counted as passing — counting an empty frontier
    as a pass is exactly how a gate opens on no evidence. Fewer than `sustain` informative ticks =>
    open=False with `reason="insufficient-samples"`.
    """
    rows = [r for r in records
            if isinstance(r, dict) and r.get("repo") == repo
            and isinstance(r.get("frontier_width"), int) and r["frontier_width"] > 0]
    rows.sort(key=lambda r: int(r.get("ts", 0) or 0))
    window = rows[-sustain:]
    ratios = [round(int(r.get("realised_dispatches", 0) or 0) / r["frontier_width"], 4)
              for r in window]
    latest = ratios[-1] if ratios else None
    if len(window) < sustain:
        return {"open": False, "reason": "insufficient-samples", "threshold": ratio,
                "sustain_ticks": sustain, "observed_ticks": len(window),
                "latest_ratio": latest, "min_ratio": min(ratios) if ratios else None}
    worst = min(ratios)
    return {"open": worst >= ratio,
            "reason": "sustained" if worst >= ratio else "below-threshold",
            "threshold": ratio, "sustain_ticks": sustain, "observed_ticks": len(window),
            "latest_ratio": latest, "min_ratio": worst}


def latest_by_repo(records):
    """Newest record per repo (highest ts, ties broken by list order). PURE."""
    newest = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        repo = record.get("repo")
        if not isinstance(repo, str):
            continue
        current = newest.get(repo)
        if current is None or int(record.get("ts", 0) or 0) >= int(current.get("ts", 0) or 0):
            newest[repo] = record
    return newest


# =================================================================================================
# PURE: ledger validation + pruning
# =================================================================================================
_REQUIRED_FIELDS = ("ts", "run_id", "repo", "frontier_width", "realised_dispatches",
                    "conflict_deferrals")


def _valid_record(record):
    if not isinstance(record, dict):
        return False
    if not isinstance(record.get("ts"), int) or record["ts"] < 0:
        return False
    if not isinstance(record.get("repo"), str) or not REPO_RE.match(record["repo"]):
        return False
    if not isinstance(record.get("run_id"), str) or not RUN_ID_RE.match(record["run_id"]):
        return False
    for field in _REQUIRED_FIELDS[3:]:
        if not isinstance(record.get(field), int) or record[field] < 0:
            return False
    for field in ("conflict_by_area", "census"):
        value = record.get(field, {})
        if not isinstance(value, dict) or any(
                not isinstance(k, str) or not isinstance(v, int) for k, v in value.items()):
            return False
    return True


def validate_ledger(document):
    """Return the record list, or raise. A malformed blob fails LOUD — never silently empty."""
    if not isinstance(document, dict) or not isinstance(document.get("records"), list):
        raise ValueError("dispatch-telemetry ledger must be an object with a records list")
    for record in document["records"]:
        if not _valid_record(record):
            raise ValueError("dispatch-telemetry ledger holds a malformed record")
    return document["records"]


def prune(records, now):
    """Newest-first cap to MAX_RECORDS, stored oldest->newest."""
    kept = sorted((r for r in records if _valid_record(r)),
                  key=lambda r: (int(r["ts"]), r["repo"], r["run_id"]))
    del now
    return kept[-MAX_RECORDS:]


def record_identity(record):
    """Idempotency key: one tick, one target, one record.

    `(run_id, repo)`. The run_id carries the PRODUCING job's attempt (`RUN_ID.RUN_ATTEMPT`), so a
    re-run of the recorder replays the same key and dedups, while a genuine re-execution stamps a
    fresh attempt and legitimately appends. Returns None when the key is incomplete — an unkeyed
    record always appends (fail toward recording), and validation rejects it upstream anyway.
    """
    if not isinstance(record, dict):
        return None
    run_id, repo = record.get("run_id"), record.get("repo")
    if not isinstance(run_id, str) or not run_id or not isinstance(repo, str) or not repo:
        return None
    return (run_id, repo)


# =================================================================================================
# Ledger I/O (contents-API CAS, same shape as model-health.append_record)
# =================================================================================================
class GitHubAPI:
    """Minimal contents-API client. Local, so --self-test stays import-light and token-free."""

    def __init__(self, token):
        from urllib.request import Request
        if not token:
            raise TelemetryError("registry token is missing")
        self._token = token
        self._Request = Request

    def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
        from urllib.error import HTTPError, URLError
        from urllib.request import urlopen
        if not path.startswith("/") or "\n" in path or "\r" in path:
            raise TelemetryError("unsafe GitHub API path")
        payload = json.dumps(body).encode() if body is not None else None
        request = self._Request(
            "https://api.github.com" + path, data=payload, method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "registry-dispatch-telemetry",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if payload is not None else {}),
            })
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as exc:
            if allow_404 and exc.code == 404:
                return None
            if retry_conflict and ledger_retry.is_cas_conflict(
                    f"HTTP {exc.code}", create=body is not None and "sha" not in (body or {})):
                raise TelemetryConflict("dispatch-telemetry ledger CAS conflict") from exc
            raise TelemetryError(f"GitHub API {method} failed with HTTP {exc.code}") from exc
        except (URLError, TimeoutError) as exc:
            raise TelemetryError("GitHub API request failed") from exc
        try:
            return json.loads(raw or b"null")
        except json.JSONDecodeError as exc:
            raise TelemetryError("GitHub API returned malformed JSON") from exc


def ledger_read_path(registry_repo):
    return f"/repos/{registry_repo}/contents/{LEDGER_PATH}?ref={LEDGER_REF}"


def read_ledger(api, registry_repo):
    """(records, sha). A missing FILE on a present ledger branch seeds an empty ring; a missing
    ledger BRANCH fails LOUD (issue #28) — silently-empty hides the outage the ref exists for."""
    result = api.request("GET", ledger_read_path(registry_repo), allow_404=True)
    if result is None:
        if api.request("GET", f"/repos/{registry_repo}/git/ref/heads/{LEDGER_REF}",
                       allow_404=True) is None:
            raise TelemetryError(
                f"ledger branch '{LEDGER_REF}' is missing — create it from master "
                "(see data/README.md) before recording dispatch telemetry")
        return [], None
    if not isinstance(result, dict):
        raise TelemetryError("dispatch-telemetry ledger response is malformed")
    content, sha = result.get("content"), result.get("sha")
    if not isinstance(content, str) or not isinstance(sha, str) or not sha:
        raise TelemetryError("dispatch-telemetry ledger metadata is malformed")
    try:
        document = json.loads(base64.b64decode("".join(content.split()), validate=True).decode())
    except (ValueError, UnicodeDecodeError) as exc:
        raise TelemetryError("dispatch-telemetry ledger content is malformed") from exc
    return validate_ledger(document), sha


def _sleep_backoff(attempt):
    ledger_retry.sleep_backoff(attempt)


def append_records(api, registry_repo, new_records, now, retries=CAS_RETRIES):
    """CAS-append records for one tick, IDEMPOTENTLY on (run_id, repo).

    A replayed emission is a confirmed no-op — a duplicate would inflate every bucket it touches
    (registry #737). Returns the ring size after the write.
    """
    for attempt in range(retries):
        if attempt:
            _sleep_backoff(attempt)
        records, sha = read_ledger(api, registry_repo)
        known = {record_identity(r) for r in records}
        fresh = [r for r in new_records
                 if record_identity(r) is not None and record_identity(r) not in known]
        if not fresh:
            return len(prune(records, now))
        records = prune(records + fresh, now)
        try:
            validate_ledger({"records": records})
        except ValueError as exc:
            raise TelemetryError(
                f"refusing to write a malformed dispatch-telemetry record: {exc}") from exc
        encoded = base64.b64encode(
            (json.dumps({"records": records}, indent=1) + "\n").encode()).decode()
        body = {"message": f"dispatch telemetry ({len(fresh)} tick record(s))",
                "content": encoded,
                "branch": LEDGER_REF}
        if sha:
            body["sha"] = sha
        try:
            result = api.request(
                "PUT", f"/repos/{registry_repo}/contents/{LEDGER_PATH}", body, retry_conflict=True)
        except TelemetryConflict:
            continue
        if isinstance(result, dict) and isinstance(result.get("content"), dict):
            return len(records)
    raise TelemetryError("dispatch-telemetry ledger CAS conflicts did not settle")


# =================================================================================================
# CLI
# =================================================================================================
def _read_json(path, what):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise TelemetryError(f"cannot read the {what} document") from exc


def tick_records(frontier_doc, summary_doc, run_id, now):
    """Every per-repo record for one tick. PURE.

    A repo present in the PLAN census but absent from the CLAIM per-repo counts is recorded with
    realised=0 — that is the planned-but-unrealised case the gate exists to catch, and dropping it
    would silently improve the ratio.
    """
    repos = (frontier_doc or {}).get("repositories")
    repos = repos if isinstance(repos, dict) else {}
    by_repo = (summary_doc or {}).get("by_repo")
    by_repo = by_repo if isinstance(by_repo, dict) else {}
    return [build_record(repo, run_id, repos[repo], by_repo.get(repo, {}), now)
            for repo in sorted(repos)]


def cmd_record(args):
    frontier_doc = _read_json(args.frontier, "PLAN frontier census")
    summary_doc = _read_json(args.summary, "CLAIM dispatch summary") if args.summary else {}
    records = tick_records(frontier_doc, summary_doc, args.run_id, int(time.time()))
    if not records:
        print("dispatch-telemetry no-repositories=1")
        return 0
    for record in records:
        print(render_log_line(record))
        if record["census_unclassified"]:
            print(f"::warning::dispatch-telemetry {record['repo']}: "
                  f"{record['census_unclassified']} open issue(s) fell in NO census bucket — "
                  "a dispatch state has no exit edge")
    api = GitHubAPI(os.environ.get("GH_TOKEN") or os.environ.get("REGISTRY_GH_TOKEN"))
    size = append_records(api, args.registry_repo, records, int(time.time()))
    print(f"dispatch-telemetry ring-size={size} written={len(records)}")
    return 0


# =================================================================================================
# self-test
# =================================================================================================
def _workflow_block(path, step_id, marker):
    """The dedented python between `# >>> <marker>` and `# <<< <marker>` inside the ONE workflow
    step whose `id:` is `step_id`. Raises on anything it cannot resolve uniquely — an assertion that
    cannot find its target must FAIL, never pass vacuously. (Same extractor shape as
    dispatch-plan.py's; the YAML seam is where vacuity lives, so the block is EXECUTED, not
    pattern-matched.)"""
    lines = Path(path).read_text(encoding="utf-8").split("\n")
    ids = [i for i, line in enumerate(lines) if line.strip() == f"id: {step_id}"]
    if len(ids) != 1:
        raise AssertionError(f"expected one workflow step `id: {step_id}`, found {len(ids)}")
    starts = [i for i in range(ids[0], -1, -1) if lines[i].lstrip().startswith("- ")]
    indent = len(lines[starts[0]]) - len(lines[starts[0]].lstrip())
    end = len(lines)
    for i in range(starts[0] + 1, len(lines)):
        if not lines[i].strip():
            continue
        here = len(lines[i]) - len(lines[i].lstrip())
        if here < indent or (here == indent and lines[i].lstrip().startswith("- ")):
            end = i
            break
    block = lines[starts[0]:end]
    opens = [i for i, line in enumerate(block) if line.strip().startswith(f"# >>> {marker}")]
    closes = [i for i, line in enumerate(block) if line.strip() == f"# <<< {marker}"]
    if len(opens) != 1 or len(closes) != 1 or closes[0] <= opens[0]:
        raise AssertionError(
            f"step `id: {step_id}` must contain exactly one `# >>> {marker}` ... `# <<< {marker}` "
            f"pair, found {len(opens)}/{len(closes)} — refusing")
    body = [line for line in block[opens[0] + 1:closes[0]]
            if line.strip() and not line.lstrip().startswith("#")]
    if not body:
        raise AssertionError(f"the `{marker}` block extracted to nothing — refusing")
    pad = min(len(line) - len(line.lstrip()) for line in body)
    source = "\n".join(line[pad:] for line in body)
    compile(source, f"<{marker}>", "exec")
    return source


def _load_dispatch_claim():
    """The REAL `scripts/dispatch-claim.py`, loaded the way dispatch.yml itself loads it.

    Self-test-only. The assemble-leg seam assertions run the production `filter_busy_area_items`
    rather than a stub: a stub with no holder concept cannot tell "attributed to the reservation
    that caused the drop" apart from "attributed to the dropped row's own crate", which is exactly
    how the wrong keying shipped (registry #756 review / #758 mutant M8)."""
    import importlib.util   # self-test-only, same lazy-import discipline as the yaml import
    path = Path(__file__).resolve().parent / "dispatch-claim.py"
    spec = importlib.util.spec_from_file_location("registry_dispatch_claim_telemetry", path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path} — the assemble-leg seam test has no filter")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _workflow_step_text(path, step_id, strip_comments=False):
    """The yaml of the ONE step with `id: <step_id>`, for asserting its `if:`/env/path wiring.

    `strip_comments=True` drops `#` lines FIRST. This is load-bearing, not tidiness: the artifact
    upload step's own comment names `frontier-census.json`, so a substring check over the raw step
    stayed green after the path line was deleted — a claim in a comment satisfying a wiring check,
    the same vacuity class dispatch-plan.py already guards against. Measured: mutant M9 survived
    until this argument existed.
    """
    text = Path(path).read_text(encoding="utf-8")
    if strip_comments:
        text = "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))
    lines = text.split("\n")
    ids = [i for i, line in enumerate(lines) if line.strip() == f"id: {step_id}"]
    if len(ids) != 1:
        raise AssertionError(f"expected one workflow step `id: {step_id}`, found {len(ids)}")
    starts = [i for i in range(ids[0], -1, -1) if lines[i].lstrip().startswith("- ")]
    indent = len(lines[starts[0]]) - len(lines[starts[0]].lstrip())
    end = len(lines)
    for i in range(starts[0] + 1, len(lines)):
        if not lines[i].strip():
            continue
        here = len(lines[i]) - len(lines[i].lstrip())
        if here < indent or (here == indent and lines[i].lstrip().startswith("- ")):
            end = i
            break
    return "\n".join(lines[starts[0]:end])


def _self_test():   # noqa: C901 — one flat assertion table, deliberately
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    # ---- census: the buckets SUM to the population -------------------------------------------
    # A 10-issue board: 2 untrusted/linked, 4 label-excluded (one per class), 4 candidates of which
    # 1 is on the frontier and 3 are conflict-deferred.
    population = set(range(1, 11))
    admitted = population - {1, 2}
    reasons = {3: "no status:ready attestation", 4: "gated by needs:user",
               5: "busy: status:in-progress", 6: "2 open blocker(s)"}
    candidates = {7, 8, 9, 10}
    frontier = {7}
    areas = {"bench": 2, "ci": 1}
    doc = census(population, admitted, reasons, candidates, frontier, areas)
    chk("[buckets-sum] the census partitions the WHOLE open population",
        (doc["total"], doc["population"], doc["unclassified"]), (10, 10, 0))
    chk("[buckets-sum] every bucket is named and they add up",
        (sum(doc["buckets"].values()), sorted(doc["buckets"])),
        (10, ["conflict-deferred", "excluded:blocked", "excluded:busy", "excluded:gated",
              "excluded:no-attestation", "frontier", "trust-or-linked-excluded", "unclassified"]))
    # NON-VACUOUS: drop one bucket's contribution (the missing-edge shape) and the residual MUST
    # appear as `unclassified` rather than the totals quietly rebalancing.
    gap = census(population, admitted, reasons, candidates, frontier, {"bench": 1, "ci": 1})
    chk("[buckets-sum] a state with no exit shows as a GAP, not a silent rebalance",
        (gap["unclassified"], gap["total"], sum(gap["buckets"].values())), (1, 10, 10))
    chk("[buckets-sum] `unclassified` is emitted even at zero (never a silent healthy census)",
        "unclassified" in doc["buckets"], True)

    # ---- no double counting -------------------------------------------------------------------
    dup = census(population, admitted, reasons, list(candidates) + list(candidates),
                 [7, 7, 7], areas)
    chk("[no-double-count] repeated issue emissions do not inflate a bucket",
        (dup["buckets"]["frontier"], dup["total"], dup["unclassified"]), (1, 10, 0))
    # ...and a duplicated ATTRIBUTION line cannot inflate an area beyond the authoritative total.
    lines = ["conflict #11: area bench held by pr#1", "conflict #11: area bench held by pr#1",
             "conflict #12: area ci held by issue#2"]
    chk("[no-double-count] parsed attribution never exceeds the subtraction-derived total",
        parse_conflict_areas(lines, total=2), ({UNATTRIBUTED_AREA: 2}, 0))
    chk("[no-double-count] a clean parse attributes exactly, with no unattributed remainder",
        parse_conflict_areas(["conflict #11: area bench held by pr#1",
                              "conflict #12: area ci held by issue#2"], total=2),
        ({"bench": 1, "ci": 1}, 2))
    chk("[no-double-count] an unparseable line becomes VISIBLE unattributed weight, not a loss",
        parse_conflict_areas(["garbage", "conflict #12: area ci held by issue#2"], total=2),
        ({"ci": 1, UNATTRIBUTED_AREA: 1}, 1))
    chk("area cardinality is capped and the cap PRESERVES the total",
        (lambda a: (len(a), sum(a.values())))(
            parse_conflict_areas([f"conflict #{i}: area a{i} held by pr#1"
                                  for i in range(60)], total=60)[0]),
        (MAX_AREA_KEYS + 1, 60))

    # ---- planned vs realised -------------------------------------------------------------------
    frontier_doc = {"frontier_width": 10, "candidates": 372, "open_issues": 1368,
                    "conflict_deferrals": 362, "conflict_by_area": {"bench": 36},
                    "deferred_retry_width": 1, "attribution": "exact",
                    "census": {"buckets": {"frontier": 10}, "total": 1368, "unclassified": 0}}
    rec = build_record("sparq-org/sparq", "99.1", frontier_doc, {"planned": 8, "launched": 3}, 100)
    chk("[planned-vs-realised] a planned row that did NOT launch is unrealised, not a dispatch",
        (rec["planned_rows"], rec["realised_dispatches"], rec["unrealised_rows"]), (8, 3, 5))
    chk("[planned-vs-realised] realised is never inflated above planned",
        (lambda r: (r["realised_dispatches"], r["unrealised_rows"]))(
            build_record("o/t", "99.1", frontier_doc, {"planned": 2, "launched": 9}, 100)), (2, 0))
    chk("[planned-vs-realised] a repo the CLAIM lane never reached records realised=0",
        (lambda r: (r["planned_rows"], r["realised_dispatches"], r["frontier_width"]))(
            build_record("o/t", "99.1", frontier_doc, {}, 100)), (0, 0, 10))
    chk("[planned-vs-realised] frontier_width is NOT collapsed into planned_rows",
        (rec["frontier_width"], rec["planned_rows"]), (10, 8))
    chk("Gate A's three quantities are all present on the record",
        sorted(k for k in ("frontier_width", "realised_dispatches", "conflict_deferrals",
                           "conflict_by_area") if k in rec),
        ["conflict_by_area", "conflict_deferrals", "frontier_width", "realised_dispatches"])
    # ---- the dispatch CHAIN adds up leg by leg -------------------------------------------------
    # This is the shape of the real measured failure: a wide frontier, everything eaten at the
    # assemble leg, `lane worker: planned=0 launched=0`, and no counter anywhere on the loss.
    measured = build_record("sparq-org/sparq", "99.1", dict(
        frontier_doc, frontier_width=32, deferred_retry_width=0,
        plan_rows_before_assemble=30, assembler_deferrals=30,
        assembler_by_area={"__global__": 30}), {"planned": 0, "launched": 0}, 100)
    chk("[chain-sum] the HELD-area attribution reaches the record unflattened",
        measured["assembler_by_area"], {"__global__": 30})
    chk("[chain-sum] the legs partition the frontier — the loss cannot hide between two counters",
        (measured["chain"]["route_rejections"], measured["chain"]["assembler_deferrals"],
         measured["chain"]["claim_deferrals"], measured["chain"]["realised_dispatches"],
         measured["chain"]["unaccounted"]), (2, 30, 0, 0, 0))
    chk("[chain-sum] every leg sums back to the rows that entered the chain",
        sum(v for k, v in measured["chain"].items() if k != "frontier_and_retry_rows"),
        measured["chain"]["frontier_and_retry_rows"])
    mixed = build_record("o/t", "99.1", dict(
        frontier_doc, frontier_width=10, deferred_retry_width=2,
        plan_rows_before_assemble=12, assembler_deferrals=4), {"planned": 6, "launched": 5}, 100)
    chk("[chain-sum] a CLAIM-side defer is its own leg, not folded into unrealised",
        (mixed["chain"]["claim_deferrals"], mixed["chain"]["unrealised_planned_rows"],
         mixed["chain"]["unaccounted"], sum(
             v for k, v in mixed["chain"].items() if k != "frontier_and_retry_rows")),
        (2, 1, 0, 12))
    chk("[chain-sum] a target with no assemble leg reported leaves a VISIBLE residual",
        (lambda c: (c["assembler_deferrals"], c["unaccounted"]))(
            build_record("o/t", "99.1", dict(frontier_doc, frontier_width=10,
                                             deferred_retry_width=0),
                         {"planned": 0, "launched": 0}, 100)["chain"]), (0, 10))
    chk("[chain-sum] the brace-free log line carries the assemble leg and the residual",
        ("assembler_deferrals=30" in render_log_line(measured),
         "chain_unaccounted=0" in render_log_line(measured),
         "{" in render_log_line(measured)), (True, True, False))
    # tick_records keeps a census-only repo (the exact silent-improvement failure).
    ticks = tick_records({"repositories": {"a/b": frontier_doc, "c/d": frontier_doc}},
                         {"by_repo": {"a/b": {"planned": 4, "launched": 4}}}, "99.1", 100)
    chk("[planned-vs-realised] a repo missing from CLAIM is recorded, not dropped",
        [(t["repo"], t["realised_dispatches"]) for t in ticks], [("a/b", 4), ("c/d", 0)])

    # ---- secret-mask survivability --------------------------------------------------------------
    line = render_log_line(rec)
    chk("[mask-safe] the log line carries the three Gate A quantities and NO braces",
        ("frontier_width=10" in line, "realised_dispatches=3" in line,
         "conflict_deferrals=362" in line, "{" in line or "}" in line),
        (True, True, True, False))
    try:
        render_log_line({"repo": "o/{t}"})
    except TelemetryError:
        brace_guard = "raised"
    else:
        brace_guard = "silently emitted"
    chk("[mask-safe] a brace that sneaks into the line FAILS CLOSED", brace_guard, "raised")

    # ---- reason normalisation is bounded ---------------------------------------------------------
    chk("reason keys are bounded and named",
        [normalise_reason(r) for r in
         ("no status:ready attestation", "kind:epic is a tracking umbrella",
          "gated by needs:design", "busy: status:blocked", "parked: area:park",
          "no single valid priority:P0..P4 (have: none)", "no role:* label", "3 open blocker(s)",
          "some verdict this census has never seen")],
        ["excluded:no-attestation", "excluded:epic", "excluded:gated", "excluded:busy",
         "excluded:parked", "excluded:invalid-priority", "excluded:no-role", "excluded:blocked",
         "excluded:other"])

    # ---- ledger: idempotency, validation, pruning ------------------------------------------------
    class _StubAPI:
        """Records every PUT so a replay can be proven to write nothing."""

        def __init__(self, records=()):
            self.doc = {"records": list(records)}
            self.puts = 0

        def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
            del allow_404, retry_conflict
            if method == "GET" and "contents" in path:
                return {"content": base64.b64encode(json.dumps(self.doc).encode()).decode(),
                        "sha": "deadbeef"}
            if method == "PUT":
                self.puts += 1
                self.doc = json.loads(base64.b64decode(body["content"]).decode())
                return {"content": {"sha": "cafe"}}
            return None

    api = _StubAPI()
    first = append_records(api, "o/r", [rec], 100)
    replay = append_records(api, "o/r", [rec], 100)
    chk("[no-double-count] a REPLAYED tick emission is a confirmed no-op (one PUT, one record)",
        (first, replay, api.puts, len(api.doc["records"])), (1, 1, 1, 1))
    fresh = dict(rec, run_id="99.2")
    grown = append_records(api, "o/r", [fresh], 100)
    chk("...while a genuinely new tick still appends", (grown, api.puts), (2, 2))
    same_run_other_repo = dict(rec, repo="c/d")
    chk("...and the SAME run_id for a DIFFERENT target is a distinct record",
        append_records(api, "o/r", [same_run_other_repo], 100), 3)
    chk("the idempotency key is (run_id, repo)",
        (record_identity(rec), record_identity({"run_id": "", "repo": "a/b"})),
        (("99.1", "sparq-org/sparq"), None))
    try:
        validate_ledger({"records": [{"ts": 1, "repo": "bad repo", "run_id": "1.1",
                                      "frontier_width": 0, "realised_dispatches": 0,
                                      "conflict_deferrals": 0}]})
    except ValueError:
        malformed = "rejected"
    else:
        malformed = "accepted"
    chk("a malformed record is rejected, never silently dropped", malformed, "rejected")
    chk("the ring is bounded", len(prune([dict(rec, run_id=f"{i}.1", ts=i)
                                          for i in range(MAX_RECORDS + 50)], 0)), MAX_RECORDS)

    # ---- Gate A evaluation -----------------------------------------------------------------------
    passing = [dict(rec, run_id=f"{i}.1", ts=i, frontier_width=10, realised_dispatches=9)
               for i in range(GATE_A_SUSTAIN_TICKS)]
    failing = passing[:-1] + [dict(passing[-1], realised_dispatches=2)]
    chk("[gate-a] a sustained window at/above the threshold OPENS the gate",
        (lambda g: (g["open"], g["reason"], g["min_ratio"]))(
            gate_a_state(passing, "sparq-org/sparq")), (True, "sustained", 0.9))
    chk("[gate-a] ONE tick below the threshold in the window keeps it CLOSED",
        (lambda g: (g["open"], g["reason"]))(gate_a_state(failing, "sparq-org/sparq")),
        (False, "below-threshold"))
    chk("[gate-a] too few informative ticks is NOT an open gate",
        (lambda g: (g["open"], g["reason"]))(gate_a_state(passing[:3], "sparq-org/sparq")),
        (False, "insufficient-samples"))
    chk("[gate-a] empty-frontier ticks are EXCLUDED, never counted as passing",
        (lambda g: (g["open"], g["observed_ticks"]))(gate_a_state(
            [dict(rec, run_id=f"{i}.1", ts=i, frontier_width=0, realised_dispatches=0)
             for i in range(40)], "sparq-org/sparq")), (False, 0))
    chk("[gate-a] the window is per-target",
        gate_a_state(passing, "other/repo")["observed_ticks"], 0)
    chk("latest_by_repo picks the newest tick per target",
        {k: v["ts"] for k, v in latest_by_repo(
            [dict(rec, ts=5), dict(rec, ts=9), dict(rec, repo="c/d", ts=1)]).items()},
        {"sparq-org/sparq": 9, "c/d": 1})

    # ==============================================================================================
    # THE YAML SEAM. Measured on this repo: every uncaught mutant in an 18-mutant run lived in a
    # workflow `if:`/step/call-site, not in python. So the PLAN census block is EXTRACTED from
    # dispatch.yml and EXECUTED against a stub planner, and the CLAIM call site's wiring is asserted
    # against the real step text. Both extractors raise if their target is gone (fail closed).
    # ==============================================================================================
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "dispatch.yml"
    block = _workflow_block(workflow, "readiness", "frontier-census")

    class _StubPlanner:
        """Stands in for the target's `dispatch` module (dispatch-plan.py)."""

        def __init__(self, *, conflict_log=True, candidates=True):
            self._conflict_log = conflict_log
            if candidates:
                self.ready_candidates = self._candidates

        def compute_ready(self, issues, in_progress_packages=None, **kwargs):
            del in_progress_packages
            # NON-VACUITY: the census block MUST pass the attribution sink. Dropping the kwarg at
            # the call site kills every `exact`-attribution row below instead of degrading quietly.
            if "conflict_log" not in kwargs:
                raise AssertionError("the census block must call compute_ready with conflict_log")
            if not self._conflict_log:
                raise TypeError(
                    "compute_ready() got an unexpected keyword argument 'conflict_log'")
            for line in ("conflict #7: area bench held by pr#100",
                         "conflict #8: area bench held by pr#100",
                         "conflict #9: area ci held by issue#101",
                         "conflict #10: area ci held by issue#101"):
                kwargs["conflict_log"](line)
            return [i for i in issues if i["number"] == 6]

        def _candidates(self, issues, log=None):
            del log
            return [(1, i["number"], i, {"x"}) for i in issues
                    if self.exclusion_reason(set(i["labels"]), i["open_blockers"]) is None]

        @staticmethod
        def exclusion_reason(labels, open_blockers=0):
            if "needs:user" in labels:
                return "gated by needs:user"
            if "status:in-progress" in labels:
                return "busy: status:in-progress"
            if int(open_blockers) > 0:
                return f"{int(open_blockers)} open blocker(s)"
            return None

    # 10 open issues: #1,#2 trust/linked-dropped; #3 gated, #4 busy, #5 blocked; #6..#10 are
    # candidates, of which only #6 reaches the frontier and #7..#10 are conflict-deferred.
    def _row(number, labels=(), blockers=0):
        return {"number": number, "state": "OPEN", "labels": list(labels),
                "open_blockers": blockers}

    readiness_input = [_row(1), _row(2), _row(3, ["needs:user"]),
                       _row(4, ["status:in-progress"]), _row(5, blockers=1)] + \
                      [_row(n) for n in range(6, 11)]
    ready_input = [row for row in readiness_input if row["number"] >= 3]

    published = {}

    def _run_census(planner, ready=None):
        published.clear()
        namespace = {"dispatch": planner, "repo": "o/t", "telemetry": sys.modules[__name__],
                     "readiness_input": readiness_input, "ready_input": ready_input,
                     "ready": [r for r in ready_input if r["number"] == 6] if ready is None
                     else ready,
                     "deferred_ready": [], "frontier_census": {},
                     "frontier_censuses": published}
        exec(block, namespace)   # noqa: S102 — the workflow block, executed on purpose
        return namespace["frontier_census"]

    live = _run_census(_StubPlanner())
    chk("[YAML seam] the block PUBLISHES its census — computing it and not handing it on is a hole",
        (list(published), published.get("o/t") is live), (["o/t"], True))
    chk("[YAML seam] the EXECUTED census block computes Gate A's three quantities",
        (live["frontier_width"], live["conflict_deferrals"], live["conflict_by_area"],
         live["attribution"]),
        (1, 4, {"bench": 2, "ci": 2}, "exact"))
    chk("[YAML seam] ...and its buckets sum to the full open population, with no residual",
        (live["census"]["total"], live["census"]["population"], live["census"]["unclassified"],
         live["open_issues"], sorted(live["census"]["buckets"])),
        (10, 10, 0, 10,
         ["conflict-deferred", "excluded:blocked", "excluded:busy", "excluded:gated", "frontier",
          "trust-or-linked-excluded", "unclassified"]))
    degraded = _run_census(_StubPlanner(conflict_log=False))
    chk("[YAML seam] a planner with no attribution sink degrades LOUDLY, never fakes an area",
        (degraded["attribution"], degraded["conflict_deferrals"], degraded["conflict_by_area"]),
        ("unavailable", 4, {UNATTRIBUTED_AREA: 4}))
    blind = _run_census(_StubPlanner(candidates=False))
    chk("[YAML seam] a planner with no candidate enumeration leaves a VISIBLE GAP, not fake zeros",
        (blind["candidates"], blind["conflict_deferrals"], blind["census"]["unclassified"],
         blind["census"]["total"]),
        (1, 0, 7, 10))
    everything = _run_census(_StubPlanner(), ready=ready_input)
    chk("[YAML seam] a fully-free board records zero conflict deferrals",
        (everything["frontier_width"], everything["conflict_deferrals"]), (8, 0))

    # The ASSEMBLE leg — the one the measured run actually died at — is likewise EXECUTED, and
    # against the REAL `dispatch-claim` partition, never a stub.
    #
    # WHY THE REAL MODULE (registry #756 review; registry #758 mutant M8). The first version of
    # this test drove a stub whose whole body was `list(items)[:1]`. That stub HAS NO CONCEPT OF A
    # HOLDER, so no assertion written against it could distinguish "attributed to the reservation
    # that caused the drop" from "attributed to the dropped row's own crate" — and the wrong one
    # shipped. The arithmetic was pinned; the semantics the field is NAMED for were not. A stub
    # that cannot express the defect cannot pin the fix, so the discriminating cases below run the
    # production filter over production-shaped pulls/provenance/issue-label fixtures.
    assemble_block = _workflow_block(workflow, "assemble", "assembler-census")
    claim_mod = _load_dispatch_claim()
    fixture_sha = "a" * 40

    def _pull(number, ref, labels=()):
        """A `/pulls?state=open` row of the shape dispatch.yml's PLAN projection hands over."""
        return {"number": number, "state": "open", "draft": False, "auto_merge": None, "body": "",
                "head": {"ref": ref, "sha": fixture_sha, "repo": {"full_name": "o/t"}},
                "user": {"login": "sparq-agent[bot]", "type": "Bot"},
                "labels": [{"name": name} for name in labels]}

    def _record(pr_number, issue):
        return {"pr_number": pr_number, "head_sha_at_open": fixture_sha,
                "impl_provider": "anthropic", "impl_alias": "fable",
                "impl_account_h": "ab" * 8, "issue": issue, "recorded_at_run": "1.1"}

    def _run_assemble(items, pulls=(), issue_labels=None, provenance=None, leases=(),
                      claim=None):
        published = {}
        namespace = {
            "repository": {"items": [dict(item) for item in items]}, "repo": "o/t",
            "claim_mod": claim if claim is not None else claim_mod, "leases": list(leases),
            "now": 0, "pulls": list(pulls), "issue_labels": dict(issue_labels or {}),
            "provenance": dict(provenance or {}), "pr_status": {}, "starvation": {},
            "assembler_census": published}
        exec(assemble_block, namespace)   # noqa: S102 — the workflow block, executed on purpose
        return published["o/t"], [item["number"] for item in namespace["repository"]["items"]]

    def _sums(record):
        """The census obligation, as one number: every row entering the leg is in a named bucket."""
        return (sum(record["assembler_by_area"].values()) + record["plan_rows"]
                - record["plan_rows_before_assemble"])

    # (1) THE MEASURED BOARD (run 30222895098, reduced). ONE stray PR whose provenance-linked
    #     source issue carries no `area:` label reserves `__global__` — the documented fail-closed
    #     path — and eats every row. The rows' own crates are all DISTINCT and all FREE.
    #     Row-package keying publishes "10 areas x 1 row" and argues for widening crate
    #     parallelism; the truth is "1 area x 10 rows" and argues for the exact opposite.
    stall_crates = ["bench", "ci", "docs", "gui", "js", "sparq-core", "sparq-engine", "sparq-geo",
                    "sparq-reason", "sparq-trust"]
    stall_rows = [{"number": 100 + i, "package": crate, "deferred": False}
                  for i, crate in enumerate(stall_crates)]
    stall_holder = [_pull(4360, "sparq-agent/issue-4336-1-1", ["review:needs"])]
    stall_record, stall_kept = _run_assemble(
        stall_rows, stall_holder, {4336: ["role:impl"]}, {4360: _record(4360, 4336)})
    chk("[YAML seam] a __global__ reservation is attributed to the HOLDER, not to the 10 innocent "
        "crates it happened to defer",
        (stall_record["assembler_by_area"], stall_record["assembler_deferrals"],
         stall_record["plan_rows"], stall_kept),
        ({"__global__": 10}, 10, 0, []))
    chk("[YAML seam] ...and the published buckets SUM to the population entering the leg",
        (_sums(stall_record), stall_record["plan_rows_before_assemble"]), (0, 10))

    # (2) A GENUINE crate conflict still names the crate — the fix must not flatten every drop to
    #     `__global__`, or the panel loses the one case where crate parallelism IS the answer.
    crate_holder = [_pull(41, "sparq-agent/issue-7-1-1", ["review:needs"])]
    crate_record, crate_kept = _run_assemble(
        [{"number": 7, "package": "ci", "deferred": False},
         {"number": 8, "package": "docs", "deferred": False}],
        crate_holder, {7: ["area:ci", "role:impl"]}, {41: _record(41, 7)})
    chk("[YAML seam] a real one-crate overlap is still attributed to that crate",
        (crate_record["assembler_by_area"], crate_record["plan_rows"], crate_kept),
        ({"ci": 1}, 1, [8]))

    # (3) THE DISCRIMINATOR, and the mutation this block had no red test for. BOTH a `__global__`
    #     holder and a holder of the row's OWN crate are on the board. Keying on the row's package
    #     yields {"ci": 1}; keying on the cause yields {"__global__": 1}. Deleting the global
    #     holder frees the row, deleting the crate holder changes nothing — so the global holder
    #     is the cause and the crate holder is a bystander. This assertion is the difference.
    both_record, _ = _run_assemble(
        [{"number": 7, "package": "ci", "deferred": False}],
        stall_holder + crate_holder, {4336: ["role:impl"], 7: ["area:ci", "role:impl"]},
        {4360: _record(4360, 4336), 41: _record(41, 7)})
    chk("[YAML seam] with a global holder AND a holder of the row's own crate, the CAUSE wins",
        (both_record["assembler_by_area"], _sums(both_record)), ({"__global__": 1}, 0))

    # (4) The deferred-retry filter runs BEFORE the busy-area partition and its drops are NOT
    #     busy-area deferrals. They land in their own named bucket instead of inflating a crate's
    #     count — nested inside one expression they were invisible and the buckets could not sum.
    retry_record, retry_kept = _run_assemble(
        [{"number": 5, "package": "sparq-core", "deferred": True},
         {"number": 6, "package": "sparq-engine", "deferred": False}],
        leases=[{"holder": "o/t#5", "package": "sparq-core", "expires_at": 10**12}])
    chk("[YAML seam] a lease-deferred retry row is counted under its OWN reason, and the buckets "
        "still sum",
        (retry_record["assembler_by_area"], retry_record["assembler_deferrals"],
         retry_kept, _sums(retry_record)),
        ({"__deferred-retry__": 1}, 1, [6], 0))

    # (5) A FREE board records nothing and keeps everything.
    free_record, free_kept = _run_assemble(
        [{"number": 7, "package": "ci", "deferred": False},
         {"number": 8, "package": "docs", "deferred": False}])
    chk("[YAML seam] a fully-free board defers nothing at the assemble leg",
        (free_record["assembler_by_area"], free_record["assembler_deferrals"], free_kept),
        ({}, 0, [7, 8]))

    # (6) MISSING EDGE. A filter that drops rows without filling the census must show up as a
    #     visible, counted residual — not as silence, and not smeared over the real buckets. This
    #     is the only case that still uses a stub, because the production filter cannot produce it.
    class _CensusBlindClaim:
        """A partition that eats rows and records NOTHING — the missing-edge shape."""

        @staticmethod
        def filter_deferred_items(items, *_a, **_k):
            return list(items)

        @staticmethod
        def filter_busy_area_items(items, *_a, **kwargs):
            kwargs.get("starvation", {})["kept"] = 1
            return list(items)[:1]

    blind_record, blind_kept = _run_assemble(
        [{"number": 1, "package": "sparq-core"}, {"number": 2, "package": "ci"},
         {"number": 3, "package": "ci"}, {"number": 4, "package": None}],
        claim=_CensusBlindClaim())
    chk("[YAML seam] an uncounted drop branch surfaces as a NAMED residual, never as silence",
        (blind_record["assembler_by_area"], blind_record["assembler_deferrals"],
         blind_kept, _sums(blind_record)),
        ({"__uncensused__": 3}, 3, [1], 0))
    assemble_yaml = Path(workflow).read_text(encoding="utf-8")
    chk("[YAML seam] PLAN merges the assemble leg into the census CLAIM will read",
        ('census_doc.setdefault("repositories", {}).setdefault(' in assemble_yaml,
         "assembler_census.items()" in assemble_yaml), (True, True))

    claim_step = _workflow_step_text(workflow, "dispatch-telemetry")
    chk("[YAML seam] the CLAIM call site runs the recorder, always(), and cannot fail the tick",
        ("scripts/dispatch-telemetry.py" in claim_step and " record" in claim_step,
         "if: always()" in claim_step,
         "continue-on-error: true" in claim_step,
         "--frontier" in claim_step, "--summary" in claim_step, "--run-id" in claim_step),
        (True, True, True, True, True, True))
    # SCOPED to the upload step, not the whole file: the filename appears in several places, so a
    # whole-file search survives deleting it from the artifact path — which silently starves CLAIM.
    upload_step = _workflow_step_text(workflow, "upload-plan", strip_comments=True)
    chk("[YAML seam] the artifact upload step itself carries the census beside the plan",
        ("frontier-census.json" in upload_step, "plan.json" in upload_step,
         "if-no-files-found: error" in upload_step), (True, True, True))
    claim_download = _workflow_step_text(workflow, "download-plan", strip_comments=True)
    chk("[YAML seam] ...and CLAIM downloads it to the path the recorder is pointed at",
        ("path: plan" in claim_download,
         "plan/frontier-census.json" in _workflow_step_text(
             workflow, "dispatch-telemetry", strip_comments=True)),
        (True, True))

    print("dispatch-telemetry self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description="Per-tick dispatch telemetry (Gate A).")
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="command")
    rec = sub.add_parser("record", help="write one tick's per-target records to the ledger")
    rec.add_argument("--frontier", required=True, help="PLAN frontier-census.json")
    rec.add_argument("--summary", default="", help="CLAIM dispatch-summary.json")
    rec.add_argument("--registry-repo", required=True)
    rec.add_argument("--run-id", required=True, help="GITHUB_RUN_ID.GITHUB_RUN_ATTEMPT")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    if args.command == "record":
        return cmd_record(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TelemetryError as exc:
        print(f"::error::dispatch-telemetry: {exc}", file=sys.stderr)
        sys.exit(1)
