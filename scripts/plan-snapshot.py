#!/usr/bin/env python3
"""PLAN-side authenticated target snapshot (the REG-4 registry-inline half).

Runs BEFORE any target planner code executes and holds the only token the PLAN job ever
sees; the target-planner and assemble steps consume the raw-*.json files this writes.
Extracted from the dispatch.yml heredoc so the per-item degradation below is enforced by
--self-test (the pr-gate suite) instead of living untested inside the workflow.

Per-item degradation (dispatch run 29617040167, 2026-07-17): one pathological PR whose
head had accumulated >=1000 check runs (sparq merge-queue concurrency-cancel churn kept
re-running CI on the same head) tripped the runaway-snapshot ceiling and killed the
ENTIRE sweep — PLAN failed, CLAIM was skipped, zero dispatch fleet-wide. The ceiling is
now a PER-ITEM backstop: an oversized or unreadable per-PR read skips THAT PR with a
recorded reason (raw-prstatus `skips` -> plan `snapshot_skips` -> the dispatch summary's
defer_reasons) and the sweep continues.

Degradation is two-tier (round-1 review of PR #60): a check-run failure AFTER the PR
detail read succeeded must not throw the detail away, because the #42 armed-SHA-mismatch
DISARM consumes only detail data (head_sha + the auto_merge armed bit) — and for disarm
the ACT is the safety measure, so a full stand-down there is fail-OPEN (an armed PR whose
head advanced past its reviewed-sha marker would keep its stale arm latched just because
its head churned past the check-run ceiling — cheap to induce via merge-queue cancel
churn, the exact scenario this file exists for). So:
- POST-detail failure (check-runs-overflow/-malformed/-read-failed): the record is EMITTED
  with the detail fields intact, `check_runs` EMPTY, and an explicit
  `check_runs_degraded: <reason>` marker; the skip row is still recorded for visibility.
  pr_ci_status forces gate="missing" on the marker, and enumerate_review_items stands the
  check-run-DEPENDENT admissions (ci-fix, stranded) down on it while the detail-derived
  ones (the needs-rebase conflict repair, and the disarm net) still evaluate on sound
  data — monotone: a degraded record yields the undegraded outcome or do-nothing, never
  a different act.
- PRE-detail failure (pr-detail-read-failed/-malformed, worker-pr-census-overflow):
  nothing sound is derivable — NO record, every snapshot-derived admission including
  disarm stands down for that PR this tick. Residual, accepted: the detail read failing
  is a GitHub API outage/malformed-response condition, not attacker-inducible by
  inflating check-run volume on a head.

Blowup reduced at source: the check-run read is gate-filtered (the d2c0dd0 pattern — an
unfiltered listing both grows without bound under churn and can lose the gate run
entirely); the unfiltered walk that names advisory failing legs runs ONLY when the
filtered gate is a concluded failure (the only state that admits a ci-fix).

The filter is applied ONCE PER TIER NAME (claim.CI_REPAIR_GATE_CHECKS) because the REST
`check_name` parameter takes exactly one value and sparq's aggregator is named
`gate, draft-tier` on a DRAFT head — which is what every worker PR is for the whole
review loop. Reading only the strict name returned zero rows on every measured sparq
worker head, and "zero rows" is indistinguishable from "this head has no gate".
Each walk is cross-checked against the endpoint's own `total_count` so a partial read
degrades the record loudly instead of impersonating an absent aggregator.

Repo-level listings (issues / pulls) keep their sweep-fatal 5000-entry ceiling: the
target planner step requires a complete issue snapshot for every manifest repo, so a
per-repo degradation there needs a cross-step design (follow-up; see the PR record).

COST (issue #721). This step is the dispatch tick: measured 2026-07-27 it was 759 s and
812 s of a 771 s / 829 s PLAN job — ~98% — against a 600 s cron period. An instrumented
run of THIS code against the live targets timed every request:

    wall 684.9 s | inside urlopen 663.9 s (96.9%) | local compute 21.1 s (3.1%)
    613 requests, 28,334 rows, median request 0.843 s
    check-runs 474 req / 564.6 s (85%) | pr-detail 116 / 80.5 s | listings 23 / 18.8 s

So the step is API-ROUND-TRIP bound, not compute bound, and the requests were issued one
at a time. The request SET is not reducible without weakening completeness (the two
tier-name gate reads exist because REST `check_name` takes one value; the legs walk exists
because REST cannot filter check runs by conclusion), so the lever is OVERLAP: independent
reads now run concurrently, bounded by SNAPSHOT_CONCURRENCY, folded back in input order.
Nothing about WHICH pages are fetched, how a walk terminates, the per-walk ceilings, or the
`total_count` cross-check changes — see _ordered_map.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

RETRYABLE = {429, 500, 502, 503, 504}
# 403 is deliberately NOT in RETRYABLE (issue #819). It is not one status, it is three different
# server answers wearing the same number, and only one of them is a blip worth retrying:
#
#   secondary   GitHub is throttling a burst. Carries `Retry-After` (or says "secondary rate
#               limit" / "abuse detection"). RETRYABLE, after the wait it asks for.
#   budget      The installation's hourly request budget is spent. Body says "API rate limit
#               exceeded", `x-ratelimit-remaining: 0`, and — measured, 0 of 27 observed failures
#               on 2026-07-27 — NO `Retry-After` at all. NOT retryable: the reset can be most of
#               an hour, so each retry is two more requests spent deepening the outage that is
#               already refusing them.
#   permission  The token cannot do this. NOT retryable, and never was: retrying it three times
#               only made a permanent refusal take fifteen seconds to report.
#
# Until #819 every 403 took the retry path, so the tick that exhausted the budget answered by
# issuing 3x the requests for every read, in 8 parallel threads.
_SECONDARY_403_MARKERS = ("secondary rate limit", "abuse detection", "retry later")
_BUDGET_403_MARKERS = ("rate limit exceeded", "rate limit for installation")
LIST_PAGE_LIMIT = 50        # issues/pulls ceiling: 5000 entries, repo-level, sweep-fatal
# Per-SHA ceiling backstop: 4000 entries (the f37d13f emergency bump — churned sparq heads
# really do pass 1000, e.g. PR #2540 at 1061), and it now degrades PER ITEM, never per sweep.
CHECK_RUN_PAGE_LIMIT = 40
WORKER_PR_STATUS_LIMIT = 100
WORKER_HEAD_PREFIX = "sparq-agent/"
MERGEABLE_POLL_ATTEMPTS = 3
MERGEABLE_POLL_INTERVAL_SECONDS = 1
SAFE_SHA = re.compile(r"[0-9a-f]{40}")

# How many INDEPENDENT GitHub reads may be in flight at once (issue #721 / this file's
# module docstring). This is a SECONDARY-RATE-LIMIT BUDGET, not a tuning knob:
#   * GitHub's documented secondary limit for the REST API is 900 points per minute, and a
#     GET costs 1 point.
#   * Measured mean latency of this snapshot's reads (2026-07-27 instrumented run, 613
#     requests against the live targets) is ~0.85 s, so C reads in flight sustain roughly
#     C / 0.85 requests per second.
#   * C = 8  ->  ~9.4 req/s  ->  ~565 req/min: inside the budget with headroom.
#     C = 16 -> ~18.8 req/s  -> ~1130 req/min: OVER it.
# Raising this without re-deriving that arithmetic trades a slow tick for a throttled one.
# The PRIMARY limit is unaffected: overlapping reads does not change how many are issued.
SNAPSHOT_CONCURRENCY = 8
# Ceiling on a server-suggested `Retry-After` back-off. Overlapping reads is the way to
# provoke a secondary rate limit, so the back-off must honour what GitHub asks for — but a
# long suggestion must fail the read CLOSED inside the job's 15-minute timeout rather than
# park the whole sweep on a sleep.
RETRY_AFTER_CAP_SECONDS = 30

# THE REQUEST-BUDGET RESERVE (issue #819 / #796). Every REST response carries the authoritative
# `x-ratelimit-remaining` for the bucket the request was actually charged to. `GET /rate_limit`
# does NOT — it reports a different bucket and read healthy throughout the 2026-07-27 outage while
# every snapshot request 403'd, which is why that endpoint is not consulted anywhere here.
#
# When the remaining budget falls to this reserve the sweep STOPS, loudly, instead of spending the
# last of it. The reserve exists because the snapshot is not the only consumer of this bucket:
# `secrets-guard` needs a handful of reads to resolve the default branch and the environment
# policy, CLAIM needs its lease/launch writes, and plan-alert needs one `gh issue list` to raise
# the alarm. A snapshot that drains the bucket to zero takes the GUARD and the ALERT down with it
# — which is exactly what happened: on every failing tick since 18:26:17Z the guard failed with
# "cannot resolve the repository default branch" and ALERT was SKIPPED, so the total pipeline
# stall raised no alarm at all.
RATE_LIMIT_RESERVE = 100


class FetchError(Exception):
    """A GitHub read failed for good (retries exhausted) or returned a malformed page."""


class BudgetExhausted(Exception):
    """The request budget for this token is spent (or down to RATE_LIMIT_RESERVE).

    DELIBERATELY NOT a FetchError. Every per-item handler in this file catches FetchError and
    converts it into a per-PR skip, so a budget failure raised as a FetchError would be recorded
    as `check-runs-read-failed` on PR after PR while the sweep kept issuing requests into a
    bucket that has none left. Sweep-fatal is the only correct scope for this class, and making
    it a sibling of FetchError rather than a subclass is what enforces that structurally —
    `budget_403_is_never_downgraded_to_a_per_item_skip` in the self-test pins it."""


class SnapshotItemError(Exception):
    """A single PR's status snapshot failed: skip THAT PR with a reason, never the sweep.
    Raised out of _pr_status_record only for PRE-detail failures (no sound record is
    derivable); post-detail check-run failures degrade the record instead of raising.
    The reason must be a member of dispatch-claim.py's SNAPSHOT_SKIP_REASONS (validated
    there when the plan artifact is re-checked as hostile data)."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _load_claim():
    """Load dispatch-claim.py (same checkout) for CI_GATE_CHECK + interpret_check_runs —
    the snapshot must fetch exactly what those PURE interpreters later re-derive from."""
    path = Path(__file__).resolve().parent / "dispatch-claim.py"
    spec = importlib.util.spec_from_file_location("registry_dispatch_claim_snapshot", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load registry helper dispatch-claim.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _retry_delay(exc, attempt):
    """Seconds to wait before retrying a retryable read.

    GitHub answers a SECONDARY rate limit (403/429) with a `Retry-After` header saying how
    long to wait. The fixed 5s/10s ladder ignored it, which is survivable for a strictly
    serial walk and is NOT survivable once reads overlap — retrying early on a secondary
    limit is what turns a throttle into a ban. A malformed, non-positive, or absent header
    falls back to the original ladder; an oversized one is capped (RETRY_AFTER_CAP_SECONDS)
    so the read exhausts its retries and fails CLOSED instead of sleeping out the job.

    THIS HELPER ONLY SIZES THE WAIT. Which 403s are waited on at all is `classify_403`'s job
    (#819): the OTHER 403 this snapshot can hit is installation budget exhaustion — body
    `"API rate limit exceeded for installation"`, `x-ratelimit-remaining: 0`, and **no
    `Retry-After` at all** (0 of 27 observed failures on 2026-07-27 carried one). GitHub's
    guidance there is to wait for `x-ratelimit-reset`, which can be most of an hour and is
    longer than this job may live, so that class is now raised as BudgetExhausted on the FIRST
    response instead of being retried into the same empty bucket twice more. Note also that
    `GET /rate_limit` reports a DIFFERENT bucket and will happily say thousands remain while
    every read 403s (#796) — which is why every budget number here comes off the RESPONSE.
    """
    seconds = _retry_after_seconds(getattr(exc, "headers", None))
    if seconds:
        return min(seconds, RETRY_AFTER_CAP_SECONDS)
    return 5 * (attempt + 1)


def _header(headers, name):
    """Case-insensitive single header read over anything dict-like (http.client.HTTPMessage,
    a plain dict, or the dict a test hands an HTTPError). -> str|None."""
    if headers is None:
        return None
    if hasattr(headers, "get"):
        got = headers.get(name)
        if got is not None:
            return str(got)
    try:
        items = headers.items()
    except AttributeError:
        return None
    lowered = name.lower()
    for key, value in items:
        if str(key).lower() == lowered:
            return str(value)
    return None


def _retry_after_seconds(headers):
    """The `Retry-After` header as a positive int, or 0. A date-form or malformed value is 0 —
    the caller falls back to its own ladder rather than guessing at an HTTP-date."""
    raw = _header(headers, "Retry-After")
    if raw is None:
        return 0
    try:
        seconds = int(raw.strip())
    except ValueError:
        return 0
    return seconds if seconds > 0 else 0


def _int_header(headers, name):
    raw = _header(headers, name)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def classify_403(headers, body=""):
    """-> 'secondary' | 'budget' | 'permission'. See the RETRYABLE block for what each means.

    ORDER IS THE CONTRACT. `secondary` is tested first because a secondary-limit 403 can also
    carry rate-limit headers; treating one as `budget` would stop a sweep that only needed to wait
    the few seconds GitHub asked for. `budget` is tested before `permission` because a permission
    refusal is the RESIDUAL class — the one with no positive evidence — and residual classes must
    never be inferred from the ABSENCE of a header that a truncated response might simply have
    dropped."""
    text = (body or "").lower()
    if _retry_after_seconds(headers) or any(m in text for m in _SECONDARY_403_MARKERS):
        return "secondary"
    if _int_header(headers, "x-ratelimit-remaining") == 0:
        return "budget"
    if any(m in text for m in _BUDGET_403_MARKERS):
        return "budget"
    return "permission"


def _budget_detail(headers):
    """A human-readable `remaining/limit, resets at ...` for the loud failure message."""
    remaining = _int_header(headers, "x-ratelimit-remaining")
    limit = _int_header(headers, "x-ratelimit-limit")
    reset = _int_header(headers, "x-ratelimit-reset")
    when = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(reset))
            if reset is not None else "unknown")
    return (f"x-ratelimit-remaining={remaining if remaining is not None else 'absent'}"
            f"/{limit if limit is not None else 'absent'}, resets at {when}")


def _check_reserve(headers):
    """Read the AUTHORITATIVE remaining budget off a response and stop the sweep before it is
    gone. Raises BudgetExhausted; returns the remaining count otherwise (None when the header is
    absent, which is NOT treated as exhaustion — an absent header proves nothing, and failing
    closed on it would take the pipeline down on any proxy that strips it)."""
    remaining = _int_header(headers, "x-ratelimit-remaining")
    if remaining is not None and remaining <= RATE_LIMIT_RESERVE:
        raise BudgetExhausted(
            "GitHub request budget is down to the reserve — stopping this snapshot before it "
            f"spends the last of it ({_budget_detail(headers)}, reserve {RATE_LIMIT_RESERVE}). "
            "The reserve keeps enough budget for secrets-guard, CLAIM and the ops-alert; a "
            "snapshot that drains the bucket takes the pipeline's own alarm down with it (#819).")
    return remaining


def make_fetch(token):
    """Authenticated single-page reader with retry/backoff; raises FetchError, never exits
    (the caller decides sweep-fatal vs per-item)."""

    def fetch(url):
        for attempt in range(3):
            request = Request(url, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "reg4-plan-snapshot",
                "X-GitHub-Api-Version": "2022-11-28",
            })
            try:
                with urlopen(request, timeout=30) as response:
                    payload = json.load(response)
                    # Read the budget off the SUCCESSFUL response too (issue #796): that is the
                    # only place the authoritative number for this bucket ever appears, and a
                    # sweep that only looks after it has already been refused has learned it one
                    # request too late.
                    _check_reserve(getattr(response, "headers", None))
                    return payload
            except HTTPError as exc:
                if exc.code == 403:
                    headers = getattr(exc, "headers", None)
                    kind = classify_403(headers, _error_body(exc))
                    if kind == "budget":
                        raise BudgetExhausted(
                            "authenticated GitHub read refused (HTTP 403, request budget "
                            f"exhausted) for {url.split('?')[0]} — {_budget_detail(headers)}. "
                            "This class carries no Retry-After and its reset can be most of an "
                            "hour, so it is NOT retried: every retry is another request spent on "
                            "a bucket that has none. If this is sustained, the dispatcher is "
                            "issuing more requests per hour than the budget allows — see the "
                            "tick floor in scripts/dispatch-tick-floor.py (#819).") from exc
                    if kind == "secondary" and attempt < 2:
                        time.sleep(_retry_delay(exc, attempt))
                        continue
                    raise FetchError(
                        f"authenticated GitHub read failed (HTTP 403, {kind}) for "
                        + url.split("?")[0]) from exc
                if exc.code in RETRYABLE and attempt < 2:
                    time.sleep(_retry_delay(exc, attempt))
                    continue
                raise FetchError(
                    f"authenticated GitHub read failed (HTTP {exc.code}) for "
                    + url.split("?")[0]) from exc
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                if attempt < 2:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise FetchError(
                    "authenticated GitHub read failed for " + url.split("?")[0]) from exc

    return fetch


def _error_body(exc):
    """The first 4 KiB of an HTTPError's body, for CLASSIFICATION ONLY. Never rendered into a
    message, never written to the snapshot: it is remote content. Reading it is best-effort — a
    body that cannot be read leaves classification to the headers alone."""
    try:
        return exc.read(4096).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - any read failure degrades to header-only classification
        return ""


def _ordered_map(worker, jobs, concurrency=SNAPSHOT_CONCURRENCY):
    """Run `worker` over `jobs` with at most `concurrency` in flight, results in INPUT ORDER.

    What this is allowed to change, and what it is not:

    * It overlaps reads that are already INDEPENDENT — one worker PR's status never depends
      on a sibling's, and every request issued is a GET. It does NOT change which URLs are
      requested, how a page walk terminates, the per-walk ceilings, or the `total_count`
      cross-check. Completeness is therefore exactly the serial walk's completeness.
    * Results are keyed by input index, so the emitted snapshot — including the ORDER of the
      `skips` histogram, which the dispatch summary renders — is byte-identical to the
      serial walk for the same set of API responses. Determinism is a correctness property
      here, not a nicety; `snapshot_parallel_output_is_identical_to_serial` pins it.
    * Failures are NOT swallowed. `ThreadPoolExecutor.map` re-raises the first exception in
      INPUT order as the results are consumed, so a sweep-fatal FetchError out of a repo
      listing stays sweep-fatal (`sweep_fatal_listing_failure_is_still_fatal` pins it) and a
      per-item SnapshotItemError is still caught by the per-item handler that raised it.
    """
    jobs = list(jobs)
    workers = min(max(int(concurrency), 1), len(jobs))
    if workers <= 1:
        return [worker(job) for job in jobs]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(worker, jobs))


def _paginated(fetch, path):
    """Repo-level page walk to a short page. The explicit ceiling only guards a runaway
    snapshot (5000 covers the migrated backlog with organic-growth margin) and stays
    SWEEP-fatal: the target planner step needs a complete listing for every repo."""
    items = []
    for page in range(1, LIST_PAGE_LIMIT + 1):
        separator = "&" if "?" in path else "?"
        result = fetch(f"https://api.github.com{path}{separator}per_page=100&page={page}")
        if not isinstance(result, list):
            raise FetchError("GitHub API returned a non-list page")
        items.extend(result)
        if len(result) < 100:
            return items
    raise FetchError("refusing a target snapshot at or above 5000 entries")


def _fetch_check_runs(fetch, repo, sha, check_name=None):
    """Per-SHA check-runs walk. Every failure mode here is PER-ITEM (SnapshotItemError):
    the ceiling is a backstop, not a sweep-killer. check_name filtering keeps the common
    case to one small page even on churned heads with hundreds of runs — the name is
    URL-QUOTED because a tier-marked aggregator name (`gate, draft-tier`) carries a comma
    and a space.

    The walk is CROSS-CHECKED against the endpoint's own `total_count`: a listing that ends
    short of what GitHub says exists is a partial read, and a partial read that happens to
    omit the aggregator is indistinguishable from "this head has no gate" — the exact silent
    failure that stands every gate-dependent admission down. A disagreement (or an
    absent/garbage count) degrades the record instead.

    The filter is emitted FIRST in the query string, so the encoded name is always followed by a
    `&` delimiter. `check_name=gate` is a strict PREFIX of `check_name=gate%2C%20draft-tier`;
    trailing it made every name test in a fixture (or in a log grep, or in any future
    request-matching double) prefix-shaped and therefore ORDER-dependent for its correctness.
    Putting it first makes the parameter BOUNDARY available to any matcher, which is what
    dispatch-claim's live read already relies on. [round-2 review, finding 3]"""
    filter_query = f"check_name={quote(check_name, safe='')}&" if check_name else ""
    runs_out = []
    raw_seen = 0
    total = None
    for page in range(1, CHECK_RUN_PAGE_LIMIT + 1):
        try:
            doc = fetch(f"https://api.github.com/repos/{repo}/commits/{sha}"
                        f"/check-runs?{filter_query}per_page=100&page={page}")
        except FetchError as exc:
            raise SnapshotItemError("check-runs-read-failed") from exc
        runs = doc.get("check_runs") if isinstance(doc, dict) else None
        if not isinstance(runs, list):
            raise SnapshotItemError("check-runs-malformed")
        if page == 1:
            total = doc.get("total_count")
        raw_seen += len(runs)
        runs_out.extend({
            "name": run.get("name"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "started_at": run.get("started_at"),
        } for run in runs if isinstance(run, dict))
        if len(runs) < 100:
            if not isinstance(total, int) or isinstance(total, bool) or total != raw_seen:
                raise SnapshotItemError("check-runs-malformed")
            return runs_out
    raise SnapshotItemError("check-runs-overflow")


def resolve_mergeable_detail(fetch, detail_url):
    """Read one PR detail, boundedly re-polling GitHub's asynchronous mergeability.

    Kept here as the single implementation for every registry sweep that classifies a
    conflicting PR.  GitHub commonly returns ``mergeable: null`` immediately after the
    base advances; treating that first response as final makes exactly the DIRTY PRs the
    sweeps are meant to repair disappear for a tick.
    """
    for attempt in range(MERGEABLE_POLL_ATTEMPTS):
        detail = fetch(detail_url)
        if not isinstance(detail, dict) or detail.get("mergeable") is not None:
            return detail
        if attempt + 1 < MERGEABLE_POLL_ATTEMPTS:
            time.sleep(MERGEABLE_POLL_INTERVAL_SECONDS)
    return detail


def _pr_status_record(fetch, claim, repo, number):
    """One worker PR's CI/merge status: detail read (mergeable + auto_merge + fresh head)
    plus the gate-filtered check-run read; the unfiltered listing (advisory failing-leg
    names for the ci-fix prompt) is fetched ONLY when the gate is a concluded failure —
    the one state that admits a ci-fix.

    Raises SnapshotItemError ONLY for pre-detail failures. Once the detail read has
    succeeded, a check-run failure DEGRADES the record (empty check_runs + an explicit
    `check_runs_degraded` reason) instead of discarding it: the detail fields are exactly
    what the #42 armed-SHA-mismatch disarm needs, and dropping them on check-run VOLUME
    would let an armed PR defeat its own safety net by churning past the ceiling."""
    detail_url = f"https://api.github.com/repos/{repo}/pulls/{number}"
    try:
        detail = resolve_mergeable_detail(fetch, detail_url)
    except FetchError as exc:
        raise SnapshotItemError("pr-detail-read-failed") from exc
    if not isinstance(detail, dict):
        raise SnapshotItemError("pr-detail-malformed")
    sha = str((detail.get("head") or {}).get("sha", ""))
    record = {
        "head_sha": sha,
        "mergeable": detail.get("mergeable"),
        # [round-4 P1] the detail read's own draft bit (present on the pulls/N REST
        # response): the busy-partition carve-out (_pull_provably_inactive) frees a
        # human-parked draft's crate ONLY when this NEWER, head-matched read CONFIRMS
        # draft — the older pulls LISTING alone is racy (a draft flipped ready between
        # the listing and this read would otherwise free a crate the PR can merge into).
        "draft": detail.get("draft"),
        "check_runs": [],
    }
    # [round-6 P2] ABSENCE != NULL: carry `auto_merge` ONLY when the detail actually has
    # the field. `detail.get("auto_merge")` collapsed an ABSENT field to None — the exact
    # JSON value REST uses for "explicitly unarmed" — so a detail that never carried the
    # field read as PROOF of inactivity downstream and freed a parked crate (fail OPEN).
    # An omitted key survives the JSON round-trip and reads UNKNOWN in pr_ci_status
    # (armed=None: never frees a crate, never proves the stranded posture — fail closed).
    if "auto_merge" in detail:
        record["auto_merge"] = detail["auto_merge"]
    if SAFE_SHA.fullmatch(sha):
        try:
            # BOTH aggregator tier names (the REST check_name filter takes exactly one). A
            # worker PR is DRAFT for the whole review loop and sparq names the draft
            # aggregator `gate, draft-tier`, so reading only claim.CI_GATE_CHECK returned zero
            # rows on every measured sparq worker head — indistinguishable from "no gate",
            # which stands the whole ci-fix admission down. See claim.CI_REPAIR_GATE_CHECKS.
            check_runs = []
            for gate_name in claim.CI_REPAIR_GATE_CHECKS:
                check_runs += _fetch_check_runs(fetch, repo, sha, check_name=gate_name)
            if claim.repair_gate_conclusion(check_runs) == "failure":
                check_runs = check_runs + _fetch_check_runs(fetch, repo, sha)
            record["check_runs"] = check_runs
        except SnapshotItemError as exc:
            # POST-detail degradation: keep the detail (disarm still fires), blank the
            # check runs entirely (a partial gate-only listing must not admit a ci-fix
            # whose advisory legs walk overflowed), mark the reason for the skip row.
            record["check_runs_degraded"] = exc.reason
    return record


def _pr_status_snapshot(fetch, claim, repo, pulls, concurrency=SNAPSHOT_CONCURRENCY):
    """Per-worker-PR CI/merge status (GAP-A/B/C inputs) with per-item degradation.
    Returns (status_items, skips). Two tiers: a PRE-detail failure records a skip and NO
    status record (every snapshot-derived admission stands down); a POST-detail check-run
    failure records the SAME skip row for visibility but ALSO emits a degraded record
    (detail intact, check_runs empty + marked) so the #42 disarm net still fires.

    The per-PR reads OVERLAP (issue #721: this walk was 85% of a 13-minute PLAN job, and
    97% of that was time spent waiting inside urlopen). Each PR is still snapshotted by the
    unchanged `_pr_status_record` — detail, then the tier-name gate reads, then the
    conditional legs walk, in that order — so what changed is only which PRs are in flight
    together. The results are folded back in INPUT order, so `status_items` and the `skips`
    histogram are what a serial walk would have produced."""
    worker_pulls = [
        pull for pull in pulls
        if isinstance(pull, dict) and pull.get("state") == "open"
        and isinstance(pull.get("number"), int) and pull["number"] > 0
        and str((pull.get("head") or {}).get("ref", "")).startswith(WORKER_HEAD_PREFIX)
        and ((pull.get("head") or {}).get("repo") or {}).get("full_name") == repo
    ]
    if len(worker_pulls) > WORKER_PR_STATUS_LIMIT:
        # Repo-level census overflow degrades to NO prstatus for this repo (pr_number 0
        # marks the repo-wide skip): issue dispatch continues, every snapshot-derived PR
        # admission stands down. Better a status-blind tick than a dead sweep.
        return {}, [{"pr_number": 0, "reason": "worker-pr-census-overflow"}]

    def snapshot_one(pull):
        number = pull["number"]
        try:
            return number, _pr_status_record(fetch, claim, repo, number), None
        except SnapshotItemError as exc:
            # THE per-item catch (run 29617040167): one unreadable PR detail defers
            # itself with a recorded reason; its siblings and the sweep continue. It is
            # caught INSIDE the worker so a per-item failure can never abort a sibling's
            # read the way an exception escaping into _ordered_map would.
            return number, None, exc.reason

    status_items = {}
    skips = []
    for number, record, skip_reason in _ordered_map(snapshot_one, worker_pulls, concurrency):
        if record is None:
            skips.append({"pr_number": number, "reason": skip_reason})
            continue
        status_items[str(number)] = record
        if "check_runs_degraded" in record:
            # Post-detail degradation stays VISIBLE in the same skip histogram even
            # though the (detail-only) record is emitted for the disarm net.
            skips.append({"pr_number": number, "reason": record["check_runs_degraded"]})
    return status_items, skips


def snapshot_targets(fetch, claim, repos, out_dir, concurrency=SNAPSHOT_CONCURRENCY):
    # Phase 1 — every repo-level listing is independent of every other, so the walks
    # overlap. Each walk is UNCHANGED: the same serial page-walk to a short page, the same
    # sweep-fatal 5000-entry ceiling, the same non-list-page rejection. A FetchError out of
    # any of them still aborts the whole snapshot, and now does so BEFORE any file is
    # written (strictly safer than the old repo-at-a-time loop, which left the earlier
    # repo's raw-*.json on disk when a later repo's listing died).
    listing_paths = []
    for repo in repos:
        listing_paths.append(f"/repos/{repo}/issues?state=open")
        listing_paths.append(f"/repos/{repo}/pulls?state=open")
    listings = _ordered_map(lambda path: _paginated(fetch, path), listing_paths, concurrency)

    for index, repo in enumerate(repos):
        issues, pulls = listings[2 * index], listings[2 * index + 1]
        Path(out_dir, f"raw-issues-{index}.json").write_text(
            json.dumps({"complete": True, "items": issues}), encoding="utf-8")
        Path(out_dir, f"raw-pulls-{index}.json").write_text(
            json.dumps({"complete": True, "items": pulls}), encoding="utf-8")
        # Phase 2 — per-PR status. Repos stay SEQUENTIAL here so `concurrency` is the exact
        # number of reads this process can ever have in flight (the secondary-rate-limit
        # budget above); the concurrency lives INSIDE _pr_status_snapshot.
        status_items, skips = _pr_status_snapshot(fetch, claim, repo, pulls, concurrency)
        for skip in skips:
            print(f"SNAPSHOT skip {repo}#{skip['pr_number']}: {skip['reason']}")
        Path(out_dir, f"raw-prstatus-{index}.json").write_text(
            json.dumps({"complete": True, "items": status_items, "skips": skips}),
            encoding="utf-8")
    print(f"SNAPSHOT complete for {len(repos)} target repo(s)")


def _self_test():
    import contextlib
    import io
    import tempfile
    import threading
    from unittest.mock import patch

    claim = _load_claim()
    gate = claim.CI_GATE_CHECK
    draft_gate = claim.CI_GATE_DRAFT_TIER_CHECK
    repo = "example/repo"

    def gate_run(conclusion="success", status="completed", name=None,
                 started_at="2026-07-17T00:00:00Z"):
        return {"name": gate if name is None else name, "status": status,
                "conclusion": conclusion, "started_at": started_at}

    def page(runs, total=None):
        """A well-formed check-runs page: GitHub always reports `total_count` for the
        (optionally filtered) set, and _fetch_check_runs now cross-checks it."""
        return {"check_runs": runs, "total_count": len(runs) if total is None else total}

    def requested_name(url):
        """Which tier name this filtered read asked for ('' = the unfiltered legs walk),
        matched to the parameter BOUNDARY. `check_name=gate` is a strict PREFIX of
        `check_name=gate%2C%20draft-tier`, so a bare substring test answers every draft-tier
        request with the strict name's rows — the fixture bug that would fake this whole defect
        away. This is boundary-safe rather than merely ordering-safe because _fetch_check_runs
        emits the filter FIRST, so a `&` always terminates the encoded name; dropping that `&`
        here (or moving the filter back to the end of the query) reds the tier assertions
        below. [round-2 review, finding 3]"""
        for name in (gate, draft_gate):
            if f"check_name={quote(name, safe='')}&" in url:
                return name
        return ""

    def worker_pull(number, sha):
        return {"number": number, "state": "open",
                "head": {"ref": f"sparq-agent/issue-{number}-1-1", "sha": sha,
                         "repo": {"full_name": repo}}}

    sha_ok, sha_red, sha_over, sha_legs_over, sha_conflict = (
        "1" * 40, "2" * 40, "3" * 40, "4" * 40, "5" * 40)
    sha_draft_red, sha_short = "6" * 40, "7" * 40
    pulls = [
        worker_pull(7, sha_over),        # gate-filtered listing never shortens -> overflow
        worker_pull(9, sha_ok),          # healthy sibling: must still be planned
        worker_pull(11, sha_red),        # concluded gate failure: legs fetched + interpretable
        worker_pull(13, sha_ok),         # detail read hard-fails -> per-item skip
        worker_pull(15, sha_legs_over),  # gate failure but the unfiltered legs walk overflows
        worker_pull(17, sha_ok),         # detail WITHOUT an auto_merge field (round-6 P2)
        worker_pull(19, sha_conflict),   # mergeable null first, then DIRTY (issue #464)
        worker_pull(21, sha_draft_red),  # DRAFT-TIER aggregator only: no `gate` row exists
        worker_pull(23, sha_short),      # page ends short of total_count -> partial read
        {"number": 90, "state": "open",  # non-worker head: excluded from the census entirely
         "head": {"ref": "topic", "sha": sha_ok, "repo": {"full_name": repo}}},
    ]

    conflict_detail_reads = 0
    # The re-poll counter is shared state and the snapshot now reads PRs concurrently, so
    # it is guarded; `reset_fixture` lets the identity check below re-run the SAME fixture
    # from the SAME starting state at a different concurrency.
    fixture_lock = threading.Lock()

    def reset_fixture():
        nonlocal conflict_detail_reads
        with fixture_lock:
            conflict_detail_reads = 0

    def fake_fetch(url):
        nonlocal conflict_detail_reads
        if url.split("?")[0].endswith(f"/repos/{repo}/issues"):
            return []
        if url.split("?")[0].endswith(f"/repos/{repo}/pulls"):
            return pulls if "page=1" in url else []
        if "/pulls/13" in url:
            raise FetchError("boom")
        if url.split("?")[0].endswith("/pulls/17"):
            # [round-6 P2] a detail read that never carried the auto_merge field (degraded/
            # projected upstream response): the record must PRESERVE the absence.
            return {"head": {"sha": sha_ok}, "mergeable": True, "draft": True}
        if url.split("?")[0].endswith("/pulls/19"):
            with fixture_lock:
                conflict_detail_reads += 1
                seen = conflict_detail_reads
            return {"head": {"sha": sha_conflict},
                    "mergeable": None if seen == 1 else False,
                    "draft": True, "auto_merge": None}
        for number, sha in ((7, sha_over), (9, sha_ok), (11, sha_red), (15, sha_legs_over),
                            (21, sha_draft_red), (23, sha_short)):
            if url.split("?")[0].endswith(f"/pulls/{number}"):
                # PR 7 is ARMED (auto_merge latched) — the round-1 disarm-under-overflow case.
                # PR 9 is a DRAFT on the detail read — the round-4 carve-out confirmation bit.
                return {"head": {"sha": sha}, "mergeable": True, "draft": number == 9,
                        "auto_merge": {"merge_method": "squash"} if number == 7 else None}
        # BOUNDARY, not ordering: every filtered read must terminate its encoded check_name
        # with a `&` so a matcher can tell `gate` from the name it is a strict prefix of.
        # Moving the filter back to the end of the query string reds this.
        if "/check-runs?" in url and "check_name=" in url:
            assert re.search(r"[?&]check_name=[^&]+&", url), url
        wanted = requested_name(url)
        if f"/commits/{sha_over}/" in url:
            return page([gate_run() for _ in range(100)], total=1000)   # never a short page
        if f"/commits/{sha_ok}/" in url:
            assert "check_name=" in url, "healthy head must be read gate-filtered"
            return page([gate_run()] if wanted == gate else [])
        if f"/commits/{sha_red}/" in url:
            if wanted == gate:
                return page([gate_run(conclusion="failure")])
            if wanted == draft_gate:
                return page([])
            return page([gate_run(conclusion="failure"),
                         gate_run(conclusion="failure", name="leg-a")])
        if f"/commits/{sha_legs_over}/" in url:
            if wanted == gate:
                return page([gate_run(conclusion="failure")])
            if wanted == draft_gate:
                return page([])
            return page([gate_run(conclusion="failure") for _ in range(100)], total=1000)
        if f"/commits/{sha_conflict}/" in url:
            assert "check_name=" in url, "conflicting head must be read gate-filtered"
            return page([gate_run()] if wanted == gate else [])
        if f"/commits/{sha_draft_red}/" in url:
            # The live sparq shape since draft-tier CI: the head is a DRAFT, so the ONLY
            # aggregator run present is `gate, draft-tier` and a `check_name=gate` read is
            # legitimately EMPTY. Reading only the strict name yields "no gate row" and
            # stands the whole ci-fix admission down on a provably red head.
            if wanted == gate:
                return page([])
            if wanted == draft_gate:
                return page([gate_run(conclusion="failure", name=draft_gate)])
            return page([gate_run(conclusion="failure", name=draft_gate),
                         gate_run(conclusion="failure", name="leg-b")])
        if f"/commits/{sha_short}/" in url:
            # A page that ENDS (short read) while the endpoint itself reports more rows exist:
            # unprovable, and indistinguishable from "this head has no aggregator" if trusted.
            return page([gate_run()], total=42)
        raise AssertionError(f"unexpected fetch {url}")

    # NOTE: this run uses the SHIPPED default concurrency, so every degradation assertion
    # below — the skip histogram and its ORDER, the two-tier degradation split, the
    # partial-read cross-check — is an assertion about the concurrent path, not a serial
    # one that the concurrent path merely resembles.
    with patch.object(time, "sleep") as sleep, tempfile.TemporaryDirectory() as out_dir:
        snapshot_targets(fake_fetch, claim, [repo], out_dir)
        doc = json.loads(Path(out_dir, "raw-prstatus-0.json").read_text(encoding="utf-8"))

    # (i) oversized/unreadable PRs are skipped WITH a reason; the sweep did not die.
    assert doc["complete"] is True
    assert doc["skips"] == [{"pr_number": 7, "reason": "check-runs-overflow"},
                            {"pr_number": 13, "reason": "pr-detail-read-failed"},
                            {"pr_number": 15, "reason": "check-runs-overflow"},
                            {"pr_number": 23, "reason": "check-runs-malformed"}], doc["skips"]
    assert all(skip["reason"] in claim.SNAPSHOT_SKIP_REASONS for skip in doc["skips"])
    # (ii) siblings are still planned, and their records interoperate with the PURE
    # claim-side interpreters (a pre-detail-skipped PR has NO record: nothing to guess from).
    healthy = claim.pr_ci_status(doc["items"]["9"])
    assert healthy["gate"] == "success" and healthy["conflicting"] is False
    assert healthy["check_runs_degraded"] is False
    red = claim.pr_ci_status(doc["items"]["11"])
    assert red["gate"] == "failure" and red["failing_legs"] == ["leg-a"]
    # (ii-b) DRAFT-TIER head: the strict merge-required `gate` context genuinely does not
    # exist on it, but the tiered read sees the red aggregator. Deleting either tier name
    # from CI_REPAIR_GATE_CHECKS (or dropping the second _fetch_check_runs call) turns
    # repair_gate back into "missing" and reds this assertion — which is exactly the live
    # defect: the ci-fix admission was unreachable on every sparq worker head.
    draft_red = claim.pr_ci_status(doc["items"]["21"])
    assert draft_red["gate"] == "missing", draft_red
    assert draft_red["repair_gate"] == "failure", draft_red
    # ...and the aggregator itself is never handed to the fixer as a leg to repair.
    assert draft_red["failing_legs"] == ["leg-b"], draft_red
    # (ii-c) the strict-name heads keep BOTH readings consistent, so the new field cannot
    # silently diverge from `gate` where `gate` is actually present.
    # (the tier-reachable green is GRADED — issue #762 — so it is never the bare "success"
    # that the merge-required `gate` reading uses; both name the same head here.)
    assert healthy["gate"] == "success", healthy
    assert healthy["repair_gate"] == claim.GATE_GREEN_MERGE_REQUIRED, healthy
    assert red["repair_gate"] == "failure", red
    # (ii-d) PARTIAL READ != "no gate row": PR 23's page ended short of the endpoint's own
    # total_count, so the record DEGRADES (visible skip + marker) rather than reporting a
    # head with no aggregator. Deleting the total_count cross-check makes this read
    # "success"/planned and the skip row disappears.
    short = claim.pr_ci_status(doc["items"]["23"])
    assert doc["items"]["23"]["check_runs_degraded"] == "check-runs-malformed"
    assert short["gate"] == "missing" and short["repair_gate"] == "missing", short
    # (iii) POST-detail degradation (PR #60 round-1 fix): a check-run overflow KEEPS the
    # detail record — check_runs EMPTY + an explicit marker — while the pre-detail
    # failure (13) stays a full skip with no record at all.
    assert sorted(doc["items"]) == ["11", "15", "17", "19", "21", "23", "7", "9"], \
        sorted(doc["items"])
    assert doc["items"]["7"] == {"head_sha": sha_over, "mergeable": True, "draft": False,
                                 "auto_merge": {"merge_method": "squash"},
                                 "check_runs": [],
                                 "check_runs_degraded": "check-runs-overflow"}
    # [round-6 P2] ABSENCE != NULL survives the snapshot + JSON round-trip: the detail read
    # for 17 carried NO auto_merge field, so its record must OMIT the key (never emit the
    # explicit-null "unarmed" sentinel), and the claim-side interpreter must read the arm
    # bit as UNKNOWN — an absent field can never prove a parked PR inactive (busy,
    # fail closed). Contrast 9: an EXPLICIT null (a field REST actually served) still
    # reads unarmed.
    assert "auto_merge" not in doc["items"]["17"], doc["items"]["17"]
    assert claim.pr_ci_status(doc["items"]["17"])["armed"] is None
    assert "auto_merge" in doc["items"]["9"]
    assert claim.pr_ci_status(doc["items"]["9"])["armed"] is False
    degraded = claim.pr_ci_status(doc["items"]["7"])
    assert degraded["gate"] == "missing" and degraded["armed"] is True
    assert degraded["check_runs_degraded"] is True
    # [round-4 P1] the detail's draft bit flows through to the claim-side interpreter:
    # the busy-partition carve-out consumes it as the NEWER-read draft confirmation.
    assert healthy["draft"] is True and degraded["draft"] is False
    # The PARTIAL gate=failure read whose advisory-legs walk overflowed is blanked too:
    # a degraded record must never admit a ci-fix (gate reads missing, not failure).
    assert doc["items"]["15"]["check_runs"] == []
    assert claim.pr_ci_status(doc["items"]["15"])["gate"] == "missing"

    # (iv) Issue #464 snapshot -> rows -> enumeration regression: GitHub's first detail
    # response is mergeable=null, the bounded second read resolves it to False, and the
    # review:changes worker PR surfaces in the rebase fix flavour. Reverting the poll leaves
    # mergeable null: the filtered assertion then sees zero rebase items (mutation check).
    review_changes = {
        "number": 19, "state": "open", "draft": True, "body": "Fixes #19",
        "labels": [{"name": "review:changes"}],
        "head": {"ref": "sparq-agent/issue-19-1-1", "sha": sha_conflict,
                 "repo": {"full_name": repo}},
        "user": {"login": "sparq-agent[bot]", "type": "Bot"},
    }
    provenance19 = {19: {
        "pr_number": 19, "head_sha_at_open": sha_conflict, "impl_provider": "openai",
        "impl_alias": "sol", "impl_account_h": "ab" * 8, "issue": 19,
        "recorded_at_run": "1.1",
    }}
    status19 = {19: claim.pr_ci_status(doc["items"]["19"])}
    repair_log = io.StringIO()
    with contextlib.redirect_stdout(repair_log):
        repair_items = claim.enumerate_review_items(
            repo, [review_changes], provenance19, [], {19: ["role:impl"]}, 1000,
            pr_status=status19)
    assert [(item["state"], claim.FIX_KIND_OF_STATE[item["state"]])
            for item in repair_items] == [("needs-rebase", "rebase")], repair_items
    assert conflict_detail_reads == 2
    sleep.assert_called_once_with(MERGEABLE_POLL_INTERVAL_SECONDS)
    # Issue #464 conflict-lane census, asserted at the SNAPSHOT boundary rather than on a
    # hand-built status: the re-polled DIRTY record is counted, the lane is reported firing,
    # and no shortfall warning is raised.
    assert (f"review-enumeration: {repo}: 1 worker PR(s) on a CONFLICTING base -> 1 "
            "needs-rebase repair item(s)") in repair_log.getvalue(), repair_log.getvalue()
    assert "::warning::" not in repair_log.getvalue(), repair_log.getvalue()
    unresolved19 = {19: claim.pr_ci_status({**doc["items"]["19"], "mergeable": None})}
    unresolved_log = io.StringIO()
    with contextlib.redirect_stdout(unresolved_log):
        assert [item for item in claim.enumerate_review_items(
            repo, [review_changes], provenance19, [], {19: ["role:impl"]}, 1000,
            pr_status=unresolved19) if item["state"] == "needs-rebase"] == []
    # An UNRESOLVED mergeability proves no conflict, so it raises no census either — the census
    # must never invent a DIRTY PR out of the null the poll failed to resolve.
    assert "CONFLICTING" not in unresolved_log.getvalue(), unresolved_log.getvalue()
    human_owned = {**review_changes,
                   "labels": [{"name": "review:changes"}, {"name": "needs:user"}]}
    human_log = io.StringIO()
    with contextlib.redirect_stdout(human_log):
        assert claim.enumerate_review_items(
            repo, [human_owned], provenance19, [], {19: ["role:impl"]}, 1000,
            pr_status=status19) == []
    # The human-owned hold still excludes the DIRTY PR from any autonomous rebase — but the
    # residue is now LOUD: 1 conflicting PR in, 0 rebase items out, warned about on the tick it
    # happens, so a stalled DIRTY backlog can never read like an empty one (issue #464).
    assert (f"review-enumeration: {repo}: 1 worker PR(s) on a CONFLICTING base -> 0 "
            "needs-rebase repair item(s)") in human_log.getvalue(), human_log.getvalue()
    assert "auto-rebase lane is not firing" in human_log.getvalue(), human_log.getvalue()

    # (v) THE round-1 point — the degraded record restores the #42 disarm under overflow:
    # an ARMED worker PR whose churned head advanced past its reviewed-sha marker IS
    # enumerated for disarm even though its check-run listing blew the ceiling. Deleting
    # the degraded-record preservation in _pr_status_record turns this red (mutation-
    # checked): no record -> the disarm net stands down -> fail-OPEN.
    def bot_pull(number, sha, body, draft=False):
        return {"number": number, "state": "open", "draft": draft,
                "user": {"login": "sparq-agent[bot]"}, "labels": [], "body": body,
                "head": {"ref": f"sparq-agent/issue-{number}-1-1", "sha": sha,
                         "repo": {"full_name": repo}}}

    pr_status = {int(number): claim.pr_ci_status(record)
                 for number, record in doc["items"].items()}
    provenance = {7: {"pr_number": 7}, 13: {"pr_number": 13}}
    moved = bot_pull(7, sha_over, f"x <!-- sparq-reviewed-sha:{sha_ok} -->")
    assert [item["pr_number"] for item in claim.enumerate_disarm_items(
        repo, [moved], pr_status, provenance)] == [7]

    # (vi) the PRE-detail residual (documented, accepted): PR 13's detail read itself
    # failed, so nothing sound is derivable — no record, and the disarm stands down even
    # for an armed mismatch this tick. A detail-read failure is a GitHub API outage
    # condition, NOT attacker-inducible by inflating check-run volume on a head (the
    # vector the round-1 fix closes).
    moved13 = bot_pull(13, sha_ok, f"x <!-- sparq-reviewed-sha:{sha_red} -->")
    assert claim.enumerate_disarm_items(repo, [moved13], pr_status, provenance) == []

    # Repo-level census overflow degrades to a pr_number-0 skip, not a dead sweep.
    census = [worker_pull(1000 + n, sha_ok) for n in range(WORKER_PR_STATUS_LIMIT + 1)]
    items, skips = _pr_status_snapshot(fake_fetch, claim, repo, census)
    assert items == {} and skips == [{"pr_number": 0, "reason": "worker-pr-census-overflow"}]

    # Repo-level listings stay sweep-fatal: a runaway issues walk still refuses the snapshot.
    def endless(url):
        return [{"n": 1} for _ in range(100)]
    try:
        _paginated(endless, f"/repos/{repo}/issues?state=open")
    except FetchError:
        pass
    else:
        raise AssertionError("runaway repo listing must stay fail-closed")

    # ---- (vii) CONCURRENCY (issue #721) -------------------------------------------------
    # The claim under test is narrow and must be tested as stated: independent reads
    # OVERLAP, the overlap is BOUNDED by the rate-limit budget, and overlapping changes
    # NOTHING about what the snapshot says. Each check below names the mutation that reds
    # it, and each is a BEHAVIOUR kill (a wrong answer / a lost overlap), not a crash.

    def snapshot_parallel_output_is_identical_to_serial():
        """RED if concurrency changes ANY byte of the snapshot — including the ORDER of the
        `skips` histogram. Mutation: fold results in completion order (e.g. swap
        `pool.map` for `as_completed`) and the skip rows reorder; drop the per-item catch
        inside `snapshot_one` and PR 13's skip becomes an aborted sweep."""
        rendered = {}
        for label, concurrency in (("serial", 1), ("parallel", SNAPSHOT_CONCURRENCY)):
            reset_fixture()
            with patch.object(time, "sleep"), tempfile.TemporaryDirectory() as out_dir:
                snapshot_targets(fake_fetch, claim, [repo], out_dir, concurrency=concurrency)
                rendered[label] = {path.name: path.read_bytes()
                                   for path in sorted(Path(out_dir).iterdir())}
        assert rendered["serial"] == rendered["parallel"], (
            "concurrent snapshot diverged from the serial walk: "
            + repr({name: (rendered['serial'].get(name), rendered['parallel'].get(name))
                    for name in set(rendered['serial']) | set(rendered['parallel'])
                    if rendered['serial'].get(name) != rendered['parallel'].get(name)}))
        # ...and the thing they agree on is the COMPLETE, degradation-bearing snapshot, not
        # two identically-empty runs (the way this check would go vacuous).
        both = json.loads(rendered["serial"]["raw-prstatus-0.json"].decode("utf-8"))
        assert both["complete"] is True
        assert sorted(both["items"]) == ["11", "15", "17", "19", "21", "23", "7", "9"]
        assert [skip["pr_number"] for skip in both["skips"]] == [7, 13, 15, 23]
        assert both["items"]["23"]["check_runs_degraded"] == "check-runs-malformed"

    def per_pr_reads_actually_overlap():
        """THE headline guard. RED if the per-PR reads are issued one at a time: every
        worker PR's detail read blocks on a barrier that only releases once
        SNAPSHOT_CONCURRENCY of them are simultaneously in flight. Mutation: delete the
        ThreadPoolExecutor from `_ordered_map` (or hard-code concurrency to 1) and the
        barrier times out -> `overlapped` is False -> red. This is a behaviour kill: the
        serial code still returns a correct snapshot, it just never overlaps."""
        parties = SNAPSHOT_CONCURRENCY
        barrier = threading.Barrier(parties, timeout=15)
        seen = {"broken": False, "in_flight": 0, "peak": 0}
        seen_lock = threading.Lock()
        overlap_pulls = [worker_pull(200 + n, sha_ok) for n in range(parties)]

        def barrier_fetch(url):
            with seen_lock:
                seen["in_flight"] += 1
                seen["peak"] = max(seen["peak"], seen["in_flight"])
            try:
                if re.search(r"/pulls/\d+$", url.split("?")[0]):
                    try:
                        barrier.wait()
                    except threading.BrokenBarrierError:
                        seen["broken"] = True
                    return {"head": {"sha": sha_ok}, "mergeable": True, "draft": False,
                            "auto_merge": None}
                return page([gate_run()] if requested_name(url) == gate else [])
            finally:
                with seen_lock:
                    seen["in_flight"] -= 1

        items, skips = _pr_status_snapshot(barrier_fetch, claim, repo, overlap_pulls)
        assert seen["broken"] is False, (
            f"per-PR reads did not overlap: only {seen['peak']} of {parties} reads were "
            "ever in flight together, so the barrier timed out")
        assert seen["peak"] == parties, seen
        # and the overlapped run still produced every record, with no skips.
        assert sorted(items) == sorted(str(200 + n) for n in range(parties)), sorted(items)
        assert skips == [], skips

    def repo_listings_overlap_across_repos():
        """The phase-1 half of the same claim, and it needs its own red test: the per-PR
        guard above passes happily while the repo-level listing walks are still issued one
        repo at a time. RED if phase 1 stops overlapping (mutation: replace the
        `_ordered_map` in `snapshot_targets` with a list comprehension) — the barrier only
        releases once all 2*len(repos) independent walks are in flight together."""
        listing_repos = ["overlap/one", "overlap/two"]
        parties = min(2 * len(listing_repos), SNAPSHOT_CONCURRENCY)
        barrier = threading.Barrier(parties, timeout=15)
        seen = {"broken": False, "walks": 0}
        seen_lock = threading.Lock()

        def listing_fetch(url):
            path = url.split("?")[0]
            assert path.endswith("/issues") or path.endswith("/pulls"), url
            with seen_lock:
                seen["walks"] += 1
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                seen["broken"] = True
            return []          # a short first page: each walk is exactly one request

        with tempfile.TemporaryDirectory() as out_dir:
            snapshot_targets(listing_fetch, claim, listing_repos, out_dir)
            written = sorted(path.name for path in Path(out_dir).iterdir())
        assert seen["broken"] is False, (
            "repo-level listing walks did not overlap: the barrier timed out after "
            f"{seen['walks']} of {parties} walks started")
        assert seen["walks"] == parties, seen
        assert written == ["raw-issues-0.json", "raw-issues-1.json", "raw-prstatus-0.json",
                           "raw-prstatus-1.json", "raw-pulls-0.json",
                           "raw-pulls-1.json"], written

    def in_flight_reads_never_exceed_the_requested_bound():
        """RED if the cap stops being honoured. Uses a deliberately SMALL bound (3) so the
        check is independent of the box's CPU count: dropping `max_workers` from the
        ThreadPoolExecutor falls back to an interpreter default of at least 5 on any
        supported runner, which exceeds 3. Deleting the `min(..., len(jobs))` clamp or
        passing the bound through unread reds this too."""
        bound = 3
        seen = {"in_flight": 0, "peak": 0}
        seen_lock = threading.Lock()
        slow_pulls = [worker_pull(300 + n, sha_ok) for n in range(40)]

        def slow_fetch(url):
            with seen_lock:
                seen["in_flight"] += 1
                seen["peak"] = max(seen["peak"], seen["in_flight"])
            try:
                # A real wait (not the patched time.sleep) so overlap is observable.
                threading.Event().wait(0.01)
                if re.search(r"/pulls/\d+$", url.split("?")[0]):
                    return {"head": {"sha": sha_ok}, "mergeable": True, "draft": False,
                            "auto_merge": None}
                return page([gate_run()] if requested_name(url) == gate else [])
            finally:
                with seen_lock:
                    seen["in_flight"] -= 1

        items, skips = _pr_status_snapshot(
            slow_fetch, claim, repo, slow_pulls, concurrency=bound)
        assert seen["peak"] <= bound, f"cap not honoured: {seen['peak']} reads in flight"
        assert seen["peak"] > 1, f"the bounded run never overlapped at all: {seen['peak']}"
        assert len(items) == 40 and skips == []

    def concurrency_stays_inside_the_secondary_rate_limit_budget():
        """The shipped default is a BUDGET, not taste. GitHub allows 900 points/minute for
        REST and a GET costs 1; the measured mean read on this workload is ~0.85 s, so C
        in-flight reads sustain C/0.85 per second. RED if SNAPSHOT_CONCURRENCY is raised
        past what that arithmetic allows (C=16 -> ~1130/min, over budget)."""
        github_rest_points_per_minute = 900
        measured_mean_read_seconds = 0.85      # instrumented run, 613 reads, 2026-07-27
        sustained_per_minute = SNAPSHOT_CONCURRENCY / measured_mean_read_seconds * 60
        assert sustained_per_minute <= github_rest_points_per_minute, sustained_per_minute
        # ...and the budget check is not vacuous: the next power of two blows it.
        assert (2 * SNAPSHOT_CONCURRENCY) / measured_mean_read_seconds * 60 \
            > github_rest_points_per_minute

    def sweep_fatal_listing_failure_is_still_fatal():
        """RED if a failure inside a concurrent listing walk is swallowed. Mutation: catch
        or `return_exceptions`-style absorb the FetchError in `_ordered_map` and the
        snapshot returns normally with a repo's listing silently missing — the exact
        'partial view sold as complete' failure the fail-closed ceiling exists to prevent.
        Also pins that NOTHING is written when the snapshot dies."""
        def half_dead(url):
            if url.split("?")[0].endswith("/repos/dead/repo/pulls"):
                raise FetchError("listing down")
            return []

        with tempfile.TemporaryDirectory() as out_dir:
            try:
                snapshot_targets(half_dead, claim, [repo, "dead/repo"], out_dir)
            except FetchError:
                pass
            else:
                raise AssertionError("a failed repo listing must stay sweep-fatal")
            assert list(Path(out_dir).iterdir()) == [], "a dead sweep wrote a partial snapshot"

    def retry_after_is_honoured_and_capped():
        """Overlapping reads is how a SECONDARY rate limit gets provoked, so the back-off
        has to honour what GitHub asks for. Tests the helper AND its call site in
        `make_fetch` — a helper that nothing calls is the classic vacuous guard."""
        def http_error(code, headers):
            return HTTPError("https://api.github.com/x", code, "throttled", headers, None)

        assert _retry_delay(http_error(403, {"Retry-After": "7"}), 0) == 7
        assert _retry_delay(http_error(429, {"Retry-After": "3600"}), 0) \
            == RETRY_AFTER_CAP_SECONDS
        # absent / malformed / non-positive headers fall back to the original ladder
        assert _retry_delay(http_error(500, {}), 0) == 5
        assert _retry_delay(http_error(500, {}), 1) == 10
        assert _retry_delay(http_error(403, {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
                            1) == 10
        assert _retry_delay(http_error(403, {"Retry-After": "0"}), 0) == 5

        # THE CALL SITE: make_fetch must actually wait what the header asked for.
        attempts = {"n": 0}

        def throttled(request, timeout=None):
            attempts["n"] += 1
            raise http_error(403, {"Retry-After": "7"})

        module = sys.modules[__name__]
        with patch.object(module, "urlopen", throttled), \
                patch.object(time, "sleep") as slept:
            try:
                make_fetch("t")("https://api.github.com/x")
            except FetchError:
                pass
            else:
                raise AssertionError("an exhausted retryable read must raise FetchError")
        assert attempts["n"] == 3, attempts
        assert [call.args[0] for call in slept.call_args_list] == [7, 7], \
            slept.call_args_list

    def the_three_403s_are_told_apart():
        """#819. Until this landed every 403 was retried three times, so the read that proved the
        budget was gone answered by spending three more requests on it — eight threads deep."""
        assert classify_403({"Retry-After": "7"}, "") == "secondary"
        assert classify_403({}, "You have exceeded a secondary rate limit") == "secondary"
        # The MEASURED budget shape (2026-07-27, 27 observed failures): remaining 0, NO Retry-After.
        assert classify_403({"x-ratelimit-remaining": "0",
                             "x-ratelimit-reset": "1785182238"}, "") == "budget"
        assert classify_403({}, '{"message":"API rate limit exceeded for installation"}') \
            == "budget"
        # Header case is not the server's contract to keep: GitHub sends lowercase, http.client
        # normalises, a proxy may not.
        assert classify_403({"X-RateLimit-Remaining": "0"}, "") == "budget"
        # The residual class. No rate evidence at all => permission, never "assume throttle".
        assert classify_403({"x-ratelimit-remaining": "4931"},
                            "Resource not accessible by integration") == "permission"
        assert classify_403({}, "") == "permission"
        # ORDER: a secondary limit that ALSO reports remaining 0 must still be the retryable
        # class — GitHub told us exactly how long to wait, so waiting is strictly better than
        # standing the tick down.
        assert classify_403({"Retry-After": "5", "x-ratelimit-remaining": "0"}, "") == "secondary"

    def budget_403_is_not_retried_and_is_sweep_fatal():
        """Two properties, and BOTH are load-bearing at the call site:

        the retry COUNT — a non-retryable class must cost exactly one request, which is the whole
        point of classifying at all — and the exception TYPE. Asserting only the count passes a
        mutant that keeps the request count at one but raises a FetchError instead of a
        BudgetExhausted, and that mutant is not cosmetic: FetchError is what every per-item
        handler in this file converts into a per-PR skip, so it would put the sweep straight back
        into hammering an empty bucket one PR at a time."""
        module = sys.modules[__name__]
        for label, headers, body, want_attempts, want_type in (
                ("budget", {"x-ratelimit-remaining": "0"}, b"", 1, BudgetExhausted),
                ("budget-by-body", {},
                 b'{"message":"API rate limit exceeded for installation"}', 1, BudgetExhausted),
                ("permission", {"x-ratelimit-remaining": "4931"},
                 b"Resource not accessible by integration", 1, FetchError),
                ("secondary", {"Retry-After": "1"}, b"secondary rate limit", 3, FetchError),
        ):
            attempts = {"n": 0}

            def refuse(request, timeout=None, _h=headers, _b=body):
                attempts["n"] += 1
                raise HTTPError("https://api.github.com/x", 403, "no", _h, io.BytesIO(_b))

            with patch.object(module, "urlopen", refuse), patch.object(time, "sleep"):
                try:
                    make_fetch("t")("https://api.github.com/x")
                except BaseException as exc:  # noqa: BLE001 - the TYPE is the assertion
                    got = type(exc)
                else:
                    raise AssertionError(f"a {label} 403 must raise")
            assert got is want_type, (label, got, want_type)
            assert attempts["n"] == want_attempts, (label, attempts)

    def budget_403_is_never_downgraded_to_a_per_item_skip():
        """THE COMPOSITION TRAP. `_fetch_check_runs` converts every FetchError into a per-PR
        `check-runs-read-failed` skip, and `snapshot_one` swallows that. A budget failure raised as
        a FetchError would therefore be recorded as a skip on PR after PR while the sweep kept
        hammering an empty bucket — the sweep would look degraded-but-alive and would issue
        hundreds more requests. BudgetExhausted is not a FetchError precisely so it escapes both
        handlers, and this is the test that would go red if someone 'tidied' it into the
        hierarchy."""
        assert not issubclass(BudgetExhausted, FetchError)

        def broke(url):
            raise BudgetExhausted("budget gone")

        for label, call in (
                ("the check-runs walk",
                 lambda: _fetch_check_runs(broke, repo, "a" * 40, check_name=gate)),
                ("the PR detail read",
                 lambda: _pr_status_record(broke, claim, repo, 7)),
                # The full per-PR sweep, over a pull the worker filter actually admits — a
                # fixture the filter rejects would make this assertion vacuous by never issuing
                # a read at all.
                ("the whole per-PR snapshot", lambda: _pr_status_snapshot(
                    broke, claim, repo,
                    [worker_pull(7, "b" * 40)], concurrency=1)),
        ):
            try:
                call()
            except BudgetExhausted:
                pass
            except SnapshotItemError as exc:
                raise AssertionError(
                    f"{label} downgraded a budget failure to a per-item skip "
                    f"({exc.reason}) — the sweep would keep issuing requests") from exc
            else:
                raise AssertionError(f"{label} swallowed a budget failure entirely")

    def the_reserve_stops_the_sweep_before_the_budget_is_gone():
        """#796: the authoritative remaining count only ever appears on the RESPONSE. Reading it
        off successful responses is what makes the back-off happen one request early instead of
        one request late."""
        module = sys.modules[__name__]

        class _Response:
            def __init__(self, headers):
                self.headers = headers
                self._body = io.BytesIO(b"[]")

            def read(self, *args):
                return self._body.read(*args)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        for label, remaining, want in (
                ("well inside the budget", 4931, "ok"),
                ("exactly at the reserve", RATE_LIMIT_RESERVE, "stop"),
                ("one above the reserve", RATE_LIMIT_RESERVE + 1, "ok"),
                ("header absent (proves nothing — must NOT fail closed)", None, "ok"),
        ):
            headers = {} if remaining is None else {"x-ratelimit-remaining": str(remaining),
                                                    "x-ratelimit-limit": "5000",
                                                    "x-ratelimit-reset": "1785182238"}
            with patch.object(module, "urlopen",
                              lambda request, timeout=None, _h=headers: _Response(_h)):
                try:
                    make_fetch("t")("https://api.github.com/x")
                    got = "ok"
                except BudgetExhausted:
                    got = "stop"
            assert got == want, (label, got, want)

    snapshot_parallel_output_is_identical_to_serial()
    per_pr_reads_actually_overlap()
    repo_listings_overlap_across_repos()
    in_flight_reads_never_exceed_the_requested_bound()
    concurrency_stays_inside_the_secondary_rate_limit_budget()
    sweep_fatal_listing_failure_is_still_fatal()
    retry_after_is_honoured_and_capped()
    the_three_403s_are_told_apart()
    budget_403_is_not_retried_and_is_sweep_fatal()
    budget_403_is_never_downgraded_to_a_per_item_skip()
    the_reserve_stops_the_sweep_before_the_budget_is_gone()

    print("plan-snapshot self-test PASSED")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repos_file", nargs="?", help="newline-delimited owner/repo manifest")
    parser.add_argument("out_dir", nargs="?", help="directory for the raw-*.json snapshots")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    if not args.repos_file or not args.out_dir:
        parser.error("repos_file and out_dir are required unless --self-test is used")
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise SystemExit("GH_TOKEN is required for the authenticated snapshot")
    repos = [line for line in
             Path(args.repos_file).read_text(encoding="utf-8").splitlines() if line]
    try:
        snapshot_targets(make_fetch(token), _load_claim(), repos, args.out_dir)
    except BudgetExhausted as exc:
        # A distinct, annotated exit: this is not "a read failed", it is "the dispatcher is
        # running hotter than its request budget allows", and it needs a different fix from
        # every other snapshot failure. The annotation puts it on the run summary rather than
        # only in the step log.
        raise SystemExit(f"::error title=dispatch request budget exhausted::{exc}") from exc
    except FetchError as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    sys.exit(main())
