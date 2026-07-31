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
They are also KEEP-FIRST de-duplicated by `number` as the pages are joined (issue #905):
GitHub paginates a live ordering, so a row created or reordered mid-walk can land on two
pages, and every downstream repeat check — `validate_plan`'s repeated review/disarm item
and repeated issue row — reads that as corruption and kills the whole fleet-wide tick.
The join is the one place the race exists, so it is the one place it is absorbed; the
drop is annotated, never silent. See `_paginated`.

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
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import traceback
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import (Request, HTTPHandler, HTTPRedirectHandler, HTTPSHandler,
                            build_opener, urlopen)
import zipfile


class _NoRedirect(HTTPRedirectHandler):
    """Refuse to auto-follow. urllib re-sends request headers across a redirect, so following
    GitHub's 302 to blob storage automatically would forward the `Authorization` header to a
    third-party host. `make_download` takes the hop manually, without the credential."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _load_retry_taxonomy(filename, module_name):
    """Load a shared retry-classification helper out of scripts/ (same checkout), BY PATH, not by
    `import <name>`: `scripts/` is not a package and the CWD a workflow step runs from is not this
    directory.

    A load failure is FATAL and loud. This module's whole retry policy — WHICH 403 is retried and
    which stops the sweep (`gh_403`, #819), and which STATUSES it opts into replaying
    (`http_transient`, #552) — is defined in these files, and a missing taxonomy must never degrade
    into "classify nothing, retry everything": that is the exact behaviour #819 removed."""
    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load registry helper {path} — a retry taxonomy is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gh_403 = _load_retry_taxonomy("gh_403.py", "registry_gh_403_for_snapshot")
http_transient = _load_retry_taxonomy("http_transient.py", "registry_http_transient_for_snapshot")

# WHICH STATUSES THIS READ WALK REPLAYS. An ALIAS of the shared taxonomy's declared policy
# (registry #552), never a second table: this set was written out by hand here and — with a
# DIFFERENT, deliberately different membership — by hand in groom.py, with nothing anywhere
# comparing the two. The difference is intentional (this walk opts 429 in because it must survive a
# burst limiter to produce a plan at all; groom's cron sweep fails closed on every 4xx), and it is
# now enumerated and asserted in ONE place. `RETRY_STATUS_POLICY.rationale` carries the reasoning;
# `the_retry_status_policy_is_the_SHARED_one` below pins the delegation so it cannot be re-inlined.
RETRY_STATUS_POLICY = http_transient.PLAN_SNAPSHOT_READ
# 403 is deliberately NOT opted in (issue #819) — and since #552 it CANNOT be: the shared taxonomy
# refuses a policy that names 403 at all, at construction time, precisely because it is not a status
# decision. It is not one status, it is three different server answers wearing the same number, and
# only one of them is a blip worth retrying:
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
#
# THE TAXONOMY NOW LIVES IN scripts/gh_403.py (registry #1208), and this file is one of its two
# consumers. It was moved because a SECOND component — dispatch-secrets-guard, which sees the same
# 403 through `gh` CLI stderr rather than through response headers — had grown its own, coarser
# copy that put every 403 in one "availability" bucket. One 403 must not have two diagnoses in one
# pipeline. The markers and `classify_403` below are aliases of the shared definitions, NOT second
# copies: rebinding is what makes divergence impossible, and `_test_classifier_is_the_shared_one`
# pins the delegation so nobody can quietly re-inline it.
_SECONDARY_403_MARKERS = gh_403.SECONDARY_403_MARKERS
_BUDGET_403_MARKERS = gh_403.BUDGET_403_MARKERS
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

# ---------------------------------------------------------------------------------------------
# CONDITIONAL (ETag) READS — issue #1207.
#
# The tick's request SET is not reducible without weakening completeness (the module docstring
# above derives why: REST `check_name` takes one value, and REST cannot filter check runs by
# conclusion). But most of those requests do not have to be BILLABLE. An authenticated
# conditional request that answers `304 Not Modified` does not decrement the bucket, so the
# lever is to stop PAYING for reads whose answer has not changed, without issuing fewer of them.
#
# MEASURED 2026-07-29, and every number here is off a real response, not the documentation:
#
#   * Is a 304 free on THIS token class? Yes. Probed in Actions with `github.token` — the token
#     this job actually runs on, whose bucket reports `x-ratelimit-limit: 5000`,
#     `x-ratelimit-resource: core`. Against a live worker head: 10 unconditional GETs moved
#     `x-ratelimit-used` by +10; 10 conditional GETs carrying `If-None-Match` answered 304 and
#     moved it by +0. Measured on all three check-runs legs this file issues (`check_name=gate`,
#     `check_name=gate, draft-tier`, and the unfiltered legs walk). The A/B is kept in that
#     order deliberately: the unconditional burst is a KNOWN ANSWER, so a run whose control does
#     not read +10 has proved its instrument broken and may not be believed. The first version of
#     that probe reported "exempt" while reading a missing header as -1, and the control is what
#     caught it.
#
#   * How often is the answer actually unchanged? UNDER LOAD ~87-90%, and that is the figure
#     every saving here is stated at (independent re-measure on a busy window; my own first
#     numbers came from a quieter one and were too favourable). Over one tick interval,
#     re-reading the exact
#     urls this file issues against the live targets: check-runs 214 of 214 unchanged (806 s),
#     and 213 of 222 over ~25 min END TO END — that second figure RE-LISTS the pulls first, so a
#     PR whose head advanced contributes a new url that no stored ETag can help, counted as a
#     miss rather than quietly dropped. Settled heads dominate because a concluded gate is
#     terminal for that SHA: the reads that churn are exactly the ones that must be re-fetched.
#
#   * PR DETAIL is NOT cached, on the same measurement: 0 of 107 and 0 of 111 `/pulls/{n}` reads
#     were unchanged across a tick. The detail body embeds the repository object, which moves on
#     every push and every issue anywhere in the repo, so its ETag turns over continuously in a
#     busy repo. Caching it would store ~100 large bodies to buy nothing, so `_is_cacheable`
#     admits the check-runs reads ONLY. The listings are excluded for the same reason.
#
#   * Does the STORE cost more than it saves? It costs TWO requests per tick (the artifact
#     listing and the download), against ~455 saved.
#
# HOW THE STORE TRAVELS, AND WHY IT IS NOT `actions/cache` (adversarial review of PR #1218).
# The first version of this rode `actions/cache/restore`. That was WRONG, and not subtly:
#
#   1. `@actions/toolkit` extracts with `tar -xf ... -P`. `-P` is `--absolute-names`, which
#      disables tar's leading-`/` stripping AND its refusal of `..` members (verified in
#      actions/toolkit packages/cache/src/internal/tar.ts, `case 'extract'`). A cache entry is
#      therefore an ARBITRARY FILE WRITE, not merely data.
#   2. Cache entries carry NO writer attribution, and an exact-key miss falls through to the
#      `restore-keys` prefix — i.e. "newest entry anyone in the default-branch scope wrote".
#      The target-repo code this workflow's own comments call hostile runs in this very job,
#      after the save; so do worker.yml and review-fix.yml.
#   3. The restore landed BEFORE the `github.token`-bearing snapshot step, and the runner
#      populates `_actions/` before any step runs — so reordering cannot fix it either.
#
# So the transport was a write primitive aimed at a job that subsequently holds a token. It is
# replaced by one that CANNOT write: the previous tick's store is read from the ARTIFACTS API
# straight into memory (`zipfile` over a `BytesIO`), bounded, and parsed. Nothing is extracted to
# the filesystem, so there is no path for a poisoned entry to reach any file at all. Artifacts
# also carry the provenance the cache API lacks — the producing run's `head_branch` and
# `head_repository_id` — and this reader requires both before it will look at one.
#
# WHAT A POISONED STORE COULD STILL DO, stated exactly — and NOT the tidier claim it is tempting
# to make here. Review round 1 suggested asserting that check-run data never crosses into the
# PLAN->CLAIM artifact. THAT IS FALSE, and it was checked rather than adopted: check-run-DERIVED
# values do cross, in two places. `review_items[].context` carries verbatim failing-leg NAMES
# (dispatch-claim.py `interpret_check_runs` -> `_sanitize_leg` -> the `needs-ci-fix` emit) and a
# gate-conclusion string ("gate evidence: ..." on `stranded`), and `review_items[].state` is
# itself selected by `repair_gate_of`.
#
# The bound that DOES hold, and the only one relied on:
#
#   * CLAIM re-derives the gate LIVE. `_live_repair_gate` -> `_paged_check_runs` reads
#     `repos/<repo>/commits/<head_sha>/check-runs` at CLAIM time, and `decide_repair_admission` /
#     `stranded_live` gate every act on THAT value. The plan's `context` is advisory prompt text
#     for the fix model; the plan's `state` only selects which live predicate runs. So a poisoned
#     store cannot manufacture an admission the live head does not independently justify.
#   * The dispatcher has NO arm or merge path at all — the only `ready-and-arm` in the repository
#     is review-fix.yml's host-only step, and it re-reads live too.
#
# So the residual is: misleading advisory prompt text, and a wasted or skipped repair round that
# the live read then refuses to confirm. `_the_plan_carries_no_new_check_run_derived_field` below
# pins the crossing set so a THIRD channel cannot be added silently.
#
# FAIL TOWARD RE-FETCHING, ALWAYS. `If-None-Match` is sent ONLY when the payload it maps to is in
# hand, so a 304 can never be answered from a cache we do not hold; a malformed, truncated or
# absent store simply degrades to today's unconditional sweep. Acting on stale check state would
# be far worse than spending the request, so every ambiguous case spends the request.
CONDITIONAL_STORE_SCHEMA = "registry-snapshot-etags/v1"
# Bound on stored entries, so a store that somehow accumulates cannot grow without limit. Two
# targets x WORKER_PR_STATUS_LIMIT PRs x (2 tier names + the legs walk's pages) has ample room.
CONDITIONAL_STORE_LIMIT = 4000
# The artifact this travels in. Matched by EQUALITY, never by prefix — the same rule
# dispatch-tick-floor.py applies to its own marker, and for the same reason.
STORE_ARTIFACT = "dispatch-etags"
STORE_MEMBER = "etags.json"
# EVERY bound below exists because the bytes are REMOTE CONTENT. A measured live store is ~0.43
# MiB, so these are orders of magnitude of headroom, not tuning knobs; their job is to make an
# oversized or zip-bombed store a bounded no-op instead of a MemoryError that takes the sweep —
# and every subsequent tick — down with it.
STORE_MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024
STORE_MAX_JSON_BYTES = 64 * 1024 * 1024


def _is_cacheable(url):
    """Which reads may be answered conditionally. CHECK-RUNS ONLY — see the measurement above:
    it is the 77% leg AND the one that is actually static between ticks. Matched on the
    parameter BOUNDARY (`/check-runs?`) rather than a bare substring, the same rule
    `_fetch_check_runs` applies to its own filter."""
    return "/check-runs?" in url


class ConditionalStore:
    """Cross-tick ETag store for the check-runs reads. Not a general HTTP cache: it holds one
    `{etag, payload}` per url and refuses to answer anything it cannot fully account for.

    THE SAFETY INVARIANT, and the only one that matters: `etag_for` returns an ETag ONLY when
    this store also holds the PAYLOAD that ETag names. That is what makes a 304 impossible to
    receive without the body to satisfy it — the failure mode the issue calls out (treating a
    cache miss as "no change") is not handled here, it is unreachable.
    """

    def __init__(self, entries=None):
        self.entries = entries if isinstance(entries, dict) else {}
        self._hits = 0
        self._billable = 0
        self.seen = set()
        # EVERY mutator below runs on the SNAPSHOT_CONCURRENCY-wide pool. `self._hits += 1` is a
        # read-modify-write, so without this lock the audit line under-reports under exactly the
        # load it exists to measure — and a hit-rate telemetry that can undercount cannot detect
        # its own mechanism silently degrading to 0%, which is the failure this line is for.
        # (Adversarial review of PR #1218; same class as a test that passes for the wrong reason.)
        self._lock = threading.Lock()

    @property
    def hits(self):
        return self._hits

    @property
    def billable(self):
        return self._billable

    def count_hit(self):
        with self._lock:
            self._hits += 1

    def count_billable(self):
        with self._lock:
            self._billable += 1

    def note(self, url):
        """Record that THIS tick asked for `url`, so `prune` can tell a live head from a dead
        one. Called for every cacheable read, hit or miss."""
        if _is_cacheable(url):
            with self._lock:
                self.seen.add(url)

    def etag_for(self, url):
        """The ETag to send, or None to fetch unconditionally."""
        entry = self.entries.get(url)
        if not isinstance(entry, dict) or "payload" not in entry:
            return None
        etag = entry.get("etag")
        return etag if isinstance(etag, str) and etag else None

    def payload_for(self, url):
        """The stored payload for a url whose conditional read answered 304.

        TOTAL and fail-closed. `etag_for` already makes it impossible to receive a 304 we cannot
        satisfy, so reaching the raise below means that invariant has been broken — and the one
        thing this must never do then is hand back something wrong. It raises FetchError, which
        the callers already handle as "this read did not complete" (a per-item skip, or a
        sweep-fatal listing failure) rather than as data. `FetchError` is resolved at CALL time,
        so defining it further down this module is fine."""
        entry = self.entries.get(url)
        if not isinstance(entry, dict) or "payload" not in entry:
            raise FetchError(
                "a conditional read answered 304 for a url this store holds no payload for — "
                "refusing to treat an unsatisfiable 304 as 'unchanged' for "
                + url.split("?")[0])
        return entry["payload"]

    def record(self, url, etag, payload):
        """Remember a 200 so the NEXT tick can ask conditionally. Storing the ETag without the
        payload (or vice versa) is refused rather than half-written: a half-entry is exactly the
        shape `etag_for` must never hand out."""
        if not _is_cacheable(url) or not isinstance(etag, str) or not etag:
            return
        with self._lock:
            if url not in self.entries and len(self.entries) >= CONDITIONAL_STORE_LIMIT:
                return
            self.entries[url] = {"etag": etag, "payload": payload}

    def prune(self):
        """Drop entries THIS tick never asked for — a head that advanced never comes back, so
        its entry is dead weight every future restore would carry. Pruning to `seen` also means
        a tick that read nothing (an aborted sweep) is never mistaken for a tick that found
        nothing live: `save_conditional_store` is only reached on a completed sweep."""
        self.entries = {url: entry for url, entry in self.entries.items() if url in self.seen}

    def summary(self):
        total = self.hits + self.billable
        return (f"SNAPSHOT conditional reads: {self.hits} of {total} cacheable read(s) answered "
                f"304 (budget-exempt), {self.billable} billable; {len(self.entries)} entries "
                f"stored for the next tick")


def parse_conditional_store(raw):
    """Validate the store bytes a previous tick published. EVERY failure — unreadable, wrong
    schema, malformed, oversized — yields an EMPTY store, which costs exactly today's
    unconditional sweep. A store that cannot be trusted is not consulted; it is never partially
    believed.

    `MemoryError` IS CAUGHT HERE, deliberately. It is not an ordinary bug for this input: the
    bytes are remote content, so an oversized store is an ATTACKER-REACHABLE way to raise it, and
    letting it escape would stall this tick and every tick after it until the artifact expired.
    The size ceilings upstream make it nearly unreachable; this makes it survivable."""
    try:
        if isinstance(raw, (bytes, bytearray)):
            if len(raw) > STORE_MAX_JSON_BYTES:
                return ConditionalStore()
            raw = raw.decode("utf-8")
        if not isinstance(raw, str) or len(raw) > STORE_MAX_JSON_BYTES:
            return ConditionalStore()
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError, MemoryError, RecursionError):
        return ConditionalStore()
    if (not isinstance(document, dict)
            or document.get("schema") != CONDITIONAL_STORE_SCHEMA):
        return ConditionalStore()
    entries_raw = document.get("entries")
    if not isinstance(entries_raw, dict):
        return ConditionalStore()
    entries = {}
    for url, entry in entries_raw.items():
        # Per-entry validation, so ONE malformed row costs one re-fetch rather than the tick's
        # whole cache. A row missing either half is dropped: see ConditionalStore.record.
        if (isinstance(url, str) and _is_cacheable(url) and isinstance(entry, dict)
                and isinstance(entry.get("etag"), str) and entry["etag"]
                and "payload" in entry and len(entries) < CONDITIONAL_STORE_LIMIT):
            entries[url] = {"etag": entry["etag"], "payload": entry["payload"]}
    return ConditionalStore(entries)


def parse_rfc3339(raw):
    """RFC3339 -> epoch seconds, or None for anything unparseable (which sorts as 'skip')."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(
            tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def newest_store_artifact(payload, default_branch):
    """The newest non-expired artifact named EXACTLY `STORE_ARTIFACT` that this repository's own
    default branch produced. -> the artifact dict, or None.

    PROVENANCE IS CHECKED HERE because the transport this replaced had none. `head_branch` must
    be the default branch (so a run from an arbitrary `workflow_dispatch` ref cannot publish one
    this reader will pick up) and the producing run's head repository must be the repository
    itself (never a fork). An absent/garbage `default_branch` matches NOTHING — the fail-toward-
    re-fetching direction, since a store we cannot attribute is one we decline to read."""
    if not isinstance(default_branch, str) or not default_branch:
        return None
    artifacts = payload.get("artifacts") if isinstance(payload, dict) else None
    if not isinstance(artifacts, list):
        return None
    best = None
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("name") != STORE_ARTIFACT:
            continue
        if artifact.get("expired"):
            continue
        run = artifact.get("workflow_run")
        if not isinstance(run, dict) or run.get("head_branch") != default_branch:
            continue
        if (run.get("head_repository_id") is None
                or run.get("head_repository_id") != run.get("repository_id")):
            continue
        created = parse_rfc3339(artifact.get("created_at"))
        if created is None:
            continue
        if best is None or created > best[0]:
            best = (created, artifact)
    return None if best is None else best[1]


def load_store_from_artifact(fetch, download, repo, default_branch):
    """Read the previous tick's store, ENTIRELY IN MEMORY.

    THIS FUNCTION IS THE SECURITY BOUNDARY of the whole mechanism, and the property it holds is
    structural rather than defensive: nothing here writes to the filesystem, so a poisoned store
    has no path to any file. The zip is opened over a `BytesIO`, exactly one member of an exact
    name is admitted, and the read is bounded twice — once against the member's DECLARED size and
    again against the bytes actually produced, because a zip header can lie.

    THE THREE SIZE LAYERS, named honestly because they are not equally load-bearing: the
    DECLARED size is checked before the member is opened at all (a zip bomb is refused without
    expansion); the READ is issued with an explicit limit (a lying header cannot materialise
    more than the ceiling); the trailing `len(text)` comparison is REDUNDANT with
    `parse_conditional_store`'s identical ceiling and is kept only as defence in depth — its
    deletion is an equivalent mutation, covered by `an_oversized_store_is_a_bounded_no_op`.

    Every failure returns an EMPTY store (an unconditional sweep). `BudgetExhausted` is allowed
    to propagate: it is sweep-fatal everywhere else in this file and must not be downgraded here
    into "no cache today"."""
    try:
        listing = fetch(f"https://api.github.com/repos/{repo}/actions/artifacts"
                        f"?name={quote(STORE_ARTIFACT, safe='')}&per_page=100&page=1")
    except FetchError:
        return ConditionalStore()
    artifact = newest_store_artifact(listing, default_branch)
    if artifact is None:
        return ConditionalStore()
    url = artifact.get("archive_download_url")
    if not isinstance(url, str) or not url.startswith("https://api.github.com/"):
        return ConditionalStore()
    try:
        blob = download(url)
    except FetchError:
        return ConditionalStore()
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as bundle:
            # EXACTLY the one member, by name. A bundle carrying anything else is not one this
            # pipeline produced, and enumerating it is not this function's job.
            if bundle.namelist() != [STORE_MEMBER]:
                return ConditionalStore()
            if bundle.getinfo(STORE_MEMBER).file_size > STORE_MAX_JSON_BYTES:
                return ConditionalStore()
            with bundle.open(STORE_MEMBER) as handle:
                # +1 so an over-long stream is DETECTED rather than silently truncated into
                # valid-looking JSON.
                text = handle.read(STORE_MAX_JSON_BYTES + 1)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, MemoryError) as exc:
        print(f"SNAPSHOT conditional store unreadable ({type(exc).__name__}) — "
              "sweeping unconditionally")
        return ConditionalStore()
    if len(text) > STORE_MAX_JSON_BYTES:
        return ConditionalStore()
    return parse_conditional_store(text)


def make_download(token):
    """RAW byte reader for the store artifact, with a hard ceiling.

    NOT `make_fetch`: that one parses JSON, and this is a zip. It also must not follow GitHub's
    redirect to blob storage with the Authorization header still attached — that would hand the
    token to a third-party host — so the redirect is taken MANUALLY and the second leg is
    unauthenticated (the redirect target is pre-signed and needs no credential)."""
    opener = build_opener(_NoRedirect)

    def _read(response):
        # +1 so an over-long body is detected, not truncated into something that parses.
        data = response.read(STORE_MAX_DOWNLOAD_BYTES + 1)
        if len(data) > STORE_MAX_DOWNLOAD_BYTES:
            raise FetchError("conditional store artifact exceeds its size ceiling")
        return data

    def download(url):
        request = Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "reg4-plan-snapshot",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            with opener.open(request, timeout=60) as response:
                return _read(response)
        except HTTPError as exc:
            location = exc.headers.get("Location") if exc.headers is not None else None
            if exc.code not in (301, 302, 303, 307, 308) or not location:
                raise FetchError(
                    f"conditional store download failed (HTTP {exc.code})") from exc
            if not location.startswith("https://"):
                raise FetchError("conditional store redirect is not https") from exc
            try:
                # UNAUTHENTICATED on purpose — see the docstring.
                with opener.open(Request(location, headers={
                        "User-Agent": "reg4-plan-snapshot"}), timeout=60) as response:
                    return _read(response)
            except (HTTPError, URLError, TimeoutError) as inner:
                raise FetchError("conditional store download failed") from inner
        except (URLError, TimeoutError) as exc:
            raise FetchError("conditional store download failed") from exc

    return download


def save_conditional_store(path, store):
    """Write the store for the next tick. Best-effort by design: this is an optimisation, and a
    tick that cannot write its cache must still emit its snapshot."""
    if not path or store is None:
        return False
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(
            json.dumps({"schema": CONDITIONAL_STORE_SCHEMA, "entries": store.entries}),
            encoding="utf-8")
        return True
    except (OSError, TypeError, ValueError):
        return False


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


# Header readers + the classifier itself: ALIASES of the shared taxonomy (registry #1208), never
# re-implementations. `classify_403`'s order contract, its docstring and its 27-failure measurement
# all live in scripts/gh_403.py now; `the_three_403s_are_told_apart` below is unchanged and still
# exercises the whole contract through this name, which is what proves the move changed nothing.
_header = gh_403.header
_retry_after_seconds = gh_403.retry_after_seconds
_int_header = gh_403.int_header
classify_403 = gh_403.classify_403


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


def make_fetch(token, store=None):
    """Authenticated single-page reader with retry/backoff; raises FetchError, never exits
    (the caller decides sweep-fatal vs per-item).

    With a `store`, cacheable reads (see `_is_cacheable`) carry `If-None-Match` and a `304` is
    answered from the store WITHOUT spending a request — issue #1207. Everything else about the
    read is unchanged: the same urls, the same page walks, the same ceilings, the same
    `total_count` cross-check, the same budget reserve. What changes is only what GitHub charges
    for them."""

    def fetch(url):
        if store is not None:
            store.note(url)
        for attempt in range(3):
            # Re-read on EVERY attempt: a retry after a transient failure must make the same
            # decision, and re-reading keeps the etag and the payload from drifting apart.
            etag = store.etag_for(url) if store is not None else None
            request = Request(url, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "reg4-plan-snapshot",
                "X-GitHub-Api-Version": "2022-11-28",
            })
            if etag is not None:
                request.add_header("If-None-Match", etag)
            try:
                with urlopen(request, timeout=30) as response:
                    payload = json.load(response)
                    # Read the budget off the SUCCESSFUL response too (issue #796): that is the
                    # only place the authoritative number for this bucket ever appears, and a
                    # sweep that only looks after it has already been refused has learned it one
                    # request too late.
                    _check_reserve(getattr(response, "headers", None))
                    if store is not None:
                        store.count_billable()
                        store.record(url, _response_etag(getattr(response, "headers", None)),
                                     payload)
                    return payload
            except HTTPError as exc:
                # 304 IS DELIVERED AS AN HTTPError by urllib (its processor raises for every
                # non-2xx, and nothing handles 304), so this branch — not the success path above
                # — is where an unchanged read lands.
                #
                # `etag is not None` is load-bearing, not defensive noise: it is the whole
                # fail-toward-re-fetching rule. We only ever hold a payload for a url we sent a
                # conditional request for, so a 304 arriving on a request we did NOT make
                # conditional is a response we cannot satisfy — it falls through to the error
                # path below and is retried/reported, never silently treated as "unchanged".
                if exc.code == 304 and etag is not None:
                    _check_reserve(getattr(exc, "headers", None))
                    store.count_hit()
                    return store.payload_for(url)
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
                if RETRY_STATUS_POLICY.retries(exc.code) and attempt < 2:
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


def _response_etag(headers):
    """The `ETag` off a response, or None. Case-insensitive on purpose: urllib speaks HTTP/1.1,
    where GitHub sends `ETag`, while the same header arrives lower-cased over HTTP/2 — reading
    only one casing silently stores nothing and quietly disables the whole mechanism."""
    if headers is None:
        return None
    getter = getattr(headers, "get", None)
    if getter is None:
        return None
    value = getter("ETag") or getter("etag")
    return value if isinstance(value, str) and value else None


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
    """Repo-level page walk to a short page, KEEP-FIRST by `number`. The explicit ceiling
    only guards a runaway snapshot (5000 covers the migrated backlog with organic-growth
    margin) and stays SWEEP-fatal: the target planner step needs a complete listing for
    every repo.

    [registry #905] THE PAGINATION RACE IS ABSORBED HERE, at the one place the pages are
    joined. GitHub paginates a live, mutating ordering: a row created — or merely reordered
    by an update — between two page fetches can legitimately land on both pages, and a
    listing is not a set. Every downstream repeat check treats that as corruption and
    HARD-FAILS the whole fleet-wide tick: `validate_plan` raises DispatchError on a repeated
    (repo, pr_number) in `review_items` / `disarm_items` (and on a repeated `<repo>#<number>`
    issue row), and the enumerators that feed them walk this listing straight through with no
    de-duplication of their own. One routine race, zero dispatch fleet-wide.

    THIS layer owns it rather than the enumerators (the two options #905 put up) because it
    is where the defect actually is: the race is a property of joining pages, not of any one
    consumer, and this walk is the single choke point upstream of ALL of them — the issues
    leg and the pulls leg, plan rows and review/disarm rows alike. Fixing it in the
    enumerators would be the same fix written once per lane, each able to drift, and would
    still leave the issue rows repeating.

    Narrow on purpose:
    - KEEP-FIRST, so the answer is deterministic and the earlier read wins; a row's authority
      comes from the per-PR detail read (`_pr_status_record`), which re-derives head_sha and
      degrades on a mismatch, not from which page it arrived on.
    - Only rows that carry a usable `number` are de-duplicated. Anything else passes through
      UNCHANGED — this is a de-duplicator, never a filter, and dropping malformed rows here
      would silently take over a judgement the row-shape validators downstream already make.
    - The page-length ceiling still counts PAGES fetched, not surviving rows, so a runaway
      listing stays sweep-fatal even if every row on it is a repeat.
    - LOUD. A silent shrink is how a genuinely truncated listing would hide as a healthy one,
      so the drop is annotated with the exact numbers involved."""
    items = []
    seen = set()
    duplicates = []
    for page in range(1, LIST_PAGE_LIMIT + 1):
        separator = "&" if "?" in path else "?"
        result = fetch(f"https://api.github.com{path}{separator}per_page=100&page={page}")
        if not isinstance(result, list):
            raise FetchError("GitHub API returned a non-list page")
        for row in result:
            number = row.get("number") if isinstance(row, dict) else None
            if isinstance(number, int) and not isinstance(number, bool):
                if number in seen:
                    duplicates.append(number)
                    continue
                seen.add(number)
            items.append(row)
        if len(result) < 100:
            if duplicates:
                print(f"::warning::plan-snapshot: {path} returned "
                      f"{len(duplicates)} repeated row(s) across {page} page(s) "
                      f"(#{', #'.join(str(number) for number in sorted(set(duplicates)))}) "
                      "— keeping the first of each. A row created or reordered between two "
                      "page fetches lands on both pages; without this the plan's repeat "
                      "checks would fail the whole tick (registry #905).")
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


def _reason_histogram(reasons):
    counts = {}
    for reason in reasons.values():
        counts[reason] = counts.get(reason, 0) + 1
    return ", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "none"


def inertness_attestation(claim, pulls, status_items):
    """PURE per-PR "is this pull request provably inert?" map, for the PLAN-side partition.

    [sparq#4819] THE DEFECT THIS CLOSES. Two partition legs decide `area:` occupancy for the same
    PR. CLAIM's (`busy_packages_of_pulls`) frees a machine-parked PR's crates when
    `_pull_inactivity_decision` proves it is a defused draft — MEASURED 142 free events over 57
    crates in one tick. PLAN's (the target repo's own readiness engine, run in a LATER, hostile
    step that holds no token and may not see this repository at all) had no way to evaluate that
    predicate, so it reserved exactly the crates CLAIM was about to free, and it did so BEFORE the
    frontier was committed. The registry's carve-out was live, loud, and dead.

    The fix is NOT a second predicate. This walks the SAME `_pull_inactivity_decision`, with the
    SAME detail-beats-listing coherence rule CLAIM applies, and writes only its ANSWER — so the
    target engine consumes a decision it can never re-derive differently. A second implementation
    of "would parking this PR really free its crates?" is precisely the mint-vs-adopt drift that
    produced the defect.

    Returned as `{"items": {"<number>": bool}, "reasons": {"<number>": str}}`; the reasons ride
    along ONLY for the census line and diagnostics — nothing decides on them.

    WHERE IT RUNS, STATED CORRECTLY. This function runs in the authenticated registry-inline
    snapshot step, which precedes all target-code execution (REG-4) — so the attestation is
    COMPUTED from data no target has touched. An earlier draft of this docstring went one step
    further and said "no target can influence the attestation it later consumes". That is FALSE
    and was corrected in round 2: the readiness step `exec_module`s the target's
    `dispatch-plan.py` (dispatch.yml line ~399) BEFORE it reads `raw-inertness-<i>.json`
    (line ~644), both in the same job on the same filesystem, so a hostile target can rewrite the
    file at import time and hand itself any map it likes. DEMONSTRATED by execution: a target that
    rewrote the document turned `0 of 1` into `2999 of 2999`.

    That is not a hole this function opens or can close, and it is NOT the trust boundary that
    matters, which is why the architecture is deliberately left alone. PLAN is the unprivileged,
    advisory half by design (see this step's own header): it holds no token, and CLAIM
    independently re-derives `_pull_inactivity_decision` over its OWN authenticated read before
    any worker launches. A target that forges this map can therefore only over-propose rows CLAIM
    then drops — the same fail-direction as the trust and linked-PR filters above it. Verified by
    execution against a working positive control: latched, non-draft, resumed and unprovable PRs
    all read `busy` at CLAIM, and only a genuinely-inert one reads `parked-free`.

    FAILS CLOSED IN EVERY DIRECTION. A malformed row, an unparseable number, a latch, a
    non-draft bit, a head that moved between the listing and the detail read — every one of them
    yields False, because `_pull_inactivity_decision` is fail-closed and nothing here second-
    guesses it. A PR absent from the map is likewise not attested, and the consumer treats
    "absent" as "occupies".
    """
    items, reasons = {}, {}
    for pull in pulls if isinstance(pulls, list) else []:
        if not isinstance(pull, dict):
            continue
        number = pull.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            continue
        record = (status_items or {}).get(str(number), (status_items or {}).get(number))
        # The DETAIL read is the newer half of the split snapshot and is authoritative when it
        # exists — same precedence CLAIM uses. `pr_ci_status` normalises the raw record into the
        # {head_sha, armed, draft} shape the predicate wants; an absent record leaves the
        # listing's own atomic row to supply the proof (or to refuse to).
        status = claim.pr_ci_status(record) if record is not None else claim._NO_PR_DETAIL
        inactive, reason = claim._pull_inactivity_decision(pull, status)
        items[str(number)] = bool(inactive)
        reasons[str(number)] = str(reason)
    return {"items": items, "reasons": reasons}


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
        inert = inertness_attestation(claim, pulls, status_items)
        Path(out_dir, f"raw-inertness-{index}.json").write_text(
            json.dumps({"complete": True, **inert}), encoding="utf-8")
        print(f"SNAPSHOT inertness {repo}: {sum(inert['items'].values())} of "
              f"{len(inert['items'])} open PR(s) provably inert "
              f"({_reason_histogram(inert['reasons'])})")
    print(f"SNAPSHOT complete for {len(repos)} target repo(s)")


_SELFTEST_CHILD_ENV = "PLAN_SNAPSHOT_SELFTEST_CHILD"


def _pin_cli_verdict_contract_out_of_process():
    """Assert, FROM ANOTHER PROCESS, that `--self-test` always prints a verdict line.

    [sparq#4819 round 4] WHY THIS IS NOT ANOTHER TURN OF THE RECURSION. Round 3 shipped an
    in-process probe of `_run_checks` and I argued the residual was irreducible — "a guard on a
    guard, and the recursion has to stop". That was wrong, and the way it was wrong is the useful
    part: the in-process probe only ever observed the reporter's RETURN VALUE, so it could not see
    a reporter that RAISED, and it could not see anything at all that failed OUTSIDE `_run_checks`.
    `_self_test`'s prologue is ~83 straight-line statements (`claim = _load_claim()`,
    `gate = claim.CI_GATE_CHECK`, ...) and MEASURED, renaming `CI_GATE_CHECK` in
    `dispatch-claim.py` — an ordinary cross-file product regression — produced EXIT=1,
    ZERO verdict lines and ZERO bytes of stdout: the exact symptom this file claims to have fixed,
    still reproducible on the file that claims it.

    Changing the OBSERVER'S FRAME is what breaks the circularity. A different process observing the
    CLI contract is not a guard on a guard: it makes no assumption about which part of `_self_test`
    survives, because it only reads the CLI's stdout and exit status. Anything that can escape —
    prologue, reporter, an import, a `SystemExit` — is inside what it observes.

    Returns a list of failure strings (empty == contract holds). Never raises for a contract
    breach; a subprocess timeout is reported as a failure row like any other.
    """
    import collections
    import contextlib
    import shutil
    import signal
    import subprocess
    import tempfile

    completed = collections.namedtuple("completed", "returncode stdout stderr")
    # The child suite runs in ~1s; 60s is ~50x headroom on a loaded runner and is the
    # DETECTION BOUND for the fork-storm mutation above, so it is deliberately not larger.
    CHILD_TIMEOUT_SECONDS = 60
    failures = []
    source = Path(__file__).resolve().parent
    marquee = "the_inertness_attestation_adopts_the_claim_predicate_and_fails_closed"
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp, "scripts")
        # `dispatch-claim.py` loads siblings by name (park_policy, gh_retry, ...), so the whole
        # scripts/ tree is copied rather than the two files this touches.
        shutil.copytree(source, tree)
        # The child MUST NOT run this pin, or every run forks forever. TWO independent stops,
        # because MEASURED the env var alone was not enough: deleting that one dict key produced
        # a fork storm that left 53 orphaned processes on the box, since every generation opens
        # its OWN session and a process-group kill therefore cannot reach its grandchildren.
        #   1. the env var, which is also what makes the child ANNOUNCE the skip; and
        #   2. this textual neutralisation of the COPY, which makes recursion structurally
        #      impossible whatever the environment says.
        # (2) is asserted non-no-op below, so it cannot rot into a comment. It edits only the
        # branch that decides whether to run THIS pin — `main`'s CLI boundary, the contract
        # actually under test, is copied byte-for-byte.
        #
        # THE ANCHOR IS THE `else:` BRANCH, NOT THE `if`. My first cut searched for the bare
        # guard line — which is ALSO the text of the `guard_line = "..."` assignment a few lines
        # up in THIS function, so `replace(..., 1)` rewrote the pin's own variable and left the
        # real guard untouched. The child then recursed anyway (measured: 62s, 51 orphans). A
        # neutraliser whose source contains the pattern it searches for will match itself; the
        # anchor below includes the dispatch line that exists ONLY at the real site, and the
        # count is asserted to be exactly 1 so this class of near-miss reds instead of silently
        # rewriting the wrong occurrence.
        child_source = tree / "plan-snapshot.py"
        child_text = child_source.read_text(encoding="utf-8")
        anchor = ("    else:\n"
                  "        cli_failures = _pin_cli_verdict_contract_out_of_process()")
        if child_text.count(anchor) != 1:
            failures.append(
                f"could not uniquely locate the recursion dispatch in the copied CLI "
                f"({child_text.count(anchor)} matches) — refusing to spawn a child that could "
                "fork forever")
            return failures
        child_source.write_text(
            child_text.replace(anchor, "    else:\n        cli_failures = []  # [self-test copy] "
                                       "recursion structurally disabled", 1), encoding="utf-8")
        env = dict(os.environ, **{_SELFTEST_CHILD_ENV: "1", "PYTHONDONTWRITEBYTECODE": "1"})

        def run_child():
            """Run the copied CLI in its OWN process group, so a timeout reaps the WHOLE tree.

            MEASURED, and the reason this is not a plain `subprocess.run`: deleting
            `_SELFTEST_CHILD_ENV` from `env` — one dict key — turns this into a fork storm, and
            the run hung past 120s rather than failing. `subprocess.run(timeout=...)` kills only
            the DIRECT child, orphaning every grandchild. With a new session plus a group kill,
            that mutation degrades to a BOUNDED, NAMED "control run timed out" failure instead of
            a hung CI job. The guard is load-bearing; this makes its removal survivable."""
            proc = subprocess.Popen(
                [sys.executable, "-B", str(tree / "plan-snapshot.py"), "--self-test"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
                start_new_session=True)
            try:
                out, err = proc.communicate(timeout=CHILD_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.communicate(timeout=30)
                return None
            return completed(proc.returncode, out, err)

        # POSITIVE CONTROL FIRST — validate the instrument against a known answer. Without it a
        # broken COPY would also print FAILED and this pin would pass for the wrong reason.
        control = run_child()
        if control is None:
            failures.append("the unmutated control run timed out")
        elif control.returncode != 0 or "plan-snapshot self-test PASSED" not in control.stdout:
            failures.append(
                f"the unmutated control did not pass out of process (rc={control.returncode}); "
                f"stdout tail: {control.stdout[-200:]!r} stderr tail: {control.stderr[-200:]!r}")
        elif f"ok   {marquee}" not in control.stdout:
            # ...and it ran the REAL suite, not a stub that prints a verdict line and exits.
            failures.append("the control run never executed the marquee inertness guard")
        elif _SELFTEST_CHILD_ENV not in control.stdout:
            # ...and the recursion guard REACHED it. Without this the fork-storm mutation is
            # detectable only as a timeout, i.e. only after 120 wasted seconds.
            failures.append(f"the control run did not report {_SELFTEST_CHILD_ENV} — the "
                            "recursion guard is not reaching the child")

        # THE INJECTED FAILURE: the measured cross-file regression, in the PROLOGUE — the region
        # `_run_checks` cannot reach and the in-process probe cannot see.
        claim_path = tree / "dispatch-claim.py"
        before = claim_path.read_text(encoding="utf-8")
        after = before.replace("\nCI_GATE_CHECK = ", "\nCI_GATE_CHECK_RENAMED_BY_SELFTEST = ", 1)
        if after == before:
            failures.append("the injected prologue failure is a NO-OP — `CI_GATE_CHECK` was not "
                            "found in the copied dispatch-claim.py, so this pin proves nothing")
        else:
            claim_path.write_text(after, encoding="utf-8")
            broken = run_child()
            if broken is None:
                failures.append("the injected-failure run timed out")
            else:
                if broken.returncode == 0:
                    failures.append("a prologue failure exited 0 — it would be banked as a pass")
                if "plan-snapshot self-test FAILED" not in broken.stdout:
                    failures.append(
                        "a prologue failure printed NO verdict line on stdout "
                        f"({len(broken.stdout)} bytes) — the CLI boundary is not converting an "
                        "escape into a reportable verdict")
    return failures


def _run_checks(checks):
    """Run `checks` in order, fail-fast, returning (ok, rows) where each row NAMES its check.

    [sparq#4819 round 3] Separated from `_self_test` so the reporting itself is testable against
    fakes — a reporter asserted only by the suite it reports on cannot witness its own regression.

    An `AssertionError` is a KILL: the guard fired, which is the outcome a mutation battery is
    entitled to count. ANY other exception is a CRASH: the harness or the product raised, which is
    NOT a kill and is labelled differently so a mutation run cannot bank it as one. Both are
    non-ok, so the exit code is identical either way and no failure can be reported as a pass.
    The traceback is still printed on a crash, because that is the case someone has to debug.
    """
    rows = []
    for check in checks:
        try:
            check()
        except AssertionError as exc:
            rows.append(f"  FAIL {check.__name__}: {exc}")
            return False, rows
        except BaseException as exc:                # noqa: BLE001 — classified, then re-reported
            traceback.print_exc()
            rows.append(f"  CRASH {check.__name__}: {type(exc).__name__}: {exc} — NOT a kill, "
                        "the harness or the product raised")
            return False, rows
        rows.append(f"  ok   {check.__name__}")
    return True, rows


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
        assert written == ["raw-inertness-0.json", "raw-inertness-1.json",
                           "raw-issues-0.json", "raw-issues-1.json", "raw-prstatus-0.json",
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

    def a_pagination_race_duplicate_is_dropped_keep_first_and_announced():
        """[#905] A row that lands on TWO pages must not kill the tick. Downstream,
        `validate_plan` raises DispatchError on a repeated (repo, pr_number) in review_items /
        disarm_items and on a repeated issue row, and the enumerators walk this listing
        straight through — so one routine pagination race is zero dispatch fleet-wide. Each
        assertion names the mutation that reds it:
          * drop the `seen` guard entirely      -> the repeat survives into the listing (1);
          * keep-LAST instead of keep-first     -> the later body wins (2);
          * de-duplicate on some key other than
            `number` (e.g. the whole row/state) -> distinct rows collapse (3);
          * test SURVIVING rows for the short
            page instead of the raw page length -> page 1 is 100 raw rows but only 99
                                                   survivors, so the walk would stop one page
                                                   early and sell a truncated listing as
                                                   complete — page 2's row 6 vanishes (3);
          * de-duplicate keyless/non-dict rows  -> the walk becomes a silent FILTER (4);
          * drop the repeat SILENTLY            -> no annotation, and a shrinking listing
                                                   becomes indistinguishable from a healthy
                                                   one (5, via the end-to-end run).
        """
        first = {"number": 5, "state": "open", "mark": "page-1"}
        later = {"number": 5, "state": "open", "mark": "page-2"}
        pages = {
            # A FULL first page is what makes the walk fetch a second one at all — full by
            # RAW row count, with one repeat inside the page itself, so "is this the short
            # page?" can only be answered from the page GitHub returned.
            1: ([first] + [{"number": n, "state": "open"} for n in range(100, 198)]
                + [{"number": 100, "state": "open"}]),
            # The two keyless rows are IDENTICAL on purpose: a de-duplicator keyed on the
            # whole row — or on a `number` that is None for both — collapses them, and (4)
            # is what notices. Distinct keyless rows would let that mutant live.
            2: [later, {"number": 6, "state": "open"},
                {"no_number": "x"}, {"no_number": "x"}, {"number": "7"}],
        }

        def raced(url):
            return pages.get(int(url.rsplit("page=", 1)[1]), [])

        walked = _paginated(raced, f"/repos/{repo}/pulls?state=open")
        numbers = [row["number"] for row in walked if isinstance(row.get("number"), int)]
        assert len(numbers) == len(set(numbers)), numbers                              # (1)
        assert walked[0] is first and later not in walked, walked[:2]                  # (2)
        assert 6 in numbers, numbers                                                   # (3)
        assert [row for row in walked if not isinstance(row.get("number"), int)] == [
            {"no_number": "x"}, {"no_number": "x"}, {"number": "7"}], walked            # (4)

        # END TO END, through the artifact the PLAN assembler actually reads. Non-worker
        # heads, so the walk under test is the ONLY thing this run exercises (no detail
        # reads). The issues leg shares this same walk, hence the same protection.
        def raced_listing(url):
            base, _, query = url.partition("?")
            page_number = int(query.rsplit("page=", 1)[1])
            if base.endswith(f"/repos/{repo}/issues"):
                return [{"number": 4, "title": "t"}] if page_number == 1 else []
            if base.endswith(f"/repos/{repo}/pulls"):
                return [dict(row, head={"ref": "topic", "sha": "a" * 40,
                                        "repo": {"full_name": repo}})
                        for row in pages.get(page_number, [])
                        if isinstance(row.get("number"), int)]
            raise AssertionError(f"unexpected fetch {url}")

        log = io.StringIO()
        with contextlib.redirect_stdout(log), tempfile.TemporaryDirectory() as out_dir:
            snapshot_targets(raced_listing, claim, [repo], out_dir)
            listing = json.loads(
                Path(out_dir, "raw-pulls-0.json").read_text(encoding="utf-8"))
        planned = [row["number"] for row in listing["items"]]
        assert listing["complete"] is True
        assert planned.count(5) == 1 and len(planned) == len(set(planned)) == 100, planned
        assert "::warning::" in log.getvalue() and "#5" in log.getvalue(), (      # (5)
            "a de-duplicated listing must SAY so — a silent shrink is indistinguishable "
            f"from a truncated listing sold as complete: {log.getvalue()!r}")

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

    def the_classifier_is_the_SHARED_one_not_a_local_copy():
        """#1208. The check above passes just as happily against a private re-implementation, and a
        private re-implementation is precisely the defect: dispatch-secrets-guard had one, and the
        same 403 got two diagnoses in one pipeline — PLAN said "request budget exhausted", GUARD
        said "an availability reason", and only one of those motivates a retry against a bucket at
        zero.

        So pin IDENTITY, not behaviour. Re-inline `classify_403` here (or copy the marker tuples
        back) and this row goes red while every behavioural check above stays green."""
        assert classify_403 is gh_403.classify_403, "classify_403 must BE the shared taxonomy's"
        assert _SECONDARY_403_MARKERS is gh_403.SECONDARY_403_MARKERS
        assert _BUDGET_403_MARKERS is gh_403.BUDGET_403_MARKERS
        assert _header is gh_403.header
        assert _retry_after_seconds is gh_403.retry_after_seconds
        assert _int_header is gh_403.int_header
        # ...and the shared module's OWN suite must pass, since this file's correctness now rests
        # on it. A taxonomy that ships broken must not be adopted silently by its consumer.
        assert gh_403._self_test(), "the shared gh_403 taxonomy's self-test must pass"

    def the_retry_status_policy_is_the_SHARED_one():
        """#552. Same argument, one layer out: WHICH statuses this walk replays was a hand-written
        `RETRYABLE = {429, 500, 502, 503, 504}` here, and a DIFFERENT hand-written table (the whole
        5xx range, no 429) in groom.py, with nothing anywhere comparing them. The difference is
        deliberate — this walk must survive a burst limiter to produce a plan at all, groom's cron
        sweep fails closed on every 4xx — but a deliberate difference nobody can see is
        indistinguishable from drift, and the drift direction is fail-CLOSED: a transient status
        missing from a table is FATAL and costs a whole scheduled run.

        Behaviour AND identity, because each catches what the other cannot. The membership check
        below reds if the shared policy is widened or narrowed; the identity check reds if someone
        re-inlines the set here (which every behavioural check in this file would stay green
        against, exactly as it did before #552)."""
        assert RETRY_STATUS_POLICY is http_transient.PLAN_SNAPSHOT_READ, \
            "the retry status policy must BE the shared taxonomy's, not a local copy"
        # The membership this file has always had, asserted as a whole VALUE over the FULL status
        # surface — so a widening anywhere in 100..599 reds here, not just on a spot-checked code.
        assert RETRY_STATUS_POLICY.retried_statuses() == (429, 500, 502, 503, 504), \
            f"plan-snapshot's opt-in changed: {RETRY_STATUS_POLICY.retried_statuses()}"
        # 403 and 304 are the two statuses a widening here would be MOST tempting and MOST wrong:
        # 403 is `classify_403`'s (one of its three classes must never be replayed at all) and 304
        # is this file's conditional-request CACHE HIT (#1207) — replaying it is a loop, not a
        # retry. The shared taxonomy refuses both at construction; assert the outcome here too.
        assert not RETRY_STATUS_POLICY.retries(403) and not RETRY_STATUS_POLICY.retries(304)
        # ...and the shared module's OWN suite must pass, since this file's retry surface now rests
        # on it.
        assert http_transient._self_test(), "the shared http_transient taxonomy's self-test must pass"

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

    # ------------------------------------------------------------------------------------------
    # [#1207] CONDITIONAL READS. The whole mechanism turns on one rule — an `If-None-Match` is
    # sent ONLY when the payload it names is in hand — so the tests below are written against
    # that rule from both sides, including the two ways it could fail OPEN (answering a 304 we
    # cannot satisfy, and sending a conditional request we cannot satisfy).
    # ------------------------------------------------------------------------------------------
    CHECK_RUNS_URL = (f"https://api.github.com/repos/{repo}/commits/{'a' * 40}"
                      "/check-runs?check_name=gate&per_page=100&page=1")
    DETAIL_URL = f"https://api.github.com/repos/{repo}/pulls/7"

    class _Resp:
        def __init__(self, body, headers):
            self.headers = headers
            self._body = io.BytesIO(body)

        def read(self, *args):
            return self._body.read(*args)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def _wire(module, body=b"[]", headers=None, code=None, seen=None):
        """A urlopen double that records the REQUEST (so the header the fetch actually put on the
        wire is observable) and can answer a 304 the way urllib really delivers one — as an
        HTTPError, not a success."""
        headers = {"ETag": '"v1"'} if headers is None else headers

        def _fake(request, timeout=None):
            if seen is not None:
                seen.append(request)
            if code == 304:
                raise HTTPError(request.full_url, 304, "Not Modified", headers, None)
            return _Resp(body, headers)

        return patch.object(module, "urlopen", _fake)

    def a_304_is_answered_from_the_store_and_carries_the_conditional_header():
        """The mechanism, end to end: a stored {etag, payload} makes the next read conditional,
        and the 304 GitHub answers is satisfied from the store rather than re-fetched."""
        module = sys.modules[__name__]
        store = ConditionalStore({CHECK_RUNS_URL: {"etag": '"v1"',
                                                   "payload": {"check_runs": [], "total_count": 0}}})
        seen = []
        with _wire(module, code=304, seen=seen):
            got = make_fetch("t", store)(CHECK_RUNS_URL)
        assert got == {"check_runs": [], "total_count": 0}, got
        assert len(seen) == 1 and seen[0].has_header("If-none-match"), (
            "the read must actually carry If-None-Match — without it GitHub can never answer "
            "304 and the whole mechanism is inert")
        assert (store.hits, store.billable) == (1, 0), (store.hits, store.billable)

    def no_conditional_request_is_made_without_the_payload_in_hand():
        """FAIL TOWARD RE-FETCHING. A half-entry (etag, no payload) is exactly the state that
        would make a 304 unanswerable, so it must never reach the wire as a conditional request.
        Deleting the `"payload" not in entry` clause in `etag_for` turns this red."""
        module = sys.modules[__name__]
        for label, entry in (("etag but NO payload", {"etag": '"v1"'}),
                             ("payload but no etag", {"payload": {"a": 1}}),
                             ("empty etag", {"etag": "", "payload": {"a": 1}}),
                             ("not a mapping", ["nope"])):
            store = ConditionalStore({CHECK_RUNS_URL: entry})
            seen = []
            with _wire(module, body=b'{"check_runs": [], "total_count": 0}', seen=seen):
                make_fetch("t", store)(CHECK_RUNS_URL)
            assert not seen[0].has_header("If-none-match"), label
            assert store.billable == 1, (label, store.billable)

    def a_304_on_an_unconditional_request_is_never_read_as_unchanged():
        """THE FAIL-OPEN THIS CLOSES. If a 304 were honoured on its status alone, a server (or a
        proxy) answering 304 to a request we never made conditional would be served from an
        entry we do not hold — or, worse, from a STALE one. Deleting `and etag is not None` from
        the 304 branch turns this red."""
        module = sys.modules[__name__]
        store = ConditionalStore()            # nothing stored: no conditional request possible
        with _wire(module, code=304):
            try:
                make_fetch("t", store)(CHECK_RUNS_URL)
                got = "returned"
            except FetchError:
                got = "refused"
        assert got == "refused", (
            "a 304 we did not ask for must fall through to the error path, never be treated as "
            f"'unchanged' — got {got}")
        assert store.hits == 0, store.hits

    def only_check_runs_reads_are_cached():
        """PR detail and listings measured 0% unchanged across a tick, so caching them stores
        large bodies to buy nothing. `_is_cacheable` is the one place that decides it."""
        module = sys.modules[__name__]
        store = ConditionalStore()
        with _wire(module, body=b'{"check_runs": [], "total_count": 0}'):
            make_fetch("t", store)(CHECK_RUNS_URL)
        with _wire(module, body=b'{"number": 7}'):
            make_fetch("t", store)(DETAIL_URL)
        assert CHECK_RUNS_URL in store.entries, "the check-runs read must be stored"
        assert DETAIL_URL not in store.entries, "the PR detail read must NOT be stored"
        assert store.etag_for(DETAIL_URL) is None

    def a_malformed_store_degrades_to_an_unconditional_sweep():
        """Every unreadable shape costs exactly today's behaviour, never a wrong answer."""
        for label, text in (
                ("empty", ""),
                ("not json", "{["),
                ("not an object", "[]"),
                # THE FIXTURE MUST BE LOADABLE BUT FOR THE DEFECT. A wrong-schema document with
                # EMPTY entries is satisfied by dropping the schema check entirely — measured:
                # that mutation survived this row until the entries were populated.
                ("wrong schema", json.dumps({"schema": "other/v1", "entries": {
                    CHECK_RUNS_URL: {"etag": '"v1"', "payload": {"would": "be loaded"}}}})),
                ("no schema at all", json.dumps({"entries": {
                    CHECK_RUNS_URL: {"etag": '"v1"', "payload": {"would": "be loaded"}}}})),
                ("entries not a map",
                 json.dumps({"schema": CONDITIONAL_STORE_SCHEMA, "entries": []})),
                ("invalid utf-8", b"\xff\xfe not text"),
        ):
            store = parse_conditional_store(text)
            assert store.entries == {}, (label, store.entries)
            assert store.etag_for(CHECK_RUNS_URL) is None, label
        # ...and ONE malformed row costs one re-fetch, not the whole tick's cache.
        store = parse_conditional_store(json.dumps({
            "schema": CONDITIONAL_STORE_SCHEMA, "entries": {
                CHECK_RUNS_URL: {"etag": '"v1"', "payload": {"ok": True}},
                DETAIL_URL: {"etag": '"v2"', "payload": {"no": True}},
                "https://api.github.com/x/check-runs?bad": {"etag": '"v3"'}}}))
        assert list(store.entries) == [CHECK_RUNS_URL], store.entries

    def an_oversized_store_is_a_bounded_no_op():
        """[#1207 review r1] The bytes are REMOTE CONTENT, so an oversized store is an
        attacker-reachable MemoryError. Before this bound it escaped the parse and stalled EVERY
        subsequent tick until the artifact expired.

        THE FIXTURE MUST BE VALID JSON THAT IS MERELY TOO BIG. A giant blob of garbage is
        rejected by `json.loads` whether or not the size bound exists — measured: with a garbage
        fixture, deleting the bound outright SURVIVED this row."""
        module = sys.modules[__name__]
        valid = json.dumps({"schema": CONDITIONAL_STORE_SCHEMA, "entries": {
            CHECK_RUNS_URL: {"etag": '"v1"', "payload": {"x": "y"}}}})
        # CONTROL FIRST: the same document is accepted when it fits, so the refusal below is
        # attributable to the SIZE and to nothing else.
        assert parse_conditional_store(valid).entries != {}, "control fixture must load"
        with patch.object(module, "STORE_MAX_JSON_BYTES", len(valid) - 1):
            assert parse_conditional_store(valid).entries == {}, "str over the bound must refuse"
            assert parse_conditional_store(valid.encode()).entries == {}, "bytes likewise"

        # ...and MemoryError must not ESCAPE. Asserted by catching it here: letting it propagate
        # would otherwise be reported as a harness CRASH, which this suite deliberately does not
        # count as a kill.
        try:
            with patch.object(module.json, "loads",
                              lambda *a, **k: (_ for _ in ()).throw(MemoryError())):
                got = parse_conditional_store('{"schema": "x"}')
        except MemoryError:
            raise AssertionError(
                "MemoryError escaped parse_conditional_store — one oversized store would stall "
                "this tick and every tick after it until the artifact expired")
        assert got.entries == {}, got.entries

    def the_store_keeps_only_the_urls_this_tick_asked_for():
        """A head that advanced never comes back; without the prune its entry would be carried by
        every future restore for ever.

        THE READS ARE DRIVEN THROUGH `make_fetch`, NOT BY CALLING `note` BY HAND. Measured: with
        the live head noted directly, deleting the `store.note(url)` CALL SITE in `fetch` left
        this row green — the unit was pinned and the wiring was not, so the prune would have
        silently emptied the store on every tick."""
        module = sys.modules[__name__]
        live = CHECK_RUNS_URL
        dead = CHECK_RUNS_URL.replace("a" * 40, "b" * 40)
        store = ConditionalStore({live: {"etag": '"v1"', "payload": {"live": True}},
                                  dead: {"etag": '"v2"', "payload": {"dead": True}}})
        with _wire(module, code=304):
            store_payload = make_fetch("t", store)(live)
        assert store_payload == {"live": True}, store_payload
        with _wire(module, body=b'{"number": 7}'):
            make_fetch("t", store)(DETAIL_URL)   # not cacheable: never becomes a `seen` key
        assert store.seen == {live}, store.seen
        store.prune()
        assert list(store.entries) == [live], store.entries

    def the_store_round_trips_from_the_written_file_through_the_parser():
        """The save/parse pair must agree, or the artifact round-trips something the reader then
        rejects — which looks exactly like a 0% hit rate and reports nothing."""
        with tempfile.TemporaryDirectory() as workdir:
            path = str(Path(workdir, "nested", "etags.json"))
            store = ConditionalStore()
            store.record(CHECK_RUNS_URL, '"v1"', {"check_runs": [], "total_count": 0})
            assert save_conditional_store(path, store) is True
            back = parse_conditional_store(Path(path).read_text(encoding="utf-8"))
            assert back.etag_for(CHECK_RUNS_URL) == '"v1"', back.entries
            assert back.payload_for(CHECK_RUNS_URL) == {"check_runs": [], "total_count": 0}

    def the_store_reader_never_writes_to_the_filesystem():
        """[#1207 review r1] THE SECURITY PROPERTY, and the reason this is not `actions/cache`.

        `@actions/toolkit` extracts with `tar -xf ... -P` (--absolute-names), so a restore action
        is an ARBITRARY FILE WRITE — landing, in the original design, in a job that goes on to
        hold `github.token`. The replacement reads the zip out of memory, asserted structurally:
        the reader runs with every filesystem write path booby-trapped, so ANY write — by this
        code or by zipfile underneath it — fails this row."""
        module = sys.modules[__name__]
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, "w") as bundle:
            bundle.writestr(STORE_MEMBER, json.dumps({
                "schema": CONDITIONAL_STORE_SCHEMA,
                "entries": {CHECK_RUNS_URL: {"etag": '"v1"', "payload": {"in": "memory"}}}}))
        payload = blob.getvalue()

        def _no(*args, **kwargs):
            raise AssertionError("the store reader touched the filesystem")

        import builtins
        _real_open = builtins.open

        def _open_guard(file, mode="r", *args, **kwargs):
            if any(flag in str(mode) for flag in ("w", "a", "x", "+")):
                raise AssertionError(
                    f"the store reader opened {file!r} for writing (mode {mode!r})")
            return _real_open(file, mode, *args, **kwargs)

        listing = {"artifacts": [{
            "name": STORE_ARTIFACT, "expired": False,
            "created_at": "2026-07-29T09:00:00Z",
            "archive_download_url": "https://api.github.com/x/zip",
            "workflow_run": {"head_branch": "master", "repository_id": 1,
                             "head_repository_id": 1}}]}
        with patch.object(builtins, "open", _open_guard), \
                patch.object(module.Path, "write_text", _no), \
                patch.object(module.Path, "write_bytes", _no), \
                patch.object(module.os, "replace", _no), \
                patch.object(module.zipfile.ZipFile, "extractall", _no), \
                patch.object(module.zipfile.ZipFile, "extract", _no):
            store = load_store_from_artifact(
                lambda url: listing, lambda url: payload, repo, "master")
        assert store.etag_for(CHECK_RUNS_URL) == '"v1"', store.entries

    def only_attributable_store_artifacts_are_read():
        """The transport this replaced had NO writer attribution and fell through to a bare
        prefix match. Artifacts carry the producing run's branch and head repository, so the
        reader requires both; anything it cannot attribute is declined."""
        good = {"name": STORE_ARTIFACT, "expired": False,
                "created_at": "2026-07-29T09:00:00Z",
                "archive_download_url": "https://api.github.com/x/zip",
                "workflow_run": {"head_branch": "master", "repository_id": 1,
                                 "head_repository_id": 1}}
        assert newest_store_artifact({"artifacts": [good]}, "master") is good
        for label, mutation in (
                ("another branch", {"workflow_run": dict(good["workflow_run"],
                                                         head_branch="attacker")}),
                ("a fork head", {"workflow_run": dict(good["workflow_run"],
                                                      head_repository_id=99)}),
                ("expired", {"expired": True}),
                ("a look-alike name", {"name": "dispatch-etags-lookalike"}),
        ):
            assert newest_store_artifact({"artifacts": [dict(good, **mutation)]},
                                         "master") is None, label
        for branch in (None, "", 7):
            assert newest_store_artifact({"artifacts": [good]}, branch) is None, branch
        older = dict(good, created_at="2026-07-28T09:00:00Z")
        junk = dict(good, created_at="not-a-date")
        assert newest_store_artifact({"artifacts": [older, good, junk]}, "master") is good

    def _fake_https(seen, second_status=200, second_body=b"PAYLOAD",
                    location="https://blob.example/signed"):
        """A real urllib handler chain with a fake transport, so `_NoRedirect` ACTUALLY
        PARTICIPATES. The earlier version of this double patched the opener CLASS's `open`,
        one level ABOVE the handler — so deleting `_NoRedirect`, the primary token-leak
        control, left the row green. Review round 2 caught that; test the control, not its
        neighbour."""
        import email
        import urllib.response

        def _resp(code, headers, body):
            msg = email.message_from_string(
                "".join(f"{k}: {v}\n" for k, v in headers.items()))
            out = urllib.response.addinfourl(io.BytesIO(body), msg, "https://x", code)
            out.msg = "Found" if code // 100 == 3 else "OK"
            return out

        # BOTH protocols. Serving only https made an `http://` redirect fail with a
        # CONNECTION error, which takes the same FetchError path as the refusal — so deleting
        # the https pin left the row green. The insecure leg must be SERVABLE for its refusal
        # to mean anything.
        class _Handler(HTTPHandler, HTTPSHandler):
            def _answer(self, req):
                seen.append(req)
                if "api.github.com" in req.full_url:
                    return _resp(302, {"Location": location}, b"")
                return _resp(second_status, {}, second_body)

            https_open = _answer
            http_open = _answer

        return _Handler()

    def the_store_download_never_forwards_the_token_off_github():
        """THE TOKEN-LEAK CONTROL, exercised through the REAL opener chain.

        urllib re-sends request headers across a redirect — MEASURED by review round 2 to
        include `Authorization` on a cross-origin 302 — and GitHub answers the artifact
        download with a 302 to blob storage. `_NoRedirect` is what stops the automatic hop;
        `make_download` then takes it manually, unauthenticated.

        The fake transport is installed as a HANDLER alongside `_NoRedirect`, so removing
        `_NoRedirect` from `build_opener` makes urllib follow the redirect itself and this row
        sees the token on the second host."""
        module = sys.modules[__name__]
        seen = []
        real_build_opener = module.build_opener
        with patch.object(module, "build_opener",
                          lambda *handlers: real_build_opener(*handlers,
                                                              _fake_https(seen))):
            got = make_download("SEKRIT")("https://api.github.com/x/zip")
        assert got == b"PAYLOAD", got
        assert len(seen) == 2, f"expected an API leg and a blob leg, got {len(seen)}"
        assert seen[0].has_header("Authorization"), "the API leg must be authenticated"
        assert not seen[1].has_header("Authorization"), (
            "the redirect leg carried the token OFF api.github.com — `_NoRedirect` is what "
            "prevents urllib following the 302 itself")

    def the_store_download_refuses_a_non_https_redirect():
        """A 302 to `http://` would put the download on the wire in clear. Refused."""
        module = sys.modules[__name__]
        seen = []
        real_build_opener = module.build_opener
        with patch.object(module, "build_opener",
                          lambda *handlers: real_build_opener(
                              *handlers, _fake_https(seen, location="http://blob.example/x"))):
            try:
                make_download("SEKRIT")("https://api.github.com/x/zip")
                got = "followed"
            except FetchError:
                got = "refused"
        assert got == "refused", "an http:// redirect target must be refused, not followed"
        # The transport WOULD have served it (see _fake_https), so a single leg proves the
        # refusal happened in the product, not in the harness.
        assert len(seen) == 1, f"the insecure leg must never be requested: {len(seen)} legs"

    def the_store_download_is_bounded():
        """The body is REMOTE CONTENT. Without a ceiling, one oversized artifact is an
        unbounded read into memory on every tick."""
        module = sys.modules[__name__]
        seen = []
        real_build_opener = module.build_opener
        with patch.object(module, "STORE_MAX_DOWNLOAD_BYTES", 8), \
                patch.object(module, "build_opener",
                             lambda *handlers: real_build_opener(
                                 *handlers, _fake_https(seen, second_body=b"x" * 64))):
            try:
                make_download("SEKRIT")("https://api.github.com/x/zip")
                got = "accepted"
            except FetchError:
                got = "refused"
        assert got == "refused", "a body over the ceiling must be refused"
        # CONTROL: the same path accepts a body that fits, so the refusal is attributable to
        # the SIZE and not to the harness.
        seen2 = []
        with patch.object(module, "STORE_MAX_DOWNLOAD_BYTES", 64), \
                patch.object(module, "build_opener",
                             lambda *handlers: real_build_opener(
                                 *handlers, _fake_https(seen2, second_body=b"x" * 8))):
            assert make_download("SEKRIT")("https://api.github.com/x/zip") == b"x" * 8

    def _artifact_listing(url="https://api.github.com/x/zip"):
        return {"artifacts": [{
            "name": STORE_ARTIFACT, "expired": False,
            "created_at": "2026-07-29T09:00:00Z", "archive_download_url": url,
            "workflow_run": {"head_branch": "master", "repository_id": 1,
                             "head_repository_id": 1}}]}

    def _zip_of(members):
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, "w") as bundle:
            for name, body in members.items():
                bundle.writestr(name, body)
        return blob.getvalue()

    _GOOD_STORE = json.dumps({
        "schema": CONDITIONAL_STORE_SCHEMA,
        "entries": {CHECK_RUNS_URL: {"etag": '"v1"', "payload": {"in": "memory"}}}})

    def the_download_url_must_be_on_the_github_api_host():
        """`archive_download_url` comes off a listing this code did not write. Without the host
        pin, a crafted artifact record aims the authenticated download at any host it likes."""
        called = []

        def _download(url):
            called.append(url)
            return _zip_of({STORE_MEMBER: _GOOD_STORE})

        for label, url in (("another host", "https://evil.example/zip"),
                           ("plain http", "http://api.github.com/x/zip"),
                           ("not a url", "zip")):
            store = load_store_from_artifact(
                lambda _u, _l=label: _artifact_listing(
                    {"another host": "https://evil.example/zip",
                     "plain http": "http://api.github.com/x/zip",
                     "not a url": "zip"}[_l]),
                _download, repo, "master")
            assert store.entries == {}, label
        assert called == [], f"the download must never be issued at all: {called}"
        # CONTROL: the api.github.com url IS downloaded and DOES load.
        store = load_store_from_artifact(
            lambda _u: _artifact_listing(), _download, repo, "master")
        assert store.etag_for(CHECK_RUNS_URL) == '"v1"', store.entries
        assert called == ["https://api.github.com/x/zip"], called

    def the_store_bundle_must_hold_exactly_its_one_member():
        """A bundle carrying anything besides the store is not one this pipeline produced.
        Enumerating it is not this reader's job, and a bundle that smuggles extra members past
        the reader is the shape that makes an extractor dangerous in the first place."""
        payload = _zip_of({STORE_MEMBER: _GOOD_STORE, "evil.sh": "rm -rf /"})
        store = load_store_from_artifact(
            lambda _u: _artifact_listing(), lambda _u: payload, repo, "master")
        assert store.entries == {}, (
            "a bundle with an extra member must be refused wholesale, not read selectively")
        # CONTROL: the same bundle WITHOUT the extra member loads.
        ok = _zip_of({STORE_MEMBER: _GOOD_STORE})
        assert load_store_from_artifact(
            lambda _u: _artifact_listing(), lambda _u: ok,
            repo, "master").etag_for(CHECK_RUNS_URL) == '"v1"'

    def the_member_read_is_bounded():
        """The bound that actually protects memory is the SIZE ARGUMENT on the read, not the
        comparison after it — that comparison is equivalent-by-construction with
        `parse_conditional_store`'s own ceiling (both use STORE_MAX_JSON_BYTES), so deleting it
        changes nothing and `an_oversized_store_is_a_bounded_no_op` already covers the outcome.
        What is NOT covered elsewhere is an unbounded `handle.read()`, which would materialise
        a lying member in full before any ceiling could look at it. Asserted at that level: the
        row fails if the read is issued with no limit."""
        module = sys.modules[__name__]
        asked = []
        real_open = module.zipfile.ZipFile.open

        class _Handle:
            def __init__(self, inner):
                self._inner = inner

            def read(self, n=None):
                asked.append(n)
                return self._inner.read() if n is None else self._inner.read(n)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def _wrapped(self, name, *a, **k):
            return _Handle(real_open(self, name, *a, **k))

        payload = _zip_of({STORE_MEMBER: _GOOD_STORE})
        with patch.object(module.zipfile.ZipFile, "open", _wrapped):
            load_store_from_artifact(
                lambda _u: _artifact_listing(), lambda _u: payload, repo, "master")
        assert asked and all(n is not None for n in asked), (
            f"the store member was read with NO size limit ({asked}) — a lying zip header "
            "would be materialised in full before any ceiling could refuse it")

    def an_oversized_member_is_refused_without_being_read():
        """THE ZIP-BOMB BOUND. The member's DECLARED size is checked BEFORE it is opened, so a
        highly-compressible bomb is refused without ever being expanded. Asserted at that exact
        level: `ZipFile.open` is booby-trapped, so a reader that skipped the declared-size check
        and went straight to reading trips this row."""
        module = sys.modules[__name__]
        payload = _zip_of({STORE_MEMBER: "0" * 4096})

        def _boom(*args, **kwargs):
            raise AssertionError(
                "the member was OPENED despite declaring a size over the ceiling — the "
                "declared-size check must refuse it before any expansion happens")

        with patch.object(module, "STORE_MAX_JSON_BYTES", 128), \
                patch.object(module.zipfile.ZipFile, "open", _boom):
            store = load_store_from_artifact(
                lambda _u: _artifact_listing(), lambda _u: payload, repo, "master")
        assert store.entries == {}, store.entries

    def the_plan_carries_no_new_check_run_derived_field():
        """[#1207 review r1] THE BOUND ON A POISONED STORE, pinned rather than asserted in prose.

        The store can only ever supply CHECK-RUN rows, so what matters is which plan fields those
        rows can move. Today that set is exactly {state, context} on `review_items` — verified,
        not assumed; the tidier claim that check-run data does not reach the plan at all is FALSE
        (`context` carries verbatim failing-leg names and a gate-conclusion string).

        The two ends are pinned by DIFFERENT means, and the difference matters: the review-item
        channel is pinned by a FROZEN FIELD LIST (it reds when a field is added, NOT when an
        existing field starts carrying more check-run content), while the DISARM channel is
        pinned by a true differential over check-run content. Review round 2 flagged the earlier
        wording for implying the differential covered both. The disarm channel gets the stronger
        check because it consumes a degraded record on purpose — it consumes detail fields only, deliberately, so that a
        degraded/poisoned check-run record can never suppress the #42 safety act."""
        claim_mod = _load_claim()
        assert claim_mod.REVIEW_ITEM_FIELDS == {
            "pr_number", "head_sha", "state", "impl_provider", "repo", "package", "security",
            "self_attested", "context"}, claim_mod.REVIEW_ITEM_FIELDS
        assert claim_mod.DISARM_ITEM_FIELDS == {
            "pr_number", "head_sha", "reviewed_sha", "repo"}, claim_mod.DISARM_ITEM_FIELDS

        # DIFFERENTIAL: hold everything constant but the check runs, and see what moves.
        head = "c" * 40
        base = {"head_sha": head, "mergeable": True, "draft": True, "auto_merge": None}
        green = dict(base, check_runs=[gate_run(name=draft_gate, conclusion="success")])
        red = dict(base, check_runs=[gate_run(name=draft_gate, conclusion="failure"),
                                     gate_run(name="docs-quality", conclusion="failure")])
        moved = {key for key in ("head_sha", "armed", "draft", "gate", "repair_gate",
                                 "failing_legs")
                 if claim_mod.pr_ci_status(green).get(key)
                 != claim_mod.pr_ci_status(red).get(key)}
        # The STATUS is allowed to move — it is the derived view. What must not move is the
        # DISARM decision, which is the one act that consumes a degraded record on purpose.
        assert "gate" in moved or "repair_gate" in moved, (
            "the fixture no longer varies the gate at all — this differential would pass "
            f"vacuously (moved={moved})")
        # READY + head/marker MISMATCH, so the enumerator actually EMITS. A fixture that emits
        # nothing makes "green == red" true for the wrong reason and could not witness a disarm
        # that started consuming check runs.
        ready = dict(base, draft=False)
        green = dict(ready, check_runs=green["check_runs"])
        red = dict(ready, check_runs=red["check_runs"])
        # READY, reviewed-sha marker pointing at a DIFFERENT head -> the enumerator emits.
        # pr_status and provenance are both keyed by the INT pr number, and pr_status carries
        # `pr_ci_status` OUTPUT (what the assemble step builds), not the raw record.
        pull = {"number": 11, "state": "open", "draft": False,
                "body": "<!-- sparq-reviewed-sha:" + "d" * 40 + " -->",
                "head": {"sha": head, "ref": "sparq-agent/issue-1-x",
                         "repo": {"full_name": repo}},
                "user": {"login": "bot[bot]"}}
        provenance = {11: {"pr_number": 11}}
        disarm_green = claim_mod.enumerate_disarm_items(
            repo, [pull], {11: claim_mod.pr_ci_status(green)}, provenance,
            bot_login="bot[bot]")
        disarm_red = claim_mod.enumerate_disarm_items(
            repo, [pull], {11: claim_mod.pr_ci_status(red)}, provenance,
            bot_login="bot[bot]")
        assert disarm_green, (
            "the disarm fixture emits nothing, so this invariance check cannot witness a "
            "disarm that started reading check runs — it would pass vacuously")
        assert disarm_green == disarm_red, (
            "the DISARM channel moved with check-run content; it must consume detail fields "
            f"only (#42): {disarm_green} vs {disarm_red}")

    def the_inertness_attestation_adopts_the_claim_predicate_and_fails_closed():
        """[sparq#4819] The PLAN-side attestation must be `_pull_inactivity_decision`'s ANSWER —
        never an independent re-derivation of it — and every unprovable shape must read False.

        Every row is asserted `is claim._pull_inactivity_decision(...)[0]`, not against a literal:
        a hand-written expectation would let this suite and the predicate drift apart silently,
        which is the exact two-legs-disagree defect the attestation exists to end. The literal
        `want` column is carried alongside so the row still fails if BOTH sides regress together.
        """
        def listing(number, *, draft=True, latch=..., sha="a" * 40):
            row = {"number": number, "state": "open",
                   "head": {"ref": f"sparq-agent/issue-{number}-1-1", "sha": sha,
                            "repo": {"full_name": repo}}}
            if draft is not ...:
                row["draft"] = draft
            if latch is not ...:
                row["auto_merge"] = latch
            return row

        armed_latch = {"enabled_by": {"login": "u"}, "merge_method": "squash"}
        cases = [
            ("draft + explicit-null latch is the atomic single-read proof",
             listing(1, latch=None), None, True),
            ("a LATCHED draft is never inert", listing(2, latch=armed_latch), None, False),
            ("a NON-draft never frees", listing(3, draft=False, latch=None), None, False),
            ("a pre-#517 row with NO auto_merge key proves nothing (ABSENCE != NULL)",
             listing(4), None, False),
            ("a row with no draft bit at all proves nothing", listing(5, draft=..., latch=None),
             None, False),
            ("a malformed head sha proves nothing", listing(6, latch=None, sha="zz"), None, False),
            ("a garbage latch shape proves nothing", listing(7, latch="garbage"), None, False),
            # DETAIL beats listing, in both directions — the round-4 split-snapshot race.
            ("a newer detail confirming the defused draft frees", listing(8, latch=None),
             {"head_sha": "a" * 40, "auto_merge": None, "draft": True, "mergeable": True}, True),
            ("a newer detail saying the draft went READY holds", listing(9, latch=None),
             {"head_sha": "a" * 40, "auto_merge": None, "draft": False, "mergeable": True}, False),
            ("a newer detail carrying a latch holds", listing(10, latch=None),
             {"head_sha": "a" * 40, "auto_merge": armed_latch, "draft": True}, False),
            ("a detail whose head MOVED means the listing row is stale", listing(11, latch=None),
             {"head_sha": "b" * 40, "auto_merge": None, "draft": True}, False),
            ("an unreadable detail record holds (pr_ci_status -> {})", listing(12, latch=None),
             {"head_sha": "not-a-sha"}, False),
        ]
        for label, row, record, want in cases:
            items = {str(row["number"]): record} if record is not None else {}
            got = inertness_attestation(claim, [row], items)
            status = (claim.pr_ci_status(record) if record is not None
                      else claim._NO_PR_DETAIL)
            expected, reason = claim._pull_inactivity_decision(row, status)
            assert got["items"][str(row["number"])] is expected is want, (label, got, want)
            assert got["reasons"][str(row["number"])] == reason, (label, got, reason)
        # Hostile shapes never enter the map at all, and never raise.
        junk = inertness_attestation(claim, ["x", None, 42, {"number": True},
                                             {"number": -1}, {"no": "number"}], {})
        assert junk == {"items": {}, "reasons": {}}, junk
        assert inertness_attestation(claim, None, None) == {"items": {}, "reasons": {}}
        # An int-keyed status map (the in-memory shape) resolves the same as the JSON str keys.
        row13 = listing(13, latch=None)
        detail = {"head_sha": "a" * 40, "auto_merge": armed_latch, "draft": True}
        assert inertness_attestation(claim, [row13], {13: detail})["items"]["13"] is False
        assert inertness_attestation(claim, [row13], {"13": detail})["items"]["13"] is False

    # [sparq#4819 round 3] A GUARD THAT FIRES MUST SAY WHICH GUARD FIRED. This suite used to be a
    # flat call sequence, so any failure escaped as a bare traceback with NO verdict line at all —
    # `--self-test | grep -cE "self-test (PASSED|FAILED)"` returned 0. MEASURED on this file's
    # marquee guard: mutating `inertness_attestation` to fail open (attest every PR inert) was
    # detected, but reported as an unlabelled `AssertionError` indistinguishable from the harness
    # itself breaking. That distinction is the point — a crash is not a kill — and the sibling
    # data-shape guards in dispatch-plan.py already report named rows, so this file's HEADLINE
    # guard was the one with the weakest reporting.
    #
    # FAIL-FAST IS PRESERVED. `_run_checks` stops at the first failure exactly as the flat
    # sequence did (several checks share module-level fixture state, so continuing past a failure
    # would report cascades, not findings). What changed is only the reporting, and the exit code
    # is unchanged in both directions.
    # THE REPORTER IS PINNED FIRST, and with plain `if`/`print` rather than `assert` or
    # `_run_checks` itself. Both of those would route the announcement of a broken reporter
    # THROUGH the thing under test: measured, an `assert` here escaped as a bare traceback with
    # zero verdict lines under three separate reporter mutations — reproducing, inside the fix,
    # the exact defect the fix exists to remove. Fakes only, so no real check is disturbed.
    def _fake_pass():
        return None

    def _fake_kill():
        raise AssertionError("the guard fired")

    def _fake_crash():
        raise TypeError("the harness broke")

    # The crash branch prints a traceback by design; silence it for the PROBE only so a passing
    # run stays readable. Real crashes still print, because that is the case someone must debug.
    with contextlib.redirect_stderr(io.StringIO()):
        _probe = {
            "pass": _run_checks((_fake_pass,)),
            "kill": _run_checks((_fake_pass, _fake_kill, _fake_pass)),
            "crash": _run_checks((_fake_crash,)),
        }
    _want = {
        "pass": (True, ["  ok   _fake_pass"]),
        # A KILL (AssertionError = the guard fired) and a CRASH (anything else = the harness or
        # the product raised) must be LABELLED DIFFERENTLY. Collapsing them is how a crash gets
        # banked as a kill by a mutation run.
        "kill": (False, ["  ok   _fake_pass", "  FAIL _fake_kill: the guard fired"]),
        "crash": (False, ["  CRASH _fake_crash: TypeError: the harness broke — NOT a kill, "
                          "the harness or the product raised"]),
    }
    _bad = [f"{name}: got {_probe[name]!r}, want {_want[name]!r}"
            for name in _want if _probe[name] != _want[name]]
    if _bad:
        for _row in _bad:
            print(f"  FAIL _run_checks reporter self-check — {_row}")
        print("plan-snapshot self-test FAILED")
        return 1

    ok, rows = _run_checks((
        the_inertness_attestation_adopts_the_claim_predicate_and_fails_closed,
        snapshot_parallel_output_is_identical_to_serial,
        per_pr_reads_actually_overlap,
        repo_listings_overlap_across_repos,
        in_flight_reads_never_exceed_the_requested_bound,
        concurrency_stays_inside_the_secondary_rate_limit_budget,
        sweep_fatal_listing_failure_is_still_fatal,
        a_pagination_race_duplicate_is_dropped_keep_first_and_announced,
        retry_after_is_honoured_and_capped,
        the_three_403s_are_told_apart,
        the_classifier_is_the_SHARED_one_not_a_local_copy,
        the_retry_status_policy_is_the_SHARED_one,
        budget_403_is_not_retried_and_is_sweep_fatal,
        budget_403_is_never_downgraded_to_a_per_item_skip,
        the_reserve_stops_the_sweep_before_the_budget_is_gone,
        a_304_is_answered_from_the_store_and_carries_the_conditional_header,
        no_conditional_request_is_made_without_the_payload_in_hand,
        a_304_on_an_unconditional_request_is_never_read_as_unchanged,
        only_check_runs_reads_are_cached,
        a_malformed_store_degrades_to_an_unconditional_sweep,
        the_store_keeps_only_the_urls_this_tick_asked_for,
        the_store_round_trips_from_the_written_file_through_the_parser,
        an_oversized_store_is_a_bounded_no_op,
        the_store_reader_never_writes_to_the_filesystem,
        only_attributable_store_artifacts_are_read,
        the_store_download_never_forwards_the_token_off_github,
        the_store_download_refuses_a_non_https_redirect,
        the_store_download_is_bounded,
        the_download_url_must_be_on_the_github_api_host,
        the_store_bundle_must_hold_exactly_its_one_member,
        an_oversized_member_is_refused_without_being_read,
        the_member_read_is_bounded,
        the_plan_carries_no_new_check_run_derived_field,
    ))
    for row in rows:
        print(row)
    if not ok:
        print("plan-snapshot self-test FAILED")
        return 1

    # THE OUTER PIN, IN A DIFFERENT PROCESS. Runs LAST on purpose: it re-runs the whole suite in a
    # child, so a genuine product regression reds its own named row above first, rather than
    # surfacing as "the control run did not pass".
    if os.environ.get(_SELFTEST_CHILD_ENV):
        # Announced, never silent. If this variable is ever set in CI by accident, the log says the
        # outer pin did not run instead of showing an unqualified PASSED.
        print(f"  ok   CLI verdict contract — SKIPPED ({_SELFTEST_CHILD_ENV} set: child process)")
    else:
        cli_failures = _pin_cli_verdict_contract_out_of_process()
        if cli_failures:
            for failure in cli_failures:
                print(f"  FAIL CLI verdict contract (out of process) — {failure}")
            print("plan-snapshot self-test FAILED")
            return 1
        print("  ok   CLI verdict contract, observed out of process")

    print("plan-snapshot self-test PASSED")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repos_file", nargs="?", help="newline-delimited owner/repo manifest")
    parser.add_argument("out_dir", nargs="?", help="directory for the raw-*.json snapshots")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--etag-store", default=os.environ.get("SNAPSHOT_ETAG_STORE", ""),
        help=("WRITE path for the cross-tick ETag store (issue #1207) — the file the workflow's "
              "upload-artifact step publishes for the NEXT tick. The read side does not use "
              "this: it pulls the previous tick's store from the artifacts API straight into "
              "memory, because an extracting action is a filesystem-write primitive. Absent or "
              "unreadable means an unconditional sweep, so the dispatcher never depends on the "
              "store existing."))
    args = parser.parse_args()
    if args.self_test:
        # [sparq#4819 round 4] THE CLI BOUNDARY IS THE LAST PLACE AN ESCAPE CAN BE NAMED.
        # `_self_test` has ~83 straight-line prologue statements outside `_run_checks`, and
        # `_run_checks` can itself raise; either way the old bare `return _self_test()` let the
        # exception reach the interpreter, which prints a traceback to STDERR and no verdict line
        # at all. MEASURED: renaming `CI_GATE_CHECK` in dispatch-claim.py gave EXIT=1 with ZERO
        # bytes of stdout. Nothing was ever banked as a pass — CI runs this under
        # `set -euo pipefail`, and the return below is still 1 — so the loss was purely
        # DIAGNOSTIC, which is exactly what this change is about.
        #
        # SCOPED TO --self-test DELIBERATELY: the real snapshot path below must keep propagating
        # SystemExit/FetchError to the workflow unchanged. KeyboardInterrupt is re-raised because
        # a human pressing Ctrl-C is not a test result and must not be reported as one.
        try:
            return _self_test()
        except KeyboardInterrupt:
            raise
        except BaseException:                     # noqa: BLE001 — re-reported, never swallowed
            traceback.print_exc()
            print("plan-snapshot self-test FAILED")
            return 1
    if not args.repos_file or not args.out_dir:
        parser.error("repos_file and out_dir are required unless --self-test is used")
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise SystemExit("GH_TOKEN is required for the authenticated snapshot")
    repos = [line for line in
             Path(args.repos_file).read_text(encoding="utf-8").splitlines() if line]
    # The READ side is the artifacts API, straight into memory — never an extracting action.
    # See the CONDITIONAL READS block: the transport this replaced (`actions/cache`) extracts
    # with `tar -P`, which is an arbitrary file write into a job that then holds this token.
    fetch = make_fetch(token)
    store = load_store_from_artifact(
        fetch, make_download(token), os.environ.get("REGISTRY_REPO", ""),
        os.environ.get("REGISTRY_STORE_BRANCH", ""))
    try:
        snapshot_targets(make_fetch(token, store), _load_claim(), repos, args.out_dir)
        # Only a COMPLETED sweep writes the store. A sweep that died half way has a `seen` set
        # covering only the reads it got to, and pruning to that would throw away live entries
        # for every PR it never reached — turning one failed tick into a cold cache for the
        # next one.
        store.prune()
        if not save_conditional_store(args.etag_store, store):
            # LOUD, but NOT fatal — the tick's real work is already done. The workflow's upload
            # step is `if-no-files-found: warn` for the same reason; between this annotation and
            # the next tick's hit rate, a store that stopped publishing cannot go unnoticed.
            print("::warning::plan-snapshot: could not write the conditional-read store — the "
                  "next tick will sweep unconditionally (this costs budget, not correctness)")
    except BudgetExhausted as exc:
        # A distinct, annotated exit: this is not "a read failed", it is "the dispatcher is
        # running hotter than its request budget allows", and it needs a different fix from
        # every other snapshot failure. The annotation puts it on the run summary rather than
        # only in the step log.
        raise SystemExit(f"::error title=dispatch request budget exhausted::{exc}") from exc
    except FetchError as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        # ALWAYS report, including on the failure paths above: "how much of this tick was
        # billable" is exactly the number wanted when a tick has just died on the budget.
        print(store.summary())
    return 0


if __name__ == "__main__":
    sys.exit(main())
